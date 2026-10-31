package idempotency

import (
	"embed"
	"net/http"
	"time"
)

const (
	maxRequestBytes           int64 = 64 << 20
	maxResponseBytes                = 64 << 20
	maxResultTTL                    = 10 * 365 * 24 * time.Hour
	maxProcessingTTL                = 24 * time.Hour
	minProcessingTTL                = 3 * time.Millisecond
	legacyScopeKeyID                = "legacy-v1"
	legacyUnscopedKeyID             = "legacy-unscoped-v1"
	legacyRequestHashVersion  int16 = 1
	currentRequestHashVersion int16 = 2
	legacyResponseFormat      int16 = 1
	currentResponseFormat     int16 = 2
)

var defaultHashHeaders = []string{"Accept", "Accept-Charset", "Accept-Encoding", "Accept-Language", "Content-Encoding", "If-Match", "If-Modified-Since", "If-None-Match", "If-Unmodified-Since", "Origin", "Prefer", "Range", "X-API-Version"}

// Migrations contains the SQL migration files for the package. Consumers decide
// when and how to apply them to their own database.
//
//go:embed migrations/*.sql
var Migrations embed.FS

// Status is the lifecycle state of an idempotent operation.
type Status string

const (
	StatusProcessing    Status = "processing"
	StatusCompleted     Status = "completed"
	StatusFailed        Status = "failed"
	StatusIndeterminate Status = "indeterminate"
)

// Record is the database representation of one action/key pair. The response
// fields contain an encrypted envelope and must only be decoded by Service.
type Record struct {
	ID                 string
	ScopeHash          string
	ScopeHashKeyID     string
	ResponseKeyID      string
	RequestHashVersion int16
	ResponseFormat     int16
	IdempotencyKey     string
	ActionType         string
	RequestHash        string
	Status             Status
	ResponseStatus     int
	Response           []byte
	CreatedAt          time.Time
	UpdatedAt          time.Time
	ExpiresAt          time.Time
	OwnerToken         string
}

type cachedResponse struct {
	Status int                 `json:"status"`
	Header map[string][]string `json:"header"`
	Body   []byte              `json:"body"`
}

// Response is the captured HTTP response used by the middleware.
type Response struct {
	Status int
	Header map[string][]string
	Body   []byte
}

// Config controls lifecycle, limits, keyrings, and privacy-safe observations.
// Every key must be exactly 32 bytes (AES-256); responses are never persisted
// without encryption. OnEvent can be called concurrently and should return
// quickly without logging sensitive request or response values.
type Config struct {
	TTL              time.Duration
	ProcessingTTL    time.Duration
	MaxRequestBytes  int64
	MaxResponseBytes int
	// EncryptionKey is the compatibility alias for the pre-keyring key. Keep it
	// configured as a legacy read key until all legacy rows have been resolved.
	EncryptionKey          []byte
	ScopeHashKeys          []KeyMaterial
	ActiveScopeHashKeyID   string
	ResponseEncryptionKeys []KeyMaterial
	ActiveResponseKeyID    string
	// HashHeaders adds request headers whose values affect the operation or
	// representation. Standard semantic headers are included by default.
	// Credentials are excluded; put authorization identity in the trusted scope.
	HashHeaders []string
	ErrorWriter func(http.ResponseWriter, int, string)
	OnEvent     func(Event)
}

// KeyMaterial is an identified key in a read keyring. The active key ID is
// used for new writes; retained IDs remain available for old records.
type KeyMaterial struct {
	ID  string
	Key []byte
}

// ScopeHashCandidate binds a principal scope hash to the key version that
// generated it. Repository lookups consider every configured version.
type ScopeHashCandidate struct {
	KeyID string
	Hash  string
}

// RequestHashCandidate identifies a persisted request fingerprint version.
type RequestHashCandidate struct {
	Version int16
	Hash    string
}

func (c *Config) defaults() {
	if c.TTL == 0 {
		c.TTL = 24 * time.Hour
	}
	if c.ProcessingTTL == 0 {
		c.ProcessingTTL = 2 * time.Minute
	}
	if c.MaxRequestBytes == 0 {
		c.MaxRequestBytes = 1 << 20
	}
	if c.MaxResponseBytes == 0 {
		c.MaxResponseBytes = 1 << 20
	}
}
