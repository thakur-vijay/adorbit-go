package idempotency

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Service owns hashing, lifecycle rules, response encryption and replay.
type Service struct {
	repository           Repository
	config               Config
	scopeHashKeys        map[string][]byte
	activeScopeHashKeyID string
	responseAEAD         map[string]cipher.AEAD
	activeResponseKeyID  string
}

// Event is a privacy-safe lifecycle observation. It deliberately has no key,
// request body, response body, or token fields.
type Event struct {
	Name   string
	Err    error
	Count  int64
	Actor  string
	Action string
}

// NewService constructs the lifecycle service. A 32-byte encryption key is
// required so persisted responses (which can contain credentials) are encrypted.
func NewService(repository Repository, config Config) (*Service, error) {
	if repository == nil {
		return nil, errors.New("idempotency: repository is required")
	}
	config.defaults()
	config.EncryptionKey = append([]byte(nil), config.EncryptionKey...)
	config.HashHeaders = mergeHashHeaders(config.HashHeaders)
	if config.TTL < time.Second || config.TTL > maxResultTTL || config.ProcessingTTL < minProcessingTTL || config.ProcessingTTL > maxProcessingTTL || config.MaxRequestBytes < 0 || config.MaxRequestBytes > maxRequestBytes || config.MaxResponseBytes <= 0 || config.MaxResponseBytes > maxResponseBytes {
		return nil, errors.New("idempotency: invalid duration or size limit")
	}
	scopeKeys, activeScopeID, err := buildKeyring(config.ScopeHashKeys, config.EncryptionKey, config.ActiveScopeHashKeyID, "scope hash")
	if err != nil {
		return nil, err
	}
	responseKeys, activeResponseID, err := buildKeyring(config.ResponseEncryptionKeys, config.EncryptionKey, config.ActiveResponseKeyID, "response encryption")
	if err != nil {
		return nil, err
	}
	config.HashHeaders, err = normalizeHashHeaders(config.HashHeaders)
	if err != nil {
		return nil, err
	}
	responseAEAD := make(map[string]cipher.AEAD, len(responseKeys))
	for id, key := range responseKeys {
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("idempotency: response key %q must be 32 bytes: %w", id, err)
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		responseAEAD[id] = aead
	}
	return &Service{repository: repository, config: config, scopeHashKeys: scopeKeys, activeScopeHashKeyID: activeScopeID, responseAEAD: responseAEAD, activeResponseKeyID: activeResponseID}, nil
}

func buildKeyring(materials []KeyMaterial, legacyKey []byte, activeID, purpose string) (map[string][]byte, string, error) {
	keys := make(map[string][]byte, len(materials)+1)
	for _, material := range materials {
		if !validKeyID(material.ID) || len(material.Key) != 32 {
			return nil, "", fmt.Errorf("idempotency: invalid %s key material", purpose)
		}
		if _, exists := keys[material.ID]; exists {
			return nil, "", fmt.Errorf("idempotency: duplicate %s key ID", purpose)
		}
		keys[material.ID] = append([]byte(nil), material.Key...)
	}
	if len(legacyKey) > 0 {
		if len(legacyKey) != 32 {
			return nil, "", errors.New("idempotency: legacy EncryptionKey must be 32 bytes")
		}
		if existing, ok := keys["legacy-v1"]; ok && !hmac.Equal(existing, legacyKey) {
			return nil, "", errors.New("idempotency: legacy key ID conflicts with EncryptionKey")
		}
		keys["legacy-v1"] = append([]byte(nil), legacyKey...)
	}
	if len(keys) == 0 {
		return nil, "", fmt.Errorf("idempotency: %s keyring is empty", purpose)
	}
	if activeID == "" && len(keys) == 1 {
		for id := range keys {
			activeID = id
		}
	}
	if !validKeyID(activeID) {
		return nil, "", fmt.Errorf("idempotency: active %s key ID is required", purpose)
	}
	if _, ok := keys[activeID]; !ok {
		return nil, "", fmt.Errorf("idempotency: active %s key is not in the keyring", purpose)
	}
	return keys, activeID, nil
}

func validKeyID(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for _, ch := range id {
		if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-' || ch == '_' || ch == '.') {
			return false
		}
	}
	return true
}

// HashRequest computes the legacy v1 fingerprint for compatibility with stored
// records and callers that use the original helper. New service operations use
// v2 internally and also retain v1 as a lookup candidate during migration.
func HashRequest(r *http.Request, action string, maxBytes int64) (string, error) {
	legacy, _, err := hashRequestVersions(r, action, maxBytes, nil)
	return legacy, err
}

// HashRequestWithHeaders computes the current request fingerprint. Include any
// application headers that change business behavior or representation.
func HashRequestWithHeaders(r *http.Request, action string, maxBytes int64, headers []string) (string, error) {
	normalized, err := normalizeHashHeaders(mergeHashHeaders(headers))
	if err != nil {
		return "", err
	}
	_, current, err := hashRequestVersions(r, action, maxBytes, normalized)
	return current, err
}

func hashRequestCandidates(r *http.Request, action string, maxBytes int64, headers []string) ([]RequestHashCandidate, error) {
	legacy, current, err := hashRequestVersions(r, action, maxBytes, headers)
	if err != nil {
		return nil, err
	}
	// Version-1 rows cannot prove equality for URL authority, raw query ordering, or
	// newly configured semantic headers. Fail closed on those records instead of
	// replaying a possibly different operation.
	_ = legacy
	return []RequestHashCandidate{{Version: currentRequestHashVersion, Hash: current}}, nil
}

func hashRequestVersions(r *http.Request, action string, maxBytes int64, headers []string) (string, string, error) {
	if r == nil || r.URL == nil || maxBytes < 0 || maxBytes > maxRequestBytes {
		return "", "", errInvalidHashLimit
	}
	var body []byte
	if r.Body != nil {
		original := r.Body
		b, err := io.ReadAll(io.LimitReader(original, maxBytes+1))
		r.Body = &restoredBody{Reader: io.MultiReader(bytes.NewReader(b), original), Closer: original}
		if err != nil {
			return "", "", err
		}
		body = b
		if int64(len(body)) > maxBytes {
			return "", "", errRequestTooLarge
		}
	}
	query, queryErr := url.ParseQuery(r.URL.RawQuery)
	if queryErr != nil {
		return "", "", errors.New("idempotency: malformed request query")
	}
	for k := range query {
		sort.Strings(query[k])
	}
	canonical, _ := json.Marshal(query)
	legacyContentType := []byte(strings.ToLower(strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0])))
	legacy := sha256.New()
	for _, part := range [][]byte{[]byte(r.Method), []byte(action), []byte(r.URL.EscapedPath()), canonical, legacyContentType, body} {
		_, _ = legacy.Write([]byte{0})
		_, _ = legacy.Write(part)
	}
	current := sha256.New()
	tlsState := byte(0)
	if r.TLS != nil {
		tlsState = 1
	}
	forceQuery := byte(0)
	if r.URL.ForceQuery {
		forceQuery = 1
	}
	for _, part := range [][]byte{[]byte(r.Method), []byte(action), []byte(r.URL.Scheme), []byte(r.URL.Host), []byte(r.Host), []byte(r.Proto), {tlsState}, []byte(r.URL.EscapedPath()), []byte(r.URL.RawQuery), {forceQuery}, []byte(strconv.FormatInt(r.ContentLength, 10)), body} {
		writeFingerprintPart(current, part)
	}
	for _, value := range r.Header.Values("Content-Type") {
		writeFingerprintPart(current, []byte(value))
	}
	writeFingerprintPart(current, nil)
	for _, transfer := range r.TransferEncoding {
		writeFingerprintPart(current, []byte(transfer))
	}
	writeFingerprintPart(current, nil)
	closeState := byte(0)
	if r.Close {
		closeState = 1
	}
	writeFingerprintPart(current, []byte{closeState})
	for _, name := range headers {
		writeFingerprintPart(current, []byte(name))
		for _, value := range r.Header.Values(name) {
			writeFingerprintPart(current, []byte(value))
		}
		writeFingerprintPart(current, nil)
	}
	trailerNames := make([]string, 0, len(r.Trailer))
	for name := range r.Trailer {
		trailerNames = append(trailerNames, http.CanonicalHeaderKey(name))
	}
	sort.Strings(trailerNames)
	for _, name := range trailerNames {
		writeFingerprintPart(current, []byte(name))
		for _, value := range r.Trailer.Values(name) {
			writeFingerprintPart(current, []byte(value))
		}
		writeFingerprintPart(current, nil)
	}
	return fmt.Sprintf("%x", legacy.Sum(nil)), fmt.Sprintf("%x", current.Sum(nil)), nil
}

func writeFingerprintPart(h io.Writer, value []byte) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	_, _ = h.Write(length[:])
	_, _ = h.Write(value)
}

func normalizeHashHeaders(headers []string) ([]string, error) {
	seen := make(map[string]struct{}, len(headers))
	result := make([]string, 0, len(headers))
	for _, raw := range headers {
		trimmed := strings.TrimSpace(raw)
		name := http.CanonicalHeaderKey(trimmed)
		if trimmed != raw || name == "" || !validHeaderName(name) {
			return nil, errors.New("idempotency: invalid fingerprint header name")
		}
		switch strings.ToLower(name) {
		case "authorization", "proxy-authorization", "cookie", "set-cookie", "idempotency-key", "host", "content-type":
			return nil, errors.New("idempotency: reserved fingerprint header")
		}
		key := strings.ToLower(name)
		if _, ok := seen[key]; ok {
			return nil, errors.New("idempotency: duplicate fingerprint header")
		}
		seen[key] = struct{}{}
		result = append(result, name)
	}
	sort.Strings(result)
	return result, nil
}

func mergeHashHeaders(configured []string) []string {
	all := append(append([]string(nil), defaultHashHeaders...), configured...)
	seen := make(map[string]struct{}, len(all))
	merged := make([]string, 0, len(all))
	for _, name := range all {
		key := strings.ToLower(strings.TrimSpace(name))
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		merged = append(merged, name)
	}
	return merged
}

func validHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for _, c := range []byte(name) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c))) {
			return false
		}
	}
	return true
}

type restoredBody struct {
	io.Reader
	io.Closer
}

var errRequestTooLarge = errors.New("idempotency: request body exceeds configured limit")
var errInvalidHashLimit = errors.New("idempotency: invalid request body limit or request")
var errStorageEvent = errors.New("idempotency storage operation failed")
var errHeartbeatShutdownTimeout = errors.New("idempotency: heartbeat shutdown timed out")

const (
	maxHeartbeatOperationTimeout = 5 * time.Second
	minHeartbeatOperationTimeout = time.Millisecond
)

// Serve protects one action. It returns stored terminal responses and runs next
// only after atomically acquiring a processing lease.
func (s *Service) Serve(action string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key, ok := GetIdempotencyKey(r.Context())
		if !ok {
			s.writeError(w, http.StatusBadRequest, "Idempotency-Key header is required")
			return
		}
		scope, scoped := GetIdempotencyScope(r.Context())
		if !scoped || scope == "" || strings.TrimSpace(scope) != scope || len(scope) > 1024 {
			s.observe(Event{Name: "scope_missing"})
			s.writeError(w, http.StatusInternalServerError, "idempotency scope is required")
			return
		}
		scopeCandidates, activeScope := s.scopeHashCandidates(scope)
		if !validAction(action) {
			s.writeError(w, http.StatusInternalServerError, "invalid idempotency action")
			return
		}
		hashes, err := hashRequestCandidates(r, action, s.config.MaxRequestBytes, s.config.HashHeaders)
		if errors.Is(err, errRequestTooLarge) {
			s.writeError(w, http.StatusRequestEntityTooLarge, "request body is too large")
			return
		}
		if err != nil {
			s.writeError(w, http.StatusBadRequest, "could not read request body")
			return
		}
		owner := uuid.NewString()
		activeHash := hashes[0]
		rec, claimed, err := s.repository.Claim(r.Context(), scopeCandidates, activeScope, hashes, activeHash, key, action, owner, s.config.TTL, s.config.ProcessingTTL)
		if err != nil {
			if errors.Is(err, errLegacyIndeterminate) || errors.Is(err, errFingerprintIndeterminate) {
				s.observe(Event{Name: "indeterminate_conflict"})
				s.writeError(w, http.StatusConflict, "earlier operation has an indeterminate outcome and requires operator resolution")
				return
			}
			if errors.Is(err, errLegacyScopeConflict) {
				s.observe(Event{Name: "request_conflict"})
				s.writeError(w, http.StatusConflict, "Idempotency-Key is reserved by an earlier unscoped request until it expires")
				return
			}
			s.observe(Event{Name: "claim_failed", Err: errStorageEvent})
			w.Header().Set("Retry-After", "1")
			s.writeError(w, http.StatusServiceUnavailable, "idempotency storage is unavailable")
			return
		}
		if !claimed {
			if rec.Status == StatusIndeterminate {
				s.observe(Event{Name: "indeterminate_conflict"})
				s.writeError(w, http.StatusConflict, "operation outcome is indeterminate and requires operator resolution")
				return
			}
			if rec.RequestHashVersion == legacyRequestHashVersion {
				s.observe(Event{Name: "fingerprint_upgrade_conflict"})
				if rec.Status == StatusProcessing {
					w.Header().Set("Retry-After", "1")
				}
				s.writeError(w, http.StatusConflict, "stored operation uses a legacy request fingerprint and cannot be safely replayed")
				return
			}
			if !requestHashCandidateMatches(rec.RequestHashVersion, rec.RequestHash, hashes) {
				s.observe(Event{Name: "request_conflict"})
				s.writeError(w, http.StatusConflict, "Idempotency-Key was already used with a different request")
				return
			}
			if rec.Status == StatusProcessing {
				s.observe(Event{Name: "processing_conflict"})
				w.Header().Set("Retry-After", "1")
				s.writeError(w, http.StatusConflict, "request with this Idempotency-Key is already being processed")
				return
			}
			cached, err := s.decrypt(rec.Response, rec.ScopeHashKeyID, rec.ScopeHash, rec.ResponseKeyID, rec.ResponseFormat, rec.ActionType, rec.IdempotencyKey, rec.RequestHash)
			if err != nil {
				s.writeError(w, http.StatusServiceUnavailable, "stored response is unavailable")
				return
			}
			s.observe(Event{Name: "replay"})
			writeResponse(w, cached)
			return
		}
		s.observe(Event{Name: "claim_acquired"})

		capture := newCaptureWriter(w, s.config.MaxResponseBytes)
		handlerCtx, cancelHandler := context.WithCancel(r.Context())
		leaseCtx, cancelLease := context.WithCancel(context.WithoutCancel(r.Context()))
		heartbeatDone := make(chan struct{})
		heartbeatStop := make(chan struct{})
		heartbeatErr := make(chan error, 1)
		go s.refreshLease(leaseCtx, owner, heartbeatStop, heartbeatDone, heartbeatErr, cancelHandler)
		heartbeatStopped := false
		stopHeartbeat := func() error {
			if heartbeatStopped {
				return nil
			}
			heartbeatStopped = true
			// Cancel first so an in-flight Refresh using leaseCtx can unwind before
			// we wait for the heartbeat goroutine.
			cancelLease()
			cancelHandler()
			close(heartbeatStop)
			timer := time.NewTimer(s.heartbeatOperationTimeout())
			defer timer.Stop()
			select {
			case <-heartbeatDone:
				select {
				case err := <-heartbeatErr:
					return err
				default:
					return nil
				}
			case <-timer.C:
				s.observe(Event{Name: "heartbeat_shutdown_timeout", Err: errStorageEvent})
				return errHeartbeatShutdownTimeout
			}
		}
		defer stopHeartbeat()
		next.ServeHTTP(capture, r.WithContext(handlerCtx))

		select {
		case <-heartbeatErr:
			s.observe(Event{Name: "lease_lost", Err: errStorageEvent})
			_ = stopHeartbeat()
			if !capture.dstCommitted && !capture.hijacked && r.Context().Err() == nil {
				capture.resetForError()
				w.Header().Set("Retry-After", "1")
				s.writeError(w, http.StatusServiceUnavailable, "idempotency lease was lost; retry with the same key")
			}
			return
		default:
		}
		if r.Context().Err() != nil {
			s.observe(Event{Name: "request_cancelled"})
			_ = stopHeartbeat()
			// Keep the processing row until stale recovery. Releasing immediately
			// could allow a second handler to overlap side effects from this request.
			return
		}
		resp := capture.response()
		if capture.maxExceeded || capture.passthrough {
			stopErr := stopHeartbeat()
			if err := stopErr; err != nil {
				s.observe(Event{Name: "lease_lost", Err: errStorageEvent})
			}
			if errors.Is(stopErr, errHeartbeatShutdownTimeout) {
				if !capture.hijacked {
					_ = capture.commit()
				}
				return
			}
			if err := s.repository.Release(r.Context(), owner); err != nil {
				s.observe(Event{Name: "release_failed", Err: errStorageEvent})
			}
			if !capture.hijacked {
				_ = capture.commit()
			}
			return
		}
		if resp.Status >= 500 || resp.Status == http.StatusTooManyRequests || resp.Status == http.StatusRequestTimeout || resp.Status == http.StatusTooEarly {
			stopErr := stopHeartbeat()
			if err := stopErr; err != nil {
				s.observe(Event{Name: "lease_lost", Err: errStorageEvent})
			}
			if errors.Is(stopErr, errHeartbeatShutdownTimeout) {
				_ = capture.commit()
				return
			}
			if err := s.repository.Release(r.Context(), owner); err != nil {
				s.observe(Event{Name: "release_failed", Err: errStorageEvent})
			}
			_ = capture.commit()
			return
		}
		if resp.Status == http.StatusNoContent || resp.Status == http.StatusResetContent || resp.Status == http.StatusNotModified {
			resp.Body = nil
			capture.body.Reset()
		}
		storedResponse := filterReplayHeaders(resp)
		encoded, err := s.encrypt(storedResponse, activeScope.KeyID, activeScope.Hash, s.activeResponseKeyID, action, key, activeHash.Hash)
		if err != nil {
			s.observe(Event{Name: "encrypt_failed", Err: err})
			_ = stopHeartbeat()
			capture.resetForError()
			w.Header().Set("Retry-After", "1")
			s.writeError(w, http.StatusServiceUnavailable, "could not safely persist idempotent response")
			return
		}
		state := StatusCompleted
		if resp.Status >= 400 {
			state = StatusFailed
		}
		if err := s.completeWithRetry(r.Context(), owner, state, resp.Status, s.activeResponseKeyID, encoded); err != nil {
			s.observe(Event{Name: "complete_failed", Err: errStorageEvent})
			_ = stopHeartbeat()
			if r.Context().Err() != nil {
				return
			}
			capture.resetForError()
			w.Header().Set("Retry-After", "1")
			s.writeError(w, http.StatusServiceUnavailable, "idempotency response could not be persisted; retry with the same key")
			return
		}
		_ = stopHeartbeat()
		if err := capture.commit(); err != nil {
			s.observe(Event{Name: "response_write_failed", Err: errors.New("HTTP response write failed")})
		}
		s.observe(Event{Name: "completed"})
	})
}

func (s *Service) refreshLease(ctx context.Context, owner string, stop <-chan struct{}, done chan<- struct{}, failure chan<- error, cancel context.CancelFunc) {
	defer close(done)
	interval := s.config.ProcessingTTL / 3
	if interval <= 0 {
		interval = time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			refreshCtx, cancelRefresh := context.WithTimeout(ctx, s.heartbeatOperationTimeout())
			err := s.repository.Refresh(refreshCtx, owner)
			cancelRefresh()
			if err != nil {
				failure <- err
				cancel()
				s.observe(Event{Name: "heartbeat_failed", Err: errStorageEvent})
				return
			}
		}
	}
}

func (s *Service) heartbeatOperationTimeout() time.Duration {
	timeout := s.config.ProcessingTTL / 3
	if timeout > maxHeartbeatOperationTimeout {
		return maxHeartbeatOperationTimeout
	}
	if timeout < minHeartbeatOperationTimeout {
		return minHeartbeatOperationTimeout
	}
	return timeout
}

func (s *Service) completeWithRetry(ctx context.Context, owner string, state Status, status int, responseKeyID string, response []byte) error {
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		err = s.repository.Complete(ctx, owner, state, status, responseKeyID, response, time.Now().Add(s.config.TTL))
		if err == nil || errors.Is(err, ErrNotOwner) {
			return err
		}
		if attempt < 2 {
			timer := time.NewTimer(time.Duration(attempt+1) * 50 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
	}
	return err
}

func (s *Service) writeError(w http.ResponseWriter, status int, message string) {
	if s.config.ErrorWriter != nil {
		s.config.ErrorWriter(w, status, message)
		return
	}
	writeError(w, status, message)
}

func (s *Service) observe(event Event) {
	if s.config.OnEvent != nil {
		func() { defer func() { _ = recover() }(); s.config.OnEvent(event) }()
	}
}

var replayHeaderAllowlist = map[string]struct{}{
	"content-type": {}, "content-encoding": {}, "content-language": {}, "cache-control": {},
	"etag": {}, "last-modified": {}, "location": {}, "content-disposition": {},
}

func filterReplayHeaders(response Response) Response {
	headers := make(map[string][]string)
	for name, values := range response.Header {
		canonical := http.CanonicalHeaderKey(name)
		if _, ok := replayHeaderAllowlist[strings.ToLower(canonical)]; ok {
			headers[canonical] = append([]string(nil), values...)
		}
	}
	response.Header = headers
	return response
}

func validAction(action string) bool { return action != "" && len(action) <= 100 }

func (s *Service) encrypt(response Response, scopeHashKeyID, scopeHash, responseKeyID, action, key, requestHash string) ([]byte, error) {
	plain, err := json.Marshal(cachedResponse{Status: response.Status, Header: response.Header, Body: response.Body})
	if err != nil {
		return nil, err
	}
	aead := s.responseAEAD[responseKeyID]
	nonce := make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}
	sealed := aead.Seal(nonce, nonce, plain, responseAAD(scopeHashKeyID, scopeHash, responseKeyID, action, key, requestHash))
	return []byte(base64.StdEncoding.EncodeToString(sealed)), nil
}

func (s *Service) decrypt(value []byte, scopeHashKeyID, scopeHash, responseKeyID string, format int16, action, key, requestHash string) (Response, error) {
	aead, ok := s.responseAEAD[responseKeyID]
	if !ok {
		return Response{}, errors.New("idempotency: response key version is unavailable")
	}
	sealed, err := base64.StdEncoding.DecodeString(string(value))
	if err != nil || len(sealed) < aead.NonceSize() {
		return Response{}, errors.New("invalid encrypted response")
	}
	nonce, ciphertext := sealed[:aead.NonceSize()], sealed[aead.NonceSize():]
	var plain []byte
	if format == legacyResponseFormat {
		plain, err = aead.Open(nil, nonce, ciphertext, legacyResponseAAD(scopeHash, action, key, requestHash))
	} else if format == currentResponseFormat {
		plain, err = aead.Open(nil, nonce, ciphertext, responseAAD(scopeHashKeyID, scopeHash, responseKeyID, action, key, requestHash))
	} else {
		return Response{}, errors.New("idempotency: unsupported response format")
	}
	if err != nil {
		return Response{}, err
	}
	var cached cachedResponse
	if err := json.Unmarshal(plain, &cached); err != nil {
		return Response{}, err
	}
	return Response{Status: cached.Status, Header: cached.Header, Body: cached.Body}, nil
}

func legacyResponseAAD(scopeHash, action, key, requestHash string) []byte {
	return []byte(scopeHash + "\x00" + action + "\x00" + key + "\x00" + requestHash)
}

func responseAAD(scopeHashKeyID, scopeHash, responseKeyID, action, key, requestHash string) []byte {
	return []byte(scopeHashKeyID + "\x00" + scopeHash + "\x00" + responseKeyID + "\x00" + action + "\x00" + key + "\x00" + requestHash)
}

func (s *Service) scopeHashCandidates(scope string) ([]ScopeHashCandidate, ScopeHashCandidate) {
	ids := make([]string, 0, len(s.scopeHashKeys))
	for id := range s.scopeHashKeys {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	candidates := make([]ScopeHashCandidate, 0, len(ids))
	var active ScopeHashCandidate
	for _, id := range ids {
		candidate := ScopeHashCandidate{KeyID: id, Hash: hashScope(s.scopeHashKeys[id], []byte(scope))}
		candidates = append(candidates, candidate)
		if id == s.activeScopeHashKeyID {
			active = candidate
		}
	}
	return candidates, active
}

func hashScope(key, scope []byte) string {
	keyDeriver := hmac.New(sha256.New, key)
	_, _ = keyDeriver.Write([]byte("adorbit-go:idempotency:scope-key:v1"))
	mac := hmac.New(sha256.New, keyDeriver.Sum(nil))
	_, _ = mac.Write([]byte("adorbit-go:idempotency:scope:v1\x00"))
	_, _ = mac.Write(scope)
	return fmt.Sprintf("%x", mac.Sum(nil))
}

// scopeHash returns the currently active version's hash. It is retained for
// package tests and compatibility with callers that need a diagnostic hash.
func (s *Service) scopeHash(scope string) string {
	return hashScope(s.scopeHashKeys[s.activeScopeHashKeyID], []byte(scope))
}

// ResolveLegacyIndeterminate releases a legacy unscoped key only when an
// operator can assert that its business effect definitely did not occur.
// Unknown or applied effects must remain blocked for domain-specific repair.
func (s *Service) ResolveLegacyIndeterminate(ctx context.Context, key, action, actor string, resolution string) error {
	if key == "" || len(key) > 255 || !validAction(action) || strings.TrimSpace(actor) == "" || len(actor) > 128 || resolution != ResolutionConfirmedNotApplied {
		return ErrInvalidState
	}
	resolver, ok := s.repository.(IndeterminateResolver)
	if !ok {
		return errors.New("idempotency: repository does not support indeterminate resolution")
	}
	if err := resolver.ResolveLegacyIndeterminate(ctx, key, action, actor, resolution); err != nil {
		return err
	}
	s.observe(Event{Name: "legacy_indeterminate_resolved", Actor: actor, Action: action})
	return nil
}

// ResolveIndeterminate resolves a scoped indeterminate record only after an
// operator confirms the business effect definitely did not occur. The
// repository writes a durable audit row in the same transaction as release.
func (s *Service) ResolveIndeterminate(ctx context.Context, scope, key, action, actor, resolution string) error {
	if scope == "" || strings.TrimSpace(scope) != scope || len(scope) > 1024 || key == "" || len(key) > 255 || !validAction(action) || strings.TrimSpace(actor) == "" || len(actor) > 128 || resolution != ResolutionConfirmedNotApplied {
		return ErrInvalidState
	}
	resolver, ok := s.repository.(IndeterminateResolver)
	if !ok {
		return errors.New("idempotency: repository does not support indeterminate resolution")
	}
	candidates, _ := s.scopeHashCandidates(scope)
	if err := resolver.ResolveIndeterminate(ctx, candidates, key, action, actor, resolution); err != nil {
		return err
	}
	s.observe(Event{Name: "indeterminate_resolved", Actor: actor, Action: action})
	return nil
}

// SetActiveScopeHashKey changes the database-enforced writer epoch. All
// instances must retain both key versions before calling this during cutover.
func (s *Service) SetActiveScopeHashKey(ctx context.Context, expected, next string) error {
	if _, ok := s.scopeHashKeys[next]; !ok {
		return errors.New("idempotency: new scope key is not retained by this instance")
	}
	controller, ok := s.repository.(ScopeEpochController)
	if !ok {
		return errors.New("idempotency: repository does not support scope-key cutover")
	}
	return controller.SetActiveScopeHashKey(ctx, expected, next)
}

// DeleteExpired performs one bounded cleanup batch.
func (s *Service) DeleteExpired(ctx context.Context, limit int) (int64, error) {
	n, err := s.repository.DeleteExpired(ctx, time.Now().UTC(), limit)
	if err != nil {
		s.observe(Event{Name: "cleanup_failed", Err: errStorageEvent})
		return n, err
	}
	s.observe(Event{Name: "cleanup_completed", Count: n})
	return n, nil
}
