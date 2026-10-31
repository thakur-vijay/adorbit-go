package idempotency

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"strings"

	"github.com/google/uuid"
)

type contextKey string

const (
	idempotencyKeyContext   contextKey = "idempotency_key"
	idempotencyScopeContext contextKey = "idempotency_scope"
)

// Middleware exposes key validation and service-backed idempotency protection.
type Middleware struct{ service *Service }

// NewHTTPMiddleware binds reusable idempotency behavior to the injected service.
func NewHTTPMiddleware(service *Service) *Middleware { return &Middleware{service: service} }

// NewMiddleware preserves the original key-validation-only middleware API.
func NewMiddleware() *Middleware { return &Middleware{} }

// RequireIdempotencyKey validates and stores a UUID Idempotency-Key in context.
func (m *Middleware) RequireIdempotencyKey(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Headers: %+v", r.Header)
		log.Printf("Idempotency-Key: %q", r.Header.Get("Idempotency-Key"))
		key := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
		if key == "" {
			m.writeError(w, http.StatusBadRequest, "Idempotency-Key header is required")
			return
		}
		if len(key) > 255 {
			m.writeError(w, http.StatusBadRequest, "Idempotency-Key exceeds maximum length")
			return
		}
		parsed, err := uuid.Parse(key)
		if err != nil {
			m.writeError(w, http.StatusBadRequest, "Idempotency-Key must be a valid UUID")
			return
		}
		ctx := context.WithValue(r.Context(), idempotencyKeyContext, parsed.String())
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireIdempotency protects one named operation. The key validation
// middleware must run first.
func (m *Middleware) RequireIdempotency(action string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if m == nil || m.service == nil {
			return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				writeError(w, http.StatusInternalServerError, "idempotency middleware is not configured")
			})
		}
		return m.service.Serve(action, next)
	}
}

// GetIdempotencyKey returns the validated key previously added to context.
func GetIdempotencyKey(ctx context.Context) (string, bool) {
	key, ok := ctx.Value(idempotencyKeyContext).(string)
	return key, ok
}

// WithIdempotencyScope adds a trusted principal/tenant scope to the request
// context. Call it from server-side authentication or route middleware; never
// derive the scope directly from an untrusted request header.
func WithIdempotencyScope(ctx context.Context, scope string) context.Context {
	return context.WithValue(ctx, idempotencyScopeContext, scope)
}

// GetIdempotencyScope returns the server-supplied scope for the request.
func GetIdempotencyScope(ctx context.Context) (string, bool) {
	scope, ok := ctx.Value(idempotencyScopeContext).(string)
	return scope, ok
}

func writeError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(struct {
		StatusCode int    `json:"status_code"`
		Message    string `json:"message"`
	}{StatusCode: status, Message: message})
}

func (m *Middleware) writeError(w http.ResponseWriter, status int, message string) {
	if m != nil && m.service != nil {
		m.service.writeError(w, status, message)
		return
	}
	writeError(w, status, message)
}

func writeResponse(w http.ResponseWriter, response Response) {
	for k, values := range response.Header {
		if _, ok := replayHeaderAllowlist[strings.ToLower(http.CanonicalHeaderKey(k))]; !ok {
			continue
		}
		w.Header()[http.CanonicalHeaderKey(k)] = append([]string(nil), values...)
	}
	w.WriteHeader(response.Status)
	_, _ = w.Write(response.Body)
}

type captureWriter struct {
	dst             http.ResponseWriter
	header          http.Header
	initialHeader   http.Header
	status          int
	body            bytes.Buffer
	max             int
	maxExceeded     bool
	passthrough     bool
	hijacked        bool
	committed       bool
	dstCommitted    bool
	committedHeader http.Header
}

func newCaptureWriter(dst http.ResponseWriter, max int) *captureWriter {
	initial := dst.Header().Clone()
	return &captureWriter{dst: dst, max: max, header: initial.Clone(), initialHeader: initial}
}
func (w *captureWriter) Header() http.Header { return w.header }
func (w *captureWriter) WriteHeader(code int) {
	if w.hijacked {
		return
	}
	if code < 100 || code > 999 {
		panic("invalid WriteHeader code")
	}
	if w.committed {
		return
	}
	if code >= 100 && code < 200 && code != http.StatusSwitchingProtocols {
		copyHeader(w.dst.Header(), w.header)
		w.dst.WriteHeader(code)
		return
	}
	if code == http.StatusSwitchingProtocols {
		w.passthrough = true
	}
	w.committed = true
	w.status = code
	w.committedHeader = w.header.Clone()
}

func (w *captureWriter) Push(target string, opts *http.PushOptions) error {
	if w.hijacked {
		return http.ErrNotSupported
	}
	pusher, ok := w.dst.(http.Pusher)
	if !ok {
		return http.ErrNotSupported
	}
	err := pusher.Push(target, opts)
	if err == nil {
		w.passthrough = true
		return nil
	}
	return err
}
func (w *captureWriter) Write(p []byte) (int, error) {
	if w.hijacked {
		return 0, errors.New("idempotency: HTTP response writer was hijacked")
	}
	if !w.committed {
		w.WriteHeader(http.StatusOK)
	}
	if w.passthrough {
		if err := w.commit(); err != nil {
			return 0, err
		}
		return w.dst.Write(p)
	}
	if w.body.Len()+len(p) > w.max {
		w.maxExceeded = true
		w.passthrough = true
		if err := w.commit(); err != nil {
			return 0, err
		}
		return w.dst.Write(p)
	}
	return w.body.Write(p)
}

func (w *captureWriter) commit() error {
	if w.hijacked {
		return nil
	}
	if !w.dstCommitted {
		copyHeader(w.dst.Header(), w.committedHeader)
		w.dst.WriteHeader(w.status)
		w.dstCommitted = true
		if w.body.Len() > 0 {
			if _, err := w.dst.Write(w.body.Bytes()); err != nil {
				return err
			}
		}
	}
	return nil
}

func copyHeader(dst, src http.Header) {
	for key := range dst {
		delete(dst, key)
	}
	for key, values := range src {
		dst[key] = append([]string(nil), values...)
	}
}

func (w *captureWriter) Flush() {
	if w.hijacked {
		return
	}
	w.passthrough = true
	if !w.committed {
		w.WriteHeader(http.StatusOK)
	}
	_ = w.commit()
	if flusher, ok := w.dst.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (w *captureWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := w.dst.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("response writer does not support hijacking")
	}
	conn, rw, err := hijacker.Hijack()
	if err != nil {
		return conn, rw, err
	}
	// A hijacked handler owns the raw protocol handshake (for example, HTTP 101
	// for WebSockets). Never commit the captured HTTP status before delegating.
	w.hijacked = true
	w.passthrough = true
	return conn, rw, nil
}
func (w *captureWriter) response() Response {
	if !w.committed {
		w.status = http.StatusOK
		w.committedHeader = w.header.Clone()
		w.committed = true
	}
	if w.status == 0 {
		w.status = http.StatusOK
	}
	committed := w.committedHeader
	header := make(map[string][]string, len(committed))
	for k, values := range committed {
		header[k] = append([]string(nil), values...)
	}
	return Response{Status: w.status, Header: header, Body: append([]byte(nil), w.body.Bytes()...)}
}

func (w *captureWriter) resetForError() {
	if w.dstCommitted {
		return
	}
	copyHeader(w.header, w.initialHeader)
}
