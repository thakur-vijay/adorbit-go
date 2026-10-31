package idempotency

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type memoryRepo struct {
	mu    sync.Mutex
	rows  map[string]*Record
	audit []string
}

func newMemoryRepo() *memoryRepo { return &memoryRepo{rows: make(map[string]*Record)} }
func (m *memoryRepo) Claim(_ context.Context, candidates []ScopeHashCandidate, active ScopeHashCandidate, hashes []RequestHashCandidate, activeHash RequestHashCandidate, key, action, owner string, ttl, stale time.Duration) (*Record, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	scopeHash := active.Hash
	if active.KeyID != legacyUnscopedKeyID {
		if legacy := m.rows[legacyUnscopedKeyID+":"+legacyScopeHash+":"+key+":"+action]; legacy != nil && (legacy.Status == StatusProcessing || legacy.ExpiresAt.After(time.Now())) {
			return nil, false, errLegacyScopeConflict
		}
	}
	id := active.KeyID + ":" + scopeHash + ":" + key + ":" + action
	var rec *Record
	for _, candidate := range candidates {
		if found := m.rows[candidate.KeyID+":"+candidate.Hash+":"+key+":"+action]; found != nil {
			rec = found
			break
		}
	}
	if rec != nil {
		if rec.Status == StatusProcessing && rec.UpdatedAt.Add(stale).Before(time.Now()) && !requestHashCandidateMatches(rec.RequestHashVersion, rec.RequestHash, hashes) {
			rec.Status, rec.OwnerToken, rec.UpdatedAt = StatusIndeterminate, "", time.Now()
			return nil, false, errFingerprintIndeterminate
		}
		expired := (rec.Status == StatusCompleted || rec.Status == StatusFailed) && !rec.ExpiresAt.After(time.Now())
		staleProcessing := rec.Status == StatusProcessing && requestHashCandidateMatches(rec.RequestHashVersion, rec.RequestHash, hashes) && rec.UpdatedAt.Add(stale).Before(time.Now())
		if expired || staleProcessing {
			delete(m.rows, rec.ScopeHashKeyID+":"+rec.ScopeHash+":"+key+":"+action)
			rec.ScopeHashKeyID, rec.ScopeHash = active.KeyID, active.Hash
			rec.RequestHash, rec.RequestHashVersion, rec.ResponseFormat, rec.Status, rec.OwnerToken, rec.UpdatedAt, rec.ExpiresAt = activeHash.Hash, activeHash.Version, 0, StatusProcessing, owner, time.Now(), time.Now().Add(ttl)
			m.rows[id] = rec
			copy := *rec
			return &copy, true, nil
		}
		copy := *rec
		return &copy, false, nil
	}
	rec = &Record{ScopeHash: scopeHash, ScopeHashKeyID: active.KeyID, IdempotencyKey: key, ActionType: action, RequestHash: activeHash.Hash, RequestHashVersion: activeHash.Version, Status: StatusProcessing, OwnerToken: owner, CreatedAt: time.Now(), UpdatedAt: time.Now(), ExpiresAt: time.Now().Add(ttl)}
	m.rows[id] = rec
	copy := *rec
	return &copy, true, nil
}
func (m *memoryRepo) Complete(_ context.Context, owner string, state Status, status int, responseKeyID string, body []byte, expiry time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, rec := range m.rows {
		if rec.OwnerToken == owner && rec.Status == StatusProcessing {
			rec.Status, rec.ResponseStatus, rec.ResponseKeyID, rec.ResponseFormat, rec.Response, rec.ExpiresAt = state, status, responseKeyID, currentResponseFormat, body, expiry
			return nil
		}
	}
	return ErrNotOwner
}
func (m *memoryRepo) Refresh(_ context.Context, owner string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, rec := range m.rows {
		if rec.OwnerToken == owner && rec.Status == StatusProcessing {
			rec.UpdatedAt = time.Now()
			return nil
		}
	}
	return ErrNotOwner
}
func (m *memoryRepo) Release(_ context.Context, owner string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for key, rec := range m.rows {
		if rec.OwnerToken == owner && rec.Status == StatusProcessing {
			delete(m.rows, key)
			return nil
		}
	}
	return ErrNotOwner
}
func (m *memoryRepo) DeleteExpired(_ context.Context, now time.Time, _ int) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var count int64
	for key, rec := range m.rows {
		if (rec.Status == StatusCompleted || rec.Status == StatusFailed) && !rec.ExpiresAt.After(now) {
			delete(m.rows, key)
			count++
		}
	}
	return count, nil
}

func (m *memoryRepo) ResolveLegacyIndeterminate(_ context.Context, key, action, actor, resolution string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if resolution != ResolutionConfirmedNotApplied {
		return ErrInvalidState
	}
	id := legacyUnscopedKeyID + ":" + legacyScopeHash + ":" + key + ":" + action
	if rec := m.rows[id]; rec != nil && rec.Status == StatusIndeterminate {
		delete(m.rows, id)
		m.audit = append(m.audit, actor+":"+action+":"+resolution)
		return nil
	}
	return ErrNotIndeterminate
}

func (m *memoryRepo) ResolveIndeterminate(_ context.Context, candidates []ScopeHashCandidate, key, action, actor, resolution string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if resolution != ResolutionConfirmedNotApplied {
		return ErrInvalidState
	}
	for _, candidate := range candidates {
		id := candidate.KeyID + ":" + candidate.Hash + ":" + key + ":" + action
		if rec := m.rows[id]; rec != nil && rec.Status == StatusIndeterminate {
			delete(m.rows, id)
			m.audit = append(m.audit, actor+":"+action+":"+resolution)
			return nil
		}
	}
	return ErrNotIndeterminate
}

func claimForTest(repo Repository, ctx context.Context, scopeHash, key, action, hash, owner string, ttl, stale time.Duration) (*Record, bool, error) {
	id := legacyScopeKeyID
	if scopeHash == legacyScopeHash {
		id = legacyUnscopedKeyID
	}
	candidate := ScopeHashCandidate{KeyID: id, Hash: scopeHash}
	hashCandidate := RequestHashCandidate{Version: currentRequestHashVersion, Hash: hash}
	return repo.Claim(ctx, []ScopeHashCandidate{candidate}, candidate, []RequestHashCandidate{hashCandidate}, hashCandidate, key, action, owner, ttl, stale)
}

func testService(t *testing.T, repo Repository) *Service {
	t.Helper()
	service, err := NewService(repo, Config{EncryptionKey: []byte("0123456789abcdef0123456789abcdef")})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

const testScope = "unit-test:principal-one"

func memoryRecordKey(service *Service, key, action string) string {
	return service.activeScopeHashKeyID + ":" + service.scopeHash(testScope) + ":" + key + ":" + action
}

func invoke(service *Service, key, body string, handler http.Handler) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/resource?b=2&a=1", strings.NewReader(body))
	r.Header.Set("Idempotency-Key", key)
	r = r.WithContext(WithIdempotencyScope(r.Context(), testScope))
	rw := httptest.NewRecorder()
	NewHTTPMiddleware(service).RequireIdempotencyKey(service.Serve("create", handler)).ServeHTTP(rw, r)
	return rw
}

func TestRequireIdempotencyKeyValidation(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })
	for _, tc := range []struct {
		key    string
		status int
	}{{"", 400}, {"nope", 400}} {
		r := httptest.NewRequest("POST", "/", nil)
		r.Header.Set("Idempotency-Key", tc.key)
		w := httptest.NewRecorder()
		NewMiddleware().RequireIdempotencyKey(next).ServeHTTP(w, r)
		if w.Code != tc.status || called {
			t.Fatalf("key %q: status=%d called=%v", tc.key, w.Code, called)
		}
	}
}

func TestFirstDuplicateConflictAndResponseReplay(t *testing.T) {
	repo := newMemoryRepo()
	service := testService(t, repo)
	key := "123e4567-e89b-12d3-a456-426614174000"
	calls := 0
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if got, _ := io.ReadAll(r.Body); string(got) != "payload" {
			t.Errorf("body not restored: %q", got)
		}
		w.Header().Set("Content-Type", "application/vnd.test+json")
		w.Header().Set("X-Request-ID", "request-specific")
		w.Header().Set("Set-Cookie", "session=secret")
		w.WriteHeader(201)
		_, _ = w.Write([]byte("created"))
	})
	first := invoke(service, key, "payload", h)
	second := invoke(service, key, "payload", h)
	if calls != 1 || first.Code != 201 || first.Body.String() != "created" || second.Code != 201 || second.Body.String() != "created" || second.Header().Get("Content-Type") != "application/vnd.test+json" || second.Header().Get("X-Request-ID") != "" || second.Header().Get("Set-Cookie") != "" {
		t.Fatalf("calls=%d first=%d second=%d body=%q headers=%v", calls, first.Code, second.Code, second.Body.String(), second.Header())
	}
	different := invoke(service, key, "other", h)
	if different.Code != http.StatusConflict || calls != 1 {
		t.Fatalf("different payload: status=%d calls=%d", different.Code, calls)
	}
}

func TestAuthenticatedScopesIsolateSameKeyAndPayload(t *testing.T) {
	repo := newMemoryRepo()
	service := testService(t, repo)
	key := "123e4567-e89b-12d3-a456-426614174000"
	calls := 0
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		scope, _ := GetIdempotencyScope(r.Context())
		_, _ = w.Write([]byte(scope))
	})
	request := func(scope string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/private", strings.NewReader("same"))
		r.Header.Set("Idempotency-Key", key)
		r = r.WithContext(WithIdempotencyScope(r.Context(), scope))
		w := httptest.NewRecorder()
		NewHTTPMiddleware(service).RequireIdempotencyKey(service.Serve("read", handler)).ServeHTTP(w, r)
		return w
	}
	one := request("tenant:one:user:7")
	two := request("tenant:two:user:7")
	replay := request("tenant:one:user:7")
	if calls != 2 || one.Body.String() != "tenant:one:user:7" || two.Body.String() != "tenant:two:user:7" || replay.Body.String() != one.Body.String() {
		t.Fatalf("calls=%d one=%q two=%q replay=%q", calls, one.Body.String(), two.Body.String(), replay.Body.String())
	}
	if len(repo.rows) != 2 {
		t.Fatalf("scope records=%d want 2", len(repo.rows))
	}
	for _, record := range repo.rows {
		if strings.Contains(record.ScopeHash, "tenant:") || strings.Contains(record.ScopeHash, "user:") {
			t.Fatalf("raw principal scope was stored: %q", record.ScopeHash)
		}
	}
}

func TestIdempotencyScopeIsRequired(t *testing.T) {
	service := testService(t, newMemoryRepo())
	calls := 0
	r := httptest.NewRequest(http.MethodPost, "/private", strings.NewReader("body"))
	r.Header.Set("Idempotency-Key", "123e4567-e89b-12d3-a456-426614174000")
	w := httptest.NewRecorder()
	NewHTTPMiddleware(service).RequireIdempotencyKey(service.Serve("write", http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls++ }))).ServeHTTP(w, r)
	if w.Code != http.StatusInternalServerError || calls != 0 {
		t.Fatalf("status=%d handler calls=%d", w.Code, calls)
	}
}

func TestLegacyUnscopedResponseBlocksExecutionWithoutReplayingAcrossPrincipals(t *testing.T) {
	repo := newMemoryRepo()
	key := "123e4567-e89b-12d3-a456-426614174000"
	request := httptest.NewRequest(http.MethodPost, "/resource?b=2&a=1", strings.NewReader("payload"))
	hash, err := HashRequest(request, "create", 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	_, claimed, err := claimForTest(repo, context.Background(), legacyScopeHash, key, "create", hash, "old-owner", time.Hour, time.Minute)
	if err != nil || !claimed {
		t.Fatalf("legacy seed claim=%v err=%v", claimed, err)
	}
	if err := repo.Complete(context.Background(), "old-owner", StatusCompleted, 201, "legacy-v1", []byte("legacy-ciphertext"), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	service := testService(t, repo)
	calls := 0
	h := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls++ })
	if got := invoke(service, key, "payload", h); got.Code != http.StatusConflict || calls != 0 {
		t.Fatalf("legacy collision status=%d calls=%d", got.Code, calls)
	}
	repo.mu.Lock()
	repo.rows[legacyUnscopedKeyID+":"+legacyScopeHash+":"+key+":create"].ExpiresAt = time.Now().Add(-time.Second)
	repo.mu.Unlock()
	if _, err := service.DeleteExpired(context.Background(), 10); err != nil {
		t.Fatal(err)
	}
	if got := invoke(service, key, "payload", h); got.Code != http.StatusOK || calls != 1 {
		t.Fatalf("after legacy expiry status=%d calls=%d", got.Code, calls)
	}
}

func TestReplayKeepsCurrentRequestCorsAndRequestID(t *testing.T) {
	service := testService(t, newMemoryRepo())
	key := "123e4567-e89b-12d3-a456-426614174000"
	calls := 0
	handler := service.Serve("create", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{}"))
	}))
	protected := NewHTTPMiddleware(service).RequireIdempotencyKey(handler)
	request := func(origin, requestID string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/resource", strings.NewReader(""))
		r.Header.Set("Idempotency-Key", key)
		r.Header.Set("Origin", origin)
		r = r.WithContext(WithIdempotencyScope(r.Context(), testScope))
		w := httptest.NewRecorder()
		corsAndRequestID := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
			w.Header().Set("X-Request-ID", requestID)
			protected.ServeHTTP(w, r)
		})
		corsAndRequestID.ServeHTTP(w, r)
		return w
	}
	first := request("https://one.example", "req-one")
	second := request("https://two.example", "req-two")
	if calls != 1 || first.Header().Get("Access-Control-Allow-Origin") != "https://one.example" || second.Header().Get("Access-Control-Allow-Origin") != "https://two.example" || second.Header().Get("X-Request-ID") != "req-two" {
		t.Fatalf("calls=%d first=%v second=%v", calls, first.Header(), second.Header())
	}
}

func TestConcurrentIdenticalRequestsRunOnce(t *testing.T) {
	service := testService(t, newMemoryRepo())
	key := "123e4567-e89b-12d3-a456-426614174000"
	var calls int
	var mu sync.Mutex
	entered := make(chan struct{})
	release := make(chan struct{})
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		calls++
		mu.Unlock()
		close(entered)
		<-release
		w.WriteHeader(200)
		_, _ = w.Write([]byte("ok"))
	})
	first := make(chan *httptest.ResponseRecorder, 1)
	go func() { first <- invoke(service, key, "same", h) }()
	<-entered
	duplicate := invoke(service, key, "same", h)
	if duplicate.Code != http.StatusConflict {
		t.Fatalf("processing duplicate status=%d", duplicate.Code)
	}
	close(release)
	if got := <-first; got.Code != http.StatusOK {
		t.Fatalf("first status=%d", got.Code)
	}
	if calls != 1 {
		t.Fatalf("handler called %d times", calls)
	}
}

func TestConcurrentDifferentPayloadConflicts(t *testing.T) {
	service := testService(t, newMemoryRepo())
	key := "123e4567-e89b-12d3-a456-426614174000"
	entered := make(chan struct{})
	release := make(chan struct{})
	calls := 0
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls++; close(entered); <-release; w.WriteHeader(200) })
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- invoke(service, key, "first", h) }()
	<-entered
	conflict := invoke(service, key, "different", h)
	close(release)
	<-done
	if conflict.Code != http.StatusConflict || calls != 1 {
		t.Fatalf("status=%d calls=%d", conflict.Code, calls)
	}
}

type failingRepo struct{ Repository }

func (f failingRepo) Claim(context.Context, []ScopeHashCandidate, ScopeHashCandidate, []RequestHashCandidate, RequestHashCandidate, string, string, string, time.Duration, time.Duration) (*Record, bool, error) {
	return nil, false, errors.New("database unavailable")
}

func TestStorageFailureDoesNotRunHandler(t *testing.T) {
	service := testService(t, failingRepo{Repository: newMemoryRepo()})
	calls := 0
	w := invoke(service, "123e4567-e89b-12d3-a456-426614174000", "", http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls++ }))
	if w.Code != http.StatusServiceUnavailable || calls != 0 {
		t.Fatalf("status=%d calls=%d", w.Code, calls)
	}
}

type refreshFailRepo struct{ Repository }

func (f refreshFailRepo) Refresh(context.Context, string) error {
	return errors.New("temporary refresh failure")
}

func TestHeartbeatFailureCancelsHandlerAndFailsClosed(t *testing.T) {
	events := make(chan Event, 8)
	service, err := NewService(refreshFailRepo{Repository: newMemoryRepo()}, Config{EncryptionKey: []byte("0123456789abcdef0123456789abcdef"), ProcessingTTL: 30 * time.Millisecond, OnEvent: func(e Event) { events <- e }})
	if err != nil {
		t.Fatal(err)
	}
	key := "123e4567-e89b-12d3-a456-426614174000"
	w := invoke(service, key, "", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
		_, _ = w.Write([]byte("must not be sent"))
	}))
	if w.Code != http.StatusServiceUnavailable || strings.Contains(w.Body.String(), "must not be sent") {
		t.Fatalf("status=%d body=%q", w.Code, w.Body.String())
	}
	seenFailure, seenLost := false, false
	for len(events) > 0 {
		switch (<-events).Name {
		case "heartbeat_failed":
			seenFailure = true
		case "lease_lost":
			seenLost = true
		}
	}
	if !seenFailure || !seenLost {
		t.Fatalf("heartbeat observations: failed=%v lost=%v", seenFailure, seenLost)
	}
}

type blockedRefreshRepo struct {
	Repository
	entered    chan struct{}
	cancelled  chan struct{}
	unblock    chan struct{}
	finished   chan struct{}
	once       sync.Once
	cancelOnce sync.Once
	finishOnce sync.Once
}

func (r *blockedRefreshRepo) Refresh(ctx context.Context, owner string) error {
	r.once.Do(func() { close(r.entered) })
	go func() { <-ctx.Done(); r.cancelOnce.Do(func() { close(r.cancelled) }) }()
	<-r.unblock // intentionally ignores ctx until the test releases it
	defer r.finishOnce.Do(func() { close(r.finished) })
	return r.Repository.Refresh(ctx, owner)
}

func TestStopHeartbeatIsBoundedWhenRefreshBlocks(t *testing.T) {
	base := newMemoryRepo()
	repo := &blockedRefreshRepo{Repository: base, entered: make(chan struct{}), cancelled: make(chan struct{}), unblock: make(chan struct{}), finished: make(chan struct{})}
	events := make(chan Event, 8)
	service, err := NewService(repo, Config{EncryptionKey: []byte("0123456789abcdef0123456789abcdef"), ProcessingTTL: 30 * time.Millisecond, OnEvent: func(e Event) { events <- e }})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		done <- invoke(service, "123e4567-e89b-12d3-a456-426614174000", "", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { <-repo.entered; _, _ = w.Write([]byte("ok")) }))
	}()
	started := time.Now()
	var response *httptest.ResponseRecorder
	select {
	case response = <-done:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("middleware waited indefinitely for blocked Refresh")
	}
	if response.Code != http.StatusOK || response.Body.String() != "ok" {
		t.Fatalf("response status=%d body=%q", response.Code, response.Body.String())
	}
	if time.Since(started) > 250*time.Millisecond {
		t.Fatal("heartbeat shutdown exceeded its bound")
	}
	select {
	case <-repo.cancelled:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("lease context was not cancelled during shutdown")
	}
	seenTimeout := false
	for len(events) > 0 {
		if (<-events).Name == "heartbeat_shutdown_timeout" {
			seenTimeout = true
		}
	}
	if !seenTimeout {
		t.Fatal("expected heartbeat_shutdown_timeout observation")
	}
	select {
	case <-repo.finished:
		t.Fatal("context-ignoring Refresh unexpectedly terminated before its blocker was released")
	default:
		// Shutdown is bounded, but a repository that ignores context can outlive it.
	}
	close(repo.unblock)
	select {
	case <-repo.finished:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("blocked fake Refresh did not finish after release")
	}
}

func TestBlockedRefreshTimeoutDoesNotReleaseProcessingLease(t *testing.T) {
	repo := &blockedRefreshRepo{Repository: newMemoryRepo(), entered: make(chan struct{}), cancelled: make(chan struct{}), unblock: make(chan struct{}), finished: make(chan struct{})}
	service, err := NewService(repo, Config{EncryptionKey: []byte("0123456789abcdef0123456789abcdef"), ProcessingTTL: 30 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	key := "123e4567-e89b-12d3-a456-426614174000"
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		done <- invoke(service, key, "", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			<-repo.entered
			http.Error(w, "temporary", http.StatusServiceUnavailable)
		}))
	}()
	select {
	case <-repo.entered:
	case <-time.After(time.Second):
		t.Fatal("Refresh was not started")
	}
	select {
	case w := <-done:
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("status=%d", w.Code)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("handler shutdown did not return")
	}
	if row := repo.Repository.(*memoryRepo).rows[memoryRecordKey(service, key, "create")]; row == nil || row.Status != StatusProcessing {
		t.Fatalf("lease was released while Refresh remained blocked: %+v", row)
	}
	close(repo.unblock)
	select {
	case <-repo.finished:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("blocked Refresh did not exit after release")
	}
}

type restoredRefreshRepo struct {
	Repository
	fail atomic.Bool
}

func (r *restoredRefreshRepo) Refresh(ctx context.Context, owner string) error {
	if r.fail.Load() {
		return errors.New("database unavailable")
	}
	return r.Repository.Refresh(ctx, owner)
}

func TestRetryRecoversAfterHeartbeatConnectivityReturns(t *testing.T) {
	base := newMemoryRepo()
	repo := &restoredRefreshRepo{Repository: base}
	repo.fail.Store(true)
	service, err := NewService(repo, Config{EncryptionKey: []byte("0123456789abcdef0123456789abcdef"), ProcessingTTL: 30 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	key := "123e4567-e89b-12d3-a456-426614174000"
	calls := 0
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			<-r.Context().Done()
			return
		}
		_, _ = w.Write([]byte("recovered"))
	})
	if first := invoke(service, key, "", h); first.Code != http.StatusServiceUnavailable {
		t.Fatalf("first response=%d", first.Code)
	}
	base.mu.Lock()
	base.rows[memoryRecordKey(service, key, "create")].UpdatedAt = time.Now().Add(-time.Hour)
	base.mu.Unlock()
	repo.fail.Store(false)
	if second := invoke(service, key, "", h); second.Code != http.StatusOK || second.Body.String() != "recovered" || calls != 2 {
		t.Fatalf("status=%d body=%q calls=%d", second.Code, second.Body.String(), calls)
	}
}

func TestCancelledRequestRetainsProcessingLeaseAndDoesNotPersist(t *testing.T) {
	repo := newMemoryRepo()
	service := testService(t, repo)
	key := "123e4567-e89b-12d3-a456-426614174000"
	r, cancel := context.WithCancel(context.Background())
	request := httptest.NewRequest(http.MethodPost, "/resource", strings.NewReader("body")).WithContext(r)
	request.Header.Set("Idempotency-Key", key)
	request = request.WithContext(WithIdempotencyScope(request.Context(), testScope))
	entered := make(chan struct{})
	done := make(chan *httptest.ResponseRecorder, 1)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-r.Context().Done()
		w.WriteHeader(201)
		_, _ = w.Write([]byte("must not persist"))
	})
	wrapped := NewHTTPMiddleware(service).RequireIdempotencyKey(service.Serve("create", handler))
	go func() { w := httptest.NewRecorder(); wrapped.ServeHTTP(w, request); done <- w }()
	<-entered
	cancel()
	w := <-done
	if w.Body.Len() != 0 {
		t.Fatalf("cancelled response body was sent: %q", w.Body.String())
	}
	row := repo.rows[memoryRecordKey(service, key, "create")]
	if row == nil || row.Status != StatusProcessing || len(row.Response) != 0 {
		t.Fatalf("cancelled operation state=%+v", row)
	}
	if retry := invoke(service, key, "body", http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("retry overlapped the cancelled handler") })); retry.Code != http.StatusConflict {
		t.Fatalf("immediate retry status=%d", retry.Code)
	}
}

func TestCommittedResponseIsNotReplacedAfterHeartbeatLoss(t *testing.T) {
	for _, mode := range []string{"flush", "large", "hijack"} {
		t.Run(mode, func(t *testing.T) {
			repo := newMemoryRepo()
			service, err := NewService(refreshFailRepo{Repository: repo}, Config{EncryptionKey: []byte("0123456789abcdef0123456789abcdef"), ProcessingTTL: 30 * time.Millisecond, MaxResponseBytes: 4})
			if err != nil {
				t.Fatal(err)
			}
			key := "123e4567-e89b-12d3-a456-426614174000"
			entered := make(chan struct{})
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if mode == "flush" {
					_, _ = w.Write([]byte("prefix"))
					w.(http.Flusher).Flush()
				}
				if mode == "large" {
					_, _ = w.Write([]byte("prefix"))
				}
				var hijacked *bufio.ReadWriter
				if mode == "hijack" {
					_, rw, e := w.(http.Hijacker).Hijack()
					if e != nil {
						t.Error(e)
					}
					hijacked = rw
					_, _ = hijacked.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
					_ = hijacked.Flush()
				}
				close(entered)
				<-r.Context().Done()
				if hijacked != nil {
					_, _ = hijacked.WriteString("socket-data")
					_ = hijacked.Flush()
				} else {
					_, _ = w.Write([]byte("suffix"))
				}
			})
			done := make(chan *fakeHijacker, 1)
			go func() { done <- invokeWithWriter(service, key, handler) }()
			<-entered
			w := <-done
			if mode == "hijack" && w.headerCalls != 0 {
				t.Fatalf("hijack response writer committed HTTP status %v", w.headerCalls)
			}
			if mode == "hijack" && !strings.HasPrefix(w.handshake.String(), "HTTP/1.1 101 Switching Protocols\r\n") {
				t.Fatalf("WebSocket handshake was not written through the hijacked connection: %q", w.handshake.String())
			}
			if mode != "hijack" && w.Code == http.StatusServiceUnavailable {
				t.Fatalf("already committed response was replaced: %q", w.Body.String())
			}
			if row := repo.rows[memoryRecordKey(service, key, "create")]; row == nil || row.Status != StatusProcessing {
				t.Fatalf("lease was released after committed lease loss: %+v", row)
			}
		})
	}
}

type completeFailRepo struct{ Repository }

func (f completeFailRepo) Complete(context.Context, string, Status, int, string, []byte, time.Time) error {
	return errors.New("database unavailable")
}

func TestResponseIsNotSentBeforeCompletionPersists(t *testing.T) {
	service := testService(t, completeFailRepo{Repository: newMemoryRepo()})
	calls := 0
	key := "123e4567-e89b-12d3-a456-426614174000"
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(201)
		_, _ = w.Write([]byte("business result"))
	})
	w := invoke(service, key, "", h)
	if w.Code != http.StatusServiceUnavailable || strings.Contains(w.Body.String(), "business result") || calls != 1 {
		t.Fatalf("status=%d body=%q calls=%d", w.Code, w.Body.String(), calls)
	}
	second := invoke(service, key, "", h)
	if second.Code != http.StatusConflict || calls != 1 {
		t.Fatalf("retry status=%d calls=%d", second.Code, calls)
	}
}

func TestResponseCaptureWriteHeaderAndImplicitStatus(t *testing.T) {
	dst := httptest.NewRecorder()
	capture := newCaptureWriter(dst, 64)
	capture.Header().Set("Content-Type", "text/plain")
	capture.WriteHeader(201)
	capture.WriteHeader(202)
	_, _ = capture.Write([]byte("done"))
	resp := capture.response()
	if resp.Status != 201 || string(resp.Body) != "done" || dst.Body.Len() != 0 {
		t.Fatalf("captured=%+v sent=%q", resp, dst.Body.String())
	}
	if err := capture.commit(); err != nil || dst.Code != 201 || dst.Body.String() != "done" {
		t.Fatalf("commit err=%v code=%d body=%q", err, dst.Code, dst.Body.String())
	}
	implicit := newCaptureWriter(httptest.NewRecorder(), 64)
	_, _ = implicit.Write([]byte("ok"))
	if got := implicit.response(); got.Status != 200 {
		t.Fatalf("implicit status=%d", got.Status)
	}
}

type fakeHijacker struct {
	*httptest.ResponseRecorder
	handshake   bytes.Buffer
	headerCalls int
}

func (w *fakeHijacker) WriteHeader(status int) {
	w.headerCalls++
	w.ResponseRecorder.WriteHeader(status)
}

func (w *fakeHijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return nil, bufio.NewReadWriter(bufio.NewReader(strings.NewReader("")), bufio.NewWriter(&w.handshake)), nil
}

func TestHijackedAndNoContentResponses(t *testing.T) {
	key := "123e4567-e89b-12d3-a456-426614174000"
	t.Run("hijack", func(t *testing.T) {
		service := testService(t, newMemoryRepo())
		calls := 0
		h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			calls++
			_, rw, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
			}
			_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
			_ = rw.Flush()
		})
		one, two := invokeWithWriter(service, key, h), invokeWithWriter(service, key, h)
		if calls != 2 || one.headerCalls != 0 || two.headerCalls != 0 || one.Body.Len() != 0 || two.Body.Len() != 0 || !strings.HasPrefix(one.handshake.String(), "HTTP/1.1 101 Switching Protocols\r\n") || !strings.HasPrefix(two.handshake.String(), "HTTP/1.1 101 Switching Protocols\r\n") {
			t.Fatalf("calls=%d headers=%d/%d bodies=%q/%q handshakes=%q/%q", calls, one.headerCalls, two.headerCalls, one.Body.String(), two.Body.String(), one.handshake.String(), two.handshake.String())
		}
	})
	t.Run("204", func(t *testing.T) {
		service := testService(t, newMemoryRepo())
		calls := 0
		h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			calls++
			w.WriteHeader(http.StatusNoContent)
			_, _ = w.Write([]byte("invalid body"))
		})
		one, two := invoke(service, key, "", h), invoke(service, key, "", h)
		if calls != 1 || one.Code != 204 || two.Code != 204 || one.Body.Len() != 0 || two.Body.Len() != 0 {
			t.Fatalf("calls=%d first=%d/%q second=%d/%q", calls, one.Code, one.Body.String(), two.Code, two.Body.String())
		}
	})
}

func invokeWithWriter(service *Service, key string, handler http.Handler) *fakeHijacker {
	w := &fakeHijacker{ResponseRecorder: httptest.NewRecorder()}
	request := httptest.NewRequest(http.MethodPost, "/resource", strings.NewReader(""))
	request.Header.Set("Idempotency-Key", key)
	request = request.WithContext(WithIdempotencyScope(request.Context(), testScope))
	wrapped := NewHTTPMiddleware(service).RequireIdempotencyKey(service.Serve("create", handler))
	wrapped.ServeHTTP(w, request)
	return w
}

func TestOversizedAndFlushedResponsesAreDeliveredButNotCached(t *testing.T) {
	key := "123e4567-e89b-12d3-a456-426614174000"
	for _, mode := range []string{"large", "flush"} {
		t.Run(mode, func(t *testing.T) {
			repo := newMemoryRepo()
			service, err := NewService(repo, Config{EncryptionKey: []byte("0123456789abcdef0123456789abcdef"), MaxResponseBytes: 4})
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls++
				if mode == "large" {
					_, _ = w.Write([]byte("abcdef"))
					return
				}
				_, _ = w.Write([]byte("one"))
				w.(http.Flusher).Flush()
				_, _ = w.Write([]byte("two"))
			})
			first, second := invoke(service, key, "", handler), invoke(service, key, "", handler)
			if first.Body.String() == "" || second.Body.String() != first.Body.String() || calls != 2 {
				t.Fatalf("calls=%d first=%q second=%q", calls, first.Body.String(), second.Body.String())
			}
		})
	}
}

func TestPostgresRepositoryNilReceiverErrors(t *testing.T) {
	var repo *PostgresRepository
	ctx := context.Background()
	now := time.Now()
	if _, _, err := claimForTest(repo, ctx, strings.Repeat("s", 64), "key", "action", strings.Repeat("a", 64), "owner", time.Hour, time.Minute); !errors.Is(err, ErrNilDatabase) {
		t.Fatalf("Claim: %v", err)
	}
	if err := repo.Complete(ctx, "owner", StatusCompleted, 200, "legacy-v1", []byte("x"), now.Add(time.Hour)); !errors.Is(err, ErrNilDatabase) {
		t.Fatalf("Complete: %v", err)
	}
	if err := repo.Refresh(ctx, "owner"); !errors.Is(err, ErrNilDatabase) {
		t.Fatalf("Refresh: %v", err)
	}
	if err := repo.Release(ctx, "owner"); !errors.Is(err, ErrNilDatabase) {
		t.Fatalf("Release: %v", err)
	}
	if _, err := repo.DeleteExpired(ctx, now, 10); !errors.Is(err, ErrNilDatabase) {
		t.Fatalf("DeleteExpired: %v", err)
	}
}

func TestServiceConfigurationValidation(t *testing.T) {
	for _, config := range []Config{
		{EncryptionKey: []byte("0123456789abcdef0123456789abcdef"), TTL: -time.Second},
		{EncryptionKey: []byte("0123456789abcdef0123456789abcdef"), ProcessingTTL: -time.Second},
		{EncryptionKey: []byte("0123456789abcdef0123456789abcdef"), ProcessingTTL: time.Millisecond},
		{EncryptionKey: []byte("0123456789abcdef0123456789abcdef"), MaxRequestBytes: -1},
		{EncryptionKey: []byte("0123456789abcdef0123456789abcdef"), MaxResponseBytes: -1},
		{EncryptionKey: []byte("short")},
		{EncryptionKey: []byte("0123456789abcdef0123456789abcdef"), MaxRequestBytes: maxRequestBytes + 1},
		{EncryptionKey: []byte("0123456789abcdef0123456789abcdef"), MaxResponseBytes: maxResponseBytes + 1},
		{EncryptionKey: []byte("0123456789abcdef0123456789abcdef"), TTL: maxResultTTL + time.Second},
		{EncryptionKey: []byte("0123456789abcdef0123456789abcdef"), ProcessingTTL: maxProcessingTTL + time.Second},
	} {
		if _, err := NewService(newMemoryRepo(), config); err == nil {
			t.Fatalf("invalid config accepted: %+v", config)
		}
	}
}

func TestTerminalStatusStateValidationIncludesRedirects(t *testing.T) {
	for _, tc := range []struct {
		state Status
		code  int
		valid bool
	}{{StatusCompleted, 302, true}, {StatusFailed, 422, true}, {StatusCompleted, 400, false}, {StatusFailed, 500, false}, {StatusProcessing, 200, false}, {StatusCompleted, 199, false}, {StatusFailed, 600, false}} {
		if got := validTerminalState(tc.state, tc.code); got != tc.valid {
			t.Errorf("validTerminalState(%q,%d)=%v want %v", tc.state, tc.code, got, tc.valid)
		}
	}
}

func TestHashRequestRejectsOverflowingLimitBeforeReading(t *testing.T) {
	r := httptest.NewRequest("POST", "/", strings.NewReader("body"))
	maxInt64 := int64(^uint64(0) >> 1)
	if _, err := HashRequest(r, "action", maxInt64); !errors.Is(err, errInvalidHashLimit) {
		t.Fatalf("limit error=%v", err)
	}
	body, err := io.ReadAll(r.Body)
	if err != nil || string(body) != "body" {
		t.Fatalf("body=%q err=%v", body, err)
	}
}

func TestTransientServerErrorCanRetry(t *testing.T) {
	service := testService(t, newMemoryRepo())
	key := "123e4567-e89b-12d3-a456-426614174000"
	calls := 0
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		if calls == 1 {
			http.Error(w, "temporary", 503)
			return
		}
		_, _ = w.Write([]byte("ok"))
	})
	if got := invoke(service, key, "", h); got.Code != 503 {
		t.Fatal(got.Code)
	}
	if got := invoke(service, key, "", h); got.Code != 200 || calls != 2 {
		t.Fatalf("status=%d calls=%d", got.Code, calls)
	}
}

func TestRedirectResponseIsReplayable(t *testing.T) {
	service := testService(t, newMemoryRepo())
	key := "123e4567-e89b-12d3-a456-426614174000"
	calls := 0
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; http.Redirect(w, r, "/next", http.StatusFound) })
	one, two := invoke(service, key, "", h), invoke(service, key, "", h)
	if calls != 1 || one.Code != http.StatusFound || two.Code != http.StatusFound || one.Header().Get("Location") != "/next" || two.Header().Get("Location") != "/next" || two.Body.String() != one.Body.String() {
		t.Fatalf("calls=%d first=%d second=%d headers=%v", calls, one.Code, two.Code, two.Header())
	}
}

func TestTerminalFailureIsReplayedAndEncrypted(t *testing.T) {
	repo := newMemoryRepo()
	service := testService(t, repo)
	key := "123e4567-e89b-12d3-a456-426614174000"
	calls := 0
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Reason", "request-specific")
		http.Error(w, "business failure", http.StatusUnprocessableEntity)
	})
	first := invoke(service, key, "", h)
	second := invoke(service, key, "", h)
	if first.Code != 422 || second.Code != 422 || calls != 1 || second.Header().Get("Cache-Control") != "no-store" || second.Header().Get("X-Reason") != "" || second.Body.String() != first.Body.String() {
		t.Fatalf("first=%d second=%d calls=%d", first.Code, second.Code, calls)
	}
	for _, rec := range repo.rows {
		if strings.Contains(string(rec.Response), "business failure") {
			t.Fatal("response was stored in plaintext")
		}
		if _, err := service.decrypt(rec.Response, rec.ScopeHashKeyID, rec.ScopeHash+"different", rec.ResponseKeyID, rec.ResponseFormat, rec.ActionType, rec.IdempotencyKey, rec.RequestHash); err == nil {
			t.Fatal("response ciphertext was not bound to its idempotency record")
		}
	}
}

func TestStaleV1FingerprintBecomesIndeterminate(t *testing.T) {
	repo := newMemoryRepo()
	key := "123e4567-e89b-12d3-a456-426614174000"
	service := testService(t, repo)
	req := httptest.NewRequest(http.MethodPost, "/resource?b=2&a=1", strings.NewReader("new"))
	hash, _ := HashRequest(req, "create", 1<<20)
	repo.rows[memoryRecordKey(service, key, "create")] = &Record{ScopeHash: service.scopeHash(testScope), ScopeHashKeyID: service.activeScopeHashKeyID, RequestHashVersion: legacyRequestHashVersion, IdempotencyKey: key, ActionType: "create", RequestHash: hash, Status: StatusProcessing, OwnerToken: "old-owner", UpdatedAt: time.Now().Add(-time.Hour), ExpiresAt: time.Now().Add(time.Hour)}
	calls := 0
	w := invoke(service, key, "new", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls++; _, _ = w.Write([]byte("recovered")) }))
	if w.Code != http.StatusConflict || calls != 0 {
		t.Fatalf("status=%d calls=%d", w.Code, calls)
	}
	repo.mu.Lock()
	row := repo.rows[memoryRecordKey(service, key, "create")]
	state := row.Status
	repo.mu.Unlock()
	if state != StatusIndeterminate {
		t.Fatalf("legacy fingerprint state=%s", state)
	}
}

func TestStaleProcessingWithDifferentHashConflicts(t *testing.T) {
	repo := newMemoryRepo()
	service := testService(t, repo)
	key := "123e4567-e89b-12d3-a456-426614174000"
	repo.rows[memoryRecordKey(service, key, "create")] = &Record{ScopeHash: service.scopeHash(testScope), ScopeHashKeyID: service.activeScopeHashKeyID, RequestHashVersion: currentRequestHashVersion, IdempotencyKey: key, ActionType: "create", RequestHash: strings.Repeat("a", 64), Status: StatusProcessing, OwnerToken: "still-owned", UpdatedAt: time.Now().Add(-time.Hour), ExpiresAt: time.Now().Add(time.Hour)}
	calls := 0
	w := invoke(service, key, "different", http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls++ }))
	if w.Code != http.StatusConflict || calls != 0 {
		t.Fatalf("status=%d calls=%d", w.Code, calls)
	}
	repo.mu.Lock()
	state := repo.rows[memoryRecordKey(service, key, "create")].Status
	repo.mu.Unlock()
	if state != StatusIndeterminate {
		t.Fatalf("stale mismatched request was not made indeterminate: %s", state)
	}
}

func TestHashRequestRestoresBodyAndCanonicalQuery(t *testing.T) {
	a := httptest.NewRequest("POST", "/x?b=2&a=1", strings.NewReader("body"))
	b := httptest.NewRequest("POST", "/x?a=1&b=2", strings.NewReader("body"))
	ha, err := HashRequest(a, "action", 100)
	if err != nil {
		t.Fatal(err)
	}
	hb, err := HashRequest(b, "action", 100)
	if err != nil {
		t.Fatal(err)
	}
	if ha != hb {
		t.Fatal("equivalent queries should hash identically")
	}
	c := httptest.NewRequest("PUT", "/x?a=1&b=2", strings.NewReader("body"))
	hc, err := HashRequest(c, "action", 100)
	if err != nil {
		t.Fatal(err)
	}
	if hc == ha {
		t.Fatal("method must participate in the request hash")
	}
	d := httptest.NewRequest("POST", "/different?a=1&b=2", strings.NewReader("body"))
	hd, err := HashRequest(d, "action", 100)
	if err != nil {
		t.Fatal(err)
	}
	if hd == ha {
		t.Fatal("path must participate in the request hash")
	}
	e := httptest.NewRequest("POST", "/x?a=1&b=2", strings.NewReader("body"))
	e.Header.Set("Content-Type", "application/json")
	he, err := HashRequest(e, "action", 100)
	if err != nil {
		t.Fatal(err)
	}
	if he == ha {
		t.Fatal("content type must participate in the request hash")
	}
	buf := make([]byte, 4)
	n, _ := a.Body.Read(buf)
	if string(buf[:n]) != "body" {
		t.Fatalf("restored body=%q", buf[:n])
	}
}

type partialErrorBody struct{ done bool }

func (b *partialErrorBody) Read(p []byte) (int, error) {
	if !b.done {
		b.done = true
		copy(p, "part")
		return 4, errors.New("read failed")
	}
	return 0, io.EOF
}
func (b *partialErrorBody) Close() error { return nil }

func TestHashRequestRestoresBodyAfterReadErrorAndLimit(t *testing.T) {
	r := httptest.NewRequest("POST", "/", nil)
	r.Body = &partialErrorBody{}
	if _, err := HashRequest(r, "a", 20); err == nil {
		t.Fatal("expected read error")
	}
	body, err := io.ReadAll(r.Body)
	if err != nil || string(body) != "part" {
		t.Fatalf("restored body=%q err=%v", body, err)
	}
	large := httptest.NewRequest("POST", "/", strings.NewReader("0123456789"))
	if _, err := HashRequest(large, "a", 4); !errors.Is(err, errRequestTooLarge) {
		t.Fatalf("oversize err=%v", err)
	}
	body, err = io.ReadAll(large.Body)
	if err != nil || string(body) != "0123456789" {
		t.Fatalf("restored oversized body=%q err=%v", body, err)
	}
}

func TestExpiredRowsAreCleaned(t *testing.T) {
	repo := newMemoryRepo()
	rec := &Record{IdempotencyKey: "k", ActionType: "a", Status: StatusCompleted, ExpiresAt: time.Now().Add(-time.Second)}
	repo.rows[strings.Repeat("s", 64)+":k:a"] = rec
	n, err := repo.DeleteExpired(context.Background(), time.Now(), 10)
	if err != nil || n != 1 {
		t.Fatalf("deleted=%d err=%v", n, err)
	}
}

func TestExpiredProcessingLeaseCannotBeReclaimedOrCleanedWhileRecent(t *testing.T) {
	repo := newMemoryRepo()
	key := "expired-processing"
	scopeHash := strings.Repeat("s", 64)
	repo.rows[legacyScopeKeyID+":"+scopeHash+":"+key+":create"] = &Record{ScopeHash: scopeHash, ScopeHashKeyID: legacyScopeKeyID, RequestHashVersion: currentRequestHashVersion, IdempotencyKey: key, ActionType: "create", RequestHash: strings.Repeat("a", 64), Status: StatusProcessing, OwnerToken: "owner-one", UpdatedAt: time.Now(), ExpiresAt: time.Now().Add(-time.Second)}
	if _, claimed, err := claimForTest(repo, context.Background(), scopeHash, key, "create", strings.Repeat("a", 64), "owner-two", time.Hour, time.Minute); err != nil || claimed {
		t.Fatalf("active expired processing claimed=%v err=%v", claimed, err)
	}
	deleted, err := repo.DeleteExpired(context.Background(), time.Now(), 10)
	if err != nil || deleted != 0 {
		t.Fatalf("active processing cleanup deleted=%d err=%v", deleted, err)
	}
}

func TestKeyRotationReadsOldScopeAndResponseKeys(t *testing.T) {
	repo := newMemoryRepo()
	legacy := []byte("0123456789abcdef0123456789abcdef")
	newScope := []byte("scope-key-v2-0123456789abcdefghi")
	newResponse := []byte("response-key-v2-material-1234567")
	oldService, err := NewService(repo, Config{EncryptionKey: legacy})
	if err != nil {
		t.Fatal(err)
	}
	key := "123e4567-e89b-12d3-a456-426614174010"
	calls := 0
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(201)
		_, _ = w.Write([]byte("saved"))
	})
	if got := invoke(oldService, key, "payload", h); got.Code != 201 {
		t.Fatalf("initial status=%d", got.Code)
	}
	rotated, err := NewService(repo, Config{
		ScopeHashKeys: []KeyMaterial{{ID: "legacy-v1", Key: legacy}, {ID: "scope-v2", Key: newScope}}, ActiveScopeHashKeyID: "scope-v2",
		ResponseEncryptionKeys: []KeyMaterial{{ID: "legacy-v1", Key: legacy}, {ID: "response-v2", Key: newResponse}}, ActiveResponseKeyID: "response-v2",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := invoke(rotated, key, "payload", h); got.Code != 201 || got.Body.String() != "saved" || calls != 1 {
		t.Fatalf("old-key replay status=%d body=%q calls=%d", got.Code, got.Body.String(), calls)
	}
	newKey := "123e4567-e89b-12d3-a456-426614174011"
	if got := invoke(rotated, newKey, "payload", h); got.Code != 201 || calls != 2 {
		t.Fatalf("rotated write status=%d calls=%d", got.Code, calls)
	}
	repo.mu.Lock()
	defer repo.mu.Unlock()
	row := repo.rows[memoryRecordKey(rotated, newKey, "create")]
	if row == nil || row.ScopeHashKeyID != "scope-v2" || row.ResponseKeyID != "response-v2" {
		t.Fatalf("rotated row key IDs: %+v", row)
	}
}

func TestLegacyCiphertextAADRemainsReadable(t *testing.T) {
	keyBytes := []byte("0123456789abcdef0123456789abcdef")
	service := testService(t, newMemoryRepo())
	requestHash := strings.Repeat("a", 64)
	plain, err := json.Marshal(cachedResponse{Status: 201, Header: map[string][]string{"Content-Type": {"text/plain"}}, Body: []byte("legacy")})
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	sealed := aead.Seal(nonce, nonce, plain, legacyResponseAAD(service.scopeHash(testScope), "create", "123e4567-e89b-12d3-a456-426614174012", requestHash))
	encoded := []byte(base64.StdEncoding.EncodeToString(sealed))
	got, err := service.decrypt(encoded, legacyScopeKeyID, service.scopeHash(testScope), legacyScopeKeyID, legacyResponseFormat, "create", "123e4567-e89b-12d3-a456-426614174012", requestHash)
	if err != nil || got.Status != 201 || string(got.Body) != "legacy" {
		t.Fatalf("legacy decrypt=%+v err=%v", got, err)
	}
}

func TestIndeterminateResolutionRequiresConfirmationAndEmitsSafeAuditObservation(t *testing.T) {
	repo := newMemoryRepo()
	key := "123e4567-e89b-12d3-a456-426614174030"
	action := "legacy-write"
	repo.rows[legacyUnscopedKeyID+":"+legacyScopeHash+":"+key+":"+action] = &Record{Status: StatusIndeterminate, ExpiresAt: time.Now().Add(-time.Hour)}
	events := make(chan Event, 2)
	service, err := NewService(repo, Config{EncryptionKey: []byte("0123456789abcdef0123456789abcdef"), OnEvent: func(e Event) { events <- e }})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.ResolveLegacyIndeterminate(context.Background(), key, action, "operator-7", "unknown"); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("unsafe resolution=%v", err)
	}
	if err := service.ResolveLegacyIndeterminate(context.Background(), key, action, "operator-7", ResolutionConfirmedNotApplied); err != nil {
		t.Fatal(err)
	}
	e := <-events
	if e.Name != "legacy_indeterminate_resolved" || e.Actor != "operator-7" || e.Action != action || strings.Contains(e.Actor, key) {
		t.Fatalf("audit observation=%+v", e)
	}
	repo.mu.Lock()
	defer repo.mu.Unlock()
	if len(repo.rows) != 0 {
		t.Fatalf("indeterminate row was not resolved: %d", len(repo.rows))
	}
	if len(repo.audit) != 1 || repo.audit[0] != "operator-7:"+action+":"+ResolutionConfirmedNotApplied {
		t.Fatalf("audit observations=%v", repo.audit)
	}
}

func TestResponseKeyRotationDoesNotChangeScopeHash(t *testing.T) {
	scopeKey := bytes.Repeat([]byte("s"), 32)
	responseOne := bytes.Repeat([]byte("1"), 32)
	responseTwo := bytes.Repeat([]byte("2"), 32)
	common := []KeyMaterial{{ID: "scope-v1", Key: scopeKey}}
	first, err := NewService(newMemoryRepo(), Config{ScopeHashKeys: common, ActiveScopeHashKeyID: "scope-v1", ResponseEncryptionKeys: []KeyMaterial{{ID: "response-v1", Key: responseOne}}, ActiveResponseKeyID: "response-v1"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewService(newMemoryRepo(), Config{ScopeHashKeys: common, ActiveScopeHashKeyID: "scope-v1", ResponseEncryptionKeys: []KeyMaterial{{ID: "response-v1", Key: responseOne}, {ID: "response-v2", Key: responseTwo}}, ActiveResponseKeyID: "response-v2"})
	if err != nil {
		t.Fatal(err)
	}
	if first.scopeHash(testScope) != second.scopeHash(testScope) {
		t.Fatal("response key rotation changed the principal scope hash")
	}
}

func TestVersionedFingerprintIncludesRawQueryAndConfiguredSemanticHeaders(t *testing.T) {
	a := httptest.NewRequest(http.MethodPost, "/resource?a=1&b=2", strings.NewReader("payload"))
	b := httptest.NewRequest(http.MethodPost, "/resource?b=2&a=1", strings.NewReader("payload"))
	a.Header.Set("X-API-Version", "v1")
	b.Header.Set("X-API-Version", "v2")
	ha, err := HashRequestWithHeaders(a, "create", 1024, []string{"X-API-Version"})
	if err != nil {
		t.Fatal(err)
	}
	hb, err := HashRequestWithHeaders(b, "create", 1024, []string{"x-api-version"})
	if err != nil {
		t.Fatal(err)
	}
	if ha == hb {
		t.Fatal("raw query and configured semantic header must affect current fingerprint")
	}
	contentA := httptest.NewRequest(http.MethodPost, "/resource", strings.NewReader("payload"))
	contentB := httptest.NewRequest(http.MethodPost, "/resource", strings.NewReader("payload"))
	contentA.Header.Set("Content-Type", "application/json; profile=v1")
	contentB.Header.Set("Content-Type", "application/json; profile=v2")
	contentHashA, err := HashRequestWithHeaders(contentA, "create", 1024, nil)
	if err != nil {
		t.Fatal(err)
	}
	contentHashB, err := HashRequestWithHeaders(contentB, "create", 1024, nil)
	if err != nil {
		t.Fatal(err)
	}
	if contentHashA == contentHashB {
		t.Fatal("Content-Type parameters must affect current fingerprint")
	}
	if _, err := HashRequestWithHeaders(httptest.NewRequest(http.MethodPost, "/resource?x=%ZZ", nil), "create", 1024, nil); err == nil {
		t.Fatal("malformed query should be rejected, not collapsed into another request fingerprint")
	}
	if _, err := HashRequestWithHeaders(httptest.NewRequest(http.MethodPost, "/resource", nil), "create", 1024, []string{"Authorization"}); err == nil {
		t.Fatal("credential headers must not be accepted as fingerprint inputs")
	}
}

func TestServiceFingerprintUsesDefaultSemanticHeaders(t *testing.T) {
	service := testService(t, newMemoryRepo())
	a := httptest.NewRequest(http.MethodGet, "/resource", nil)
	b := httptest.NewRequest(http.MethodGet, "/resource", nil)
	a.Header.Set("Accept", "application/json")
	b.Header.Set("Accept", "text/plain")
	ha, err := HashRequestWithHeaders(a, "read", 1024, nil)
	if err != nil {
		t.Fatal(err)
	}
	hb, err := HashRequestWithHeaders(b, "read", 1024, nil)
	if err != nil {
		t.Fatal(err)
	}
	if ha == hb {
		t.Fatal("default Accept header did not affect the fingerprint")
	}
	if len(service.config.HashHeaders) == 0 {
		t.Fatal("service did not initialize default semantic headers")
	}
}

func TestVersionedFingerprintDoesNotReplayUnverifiableLegacyHash(t *testing.T) {
	repo := newMemoryRepo()
	service := testService(t, repo)
	key := "123e4567-e89b-12d3-a456-426614174040"
	req := httptest.NewRequest(http.MethodPost, "/resource?b=2&a=1", strings.NewReader("legacy-payload"))
	legacyHash, err := HashRequest(req, "create", 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := json.Marshal(cachedResponse{Status: 201, Header: map[string][]string{"Content-Type": {"text/plain"}}, Body: []byte("legacy response")})
	if err != nil {
		t.Fatal(err)
	}
	keyBytes := []byte("0123456789abcdef0123456789abcdef")
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	sealed := aead.Seal(nonce, nonce, plain, legacyResponseAAD(service.scopeHash(testScope), "create", key, legacyHash))
	row := &Record{ScopeHash: service.scopeHash(testScope), ScopeHashKeyID: legacyScopeKeyID, ResponseKeyID: legacyScopeKeyID, RequestHashVersion: legacyRequestHashVersion, ResponseFormat: legacyResponseFormat, IdempotencyKey: key, ActionType: "create", RequestHash: legacyHash, Status: StatusCompleted, ResponseStatus: 201, Response: []byte(base64.StdEncoding.EncodeToString(sealed)), CreatedAt: time.Now(), UpdatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}
	repo.rows[memoryRecordKey(service, key, "create")] = row
	got := invoke(service, key, "legacy-payload", http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("legacy row unexpectedly executed handler") }))
	if got.Code != http.StatusConflict {
		t.Fatalf("legacy row should fail closed, status=%d body=%q", got.Code, got.Body.String())
	}
}

func TestServiceErrorWriterCanBeCustomized(t *testing.T) {
	called := false
	service := testService(t, newMemoryRepo())
	service.config.ErrorWriter = func(w http.ResponseWriter, status int, message string) { called = true; w.WriteHeader(status) }
	r := httptest.NewRequest(http.MethodPost, "/resource", nil)
	w := httptest.NewRecorder()
	NewHTTPMiddleware(service).RequireIdempotencyKey(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("invalid key should stop request") })).ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest || !called {
		t.Fatalf("status=%d custom writer called=%v", w.Code, called)
	}
}

func TestDefaultErrorWriterPreservesPriorJSONEnvelope(t *testing.T) {
	w := httptest.NewRecorder()
	writeError(w, http.StatusBadRequest, "missing key")
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if w.Code != http.StatusBadRequest || w.Header().Get("Content-Type") != "application/json" || got["status_code"] != float64(http.StatusBadRequest) || got["message"] != "missing key" || got["data"] != nil {
		t.Fatalf("status=%d headers=%v body=%v", w.Code, w.Header(), got)
	}
}

func TestConfiguredHashHeadersExtendDefaultsWithoutDuplicates(t *testing.T) {
	service, err := NewService(newMemoryRepo(), Config{EncryptionKey: []byte("0123456789abcdef0123456789abcdef"), HashHeaders: []string{"Accept", "X-API-Version"}})
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, name := range service.config.HashHeaders {
		if strings.EqualFold(name, "Accept") {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("Accept appears %d times in hash headers", count)
	}
	found := false
	for _, name := range service.config.HashHeaders {
		if strings.EqualFold(name, "X-API-Version") {
			found = true
		}
	}
	if !found {
		t.Fatal("custom semantic header was not retained")
	}
}
