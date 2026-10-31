package idempotency

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// Set ADORBIT_IDEMPOTENCY_TEST_DATABASE_URL to a disposable PostgreSQL database
// to run the database-specific lifecycle and concurrency tests.
func postgresTestRepository(t *testing.T) (*sql.DB, *PostgresRepository) {
	t.Helper()
	dsn := os.Getenv("ADORBIT_IDEMPOTENCY_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("ADORBIT_IDEMPOTENCY_TEST_DATABASE_URL is not set")
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	admin := stdlib.OpenDB(*cfg)
	schema := "idempotency_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.ExecContext(context.Background(), `CREATE SCHEMA `+schema); err != nil {
		_ = admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.ExecContext(context.Background(), `DROP SCHEMA `+schema+` CASCADE`)
		_ = admin.Close()
	})
	testCfg := cfg.Copy()
	testCfg.RuntimeParams["search_path"] = schema
	db := stdlib.OpenDB(*testCfg)
	db.SetMaxOpenConns(12)
	up, err := Migrations.ReadFile("migrations/001_create_idempotency_keys.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(context.Background(), string(up)); err != nil {
		t.Fatal(err)
	}
	// Running 002 after a fresh 001 install must be harmless; earlier installs
	// use it to upgrade key scoping, lease ownership, and the terminal-state check.
	up, err = Migrations.ReadFile("migrations/002_add_processing_owner.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(context.Background(), string(up)); err != nil {
		t.Fatal(err)
	}
	up, err = Migrations.ReadFile("migrations/003_keyrings_and_indeterminate.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(context.Background(), string(up)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = db.Close()
	})
	return db, NewPostgresRepository(db)
}

func TestPostgresConcurrentInitialClaimHasSingleOwner(t *testing.T) {
	_, repo := postgresTestRepository(t)
	ctx := context.Background()
	const key, action, hash = "123e4567-e89b-12d3-a456-426614174000", "create", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	scopeHash := strings.Repeat("s", 64)
	var wg sync.WaitGroup
	var mu sync.Mutex
	owners := 0
	errorsFound := make(chan error, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, claimed, err := claimForTest(repo, ctx, scopeHash, key, action, hash, uuid.NewString(), time.Hour, time.Minute)
			if err != nil {
				errorsFound <- err
				return
			}
			if claimed {
				mu.Lock()
				owners++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	close(errorsFound)
	for err := range errorsFound {
		t.Error(err)
	}
	if owners != 1 {
		t.Fatalf("got %d owners; want exactly one", owners)
	}
	if _, claimed, err := claimForTest(repo, ctx, strings.Repeat("t", 64), key, action, hash, uuid.NewString(), time.Hour, time.Minute); err != nil || !claimed {
		t.Fatalf("same key/action in independent scope: claimed=%v err=%v", claimed, err)
	}
}

func TestPostgresRefreshHonorsContextCancellation(t *testing.T) {
	db, repo := postgresTestRepository(t)
	ctx := context.Background()
	key, owner := "123e4567-e89b-12d3-a456-426614174099", uuid.NewString()
	scopeHash := strings.Repeat("r", 64)
	if _, claimed, err := claimForTest(repo, ctx, scopeHash, key, "refresh", strings.Repeat("a", 64), owner, time.Hour, time.Minute); err != nil || !claimed {
		t.Fatalf("claim=%v err=%v", claimed, err)
	}
	locker, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer locker.Rollback()
	var id string
	if err := locker.QueryRowContext(ctx, `SELECT id::text FROM idempotency_keys WHERE scope_hash=$1 AND owner_token=$2 FOR UPDATE`, scopeHash, owner).Scan(&id); err != nil {
		t.Fatal(err)
	}
	refreshCtx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- repo.Refresh(refreshCtx, owner) }()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Refresh error=%v, want deadline exceeded", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Refresh did not return after its context was cancelled")
	}
}

func TestPostgresReclaimOwnershipReplayAndCleanup(t *testing.T) {
	db, repo := postgresTestRepository(t)
	ctx := context.Background()
	key := "123e4567-e89b-12d3-a456-426614174000"
	hash := strings.Repeat("a", 64)
	scopeHash := strings.Repeat("s", 64)
	reusedHash := strings.Repeat("b", 64)
	firstOwner, expiredOwner, staleOwner := uuid.NewString(), uuid.NewString(), uuid.NewString()
	if _, claimed, err := claimForTest(repo, ctx, scopeHash, key, "create", hash, firstOwner, time.Hour, time.Minute); err != nil || !claimed {
		t.Fatalf("initial claim=%v err=%v", claimed, err)
	}
	processing, claimed, err := claimForTest(repo, ctx, scopeHash, key, "create", hash, uuid.NewString(), time.Hour, time.Minute)
	if err != nil || claimed || processing.Status != StatusProcessing {
		t.Fatalf("processing duplicate=%v record=%+v err=%v", claimed, processing, err)
	}
	other, claimed, err := claimForTest(repo, ctx, scopeHash, key, "create", strings.Repeat("b", 64), uuid.NewString(), time.Hour, time.Minute)
	if err != nil || claimed || other.RequestHash != hash {
		t.Fatalf("different hash claim=%v record=%+v err=%v", claimed, other, err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE idempotency_keys SET created_at=NOW()-interval '2 seconds', expires_at=NOW()-interval '1 second' WHERE idempotency_key=$1`, key); err != nil {
		t.Fatal(err)
	}
	if _, claimed, err := claimForTest(repo, ctx, scopeHash, key, "create", hash, uuid.NewString(), time.Hour, time.Minute); err != nil || claimed {
		t.Fatalf("expired active processing row was reclaimed: claimed=%v err=%v", claimed, err)
	}
	if deleted, err := repo.DeleteExpired(ctx, time.Now(), 10); err != nil || deleted != 0 {
		t.Fatalf("expired active processing cleanup deleted=%d err=%v", deleted, err)
	}
	if err := repo.Complete(ctx, firstOwner, StatusCompleted, 302, "legacy-v1", []byte("encrypted-result"), time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("complete initial owner: %v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE idempotency_keys SET created_at=NOW()-interval '2 seconds', expires_at=NOW()-interval '1 second' WHERE idempotency_key=$1`, key); err != nil {
		t.Fatal(err)
	}
	if _, claimed, err := claimForTest(repo, ctx, scopeHash, key, "create", reusedHash, expiredOwner, time.Hour, time.Minute); err != nil || !claimed {
		t.Fatalf("expired reclaim=%v err=%v", claimed, err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE idempotency_keys SET updated_at=NOW()-interval '10 minutes' WHERE idempotency_key=$1`, key); err != nil {
		t.Fatal(err)
	}
	if _, claimed, err := claimForTest(repo, ctx, scopeHash, key, "create", reusedHash, staleOwner, time.Second, time.Minute); err != nil || !claimed {
		t.Fatalf("stale reclaim=%v err=%v", claimed, err)
	}
	if err := repo.Refresh(ctx, staleOwner); err != nil {
		t.Fatalf("lease refresh: %v", err)
	}
	var refreshedAt time.Time
	if err := db.QueryRowContext(ctx, `SELECT updated_at FROM idempotency_keys WHERE idempotency_key=$1`, key).Scan(&refreshedAt); err != nil {
		t.Fatal(err)
	}
	if time.Since(refreshedAt) > 5*time.Second {
		t.Fatalf("lease timestamp was not refreshed: %v", refreshedAt)
	}
	if err := repo.Complete(ctx, expiredOwner, StatusCompleted, 200, "legacy-v1", []byte("old-owner-response"), time.Now().Add(time.Hour)); err != ErrNotOwner {
		t.Fatalf("old owner completion error=%v", err)
	}
	if err := repo.Release(ctx, expiredOwner); err != ErrNotOwner {
		t.Fatalf("old owner release error=%v", err)
	}
	current, claimed, err := claimForTest(repo, ctx, scopeHash, key, "create", reusedHash, uuid.NewString(), time.Hour, time.Minute)
	if err != nil || claimed || current.OwnerToken != staleOwner {
		t.Fatalf("old release changed owner: claimed=%v owner=%s err=%v", claimed, current.OwnerToken, err)
	}

	// A stale lease can only be claimed by one concurrent recovery request.
	if _, err := db.ExecContext(ctx, `UPDATE idempotency_keys SET updated_at=NOW()-interval '10 minutes' WHERE idempotency_key=$1`, key); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	owners := 0
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, claimed, err := claimForTest(repo, ctx, scopeHash, key, "create", reusedHash, uuid.NewString(), time.Hour, time.Minute)
			if err != nil {
				t.Error(err)
				return
			}
			if claimed {
				mu.Lock()
				owners++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if owners != 1 {
		t.Fatalf("stale recovery owners=%d", owners)
	}

	// End-to-end persistence proves that encrypted status, headers and body can be
	// read back and replayed without running the handler twice.
	service, err := NewService(repo, Config{EncryptionKey: []byte("0123456789abcdef0123456789abcdef")})
	if err != nil {
		t.Fatal(err)
	}
	responseKey := "123e4567-e89b-12d3-a456-426614174001"
	calls := 0
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Set-Cookie", "secret=token")
		w.WriteHeader(201)
		_, _ = w.Write([]byte(`{"saved":true}`))
	})
	invokeHTTP := func(idempotencyKey, scope, body string, target http.Handler) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/create", strings.NewReader(body))
		r.Header.Set("Idempotency-Key", idempotencyKey)
		r = r.WithContext(WithIdempotencyScope(r.Context(), scope))
		w := httptest.NewRecorder()
		NewHTTPMiddleware(service).RequireIdempotencyKey(service.Serve("create", target)).ServeHTTP(w, r)
		return w
	}
	principalScope := "tenant:tenant-1:user:user-7"
	one, two := invokeHTTP(responseKey, principalScope, "body", handler), invokeHTTP(responseKey, principalScope, "body", handler)
	if calls != 1 || one.Code != 201 || two.Code != 201 || two.Body.String() != one.Body.String() || two.Header().Get("Content-Type") != "application/json" || two.Header().Get("Set-Cookie") != "" {
		t.Fatalf("calls=%d first=%d second=%d headers=%v", calls, one.Code, two.Code, two.Header())
	}
	if different := invokeHTTP(responseKey, principalScope, "different", handler); different.Code != http.StatusConflict || calls != 1 {
		t.Fatalf("different payload status=%d calls=%d", different.Code, calls)
	}
	legacyKey := "123e4567-e89b-12d3-a456-426614174002"
	legacyRequest := httptest.NewRequest(http.MethodPost, "/create", strings.NewReader("body"))
	legacyHash, err := HashRequest(legacyRequest, "create", 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO idempotency_keys(scope_hash_key_id,scope_hash,idempotency_key,action_type,request_hash,status,response_key_id,response_format,response_status_code,response_body,created_at,updated_at,expires_at) VALUES($1,$2,$3,$4,$5,'completed','legacy-v1',1,201,'"old-response"'::jsonb,NOW(),NOW(),NOW()+interval '1 hour')`, legacyUnscopedKeyID, legacyScopeHash, legacyKey, "create", legacyHash); err != nil {
		t.Fatal(err)
	}
	legacyCalls := 0
	legacyHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { legacyCalls++; w.WriteHeader(201) })
	if legacy := invokeHTTP(legacyKey, principalScope, "body", legacyHandler); legacy.Code != http.StatusConflict || legacyCalls != 0 {
		t.Fatalf("legacy replay status=%d calls=%d", legacy.Code, legacyCalls)
	}
	if _, err := db.ExecContext(ctx, `UPDATE idempotency_keys SET created_at=NOW()-interval '2 seconds', expires_at=NOW()-interval '1 second' WHERE scope_hash=$1 AND idempotency_key=$2`, legacyScopeHash, legacyKey); err != nil {
		t.Fatal(err)
	}
	if deleted, err := repo.DeleteExpired(ctx, time.Now(), 1); err != nil || deleted != 1 {
		t.Fatalf("legacy cleanup deleted=%d err=%v", deleted, err)
	}
	if afterExpiry := invokeHTTP(legacyKey, principalScope, "body", legacyHandler); afterExpiry.Code != 201 || legacyCalls != 1 {
		t.Fatalf("after legacy expiry status=%d calls=%d", afterExpiry.Code, legacyCalls)
	}

	for i := 0; i < 3; i++ {
		owner := uuid.NewString()
		if _, claimed, err := claimForTest(repo, ctx, scopeHash, "expired-"+uuid.NewString(), "cleanup", hash, owner, time.Hour, time.Minute); err != nil || !claimed {
			t.Fatalf("cleanup seed claim=%v err=%v", claimed, err)
		}
		if err := repo.Complete(ctx, owner, StatusCompleted, 200, "legacy-v1", []byte("encrypted-result"), time.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.ExecContext(ctx, `UPDATE idempotency_keys SET created_at=NOW()-interval '2 seconds', expires_at=NOW()-interval '1 second' WHERE action_type='cleanup'`); err != nil {
		t.Fatal(err)
	}
	deleted, err := repo.DeleteExpired(ctx, time.Now(), 2)
	if err != nil || deleted != 2 {
		t.Fatalf("first cleanup deleted=%d err=%v", deleted, err)
	}
	deleted, err = repo.DeleteExpired(ctx, time.Now(), 2)
	if err != nil || deleted != 1 {
		t.Fatalf("second cleanup deleted=%d err=%v", deleted, err)
	}
}

func TestPostgresScopeKeyEpochPreventsDuplicateAcrossCutover(t *testing.T) {
	db, repo := postgresTestRepository(t)
	legacy := []byte("0123456789abcdef0123456789abcdef")
	nextScope := []byte("abcdef0123456789abcdef0123456789")
	nextResponse := []byte("fedcba9876543210fedcba9876543210")
	oldService, err := NewService(repo, Config{EncryptionKey: legacy})
	if err != nil {
		t.Fatal(err)
	}
	key := "123e4567-e89b-12d3-a456-426614174020"
	var calls atomic.Int32
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(201)
		_, _ = w.Write([]byte("created"))
	})
	serve := func(s *Service) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/resource", strings.NewReader("payload"))
		r.Header.Set("Idempotency-Key", key)
		r = r.WithContext(WithIdempotencyScope(r.Context(), "tenant:t1:user:u1"))
		w := httptest.NewRecorder()
		NewHTTPMiddleware(s).RequireIdempotencyKey(s.Serve("create", handler)).ServeHTTP(w, r)
		return w
	}
	if got := serve(oldService); got.Code != 201 {
		t.Fatalf("old write=%d", got.Code)
	}
	newService, err := NewService(repo, Config{ScopeHashKeys: []KeyMaterial{{ID: "legacy-v1", Key: legacy}, {ID: "scope-v2", Key: nextScope}}, ActiveScopeHashKeyID: "scope-v2", ResponseEncryptionKeys: []KeyMaterial{{ID: "legacy-v1", Key: legacy}, {ID: "response-v2", Key: nextResponse}}, ActiveResponseKeyID: "response-v2"})
	if err != nil {
		t.Fatal(err)
	}
	if got := serve(newService); got.Code != http.StatusServiceUnavailable {
		t.Fatalf("new writer before cutover status=%d", got.Code)
	}
	if err := newService.SetActiveScopeHashKey(context.Background(), "legacy-v1", "scope-v2"); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	codes := make(chan int, 2)
	for _, svc := range []*Service{oldService, newService} {
		wg.Add(1)
		go func(s *Service) { defer wg.Done(); codes <- serve(s).Code }(svc)
	}
	wg.Wait()
	close(codes)
	for code := range codes {
		if code != 201 && code != http.StatusServiceUnavailable {
			t.Fatalf("cutover response status=%d", code)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("business handler ran %d times", calls.Load())
	}
	// A new key is written only under the new scope epoch. Removing legacy-v1
	// before its old row is gone must fail closed instead of creating a duplicate.
	newKey := "123e4567-e89b-12d3-a456-426614174022"
	newKeyServe := func(s *Service) int {
		r := httptest.NewRequest(http.MethodPost, "/resource", strings.NewReader("payload"))
		r.Header.Set("Idempotency-Key", newKey)
		r = r.WithContext(WithIdempotencyScope(r.Context(), "tenant:t1:user:u1"))
		w := httptest.NewRecorder()
		NewHTTPMiddleware(s).RequireIdempotencyKey(s.Serve("create", handler)).ServeHTTP(w, r)
		return w.Code
	}
	if code := newKeyServe(newService); code != 201 {
		t.Fatalf("new epoch write status=%d", code)
	}
	missingLegacy, err := NewService(repo, Config{ScopeHashKeys: []KeyMaterial{{ID: "scope-v2", Key: nextScope}}, ActiveScopeHashKeyID: "scope-v2", ResponseEncryptionKeys: []KeyMaterial{{ID: "response-v2", Key: nextResponse}}, ActiveResponseKeyID: "response-v2"})
	if err != nil {
		t.Fatal(err)
	}
	if code := newKeyServe(missingLegacy); code != http.StatusServiceUnavailable {
		t.Fatalf("missing retained scope key status=%d", code)
	}
	var count int
	if err := db.QueryRowContext(context.Background(), `SELECT count(*) FROM idempotency_keys WHERE idempotency_key=$1 AND action_type='create'`, key).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("records=%d, want one", count)
	}
}

func TestPostgresStaleLegacyProcessingBecomesIndeterminateAtomically(t *testing.T) {
	db, repo := postgresTestRepository(t)
	key := "123e4567-e89b-12d3-a456-426614174021"
	action := "legacy-create"
	hash := strings.Repeat("a", 64)
	if _, err := db.ExecContext(context.Background(), `INSERT INTO idempotency_keys(scope_hash_key_id,scope_hash,idempotency_key,action_type,request_hash,status,owner_token,created_at,updated_at,expires_at) VALUES($1,$2,$3,$4,$5,'processing',$6,NOW()-interval '2 hours',NOW()-interval '1 hour',NOW()-interval '1 hour')`, legacyUnscopedKeyID, legacyScopeHash, key, action, hash, uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	service, err := NewService(repo, Config{EncryptionKey: []byte("0123456789abcdef0123456789abcdef")})
	if err != nil {
		t.Fatal(err)
	}
	candidates, active := service.scopeHashCandidates("tenant:t1:user:u1")
	var wg sync.WaitGroup
	errs := make(chan error, 12)
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, e := repo.Claim(context.Background(), candidates, active, []RequestHashCandidate{{Version: currentRequestHashVersion, Hash: hash}, {Version: legacyRequestHashVersion, Hash: hash}}, RequestHashCandidate{Version: currentRequestHashVersion, Hash: hash}, key, action, uuid.NewString(), time.Hour, time.Minute)
			errs <- e
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		if !errors.Is(e, errLegacyIndeterminate) {
			t.Errorf("claim error=%v, want indeterminate", e)
		}
	}
	var status string
	var owner sql.NullString
	if err := db.QueryRowContext(context.Background(), `SELECT status,owner_token FROM idempotency_keys WHERE scope_hash_key_id=$1 AND idempotency_key=$2`, legacyUnscopedKeyID, key).Scan(&status, &owner); err != nil {
		t.Fatal(err)
	}
	if status != "indeterminate" || owner.Valid {
		t.Fatalf("status=%q owner=%v", status, owner)
	}
	if deleted, err := repo.DeleteExpired(context.Background(), time.Now().Add(24*time.Hour), 10); err != nil || deleted != 0 {
		t.Fatalf("indeterminate cleanup deleted=%d err=%v", deleted, err)
	}
	if _, _, err := repo.Claim(context.Background(), candidates, active, []RequestHashCandidate{{Version: currentRequestHashVersion, Hash: hash}, {Version: legacyRequestHashVersion, Hash: hash}}, RequestHashCandidate{Version: currentRequestHashVersion, Hash: hash}, key, action, uuid.NewString(), time.Hour, time.Minute); !errors.Is(err, errLegacyIndeterminate) {
		t.Fatalf("indeterminate reclaim error=%v", err)
	}
	if err := repo.ResolveLegacyIndeterminate(context.Background(), key, action, "operator-9", ResolutionConfirmedNotApplied); err != nil {
		t.Fatal(err)
	}
	if err := repo.ResolveLegacyIndeterminate(context.Background(), key, action, "operator-9", ResolutionConfirmedNotApplied); !errors.Is(err, ErrNotIndeterminate) {
		t.Fatalf("second resolution=%v", err)
	}
}

func TestPostgresStaleV1FingerprintBecomesIndeterminateAndAuditsAtomically(t *testing.T) {
	db, repo := postgresTestRepository(t)
	ctx := context.Background()
	service, err := NewService(repo, Config{EncryptionKey: []byte("0123456789abcdef0123456789abcdef")})
	if err != nil {
		t.Fatal(err)
	}
	key, action, scope := "123e4567-e89b-12d3-a456-426614174050", "create-v1", "tenant:tenant-a:user:user-a"
	_, activeScope := service.scopeHashCandidates(scope)
	legacyRequest := httptest.NewRequest(http.MethodPost, "/legacy", strings.NewReader("payload"))
	legacyHash, err := HashRequest(legacyRequest, action, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, `INSERT INTO idempotency_keys(scope_hash_key_id,scope_hash,idempotency_key,action_type,request_hash,request_hash_version,status,owner_token,created_at,updated_at,expires_at) VALUES('legacy-v1',$1,$2,$3,$4,1,'processing',$5,NOW()-interval '2 hours',NOW()-interval '1 hour',NOW()+interval '1 hour')`, activeScope.Hash, key, action, legacyHash, uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	wrapped := NewHTTPMiddleware(service).RequireIdempotencyKey(service.Serve(action, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) })))
	var wg sync.WaitGroup
	statuses := make(chan int, 12)
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := httptest.NewRequest(http.MethodPost, "/legacy", strings.NewReader("payload"))
			r.Header.Set("Idempotency-Key", key)
			r = r.WithContext(WithIdempotencyScope(r.Context(), scope))
			w := httptest.NewRecorder()
			wrapped.ServeHTTP(w, r)
			statuses <- w.Code
		}()
	}
	wg.Wait()
	close(statuses)
	for status := range statuses {
		if status != http.StatusConflict {
			t.Errorf("status=%d, want conflict", status)
		}
	}
	if calls.Load() != 0 {
		t.Fatalf("handler calls=%d", calls.Load())
	}
	var state string
	if err := db.QueryRowContext(ctx, `SELECT status FROM idempotency_keys WHERE idempotency_key=$1`, key).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != "indeterminate" {
		t.Fatalf("state=%s", state)
	}
	if deleted, err := repo.DeleteExpired(ctx, time.Now().Add(48*time.Hour), 10); err != nil || deleted != 0 {
		t.Fatalf("cleanup deleted=%d err=%v", deleted, err)
	}
	if _, err := db.ExecContext(ctx, `ALTER TABLE idempotency_resolution_audit ADD CONSTRAINT reject_test_actor CHECK(actor <> 'operator-test')`); err != nil {
		t.Fatal(err)
	}
	if err := service.ResolveIndeterminate(ctx, scope, key, action, "operator-test", ResolutionConfirmedNotApplied); err == nil {
		t.Fatal("resolution succeeded despite audit insert failure")
	}
	if err := db.QueryRowContext(ctx, `SELECT status FROM idempotency_keys WHERE idempotency_key=$1`, key).Scan(&state); err != nil || state != "indeterminate" {
		t.Fatalf("audit failure did not roll back release: state=%q err=%v", state, err)
	}
	if _, err := db.ExecContext(ctx, `ALTER TABLE idempotency_resolution_audit DROP CONSTRAINT reject_test_actor`); err != nil {
		t.Fatal(err)
	}
	if err := service.ResolveIndeterminate(ctx, scope, key, action, "operator-test", ResolutionConfirmedNotApplied); err != nil {
		t.Fatal(err)
	}
	var auditCount int
	var actor, resolution string
	if err := db.QueryRowContext(ctx, `SELECT count(*),min(actor),min(resolution) FROM idempotency_resolution_audit WHERE action_type=$1`, action).Scan(&auditCount, &actor, &resolution); err != nil {
		t.Fatal(err)
	}
	if auditCount != 1 || actor != "operator-test" || resolution != ResolutionConfirmedNotApplied {
		t.Fatalf("audit count=%d actor=%q resolution=%q", auditCount, actor, resolution)
	}
	down, err := Migrations.ReadFile("migrations/003_keyrings_and_indeterminate.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, string(down)); err == nil {
		t.Fatal("downgrade discarded durable operator audit")
	}
}

func TestPostgresDowngradeRejectsNewFingerprintOrResponseFormat(t *testing.T) {
	db, repo := postgresTestRepository(t)
	ctx := context.Background()
	hash := strings.Repeat("a", 64)
	owner := uuid.NewString()
	key := "123e4567-e89b-12d3-a456-426614174051"
	scopeHash := strings.Repeat("b", 64)
	if _, claimed, err := claimForTest(repo, ctx, scopeHash, key, "downgrade", hash, owner, time.Hour, time.Minute); err != nil || !claimed {
		t.Fatalf("claim=%v err=%v", claimed, err)
	}
	if err := repo.Complete(ctx, owner, StatusCompleted, 201, "legacy-v1", []byte("ciphertext"), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	down, err := Migrations.ReadFile("migrations/003_keyrings_and_indeterminate.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, string(down)); err == nil {
		t.Fatal("downgrade accepted a current-format response")
	}
	var tableExists bool
	if err := db.QueryRowContext(ctx, `SELECT to_regclass('idempotency_key_config') IS NOT NULL`).Scan(&tableExists); err != nil || !tableExists {
		t.Fatalf("downgrade partially removed epoch table: exists=%v err=%v", tableExists, err)
	}
}

func TestPostgresMigrationBackfillsLegacyVersionsAndAllowsSafeDowngrade(t *testing.T) {
	dsn := os.Getenv("ADORBIT_IDEMPOTENCY_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("ADORBIT_IDEMPOTENCY_TEST_DATABASE_URL is not set")
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	admin := stdlib.OpenDB(*cfg)
	schema := "idempotency_migration_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err = admin.ExecContext(context.Background(), `CREATE SCHEMA `+schema); err != nil {
		_ = admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.ExecContext(context.Background(), `DROP SCHEMA `+schema+` CASCADE`)
		_ = admin.Close()
	})
	testCfg := cfg.Copy()
	testCfg.RuntimeParams["search_path"] = schema
	db := stdlib.OpenDB(*testCfg)
	t.Cleanup(func() { _ = db.Close() })
	for _, name := range []string{"migrations/001_create_idempotency_keys.up.sql", "migrations/002_add_processing_owner.up.sql"} {
		body, e := Migrations.ReadFile(name)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = db.ExecContext(context.Background(), string(body)); e != nil {
			t.Fatalf("apply %s: %v", name, e)
		}
	}
	key := "123e4567-e89b-12d3-a456-426614174060"
	requestHash := strings.Repeat("c", 64)
	if _, err = db.ExecContext(context.Background(), `INSERT INTO idempotency_keys(scope_hash,idempotency_key,action_type,request_hash,status,response_status_code,response_body,created_at,updated_at,expires_at) VALUES($1,$2,'legacy',$3,'completed',201,'"legacy-envelope"'::jsonb,NOW()-interval '1 hour',NOW(),NOW()+interval '1 hour')`, legacyScopeHash, key, requestHash); err != nil {
		t.Fatal(err)
	}
	body, err := Migrations.ReadFile("migrations/003_keyrings_and_indeterminate.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(context.Background(), string(body)); err != nil {
		t.Fatalf("apply key version migration: %v", err)
	}
	var scopeKeyID, responseKeyID sql.NullString
	var requestVersion int16
	var responseFormat sql.NullInt64
	if err = db.QueryRowContext(context.Background(), `SELECT scope_hash_key_id,response_key_id,request_hash_version,response_format FROM idempotency_keys WHERE idempotency_key=$1`, key).Scan(&scopeKeyID, &responseKeyID, &requestVersion, &responseFormat); err != nil {
		t.Fatal(err)
	}
	if !scopeKeyID.Valid || scopeKeyID.String != legacyUnscopedKeyID || !responseKeyID.Valid || responseKeyID.String != "legacy-v1" || requestVersion != legacyRequestHashVersion || !responseFormat.Valid || responseFormat.Int64 != int64(legacyResponseFormat) {
		t.Fatalf("backfill scope=%v response=%v request-version=%d response-format=%v", scopeKeyID, responseKeyID, requestVersion, responseFormat)
	}
	down, err := Migrations.ReadFile("migrations/003_keyrings_and_indeterminate.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(context.Background(), string(down)); err != nil {
		t.Fatalf("safe legacy key-version downgrade rejected: %v", err)
	}
	down, err = Migrations.ReadFile("migrations/002_add_processing_owner.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(context.Background(), string(down)); err != nil {
		t.Fatalf("legacy sentinel-only scope downgrade rejected: %v", err)
	}
}

func TestPostgresScopeDowngradeRefusesTenantScopedRows(t *testing.T) {
	db, _ := postgresTestRepository(t)
	ctx := context.Background()
	key := "123e4567-e89b-12d3-a456-426614174061"
	scopeHash := strings.Repeat("d", 64)
	if _, err := db.ExecContext(ctx, `INSERT INTO idempotency_keys(scope_hash_key_id,scope_hash,idempotency_key,action_type,request_hash,request_hash_version,status,response_key_id,response_format,response_status_code,response_body,created_at,updated_at,expires_at) VALUES('legacy-v1',$1,$2,'tenant-write',$3,1,'completed','legacy-v1',1,201,'"old"'::jsonb,NOW()-interval '1 hour',NOW(),NOW()+interval '1 hour')`, scopeHash, key, strings.Repeat("e", 64)); err != nil {
		t.Fatal(err)
	}
	down, err := Migrations.ReadFile("migrations/003_keyrings_and_indeterminate.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, string(down)); err != nil {
		t.Fatalf("legacy-format downgrade unexpectedly failed: %v", err)
	}
	down, err = Migrations.ReadFile("migrations/002_add_processing_owner.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, string(down)); err == nil {
		t.Fatal("scope-removing downgrade accepted tenant-scoped records")
	}
	var scope string
	if err = db.QueryRowContext(ctx, `SELECT scope_hash FROM idempotency_keys WHERE idempotency_key=$1`, key).Scan(&scope); err != nil || scope != scopeHash {
		t.Fatalf("tenant scope data changed after rejected downgrade: %q err=%v", scope, err)
	}
}

func TestPostgresStaleFingerprintMismatchDoesNotReclaim(t *testing.T) {
	db, repo := postgresTestRepository(t)
	ctx := context.Background()
	key := "123e4567-e89b-12d3-a456-426614174062"
	scopeHash := strings.Repeat("f", 64)
	owner := uuid.NewString()
	originalHash, replacementHash := strings.Repeat("1", 64), strings.Repeat("2", 64)
	if _, claimed, err := claimForTest(repo, ctx, scopeHash, key, "stale-mismatch", originalHash, owner, time.Hour, time.Minute); err != nil || !claimed {
		t.Fatalf("claim=%v err=%v", claimed, err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE idempotency_keys SET updated_at=NOW()-interval '1 hour' WHERE idempotency_key=$1`, key); err != nil {
		t.Fatal(err)
	}
	_, active := ScopeHashCandidate{KeyID: legacyScopeKeyID, Hash: scopeHash}, ScopeHashCandidate{KeyID: legacyScopeKeyID, Hash: scopeHash}
	candidate := RequestHashCandidate{Version: currentRequestHashVersion, Hash: replacementHash}
	if _, claimed, err := repo.Claim(ctx, []ScopeHashCandidate{active}, active, []RequestHashCandidate{candidate}, candidate, key, "stale-mismatch", uuid.NewString(), time.Hour, time.Minute); !errors.Is(err, errFingerprintIndeterminate) || claimed {
		t.Fatalf("claim=%v err=%v, want indeterminate", claimed, err)
	}
	var status string
	if err := db.QueryRowContext(ctx, `SELECT status FROM idempotency_keys WHERE idempotency_key=$1`, key).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "indeterminate" {
		t.Fatalf("status=%s", status)
	}
}
