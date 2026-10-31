# Idempotency

The package protects HTTP operations using a PostgreSQL table owned by each
consuming service. Inject that service's `*sql.DB`; the package never opens a
connection or applies migrations automatically. It is a standalone Go module in
this repository at `github.com/thakur-vijay/adorbit-go/idempotency`, with its
own Go 1.25 module declaration and dependency set. Publish versions using the
nested-module tag form `idempotency/vX.Y.Z`; consumers can add it with
`go get github.com/thakur-vijay/adorbit-go/idempotency@vX.Y.Z`. It imports no
sibling AdOrbit application packages. Because it is a nested module, repository
CI must run Go commands from both the repository root and `idempotency/`; root
`./...` patterns do not descend into nested modules. The default error JSON remains wire-compatible with the
repository's prior response envelope; set `Config.ErrorWriter` to use your
service's error format.

## Setup

Use separate stable AES-256 keyrings for scope HMAC and response encryption. All instances sharing the idempotency table must have compatible retained keyrings, identical `HashHeaders` configuration, and the same active scope-key epoch. The defaults are a 24-hour result
TTL, a 2-minute processing lease, and 1 MiB request and response limits.
Request and response limits are capped at 64 MiB to keep `limit + 1` safe and
bound memory use. The configured result TTL is limited to 10 years and the
processing lease to 24 hours.

```go
repo := idempotency.NewPostgresRepository(serviceDB)
idem, err := idempotency.NewService(repo, idempotency.Config{
	TTL:              24 * time.Hour,
	ProcessingTTL:    2 * time.Minute,
	MaxRequestBytes:  1 << 20,
	MaxResponseBytes: 1 << 20,
	HashHeaders: []string{"X-Tenant-API-Version", "X-Feature-Mode"}, // add semantic headers
	// EncryptionKey preserves the old single-key configuration. It is read
	// under key ID legacy-v1 for both scope hashing and old response ciphertext.
	EncryptionKey: keyFromSecretManager, // exactly 32 bytes
})
if err != nil { return err }
middleware := idempotency.NewHTTPMiddleware(idem)

router.With(
	// Set a stable tenant/principal scope from trusted authenticated context.
	authenticatedPrincipalScopeMiddleware,
	middleware.RequireIdempotencyKey,
	middleware.RequireIdempotency("update-profile"),
).Post("/profile", updateProfileHandler)

router.With(
	// Use a server-issued registration flow ID for unauthenticated signup.
	signupFlowScopeMiddleware,
	middleware.RequireIdempotencyKey,
	middleware.RequireIdempotency("signup"),
).Post("/signup", signupHandler)
```

Each backend service should inject its own database and apply the migrations there. Keys are unique in that database within `action_type`; use a stable action name for each logical operation.
Put authentication and CORS middleware outside idempotency so auth runs before
the protected operation and current-request CORS headers remain current on a
replay.

The scope is required. Set it with `idempotency.WithIdempotencyScope` from
trusted server-side context; never read it from a client header. Include every
authorization dimension that can change the response, commonly canonical
tenant and principal IDs. The package HMACs the scope with a derived key before
storing or querying it, and binds the hash into response encryption.
Unauthenticated operations have no principal to infer. For signup, use a
server-issued flow/session identifier as scope when possible. A global value
such as `public:signup` is an explicit shared namespace and can replay another
caller's response if the same key and payload are reused; use it only if that
sharing is acceptable.

## API migration for adopters

The keyring and fingerprint formats require the repository contract to carry multiple scope hashes, active key IDs, request-hash candidates, and response-format metadata. Custom `Repository` implementations must update their `Claim` and `Complete` methods. Deploy this module as a coordinated schema/API upgrade; existing single-hash repository implementations will no longer compile against the new interface. Repositories that support operator resolution must implement both `IndeterminateResolver` methods and atomically write the audit record with record deletion; repositories that support scope cutover must implement `ScopeEpochController`. The PostgreSQL implementation is the reference. `HashRequest` retains its v1 behavior; use `HashRequestWithHeaders` for v2 fingerprints. The default error response retains its previous JSON fields, and `Config.ErrorWriter` allows another service format.

## Migrations, key versions, and cutover

`idempotency.Migrations` embeds migration files; the consuming service applies them through a transactional migration runner. Apply 001, 002, and 003 in order. The runner must execute each migration file in one database transaction so locks and preflight checks cannot race with writers. Migration 003 adds scope and response key IDs, request-hash and response-format versions, backfills existing rows with legacy versions, adds `indeterminate`, creates `idempotency_key_config`, and creates a durable operator-resolution audit table. Its singleton row starts with `legacy-v1` active. The 003 down migration requires application writes paused and instances drained. It locks the key configuration and records during its preflight, and refuses to proceed while processing or indeterminate rows, audited resolutions, a non-legacy scope epoch, rotated scope-key rows, or current-format request/response rows exist. The 002 down migration refuses to remove principal scoping while any scoped record remains. Treat these migrations as forward-only after new-format or tenant-scoped writes.

`EncryptionKey` remains a compatibility alias for the pre-keyring 32-byte key. It is loaded as `legacy-v1` in both keyrings. New deployments may configure keyrings directly:

```go
Config{
    ScopeHashKeys: []KeyMaterial{
        {ID: "legacy-v1", Key: oldScopeKey},
        {ID: "scope-v2", Key: newScopeKey},
    },
    ActiveScopeHashKeyID: "legacy-v1",
    ResponseEncryptionKeys: []KeyMaterial{
        {ID: "legacy-v1", Key: oldEncryptionKey},
        {ID: "response-v2", Key: newEncryptionKey},
    },
    ActiveResponseKeyID: "response-v2",
}
```

The active scope key writes new scope hashes; all retained scope keys are queried for old records. Active response encryption uses the configured write key; the row's `response_key_id` and `response_format` choose the correct retained key and AAD format. The package checks the database for scope-key IDs still present and fails closed if an instance omits one. Legacy request fingerprints are not replayed after upgrade because they omitted authority, raw query, and semantic-header inputs; terminal legacy rows conflict until expiry and cleanup. Stale legacy-fingerprint processing rows become `indeterminate`. Keep response keys until no retained rows reference them; missing decryption keys produce an unavailable stored response, never a new business execution.

### Scope-key coordinated cutover

Scope-key rotation requires an explicit coordinated write pause:

1. Deploy keyring-capable binaries to every instance with the old and new scope keys in the read keyring. Keep the database and all instances on the old active key. Retain old response keys too. Drain binaries that do not enforce `idempotency_key_config`.
2. Pause idempotency-protected writes and wait for in-flight claim transactions to finish. Do not switch key IDs while old binaries can still receive protected traffic.
3. Change the database epoch with `service.SetActiveScopeHashKey(ctx, oldID, newID)` using a version that has both keys. The database row lock is a barrier against concurrent claims. The compare-and-swap fails if the expected epoch changed.
4. Set every instance's active scope key to the new ID while retaining both read keys, then resume writes. Instances still configured for the old epoch fail closed with 503. New instances can find old-key records and replay them rather than creating a duplicate.
5. Remove an old scope key only after every row using it has been cleaned or otherwise safely resolved and all instances are updated. The repository rejects claims from an incomplete scope keyring while matching-version rows remain.

Response-key rotation is less coordinated: deploy readers with old and new response keys, then switch the active response key; retain the old key until no rows reference it. Scope and response keys are separate secrets and must not be reused by design. Key IDs are metadata, not secret material.

The package HMACs trusted principal/tenant scope values before storage and never includes raw scopes or key material in observations. Include all authorization dimensions that affect the response. For signup or other unauthenticated actions, use a server-issued flow identifier where possible. Legacy unscoped records are never replayed into a scoped principal; live terminal records conflict until expiry/cleanup. Expired legacy processing records are not assumed safe to replay or delete: a stale one is atomically converted to `indeterminate`.

## Request and concurrency behavior

The key middleware validates a UUID and stores its canonical form in context.
New records use a versioned fingerprint over method, action, scheme/authority,
HTTP protocol/TLS state, escaped path, exact raw query, content length/encoding,
full Content-Type values, trailers, exact body, and values of default semantic
headers plus configured `HashHeaders` (additional headers). Configure every
application-specific non-credential header that can change business behavior or
representation. Other trusted context that affects behavior must be represented
in the action or principal scope. Keep this configuration identical across
instances. Changing it is a coordinated fingerprint rollout: rows from a prior
profile fail closed with 409, while stale processing rows with mismatched
fingerprints become indeterminate.
Authorization and cookies are excluded: trusted identity and authorization
dimensions must be part of the principal scope. Malformed queries are rejected.
`HashRequest` remains available with the original v1 algorithm for compatibility;
service requests write v2 fingerprints. Existing v1 terminal rows return 409
until expiration rather than being replayed without enough data to prove that
all effective request inputs match. A stale processing row with an unverifiable fingerprint becomes indeterminate and requires audited operator resolution. The bounded body is restored after reads.

PostgreSQL atomically inserts or conditionally reclaims expired terminal rows
and stale processing leases. An `expires_at` value alone never reclaims or
deletes a processing row. Stale processing can only be reclaimed by a request
with the same hash; an expired completed/failed key may begin a new TTL
lifecycle, including with a new payload. A duplicate of an
active request gets HTTP 409 with `Retry-After: 1`; retry it with the same key
and payload. A 409 caused by a different request hash is a key-reuse conflict
and must not be retried with that key.

The active owner refreshes its processing timestamp; processing records are
never reclaimed or deleted from `expires_at` alone. A heartbeat failure cancels
the handler context and fails closed with 503 when the response is still
buffered. If a response was already committed by `Flush`, `Hijack`, or an
oversized-response pass-through, it cannot be replaced; it is left as sent and
the processing row is retained. Handlers must honor request cancellation.
Heartbeats use a lease context independent of client cancellation and continue
until the handler returns. A cancelled request is never completed or released:
its processing row remains until a same-hash retry can recover it after going
stale. Cacheable responses are buffered and persisted before their status and
body are sent to the client.
Each `Refresh` uses a context timeout capped at five seconds and at one-third of
the processing lease. Shutdown cancels the lease context before waiting and
waits for at most the same bounded interval. If a repository ignores context
cancellation, shutdown can return while its heartbeat goroutine is still
running; the built-in PostgreSQL repository passes the context to
`ExecContext`. Processing leases shorter than three milliseconds are rejected.
Completion gets a short bounded retry window while the lease heartbeat remains
active. If storage still fails, the service returns 503 and leaves the row
processing for stale recovery; a retry gets 409 while that lease remains
active.

Completed 2xx/3xx responses and terminal 4xx responses are replayed. HTTP 5xx,
408, 425, and 429 are transient:
the processing record is released and the request may be retried with the same
key. The replay header allowlist is `Content-Type`, `Content-Encoding`,
`Content-Language`, `Cache-Control`, `ETag`, `Last-Modified`, `Location`, and
`Content-Disposition`. `Date`, `Set-Cookie`, `X-Request-ID`, and CORS headers
are not cached; outer middleware supplies request-specific values on replay.

The response writer buffers up to `MaxResponseBytes`. Oversized responses,
`Flush`, and hijacked connections switch to pass-through and are not cached.
This means the handler can run again for a retry of these response modes.

## Delivery guarantees and monitoring

This package prevents overlapping execution while its database lease remains
healthy and avoids telling the client a cacheable operation succeeded before
the response record is persisted. It does not guarantee exactly-once business
effects across a crash between committing a business write and persisting the
idempotency result. A stale processing record is ambiguous: recovery can repeat work that succeeded immediately before a crash. Legacy unscoped stale processing is therefore moved to `indeterminate` instead of replayed. Expired processing rows are
not deleted by cleanup; they require a same-hash retry for recovery. The default middleware and
`PostgresRepository` do not combine business writes and completion in one
transaction. Exactly-once effects require a transaction-aware integration that
commits both together, or a transactional outbox/inbox with idempotent
consumers. Heartbeat cancellation is cooperative; handlers that ignore context
can keep working after lease loss. No library-only lease can fence external
side effects.

Set `Config.OnEvent` to observe privacy-safe events for replays, conflicts,
heartbeat failures, completion failures, cleanup, and operator resolutions. The callback runs synchronously and should return quickly. Events contain no keys,
request/response bodies, or tokens; this package does not log them.

Call `service.DeleteExpired(ctx, batchSize)` from the consuming service's
scheduled job. Each call deletes one bounded batch of expired terminal rows
with `SKIP LOCKED`, allowing multiple cleanup workers. Scoped stale processing rows remain available for same-hash recovery. Legacy unscoped stale processing rows and stale processing rows with an unverifiable v1 fingerprint are atomically marked indeterminate and excluded from cleanup permanently. Do not automatically replay or delete these rows. Protect resolution endpoints with operator authentication and authorize only trusted operators. Pass a stable non-sensitive operator identifier as `operatorID`. Resolve only after domain-level investigation confirms the effect definitely did not happen:

```go
err := service.ResolveLegacyIndeterminate(ctx, key, action, operatorID, "confirmed_not_applied")
// For a scoped v1 processing record, provide its trusted scope instead:
err = service.ResolveIndeterminate(ctx, scope, key, action, operatorID, "confirmed_not_applied")
```

Resolution and audit insertion commit in one database transaction. The durable `idempotency_resolution_audit` row contains the record UUID, actor, action and resolution, but no idempotency key or principal scope. A privacy-safe `legacy_indeterminate_resolved` or `indeterminate_resolved` observation is also emitted after commit. Audit rows are retained until an operator applies an explicit retention policy; the downgrade migration refuses to discard them. If the effect happened or remains unknown, leave the row blocked and use domain-specific reconciliation. Schedule short periodic cleanup batches through the service's existing job runner.
