Review and improve the existing adorbit-go/idempotency package. Do not rewrite the architecture or introduce unnecessary abstractions. Preserve the current design unless a change is required to fix a concrete issue.

Implement the following improvements in priority order:

P0 — Critical correctness issues

1. Prevent duplicate business operations
   - Review the gap between successful business execution and repository.Complete().
   - Currently, the HTTP response is sent before idempotency completion is persisted.
   - If the business operation succeeds but Complete() fails, a retry may execute the operation again.
   - Design a reliable recovery strategy and clearly document the limitations.
   - Do not claim exactly-once execution unless the business operation and idempotency state are protected by the same transaction or an appropriate transactional outbox/inbox pattern.
2. Fix lease heartbeat failure handling
   - Currently, heartbeat errors from repository.Refresh() are silently ignored.
   - Track heartbeat failures and ensure the service handles lost lease ownership safely.
   - Prevent an expired lease from allowing another request to execute concurrently while the original handler is still running.
   - Review owner-token checks and consider fencing/versioning if necessary.
3. Fix response header replay
   - Do not blindly cache and replay every HTTP response header.
   - Define an explicit response-header allowlist or denylist.
   - Handle dynamic headers such as Date, Set-Cookie, X-Request-ID, and CORS headers correctly.
   - Ensure replayed responses remain compatible with the current request’s Origin and other request-specific values.
4. Make repository ownership checks consistent
   - Add nil database validation to all repository methods, not only Claim().
   - Ensure Complete(), Refresh(), Release(), and DeleteExpired() return errors instead of panicking when the repository or DB is nil.

P1 — Database and concurrency correctness

5. Fix migration consistency
   - 001_create_idempotency_keys.up.sql already creates owner_token.
   - 002_add_processing_owner.up.sql adds the same column again.
   - Check whether migration 001 has already been released/applied:
     - If unreleased, simplify the migration history.
     - If already released, preserve migration immutability and retain 002 as an upgrade migration.
   - Ensure fresh installations and existing installations both work correctly.
6. Review PostgreSQL Claim() concurrency
   - Thoroughly review the INSERT ... ON CONFLICT DO NOTHING, conditional UPDATE, and subsequent SELECT flow.
   - Verify behavior under concurrent requests, expired records, stale processing records, and different request hashes.
   - Ensure ownership cannot accidentally be transferred from one active request to another.
   - Preserve atomic claim semantics.
7. Make stale lease recovery consistent
   - The in-memory test repository currently permits stale processing recovery with a different request hash.
   - PostgreSQL Claim() only permits stale processing recovery when the request hash matches.
   - Make mock and PostgreSQL implementations follow identical semantics.
   - Update tests accordingly.
8. Review Complete(), Refresh(), and Release()
   - Ensure every state transition is conditional on the current owner token.
   - Ensure an old owner cannot complete or release a record after another request has reclaimed it.
   - Verify that Complete() only transitions valid processing records into terminal states.
   - Validate allowed status values.

P1 — Testing

9. Expand PostgreSQL integration tests
   Current integration tests primarily verify concurrent initial claims.
   Add real PostgreSQL tests for:
   - Same key + same request replay.
   - Same key + different request hash returns conflict.
   - Expired record reclamation.
   - Stale processing lease recovery.
   - Old owner attempting completion after lease reclamation.
   - Old owner attempting release after lease reclamation.
   - Concurrent requests attempting to reclaim the same stale record.
   - Response encryption/decryption and persistence.
   - Cleanup behavior with multiple expired records.
10. Test heartbeat failures
    - Simulate database failures during heartbeat.
    - Verify the service does not silently continue as if it still owns the lease.
    - Test recovery after database connectivity returns.
11. Improve test realism
    - Ensure in-memory repository behavior matches PostgreSQL behavior.
    - Do not rely exclusively on mocks for concurrency and ownership guarantees.

P2 — Reliability and maintainability

12. Validate configuration
    - Reject negative or invalid TTL values.
    - Validate ProcessingTTL, request size, response size, and encryption key.
    - Ensure heartbeat interval cannot become zero.
    - Document sensible production defaults.
13. Review request hashing
    - Verify canonical query parameter handling.
    - Verify method, action, path, content type, and body are consistently included.
    - Explicitly document which request headers are excluded and why.
    - Ensure request body restoration works even when reading fails or the request exceeds the configured limit.
14. Review response capture
    - Verify behavior for WriteHeader(), multiple calls to WriteHeader(), implicit 200 responses, large responses, Flush(), Hijack(), and unsupported streaming scenarios.
    - Ensure the original HTTP response is not corrupted when caching is skipped.
    - Add tests for these cases.
15. Improve cleanup reliability
    - Verify DeleteExpired() safely deletes records in batches.
    - Ensure concurrent cleanup workers cannot cause correctness issues.
    - Recommend an appropriate cleanup execution strategy without automatically starting background goroutines inside the package.
16. Improve error handling and observability
    - Use consistent, meaningful errors.
    - Avoid silently ignoring database or encryption errors.
    - Add structured logging hooks or expose sufficient information for consuming services to monitor claim failures, lease losses, replay counts, and cleanup failures.
    - Do not log raw idempotency keys, tokens, encrypted responses, or sensitive request data.
17. Review public API and documentation
    - Remove redundant constructors or APIs if they create confusion.
    - Document middleware ordering and required configuration.
    - Document retry behavior for HTTP 409, 5xx, and other responses.
    - Document that idempotency protects repeated HTTP requests but does not independently guarantee exactly-once execution across databases, RabbitMQ, or external services.

Important implementation requirements

- Maintain compatibility with the existing Auth and Users services wherever practical.
- Keep database ownership with the consuming microservice.
- Do not introduce Redis or any paid infrastructure dependency.
- Do not introduce unnecessary third-party dependencies.
- Do not automatically run migrations during service startup.
- Preserve AES-GCM encryption for cached responses.
- Add or update tests for every behavior changed.
- Run go test ./... and PostgreSQL integration tests where a test database is available.
- Report which issues were fixed, which remain unresolved, and why.
- Do not mark the package production-ready merely because unit tests pass.
