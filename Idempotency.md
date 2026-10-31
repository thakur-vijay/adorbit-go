Task: Implement Production-Ready Idempotency Layer in AdOrbit Go Package

Act as a Senior Go Backend Engineer and Software Architect.

I am building a reusable Go package called adorbit-go, which is shared across multiple independent microservices in the AdOrbit ecosystem.

I have already created the initial structure for an Idempotency package.

Your task is to inspect the existing implementation and complete a production-ready, reusable, concurrency-safe Idempotency Layer.

IMPORTANT: Before writing or modifying anything, inspect the existing repository structure, coding conventions, database abstractions, response utilities, error handling, middleware patterns, and dependencies.

Do not blindly introduce new abstractions if reusable implementations already exist.

1. Existing Implementation

I have already added the following components:

* middleware.go
* models.go
* service.go
* repository.go
* migrations/001_create_idempotency_keys.up.sql
* migrations/001_create_idempotency_keys.down.sql

The middleware currently:

* Reads the Idempotency-Key HTTP header.
* Validates that the header exists.
* Validates that the value is a valid UUID.
* Stores the key inside the request context.
* Provides GetIdempotencyKey(ctx) to retrieve it.

The existing database table is:

CREATE TABLE idempotency_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    idempotency_key VARCHAR(255) NOT NULL,
    action_type VARCHAR(100) NOT NULL,
    request_hash VARCHAR(64) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'processing',
    response_status_code SMALLINT,
    response_body JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT uq_idempotency_key_action
        UNIQUE (idempotency_key, action_type),
    CONSTRAINT chk_idempotency_status
        CHECK (status IN ('processing', 'completed', 'failed')),
    CONSTRAINT chk_idempotency_response
        CHECK (
            (
                status = 'processing'
                AND response_status_code IS NULL
                AND response_body IS NULL
            )
            OR (
                status IN ('completed', 'failed')
                AND response_status_code IS NOT NULL
                AND response_body IS NOT NULL
            )
        ),
    CONSTRAINT chk_idempotency_expiry
        CHECK (expires_at > created_at)
);
CREATE INDEX idx_idempotency_keys_expires_at
    ON idempotency_keys (expires_at);

You may propose necessary schema improvements if you identify genuine production concerns.

Do not modify the schema without explaining why the change is necessary.

2. Architecture Requirements

This is a shared Go library, NOT a separate microservice.

The architecture must follow these rules:

1. Idempotency logic must live inside adorbit-go/idempotency.
2. Each microservice owns its own database.
3. Each microservice maintains its own idempotency_keys table.
4. All services reuse the same Go implementation.
5. Database connections must be injected from the consuming microservice.
6. The shared package must never create its own database connection.
7. The package must not know anything about Authentication, Users, Campaigns, or other business domains.

For example:

Authentication Service:

idempotencyRepo := idempotency.NewPostgresRepository(authDB)

Users Service:

idempotencyRepo := idempotency.NewPostgresRepository(usersDB)

Both services use the same implementation but operate on their respective databases.

3. Core Functional Requirements

Implement the complete idempotency lifecycle.

A. First Request

When a request arrives:

1. Read the Idempotency-Key from context.
2. Identify the operation using action_type.
3. Generate a deterministic SHA-256 request hash.
4. Check whether the same key and action already exist.
5. If not, atomically create a new record with processing status.
6. Allow the business handler to execute.
7. Capture the original HTTP response.
8. Persist the response status and response body.
9. Update the record to completed or an appropriate terminal failed state.

B. Duplicate Request

When the same request arrives again with the same key:

* If the operation is completed, replay the original HTTP status and response body.
* Do not execute the business handler again.
* Preserve the original response semantics.
* Do not generate another operation.

C. Same Key, Different Payload

If the client reuses an existing key with a different request payload:

* Detect the mismatch using request_hash.
* Return HTTP 409 Conflict.
* Do not execute the business handler.

D. Concurrent Requests

This is one of the most important requirements.

Suppose two identical requests arrive simultaneously with the same Idempotency-Key.

The implementation must guarantee that only one request executes the business handler.

Use PostgreSQL atomic operations, unique constraints, transactions, and appropriate locking where necessary.

Do not implement this using a simple SELECT followed by INSERT.

Define clear behavior for concurrent requests when an operation is already processing.

Avoid unnecessary waiting or unbounded blocking.

E. Failed Operations

Define proper failure semantics.

Differentiate between:

* Successful completed operations.
* Terminal business failures that should be replayed.
* Transient infrastructure failures that may be retried.
* Unexpected server errors.
* Operations interrupted by process crashes.

Do not blindly cache every HTTP 500 response as a permanent failure.

Ensure the system can recover from stale processing records.

4. Request Hashing

Implement a reusable request hashing mechanism.

Requirements:

* Use SHA-256.
* Hash the actual request payload.
* Ensure deterministic hashing.
* Handle empty request bodies.
* Avoid hashing sensitive data into logs.
* Do not store raw passwords or other sensitive request data.
* Restore the HTTP request body after reading it so the original handler can consume it.

Consider relevant request attributes when defining the hashing strategy.

Document which attributes are included and excluded.

5. HTTP Response Capture and Replay

Implement a proper HTTP response writer wrapper.

It must:

* Capture HTTP status code.
* Capture response body.
* Preserve response headers.
* Correctly handle WriteHeader.
* Correctly handle multiple Write calls.
* Default status to HTTP 200 when WriteHeader is not explicitly called.
* Avoid breaking normal HTTP handler behavior.

The original response must be written to the client normally.

For duplicate requests, return the previously stored response without executing the handler.

Do not accidentally change the existing response format used by AdOrbit services.

Also handle response sizes safely and document any limitations.

6. Repository Layer

Implement a clean repository abstraction.

The service layer must not execute SQL directly.

The repository should support operations such as:

* Create an idempotency record atomically.
* Find an existing record.
* Mark an operation completed.
* Mark a terminal failure.
* Handle stale processing records where appropriate.
* Delete expired records.

Use interfaces where they improve testability and database independence.

Implement PostgreSQL-specific behavior inside the PostgreSQL repository.

Use parameterized SQL queries.

Handle PostgreSQL unique constraint violations correctly.

7. Service Layer

The service layer should own the idempotency lifecycle and business-independent rules.

It should handle:

* Key validation at the appropriate layer.
* Request hash comparison.
* Record state transitions.
* Duplicate detection.
* Conflict detection.
* Expiration policy.
* Error classification.
* Concurrency outcomes.

Keep the implementation simple and maintainable.

Avoid unnecessary abstractions and excessive interfaces.

8. Middleware Integration

The consuming microservice should have a very simple integration experience.

Ideally, the API should look conceptually like:

idempotencyService := idempotency.NewService(
    idempotencyRepo,
    idempotency.Config{
        TTL: 24 * time.Hour,
    },
)
idempotencyMiddleware := idempotency.NewHTTPMiddleware(
    idempotencyService,
)

Example route integration:

router.With(
    keyMiddleware.RequireIdempotencyKey,
    idempotencyMiddleware.RequireIdempotency("signup"),
).Post("/signup", signupHandler)

This is an illustrative API, not a mandatory signature.

You may design a better API if necessary.

The final integration should remain straightforward.

A consuming microservice should not need to manually implement:

* Database lookups.
* Request hashing.
* Duplicate detection.
* Response caching.
* Response replay.
* Concurrency handling.

All of these responsibilities must be handled by the shared package.

9. Database Migration Management

The migration files already exist inside the shared package.

Use Go’s embed package where appropriate.

Example:

//go:embed migrations/*.sql
var Migrations embed.FS

The consuming microservice must be able to access these migrations and execute them against its own database.

Do not automatically execute migrations every time the application starts.

The package should expose the embedded migration filesystem or an appropriate migration integration mechanism.

10. Security Requirements

Pay special attention to sensitive response data.

Signup responses may contain:

* Access tokens.
* Refresh tokens.
* User information.

Do not assume storing these responses as plaintext JSONB is safe.

Evaluate an appropriate secure response storage/replay strategy.

Do not log:

* Passwords.
* Access tokens.
* Refresh tokens.
* Full sensitive request bodies.
* Sensitive response bodies.

Also consider:

* Request body size limits.
* Malformed requests.
* Invalid keys.
* SQL injection prevention.
* Expired record handling.

11. Cleanup

Provide an efficient cleanup mechanism for expired records.

Requirements:

* Use the existing expires_at index.
* Delete expired records in batches.
* Avoid long-running transactions.
* Avoid blocking normal application requests.
* Allow consuming services to schedule cleanup independently.

Do not create a background goroutine automatically inside the shared package without explicit lifecycle management.

12. Testing Requirements

Write meaningful unit and integration tests.

At minimum, test:

1. Missing Idempotency-Key.
2. Invalid UUID.
3. First request.
4. Duplicate completed request.
5. Same key with different payload.
6. Concurrent identical requests.
7. Concurrent requests with different payloads.
8. Processing state behavior.
9. Terminal failure replay.
10. Transient infrastructure failure.
11. Expired records.
12. Response status preservation.
13. Response body preservation.
14. Response headers preservation.
15. Recovery from stale processing records.
16. Database errors.
17. Request body restoration.

Use PostgreSQL integration tests for database-specific concurrency behavior.

Do not rely exclusively on mocks to prove concurrency correctness.

13. Code Quality

Follow Go best practices:

* Idiomatic Go.
* Explicit error handling.
* Context propagation.
* Dependency injection.
* Small, focused functions.
* Thread-safe implementation.
* No global database connections.
* No unnecessary goroutines.
* No unnecessary dependencies.
* Clear exported API documentation.

Do not overengineer the package.

I want production-quality code that is easy to understand and maintain.

14. Expected Final Deliverables

After implementation:

1. Show the final package structure.
2. Explain the responsibility of every file.
3. Show the complete public API.
4. Provide a simple Authentication Service integration example.
5. Explain how another microservice injects its own database.
6. Explain how migrations are consumed.
7. Explain the complete request lifecycle.
8. Explain concurrency handling.
9. Explain failure recovery.
10. List all tests and their results.
11. Highlight any schema changes and their reasoning.

Final Architectural Goal

I want this experience in every AdOrbit microservice:

repo := idempotency.NewPostgresRepository(db)
service := idempotency.NewService(
    repo,
    idempotency.Config{
        TTL: 24 * time.Hour,
    },
)
middleware := idempotency.NewHTTPMiddleware(service)

Then the service should be able to protect an endpoint with a simple middleware integration.

The consuming microservice should only provide its own database connection and configure the operation.

Everything else should be reusable.

IMPORTANT:

First inspect the existing code.

Then propose the implementation plan.

After that, implement it while respecting the existing architecture.

Do not rewrite unrelated packages.

Do not introduce unnecessary microservices.

Do not assume the current implementation is correct just because it exists.

If you identify a design flaw, explain it and fix it.

The final result must be a reusable, production-oriented Idempotency Layer for the AdOrbit microservices ecosystem.