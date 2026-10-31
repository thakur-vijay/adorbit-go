CREATE TABLE
    idempotency_keys (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
        scope_hash CHAR(64) NOT NULL,
        idempotency_key VARCHAR(255) NOT NULL,
        action_type VARCHAR(100) NOT NULL,
        request_hash VARCHAR(64) NOT NULL,
        status VARCHAR(20) NOT NULL DEFAULT 'processing',
        owner_token UUID,
        response_status_code SMALLINT,
        response_body JSONB,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW (),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW (),
        expires_at TIMESTAMPTZ NOT NULL,
        CONSTRAINT uq_idempotency_scope_key_action UNIQUE (scope_hash, idempotency_key, action_type),
        CONSTRAINT chk_idempotency_status CHECK (status IN ('processing', 'completed', 'failed')),
        CONSTRAINT chk_idempotency_response CHECK (
            (
                status = 'processing'
                AND response_status_code IS NULL
                AND response_body IS NULL
            )
            OR (
                status = 'completed'
                AND response_status_code BETWEEN 200 AND 399
                AND response_body IS NOT NULL
            )
            OR (
                status = 'failed'
                AND response_status_code BETWEEN 400 AND 499
                AND response_body IS NOT NULL
            )
        ),
        CONSTRAINT chk_idempotency_expiry CHECK (expires_at > created_at)
    );

CREATE INDEX idx_idempotency_keys_expires_at ON idempotency_keys (expires_at);
CREATE INDEX idx_idempotency_keys_owner_token ON idempotency_keys (owner_token) WHERE status = 'processing';
