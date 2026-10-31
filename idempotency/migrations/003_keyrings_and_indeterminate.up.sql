-- Preserve hashes and ciphertext created before key IDs and format versions existed.
ALTER TABLE idempotency_keys ADD COLUMN IF NOT EXISTS scope_hash_key_id VARCHAR(64);
ALTER TABLE idempotency_keys ADD COLUMN IF NOT EXISTS response_key_id VARCHAR(64);
ALTER TABLE idempotency_keys ADD COLUMN IF NOT EXISTS request_hash_version SMALLINT;
ALTER TABLE idempotency_keys ADD COLUMN IF NOT EXISTS response_format SMALLINT;
UPDATE idempotency_keys SET scope_hash_key_id = CASE
    WHEN scope_hash = '96f248316ff500fb18cdd1ca9da6403253d24fc5c8d5244af498539e5f895e3f' THEN 'legacy-unscoped-v1'
    ELSE 'legacy-v1' END
WHERE scope_hash_key_id IS NULL;
UPDATE idempotency_keys SET response_key_id='legacy-v1', response_format=1
WHERE response_key_id IS NULL AND status IN ('completed','failed');
UPDATE idempotency_keys SET request_hash_version=1 WHERE request_hash_version IS NULL;
ALTER TABLE idempotency_keys ALTER COLUMN scope_hash_key_id SET NOT NULL;
ALTER TABLE idempotency_keys ALTER COLUMN request_hash_version SET NOT NULL;
ALTER TABLE idempotency_keys ALTER COLUMN request_hash_version SET DEFAULT 2;
ALTER TABLE idempotency_keys DROP CONSTRAINT IF EXISTS uq_idempotency_scope_key_action;
ALTER TABLE idempotency_keys DROP CONSTRAINT IF EXISTS chk_idempotency_status;
ALTER TABLE idempotency_keys DROP CONSTRAINT IF EXISTS chk_idempotency_response;
ALTER TABLE idempotency_keys ADD CONSTRAINT uq_idempotency_scope_key_action
    UNIQUE (scope_hash_key_id, scope_hash, idempotency_key, action_type);
ALTER TABLE idempotency_keys ADD CONSTRAINT chk_idempotency_status
    CHECK (status IN ('processing','completed','failed','indeterminate'));
ALTER TABLE idempotency_keys ADD CONSTRAINT chk_idempotency_scope_key_id
    CHECK (scope_hash_key_id ~ '^[A-Za-z0-9_.-]{1,64}$');
ALTER TABLE idempotency_keys ADD CONSTRAINT chk_idempotency_response_key_id
    CHECK (response_key_id IS NULL OR response_key_id ~ '^[A-Za-z0-9_.-]{1,64}$');
ALTER TABLE idempotency_keys ADD CONSTRAINT chk_idempotency_request_hash_version
    CHECK (request_hash_version IN (1,2));
ALTER TABLE idempotency_keys ADD CONSTRAINT chk_idempotency_response_format
    CHECK (response_format IS NULL OR response_format IN (1,2));
ALTER TABLE idempotency_keys ADD CONSTRAINT chk_idempotency_response CHECK (
    (status = 'processing' AND response_status_code IS NULL AND response_body IS NULL AND response_key_id IS NULL AND response_format IS NULL)
    OR (status = 'indeterminate' AND response_status_code IS NULL AND response_body IS NULL AND response_key_id IS NULL AND response_format IS NULL AND owner_token IS NULL)
    OR (status = 'completed' AND response_status_code BETWEEN 200 AND 399 AND response_body IS NOT NULL AND response_key_id IS NOT NULL AND response_format IS NOT NULL)
    OR (status = 'failed' AND response_status_code BETWEEN 400 AND 499 AND response_body IS NOT NULL AND response_key_id IS NOT NULL AND response_format IS NOT NULL)
);
CREATE INDEX IF NOT EXISTS idx_idempotency_key_versions ON idempotency_keys (scope_hash_key_id, scope_hash);
CREATE TABLE IF NOT EXISTS idempotency_key_config (
    id SMALLINT PRIMARY KEY CHECK (id=1),
    active_scope_hash_key_id VARCHAR(64) NOT NULL CHECK (active_scope_hash_key_id ~ '^[A-Za-z0-9_.-]{1,64}$'),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
INSERT INTO idempotency_key_config(id,active_scope_hash_key_id) VALUES (1,'legacy-v1') ON CONFLICT (id) DO NOTHING;

-- Durable resolution audit is committed atomically with deletion of the blocked record.
CREATE TABLE IF NOT EXISTS idempotency_resolution_audit (
    id BIGSERIAL PRIMARY KEY,
    record_id UUID NOT NULL,
    actor VARCHAR(128) NOT NULL CHECK (length(actor)>0),
    action_type VARCHAR(100) NOT NULL,
    resolution VARCHAR(32) NOT NULL CHECK (resolution='confirmed_not_applied'),
    resolved_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_idempotency_resolution_audit_resolved_at ON idempotency_resolution_audit(resolved_at);
