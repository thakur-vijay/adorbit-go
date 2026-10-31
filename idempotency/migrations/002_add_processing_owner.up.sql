ALTER TABLE idempotency_keys ADD COLUMN IF NOT EXISTS scope_hash CHAR(64);
-- Legacy rows have no principal identity; this sentinel is never used by scoped requests.
UPDATE idempotency_keys
SET scope_hash = '96f248316ff500fb18cdd1ca9da6403253d24fc5c8d5244af498539e5f895e3f'
WHERE scope_hash IS NULL;
ALTER TABLE idempotency_keys ALTER COLUMN scope_hash SET NOT NULL;
ALTER TABLE idempotency_keys DROP CONSTRAINT IF EXISTS uq_idempotency_key_action;
ALTER TABLE idempotency_keys DROP CONSTRAINT IF EXISTS uq_idempotency_scope_key_action;
ALTER TABLE idempotency_keys ADD CONSTRAINT uq_idempotency_scope_key_action
    UNIQUE (scope_hash, idempotency_key, action_type);
ALTER TABLE idempotency_keys ADD COLUMN IF NOT EXISTS owner_token UUID;
CREATE INDEX IF NOT EXISTS idx_idempotency_keys_owner_token ON idempotency_keys (owner_token) WHERE status = 'processing';
ALTER TABLE idempotency_keys DROP CONSTRAINT IF EXISTS chk_idempotency_response;
ALTER TABLE idempotency_keys ADD CONSTRAINT chk_idempotency_response CHECK (
    (status = 'processing' AND response_status_code IS NULL AND response_body IS NULL)
    OR (status = 'completed' AND response_status_code BETWEEN 200 AND 399 AND response_body IS NOT NULL)
    OR (status = 'failed' AND response_status_code BETWEEN 400 AND 499 AND response_body IS NOT NULL)
);
