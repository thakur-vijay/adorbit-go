-- Downgrading removes principal isolation. Do not do so while scoped data exists.
LOCK TABLE idempotency_keys IN ACCESS EXCLUSIVE MODE;
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM idempotency_keys WHERE status='processing') THEN
        RAISE EXCEPTION 'drain processing operations before removing lease ownership';
    END IF;
    IF EXISTS (SELECT 1 FROM idempotency_keys GROUP BY idempotency_key,action_type HAVING COUNT(*)>1) THEN
        RAISE EXCEPTION 'resolve global idempotency-key collisions before downgrade';
    END IF;
    IF EXISTS (SELECT 1 FROM idempotency_keys WHERE scope_hash <> '96f248316ff500fb18cdd1ca9da6403253d24fc5c8d5244af498539e5f895e3f') THEN
        RAISE EXCEPTION 'cannot remove scope isolation while scoped idempotency records exist';
    END IF;
END $$;
DROP INDEX IF EXISTS idx_idempotency_keys_owner_token;
ALTER TABLE idempotency_keys DROP CONSTRAINT IF EXISTS uq_idempotency_scope_key_action;
-- This downgrade can still fail if retained legacy rows collide globally.
ALTER TABLE idempotency_keys ADD CONSTRAINT uq_idempotency_key_action UNIQUE (idempotency_key, action_type);
ALTER TABLE idempotency_keys DROP COLUMN IF EXISTS scope_hash;
ALTER TABLE idempotency_keys DROP CONSTRAINT IF EXISTS chk_idempotency_response;
ALTER TABLE idempotency_keys ADD CONSTRAINT chk_idempotency_response CHECK (
    (status = 'processing' AND response_status_code IS NULL AND response_body IS NULL)
    OR (status IN ('completed', 'failed') AND response_status_code IS NOT NULL AND response_body IS NOT NULL)
);
ALTER TABLE idempotency_keys DROP COLUMN IF EXISTS owner_token;
