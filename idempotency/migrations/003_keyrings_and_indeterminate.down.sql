-- Run this downgrade only with application writes paused and instances drained.
-- Lock in the same order as Claim (key config before record table) so checks
-- cannot race with new claims or operator resolution.
LOCK TABLE idempotency_key_config IN ACCESS EXCLUSIVE MODE;
LOCK TABLE idempotency_keys IN ACCESS EXCLUSIVE MODE;
LOCK TABLE idempotency_resolution_audit IN ACCESS EXCLUSIVE MODE;
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM idempotency_keys WHERE status='processing') THEN
        RAISE EXCEPTION 'drain all processing operations before downgrade';
    END IF;
    IF EXISTS (SELECT 1 FROM idempotency_keys WHERE status='indeterminate') THEN
        RAISE EXCEPTION 'resolve all indeterminate idempotency records before downgrade';
    END IF;
    IF EXISTS (SELECT 1 FROM idempotency_key_config WHERE id=1 AND active_scope_hash_key_id <> 'legacy-v1') THEN
        RAISE EXCEPTION 'restore the legacy-v1 scope epoch before downgrade';
    END IF;
    IF EXISTS (SELECT 1 FROM idempotency_keys WHERE scope_hash_key_id NOT IN ('legacy-v1','legacy-unscoped-v1')) THEN
        RAISE EXCEPTION 'remove records using rotated scope keys before downgrade';
    END IF;
    IF EXISTS (SELECT 1 FROM idempotency_keys WHERE request_hash_version <> 1 OR (status IN ('completed','failed') AND response_format <> 1)) THEN
        RAISE EXCEPTION 'remove records using newer request or response formats before downgrade';
    END IF;
    IF EXISTS (SELECT 1 FROM idempotency_keys WHERE response_key_id IS NOT NULL AND response_key_id <> 'legacy-v1') THEN
        RAISE EXCEPTION 'remove records using rotated response keys before downgrade';
    END IF;
    IF EXISTS (SELECT 1 FROM idempotency_keys GROUP BY scope_hash,idempotency_key,action_type HAVING COUNT(*)>1) THEN
        RAISE EXCEPTION 'resolve duplicate scope/key/action rows before downgrade';
    END IF;
    IF EXISTS (SELECT 1 FROM idempotency_resolution_audit) THEN
        RAISE EXCEPTION 'preserve operator resolution audit before downgrade';
    END IF;
END $$;
DROP INDEX IF EXISTS idx_idempotency_resolution_audit_resolved_at;
DROP TABLE IF EXISTS idempotency_resolution_audit;
DROP TABLE IF EXISTS idempotency_key_config;
DROP INDEX IF EXISTS idx_idempotency_key_versions;
ALTER TABLE idempotency_keys DROP CONSTRAINT IF EXISTS uq_idempotency_scope_key_action;
ALTER TABLE idempotency_keys DROP CONSTRAINT IF EXISTS chk_idempotency_status;
ALTER TABLE idempotency_keys DROP CONSTRAINT IF EXISTS chk_idempotency_response;
ALTER TABLE idempotency_keys DROP CONSTRAINT IF EXISTS chk_idempotency_scope_key_id;
ALTER TABLE idempotency_keys DROP CONSTRAINT IF EXISTS chk_idempotency_response_key_id;
ALTER TABLE idempotency_keys DROP CONSTRAINT IF EXISTS chk_idempotency_request_hash_version;
ALTER TABLE idempotency_keys DROP CONSTRAINT IF EXISTS chk_idempotency_response_format;
ALTER TABLE idempotency_keys DROP COLUMN IF EXISTS response_key_id;
ALTER TABLE idempotency_keys DROP COLUMN IF EXISTS response_format;
ALTER TABLE idempotency_keys DROP COLUMN IF EXISTS request_hash_version;
ALTER TABLE idempotency_keys DROP COLUMN IF EXISTS scope_hash_key_id;
ALTER TABLE idempotency_keys ADD CONSTRAINT uq_idempotency_scope_key_action UNIQUE (scope_hash,idempotency_key,action_type);
ALTER TABLE idempotency_keys ADD CONSTRAINT chk_idempotency_status CHECK (status IN ('processing','completed','failed'));
ALTER TABLE idempotency_keys ADD CONSTRAINT chk_idempotency_response CHECK (
    (status='processing' AND response_status_code IS NULL AND response_body IS NULL)
    OR (status='completed' AND response_status_code BETWEEN 200 AND 399 AND response_body IS NOT NULL)
    OR (status='failed' AND response_status_code BETWEEN 400 AND 499 AND response_body IS NOT NULL)
);
