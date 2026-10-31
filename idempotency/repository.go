package idempotency

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrNotOwner                = errors.New("idempotency operation lease is no longer owned")
	ErrInvalidState            = errors.New("idempotency: invalid terminal state or response")
	ErrNilDatabase             = errors.New("idempotency: nil database")
	ErrScopeHashEpochMismatch  = errors.New("idempotency: active scope key epoch mismatch")
	ErrScopeHashKeyUnavailable = errors.New("idempotency: a scope key version still in use is unavailable")
	ErrNotIndeterminate        = errors.New("idempotency: legacy operation is not indeterminate")
)

var (
	errLegacyScopeConflict      = errors.New("idempotency: key belongs to a legacy unscoped operation")
	errLegacyIndeterminate      = errors.New("idempotency: legacy operation is indeterminate and requires operator resolution")
	errFingerprintIndeterminate = errors.New("idempotency: prior fingerprint version has an indeterminate outcome")
)

// legacyScopeHash is assigned by migration 002 to rows created before scope isolation.
const legacyScopeHash = "96f248316ff500fb18cdd1ca9da6403253d24fc5c8d5244af498539e5f895e3f"

const ResolutionConfirmedNotApplied = "confirmed_not_applied"

// Repository describes the atomic operations required by Service.
type Repository interface {
	Claim(context.Context, []ScopeHashCandidate, ScopeHashCandidate, []RequestHashCandidate, RequestHashCandidate, string, string, string, time.Duration, time.Duration) (*Record, bool, error)
	Refresh(context.Context, string) error
	Complete(context.Context, string, Status, int, string, []byte, time.Time) error
	Release(context.Context, string) error
	DeleteExpired(context.Context, time.Time, int) (int64, error)
}

type IndeterminateResolver interface {
	ResolveLegacyIndeterminate(context.Context, string, string, string, string) error
	ResolveIndeterminate(context.Context, []ScopeHashCandidate, string, string, string, string) error
}
type ScopeEpochController interface {
	SetActiveScopeHashKey(context.Context, string, string) error
}

// PostgresRepository stores idempotency records in the caller's database.
type PostgresRepository struct{ db *sql.DB }

func NewPostgresRepository(db *sql.DB) *PostgresRepository { return &PostgresRepository{db: db} }
func NewRepository(db *sql.DB) *PostgresRepository         { return NewPostgresRepository(db) }

func (r *PostgresRepository) validate() error {
	if r == nil || r.db == nil {
		return ErrNilDatabase
	}
	return nil
}

func (r *PostgresRepository) Claim(ctx context.Context, candidates []ScopeHashCandidate, active ScopeHashCandidate, hashes []RequestHashCandidate, activeHash RequestHashCandidate, key, action, owner string, ttl, staleAfter time.Duration) (*Record, bool, error) {
	if err := r.validate(); err != nil {
		return nil, false, err
	}
	if len(candidates) == 0 || len(hashes) == 0 || !validKeyID(active.KeyID) || len(active.Hash) != 64 || activeHash.Version != currentRequestHashVersion || len(activeHash.Hash) != 64 || key == "" || action == "" || len(action) > 100 || len(key) > 255 || owner == "" || ttl <= 0 || ttl > maxResultTTL || staleAfter < minProcessingTTL || staleAfter > maxProcessingTTL {
		return nil, false, errors.New("idempotency: invalid claim arguments")
	}
	foundActive := false
	for _, c := range candidates {
		if c.KeyID == active.KeyID && c.Hash == active.Hash {
			foundActive = true
		}
		if !validKeyID(c.KeyID) || len(c.Hash) != 64 {
			return nil, false, errors.New("idempotency: invalid scope hash candidate")
		}
	}
	if !foundActive {
		return nil, false, errors.New("idempotency: active scope hash is not a candidate")
	}
	foundActiveHash := false
	for _, candidate := range hashes {
		if candidate.Version == activeHash.Version && candidate.Hash == activeHash.Hash {
			foundActiveHash = true
		}
		if (candidate.Version != legacyRequestHashVersion && candidate.Version != currentRequestHashVersion) || len(candidate.Hash) != 64 {
			return nil, false, errors.New("idempotency: invalid request hash candidate")
		}
	}
	if !foundActiveHash {
		return nil, false, errors.New("idempotency: active request hash is not a candidate")
	}
	claimLease := ttl
	if staleAfter > ttl {
		claimLease = staleAfter
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback()
	var dbActive string
	if err := tx.QueryRowContext(ctx, `SELECT active_scope_hash_key_id FROM idempotency_key_config WHERE id=1 FOR SHARE`).Scan(&dbActive); err != nil {
		return nil, false, err
	}
	if dbActive != active.KeyID {
		return nil, false, ErrScopeHashEpochMismatch
	}
	configuredIDs := make(map[string]struct{}, len(candidates))
	for _, c := range candidates {
		configuredIDs[c.KeyID] = struct{}{}
	}
	rows, err := tx.QueryContext(ctx, `SELECT DISTINCT scope_hash_key_id FROM idempotency_keys WHERE scope_hash_key_id <> $1`, legacyUnscopedKeyID)
	if err != nil {
		return nil, false, err
	}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, false, err
		}
		if _, ok := configuredIDs[id]; !ok {
			rows.Close()
			return nil, false, ErrScopeHashKeyUnavailable
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, false, err
	}
	if err := rows.Close(); err != nil {
		return nil, false, err
	}

	// Legacy unscoped records cannot safely be replayed into a principal scope.
	// A stale processing row becomes a durable ambiguity marker atomically.
	if active.KeyID != legacyUnscopedKeyID {
		var legacy Record
		err := scanRecord(tx.QueryRowContext(ctx, recordSelect+` WHERE scope_hash_key_id=$1 AND scope_hash=$2 AND idempotency_key=$3 AND action_type=$4 AND (status IN ('processing','indeterminate') OR expires_at>NOW()) FOR UPDATE`, legacyUnscopedKeyID, legacyScopeHash, key, action), &legacy)
		if err == nil {
			if legacy.Status == StatusProcessing {
				res, e := tx.ExecContext(ctx, `UPDATE idempotency_keys SET status='indeterminate', owner_token=NULL, updated_at=NOW() WHERE id=$1 AND status='processing' AND updated_at <= NOW()-($2 * interval '1 second')`, legacy.ID, staleAfter.Seconds())
				if e != nil {
					return nil, false, e
				}
				n, e := res.RowsAffected()
				if e != nil {
					return nil, false, e
				}
				if n == 1 {
					if e = tx.Commit(); e != nil {
						return nil, false, e
					}
					return nil, false, errLegacyIndeterminate
				}
				if e = tx.Commit(); e != nil {
					return nil, false, e
				}
				return nil, false, errLegacyScopeConflict
			}
			if legacy.Status == StatusIndeterminate {
				if err = tx.Commit(); err != nil {
					return nil, false, err
				}
				return nil, false, errLegacyIndeterminate
			}
			if err = tx.Commit(); err != nil {
				return nil, false, err
			}
			return nil, false, errLegacyScopeConflict
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return nil, false, err
		}
	}

	// Search all retained scope-key versions before inserting under the active one.
	var rec Record
	for _, candidate := range candidates {
		err = scanRecord(tx.QueryRowContext(ctx, recordSelect+` WHERE scope_hash_key_id=$1 AND scope_hash=$2 AND idempotency_key=$3 AND action_type=$4`, candidate.KeyID, candidate.Hash, key, action), &rec)
		if err == nil {
			break
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return nil, false, err
		}
	}
	if err == nil {
		if rec.Status == StatusIndeterminate {
			_ = tx.Commit()
			return &rec, false, nil
		}
		if rec.Status == StatusProcessing && !rec.UpdatedAt.After(time.Now().Add(-staleAfter)) && !requestHashCandidateMatches(rec.RequestHashVersion, rec.RequestHash, hashes) {
			res, e := tx.ExecContext(ctx, `UPDATE idempotency_keys SET status='indeterminate',owner_token=NULL,updated_at=NOW() WHERE id=$1 AND status='processing' AND updated_at<=NOW()-($2 * interval '1 second')`, rec.ID, staleAfter.Seconds())
			if e != nil {
				return nil, false, e
			}
			n, e := res.RowsAffected()
			if e != nil {
				return nil, false, e
			}
			if n == 0 {
				current := &Record{}
				if e = scanRecord(tx.QueryRowContext(ctx, recordSelect+` WHERE id=$1 FOR UPDATE`, rec.ID), current); e != nil {
					return nil, false, e
				}
				if e = tx.Commit(); e != nil {
					return nil, false, e
				}
				return current, false, nil
			}
			if e = tx.Commit(); e != nil {
				return nil, false, e
			}
			return nil, false, errFingerprintIndeterminate
		}
		if rec.Status == StatusProcessing && requestHashCandidateMatches(rec.RequestHashVersion, rec.RequestHash, hashes) && !rec.UpdatedAt.After(time.Now().Add(-staleAfter)) {
			updated := &Record{}
			e := scanRecord(tx.QueryRowContext(ctx, `UPDATE idempotency_keys SET scope_hash_key_id=$2, scope_hash=$3, request_hash=$4, request_hash_version=$5, status='processing', response_status_code=NULL, response_body=NULL, response_key_id=NULL, response_format=NULL, owner_token=$6, updated_at=NOW(), expires_at=NOW()+($7 * interval '1 second') WHERE id=$1 AND status='processing' AND request_hash=$8 AND request_hash_version=$9 AND updated_at <= NOW()-($10 * interval '1 second') RETURNING `+recordColumns, rec.ID, active.KeyID, active.Hash, activeHash.Hash, activeHash.Version, owner, claimLease.Seconds(), rec.RequestHash, rec.RequestHashVersion, staleAfter.Seconds()), updated)
			if e == nil {
				if e = tx.Commit(); e != nil {
					return nil, false, e
				}
				return updated, true, nil
			}
			if !errors.Is(e, sql.ErrNoRows) {
				return nil, false, e
			}
		}
		if (rec.Status == StatusCompleted || rec.Status == StatusFailed) && !rec.ExpiresAt.After(time.Now()) {
			updated := &Record{}
			e := scanRecord(tx.QueryRowContext(ctx, `UPDATE idempotency_keys SET scope_hash_key_id=$2, scope_hash=$3, request_hash=$4, request_hash_version=$5, status='processing', response_status_code=NULL, response_body=NULL, response_key_id=NULL, response_format=NULL, owner_token=$6, updated_at=NOW(), expires_at=NOW()+($7 * interval '1 second') WHERE id=$1 AND status IN ('completed','failed') AND expires_at<=NOW() RETURNING `+recordColumns, rec.ID, active.KeyID, active.Hash, activeHash.Hash, activeHash.Version, owner, claimLease.Seconds()), updated)
			if e == nil {
				if e = tx.Commit(); e != nil {
					return nil, false, e
				}
				return updated, true, nil
			}
			if !errors.Is(e, sql.ErrNoRows) {
				return nil, false, e
			}
		}
		if err = tx.Commit(); err != nil {
			return nil, false, err
		}
		return &rec, false, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, false, err
	}
	err = scanRecord(tx.QueryRowContext(ctx, `INSERT INTO idempotency_keys (scope_hash_key_id,scope_hash,idempotency_key,action_type,request_hash,request_hash_version,status,owner_token,created_at,updated_at,expires_at) VALUES ($1,$2,$3,$4,$5,$6,'processing',$7,NOW(),NOW(),NOW()+($8 * interval '1 second')) ON CONFLICT (scope_hash_key_id,scope_hash,idempotency_key,action_type) DO NOTHING RETURNING `+recordColumns, active.KeyID, active.Hash, key, action, activeHash.Hash, activeHash.Version, owner, claimLease.Seconds()), &rec)
	if err == nil {
		if err = tx.Commit(); err != nil {
			return nil, false, err
		}
		return &rec, true, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, false, err
	}
	// Concurrent insert: the unique index winner is visible after restarting the transaction.
	if err = tx.Commit(); err != nil {
		return nil, false, err
	}
	return r.lookupCandidates(ctx, candidates, key, action)
}

const recordColumns = `id::text,scope_hash_key_id,scope_hash,response_key_id,request_hash_version,response_format,idempotency_key,action_type,request_hash,status,response_status_code,response_body,created_at,updated_at,expires_at,owner_token`
const recordSelect = `SELECT ` + recordColumns + ` FROM idempotency_keys`

func requestHashCandidateMatches(version int16, hash string, candidates []RequestHashCandidate) bool {
	for _, candidate := range candidates {
		if candidate.Version == version && candidate.Hash == hash {
			return true
		}
	}
	return false
}

func (r *PostgresRepository) lookupCandidates(ctx context.Context, candidates []ScopeHashCandidate, key, action string) (*Record, bool, error) {
	for _, c := range candidates {
		var rec Record
		err := scanRecord(r.db.QueryRowContext(ctx, recordSelect+` WHERE scope_hash_key_id=$1 AND scope_hash=$2 AND idempotency_key=$3 AND action_type=$4`, c.KeyID, c.Hash, key, action), &rec)
		if err == nil {
			return &rec, false, nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return nil, false, err
		}
	}
	return nil, false, sql.ErrNoRows
}

func scanRecord(row *sql.Row, rec *Record) error {
	var statusCode sql.NullInt64
	var responseKey sql.NullString
	var owner sql.NullString
	var responseFormat sql.NullInt64
	var body []byte
	err := row.Scan(&rec.ID, &rec.ScopeHashKeyID, &rec.ScopeHash, &responseKey, &rec.RequestHashVersion, &responseFormat, &rec.IdempotencyKey, &rec.ActionType, &rec.RequestHash, &rec.Status, &statusCode, &body, &rec.CreatedAt, &rec.UpdatedAt, &rec.ExpiresAt, &owner)
	if err != nil {
		return err
	}
	if statusCode.Valid {
		rec.ResponseStatus = int(statusCode.Int64)
	}
	if responseKey.Valid {
		rec.ResponseKeyID = responseKey.String
	}
	if responseFormat.Valid {
		rec.ResponseFormat = int16(responseFormat.Int64)
	}
	if owner.Valid {
		rec.OwnerToken = owner.String
	}
	if len(body) > 0 {
		var encrypted string
		if err := json.Unmarshal(body, &encrypted); err != nil {
			return err
		}
		rec.Response = []byte(encrypted)
	}
	return nil
}

func (r *PostgresRepository) Complete(ctx context.Context, owner string, state Status, status int, responseKeyID string, response []byte, expiry time.Time) error {
	if err := r.validate(); err != nil {
		return err
	}
	if owner == "" || !validKeyID(responseKeyID) || !validTerminalState(state, status) || len(response) == 0 || !expiry.After(time.Now()) {
		return ErrInvalidState
	}
	encoded, err := json.Marshal(string(response))
	if err != nil {
		return err
	}
	result, err := r.db.ExecContext(ctx, `UPDATE idempotency_keys SET status=$2,response_status_code=$3,response_key_id=$4,response_format=$5,response_body=$6::jsonb,updated_at=NOW(),expires_at=$7 WHERE owner_token=$1 AND status='processing'`, owner, state, status, responseKeyID, currentResponseFormat, string(encoded), expiry)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrNotOwner
	}
	return nil
}
func validTerminalState(state Status, status int) bool {
	if status < 200 || status > 599 {
		return false
	}
	switch state {
	case StatusCompleted:
		return status < 400
	case StatusFailed:
		return status >= 400 && status < 500
	default:
		return false
	}
}
func (r *PostgresRepository) Refresh(ctx context.Context, owner string) error {
	if err := r.validate(); err != nil {
		return err
	}
	if owner == "" {
		return ErrNotOwner
	}
	result, err := r.db.ExecContext(ctx, `UPDATE idempotency_keys SET updated_at=NOW() WHERE owner_token=$1 AND status='processing'`, owner)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrNotOwner
	}
	return nil
}
func (r *PostgresRepository) Release(ctx context.Context, owner string) error {
	if err := r.validate(); err != nil {
		return err
	}
	if owner == "" {
		return ErrNotOwner
	}
	result, err := r.db.ExecContext(ctx, `DELETE FROM idempotency_keys WHERE owner_token=$1 AND status='processing'`, owner)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrNotOwner
	}
	return nil
}
func (r *PostgresRepository) DeleteExpired(ctx context.Context, now time.Time, limit int) (int64, error) {
	if err := r.validate(); err != nil {
		return 0, err
	}
	if limit <= 0 {
		return 0, errors.New("idempotency: cleanup limit must be positive")
	}
	result, err := r.db.ExecContext(ctx, `DELETE FROM idempotency_keys WHERE id IN (SELECT id FROM idempotency_keys WHERE expires_at<=$1 AND status IN ('completed','failed') ORDER BY expires_at LIMIT $2 FOR UPDATE SKIP LOCKED)`, now, limit)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// ResolveLegacyIndeterminate removes a blocked unscoped legacy row only after
// an operator confirms the effect definitely did not occur. The audit insert
// and deletion commit atomically.
func (r *PostgresRepository) ResolveLegacyIndeterminate(ctx context.Context, key, action, actor, resolution string) error {
	return r.resolveIndeterminate(ctx, []ScopeHashCandidate{{KeyID: legacyUnscopedKeyID, Hash: legacyScopeHash}}, key, action, actor, resolution)
}

// ResolveIndeterminate resolves a scoped ambiguous record by its trusted scope.
func (r *PostgresRepository) ResolveIndeterminate(ctx context.Context, candidates []ScopeHashCandidate, key, action, actor, resolution string) error {
	return r.resolveIndeterminate(ctx, candidates, key, action, actor, resolution)
}

func (r *PostgresRepository) resolveIndeterminate(ctx context.Context, candidates []ScopeHashCandidate, key, action, actor, resolution string) error {
	if err := r.validate(); err != nil {
		return err
	}
	if len(candidates) == 0 || key == "" || len(key) > 255 || !validAction(action) || actor == "" || strings.TrimSpace(actor) != actor || len(actor) > 128 || !validAuditActor(actor) || resolution != ResolutionConfirmedNotApplied {
		return ErrInvalidState
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var recordID string
	for _, candidate := range candidates {
		if !validKeyID(candidate.KeyID) || len(candidate.Hash) != 64 {
			return ErrInvalidState
		}
		err = tx.QueryRowContext(ctx, `SELECT id::text FROM idempotency_keys WHERE scope_hash_key_id=$1 AND scope_hash=$2 AND idempotency_key=$3 AND action_type=$4 AND status='indeterminate' FOR UPDATE`, candidate.KeyID, candidate.Hash, key, action).Scan(&recordID)
		if err == nil {
			break
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
	}
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotIndeterminate
	}
	if err != nil {
		return err
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM idempotency_keys WHERE id=$1 AND status='indeterminate'`, recordID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrNotIndeterminate
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO idempotency_resolution_audit(record_id,actor,action_type,resolution) VALUES($1,$2,$3,$4)`, recordID, actor, action, resolution); err != nil {
		return err
	}
	return tx.Commit()
}

func validAuditActor(actor string) bool {
	for _, r := range actor {
		if r < 0x21 || r == 0x7f {
			return false
		}
	}
	return true
}

// SetActiveScopeHashKey performs a compare-and-swap epoch change. Claims hold a
// shared lock on this row for their transaction, making the cutover a barrier.
func (r *PostgresRepository) SetActiveScopeHashKey(ctx context.Context, expected, next string) error {
	if err := r.validate(); err != nil {
		return err
	}
	if !validKeyID(expected) || !validKeyID(next) {
		return fmt.Errorf("idempotency: invalid scope key ID")
	}
	res, err := r.db.ExecContext(ctx, `UPDATE idempotency_key_config SET active_scope_hash_key_id=$2,updated_at=NOW() WHERE id=1 AND active_scope_hash_key_id=$1`, expected, next)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrScopeHashEpochMismatch
	}
	return nil
}
