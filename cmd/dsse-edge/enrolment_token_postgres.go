package main

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/enrolltoken"
)

// The Postgres-backed enrolment-token authority.
//
// It exists for one property the in-memory store cannot provide: a token has to be spendable exactly once across
// EVERY Edge, not once per Edge. The in-memory store loads its persister at boot and mutates a copy, so two Edges
// sharing a blob would each have their own idea of what had been spent and could both honour the same token —
// "one-time" would quietly mean "once per Edge". Here the decision is a single conditional UPDATE, and the
// database makes it.
//
// Everything else is deliberately the same shape as the in-memory store, including hashing, so a deployment can
// move between them without the tokens it already issued becoming unrecognisable.
type postgresEnrolmentTokenStore struct {
	db *sql.DB
}

func newPostgresEnrolmentTokenStore(db *sql.DB) *postgresEnrolmentTokenStore {
	return &postgresEnrolmentTokenStore{db: db}
}

var _ enrolltoken.Authority = (*postgresEnrolmentTokenStore)(nil)

const enrolmentTokenColumns = `id, token_hash, tenant_id, device_group, label, issued_by, issued_by_label,
	issued_at, expires_at, used_at, used_by, revoked_at, revoked_by`

func scanEnrolmentToken(scan func(dest ...any) error) (enrolltoken.Token, error) {
	var (
		t                             enrolltoken.Token
		issuedAt, expiresAt           time.Time
		usedAt, revokedAt             sql.NullTime
		usedBy, revokedBy, grp, label sql.NullString
		// Null for every token issued before the column existed; the display resolves the id instead while the
		// account is still there.
		issuedByLabel sql.NullString
	)
	if err := scan(&t.ID, &t.Hash, &t.TenantID, &grp, &label, &t.IssuedBy, &issuedByLabel,
		&issuedAt, &expiresAt, &usedAt, &usedBy, &revokedAt, &revokedBy); err != nil {
		return enrolltoken.Token{}, err
	}
	t.Group, t.Label = grp.String, label.String
	t.IssuedByLabel = issuedByLabel.String
	t.IssuedAt = issuedAt.UTC().Format(time.RFC3339)
	t.ExpiresAt = expiresAt.UTC().Format(time.RFC3339)
	if usedAt.Valid {
		t.UsedAt = usedAt.Time.UTC().Format(time.RFC3339)
		t.UsedBy = usedBy.String
	}
	if revokedAt.Valid {
		t.RevokedAt = revokedAt.Time.UTC().Format(time.RFC3339)
		t.RevokedBy = revokedBy.String
	}
	return t, nil
}

func (s *postgresEnrolmentTokenStore) Issue(policy enrolltoken.Policy, tenantID, group, label, issuedBy, issuedByLabel string,
	expiresAt, now time.Time) (enrolltoken.Token, string, error) {
	return s.IssueContext(context.Background(), policy, tenantID, group, label, issuedBy, issuedByLabel, expiresAt, now)
}

func (s *postgresEnrolmentTokenStore) IssueContext(parent context.Context, policy enrolltoken.Policy, tenantID, group, label, issuedBy, issuedByLabel string, expiresAt, now time.Time) (enrolltoken.Token, string, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return enrolltoken.Token{}, "", fmt.Errorf("tenant is required")
	}
	if strings.TrimSpace(issuedBy) == "" {
		return enrolltoken.Token{}, "", fmt.Errorf("issuing admin is required")
	}
	if !expiresAt.After(now) {
		return enrolltoken.Token{}, "", enrolltoken.ErrLifetimeNotFuture
	}
	if policy.MaxLifetime > 0 && expiresAt.Sub(now) > policy.MaxLifetime {
		return enrolltoken.Token{}, "", enrolltoken.ErrLifetimeTooLong
	}
	ctx, cancel := context.WithTimeout(parent, cpStateBlobDBTimeout)
	defer cancel()
	budget := newCPStatementBudget(ctx)
	defer budget.cancel()
	tx, finish, err := beginCPWriteTransactionContexts(ctx, budget.sqlCtx, s.db, nil)
	if err != nil {
		return enrolltoken.Token{}, "", fmt.Errorf("%w: %v", enrolltoken.ErrStateUnavailable, err)
	}
	defer finish()
	defer tx.Rollback()
	// All issuers, including unlimited-policy callers, serialize on the tenant.
	// A transaction-scoped two-key lock is separate from the CP election lock.
	if _, err := budget.exec(tx, `SELECT pg_advisory_xact_lock(1162760780, hashtext(lower($1)))`, tenantID); err != nil {
		return enrolltoken.Token{}, "", fmt.Errorf("%w: %v", enrolltoken.ErrStateUnavailable, err)
	}
	if policy.MaxOutstanding > 0 {
		var outstanding int
		if err := budget.queryRow(tx, `SELECT count(*) FROM enrolment_tokens WHERE lower(tenant_id)=lower($1) AND used_at IS NULL AND revoked_at IS NULL AND expires_at>$2`, tenantID, now.UTC()).Scan(&outstanding); err != nil {
			return enrolltoken.Token{}, "", fmt.Errorf("%w: %v", enrolltoken.ErrStateUnavailable, err)
		}
		if outstanding >= policy.MaxOutstanding {
			return enrolltoken.Token{}, "", enrolltoken.ErrOutstandingCap
		}
	}
	secret, err := enrolltoken.NewSecret()
	if err != nil {
		return enrolltoken.Token{}, "", err
	}
	id, err := enrolltoken.NewID()
	if err != nil {
		return enrolltoken.Token{}, "", err
	}
	tok := enrolltoken.Token{
		ID: id, Hash: enrolltoken.HashSecret(secret), TenantID: tenantID,
		Group: strings.TrimSpace(group), Label: strings.TrimSpace(label), IssuedBy: strings.TrimSpace(issuedBy),
		IssuedByLabel: strings.TrimSpace(issuedByLabel),
		IssuedAt:      now.UTC().Format(time.RFC3339), ExpiresAt: expiresAt.UTC().Format(time.RFC3339),
	}
	if _, err := budget.exec(tx, `INSERT INTO enrolment_tokens
		(id, token_hash, tenant_id, device_group, label, issued_by, issued_by_label, issued_at, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		tok.ID, tok.Hash, tok.TenantID, tok.Group, tok.Label, tok.IssuedBy, tok.IssuedByLabel, now.UTC(), expiresAt.UTC()); err != nil {
		return enrolltoken.Token{}, "", fmt.Errorf("%w: insert enrolment token: %v", enrolltoken.ErrStateUnavailable, err)
	}
	if err := budget.commit(tx); err != nil {
		return enrolltoken.Token{}, "", fmt.Errorf("%w: %v", enrolltoken.ErrStateUnavailable, err)
	}
	return tok, secret, nil
}

// Verify answers "would this work right now" without spending, so the enrolment endpoint can run its remaining
// checks — a device an admin disabled is refused — before burning a credential the admin would have to re-issue.
func (s *postgresEnrolmentTokenStore) Verify(secret, tenantID string, now time.Time) (enrolltoken.Token, error) {
	row := s.db.QueryRow(`SELECT `+enrolmentTokenColumns+` FROM enrolment_tokens WHERE token_hash = $1`,
		enrolltoken.HashSecret(secret))
	tok, err := scanEnrolmentToken(row.Scan)
	if err == sql.ErrNoRows {
		return enrolltoken.Token{}, enrolltoken.ErrUnknownToken
	}
	if err != nil {
		return enrolltoken.Token{}, fmt.Errorf("read enrolment token: %w", err)
	}
	return tok, enrolmentTokenUsability(tok, tenantID, now)
}

// Spend is the whole reason this implementation exists. ONE statement decides: the row moves from unspent to
// spent only if it is still unspent, unrevoked, unexpired and this tenant's, so two Edges racing with a copied
// installer config produce exactly one enrolment no matter how the timing falls.
//
// A zero-row result is not an error in itself — it means somebody else got there first, or the token lapsed
// between the verify and here. The reason is read back afterwards purely so the operator's log says which.
func (s *postgresEnrolmentTokenStore) Spend(id, tenantID, deviceID string, now time.Time) (enrolltoken.Token, error) {
	return s.SpendContext(context.Background(), id, tenantID, deviceID, now)
}

func (s *postgresEnrolmentTokenStore) SpendContext(parent context.Context, id, tenantID, deviceID string, now time.Time) (enrolltoken.Token, error) {
	ctx, cancel := context.WithTimeout(parent, cpStateBlobDBTimeout)
	defer cancel()
	budget := newCPStatementBudget(ctx)
	defer budget.cancel()
	tx, finish, err := beginCPWriteTransactionContexts(ctx, budget.sqlCtx, s.db, nil)
	if err != nil {
		return enrolltoken.Token{}, fmt.Errorf("%w: %v", enrolltoken.ErrStateUnavailable, err)
	}
	defer finish()
	defer tx.Rollback()
	id = strings.TrimSpace(id)
	tok, err := scanEnrolmentToken(budget.queryRow(tx, `UPDATE enrolment_tokens SET used_at=$1, used_by=$2
 WHERE id=$3 AND used_at IS NULL AND revoked_at IS NULL AND expires_at>$1
 AND ($4='' OR lower(tenant_id)=lower($4)) RETURNING `+enrolmentTokenColumns,
		now.UTC(), strings.TrimSpace(deviceID), id, strings.TrimSpace(tenantID)).Scan)
	if err == nil {
		if err := budget.commit(tx); err != nil {
			return enrolltoken.Token{}, fmt.Errorf("%w: %v", enrolltoken.ErrStateUnavailable, err)
		}
		return tok, nil
	}
	if err != sql.ErrNoRows {
		return enrolltoken.Token{}, fmt.Errorf("%w: %v", enrolltoken.ErrStateUnavailable, err)
	}
	tok, err = scanEnrolmentToken(budget.queryRow(tx, `SELECT `+enrolmentTokenColumns+` FROM enrolment_tokens WHERE id=$1`, id).Scan)
	if err == sql.ErrNoRows {
		return enrolltoken.Token{}, enrolltoken.ErrUnknownToken
	}
	if err != nil {
		return enrolltoken.Token{}, fmt.Errorf("%w: %v", enrolltoken.ErrStateUnavailable, err)
	}
	if reason := enrolmentTokenUsability(tok, tenantID, now); reason != nil {
		return enrolltoken.Token{}, reason
	}
	return enrolltoken.Token{}, &enrolltoken.AlreadyUsedError{UsedBy: tok.UsedBy, UsedAt: tok.UsedAt}
}

// enrolmentTokenUsability names the most specific reason a token cannot be spent, mirroring the in-memory store's
// ordering so an operator's log reads the same whichever backend is in use.
func enrolmentTokenUsability(tok enrolltoken.Token, tenantID string, now time.Time) error {
	if tok.RevokedAt != "" {
		return enrolltoken.ErrTokenRevoked
	}
	if tok.UsedAt != "" {
		// ★★★ THE SAME SENTENCE FROM WHICHEVER STORE IS RUNNING (2026-09-01, caught on the live deployment
		// AFTER the in-memory store had been fixed and the test passed). A generated deployment runs THIS
		// store, so a refusal improved only in the other one improves nothing an operator will ever read —
		// the wire came back error="used" with used_by empty, from a control plane running the new build.
		return &enrolltoken.AlreadyUsedError{UsedBy: tok.UsedBy, UsedAt: tok.UsedAt}
	}
	if !tok.Outstanding(now) {
		return enrolltoken.ErrTokenExpired
	}
	if t := strings.TrimSpace(tenantID); t != "" && !strings.EqualFold(t, tok.TenantID) {
		return enrolltoken.ErrWrongTenant
	}
	return nil
}

// Compatibility callers cannot report storage errors; management uses the checked,
// tenant-scoped operation below.
func (s *postgresEnrolmentTokenStore) Revoke(id, revokedBy string, now time.Time) (enrolltoken.Token, bool) {
	tok, ok, _ := s.RevokeForTenantContext(context.Background(), "", id, revokedBy, now)
	return tok, ok
}

func (s *postgresEnrolmentTokenStore) RevokeForTenantContext(parent context.Context, tenant, id, revokedBy string, now time.Time) (enrolltoken.Token, bool, error) {
	ctx, cancel := context.WithTimeout(parent, cpStateBlobDBTimeout)
	defer cancel()
	budget := newCPStatementBudget(ctx)
	defer budget.cancel()
	tx, finish, err := beginCPWriteTransactionContexts(ctx, budget.sqlCtx, s.db, nil)
	if err != nil {
		return enrolltoken.Token{}, false, err
	}
	defer finish()
	defer tx.Rollback()
	// RETURNING ties the reported identity to the mutation, without a second read
	// which could fail after the revocation has already committed.
	tok, err := scanEnrolmentToken(budget.queryRow(tx, `UPDATE enrolment_tokens SET revoked_at=$1, revoked_by=$2
 WHERE id=$3 AND revoked_at IS NULL AND ($4='' OR lower(tenant_id)=lower($4)) RETURNING `+enrolmentTokenColumns,
		now.UTC(), strings.TrimSpace(revokedBy), strings.TrimSpace(id), strings.TrimSpace(tenant)).Scan)
	if err == sql.ErrNoRows {
		return enrolltoken.Token{}, false, nil
	}
	if err != nil {
		return enrolltoken.Token{}, false, err
	}
	if err := budget.commit(tx); err != nil {
		return enrolltoken.Token{}, false, err
	}
	return tok, true, nil
}

func (s *postgresEnrolmentTokenStore) List(tenantID string) []enrolltoken.Token {
	tokens, _ := s.ListContext(context.Background(), tenantID)
	return tokens
}

func (s *postgresEnrolmentTokenStore) ListContext(parent context.Context, tenantID string) ([]enrolltoken.Token, error) {
	ctx, cancel := context.WithTimeout(parent, cpStateBlobDBTimeout)
	defer cancel()
	query := `SELECT ` + enrolmentTokenColumns + ` FROM enrolment_tokens`
	args := []any{}
	if t := strings.TrimSpace(tenantID); t != "" {
		query += ` WHERE lower(tenant_id) = lower($1)`
		args = append(args, t)
	}
	query += ` ORDER BY issued_at DESC, id ASC`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []enrolltoken.Token{}
	for rows.Next() {
		tok, err := scanEnrolmentToken(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, tok)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *postgresEnrolmentTokenStore) Outstanding(tenantID string, now time.Time) int {
	n, err := s.OutstandingContext(context.Background(), tenantID, now)
	if err != nil {
		return 1 << 30
	} // Compatibility callers fail closed.
	return n
}
func (s *postgresEnrolmentTokenStore) OutstandingContext(parent context.Context, tenantID string, now time.Time) (int, error) {
	ctx, cancel := context.WithTimeout(parent, cpStateBlobDBTimeout)
	defer cancel()
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM enrolment_tokens WHERE lower(tenant_id)=lower($1) AND used_at IS NULL AND revoked_at IS NULL AND expires_at>$2`, strings.TrimSpace(tenantID), now.UTC()).Scan(&n)
	return n, err
}

func (s *postgresEnrolmentTokenStore) ExpiringWithin(tenantID string, window time.Duration, now time.Time) []enrolltoken.Token {
	rows, err := s.db.Query(`SELECT `+enrolmentTokenColumns+` FROM enrolment_tokens
		 WHERE lower(tenant_id) = lower($1) AND used_at IS NULL AND revoked_at IS NULL
		   AND expires_at > $2 AND expires_at < $3
		 ORDER BY expires_at ASC`,
		strings.TrimSpace(tenantID), now.UTC(), now.Add(window).UTC())
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []enrolltoken.Token
	for rows.Next() {
		if tok, err := scanEnrolmentToken(rows.Scan); err == nil {
			out = append(out, tok)
		}
	}
	return out
}
