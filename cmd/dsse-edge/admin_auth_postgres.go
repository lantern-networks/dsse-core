package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"
)

type postgresAdminAuthStore struct {
	DB *sql.DB
}

var _ adminAuthRuntimeStore = postgresAdminAuthStore{}
var _ adminAuthStatsReader = postgresAdminAuthStore{}

// PrincipalIDForSubject is the Postgres side of the same question the cache answers: does this organization
// already know this person, and by what id. It exists here because the deployment the documentation names for
// production uses this store, and a fix that only works on the cache is a fix that does not ship.
func (p postgresAdminAuthStore) PrincipalIDForSubject(tenantID, subject string) (string, bool) {
	if p.DB == nil {
		return "", false
	}
	want := strings.ToLower(strings.TrimSpace(subject))
	if want == "" {
		return "", false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var id string
	err := p.DB.QueryRowContext(ctx,
		"SELECT admin_principal_id FROM admin_principals WHERE tenant_id = $1 AND lower(subject) = $2 LIMIT 1",
		strings.TrimSpace(tenantID), want).Scan(&id)
	if err != nil || strings.TrimSpace(id) == "" {
		return "", false
	}
	return id, true
}

type postgresAdminAuthStatement struct {
	SQL  string
	Args []any
}

func (store postgresAdminAuthStore) PersistPrincipal(ctx context.Context, principal adminPrincipal) error {
	if store.DB == nil {
		return fmt.Errorf("postgres admin auth db is not configured")
	}
	statement, err := buildPostgresAdminPrincipalUpsertStatement(principal)
	if err != nil {
		return err
	}
	ctx = normalizePostgresExportTaskContext(ctx)
	_, err = store.DB.ExecContext(ctx, statement.SQL, statement.Args...)
	return err
}

func (store postgresAdminAuthStore) PersistSession(ctx context.Context, session adminSession) error {
	if store.DB == nil {
		return fmt.Errorf("postgres admin auth db is not configured")
	}
	statement, err := buildPostgresAdminSessionUpsertStatement(session)
	if err != nil {
		return err
	}
	ctx = normalizePostgresExportTaskContext(ctx)
	_, err = store.DB.ExecContext(ctx, statement.SQL, statement.Args...)
	return err
}

func (store postgresAdminAuthStore) PersistAPIToken(ctx context.Context, token adminAPIToken) error {
	if store.DB == nil {
		return fmt.Errorf("postgres admin auth db is not configured")
	}
	statement, err := buildPostgresAdminAPITokenUpsertStatement(token)
	if err != nil {
		return err
	}
	ctx = normalizePostgresExportTaskContext(ctx)
	_, err = store.DB.ExecContext(ctx, statement.SQL, statement.Args...)
	return err
}

func (store postgresAdminAuthStore) FindPrincipal(ctx context.Context, id, tenantID string) (adminPrincipal, bool, error) {
	if store.DB == nil {
		return adminPrincipal{}, false, fmt.Errorf("postgres admin auth db is not configured")
	}
	statement, err := buildPostgresAdminPrincipalGetStatement(tenantID, id)
	if err != nil {
		return adminPrincipal{}, false, err
	}
	ctx = normalizePostgresExportTaskContext(ctx)
	var payload []byte
	if err := store.DB.QueryRowContext(ctx, statement.SQL, statement.Args...).Scan(&payload); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return adminPrincipal{}, false, nil
		}
		return adminPrincipal{}, false, err
	}
	principal, err := decodePostgresAdminPrincipalPayload(payload)
	if err != nil {
		return adminPrincipal{}, false, err
	}
	return principal, true, nil
}

func (store postgresAdminAuthStore) HasAuthRecords(ctx context.Context, tenantID string) (bool, error) {
	stats, err := store.AdminAuthStats(ctx, tenantID)
	if err != nil {
		return false, err
	}
	return stats.Total > 0, nil
}

func (store postgresAdminAuthStore) AdminAuthStats(ctx context.Context, tenantID string) (adminAuthStoreStats, error) {
	if store.DB == nil {
		return adminAuthStoreStats{}, fmt.Errorf("postgres admin auth db is not configured")
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return adminAuthStoreStats{}, fmt.Errorf("tenant_id is required")
	}
	ctx = normalizePostgresExportTaskContext(ctx)
	stats := adminAuthStoreStats{}
	if err := store.DB.QueryRowContext(ctx, "SELECT (SELECT count(*) FROM admin_principals WHERE tenant_id = $1), (SELECT count(*) FROM admin_sessions WHERE tenant_id = $1), (SELECT count(*) FROM admin_api_tokens WHERE tenant_id = $1)", tenantID).Scan(&stats.Principals, &stats.Sessions, &stats.APITokens); err != nil {
		return adminAuthStoreStats{}, err
	}
	stats.Total = stats.Principals + stats.Sessions + stats.APITokens
	return stats, nil
}

func (store postgresAdminAuthStore) ListAPITokensForTenant(ctx context.Context, tenantID string) ([]adminAPIToken, error) {
	if store.DB == nil {
		return nil, fmt.Errorf("postgres admin auth db is not configured")
	}
	statement, err := buildPostgresAdminAPITokenListStatement(tenantID)
	if err != nil {
		return nil, err
	}
	ctx = normalizePostgresExportTaskContext(ctx)
	rows, err := store.DB.QueryContext(ctx, statement.SQL, statement.Args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	tokens := []adminAPIToken{}
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		token, err := decodePostgresAdminAPITokenPayload(payload)
		if err != nil {
			return nil, err
		}
		tokens = append(tokens, token)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return tokens, nil
}

func (store postgresAdminAuthStore) CreateAPITokenForTenant(ctx context.Context, req adminAPITokenCreateRequest, tenantID, createdBy string, now time.Time) (adminAPIToken, string, error) {
	token, rawToken, labPrincipal, err := buildAdminAPIToken(req, tenantID, createdBy, now)
	if err != nil {
		return adminAPIToken{}, "", err
	}
	if labPrincipal != nil {
		if err := store.PersistPrincipal(ctx, *labPrincipal); err != nil {
			return adminAPIToken{}, "", err
		}
	}
	if err := store.PersistAPIToken(ctx, token); err != nil {
		return adminAPIToken{}, "", err
	}
	return token, rawToken, nil
}

func (store postgresAdminAuthStore) RevokeAPITokenForTenant(ctx context.Context, id, tenantID string, now time.Time) (adminAPIToken, bool, error) {
	token, ok, err := store.adminAPIToken(ctx, id, tenantID)
	if err != nil || !ok {
		return adminAPIToken{}, ok, err
	}
	token.Status = "revoked"
	revokedAt := now.UTC().Format(time.RFC3339)
	if token.Metadata == nil {
		token.Metadata = map[string]any{}
	}
	token.Metadata["revoked_at"] = revokedAt
	if err := store.PersistAPIToken(ctx, token); err != nil {
		return adminAPIToken{}, false, err
	}
	return token, true, nil
}

func (store postgresAdminAuthStore) RotateAPITokenForTenant(ctx context.Context, id, tenantID, rotatedBy string, req adminAPITokenRotateRequest, now time.Time) (adminAPIToken, string, bool, error) {
	if store.DB == nil {
		return adminAPIToken{}, "", false, fmt.Errorf("postgres admin auth db is not configured")
	}
	statement, err := buildPostgresAdminAPITokenGetForUpdateStatement(tenantID, id)
	if err != nil {
		return adminAPIToken{}, "", false, err
	}
	ctx = normalizePostgresExportTaskContext(ctx)
	tx, err := store.DB.BeginTx(ctx, nil)
	if err != nil {
		return adminAPIToken{}, "", false, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	var payload []byte
	if err := tx.QueryRowContext(ctx, statement.SQL, statement.Args...).Scan(&payload); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return adminAPIToken{}, "", false, nil
		}
		return adminAPIToken{}, "", false, err
	}
	existing, err := decodePostgresAdminAPITokenPayload(payload)
	if err != nil {
		return adminAPIToken{}, "", true, err
	}
	revoked, rotated, rawToken, err := rotateAdminAPIToken(existing, rotatedBy, req, now)
	if err != nil {
		return adminAPIToken{}, "", true, err
	}
	for _, token := range []adminAPIToken{revoked, rotated} {
		upsert, err := buildPostgresAdminAPITokenUpsertStatement(token)
		if err != nil {
			return adminAPIToken{}, "", true, err
		}
		if _, err := tx.ExecContext(ctx, upsert.SQL, upsert.Args...); err != nil {
			return adminAPIToken{}, "", true, err
		}
	}
	if err := tx.Commit(); err != nil {
		return adminAPIToken{}, "", true, err
	}
	committed = true
	return rotated, rawToken, true, nil
}

func (store postgresAdminAuthStore) RevokeSessionForTenant(ctx context.Context, id, tenantID string, now time.Time) (adminSession, bool, error) {
	session, ok, err := store.adminSession(ctx, id, tenantID)
	if err != nil || !ok {
		return adminSession{}, ok, err
	}
	session.Status = "revoked"
	session.LastActiveAt = now.UTC().Format(time.RFC3339)
	if err := store.PersistSession(ctx, session); err != nil {
		return adminSession{}, false, err
	}
	return session, true, nil
}

// RevokeAllForTenant revokes every live session and API token a tenant holds. See the in-memory twin for why:
// refusing a LOGIN after a tenant is deleted still leaves whoever was already signed in working for the rest
// of their eight hours, and an API token working indefinitely. Rows are marked revoked, never dropped — the
// record of what existed has to survive the deletion.
func (store postgresAdminAuthStore) RevokeAllForTenant(ctx context.Context, tenantID string, now time.Time) (int, int, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return 0, 0, nil
	}
	if store.DB == nil {
		return 0, 0, fmt.Errorf("postgres admin auth db is not configured")
	}
	stamp := now.UTC()
	sessions, err := store.DB.ExecContext(ctx,
		"UPDATE admin_sessions SET status = 'revoked', last_active_at = $2 WHERE tenant_id = $1 AND status <> 'revoked'",
		tenantID, stamp)
	if err != nil {
		return 0, 0, fmt.Errorf("revoke sessions for tenant %q: %w", tenantID, err)
	}
	tokens, err := store.DB.ExecContext(ctx,
		"UPDATE admin_api_tokens SET status = 'revoked' WHERE tenant_id = $1 AND status <> 'revoked'",
		tenantID)
	if err != nil {
		return 0, 0, fmt.Errorf("revoke api tokens for tenant %q: %w", tenantID, err)
	}
	sessionCount, _ := sessions.RowsAffected()
	tokenCount, _ := tokens.RowsAffected()
	return int(sessionCount), int(tokenCount), nil
}

func (store postgresAdminAuthStore) LookupSessionAdminIdentity(ctx context.Context, sessionID, tenantID string, now time.Time) (adminIdentity, bool, error) {
	return store.LookupSessionIdentity(ctx, sessionID, tenantID, now)
}

func (store postgresAdminAuthStore) LookupAPITokenAdminIdentity(ctx context.Context, rawToken, tenantID string, now time.Time) (adminIdentity, bool, error) {
	return store.LookupAPITokenIdentity(ctx, rawToken, tenantID, now)
}

func (store postgresAdminAuthStore) LookupSessionIdentity(ctx context.Context, sessionID, tenantID string, now time.Time) (adminIdentity, bool, error) {
	if store.DB == nil {
		return adminIdentity{}, false, fmt.Errorf("postgres admin auth db is not configured")
	}
	statement, err := buildPostgresAdminSessionIdentityStatement(tenantID, sessionID, now)
	if err != nil {
		return adminIdentity{}, false, err
	}
	ctx = normalizePostgresExportTaskContext(ctx)
	var sessionPayload, principalPayload []byte
	if err := store.DB.QueryRowContext(ctx, statement.SQL, statement.Args...).Scan(&sessionPayload, &principalPayload); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return adminIdentity{}, false, nil
		}
		return adminIdentity{}, false, err
	}
	session, err := decodePostgresAdminSessionPayload(sessionPayload)
	if err != nil {
		return adminIdentity{}, false, err
	}
	principal, err := decodePostgresAdminPrincipalPayload(principalPayload)
	if err != nil {
		return adminIdentity{}, false, err
	}
	if err := store.RecordSessionActive(ctx, session.TenantID, session.ID, now); err != nil {
		log.Printf("postgres admin session last_active_at update failed: %v", err)
	}
	return adminIdentity{
		PrincipalID: principal.ID,
		TenantID:    session.TenantID,
		Roles:       append([]string(nil), session.Roles...),
		AuthMethod:  "admin_session",
		CSRFToken:   stringMetadata(session.Metadata, adminCSRFTokenKey),
	}, true, nil
}

func (store postgresAdminAuthStore) RecordSessionActive(ctx context.Context, tenantID, sessionID string, now time.Time) error {
	if store.DB == nil {
		return fmt.Errorf("postgres admin auth db is not configured")
	}
	statement, err := buildPostgresAdminSessionActiveStatement(tenantID, sessionID, now)
	if err != nil {
		return err
	}
	ctx = normalizePostgresExportTaskContext(ctx)
	result, err := store.DB.ExecContext(ctx, statement.SQL, statement.Args...)
	if err != nil {
		return err
	}
	if affected, err := result.RowsAffected(); err == nil && affected == 0 {
		return fmt.Errorf("admin session %s is absent", sessionID)
	}
	return nil
}

func (store postgresAdminAuthStore) RecordAPITokenUsed(ctx context.Context, tenantID, tokenID string, now time.Time) error {
	if store.DB == nil {
		return fmt.Errorf("postgres admin auth db is not configured")
	}
	statement, err := buildPostgresAdminAPITokenUsedStatement(tenantID, tokenID, now)
	if err != nil {
		return err
	}
	ctx = normalizePostgresExportTaskContext(ctx)
	result, err := store.DB.ExecContext(ctx, statement.SQL, statement.Args...)
	if err != nil {
		return err
	}
	if affected, err := result.RowsAffected(); err == nil && affected == 0 {
		return fmt.Errorf("admin api token %s is absent", tokenID)
	}
	return nil
}

func (store postgresAdminAuthStore) LookupAPITokenIdentity(ctx context.Context, rawToken, tenantID string, now time.Time) (adminIdentity, bool, error) {
	if store.DB == nil {
		return adminIdentity{}, false, fmt.Errorf("postgres admin auth db is not configured")
	}
	statement, err := buildPostgresAdminAPITokenIdentityStatement(tenantID, adminTokenHash(rawToken), now)
	if err != nil {
		return adminIdentity{}, false, err
	}
	ctx = normalizePostgresExportTaskContext(ctx)
	var tokenPayload, principalPayload []byte
	if err := store.DB.QueryRowContext(ctx, statement.SQL, statement.Args...).Scan(&tokenPayload, &principalPayload); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return adminIdentity{}, false, nil
		}
		return adminIdentity{}, false, err
	}
	token, err := decodePostgresAdminAPITokenPayload(tokenPayload)
	if err != nil {
		return adminIdentity{}, false, err
	}
	principal, err := decodePostgresAdminPrincipalPayload(principalPayload)
	if err != nil {
		return adminIdentity{}, false, err
	}
	if err := store.RecordAPITokenUsed(ctx, token.TenantID, token.ID, now); err != nil {
		log.Printf("postgres admin api token last_used_at update failed: %v", err)
	}
	return adminIdentity{
		PrincipalID: principal.ID,
		TenantID:    token.TenantID,
		Roles:       append([]string(nil), token.Roles...),
		Scopes:      append([]string(nil), token.Scopes...),
		AuthMethod:  "admin_api_token",
		APITokenID:  token.ID,
	}, true, nil
}

func (store postgresAdminAuthStore) adminAPIToken(ctx context.Context, id, tenantID string) (adminAPIToken, bool, error) {
	if store.DB == nil {
		return adminAPIToken{}, false, fmt.Errorf("postgres admin auth db is not configured")
	}
	statement, err := buildPostgresAdminAPITokenGetStatement(tenantID, id)
	if err != nil {
		return adminAPIToken{}, false, err
	}
	ctx = normalizePostgresExportTaskContext(ctx)
	var payload []byte
	if err := store.DB.QueryRowContext(ctx, statement.SQL, statement.Args...).Scan(&payload); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return adminAPIToken{}, false, nil
		}
		return adminAPIToken{}, false, err
	}
	token, err := decodePostgresAdminAPITokenPayload(payload)
	if err != nil {
		return adminAPIToken{}, false, err
	}
	return token, true, nil
}

func (store postgresAdminAuthStore) adminSession(ctx context.Context, id, tenantID string) (adminSession, bool, error) {
	if store.DB == nil {
		return adminSession{}, false, fmt.Errorf("postgres admin auth db is not configured")
	}
	statement, err := buildPostgresAdminSessionGetStatement(tenantID, id)
	if err != nil {
		return adminSession{}, false, err
	}
	ctx = normalizePostgresExportTaskContext(ctx)
	var payload []byte
	if err := store.DB.QueryRowContext(ctx, statement.SQL, statement.Args...).Scan(&payload); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return adminSession{}, false, nil
		}
		return adminSession{}, false, err
	}
	session, err := decodePostgresAdminSessionPayload(payload)
	if err != nil {
		return adminSession{}, false, err
	}
	return session, true, nil
}

func postgresAdminAuthSchemaSQL() []string {
	return []string{
		strings.Join([]string{
			"CREATE TABLE IF NOT EXISTS admin_principals (",
			"tenant_id text NOT NULL,",
			"admin_principal_id text NOT NULL,",
			"idp_id text NOT NULL,",
			"subject text NOT NULL,",
			"email text NOT NULL,",
			"status text NOT NULL CHECK (status IN ('active', 'disabled', 'deleted')),",
			"created_at timestamptz NOT NULL,",
			"last_login_at timestamptz,",
			"payload jsonb NOT NULL,",
			"PRIMARY KEY (tenant_id, admin_principal_id)",
			")",
		}, " "),
		"CREATE UNIQUE INDEX IF NOT EXISTS admin_principals_subject_unique_idx ON admin_principals (tenant_id, idp_id, subject)",
		"CREATE INDEX IF NOT EXISTS admin_principals_tenant_status_idx ON admin_principals (tenant_id, status, created_at DESC)",
		strings.Join([]string{
			"CREATE TABLE IF NOT EXISTS admin_sessions (",
			"tenant_id text NOT NULL,",
			"session_id text NOT NULL,",
			"admin_principal_id text NOT NULL,",
			"status text NOT NULL CHECK (status IN ('active', 'revoked', 'expired')),",
			"created_at timestamptz NOT NULL,",
			"expires_at timestamptz NOT NULL,",
			"last_active_at timestamptz NOT NULL,",
			"payload jsonb NOT NULL,",
			"PRIMARY KEY (tenant_id, session_id)",
			")",
		}, " "),
		"CREATE INDEX IF NOT EXISTS admin_sessions_principal_idx ON admin_sessions (tenant_id, admin_principal_id, created_at DESC)",
		"CREATE INDEX IF NOT EXISTS admin_sessions_status_expiry_idx ON admin_sessions (tenant_id, status, expires_at)",
		strings.Join([]string{
			"CREATE TABLE IF NOT EXISTS admin_api_tokens (",
			"tenant_id text NOT NULL,",
			"token_id text NOT NULL,",
			"token_hash text NOT NULL,",
			"created_by_admin_principal_id text NOT NULL,",
			"status text NOT NULL CHECK (status IN ('active', 'revoked', 'expired')),",
			"created_at timestamptz NOT NULL,",
			"expires_at timestamptz NOT NULL,",
			"last_used_at timestamptz,",
			"payload jsonb NOT NULL,",
			"PRIMARY KEY (tenant_id, token_id)",
			")",
		}, " "),
		"CREATE UNIQUE INDEX IF NOT EXISTS admin_api_tokens_hash_unique_idx ON admin_api_tokens (token_hash)",
		"CREATE INDEX IF NOT EXISTS admin_api_tokens_tenant_status_idx ON admin_api_tokens (tenant_id, status, expires_at)",
	}
}

func buildPostgresAdminPrincipalUpsertStatement(principal adminPrincipal) (postgresAdminAuthStatement, error) {
	tenantID := strings.TrimSpace(principal.TenantID)
	principalID := strings.TrimSpace(principal.ID)
	idpID := strings.TrimSpace(principal.IDPID)
	subject := strings.TrimSpace(principal.Subject)
	email := strings.TrimSpace(principal.Email)
	status := strings.TrimSpace(principal.Status)
	if tenantID == "" || principalID == "" || idpID == "" || subject == "" || email == "" || status == "" {
		return postgresAdminAuthStatement{}, fmt.Errorf("admin principal tenant_id, id, idp_id, subject, email, and status are required")
	}
	createdAt, err := time.Parse(time.RFC3339, strings.TrimSpace(principal.CreatedAt))
	if err != nil {
		return postgresAdminAuthStatement{}, fmt.Errorf("parse admin principal created_at: %w", err)
	}
	var lastLoginAt any
	if principal.LastLoginAt != nil && strings.TrimSpace(*principal.LastLoginAt) != "" {
		parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(*principal.LastLoginAt))
		if err != nil {
			return postgresAdminAuthStatement{}, fmt.Errorf("parse admin principal last_login_at: %w", err)
		}
		lastLoginAt = parsed.UTC()
	}
	payload, err := json.Marshal(principal)
	if err != nil {
		return postgresAdminAuthStatement{}, err
	}
	return postgresAdminAuthStatement{
		SQL: strings.Join([]string{
			"INSERT INTO admin_principals",
			"(tenant_id, admin_principal_id, idp_id, subject, email, status, created_at, last_login_at, payload)",
			"VALUES ($1, $2, $3, $4, $5, $6, $7::timestamptz, $8::timestamptz, $9::jsonb)",
			"ON CONFLICT (tenant_id, admin_principal_id) DO UPDATE SET",
			"idp_id = EXCLUDED.idp_id,",
			"subject = EXCLUDED.subject,",
			"email = EXCLUDED.email,",
			"status = EXCLUDED.status,",
			"last_login_at = EXCLUDED.last_login_at,",
			"payload = EXCLUDED.payload",
		}, " "),
		Args: []any{tenantID, principalID, idpID, subject, email, status, createdAt.UTC(), lastLoginAt, string(payload)},
	}, nil
}

func buildPostgresAdminSessionUpsertStatement(session adminSession) (postgresAdminAuthStatement, error) {
	tenantID := strings.TrimSpace(session.TenantID)
	sessionID := strings.TrimSpace(session.ID)
	principalID := strings.TrimSpace(session.AdminPrincipalID)
	status := strings.TrimSpace(session.Status)
	if tenantID == "" || sessionID == "" || principalID == "" || status == "" {
		return postgresAdminAuthStatement{}, fmt.Errorf("admin session tenant_id, id, admin_principal_id, and status are required")
	}
	createdAt, err := parseAdminAuthRequiredTime(session.CreatedAt, "admin session created_at")
	if err != nil {
		return postgresAdminAuthStatement{}, err
	}
	expiresAt, err := parseAdminAuthRequiredTime(session.ExpiresAt, "admin session expires_at")
	if err != nil {
		return postgresAdminAuthStatement{}, err
	}
	lastActiveAt, err := parseAdminAuthRequiredTime(session.LastActiveAt, "admin session last_active_at")
	if err != nil {
		return postgresAdminAuthStatement{}, err
	}
	payload, err := json.Marshal(session)
	if err != nil {
		return postgresAdminAuthStatement{}, err
	}
	return postgresAdminAuthStatement{
		SQL: strings.Join([]string{
			"INSERT INTO admin_sessions",
			"(tenant_id, session_id, admin_principal_id, status, created_at, expires_at, last_active_at, payload)",
			"VALUES ($1, $2, $3, $4, $5::timestamptz, $6::timestamptz, $7::timestamptz, $8::jsonb)",
			"ON CONFLICT (tenant_id, session_id) DO UPDATE SET",
			"admin_principal_id = EXCLUDED.admin_principal_id,",
			"status = EXCLUDED.status,",
			"expires_at = EXCLUDED.expires_at,",
			"last_active_at = EXCLUDED.last_active_at,",
			"payload = EXCLUDED.payload",
		}, " "),
		Args: []any{tenantID, sessionID, principalID, status, createdAt.UTC(), expiresAt.UTC(), lastActiveAt.UTC(), string(payload)},
	}, nil
}

func buildPostgresAdminAPITokenUpsertStatement(token adminAPIToken) (postgresAdminAuthStatement, error) {
	tenantID := strings.TrimSpace(token.TenantID)
	tokenID := strings.TrimSpace(token.ID)
	tokenHash := strings.TrimSpace(token.TokenHash)
	createdBy := strings.TrimSpace(token.CreatedByAdminPrincipalID)
	status := strings.TrimSpace(token.Status)
	if tenantID == "" || tokenID == "" || tokenHash == "" || createdBy == "" || status == "" {
		return postgresAdminAuthStatement{}, fmt.Errorf("admin api token tenant_id, id, token_hash, created_by, and status are required")
	}
	createdAt, err := parseAdminAuthRequiredTime(token.CreatedAt, "admin api token created_at")
	if err != nil {
		return postgresAdminAuthStatement{}, err
	}
	expiresAt, err := parseAdminAuthRequiredTime(token.ExpiresAt, "admin api token expires_at")
	if err != nil {
		return postgresAdminAuthStatement{}, err
	}
	var lastUsedAt any
	if token.LastUsedAt != nil && strings.TrimSpace(*token.LastUsedAt) != "" {
		parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(*token.LastUsedAt))
		if err != nil {
			return postgresAdminAuthStatement{}, fmt.Errorf("parse admin api token last_used_at: %w", err)
		}
		lastUsedAt = parsed.UTC()
	}
	payload, err := json.Marshal(token)
	if err != nil {
		return postgresAdminAuthStatement{}, err
	}
	return postgresAdminAuthStatement{
		SQL: strings.Join([]string{
			"INSERT INTO admin_api_tokens",
			"(tenant_id, token_id, token_hash, created_by_admin_principal_id, status, created_at, expires_at, last_used_at, payload)",
			"VALUES ($1, $2, $3, $4, $5, $6::timestamptz, $7::timestamptz, $8::timestamptz, $9::jsonb)",
			"ON CONFLICT (tenant_id, token_id) DO UPDATE SET",
			"token_hash = EXCLUDED.token_hash,",
			"created_by_admin_principal_id = EXCLUDED.created_by_admin_principal_id,",
			"status = EXCLUDED.status,",
			"expires_at = EXCLUDED.expires_at,",
			"last_used_at = EXCLUDED.last_used_at,",
			"payload = EXCLUDED.payload",
		}, " "),
		Args: []any{tenantID, tokenID, tokenHash, createdBy, status, createdAt.UTC(), expiresAt.UTC(), lastUsedAt, string(payload)},
	}, nil
}

func buildPostgresAdminPrincipalGetStatement(tenantID, principalID string) (postgresAdminAuthStatement, error) {
	tenantID = strings.TrimSpace(tenantID)
	principalID = strings.TrimSpace(principalID)
	if tenantID == "" || principalID == "" {
		return postgresAdminAuthStatement{}, fmt.Errorf("tenant_id and admin_principal_id are required")
	}
	return postgresAdminAuthStatement{
		SQL:  "SELECT payload FROM admin_principals WHERE tenant_id = $1 AND admin_principal_id = $2",
		Args: []any{tenantID, principalID},
	}, nil
}

func buildPostgresAdminAPITokenListStatement(tenantID string) (postgresAdminAuthStatement, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return postgresAdminAuthStatement{}, fmt.Errorf("tenant_id is required")
	}
	return postgresAdminAuthStatement{
		SQL:  "SELECT payload FROM admin_api_tokens WHERE tenant_id = $1 ORDER BY token_id ASC",
		Args: []any{tenantID},
	}, nil
}

func buildPostgresAdminAPITokenGetStatement(tenantID, tokenID string) (postgresAdminAuthStatement, error) {
	tenantID = strings.TrimSpace(tenantID)
	tokenID = strings.TrimSpace(tokenID)
	if tenantID == "" || tokenID == "" {
		return postgresAdminAuthStatement{}, fmt.Errorf("tenant_id and token_id are required")
	}
	return postgresAdminAuthStatement{
		SQL:  "SELECT payload FROM admin_api_tokens WHERE tenant_id = $1 AND token_id = $2",
		Args: []any{tenantID, tokenID},
	}, nil
}

func buildPostgresAdminAPITokenGetForUpdateStatement(tenantID, tokenID string) (postgresAdminAuthStatement, error) {
	statement, err := buildPostgresAdminAPITokenGetStatement(tenantID, tokenID)
	if err != nil {
		return postgresAdminAuthStatement{}, err
	}
	statement.SQL += " FOR UPDATE"
	return statement, nil
}

func buildPostgresAdminSessionGetStatement(tenantID, sessionID string) (postgresAdminAuthStatement, error) {
	tenantID = strings.TrimSpace(tenantID)
	sessionID = strings.TrimSpace(sessionID)
	if tenantID == "" || sessionID == "" {
		return postgresAdminAuthStatement{}, fmt.Errorf("tenant_id and session_id are required")
	}
	return postgresAdminAuthStatement{
		SQL:  "SELECT payload FROM admin_sessions WHERE tenant_id = $1 AND session_id = $2",
		Args: []any{tenantID, sessionID},
	}, nil
}

func buildPostgresAdminSessionIdentityStatement(tenantID, sessionID string, now time.Time) (postgresAdminAuthStatement, error) {
	tenantID = strings.TrimSpace(tenantID)
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return postgresAdminAuthStatement{}, fmt.Errorf("session_id is required")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	// ★ AN EMPTY tenantID MEANS "RESOLVE THE SESSION'S OWN TENANT" (2026-08-15).
	//
	// This used to require the caller to already know which tenant the session belonged to, and the only
	// caller passed the NODE's tenant (evaluator.PolicyBundle.TenantID). So a session minted for any other
	// organization could not be looked up at all: the administrator signed in, received a cookie, and every
	// request with it answered "admin authentication is required".
	//
	// Measured twice on the lab before the cause was found — once for a customer tenant's administrator, and
	// again for the OPERATOR account, which by design lives in its own tenant. That second one makes the whole
	// operator-separation feature unusable: the account it tells you to create cannot use the console.
	//
	// The tenant filter was never a security control. A session id is an unguessable credential; holding one
	// is the authorisation, and the identity that comes back carries the session's OWN tenant, which is what
	// every handler then scopes to. The control-plane authority path in this same file already documents
	// exactly that rule: never substitute the seed/primary tenant, use the bound one.
	where := "WHERE s.session_id = $1"
	args := []any{sessionID, now.UTC()}
	if tenantID != "" {
		where = "WHERE s.tenant_id = $3 AND s.session_id = $1"
		args = append(args, tenantID)
	}
	return postgresAdminAuthStatement{
		SQL: strings.Join([]string{
			"SELECT s.payload, p.payload",
			"FROM admin_sessions s",
			"JOIN admin_principals p ON p.tenant_id = s.tenant_id AND p.admin_principal_id = s.admin_principal_id",
			where,
			"AND s.status = 'active' AND s.expires_at > $2::timestamptz",
			"AND p.status = 'active'",
		}, " "),
		Args: args,
	}, nil
}

func buildPostgresAdminAPITokenIdentityStatement(tenantID, tokenHash string, now time.Time) (postgresAdminAuthStatement, error) {
	tenantID = strings.TrimSpace(tenantID)
	tokenHash = strings.TrimSpace(tokenHash)
	if tokenHash == "" {
		return postgresAdminAuthStatement{}, fmt.Errorf("token_hash is required")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	// ★ THE SAME DEFECT AS THE SESSION LOOKUP ABOVE, LEFT BEHIND (found 2026-08-16). That one was fixed on
	// 2026-08-15: requiring the caller to already know the tenant meant the only caller passed the NODE's
	// tenant, so any other organization's credential could not be looked up at all. The API-token statement,
	// forty lines below it, kept the mandatory tenant filter.
	//
	// The consequence is narrower than the session one and lands in the same place: an administrator of any
	// tenant other than the node's own could sign in to the Console and then find every API token they minted
	// answering "admin authentication is required" — no automation, no scripted rotation, no CI. Found while
	// making the device CA tenant-manageable, because the first test of "the customer can operate its own PKI"
	// authenticates as that customer and got a flat 401 that reads as a bad token.
	//
	// A token hash is an unguessable credential; holding it is the authorisation, and the identity that comes
	// back carries the TOKEN's own tenant, which is what every handler then scopes to. An explicit tenantID is
	// still honoured for callers that genuinely mean "this tenant's token".
	where := "WHERE t.token_hash = $1"
	args := []any{tokenHash, now.UTC()}
	if tenantID != "" {
		where = "WHERE t.tenant_id = $3 AND t.token_hash = $1"
		args = append(args, tenantID)
	}
	return postgresAdminAuthStatement{
		SQL: strings.Join([]string{
			"SELECT t.payload, p.payload",
			"FROM admin_api_tokens t",
			// ★ THE CREATOR DOES NOT LIVE IN THE TOKEN'S ORGANIZATION (found live, 2026-08-16). The join
			// required p.tenant_id = t.tenant_id, so a token an OPERATOR minted for a customer — the ordinary
			// managed-service act, and the one this whole C-7 migration depends on — matched no principal row
			// and authenticated nowhere. The mint answered 201 and the credential was dead on arrival: 401 on
			// every plane, forever, with nothing saying why.
			//
			// The in-memory store has always resolved the principal by id alone, so the two stores disagreed
			// about who may authenticate — the exact hazard the note on the tenant filter above warns about,
			// pointing the other way. The join exists to check the creator is still ACTIVE (revoke a person and
			// their tokens stop); provenance is not authorization, and the token's own tenant is what every
			// handler scopes to.
			//
			// Same-tenant row preferred and exactly one taken, because one principal id can legitimately exist
			// in two organizations — "admin_legacy_token" is persisted per node tenant and is precisely that.
			"JOIN LATERAL (",
			"  SELECT pp.payload, pp.status FROM admin_principals pp",
			"  WHERE pp.admin_principal_id = t.created_by_admin_principal_id",
			"  ORDER BY (pp.tenant_id = t.tenant_id) DESC LIMIT 1",
			") p ON TRUE",
			where,
			"AND t.status = 'active' AND t.expires_at > $2::timestamptz",
			"AND p.status = 'active'",
		}, " "),
		Args: args,
	}, nil
}

func buildPostgresAdminAPITokenUsedStatement(tenantID, tokenID string, now time.Time) (postgresAdminAuthStatement, error) {
	tenantID = strings.TrimSpace(tenantID)
	tokenID = strings.TrimSpace(tokenID)
	if tenantID == "" || tokenID == "" {
		return postgresAdminAuthStatement{}, fmt.Errorf("tenant_id and token_id are required")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	usedAt := now.UTC().Format(time.RFC3339)
	return postgresAdminAuthStatement{
		SQL: strings.Join([]string{
			"UPDATE admin_api_tokens SET",
			"last_used_at = $3::timestamptz,",
			"payload = jsonb_set(payload, '{last_used_at}', to_jsonb($4::text), true)",
			"WHERE tenant_id = $1 AND token_id = $2",
		}, " "),
		Args: []any{tenantID, tokenID, now.UTC(), usedAt},
	}, nil
}

func buildPostgresAdminSessionActiveStatement(tenantID, sessionID string, now time.Time) (postgresAdminAuthStatement, error) {
	tenantID = strings.TrimSpace(tenantID)
	sessionID = strings.TrimSpace(sessionID)
	if tenantID == "" || sessionID == "" {
		return postgresAdminAuthStatement{}, fmt.Errorf("tenant_id and session_id are required")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	activeAt := now.UTC().Format(time.RFC3339)
	return postgresAdminAuthStatement{
		SQL: strings.Join([]string{
			"UPDATE admin_sessions SET",
			"last_active_at = $3::timestamptz,",
			"payload = jsonb_set(payload, '{last_active_at}', to_jsonb($4::text), true)",
			"WHERE tenant_id = $1 AND session_id = $2",
		}, " "),
		Args: []any{tenantID, sessionID, now.UTC(), activeAt},
	}, nil
}

func decodePostgresAdminPrincipalPayload(payload []byte) (adminPrincipal, error) {
	if len(payload) == 0 {
		return adminPrincipal{}, fmt.Errorf("admin principal payload is required")
	}
	var principal adminPrincipal
	if err := json.Unmarshal(payload, &principal); err != nil {
		return adminPrincipal{}, fmt.Errorf("decode admin principal payload: %w", err)
	}
	if strings.TrimSpace(principal.ID) == "" || strings.TrimSpace(principal.TenantID) == "" {
		return adminPrincipal{}, fmt.Errorf("admin principal payload is missing id or tenant_id")
	}
	return principal, nil
}

func decodePostgresAdminSessionPayload(payload []byte) (adminSession, error) {
	if len(payload) == 0 {
		return adminSession{}, fmt.Errorf("admin session payload is required")
	}
	var session adminSession
	if err := json.Unmarshal(payload, &session); err != nil {
		return adminSession{}, fmt.Errorf("decode admin session payload: %w", err)
	}
	if strings.TrimSpace(session.ID) == "" || strings.TrimSpace(session.TenantID) == "" {
		return adminSession{}, fmt.Errorf("admin session payload is missing id or tenant_id")
	}
	return session, nil
}

func decodePostgresAdminAPITokenPayload(payload []byte) (adminAPIToken, error) {
	if len(payload) == 0 {
		return adminAPIToken{}, fmt.Errorf("admin api token payload is required")
	}
	var token adminAPIToken
	if err := json.Unmarshal(payload, &token); err != nil {
		return adminAPIToken{}, fmt.Errorf("decode admin api token payload: %w", err)
	}
	if strings.TrimSpace(token.ID) == "" || strings.TrimSpace(token.TenantID) == "" {
		return adminAPIToken{}, fmt.Errorf("admin api token payload is missing id or tenant_id")
	}
	return token, nil
}

func parseAdminAuthRequiredTime(value, field string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(value))
	if err != nil {
		return time.Time{}, fmt.Errorf("parse %s: %w", field, err)
	}
	return parsed.UTC(), nil
}
