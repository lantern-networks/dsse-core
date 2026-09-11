package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPostgresAdminAuthMigrationMatchesSchemaSQL(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "migrations", "005_admin_auth.sql"))
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	want := normalizePostgresExportTaskSQLContract(strings.Join(postgresAdminAuthSchemaSQL(), "\n"))
	got := normalizePostgresExportTaskSQLContract(string(data))
	if got != want {
		t.Fatalf("admin auth migration SQL does not match schema helper\nmigration: %s\nhelper:    %s", got, want)
	}
}

func TestPostgresAdminAuthSchemaSecurityContracts(t *testing.T) {
	sqlText := strings.Join(postgresAdminAuthSchemaSQL(), "\n")
	for _, want := range []string{
		"PRIMARY KEY (tenant_id, admin_principal_id)",
		"PRIMARY KEY (tenant_id, session_id)",
		"PRIMARY KEY (tenant_id, token_id)",
		"admin_principals_subject_unique_idx",
		"admin_api_tokens_hash_unique_idx",
		"created_by_admin_principal_id text NOT NULL",
		"CHECK (status IN ('active', 'revoked', 'expired'))",
	} {
		if !strings.Contains(sqlText, want) {
			t.Fatalf("admin auth schema SQL missing %q:\n%s", want, sqlText)
		}
	}
	if strings.Contains(sqlText, "raw_token") {
		t.Fatalf("admin auth schema must not persist raw API tokens:\n%s", sqlText)
	}
}

func TestBuildPostgresAdminAuthUpsertStatementsSerializePayloads(t *testing.T) {
	now := time.Date(2026, 5, 24, 1, 0, 0, 0, time.UTC)
	lastLoginAt := now.Add(time.Minute).Format(time.RFC3339)
	principal := adminPrincipal{
		ID:          "admin_user_001",
		TenantID:    "tenant_lab_001",
		Subject:     "sub_admin_001",
		Email:       "admin@example.local",
		Roles:       []string{"admin"},
		IDPID:       "idp_keycloak_lab",
		Status:      "active",
		CreatedAt:   now.Format(time.RFC3339),
		LastLoginAt: &lastLoginAt,
		Metadata:    map[string]any{"source": "test"},
	}
	principalStatement, err := buildPostgresAdminPrincipalUpsertStatement(principal)
	if err != nil {
		t.Fatalf("buildPostgresAdminPrincipalUpsertStatement returned error: %v", err)
	}
	if !strings.Contains(principalStatement.SQL, "ON CONFLICT (tenant_id, admin_principal_id) DO UPDATE") || len(principalStatement.Args) != 9 {
		t.Fatalf("principal statement = %#v", principalStatement)
	}
	var principalPayload adminPrincipal
	if err := json.Unmarshal([]byte(principalStatement.Args[8].(string)), &principalPayload); err != nil {
		t.Fatalf("unmarshal principal payload: %v", err)
	}
	if principalPayload.ID != principal.ID || principalPayload.TenantID != principal.TenantID {
		t.Fatalf("principal payload = %#v", principalPayload)
	}

	session := adminSession{
		ID:               "admin_sess_001",
		TenantID:         "tenant_lab_001",
		AdminPrincipalID: principal.ID,
		Subject:          principal.Subject,
		Roles:            []string{"admin"},
		AuthTime:         now.Format(time.RFC3339),
		MFAState:         "fresh",
		CreatedAt:        now.Format(time.RFC3339),
		ExpiresAt:        now.Add(8 * time.Hour).Format(time.RFC3339),
		LastActiveAt:     now.Format(time.RFC3339),
		Status:           "active",
		Metadata:         map[string]any{adminCSRFTokenKey: "csrf"},
	}
	sessionStatement, err := buildPostgresAdminSessionUpsertStatement(session)
	if err != nil {
		t.Fatalf("buildPostgresAdminSessionUpsertStatement returned error: %v", err)
	}
	if !strings.Contains(sessionStatement.SQL, "ON CONFLICT (tenant_id, session_id) DO UPDATE") || len(sessionStatement.Args) != 8 {
		t.Fatalf("session statement = %#v", sessionStatement)
	}

	lastUsedAt := now.Add(2 * time.Minute).Format(time.RFC3339)
	token := adminAPIToken{
		ID:                        "admin_token_001",
		TenantID:                  "tenant_lab_001",
		Name:                      "automation",
		TokenHash:                 adminTokenHash("adm_test_token"),
		Roles:                     []string{"auditor"},
		Scopes:                    []string{"admin.logs.read"},
		CreatedByAdminPrincipalID: principal.ID,
		CreatedAt:                 now.Format(time.RFC3339),
		ExpiresAt:                 now.Add(24 * time.Hour).Format(time.RFC3339),
		LastUsedAt:                &lastUsedAt,
		Status:                    "active",
		Metadata:                  map[string]any{"token_display_prefix": "adm_test"},
	}
	tokenStatement, err := buildPostgresAdminAPITokenUpsertStatement(token)
	if err != nil {
		t.Fatalf("buildPostgresAdminAPITokenUpsertStatement returned error: %v", err)
	}
	if !strings.Contains(tokenStatement.SQL, "created_by_admin_principal_id") || len(tokenStatement.Args) != 9 {
		t.Fatalf("token statement = %#v", tokenStatement)
	}
	var tokenPayload adminAPIToken
	if err := json.Unmarshal([]byte(tokenStatement.Args[8].(string)), &tokenPayload); err != nil {
		t.Fatalf("unmarshal token payload: %v", err)
	}
	if tokenPayload.TokenHash != token.TokenHash || strings.Contains(tokenStatement.Args[8].(string), "adm_test_token") {
		t.Fatalf("token payload stores unexpected value: %#v", tokenPayload)
	}
}

func TestBuildPostgresAdminAuthIdentityStatementsScopeTenant(t *testing.T) {
	now := time.Date(2026, 5, 24, 1, 0, 0, 0, time.UTC)
	sessionStatement, err := buildPostgresAdminSessionIdentityStatement("tenant_lab_001", "admin_sess_001", now)
	if err != nil {
		t.Fatalf("buildPostgresAdminSessionIdentityStatement returned error: %v", err)
	}
	for _, want := range []string{
		"JOIN admin_principals",
		"WHERE s.tenant_id = $3 AND s.session_id = $1",
		"s.status = 'active'",
		"s.expires_at > $2::timestamptz",
		"p.status = 'active'",
	} {
		if !strings.Contains(sessionStatement.SQL, want) {
			t.Fatalf("session identity SQL = %s, want %s", sessionStatement.SQL, want)
		}
	}
	if sessionStatement.Args[0] != "admin_sess_001" || sessionStatement.Args[2] != "tenant_lab_001" {
		t.Fatalf("session identity args = %#v", sessionStatement.Args)
	}

	// ★ AND AN EMPTY TENANT RESOLVES THE SESSION'S OWN (2026-08-15). Requiring the caller to already know the
	// tenant is what broke multi-tenant sign-in: the only caller passed the NODE's tenant, so an administrator
	// of any other organization — including the operator account, which by design lives in its own tenant —
	// received a session cookie and was then told "admin authentication is required" on every request. The
	// filter was never a security control: a session id is the credential, and the identity that comes back
	// carries the tenant every handler then scopes to.
	anyTenant, err := buildPostgresAdminSessionIdentityStatement("", "admin_sess_001", now)
	if err != nil {
		t.Fatalf("empty tenant must resolve the session's own: %v", err)
	}
	if strings.Contains(anyTenant.SQL, "s.tenant_id =") {
		t.Fatalf("the tenant filter is still applied with no tenant given: %s", anyTenant.SQL)
	}
	if len(anyTenant.Args) != 2 || anyTenant.Args[0] != "admin_sess_001" {
		t.Fatalf("args = %#v", anyTenant.Args)
	}

	tokenHash := adminTokenHash("adm_test_token")
	tokenStatement, err := buildPostgresAdminAPITokenIdentityStatement("tenant_lab_001", tokenHash, now)
	if err != nil {
		t.Fatalf("buildPostgresAdminAPITokenIdentityStatement returned error: %v", err)
	}
	// ★ THIS LIST USED TO PIN THE BROKEN SHAPE (2026-08-16, the second time a gate here did). It asserted the
	// literal "JOIN admin_principals", which the join satisfied while also requiring
	// p.tenant_id = t.tenant_id — and that equality meant a token an OPERATOR minted for a customer matched no
	// principal and authenticated nowhere, 201 then 401 forever. A string match cannot tell a correct join
	// from a correct-looking one, so what is asserted below is the PROPERTY.
	for _, want := range []string{
		"admin_principals",
		"WHERE t.tenant_id = $3 AND t.token_hash = $1",
		"t.status = 'active'",
		"t.expires_at > $2::timestamptz",
		"p.status = 'active'",
	} {
		if !strings.Contains(tokenStatement.SQL, want) {
			t.Fatalf("token identity SQL = %s, want %s", tokenStatement.SQL, want)
		}
	}
	// The tenant of the creating principal may be a PREFERENCE (which row to pick when one principal id
	// exists in two organizations) and must not be a FILTER. Checked by removing the ordering clause and
	// looking at what is left, so the assertion says which of the two it objects to.
	filtering := tokenStatement.SQL
	if start := strings.Index(filtering, "ORDER BY"); start >= 0 {
		if end := strings.Index(filtering[start:], "LIMIT"); end >= 0 {
			filtering = filtering[:start] + filtering[start+end:]
		}
	}
	if strings.Contains(filtering, "tenant_id = t.tenant_id") {
		t.Fatalf("the creating principal is REQUIRED to live in the token's own organization, so a token an "+
			"operator minted for a customer resolves to nobody: %s", tokenStatement.SQL)
	}
	if tokenStatement.Args[0] != tokenHash || tokenStatement.Args[2] != "tenant_lab_001" {
		t.Fatalf("token identity args = %#v", tokenStatement.Args)
	}

	// ★ AND THE SAME FOR API TOKENS, WHICH THIS TEST PINNED THE BROKEN SHAPE OF (2026-08-16). The session
	// statement above was fixed on 2026-08-15; the token statement forty lines below it kept the mandatory
	// tenant filter, and this test asserted that filter as correct — so the gate that should have caught the
	// second half of the defect was holding it in place. An administrator of any other organization could sign
	// in and then find every API token they minted answering "admin authentication is required".
	anyTenantToken, err := buildPostgresAdminAPITokenIdentityStatement("", tokenHash, now)
	if err != nil {
		t.Fatalf("empty tenant must resolve the token's own: %v", err)
	}
	if strings.Contains(anyTenantToken.SQL, "t.tenant_id =") {
		t.Fatalf("the tenant filter is still applied with no tenant given: %s", anyTenantToken.SQL)
	}
	if len(anyTenantToken.Args) != 2 || anyTenantToken.Args[0] != tokenHash {
		t.Fatalf("args = %#v", anyTenantToken.Args)
	}

	usedStatement, err := buildPostgresAdminAPITokenUsedStatement("tenant_lab_001", "admin_token_001", now)
	if err != nil {
		t.Fatalf("buildPostgresAdminAPITokenUsedStatement returned error: %v", err)
	}
	for _, want := range []string{
		"UPDATE admin_api_tokens SET",
		"last_used_at = $3::timestamptz",
		"jsonb_set(payload, '{last_used_at}'",
		"WHERE tenant_id = $1 AND token_id = $2",
	} {
		if !strings.Contains(usedStatement.SQL, want) {
			t.Fatalf("token used SQL = %s, want %s", usedStatement.SQL, want)
		}
	}
	if usedStatement.Args[0] != "tenant_lab_001" || usedStatement.Args[1] != "admin_token_001" {
		t.Fatalf("token used args = %#v", usedStatement.Args)
	}

	activeStatement, err := buildPostgresAdminSessionActiveStatement("tenant_lab_001", "admin_sess_001", now)
	if err != nil {
		t.Fatalf("buildPostgresAdminSessionActiveStatement returned error: %v", err)
	}
	for _, want := range []string{
		"UPDATE admin_sessions SET",
		"last_active_at = $3::timestamptz",
		"jsonb_set(payload, '{last_active_at}'",
		"WHERE tenant_id = $1 AND session_id = $2",
	} {
		if !strings.Contains(activeStatement.SQL, want) {
			t.Fatalf("session active SQL = %s, want %s", activeStatement.SQL, want)
		}
	}
	if activeStatement.Args[0] != "tenant_lab_001" || activeStatement.Args[1] != "admin_sess_001" {
		t.Fatalf("session active args = %#v", activeStatement.Args)
	}
}

func TestBuildPostgresAdminAuthStatementsRejectInvalidInputs(t *testing.T) {
	if _, err := buildPostgresAdminPrincipalUpsertStatement(adminPrincipal{}); err == nil {
		t.Fatalf("principal upsert accepted empty principal")
	}
	if _, err := buildPostgresAdminSessionUpsertStatement(adminSession{}); err == nil {
		t.Fatalf("session upsert accepted empty session")
	}
	if _, err := buildPostgresAdminAPITokenUpsertStatement(adminAPIToken{}); err == nil {
		t.Fatalf("token upsert accepted empty token")
	}
	// An empty tenant is now MEANINGFUL for the session lookup (resolve the session's own) — see
	// TestBuildPostgresAdminAuthIdentityStatementsScopeTenant. An empty SESSION id is still invalid: without a
	// credential there is nothing to resolve, and a statement with no predicate would match every live session.
	if _, err := buildPostgresAdminSessionIdentityStatement("tenant_lab_001", "", time.Now()); err == nil {
		t.Fatalf("session identity accepted an empty session id — that statement would match any live session")
	}
	if _, err := buildPostgresAdminSessionIdentityStatement("", "", time.Now()); err == nil {
		t.Fatalf("session identity accepted no tenant AND no session id")
	}
	if _, err := buildPostgresAdminAPITokenIdentityStatement("tenant_lab_001", "", time.Now()); err == nil {
		t.Fatalf("token identity accepted empty hash")
	}
	if _, err := buildPostgresAdminAPITokenUsedStatement("tenant_lab_001", "", time.Now()); err == nil {
		t.Fatalf("token used accepted empty token id")
	}
	tokenGetForUpdateStatement, err := buildPostgresAdminAPITokenGetForUpdateStatement("tenant_lab_001", "admin_token_001")
	if err != nil {
		t.Fatalf("buildPostgresAdminAPITokenGetForUpdateStatement returned error: %v", err)
	}
	if !strings.Contains(tokenGetForUpdateStatement.SQL, "WHERE tenant_id = $1 AND token_id = $2 FOR UPDATE") {
		t.Fatalf("token get for update SQL = %s", tokenGetForUpdateStatement.SQL)
	}
	if _, err := buildPostgresAdminSessionActiveStatement("tenant_lab_001", "", time.Now()); err == nil {
		t.Fatalf("session active accepted empty session id")
	}
}

func TestDecodePostgresAdminAuthPayloadsRejectInvalidPayload(t *testing.T) {
	if _, err := decodePostgresAdminPrincipalPayload(nil); err == nil {
		t.Fatalf("principal decoder accepted empty payload")
	}
	if _, err := decodePostgresAdminPrincipalPayload([]byte(`{"id":"","tenant_id":"tenant_lab_001"}`)); err == nil {
		t.Fatalf("principal decoder accepted missing id")
	}
	if _, err := decodePostgresAdminSessionPayload(nil); err == nil {
		t.Fatalf("session decoder accepted empty payload")
	}
	if _, err := decodePostgresAdminSessionPayload([]byte(`{"id":"admin_sess_001","tenant_id":""}`)); err == nil {
		t.Fatalf("session decoder accepted missing tenant")
	}
	if _, err := decodePostgresAdminAPITokenPayload(nil); err == nil {
		t.Fatalf("token decoder accepted empty payload")
	}
	if _, err := decodePostgresAdminAPITokenPayload([]byte(`{"id":"","tenant_id":"tenant_lab_001"}`)); err == nil {
		t.Fatalf("token decoder accepted missing id")
	}
}

func TestPostgresAdminAuthStoreRejectsMissingDB(t *testing.T) {
	store := postgresAdminAuthStore{}
	if err := store.PersistPrincipal(context.Background(), adminPrincipal{}); err == nil {
		t.Fatalf("PersistPrincipal accepted missing DB")
	}
	if _, _, err := store.LookupSessionIdentity(context.Background(), "admin_sess_001", "tenant_lab_001", time.Now()); err == nil {
		t.Fatalf("LookupSessionIdentity accepted missing DB")
	}
	if _, _, err := store.LookupAPITokenIdentity(context.Background(), "adm_token", "tenant_lab_001", time.Now()); err == nil {
		t.Fatalf("LookupAPITokenIdentity accepted missing DB")
	}
	if _, err := store.HasAuthRecords(context.Background(), "tenant_lab_001"); err == nil {
		t.Fatalf("HasAuthRecords accepted missing DB")
	}
}
