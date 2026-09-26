package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/logs"

	_ "github.com/lib/pq"
)

func TestPostgresAdminAuthSQLContractE2E(t *testing.T) {
	dsn := os.Getenv("POSTGRES_QUEUE_E2E_DSN")
	if dsn == "" {
		t.Skip("POSTGRES_QUEUE_E2E_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("sql.Open returned error: %v", err)
	}
	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("PingContext returned error: %v", err)
	}
	resetPostgresExportTaskQueueTables(t, ctx, db)
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		resetPostgresExportTaskQueueTables(t, cleanupCtx, db)
		_ = db.Close()
	})
	applyPostgresExportTaskQueueMigration(t, ctx, db)
	store := postgresAdminAuthStore{DB: db}

	now := time.Date(2026, 5, 24, 1, 0, 0, 0, time.UTC)
	principal := adminPrincipal{
		ID:        "admin_user_pg_001",
		TenantID:  "tenant_lab_001",
		Subject:   "sub_admin_pg_001",
		Email:     "admin-pg@example.local",
		Roles:     []string{"admin"},
		IDPID:     "idp_keycloak_lab",
		Status:    "active",
		CreatedAt: now.Format(time.RFC3339),
		Metadata:  map[string]any{"source": "postgres_e2e"},
	}
	if err := store.PersistPrincipal(ctx, principal); err != nil {
		t.Fatalf("PersistPrincipal returned error: %v", err)
	}

	session := adminSession{
		ID:               "admin_sess_pg_001",
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
		Metadata:         map[string]any{adminCSRFTokenKey: "csrf-pg"},
	}
	if err := store.PersistSession(ctx, session); err != nil {
		t.Fatalf("PersistSession returned error: %v", err)
	}

	rawToken := "adm_postgres_e2e_token"
	token := adminAPIToken{
		ID:                        "admin_token_pg_001",
		TenantID:                  "tenant_lab_001",
		Name:                      "postgres-e2e",
		TokenHash:                 adminTokenHash(rawToken),
		Roles:                     []string{"auditor"},
		Scopes:                    []string{"admin.logs.read"},
		CreatedByAdminPrincipalID: principal.ID,
		CreatedAt:                 now.Format(time.RFC3339),
		ExpiresAt:                 now.Add(24 * time.Hour).Format(time.RFC3339),
		Status:                    "active",
		Metadata:                  map[string]any{"token_display_prefix": rawTokenPrefix(rawToken)},
	}
	if err := store.PersistAPIToken(ctx, token); err != nil {
		t.Fatalf("PersistAPIToken returned error: %v", err)
	}
	hasRecords, err := store.HasAuthRecords(ctx, "tenant_lab_001")
	if err != nil {
		t.Fatalf("HasAuthRecords returned error: %v", err)
	}
	if !hasRecords {
		t.Fatalf("HasAuthRecords returned false for tenant with admin auth records")
	}
	otherTenantHasRecords, err := store.HasAuthRecords(ctx, "tenant_other_001")
	if err != nil {
		t.Fatalf("HasAuthRecords other tenant returned error: %v", err)
	}
	if otherTenantHasRecords {
		t.Fatalf("HasAuthRecords returned true for tenant without admin auth records")
	}
	stats, err := store.AdminAuthStats(ctx, "tenant_lab_001")
	if err != nil {
		t.Fatalf("AdminAuthStats returned error: %v", err)
	}
	if stats.Principals != 1 || stats.Sessions != 1 || stats.APITokens != 1 || stats.Total != 3 {
		t.Fatalf("AdminAuthStats = %#v, want one principal/session/token", stats)
	}
	otherStats, err := store.AdminAuthStats(ctx, "tenant_other_001")
	if err != nil {
		t.Fatalf("AdminAuthStats other tenant returned error: %v", err)
	}
	if otherStats.Total != 0 {
		t.Fatalf("AdminAuthStats other tenant = %#v, want empty", otherStats)
	}

	sessionIdentityValue, ok, err := store.LookupSessionIdentity(ctx, session.ID, "tenant_lab_001", now)
	if err != nil {
		t.Fatalf("LookupSessionIdentity returned error: %v", err)
	}
	if !ok || sessionIdentityValue.PrincipalID != principal.ID || sessionIdentityValue.AuthMethod != "admin_session" || sessionIdentityValue.CSRFToken != "csrf-pg" {
		t.Fatalf("session identity = %#v, ok=%v", sessionIdentityValue, ok)
	}
	later := now.Add(5 * time.Minute)
	if _, ok, err := store.LookupSessionIdentity(ctx, session.ID, "tenant_lab_001", later); err != nil || !ok {
		t.Fatalf("LookupSessionIdentity later returned identity=%v error=%v", ok, err)
	}
	var persistedLastActiveAt time.Time
	var persistedSessionPayload []byte
	if err := db.QueryRowContext(ctx, "SELECT last_active_at, payload FROM admin_sessions WHERE tenant_id = $1 AND session_id = $2", session.TenantID, session.ID).Scan(&persistedLastActiveAt, &persistedSessionPayload); err != nil {
		t.Fatalf("query session last_active_at: %v", err)
	}
	if !persistedLastActiveAt.Equal(later) {
		t.Fatalf("last_active_at = %s, want %s", persistedLastActiveAt.Format(time.RFC3339), later.Format(time.RFC3339))
	}
	var persistedSession adminSession
	if err := json.Unmarshal(persistedSessionPayload, &persistedSession); err != nil {
		t.Fatalf("decode persisted session payload: %v", err)
	}
	if persistedSession.LastActiveAt != later.Format(time.RFC3339) {
		t.Fatalf("payload last_active_at = %q, want %s", persistedSession.LastActiveAt, later.Format(time.RFC3339))
	}
	sessionIdentity, err := buildPostgresAdminSessionIdentityStatement("tenant_lab_001", session.ID, now)
	if err != nil {
		t.Fatalf("build session identity: %v", err)
	}
	var sessionPayload, sessionPrincipalPayload []byte
	if err := db.QueryRowContext(ctx, sessionIdentity.SQL, sessionIdentity.Args...).Scan(&sessionPayload, &sessionPrincipalPayload); err != nil {
		t.Fatalf("query session identity: %v", err)
	}
	var gotSession adminSession
	var gotSessionPrincipal adminPrincipal
	if err := json.Unmarshal(sessionPayload, &gotSession); err != nil {
		t.Fatalf("decode session payload: %v", err)
	}
	if err := json.Unmarshal(sessionPrincipalPayload, &gotSessionPrincipal); err != nil {
		t.Fatalf("decode session principal payload: %v", err)
	}
	if gotSession.ID != session.ID || gotSessionPrincipal.ID != principal.ID {
		t.Fatalf("session identity payloads = %#v / %#v", gotSession, gotSessionPrincipal)
	}

	tokenIdentityValue, ok, err := store.LookupAPITokenIdentity(ctx, rawToken, "tenant_lab_001", now)
	if err != nil {
		t.Fatalf("LookupAPITokenIdentity returned error: %v", err)
	}
	if !ok || tokenIdentityValue.PrincipalID != principal.ID || tokenIdentityValue.AuthMethod != "admin_api_token" {
		t.Fatalf("token identity = %#v, ok=%v", tokenIdentityValue, ok)
	}
	if !reflect.DeepEqual(tokenIdentityValue.Scopes, token.Scopes) {
		t.Fatalf("token identity scopes = %#v, want %#v", tokenIdentityValue.Scopes, token.Scopes)
	}
	var persistedLastUsedAt sql.NullTime
	var persistedTokenPayload []byte
	if err := db.QueryRowContext(ctx, "SELECT last_used_at, payload FROM admin_api_tokens WHERE tenant_id = $1 AND token_id = $2", token.TenantID, token.ID).Scan(&persistedLastUsedAt, &persistedTokenPayload); err != nil {
		t.Fatalf("query token last_used_at: %v", err)
	}
	if !persistedLastUsedAt.Valid || !persistedLastUsedAt.Time.Equal(now) {
		t.Fatalf("last_used_at = %#v, want %s", persistedLastUsedAt, now.Format(time.RFC3339))
	}
	var persistedToken adminAPIToken
	if err := json.Unmarshal(persistedTokenPayload, &persistedToken); err != nil {
		t.Fatalf("decode persisted token payload: %v", err)
	}
	if persistedToken.LastUsedAt == nil || *persistedToken.LastUsedAt != now.Format(time.RFC3339) {
		t.Fatalf("payload last_used_at = %#v, want %s", persistedToken.LastUsedAt, now.Format(time.RFC3339))
	}
	tokenIdentity, err := buildPostgresAdminAPITokenIdentityStatement("tenant_lab_001", token.TokenHash, now)
	if err != nil {
		t.Fatalf("build token identity: %v", err)
	}
	var tokenPayload, tokenPrincipalPayload []byte
	if err := db.QueryRowContext(ctx, tokenIdentity.SQL, tokenIdentity.Args...).Scan(&tokenPayload, &tokenPrincipalPayload); err != nil {
		t.Fatalf("query token identity: %v", err)
	}
	var gotToken adminAPIToken
	var gotTokenPrincipal adminPrincipal
	if err := json.Unmarshal(tokenPayload, &gotToken); err != nil {
		t.Fatalf("decode token payload: %v", err)
	}
	if err := json.Unmarshal(tokenPrincipalPayload, &gotTokenPrincipal); err != nil {
		t.Fatalf("decode token principal payload: %v", err)
	}
	if gotToken.TokenHash != token.TokenHash || gotTokenPrincipal.ID != principal.ID {
		t.Fatalf("token identity payloads = %#v / %#v", gotToken, gotTokenPrincipal)
	}
	if strings.Contains(string(tokenPayload), rawToken) {
		t.Fatalf("token payload unexpectedly contains raw token: %s", string(tokenPayload))
	}

	if _, err := db.ExecContext(ctx, `
CREATE OR REPLACE FUNCTION admin_api_token_used_fail_test() RETURNS trigger AS $$
BEGIN
	RAISE EXCEPTION 'forced last_used_at failure';
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER admin_api_token_used_fail_before_update
BEFORE UPDATE OF last_used_at ON admin_api_tokens
FOR EACH ROW EXECUTE FUNCTION admin_api_token_used_fail_test();
`); err != nil {
		t.Fatalf("install token usage failure trigger: %v", err)
	}
	tokenIdentityValue, ok, err = store.LookupAPITokenIdentity(ctx, rawToken, "tenant_lab_001", now.Add(time.Minute))
	if err != nil {
		t.Fatalf("LookupAPITokenIdentity should ignore token usage update failure, got error: %v", err)
	}
	if !ok || tokenIdentityValue.PrincipalID != principal.ID {
		t.Fatalf("token identity after usage update failure = %#v, ok=%v", tokenIdentityValue, ok)
	}
}

func TestPostgresAdminAuthRuntimeAPITokenLifecycleE2E(t *testing.T) {
	dsn := os.Getenv("POSTGRES_QUEUE_E2E_DSN")
	if dsn == "" {
		t.Skip("POSTGRES_QUEUE_E2E_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("sql.Open returned error: %v", err)
	}
	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("PingContext returned error: %v", err)
	}
	resetPostgresExportTaskQueueTables(t, ctx, db)
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		resetPostgresExportTaskQueueTables(t, cleanupCtx, db)
		_ = db.Close()
	})
	applyPostgresExportTaskQueueMigration(t, ctx, db)

	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator:        testEvaluator(),
		Writer:           writer,
		AdminAuth:        postgresAdminAuthStore{DB: db},
		AdminAuditOutbox: postgresAdminAuditOutboxReader{DB: db},
	})

	createReq := httptest.NewRequest(http.MethodPost, "/admin/api-tokens", strings.NewReader(`{
		"name": "postgres-runtime-admin",
		"roles": ["admin"],
		"scopes": ["admin.state.read", "admin.api_tokens.write"],
		"expires_at": "2099-05-25T00:00:00Z"
	}`))
	createRec := httptest.NewRecorder()
	handler.ServeHTTP(createRec, createReq)
	if createRec.Code != http.StatusCreated {
		t.Fatalf("create api token status = %d, body=%s", createRec.Code, createRec.Body.String())
	}
	var created adminAPITokenCreateResponse
	if err := json.Unmarshal(createRec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	if created.RawToken == "" || created.Token.CreatedByAdminPrincipalID != "admin_lab_bypass" {
		t.Fatalf("created token response = %#v", created)
	}

	var principalCount, tokenCount int
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM admin_principals WHERE tenant_id = $1 AND admin_principal_id = $2", "tenant_lab_001", "admin_lab_bypass").Scan(&principalCount); err != nil {
		t.Fatalf("query principal count: %v", err)
	}
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM admin_api_tokens WHERE tenant_id = $1 AND token_id = $2", "tenant_lab_001", created.Token.ID).Scan(&tokenCount); err != nil {
		t.Fatalf("query token count: %v", err)
	}
	if principalCount != 1 || tokenCount != 1 {
		t.Fatalf("principal/token counts = %d/%d, want 1/1", principalCount, tokenCount)
	}

	sessionReq := httptest.NewRequest(http.MethodGet, "/admin/session", nil)
	sessionReq.Header.Set("authorization", "Bearer "+created.RawToken)
	sessionRec := httptest.NewRecorder()
	handler.ServeHTTP(sessionRec, sessionReq)
	if sessionRec.Code != http.StatusOK {
		t.Fatalf("session status = %d, body=%s", sessionRec.Code, sessionRec.Body.String())
	}
	var sessionPayload map[string]any
	if err := json.Unmarshal(sessionRec.Body.Bytes(), &sessionPayload); err != nil {
		t.Fatalf("decode session payload: %v", err)
	}
	if sessionPayload["auth_method"] != "admin_api_token" || sessionPayload["principal_id"] != "admin_lab_bypass" {
		t.Fatalf("session payload = %#v", sessionPayload)
	}

	rotateReq := httptest.NewRequest(http.MethodPost, "/admin/api-tokens/"+created.Token.ID+"/rotate", strings.NewReader(`{}`))
	rotateReq.Header.Set("authorization", "Bearer "+created.RawToken)
	rotateRec := httptest.NewRecorder()
	handler.ServeHTTP(rotateRec, rotateReq)
	if rotateRec.Code != http.StatusCreated {
		t.Fatalf("rotate status = %d, body=%s", rotateRec.Code, rotateRec.Body.String())
	}
	var rotated adminAPITokenCreateResponse
	if err := json.Unmarshal(rotateRec.Body.Bytes(), &rotated); err != nil {
		t.Fatalf("decode rotate response: %v", err)
	}
	if rotated.RawToken == "" || rotated.RawToken == created.RawToken || rotated.Token.ID == created.Token.ID {
		t.Fatalf("rotated token response = %#v", rotated)
	}

	sessionReq = httptest.NewRequest(http.MethodGet, "/admin/session", nil)
	sessionReq.Header.Set("authorization", "Bearer "+created.RawToken)
	sessionRec = httptest.NewRecorder()
	handler.ServeHTTP(sessionRec, sessionReq)
	if sessionRec.Code != http.StatusUnauthorized {
		t.Fatalf("session after rotate old token status = %d, want %d, body=%s", sessionRec.Code, http.StatusUnauthorized, sessionRec.Body.String())
	}
	sessionReq = httptest.NewRequest(http.MethodGet, "/admin/session", nil)
	sessionReq.Header.Set("authorization", "Bearer "+rotated.RawToken)
	sessionRec = httptest.NewRecorder()
	handler.ServeHTTP(sessionRec, sessionReq)
	if sessionRec.Code != http.StatusOK {
		t.Fatalf("session after rotate new token status = %d, body=%s", sessionRec.Code, sessionRec.Body.String())
	}

	var oldStatus, newStatus string
	if err := db.QueryRowContext(ctx, "SELECT status FROM admin_api_tokens WHERE tenant_id = $1 AND token_id = $2", "tenant_lab_001", created.Token.ID).Scan(&oldStatus); err != nil {
		t.Fatalf("query old rotated token status: %v", err)
	}
	if err := db.QueryRowContext(ctx, "SELECT status FROM admin_api_tokens WHERE tenant_id = $1 AND token_id = $2", "tenant_lab_001", rotated.Token.ID).Scan(&newStatus); err != nil {
		t.Fatalf("query new rotated token status: %v", err)
	}
	if oldStatus != "revoked" || newStatus != "active" {
		t.Fatalf("rotated token statuses = %s/%s, want revoked/active", oldStatus, newStatus)
	}

	revokeReq := httptest.NewRequest(http.MethodPost, "/admin/api-tokens/"+rotated.Token.ID+"/revoke", nil)
	revokeReq.Header.Set("authorization", "Bearer "+rotated.RawToken)
	revokeRec := httptest.NewRecorder()
	handler.ServeHTTP(revokeRec, revokeReq)
	if revokeRec.Code != http.StatusOK {
		t.Fatalf("revoke status = %d, body=%s", revokeRec.Code, revokeRec.Body.String())
	}

	sessionReq = httptest.NewRequest(http.MethodGet, "/admin/session", nil)
	sessionReq.Header.Set("authorization", "Bearer "+rotated.RawToken)
	sessionRec = httptest.NewRecorder()
	handler.ServeHTTP(sessionRec, sessionReq)
	if sessionRec.Code != http.StatusUnauthorized {
		t.Fatalf("session after revoke status = %d, want %d, body=%s", sessionRec.Code, http.StatusUnauthorized, sessionRec.Body.String())
	}
	gotEvents := map[string]bool{}
	for _, eventType := range postgresAdminAuditOutboxEventTypes(t, ctx, db, "tenant_lab_001") {
		gotEvents[eventType] = true
	}
	for _, want := range []string{"admin_api_token_created", "admin_api_token_revoked", "admin_api_token_rotated"} {
		if !gotEvents[want] {
			t.Fatalf("admin audit outbox events = %#v, want %s", gotEvents, want)
		}
	}
}

func TestPostgresAdminAuthRemovedOIDCCallbackDoesNotCreateSessionE2E(t *testing.T) {
	dsn := os.Getenv("POSTGRES_QUEUE_E2E_DSN")
	if dsn == "" {
		t.Skip("POSTGRES_QUEUE_E2E_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("sql.Open returned error: %v", err)
	}
	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("PingContext returned error: %v", err)
	}
	resetPostgresExportTaskQueueTables(t, ctx, db)
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		resetPostgresExportTaskQueueTables(t, cleanupCtx, db)
		_ = db.Close()
	})
	applyPostgresExportTaskQueueMigration(t, ctx, db)
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	handler := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: writer, AdminAuth: postgresAdminAuthStore{DB: db}})
	req := httptest.NewRequest(http.MethodGet, "/admin/oidc/callback?code=retired-flow&state=test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("removed admin federation route status=%d", rec.Code)
	}
	var count int
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM admin_sessions").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("removed admin federation created a session")
	}
}

func TestSetupEdgeAdminAuthStorePostgresE2E(t *testing.T) {
	dsn := os.Getenv("POSTGRES_QUEUE_E2E_DSN")
	if dsn == "" {
		t.Skip("POSTGRES_QUEUE_E2E_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("sql.Open returned error: %v", err)
	}
	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("PingContext returned error: %v", err)
	}
	resetPostgresExportTaskQueueTables(t, ctx, db)
	_ = db.Close()
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		cleanupDB, err := sql.Open("postgres", dsn)
		if err != nil {
			return
		}
		defer cleanupDB.Close()
		resetPostgresExportTaskQueueTables(t, cleanupCtx, cleanupDB)
	})

	store, closeStore, err := setupEdgeAdminAuthStore(ctx, edgeAdminAuthStoreConfig{
		Mode:          "postgres",
		DSN:           dsn,
		MigrationDir:  filepath.Join("..", "..", "migrations"),
		RunMigrations: true,
	})
	if err != nil {
		t.Fatalf("setupEdgeAdminAuthStore returned error: %v", err)
	}
	defer closeStore()

	now := time.Date(2026, 5, 24, 2, 0, 0, 0, time.UTC)
	token, rawToken, err := store.CreateAPITokenForTenant(ctx, adminAPITokenCreateRequest{
		Name:      "setup-runtime-admin",
		Roles:     []string{"admin"},
		Scopes:    []string{"admin.state.read"},
		ExpiresAt: now.Add(24 * time.Hour).Format(time.RFC3339),
	}, "tenant_lab_001", "admin_lab_bypass", now)
	if err != nil {
		t.Fatalf("CreateAPITokenForTenant returned error: %v", err)
	}
	identity, ok, err := store.LookupAPITokenAdminIdentity(ctx, rawToken, "tenant_lab_001", now)
	if err != nil {
		t.Fatalf("LookupAPITokenAdminIdentity returned error: %v", err)
	}
	if !ok || identity.PrincipalID != "admin_lab_bypass" || identity.AuthMethod != "admin_api_token" {
		t.Fatalf("identity = %#v ok=%v", identity, ok)
	}
	tokens, err := store.ListAPITokensForTenant(ctx, "tenant_lab_001")
	if err != nil {
		t.Fatalf("ListAPITokensForTenant returned error: %v", err)
	}
	if len(tokens) != 1 || tokens[0].ID != token.ID {
		t.Fatalf("tokens = %#v, want %s", tokens, token.ID)
	}
}

// ★ A TOKEN AN OPERATOR MINTS FOR A CUSTOMER AUTHENTICATED NOWHERE (found live on the reference lab,
// 2026-08-16). The identity lookup joined the creating principal on tenant AND id, and an operator's principal
// does not live in the customer's organization — so the mint answered 201 and the credential was dead on
// arrival, 401 on every plane, with nothing saying why. The in-memory store had always resolved the principal
// by id alone, so the two stores disagreed about who may authenticate: the lab passed what production
// refused. This is the case, against the real database.
//
// It matters because it is the ordinary managed-service act, and because the migration away from the shared
// break-glass token depends on it: a named credential an operator issues for a customer has to work.
func TestPostgresAdminAuthCrossTenantAPITokenAuthenticatesE2E(t *testing.T) {
	dsn := os.Getenv("POSTGRES_QUEUE_E2E_DSN")
	if dsn == "" {
		t.Skip("POSTGRES_QUEUE_E2E_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("ping: %v", err)
	}
	resetPostgresExportTaskQueueTables(t, ctx, db)
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		resetPostgresExportTaskQueueTables(t, cleanupCtx, db)
		_ = db.Close()
	})
	applyPostgresExportTaskQueueMigration(t, ctx, db)

	store := postgresAdminAuthStore{DB: db}
	now := time.Now().UTC()

	// The operator's principal lives in the OPERATOR's organization.
	if err := store.PersistPrincipal(ctx, adminPrincipal{
		ID: "adm_operator_e2e", TenantID: "tenant_operator_001", Subject: "sub_operator",
		Email: "operator@example.invalid", Roles: []string{"super_admin", "admin"}, IDPID: "keycloak_lab",
		Status: "active", CreatedAt: now.Add(-time.Hour).Format(time.RFC3339),
	}); err != nil {
		t.Fatalf("persist principal: %v", err)
	}

	// It mints a token FOR a customer organization: the token's tenant is the customer's, the creator's is not.
	token, raw, _, err := buildAdminAPIToken(adminAPITokenCreateRequest{
		Name: "managed automation", Roles: []string{"admin"}, Scopes: []string{"admin.state.read"},
		ExpiresAt: now.Add(24 * time.Hour).Format(time.RFC3339),
	}, "tenant_northwind", "adm_operator_e2e", now)
	if err != nil {
		t.Fatalf("build token: %v", err)
	}
	if err := store.PersistAPIToken(ctx, token); err != nil {
		t.Fatalf("persist token: %v", err)
	}

	identity, ok, err := store.LookupAPITokenAdminIdentity(ctx, raw, "", now)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if !ok {
		t.Fatal("a token the operator minted for a customer resolved to nobody — 201 at the mint and 401 " +
			"forever afterwards, which is what the lab measured")
	}
	if identity.TenantID != "tenant_northwind" {
		t.Fatalf("the identity carries tenant %q; a token is scoped by ITS OWN organization, not its creator's",
			identity.TenantID)
	}
	if identity.PrincipalID != "adm_operator_e2e" {
		t.Fatalf("the identity names principal %q; provenance must survive the lookup", identity.PrincipalID)
	}

	// And the creator still gates it: disable the operator and every token they issued stops, in the customer's
	// organization too. That is the property the join exists for, and the one a looser join could have lost.
	if err := store.PersistPrincipal(ctx, adminPrincipal{
		ID: "adm_operator_e2e", TenantID: "tenant_operator_001", Subject: "sub_operator",
		Email: "operator@example.invalid", Roles: []string{"super_admin", "admin"}, IDPID: "keycloak_lab",
		// "disabled": the principals table permits active/disabled/deleted (the tokens table is the one with
		// active/revoked/expired — two neighbouring tables, two different vocabularies).
		Status: "disabled", CreatedAt: now.Add(-time.Hour).Format(time.RFC3339),
	}); err != nil {
		t.Fatalf("disable principal: %v", err)
	}
	if _, ok, err := store.LookupAPITokenAdminIdentity(ctx, raw, "", now); err != nil || ok {
		t.Fatalf("a token issued by a disabled principal still authenticates (ok=%v err=%v)", ok, err)
	}
}
