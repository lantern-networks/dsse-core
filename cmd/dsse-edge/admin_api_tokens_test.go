package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/logs"
)

func TestAdminEndpointAcceptsAPITokenRoles(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	adminAuth := newAdminAuthStore()
	adminAuth.UpsertPrincipal(adminPrincipal{
		ID:        "admin_user_token_001",
		TenantID:  "tenant_lab_001",
		Subject:   "sub_admin_token_001",
		Email:     "admin-token@example.jp",
		Roles:     []string{"auditor"},
		IDPID:     "keycloak_lab",
		Status:    "active",
		CreatedAt: time.Now().UTC().Add(-time.Hour).Format(time.RFC3339),
	})
	adminAuth.UpsertAPIToken(adminAPIToken{
		ID:                        "admin_token_test_001",
		TenantID:                  "tenant_lab_001",
		Name:                      "test-export-token",
		TokenHash:                 adminTokenHash("raw-admin-api-token"),
		Roles:                     []string{"auditor"},
		Scopes:                    []string{"admin.logs.read", "admin.export.create", "admin.export.read"},
		CreatedByAdminPrincipalID: "admin_user_token_001",
		CreatedAt:                 time.Now().UTC().Add(-time.Hour).Format(time.RFC3339),
		ExpiresAt:                 time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
		Status:                    "active",
	})
	handler := newServerWithConfig(serverConfig{
		Evaluator:  testEvaluator(),
		Writer:     writer,
		Registry:   connector.NewRegistry(),
		AdminAuth:  adminAuth,
		AdminToken: "legacy-token-not-used",
	})
	req := httptest.NewRequest(http.MethodGet, "/admin/logs/access", nil)
	req.Header.Set("authorization", "Bearer raw-admin-api-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status with admin api token = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/admin/export-jobs", strings.NewReader(`{"stream":"access","format":"ndjson","from":"2026-05-23T00:00:00Z","to":"2026-05-24T00:00:00Z"}`))
	req.Header.Set("authorization", "Bearer raw-admin-api-token")
	rec = httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("export status with auditor token = %d, want %d, body=%s", rec.Code, http.StatusAccepted, rec.Body.String())
	}
}

func TestAdminAPITokenScopesRestrictPermissions(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	adminAuth := newAdminAuthStore()
	adminAuth.UpsertPrincipal(adminPrincipal{
		ID:        "admin_user_scoped_token_001",
		TenantID:  "tenant_lab_001",
		Subject:   "sub_scoped_token",
		Email:     "scoped-token@example.jp",
		Roles:     []string{"auditor"},
		IDPID:     "keycloak_lab",
		Status:    "active",
		CreatedAt: time.Now().UTC().Add(-time.Hour).Format(time.RFC3339),
	})
	adminAuth.UpsertAPIToken(adminAPIToken{
		ID:                        "admin_token_scoped_001",
		TenantID:                  "tenant_lab_001",
		Name:                      "logs-only-token",
		TokenHash:                 adminTokenHash("raw-logs-only-token"),
		Roles:                     []string{"auditor"},
		Scopes:                    []string{"admin.logs.read"},
		CreatedByAdminPrincipalID: "admin_user_scoped_token_001",
		CreatedAt:                 time.Now().UTC().Add(-time.Hour).Format(time.RFC3339),
		ExpiresAt:                 time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
		Status:                    "active",
	})
	outbox := &recordingAdminAuditOutboxDeadReader{}
	handler := newServerWithConfig(serverConfig{
		Evaluator:        testEvaluator(),
		Writer:           writer,
		Registry:         connector.NewRegistry(),
		AdminAuth:        adminAuth,
		AdminAuditOutbox: outbox,
	})
	req := httptest.NewRequest(http.MethodGet, "/admin/logs/access", nil)
	req.Header.Set("authorization", "Bearer raw-logs-only-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("logs status with scoped token = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/admin/export-jobs", strings.NewReader(`{"stream":"access","format":"ndjson","from":"2026-05-23T00:00:00Z","to":"2026-05-24T00:00:00Z"}`))
	req.Header.Set("authorization", "Bearer raw-logs-only-token")
	rec = httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "admin api token scope admin.export.create is required") {
		t.Fatalf("export status with logs-only token = %d body=%s, want scope denial", rec.Code, rec.Body.String())
	}
	auditRows, err := readAuditRowsExcludingWrapper(writer)
	if err != nil {
		t.Fatalf("ReadJSONL returned error: %v", err)
	}
	last := auditRows[len(auditRows)-1]
	if last["event_type"] != "admin_rbac_denied" {
		t.Fatalf("last audit row = %#v, want admin_rbac_denied", last)
	}
	metadata, ok := last["metadata"].(map[string]any)
	if !ok || fmt.Sprint(metadata["scopes"]) == "" {
		t.Fatalf("audit metadata = %#v, want scopes", last["metadata"])
	}
	if !auditLogEventTypes(outbox.insertedAudits)["admin_rbac_denied"] {
		t.Fatalf("outbox inserted audits = %#v, want admin_rbac_denied", outbox.insertedAudits)
	}
}

func TestAdminAPITokenCreateRejectsScopeOutsideRoles(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(),
		Writer:    writer,
		Registry:  connector.NewRegistry(),
		AdminAuth: newAdminAuthStore(),
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/api-tokens", strings.NewReader(`{"name":"bad-scope","roles":["auditor"],"scopes":["admin.policy.write"],"expires_at":"2099-01-01T00:00:00Z"}`))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "api token scope admin.policy.write is not allowed by roles") {
		t.Fatalf("status = %d body=%s, want invalid scope", rec.Code, rec.Body.String())
	}
}

func TestAdminAPITokenCreateRejectsAPITokenAuthentication(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	adminAuth := newAdminAuthStore()
	adminAuth.UpsertPrincipal(adminPrincipal{
		ID:        "admin_user_token_creator_001",
		TenantID:  "tenant_lab_001",
		Subject:   "sub_token_creator_001",
		Email:     "token-creator@example.jp",
		Roles:     []string{"admin"},
		IDPID:     "keycloak_lab",
		Status:    "active",
		CreatedAt: time.Now().UTC().Add(-time.Hour).Format(time.RFC3339),
	})
	adminAuth.UpsertAPIToken(adminAPIToken{
		ID:                        "admin_token_creator_001",
		TenantID:                  "tenant_lab_001",
		Name:                      "creator-token",
		TokenHash:                 adminTokenHash("raw-creator-token"),
		Roles:                     []string{"admin"},
		Scopes:                    []string{"admin.api_tokens.write", "admin.state.read"},
		CreatedByAdminPrincipalID: "admin_user_token_creator_001",
		CreatedAt:                 time.Now().UTC().Add(-time.Hour).Format(time.RFC3339),
		ExpiresAt:                 time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
		Status:                    "active",
	})
	outbox := &recordingAdminAuditOutboxDeadReader{}
	handler := newServerWithConfig(serverConfig{
		Evaluator:        testEvaluator(),
		Writer:           writer,
		Registry:         connector.NewRegistry(),
		AdminAuth:        adminAuth,
		AdminAuditOutbox: outbox,
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/api-tokens", strings.NewReader(`{"name":"propagated","roles":["admin"],"scopes":["admin.state.read"],"expires_at":"2099-01-01T00:00:00Z"}`))
	req.Header.Set("authorization", "Bearer raw-creator-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "not allowed from admin api token authentication") {
		t.Fatalf("body = %s, want api token creation auth boundary error", rec.Body.String())
	}
	if len(adminAuth.ListAPITokens("tenant_lab_001")) != 1 {
		t.Fatalf("tokens = %#v, want only original token", adminAuth.ListAPITokens("tenant_lab_001"))
	}
	gotOutboxEvents := auditLogEventTypes(outbox.insertedAudits)
	if !gotOutboxEvents["admin_rbac_denied"] {
		t.Fatalf("outbox inserted audits = %#v, want admin_rbac_denied", gotOutboxEvents)
	}
}

func TestAdminAPITokenIDsAreRandomized(t *testing.T) {
	now := time.Date(2026, 5, 24, 18, 30, 0, 0, time.UTC)
	req := adminAPITokenCreateRequest{
		Name:      "random-id-token",
		Roles:     []string{"auditor"},
		Scopes:    []string{"admin.state.read"},
		ExpiresAt: "2099-01-01T00:00:00Z",
	}
	first, _, _, err := buildAdminAPIToken(req, "tenant_lab_001", "admin_user_001", now)
	if err != nil {
		t.Fatalf("build first token returned error: %v", err)
	}
	second, _, _, err := buildAdminAPIToken(req, "tenant_lab_001", "admin_user_001", now)
	if err != nil {
		t.Fatalf("build second token returned error: %v", err)
	}
	if !strings.HasPrefix(first.ID, "admin_token_") || !strings.HasPrefix(second.ID, "admin_token_") {
		t.Fatalf("ids = %q, %q, want admin_token_ prefix", first.ID, second.ID)
	}
	if first.ID == second.ID {
		t.Fatalf("ids are equal for same timestamp: %q", first.ID)
	}

	rotated, replacement, _, err := rotateAdminAPIToken(first, "admin_user_001", adminAPITokenRotateRequest{ExpiresAt: "2099-01-01T00:00:00Z"}, now)
	if err != nil {
		t.Fatalf("rotate token returned error: %v", err)
	}
	if replacement.ID == first.ID || replacement.ID == rotated.ID || !strings.HasPrefix(replacement.ID, "admin_token_") {
		t.Fatalf("replacement id = %q, original=%q revoked=%q", replacement.ID, first.ID, rotated.ID)
	}
	if rotated.Metadata["rotated_to_admin_api_token_id"] != replacement.ID {
		t.Fatalf("revoked metadata = %#v, want rotated_to replacement id", rotated.Metadata)
	}
}

func TestAdminAPITokenRotateRevokesOldAndReturnsNewRawToken(t *testing.T) {
	// Drives an admin route with the shared break-glass token, which is off by default now.
	armBreakGlassForTest(t)
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	adminAuth := newAdminAuthStore()
	adminAuth.UpsertPrincipal(adminPrincipal{
		ID:        "admin_user_rotate_001",
		TenantID:  "tenant_lab_001",
		Subject:   "sub_rotate",
		Email:     "rotate@example.jp",
		Roles:     []string{"admin"},
		IDPID:     "keycloak_lab",
		Status:    "active",
		CreatedAt: time.Now().UTC().Add(-time.Hour).Format(time.RFC3339),
	})
	adminAuth.UpsertAPIToken(adminAPIToken{
		ID:                        "admin_token_actor_001",
		TenantID:                  "tenant_lab_001",
		Name:                      "actor-token",
		TokenHash:                 adminTokenHash("raw-actor-token"),
		Roles:                     []string{"admin"},
		Scopes:                    []string{"admin.api_tokens.write", "admin.state.read"},
		CreatedByAdminPrincipalID: "admin_user_rotate_001",
		CreatedAt:                 time.Now().UTC().Add(-time.Hour).Format(time.RFC3339),
		ExpiresAt:                 time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
		Status:                    "active",
	})
	adminAuth.UpsertAPIToken(adminAPIToken{
		ID:                        "admin_token_target_001",
		TenantID:                  "tenant_lab_001",
		Name:                      "target-token",
		TokenHash:                 adminTokenHash("raw-target-token"),
		Roles:                     []string{"admin"},
		Scopes:                    []string{"admin.state.read", "admin.api_tokens.read"},
		CreatedByAdminPrincipalID: "admin_user_rotate_001",
		CreatedAt:                 time.Now().UTC().Add(-time.Hour).Format(time.RFC3339),
		ExpiresAt:                 time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
		Status:                    "active",
	})
	outbox := &recordingAdminAuditOutboxDeadReader{}
	handler := newServerWithConfig(serverConfig{
		Evaluator:        testEvaluator(),
		Writer:           writer,
		Registry:         connector.NewRegistry(),
		AdminAuth:        adminAuth,
		AdminAuditOutbox: outbox,
		AdminToken:       "legacy-admin-token",
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/api-tokens/admin_token_target_001/rotate", strings.NewReader(`{"expires_at":"2099-01-01T00:00:00Z"}`))
	req.Header.Set("authorization", "Bearer legacy-admin-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusCreated, rec.Body.String())
	}
	var rotated adminAPITokenCreateResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &rotated); err != nil {
		t.Fatalf("decode rotated token response: %v", err)
	}
	if rotated.RawToken == "" || rotated.Token.ID == "admin_token_target_001" || rotated.Token.Name != "target-token" {
		t.Fatalf("rotated response = %#v, want new raw target-token", rotated)
	}
	tokens := adminAuth.ListAPITokens("tenant_lab_001")
	var oldToken, newToken adminAPIToken
	for _, token := range tokens {
		switch token.ID {
		case "admin_token_target_001":
			oldToken = token
		case rotated.Token.ID:
			newToken = token
		}
	}
	if oldToken.Status != "revoked" || oldToken.Metadata["rotated_to_admin_api_token_id"] != rotated.Token.ID {
		t.Fatalf("old token = %#v, want revoked with rotation metadata", oldToken)
	}
	if newToken.Status != "active" || newToken.TokenHash != adminTokenHash(rotated.RawToken) || newToken.Metadata["rotated_from_admin_api_token_id"] != "admin_token_target_001" {
		t.Fatalf("new token = %#v, want active rotated token", newToken)
	}
	req = httptest.NewRequest(http.MethodGet, "/admin/session", nil)
	req.Header.Set("authorization", "Bearer raw-target-token")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("old raw token status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	req = httptest.NewRequest(http.MethodGet, "/admin/session", nil)
	req.Header.Set("authorization", "Bearer "+rotated.RawToken)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("new raw token status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	auditRows, err := readAuditRowsExcludingWrapper(writer)
	if err != nil {
		t.Fatalf("ReadJSONL returned error: %v", err)
	}
	hasRotationAudit := false
	for _, row := range auditRows {
		if row["event_type"] == "admin_api_token_rotated" {
			hasRotationAudit = true
			break
		}
	}
	if !hasRotationAudit {
		t.Fatalf("audit rows = %#v, want admin_api_token_rotated", auditRows)
	}
	hasOutboxRotationAudit := false
	for _, audit := range outbox.insertedAudits {
		if audit.EventType == "admin_api_token_rotated" {
			hasOutboxRotationAudit = true
			break
		}
	}
	if !hasOutboxRotationAudit {
		t.Fatalf("outbox inserted audits = %#v, want admin_api_token_rotated", outbox.insertedAudits)
	}
}

func TestAdminAPITokenRotateAllowsSelfRotationForAPITokenAuthentication(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	adminAuth := newAdminAuthStore()
	adminAuth.UpsertPrincipal(adminPrincipal{
		ID:        "admin_user_rotate_self_001",
		TenantID:  "tenant_lab_001",
		Subject:   "sub_rotate_self",
		Email:     "rotate-self@example.jp",
		Roles:     []string{"admin"},
		IDPID:     "keycloak_lab",
		Status:    "active",
		CreatedAt: time.Now().UTC().Add(-time.Hour).Format(time.RFC3339),
	})
	adminAuth.UpsertAPIToken(adminAPIToken{
		ID:                        "admin_token_self_rotate_001",
		TenantID:                  "tenant_lab_001",
		Name:                      "self-rotate-token",
		TokenHash:                 adminTokenHash("raw-self-rotate-token"),
		Roles:                     []string{"admin"},
		Scopes:                    []string{"admin.api_tokens.write", "admin.state.read"},
		CreatedByAdminPrincipalID: "admin_user_rotate_self_001",
		CreatedAt:                 time.Now().UTC().Add(-time.Hour).Format(time.RFC3339),
		ExpiresAt:                 time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
		Status:                    "active",
	})
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(),
		Writer:    writer,
		Registry:  connector.NewRegistry(),
		AdminAuth: adminAuth,
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/api-tokens/admin_token_self_rotate_001/rotate", strings.NewReader(`{"expires_at":"2099-01-01T00:00:00Z"}`))
	req.Header.Set("authorization", "Bearer raw-self-rotate-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusCreated, rec.Body.String())
	}
	var rotated adminAPITokenCreateResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &rotated); err != nil {
		t.Fatalf("decode rotated token response: %v", err)
	}
	if rotated.RawToken == "" || rotated.Token.ID == "admin_token_self_rotate_001" {
		t.Fatalf("rotated response = %#v, want replacement token", rotated)
	}
	req = httptest.NewRequest(http.MethodGet, "/admin/session", nil)
	req.Header.Set("authorization", "Bearer raw-self-rotate-token")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("old raw token status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	req = httptest.NewRequest(http.MethodGet, "/admin/session", nil)
	req.Header.Set("authorization", "Bearer "+rotated.RawToken)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("new raw token status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var sessionInfo map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &sessionInfo); err != nil {
		t.Fatalf("decode session info: %v", err)
	}
	if sessionInfo["api_token_id"] != rotated.Token.ID {
		t.Fatalf("api_token_id = %#v, want rotated token id %q", sessionInfo["api_token_id"], rotated.Token.ID)
	}
}

func TestAdminAPITokenRotateRejectsOtherTokenForAPITokenAuthentication(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	adminAuth := newAdminAuthStore()
	adminAuth.UpsertPrincipal(adminPrincipal{
		ID:        "admin_user_rotate_other_001",
		TenantID:  "tenant_lab_001",
		Subject:   "sub_rotate_other",
		Email:     "rotate-other@example.jp",
		Roles:     []string{"admin"},
		IDPID:     "keycloak_lab",
		Status:    "active",
		CreatedAt: time.Now().UTC().Add(-time.Hour).Format(time.RFC3339),
	})
	adminAuth.UpsertAPIToken(adminAPIToken{
		ID:                        "admin_token_rotate_actor_001",
		TenantID:                  "tenant_lab_001",
		Name:                      "rotate-actor-token",
		TokenHash:                 adminTokenHash("raw-rotate-actor-token"),
		Roles:                     []string{"admin"},
		Scopes:                    []string{"admin.api_tokens.write", "admin.state.read"},
		CreatedByAdminPrincipalID: "admin_user_rotate_other_001",
		CreatedAt:                 time.Now().UTC().Add(-time.Hour).Format(time.RFC3339),
		ExpiresAt:                 time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
		Status:                    "active",
	})
	adminAuth.UpsertAPIToken(adminAPIToken{
		ID:                        "admin_token_rotate_target_001",
		TenantID:                  "tenant_lab_001",
		Name:                      "rotate-target-token",
		TokenHash:                 adminTokenHash("raw-rotate-target-token"),
		Roles:                     []string{"admin"},
		Scopes:                    []string{"admin.state.read"},
		CreatedByAdminPrincipalID: "admin_user_rotate_other_001",
		CreatedAt:                 time.Now().UTC().Add(-time.Hour).Format(time.RFC3339),
		ExpiresAt:                 time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
		Status:                    "active",
	})
	outbox := &recordingAdminAuditOutboxDeadReader{}
	handler := newServerWithConfig(serverConfig{
		Evaluator:        testEvaluator(),
		Writer:           writer,
		Registry:         connector.NewRegistry(),
		AdminAuth:        adminAuth,
		AdminAuditOutbox: outbox,
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/api-tokens/admin_token_rotate_target_001/rotate", strings.NewReader(`{"expires_at":"2099-01-01T00:00:00Z"}`))
	req.Header.Set("authorization", "Bearer raw-rotate-actor-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "allowed only for the authenticating token") {
		t.Fatalf("body = %s, want self-rotation boundary error", rec.Body.String())
	}
	var target adminAPIToken
	for _, token := range adminAuth.ListAPITokens("tenant_lab_001") {
		if token.ID == "admin_token_rotate_target_001" {
			target = token
			break
		}
	}
	if target.Status != "active" || target.TokenHash != adminTokenHash("raw-rotate-target-token") {
		t.Fatalf("target token = %#v, want unchanged active target", target)
	}
	gotOutboxEvents := auditLogEventTypes(outbox.insertedAudits)
	if !gotOutboxEvents["admin_rbac_denied"] {
		t.Fatalf("outbox inserted audits = %#v, want admin_rbac_denied", gotOutboxEvents)
	}
}

func TestAdminAPITokenRevokeAllowsSelfForAPITokenAuthentication(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	adminAuth := newAdminAuthStore()
	adminAuth.UpsertPrincipal(adminPrincipal{
		ID:        "admin_user_revoke_self_001",
		TenantID:  "tenant_lab_001",
		Subject:   "sub_revoke_self",
		Email:     "revoke-self@example.jp",
		Roles:     []string{"admin"},
		IDPID:     "keycloak_lab",
		Status:    "active",
		CreatedAt: time.Now().UTC().Add(-time.Hour).Format(time.RFC3339),
	})
	adminAuth.UpsertAPIToken(adminAPIToken{
		ID:                        "admin_token_self_revoke_001",
		TenantID:                  "tenant_lab_001",
		Name:                      "self-revoke-token",
		TokenHash:                 adminTokenHash("raw-self-revoke-token"),
		Roles:                     []string{"admin"},
		Scopes:                    []string{"admin.api_tokens.write", "admin.state.read"},
		CreatedByAdminPrincipalID: "admin_user_revoke_self_001",
		CreatedAt:                 time.Now().UTC().Add(-time.Hour).Format(time.RFC3339),
		ExpiresAt:                 time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
		Status:                    "active",
	})
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(),
		Writer:    writer,
		Registry:  connector.NewRegistry(),
		AdminAuth: adminAuth,
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/api-tokens/admin_token_self_revoke_001/revoke", nil)
	req.Header.Set("authorization", "Bearer raw-self-revoke-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	req = httptest.NewRequest(http.MethodGet, "/admin/session", nil)
	req.Header.Set("authorization", "Bearer raw-self-revoke-token")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("revoked raw token status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestAdminAPITokenRevokeRejectsOtherTokenForAPITokenAuthentication(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	adminAuth := newAdminAuthStore()
	adminAuth.UpsertPrincipal(adminPrincipal{
		ID:        "admin_user_revoke_other_001",
		TenantID:  "tenant_lab_001",
		Subject:   "sub_revoke_other",
		Email:     "revoke-other@example.jp",
		Roles:     []string{"admin"},
		IDPID:     "keycloak_lab",
		Status:    "active",
		CreatedAt: time.Now().UTC().Add(-time.Hour).Format(time.RFC3339),
	})
	adminAuth.UpsertAPIToken(adminAPIToken{
		ID:                        "admin_token_revoke_actor_001",
		TenantID:                  "tenant_lab_001",
		Name:                      "revoke-actor-token",
		TokenHash:                 adminTokenHash("raw-revoke-actor-token"),
		Roles:                     []string{"admin"},
		Scopes:                    []string{"admin.api_tokens.write", "admin.state.read"},
		CreatedByAdminPrincipalID: "admin_user_revoke_other_001",
		CreatedAt:                 time.Now().UTC().Add(-time.Hour).Format(time.RFC3339),
		ExpiresAt:                 time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
		Status:                    "active",
	})
	adminAuth.UpsertAPIToken(adminAPIToken{
		ID:                        "admin_token_revoke_target_001",
		TenantID:                  "tenant_lab_001",
		Name:                      "revoke-target-token",
		TokenHash:                 adminTokenHash("raw-revoke-target-token"),
		Roles:                     []string{"admin"},
		Scopes:                    []string{"admin.state.read"},
		CreatedByAdminPrincipalID: "admin_user_revoke_other_001",
		CreatedAt:                 time.Now().UTC().Add(-time.Hour).Format(time.RFC3339),
		ExpiresAt:                 time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
		Status:                    "active",
	})
	outbox := &recordingAdminAuditOutboxDeadReader{}
	handler := newServerWithConfig(serverConfig{
		Evaluator:        testEvaluator(),
		Writer:           writer,
		Registry:         connector.NewRegistry(),
		AdminAuth:        adminAuth,
		AdminAuditOutbox: outbox,
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/api-tokens/admin_token_revoke_target_001/revoke", nil)
	req.Header.Set("authorization", "Bearer raw-revoke-actor-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "allowed only for the authenticating token") {
		t.Fatalf("body = %s, want self-revoke boundary error", rec.Body.String())
	}
	var target adminAPIToken
	for _, token := range adminAuth.ListAPITokens("tenant_lab_001") {
		if token.ID == "admin_token_revoke_target_001" {
			target = token
			break
		}
	}
	if target.Status != "active" || target.TokenHash != adminTokenHash("raw-revoke-target-token") {
		t.Fatalf("target token = %#v, want unchanged active target", target)
	}
	gotOutboxEvents := auditLogEventTypes(outbox.insertedAudits)
	if !gotOutboxEvents["admin_rbac_denied"] {
		t.Fatalf("outbox inserted audits = %#v, want admin_rbac_denied", gotOutboxEvents)
	}
}

func TestAdminAPITokenRequiresPrincipalAndMarksExpired(t *testing.T) {
	adminAuth := newAdminAuthStore()
	adminAuth.UpsertAPIToken(adminAPIToken{
		ID:                        "admin_token_missing_principal_001",
		TenantID:                  "tenant_lab_001",
		Name:                      "missing-principal-token",
		TokenHash:                 adminTokenHash("missing-principal-token"),
		Roles:                     []string{"auditor"},
		Scopes:                    []string{"admin.logs.read"},
		CreatedByAdminPrincipalID: "admin_missing_001",
		CreatedAt:                 time.Now().UTC().Add(-time.Hour).Format(time.RFC3339),
		ExpiresAt:                 time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
		Status:                    "active",
	})
	if _, ok := adminAuth.IdentityForAPIToken("missing-principal-token", "tenant_lab_001", time.Now()); ok {
		t.Fatalf("IdentityForAPIToken accepted token with missing principal")
	}

	adminAuth.UpsertPrincipal(adminPrincipal{
		ID:        "admin_expired_owner_001",
		TenantID:  "tenant_lab_001",
		Subject:   "sub_expired_owner",
		Email:     "expired-owner@example.jp",
		Roles:     []string{"auditor"},
		IDPID:     "keycloak_lab",
		Status:    "active",
		CreatedAt: time.Now().UTC().Add(-2 * time.Hour).Format(time.RFC3339),
	})
	adminAuth.UpsertAPIToken(adminAPIToken{
		ID:                        "admin_token_expired_001",
		TenantID:                  "tenant_lab_001",
		Name:                      "expired-token",
		TokenHash:                 adminTokenHash("expired-token"),
		Roles:                     []string{"auditor"},
		Scopes:                    []string{"admin.logs.read"},
		CreatedByAdminPrincipalID: "admin_expired_owner_001",
		CreatedAt:                 time.Now().UTC().Add(-2 * time.Hour).Format(time.RFC3339),
		ExpiresAt:                 time.Now().UTC().Add(-time.Hour).Format(time.RFC3339),
		Status:                    "active",
	})
	if _, ok := adminAuth.IdentityForAPIToken("expired-token", "tenant_lab_001", time.Now()); ok {
		t.Fatalf("IdentityForAPIToken accepted expired token")
	}
	tokens := adminAuth.ListAPITokens("tenant_lab_001")
	var expired adminAPIToken
	for _, token := range tokens {
		if token.ID == "admin_token_expired_001" {
			expired = token
		}
	}
	if expired.Status != "expired" {
		t.Fatalf("expired token status = %q, want expired", expired.Status)
	}
}

func TestAdminAPITokenManagementLifecycle(t *testing.T) {
	// Drives an admin route with the shared break-glass token, which is off by default now.
	armBreakGlassForTest(t)
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	adminAuth := newAdminAuthStore()
	adminAuth.UpsertPrincipal(adminPrincipal{
		ID:        "admin_owner_001",
		TenantID:  "tenant_lab_001",
		Subject:   "sub_admin_owner_001",
		Email:     "admin-owner@example.jp",
		Roles:     []string{"owner"},
		IDPID:     "keycloak_lab",
		Status:    "active",
		CreatedAt: time.Now().UTC().Add(-time.Hour).Format(time.RFC3339),
	})
	outbox := &recordingAdminAuditOutboxDeadReader{}
	handler := newServerWithConfig(serverConfig{
		Evaluator:        testEvaluator(),
		Writer:           writer,
		Registry:         connector.NewRegistry(),
		AdminAuth:        adminAuth,
		AdminToken:       "legacy-admin-token",
		AdminAuditOutbox: outbox,
	})

	createBody := `{"name":"siem-export","roles":["auditor"],"scopes":["admin.logs.read","admin.export.read"],"expires_at":"2099-01-01T00:00:00Z"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/api-tokens", strings.NewReader(createBody))
	req.Header.Set("authorization", "Bearer legacy-admin-token")
	req.Header.Set("x-admin-principal-id", "admin_owner_001")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("create status = %d, want %d, body=%s", rec.Code, http.StatusCreated, rec.Body.String())
	}
	var created adminAPITokenCreateResponse
	if err := json.NewDecoder(rec.Body).Decode(&created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	if created.RawToken == "" || created.Token.ID == "" {
		t.Fatalf("created token did not separate raw token and hash: %#v", created)
	}

	req = httptest.NewRequest(http.MethodGet, "/admin/logs/access", nil)
	req.Header.Set("authorization", "Bearer "+created.RawToken)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status with created token = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/admin/api-tokens/"+created.Token.ID+"/revoke", nil)
	req.Header.Set("authorization", "Bearer legacy-admin-token")
	req.Header.Set("x-admin-principal-id", "admin_owner_001")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/admin/logs/access", nil)
	req.Header.Set("authorization", "Bearer "+created.RawToken)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status with revoked token = %d, want %d, body=%s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
	gotOutboxEvents := map[string]bool{}
	for _, audit := range outbox.insertedAudits {
		gotOutboxEvents[audit.EventType] = true
	}
	for _, want := range []string{"admin_api_token_created", "admin_api_token_revoked"} {
		if !gotOutboxEvents[want] {
			t.Fatalf("outbox inserted audit events = %#v, want %s", gotOutboxEvents, want)
		}
	}
}

func TestAdminAPITokenCanBootstrapFromLabBypass(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	adminAuth := newAdminAuthStore()
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(),
		Writer:    writer,
		Registry:  connector.NewRegistry(),
		AdminAuth: adminAuth,
	})

	createBody := `{"name":"bootstrap-export","roles":["auditor"],"scopes":["admin.logs.read","admin.export.read"],"expires_at":"2099-01-01T00:00:00Z"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/api-tokens", strings.NewReader(createBody))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status = %d, want %d, body=%s", rec.Code, http.StatusCreated, rec.Body.String())
	}
	var created adminAPITokenCreateResponse
	if err := json.NewDecoder(rec.Body).Decode(&created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	if created.Token.CreatedByAdminPrincipalID != "admin_lab_bypass" {
		t.Fatalf("created_by = %q, want admin_lab_bypass", created.Token.CreatedByAdminPrincipalID)
	}

	req = httptest.NewRequest(http.MethodGet, "/admin/logs/access", nil)
	req.Header.Set("authorization", "Bearer "+created.RawToken)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status with bootstrap token = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/admin/logs/access", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status without token after bootstrap = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}
