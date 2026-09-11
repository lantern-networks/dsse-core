package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/logs"
)

func TestAdminAuthHealthEndpointScopesTenant(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	adminAuth := newAdminAuthStore()
	adminAuth.UpsertPrincipal(adminPrincipal{
		ID:        "admin_other_tenant_001",
		TenantID:  "tenant_other_001",
		Subject:   "sub_other",
		Email:     "other@example.jp",
		Roles:     []string{"admin"},
		IDPID:     "keycloak_lab",
		Status:    "active",
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	})
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(),
		Writer:    writer,
		AdminAuth: adminAuth,
	})

	req := httptest.NewRequest(http.MethodGet, "/admin/auth/health?tenant_id=tenant_other_001", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin auth health status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var health adminAuthStoreHealth
	if err := json.Unmarshal(rec.Body.Bytes(), &health); err != nil {
		t.Fatalf("decode admin auth health: %v", err)
	}
	if health.TenantID != "tenant_lab_001" || health.Mode != "memory" || health.Status != "ok" || health.HasRecords || health.Stats.Total != 0 {
		t.Fatalf("health = %#v, want tenant-scoped empty memory health", health)
	}
}

func TestAdminAuthHealthEndpointReportsStoreErrorWithLegacyToken(t *testing.T) {
	// Drives an admin route with the shared break-glass token, which is off by default now.
	armBreakGlassForTest(t)
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator:  testEvaluator(),
		Writer:     writer,
		AdminAuth:  postgresAdminAuthStore{},
		AdminToken: "legacy-admin-token",
	})

	req := httptest.NewRequest(http.MethodGet, "/admin/auth/health", nil)
	req.Header.Set("authorization", "Bearer legacy-admin-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin auth health status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var health adminAuthStoreHealth
	if err := json.Unmarshal(rec.Body.Bytes(), &health); err != nil {
		t.Fatalf("decode admin auth health: %v", err)
	}
	if health.Status != "degraded" || health.Mode != "postgres" || health.LastError != "admin authentication store is unavailable" || strings.Contains(rec.Body.String(), "postgres admin auth db is not configured") {
		t.Fatalf("health = %#v body=%s, want safe degraded postgres health", health, rec.Body.String())
	}
}

func TestAdminAuthStoreErrorReturnsInternalServerError(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	outbox := &recordingAdminAuditOutboxDeadReader{}
	handler := newServerWithConfig(serverConfig{
		Evaluator:        testEvaluator(),
		Writer:           writer,
		AdminAuth:        postgresAdminAuthStore{},
		AdminAuditOutbox: outbox,
	})
	req := httptest.NewRequest(http.MethodGet, "/admin/state", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusInternalServerError, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "postgres admin auth db is not configured") || !strings.Contains(rec.Body.String(), "admin authentication store is unavailable") {
		t.Fatalf("body = %s, want generic admin auth store error", rec.Body.String())
	}
	if !auditLogEventTypes(outbox.insertedAudits)["admin_auth_failed"] {
		t.Fatalf("outbox inserted audits = %#v, want admin_auth_failed", outbox.insertedAudits)
	}
}

func TestLegacyAdminTokenCanAuthenticateWhenAdminAuthStoreErrors(t *testing.T) {
	// Drives an admin route with the shared break-glass token, which is off by default now.
	armBreakGlassForTest(t)
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator:  testEvaluator(),
		Writer:     writer,
		AdminAuth:  postgresAdminAuthStore{},
		AdminToken: "legacy-admin-token",
	})
	req := httptest.NewRequest(http.MethodGet, "/admin/state", nil)
	req.Header.Set("authorization", "Bearer legacy-admin-token")
	req.AddCookie(&http.Cookie{Name: "admin_session", Value: "stale-session-that-would-hit-store"})
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
}

func TestAdminRBACCatalogExposesAPITokenRoleScopes(t *testing.T) {
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
	req := httptest.NewRequest(http.MethodGet, "/admin/rbac/catalog", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var catalog adminRBACCatalogResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &catalog); err != nil {
		t.Fatalf("decode catalog: %v", err)
	}
	if catalog.APITokenDefaultRole != defaultAdminAPITokenRole {
		t.Fatalf("default role = %q, want %q", catalog.APITokenDefaultRole, defaultAdminAPITokenRole)
	}
	roles := map[string][]string{}
	for _, entry := range catalog.APITokenRoles {
		roles[entry.Role] = entry.Permissions
	}
	if len(roles) != len(adminAPITokenAssignableRoles) {
		t.Fatalf("roles = %#v, want %d assignable roles", roles, len(adminAPITokenAssignableRoles))
	}
	if !stringSliceContains(roles["admin"], "admin.api_tokens.write") {
		t.Fatalf("admin permissions = %#v, want admin.api_tokens.write", roles["admin"])
	}
	if !stringSliceContains(roles["admin"], "admin.connectors.write") {
		t.Fatalf("admin permissions = %#v, want admin.connectors.write", roles["admin"])
	}
	if !stringSliceContains(roles["admin"], "admin.usage.read") || !stringSliceContains(roles["auditor"], "admin.usage.read") {
		t.Fatalf("usage read permission missing from admin/auditor roles: %#v", roles)
	}
	if stringSliceContains(roles["analyst"], "admin.usage.read") {
		t.Fatalf("analyst permissions = %#v, did not want admin.usage.read", roles["analyst"])
	}
	if stringSliceContains(roles["auditor"], "admin.api_tokens.write") {
		t.Fatalf("auditor permissions = %#v, did not want admin.api_tokens.write", roles["auditor"])
	}
	if stringSliceContains(roles["auditor"], "admin.connectors.write") {
		t.Fatalf("auditor permissions = %#v, did not want admin.connectors.write", roles["auditor"])
	}
	if _, ok := roles["owner"]; ok {
		t.Fatalf("catalog exposed owner role: %#v", roles["owner"])
	}
}
