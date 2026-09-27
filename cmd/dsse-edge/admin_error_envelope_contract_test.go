package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/logs"
)

func TestAdminErrorEnvelopeAndStatusConsistency(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	adminAuth, rawTokensByRole := adminRBACMatrixAuthStore(t)
	rawScopeDeniedToken := "raw-scope-denied"
	adminErrorEnvelopeAddScopedToken(t, adminAuth, rawScopeDeniedToken)
	defer writer.Close()
	handler := newServerWithConfig(adminRBACMatrixServerConfig(writer, adminAuth))

	t.Run("rbac denied admin endpoints use the shared envelope", func(t *testing.T) {
		routes := mustAdminEndpointRBACMatrixRoutes(t)
		checked := 0
		for _, route := range routes {
			deniedRole, ok := adminErrorEnvelopeDeniedRole(route.Permission)
			if !ok {
				continue
			}
			checked++
			t.Run(fmt.Sprintf("%s %s denied to %s", route.Method, route.Path, deniedRole), func(t *testing.T) {
				req := httptest.NewRequest(route.Method, adminRBACMatrixConcretePath(route.Path), adminRBACMatrixBody(route.Method))
				req.Header.Set("authorization", "Bearer "+rawTokensByRole[deniedRole])
				req.Header.Set("content-type", "application/json")
				rec := httptest.NewRecorder()

				handler.ServeHTTP(rec, req)

				message := assertAdminJSONErrorEnvelope(t, rec, http.StatusForbidden)
				if !strings.Contains(message, fmt.Sprintf("admin permission %s is required", route.Permission)) {
					t.Fatalf("RBAC denial message = %q, want permission %q", message, route.Permission)
				}
			})
		}
		if checked == 0 {
			t.Fatalf("no RBAC-deniable admin endpoints were checked")
		}
	})

	cases := []struct {
		name      string
		method    string
		target    string
		token     string
		body      string
		wantCode  int
		wantError string
	}{
		{
			name:      "unauthenticated",
			method:    http.MethodGet,
			target:    "/admin/state",
			wantCode:  http.StatusUnauthorized,
			wantError: "admin authentication is required",
		},
		{
			name:      "api token scope denied",
			method:    http.MethodPost,
			target:    "/admin/export-jobs",
			token:     rawScopeDeniedToken,
			body:      `{"stream":"access","format":"ndjson","from":"2026-05-23T00:00:00Z","to":"2026-05-24T00:00:00Z"}`,
			wantCode:  http.StatusForbidden,
			wantError: "admin api token scope admin.export.create is required",
		},
		{
			name:      "bad request",
			method:    http.MethodPost,
			target:    "/admin/policies",
			token:     rawTokensByRole["admin"],
			body:      `{`,
			wantCode:  http.StatusBadRequest,
			wantError: "decode policy",
		},
		{
			name:      "not found",
			method:    http.MethodGet,
			target:    "/admin/policies/cp_m0021_absent",
			token:     rawTokensByRole["admin"],
			wantCode:  http.StatusNotFound,
			wantError: "policy cp_m0021_absent is absent",
		},
		{
			name:      "not implemented",
			method:    http.MethodGet,
			target:    "/admin/audit-outbox/dead",
			token:     rawTokensByRole["admin"],
			wantCode:  http.StatusNotImplemented,
			wantError: "admin audit outbox dead row reader is not configured",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.target, strings.NewReader(tc.body))
			if tc.token != "" {
				req.Header.Set("authorization", "Bearer "+tc.token)
			}
			if tc.body != "" {
				req.Header.Set("content-type", "application/json")
			}
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			message := assertAdminJSONErrorEnvelope(t, rec, tc.wantCode)
			if !strings.Contains(message, tc.wantError) {
				t.Fatalf("error message = %q, want to contain %q", message, tc.wantError)
			}
		})
	}
}

func adminErrorEnvelopeDeniedRole(permission string) (string, bool) {
	for _, role := range adminAPITokenAssignableRoles {
		if !adminPermissionAllowedAny([]string{role}, permission) {
			return role, true
		}
	}
	return "", false
}

func adminErrorEnvelopeAddScopedToken(t *testing.T, store *adminAuthStore, rawToken string) {
	t.Helper()

	now := time.Now().UTC()
	store.UpsertPrincipal(adminPrincipal{
		ID:        "admin_user_cp_m0021_scope",
		TenantID:  "tenant_lab_001",
		Subject:   "sub_cp_m0021_scope",
		Email:     "scope@example.invalid",
		Roles:     []string{"admin"},
		IDPID:     "keycloak_lab",
		Status:    "active",
		CreatedAt: now.Add(-time.Hour).Format(time.RFC3339),
	})
	store.UpsertAPIToken(adminAPIToken{
		ID:                        "admin_token_cp_m0021_scope",
		TenantID:                  "tenant_lab_001",
		Name:                      "scope",
		TokenHash:                 adminTokenHash(rawToken),
		Roles:                     []string{"admin"},
		Scopes:                    []string{"admin.state.read"},
		CreatedByAdminPrincipalID: "admin_user_cp_m0021_scope",
		CreatedAt:                 now.Add(-time.Hour).Format(time.RFC3339),
		ExpiresAt:                 now.Add(time.Hour).Format(time.RFC3339),
		Status:                    "active",
	})
}

func assertAdminJSONErrorEnvelope(t *testing.T, rec *httptest.ResponseRecorder, wantStatus int) string {
	t.Helper()

	if rec.Code != wantStatus {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, wantStatus, rec.Body.String())
	}
	contentType := rec.Header().Get("content-type")
	if !strings.Contains(contentType, "application/json") {
		t.Fatalf("content-type = %q, want application/json", contentType)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response body is not JSON: %v; body=%s", err, rec.Body.String())
	}
	if len(body) != 1 {
		t.Fatalf("error envelope keys = %v, want exactly [error]", body)
	}
	message, ok := body["error"].(string)
	if !ok || strings.TrimSpace(message) == "" {
		t.Fatalf("error field = %#v, want non-empty string", body["error"])
	}
	return message
}
