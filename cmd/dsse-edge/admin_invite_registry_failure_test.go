package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

func TestAdminInviteRequiresConfirmedTenantRegistry(t *testing.T) {
	const tenant = "tenant_lab_001"
	now := time.Now().UTC()
	registry := &unavailableDelegationStore{
		adminTenantModelAdminStore: newAdminTenantModelStore(model.PolicyBundle{TenantID: tenant}, now),
		fail:                       true,
	}
	auth, tokens := adminRBACMatrixAuthStore(t)
	credentials := newLocalAdminCredentialStore("DSSE")
	handler := newServerWithConfig(serverConfig{
		Evaluator:        testEvaluator(),
		AdminAuth:        auth,
		TenantModelStore: registry,
		LocalCredentials: credentials,
	})
	invite := func() *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/admin/admins/invite", strings.NewReader(`{"email":"new@example.invalid","roles":["admin"]}`))
		req.Header.Set("Authorization", "Bearer "+tokens["admin"])
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}
	if rec := invite(); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("registry unavailable: status %d, want 503", rec.Code)
	}
	if got := credentials.List(tenant); len(got) != 0 {
		t.Fatalf("registry outage created %d administrator credential(s)", len(got))
	}
	registry.fail = false
	if rec := invite(); rec.Code != http.StatusCreated {
		t.Fatalf("registry recovered: status %d, want 201", rec.Code)
	}
	if got := credentials.List(tenant); len(got) != 1 {
		t.Fatalf("recovered registry created %d administrator credential(s), want 1", len(got))
	}
}
