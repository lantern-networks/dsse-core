package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
)

func TestAdminOperateHeaderCannotAliasCaseDistinctTenant(t *testing.T) {
	declareOperatorTenantForTest(t, "operator")
	store := newAdminAuthStore()
	now := time.Now().UTC()
	store.UpsertPrincipal(adminPrincipal{ID: "acme-admin", TenantID: "Acme", Roles: []string{"admin"}, Status: "active"})
	store.UpsertSession(adminSession{
		ID: "acme-session", TenantID: "Acme", AdminPrincipalID: "acme-admin",
		Roles: []string{"admin"}, Status: "active", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339),
	})
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	called := false
	gate := newAdminEndpointMiddleware(testEvaluator(), writer, nil, store, "", false, nil, nil, nil)
	h := gate("admin.config.read", func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodGet, "/admin/state", nil)
	req.AddCookie(&http.Cookie{Name: "admin_session", Value: "acme-session"})
	req.Header.Set("X-Operate-Tenant", "acme")
	response := httptest.NewRecorder()
	h(response, req)
	if response.Code != http.StatusForbidden || called {
		t.Fatalf("case-distinct tenant override returned HTTP %d, handler called=%v", response.Code, called)
	}
	called = false
	owned := httptest.NewRequest(http.MethodGet, "/admin/state", nil)
	owned.AddCookie(&http.Cookie{Name: "admin_session", Value: "acme-session"})
	owned.Header.Set("X-Operate-Tenant", "Acme")
	ownedResponse := httptest.NewRecorder()
	h(ownedResponse, owned)
	if ownedResponse.Code != http.StatusOK || !called {
		t.Fatalf("own-tenant header returned HTTP %d, handler called=%v", ownedResponse.Code, called)
	}
}

func TestOperatorDelegationRecognizesCaseDistinctCustomer(t *testing.T) {
	declareOperatorTenantForTest(t, "Acme")
	now := time.Now().UTC()
	store := newAdminTenantModelStore(model.PolicyBundle{TenantID: "Acme"}, now)
	if _, err := store.Put(context.Background(), adminTenantModel{TenantID: "acme", DisplayName: "acme", Status: "active"}, now); err != nil {
		t.Fatal(err)
	}
	identity := adminIdentity{PrincipalID: "operator", TenantID: "Acme", Roles: []string{"super_admin"}, AuthMethod: "admin_api_token"}
	req := requestWithAdminIdentity(httptest.NewRequest(http.MethodPost, "/admin/rules", nil), identity)
	req.Header.Set("X-Operate-Tenant", "acme")
	verdict := operatorDelegationForRequest(context.Background(), req, identity, store, now)
	if verdict.Target != "acme" || !verdict.Resolved || verdict.Delegated {
		t.Fatalf("case-distinct customer bypassed delegation: %+v", verdict)
	}
}

func TestAdminAuthRecordsKeepCaseDistinctTenantIdentity(t *testing.T) {
	store := newAdminAuthStore()
	now := time.Now().UTC()
	store.UpsertPrincipal(adminPrincipal{ID: "upper", TenantID: "Acme", IDPID: "first_party", Subject: "same-subject", Status: "active"})
	if got, ok := store.PrincipalIDForSubject("acme", "same-subject"); ok {
		t.Fatalf("case-distinct tenant looked up another tenant's principal %q", got)
	}
	if got, ok := store.PrincipalIDForSubject("Acme", "same-subject"); !ok || got != "upper" {
		t.Fatalf("own-tenant principal lookup returned %q/%v", got, ok)
	}
	store.UpsertSession(adminSession{ID: "upper-session", TenantID: "Acme", Status: "active"})
	store.UpsertSession(adminSession{ID: "lower-session", TenantID: "acme", Status: "active"})
	store.UpsertAPIToken(adminAPIToken{ID: "upper-token", TenantID: "Acme", Status: "active"})
	store.UpsertAPIToken(adminAPIToken{ID: "lower-token", TenantID: "acme", Status: "active"})
	sessions, tokens, err := store.RevokeAllForTenant(context.Background(), "Acme", now)
	if err != nil || sessions != 1 || tokens != 1 {
		t.Fatalf("revoked %d sessions and %d tokens: %v", sessions, tokens, err)
	}
	if store.sessions["lower-session"].Status != "active" || store.apiTokens["lower-token"].Status != "active" {
		t.Fatal("case-distinct tenant's authentication material was revoked")
	}
}
