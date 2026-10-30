package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/agentpolicy"
	"github.com/lantern-networks/dsse-core/grantstore"
	"github.com/lantern-networks/dsse-core/idpregistry"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/policy"
)

func TestFleetSnapshotsRejectCustomerTokensAndSessionsThroughServer(t *testing.T) {
	prior := operatorTenantConfigured()
	t.Cleanup(func() { declareOperatorTenant(prior, false) })
	wasCP := edgeIsControlPlane
	edgeIsControlPlane = true
	t.Cleanup(func() { edgeIsControlPlane = wasCP })
	auth := newAdminAuthStore()
	now := time.Now().UTC()
	for _, role := range []string{"auditor", "analyst", "admin", "owner"} {
		auth.UpsertPrincipal(adminPrincipal{ID: role, TenantID: "customer", Roles: []string{role}, Status: "active"})
		auth.UpsertAPIToken(adminAPIToken{ID: role, TenantID: "customer", TokenHash: adminTokenHash("customer-" + role), Roles: []string{role}, Scopes: []string{"*"}, CreatedByAdminPrincipalID: role, Status: "active", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)})
		auth.UpsertSession(adminSession{ID: "session-" + role, TenantID: "customer", AdminPrincipalID: role, Roles: []string{role}, Status: "active", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), AuthTime: now.Format(time.RFC3339)})
	}
	for _, role := range []string{"admin", "owner"} {
		auth.UpsertPrincipal(adminPrincipal{ID: "operator-" + role, TenantID: "operator", Roles: []string{role}, Status: "active"})
		auth.UpsertAPIToken(adminAPIToken{ID: "operator-" + role, TenantID: "operator", TokenHash: adminTokenHash("operator-" + role), Roles: []string{role}, Scopes: []string{"admin.policy.read"}, CreatedByAdminPrincipalID: "operator-" + role, Status: "active", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)})
	}
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	policies := policy.NewStore([]model.Policy{{ID: "victim-policy-marker", TenantID: "victim", Status: "active", Conditions: map[string]any{"destination_host": "victim.invalid"}, Action: model.PolicyAction{Decision: "deny"}}})
	signer := testAgentPolicySigner(t)
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: writer, AdminAuth: auth, OperatorTenantID: "operator", PolicyStore: policies, AgentPolicySigner: signer, FleetConfigStatus: newFleetConfigStatusStore(time.Second)})
	_, err = theIdPRegistry.Load().Upsert(idpregistry.Connection{IdPID: "victim-idp", TenantID: "victim", Type: "oidc", Issuer: "https://idp.invalid", AuthorizationEndpoint: "https://idp.invalid/auth", ClientID: "fixture", ClientSecret: "victim-client-secret-marker"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = theGrantStore.Load().Mint(grantstore.Grant{GrantID: "victim-bearer-grant-marker", TenantID: "victim", DeviceID: "victim-device", Scope: "app:22"}, time.Hour, now); err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range []string{"/admin/config-bundle", "/admin/authentication-grants", "/admin/grant-bundle-page"} {
		for _, role := range []string{"auditor", "analyst", "admin", "owner"} {
			for _, session := range []bool{false, true} {
				r := httptest.NewRequest("GET", endpoint+"?tenant_id=operator", nil)
				r.Header.Set("X-DSSE-Grant-Nonce", "fixture-nonce-request-1234567890")
				if session {
					r.AddCookie(&http.Cookie{Name: "admin_session", Value: "session-" + role})
				} else {
					r.Header.Set("Authorization", "Bearer customer-"+role)
				}
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				if w.Code != 403 {
					t.Fatalf("customer %s session=%v read %s: %d", role, session, endpoint, w.Code)
				}
				for _, marker := range []string{"victim-client-secret-marker", "victim-bearer-grant-marker", "victim-policy-marker"} {
					if strings.Contains(w.Body.String(), marker) {
						t.Fatal("customer response contains foreign data")
					}
				}
				// This is an authenticated policy reader, not a denial caused by
				// an unusable session/token. Its normal tenant view still works.
				r.URL.Path = "/admin/policies"
				w = httptest.NewRecorder()
				h.ServeHTTP(w, r)
				if w.Code != 200 || strings.Contains(w.Body.String(), "victim-policy-marker") {
					t.Fatalf("customer policy read not isolated: %s %v %d", role, session, w.Code)
				}
			}
		}
		if endpoint == "/admin/grant-bundle-page" {
			continue // the valid epoch and generation come from a signed config reference below
		}
		for _, role := range []string{"admin", "owner"} {
			requestPath := endpoint
			if endpoint == "/admin/authentication-grants" {
				requestPath += "?tenant=victim&device=victim-device&scope=app%3A22"
			}
			r := httptest.NewRequest("GET", requestPath, nil)
			r.Header.Set("Authorization", "Bearer operator-"+role)
			r.Header.Set("X-DSSE-Grant-Nonce", "fixture-nonce-request-1234567890")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != 200 {
				t.Fatalf("operator Edge token %s lost fleet read: %s %d", role, endpoint, w.Code)
			}
			var envelope agentpolicy.Envelope
			if json.Unmarshal(w.Body.Bytes(), &envelope) != nil {
				t.Fatal("unsigned fleet snapshot")
			}
			raw, err := agentpolicy.VerifyAny(envelope, []string{signer.PublicKeyHex()})
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(raw), "victim-bearer-grant-marker") {
				t.Fatal("operator fleet snapshot lost grant evidence")
			}
			if endpoint == "/admin/config-bundle" && (!strings.Contains(string(raw), "victim-client-secret-marker") || !strings.Contains(string(raw), "victim-policy-marker")) {
				t.Fatal("operator fleet snapshot lost enforcement configuration")
			}
		}
	}
	configRequest := httptest.NewRequest("GET", "/admin/config-bundle?grant_pages="+grantPageProtocol, nil)
	oldRequest := httptest.NewRequest("GET", "/admin/config-bundle?grant_pages=grant-pages-v1", nil)
	oldRequest.Header.Set("Authorization", "Bearer operator-admin")
	oldResponse := httptest.NewRecorder()
	h.ServeHTTP(oldResponse, oldRequest)
	if oldResponse.Code != http.StatusBadRequest {
		t.Fatalf("obsolete page protocol silently fell back to inline grants: %d", oldResponse.Code)
	}
	configRequest.Header.Set("Authorization", "Bearer operator-admin")
	configResponse := httptest.NewRecorder()
	h.ServeHTTP(configResponse, configRequest)
	if configResponse.Code != http.StatusOK {
		t.Fatalf("operator cannot fetch grant-page reference: %d", configResponse.Code)
	}
	var configEnvelope agentpolicy.Envelope
	if err := json.Unmarshal(configResponse.Body.Bytes(), &configEnvelope); err != nil {
		t.Fatal(err)
	}
	configBytes, err := agentpolicy.VerifyAny(configEnvelope, []string{signer.PublicKeyHex()})
	if err != nil {
		t.Fatal(err)
	}
	var configReference configBundlePayload
	if err := json.Unmarshal(configBytes, &configReference); err != nil || configReference.GrantPages == nil || configReference.Grants != nil {
		t.Fatalf("operator did not receive a paged grant reference: %v", err)
	}
	pagePath := fmt.Sprintf("/admin/grant-bundle-page?protocol=%s&epoch=%s&generation=%d&offset=0",
		grantPageProtocol, configReference.GrantPages.Epoch, configReference.GrantPages.Generation)
	pageRequest := httptest.NewRequest("GET", pagePath, nil)
	pageRequest.Header.Set("Authorization", "Bearer operator-admin")
	pageResponse := httptest.NewRecorder()
	h.ServeHTTP(pageResponse, pageRequest)
	if pageResponse.Code != http.StatusOK {
		t.Fatalf("operator cannot fetch signed grant page: %d", pageResponse.Code)
	}
	var pageEnvelope agentpolicy.Envelope
	if err := json.Unmarshal(pageResponse.Body.Bytes(), &pageEnvelope); err != nil {
		t.Fatal(err)
	}
	pageBytes, err := agentpolicy.VerifyAny(pageEnvelope, []string{signer.PublicKeyHex()})
	if err != nil || !strings.Contains(string(pageBytes), "victim-bearer-grant-marker") {
		t.Fatalf("operator grant page did not carry verified evidence: %v", err)
	}
	// The same broad read permission must not let a customer impersonate fleet
	// members by writing the configuration-status evidence used by the operator.
	r := httptest.NewRequest("POST", "/admin/fleet/config-status", strings.NewReader(`{"region_id":"forged-region","cluster_id":"forged-node"}`))
	r.Header.Set("Authorization", "Bearer customer-auditor")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("customer poisoned fleet inventory", w.Code)
	}
}
