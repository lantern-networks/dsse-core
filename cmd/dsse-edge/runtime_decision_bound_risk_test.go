package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/humanidentity"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/revocation"
	"github.com/lantern-networks/dsse-core/tenantca"
)

func TestRuntimeDecisionUsesCertificateTenantBeforeRiskEnrichment(t *testing.T) {
	const tenant = "tenant_risk_bound"
	dir := t.TempDir()
	ca := makeTestCA(t, dir, "bound-risk-ca", 93)
	reg, err := tenantca.LoadTenantCARegistry(writeRegistry(t, dir, map[string]string{tenant: ca.pemPath}))
	if err != nil {
		t.Fatal(err)
	}
	chains := leafSignedBy(t, ca, "connector-risk", reg.Pool)
	if len(chains) == 0 {
		t.Fatal("connector certificate did not verify")
	}
	directory := humanidentity.NewHumanIdentityDirectoryStore()
	if _, err := directory.Upsert(context.Background(), model.HumanIdentity{ID: "user-risk", Subject: "user-risk", Source: "idp"}, tenant, time.Now()); err != nil {
		t.Fatal(err)
	}
	risk := revocation.NewHighRiskOverlay()
	if _, err := risk.SetUserRisk(revocation.UserRisk{TenantID: tenant, ID: "user-risk", Severity: "high"}); err != nil {
		t.Fatal(err)
	}
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	evaluator := testEvaluatorWithPolicies([]model.Policy{
		{ID: "deny-high-risk", TenantID: tenant, Priority: 10, Status: "active", Conditions: map[string]any{"risk_state_severity": []any{"high", "critical"}}, Action: model.PolicyAction{Decision: "deny"}},
		{ID: "allow-app", TenantID: tenant, Priority: 100, Status: "active", Conditions: map[string]any{"application_id": "app-risk"}, Action: model.PolicyAction{Decision: "allow"}},
	})
	evaluator.PolicyBundle.TenantID = tenant
	h := newServerWithConfig(serverConfig{Evaluator: evaluator, Writer: writer, Registry: connector.NewRegistry(), TenantCARegistry: reg, HumanIdentities: directory, HighRiskOverlay: risk, LabMode: boolPtr(false)})
	request := func(body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/decisions/evaluate", strings.NewReader(body))
		r.Header.Set(connectorIDHeader, "connector-risk")
		r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{chains[0][0]}, VerifiedChains: chains}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	w := request(`{"user_id":"user-risk","application_id":"app-risk","service_family":"https"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("decision status=%d, want 200", w.Code)
	}
	var dec model.AccessDecision
	if err := json.Unmarshal(w.Body.Bytes(), &dec); err != nil {
		t.Fatal(err)
	}
	if dec.TenantID != tenant || dec.Decision != "deny" || dec.PolicyID != "deny-high-risk" {
		t.Fatalf("cert-bound user risk was skipped: tenant=%q decision=%q policy=%q", dec.TenantID, dec.Decision, dec.PolicyID)
	}
	w = request(`{"tenant_id":"other-tenant","user_id":"user-risk","application_id":"app-risk","service_family":"https"}`)
	if w.Code != http.StatusForbidden {
		t.Fatalf("cross-tenant claim status=%d, want 403", w.Code)
	}
}

func TestPolicyLookupUsesDecisionTenantForDuplicateIDs(t *testing.T) {
	const tenant = "tenant_second"
	evaluator := testEvaluatorWithPolicies([]model.Policy{
		{ID: "shared-id", TenantID: "tenant_first", Priority: 1, Status: "active", Action: model.PolicyAction{Decision: "allow"}},
		{ID: "shared-id", TenantID: tenant, Priority: 2, Status: "active", RequiredHumanApproval: true, Action: model.PolicyAction{Decision: "allow"}},
	})
	dec := evaluator.Evaluate(model.DecisionRequest{TenantID: tenant})
	policy, ok := policyForDecision(evaluator, dec)
	if !ok || policy.TenantID != tenant || !policy.RequiredHumanApproval {
		t.Fatalf("wrong tenant policy selected: ok=%t tenant=%q approval=%t", ok, policy.TenantID, policy.RequiredHumanApproval)
	}
	dec.TenantID = "unknown-tenant"
	if _, ok := policyForDecision(evaluator, dec); ok {
		t.Fatal("foreign tenant policy accepted for an unknown decision tenant")
	}
}

func TestPolicyLookupUsesActualGlobalOrTenantMatchWithSameID(t *testing.T) {
	const tenant = "tenant_specific"
	for _, tc := range []struct {
		name, winner                   string
		globalPriority, tenantPriority int
	}{
		{"global first", "", 1, 2},
		{"tenant first", tenant, 2, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			evaluator := testEvaluatorWithPolicies([]model.Policy{
				{ID: "shared-id", TenantID: "", Priority: tc.globalPriority, Status: "active", RequiredHumanApproval: true, Action: model.PolicyAction{Decision: "allow"}},
				{ID: "shared-id", TenantID: tenant, Priority: tc.tenantPriority, Status: "active", Action: model.PolicyAction{Decision: "allow"}},
			})
			dec := evaluator.Evaluate(model.DecisionRequest{TenantID: tenant})
			policy, ok := policyForDecision(evaluator, dec)
			if !ok || policy.TenantID != tc.winner {
				t.Fatalf("matched policy tenant=%q found=%t, want %q", policy.TenantID, ok, tc.winner)
			}
			if _, present := dec.Metadata["matched_policy_tenant_id"].(string); !present {
				t.Fatal("decision omitted server-generated matched-policy tenant")
			}
			if tc.winner == "" && !policy.RequiredHumanApproval {
				t.Fatal("global matched policy lost approval requirement")
			}
			if tc.winner == tenant && policy.RequiredHumanApproval {
				t.Fatal("tenant matched policy inherited global approval requirement")
			}
		})
	}
	dec := model.AccessDecision{TenantID: tenant, PolicyID: "shared-id", Metadata: map[string]any{}}
	if _, ok := policyForDecision(testEvaluatorWithPolicies([]model.Policy{{ID: "shared-id", TenantID: tenant}}), dec); ok {
		t.Fatal("policy inferred from an unbound decision ID")
	}
}
