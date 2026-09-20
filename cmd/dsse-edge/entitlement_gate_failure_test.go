package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
)

// A 503 must end the mutation, not merely set the status before saving a body.
func TestDLPAuthorityFailureStopsEveryGatedMutation(t *testing.T) {
	cases := []struct{ method, path, body string }{
		{"POST", "/admin/dlp-policies", `{"id":"new","name":"New","identifiers":["credit_card"],"on_match":"observe"}`},
		{"POST", "/admin/dlp-rules", `{"rules":[]}`},
		{"POST", "/admin/dlp-classifiers", `{"classifiers":[{"name":"project_code","kind":"keyword","keywords":["NEW"]}]}`},
		{"POST", "/admin/dlp-allowlist", `{"values":["4242424242424242"]}`},
		{"POST", "/admin/dlp-fingerprints", `{"name":"customer_record","values":["NEW-RECORD","SECOND-RECORD"]}`},
		{"DELETE", "/admin/dlp-fingerprints?name=customer_record", ``},
	}
	for _, tc := range cases {
		t.Run(tc.method+tc.path, func(t *testing.T) {
			tenant := "tenant_lab_001"
			rt := dlpRuntime{rules: newDLPRuleRuntimeStore(), allowlist: newDLPAllowlistRuntimeStore("fixture"), policyObjects: newDLPPolicyObjectStore(), fingerprints: newDLPFingerprintRuntimeStore("fixture"), classifiers: newDLPClassifierRuntimeStore(), entitlements: newEntitlementStore(map[string]bool{featureDLP: true})}
			p := &entitlementReviewPersister{raw: []byte(`{"features":{"tenant_lab_001":{"dlp":true}}}`)}
			if err := rt.entitlements.SetPersister(p); err != nil {
				t.Fatal(err)
			}
			rt.rules.SetRules(tenant, []model.DLPRule{{ID: "prior", TenantID: tenant, Identifiers: []string{"credit_card"}, OnMatch: "observe"}})
			if _, err := rt.fingerprints.SetDatasetDurable(tenant, "customer_record", []string{"OLD-RECORD"}); err != nil {
				t.Fatal(err)
			}
			auth := newAdminAuthStore()
			auth.UpsertPrincipal(adminPrincipal{ID: "review", TenantID: tenant, Roles: []string{"admin"}, Status: "active"})
			auth.UpsertAPIToken(adminAPIToken{ID: "gate", TenantID: tenant, TokenHash: adminTokenHash("gate-fixture"), Roles: []string{"admin"}, Scopes: []string{"*"}, CreatedByAdminPrincipalID: "review", Status: "active", ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339)})
			writer, err := logs.NewWriter(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer writer.Close()
			mux := http.NewServeMux()
			registerDLPRoutes(mux, newAdminEndpointMiddleware(testEvaluator(), writer, nil, auth, "", true, nil, nil, nil), testEvaluator(), nil, rt.rules, rt.allowlist, rt.policyObjects, rt.fingerprints, rt.classifiers, rt.entitlements, nil, "")
			snapshot := func() string {
				b, err := json.Marshal([]any{rt.rules.RulesForTenant(tenant), rt.allowlist.ValuesForTenant(tenant), rt.policyObjects.List(tenant), rt.fingerprints.DatasetsForTenant(tenant), rt.classifiers.SpecsForTenant(tenant)})
				if err != nil {
					t.Fatal(err)
				}
				return string(b)
			}
			before := snapshot()
			send := func() *httptest.ResponseRecorder {
				r := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
				r.Header.Set("Authorization", "Bearer gate-fixture")
				w := httptest.NewRecorder()
				mux.ServeHTTP(w, r)
				return w
			}
			p.raw = []byte(`{"features":null}`)
			denied := send()
			if denied.Code != 503 {
				t.Fatalf("want 503, got %d: %s", denied.Code, denied.Body)
			}
			if snapshot() != before {
				t.Error("503 changed live DLP configuration")
			}
			var body map[string]any
			if err := json.Unmarshal(denied.Body.Bytes(), &body); err != nil {
				t.Errorf("503 appended a second response: %s", denied.Body)
			}
			if string(p.raw) != `{"features":null}` {
				t.Error("corrupt authority overwritten")
			}
			p.raw = []byte(`{"features":{"tenant_lab_001":{"dlp":true}}}`)
			if rr := send(); rr.Code != 200 {
				t.Fatalf("repaired retry: %d %s", rr.Code, rr.Body)
			}
			if snapshot() == before {
				t.Fatal("healthy retry made no change")
			}
			rows := readTransportAudits(t, writer)
			if len(rows) != 2 {
				t.Fatalf("audit count %d", len(rows))
			}
			for i, row := range rows {
				want := "error"
				if i == 1 {
					want = "success"
				}
				if stringPtrValue(row.Result) != want || row.TenantID != tenant || stringPtrValue(row.ActorUserID) != "review" {
					t.Fatalf("audit %d: %+v", i, row)
				}
			}
		})
	}
}

func TestEntitlementMissingFeaturesRetainsAuthority(t *testing.T) {
	for _, bad := range []string{`{}`, `null`, `{"features":null}`} {
		t.Run(bad, func(t *testing.T) {
			p := &entitlementReviewPersister{raw: []byte(`{"features":{"one":{"dlp":true}}}`)}
			s := newEntitlementStore(nil)
			if err := s.SetPersister(p); err != nil {
				t.Fatal(err)
			}
			p.raw = []byte(bad)
			if err := s.RefreshShared(); err == nil {
				t.Error("missing features accepted by refresh")
			}
			if !s.Entitled("one", featureDLP) {
				t.Error("invalid refresh replaced acknowledged grants")
			}
			if err := s.SetFeaturesContext(context.Background(), "two", map[string]bool{featureDLP: true}); err == nil {
				t.Error("missing features accepted by mutation")
			}
			if string(p.raw) != bad || s.Entitled("two", featureDLP) {
				t.Fatal("invalid authority overwritten")
			}
			p.raw = []byte(`{"features":{}}`)
			if err := s.RefreshShared(); err != nil {
				t.Fatal(err)
			}
			if s.Entitled("one", featureDLP) {
				t.Fatal("explicit empty authority ignored")
			}
		})
	}
}
