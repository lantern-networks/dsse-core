package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/dlp"
	"github.com/lantern-networks/dsse-core/logs"
)

func TestSensitiveDataResponsesAndWritesBindTheAuthenticatedTenant(t *testing.T) {
	stores := dlpStoresForTest("context-fixture")
	auth := newAdminAuthStore()
	for _, tenant := range []string{"tenant_a", "tenant_b"} {
		auth.UpsertPrincipal(adminPrincipal{ID: tenant, TenantID: tenant, Roles: []string{"admin"}, Status: "active"})
		auth.UpsertAPIToken(adminAPIToken{ID: tenant, TenantID: tenant, TokenHash: adminTokenHash("fixture-" + tenant), Roles: []string{"admin"}, Scopes: []string{"*"}, CreatedByAdminPrincipalID: tenant, Status: "active", ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339)})
		if err := stores.classifiers.SetSpecsDurable(tenant, classifierFixtureSpecs("ORIGINAL")); err != nil {
			t.Fatal(err)
		}
		if err := stores.allowlist.SetValuesDurable(tenant, []string{"4111111111111111"}); err != nil {
			t.Fatal(err)
		}
		if _, err := stores.fingerprints.SetDatasetDurable(tenant, "customer_record", []string{"CUST-100482"}); err != nil {
			t.Fatal(err)
		}
	}
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	registerDLPRoutes(mux, newAdminEndpointMiddleware(testEvaluator(), writer, nil, auth, "", true, nil, nil, nil), testEvaluator(), nil, nil, stores.allowlist, nil, stores.fingerprints, stores.classifiers, newEntitlementStore(map[string]bool{featureDLP: true}), nil, "")
	call := func(method, path, body, actor string, status int) map[string]any {
		t.Helper()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer fixture-"+actor)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code != status {
			t.Fatalf("%s %s: %d %s", method, path, w.Code, w.Body)
		}
		var result map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	for _, tenant := range []string{"tenant_a", "tenant_b"} {
		for _, path := range []string{"/admin/dlp-classifiers", "/admin/dlp-allowlist", "/admin/dlp-fingerprints"} {
			if call("GET", path, "", tenant, 200)["tenant_id"] != tenant {
				t.Fatal("read omitted authenticated tenant")
			}
		}
	}
	steps := []struct{ method, path, body string }{
		{"POST", "/admin/dlp-classifiers", `{"expected_tenant_id":"tenant_a","classifiers":[{"name":"project_code","kind":"keyword","keywords":["NEW"]}]}`},
		{"POST", "/admin/dlp-allowlist", `{"expected_tenant_id":"tenant_a","values":["4242424242424242"]}`},
		{"POST", "/admin/dlp-fingerprints", `{"expected_tenant_id":"tenant_a","name":"customer_record","values":["CUST-900001"]}`},
		{"DELETE", "/admin/dlp-fingerprints?name=customer_record&expected_tenant_id=tenant_a", ""},
	}
	before, gen := stores.Snapshot(), stores.Generation()
	for _, step := range steps {
		call(step.method, step.path, step.body, "tenant_b", 409)
		if !reflect.DeepEqual(before, stores.Snapshot()) || stores.Generation() != gen {
			t.Fatal("mismatched tenant changed a detector")
		}
	}
	for _, step := range steps {
		if call(step.method, step.path, step.body, "tenant_a", 200)["tenant_id"] != "tenant_a" {
			t.Fatal("write acknowledgement omitted owner")
		}
	}
	if !stores.allowlist.AllowlistForTenant("tenant_b").Allowed(dlp.CreditCard, []byte("4111111111111111")) || !reflect.DeepEqual(stores.classifiers.SpecsForTenant("tenant_b"), before.Classifiers["tenant_b"]) || len(stores.fingerprints.DatasetsForTenant("tenant_b")) != 1 {
		t.Fatal("foreign detector changed")
	}
	// Older API clients omit the precondition and remain self-scoped. The Console
	// always sends it, including for explicit empty-list writes and deletions.
	if call("POST", "/admin/dlp-allowlist", `{"values":[]}`, "tenant_a", 200)["tenant_id"] != "tenant_a" {
		t.Fatal("legacy client lost self scope")
	}
	rows := readTransportAudits(t, writer)
	if len(rows) != 9 {
		t.Fatalf("audits %d", len(rows))
	}
	for i, row := range rows {
		want, owner := "success", "tenant_a"
		if i < 4 {
			want, owner = "error", "tenant_b"
		}
		if stringPtrValue(row.Result) != want || row.TenantID != owner || stringPtrValue(row.ActorUserID) != owner {
			t.Fatalf("audit %d: %+v", i, row)
		}
	}
	raw, _ := json.Marshal(rows)
	for _, private := range []string{"fixture-tenant", "4111111111111111", "4242424242424242", "CUST-900001", "ORIGINAL"} {
		if strings.Contains(string(raw), private) {
			t.Fatalf("audit disclosed %s", private)
		}
	}
}
