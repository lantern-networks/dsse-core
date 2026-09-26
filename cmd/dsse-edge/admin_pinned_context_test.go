package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/assetcatalog"
	"github.com/lantern-networks/dsse-core/edgeplane"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/policycandidate"
	"github.com/lantern-networks/dsse-core/policyrule"
)

func TestPinnedContextBindsReadsAndMutationsToAuthenticatedTenant(t *testing.T) {
	auth := newAdminAuthStore()
	store := policycandidate.NewStore()
	assets := assetcatalog.NewStore()
	rules := policyrule.NewStore()
	for _, tenant := range []string{"own", "other"} {
		auth.UpsertPrincipal(adminPrincipal{ID: tenant, TenantID: tenant, Roles: []string{"admin"}, Status: "active"})
		auth.UpsertAPIToken(adminAPIToken{ID: tenant, TenantID: tenant, TokenHash: adminTokenHash("fixture-" + tenant), Roles: []string{"admin"}, Scopes: []string{"*"}, CreatedByAdminPrincipalID: tenant, Status: "active", ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339)})
		if _, err := store.ObserveCertPinFailure(context.Background(), tenant, "named.example", "", 443, "rejected", time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	engine := edgeplane.NewNetworkExtensionLabTLSInterceptionMatchOnly([]string{"*"})
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: writer, AdminAuth: auth, PolicyCandidateStore: store, AssetStore: assets, RuleStore: rules, NetworkExtensionLabTLS: engine})
	call := func(method, path, body, actor string, status int) any {
		t.Helper()
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer fixture-"+actor)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != status {
			t.Fatalf("%s %s: %d %s", method, path, w.Code, w.Body)
		}
		var result any
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	for _, tenant := range []string{"own", "other"} {
		for _, path := range []string{"/admin/policy-candidates?", "/admin/intercept/bypass-hosts?scoped=1&"} {
			got := call("GET", path+"expected_tenant_id="+tenant, "", tenant, 200).(map[string]any)
			if got["tenant_id"] != tenant {
				t.Fatalf("owner: %v", got)
			}
			if rows, ok := got["candidates"].([]any); ok {
				if len(rows) != 1 || rows[0].(map[string]any)["tenant_id"] != tenant {
					t.Fatalf("foreign candidates: %v", got)
				}
			}
			call("GET", path+"expected_tenant_id=unrelated", "", tenant, 409)
		}
	}
	id := policycandidate.CertPinCandidateID("named.example", "", 443, "rejected")
	steps := []struct{ path, body string }{
		{"/admin/policy-candidates/" + id + "/review", `{"decision":"approved"}`},
		{"/admin/policy-candidates/" + id + "/materialize", `{}`},
		{"/admin/cert-pin-bypass", `{"host":"manual.example"}`},
	}
	before, _ := store.List(context.Background(), "other", policycandidate.ListOptions{})
	for _, s := range steps {
		call("POST", s.path+"?expected_tenant_id=own", s.body, "other", 409)
	}
	after, _ := store.List(context.Background(), "other", policycandidate.ListOptions{})
	if !reflect.DeepEqual(before, after) || len(rules.Snapshot()) != 0 || len(assets.ListEndpoints("other")) != 0 {
		t.Fatal("context rejection mutated state")
	}
	for _, s := range []struct{ path, body string }{steps[0], steps[2]} {
		if call("POST", s.path+"?expected_tenant_id=own", s.body, "own", 200).(map[string]any)["tenant_id"] != "own" {
			t.Fatal("wrong acknowledgement")
		}
	}
	// Omitted preconditions and the bare-array endpoint retain the old contract.
	if call("POST", "/admin/cert-pin-bypass", `{"host":"legacy.example"}`, "own", 200).(map[string]any)["tenant_id"] != "own" {
		t.Fatal("legacy caller lost own scope")
	}
	bare := call("GET", "/admin/intercept/bypass-hosts", "", "own", 200)
	if bare != nil {
		if _, ok := bare.([]any); !ok {
			t.Fatal("legacy array changed")
		}
	}
	rows := readSiteActorAudits(t, writer)
	if len(rows) != 9 {
		t.Fatalf("audits=%d", len(rows))
	}
	for i, r := range rows {
		want, tenant := "success", "own"
		if i < 3 {
			want, tenant = "error", "other"
		}
		if stringPtrValue(r.Result) != want || r.TenantID != tenant || stringPtrValue(r.ActorUserID) != tenant {
			t.Fatalf("audit %d: %+v", i, r)
		}
	}
	raw, _ := json.Marshal(rows)
	if strings.Contains(string(raw), "fixture-") {
		t.Fatal("credential leaked")
	}
	after, _ = store.List(context.Background(), "other", policycandidate.ListOptions{})
	if !reflect.DeepEqual(before, after) {
		t.Fatal("foreign state changed")
	}
}

func TestPinnedScopedBypassDoesNotReportUnavailableEngineAsEmpty(t *testing.T) {
	mux := http.NewServeMux()
	registerInterceptionPKIRoutes(mux, func(_ string, h http.HandlerFunc) http.HandlerFunc { return h }, serverConfig{}, testEvaluator(), nil, nil)
	for _, step := range []struct {
		path   string
		status int
	}{{"/admin/intercept/bypass-hosts?scoped=1", 503}, {"/admin/intercept/bypass-hosts", 200}} {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest("GET", step.path, nil))
		if w.Code != step.status {
			t.Fatalf("%s: %d %s", step.path, w.Code, w.Body)
		}
		if step.status == 200 && strings.TrimSpace(w.Body.String()) != "[]" {
			t.Fatal("legacy nil-engine contract changed")
		}
	}
}
