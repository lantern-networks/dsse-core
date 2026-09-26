package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/policy"
	"github.com/lantern-networks/dsse-core/swg"
	"github.com/lantern-networks/dsse-core/swghttprewrite"
	"github.com/lantern-networks/dsse-core/tenantrestriction"
)

func managedTRRoutes(t *testing.T, store *policy.Store, source string) *http.ServeMux {
	t.Helper()
	mux := http.NewServeMux()
	registerSWGTenantRestrictionRoutes(mux, func(_ string, h http.HandlerFunc) http.HandlerFunc { return h }, decision.Evaluator{}, nil, store, swg.RuntimeConfig{}, nil, source)
	return mux
}
func managedTRRequest(h http.Handler, tenant, method, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "/admin/swg/tenant-restriction", strings.NewReader(body))
	r = requestWithAdminIdentity(r, adminIdentity{PrincipalID: "test-admin", TenantID: tenant, Roles: []string{"admin"}, AuthMethod: "admin_session"})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func TestManagedTenantRestrictionNewDeployment(t *testing.T) {
	store := policy.NewStore(nil)
	if err := store.SetRuntimeStatePath(filepath.Join(t.TempDir(), "admin.json")); err != nil {
		t.Fatal(err)
	}
	h := managedTRRoutes(t, store, "")
	w := managedTRRequest(h, "new", "GET", "")
	var status struct {
		Rules     []struct{ Managed, Active, ValueConfigured bool }
		RuleCount int `json:"rule_count"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if status.RuleCount != 4 {
		t.Fatalf("new tenant has %d providers", status.RuleCount)
	}
	for _, r := range status.Rules {
		if !r.Managed || r.Active || r.ValueConfigured {
			t.Fatal("new tenant is not default OFF")
		}
	}
	for _, p := range tenantrestriction.Providers() {
		allowed := "one.example"
		if p.ID == "anthropic_claude" {
			allowed = "11111111-1111-4111-8111-111111111111"
		}
		if p.ID == "openai_chatgpt" {
			allowed = "wsp_Example123"
		}
		body := map[string]any{"provider": p.ID, "allowed_value": allowed, "enabled": true}
		if p.ID == "microsoft_365" {
			body["context_tenant_id"] = "22222222-2222-4222-8222-222222222222"
		}
		raw, _ := json.Marshal(body)
		w = managedTRRequest(h, "new", "POST", string(raw))
		if w.Code != 200 {
			t.Fatalf("%s save: %d %s", p.ID, w.Code, w.Body.String())
		}
		if bytes.Contains(w.Body.Bytes(), []byte(allowed)) {
			t.Fatal("status discloses configured value")
		}
	}
	other := managedTRRequest(h, "other", "GET", "")
	if strings.Contains(other.Body.String(), `"active":true`) {
		t.Fatal("other tenant affected")
	}
	w = managedTRRequest(managedTRRoutes(t, store, "https://cp.invalid"), "new", "POST", `{"provider":"google_workspace","enabled":false}`)
	if w.Code != 409 {
		t.Fatalf("Edge accepted local write: %d", w.Code)
	}
}

// Exercise the existing evaluator and production rewrite function, then make an
// actual HTTPS request to a private capture server. No provider receives test traffic.
func TestManagedTenantRestrictionHTTPSHeadersAllProviders(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "swghttprewrite", "testdata", "swg_saas_tenant_enforcement_preflight.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		PolicyBundle model.PolicyBundle `json:"policy_bundle"`
		Policies     []model.Policy     `json:"policies"`
		Fixtures     []struct {
			Request model.DecisionRequest `json:"request"`
		} `json:"fixtures"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, provider := range tenantrestriction.Providers() {
		t.Run(provider.ID, func(t *testing.T) {
			store := policy.NewStore(nil)
			_ = store.SetRuntimeStatePath(filepath.Join(t.TempDir(), "admin.json"))
			enabled := true
			allowed := "company.example"
			context := "22222222-2222-4222-8222-222222222222"
			if provider.ID == "anthropic_claude" {
				allowed = "11111111-1111-4111-8111-111111111111"
			}
			if provider.ID == "openai_chatgpt" {
				allowed = "wsp_Aa123"
			}
			patch := policy.TenantRestrictionPatch{AllowedValue: &allowed, Enabled: &enabled}
			if provider.ID == "microsoft_365" {
				patch.ContextTenantID = &context
			}
			if err := store.SaveTenantRestriction("customer", provider.ID, patch); err != nil {
				t.Fatal(err)
			}
			bundle := fixture.PolicyBundle
			bundle.SaaSCatalog = nil
			bundle.SWGTenantRestrictionRules = nil
			bundle.SWGTLSBypassRules = nil
			// Reuse the existing inspected allow policy fixture, with tenant/app binding updated.
			pol := fixture.Policies[0]
			pol.TenantID = "customer"
			pol.Conditions = map[string]any{"service_family": "https"}
			store.ReplaceTenant("customer", []model.Policy{pol}, time.Now())
			ev := store.RuntimeEvaluator(decision.Evaluator{PolicyBundle: bundle})
			req := fixture.Fixtures[0].Request
			req.TenantID = "customer"
			req.FQDN = provider.Hosts[0]
			req.SNI = provider.Hosts[0]
			req.Destination = provider.Hosts[0]
			dec := ev.Evaluate(req)
			if dec.Decision != "allow" {
				t.Fatalf("decision %s: %v", dec.Decision, dec.ReasonCodes)
			}
			capture := make(chan http.Header, 1)
			upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { capture <- r.Header.Clone(); w.WriteHeader(204) }))
			defer upstream.Close()
			request, _ := http.NewRequest("GET", upstream.URL, nil)
			request.Header.Set(provider.Header, "forged")
			request.Header.Set("Restrict-Access-Context", "forged")
			rewritten, result, err := rewriteEdgeSWGHTTPRequest(request, dec, swg.RuntimeConfig{}, swghttprewrite.HeaderValueMap(ev.TenantRestrictionHeaderValues))
			if err != nil || !result.HeaderApplied {
				t.Fatalf("rewrite applied=%v err=%v reasons=%v", result.HeaderApplied, err, dec.ReasonCodes)
			}
			response, err := upstream.Client().Do(rewritten)
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			headers := <-capture
			if headers.Get(provider.Header) != allowed {
				t.Fatal("captured header differs")
			}
			if provider.ID == "microsoft_365" && headers.Get("Restrict-Access-Context") != context {
				t.Fatal("M365 context missing")
			}
			encoded, _ := json.Marshal(dec)
			if bytes.Contains(encoded, []byte(allowed)) {
				t.Fatal("decision contains allowlist")
			}
			req.TenantID = "different"
			other := ev.Evaluate(req)
			for _, action := range other.Actions {
				if action.Type == "inject_saas_tenant_restriction_header" {
					t.Fatal("another tenant received restriction")
				}
			}
		})
	}
}

func TestManagedTenantRestrictionConfigSyncRejectsInvalidBeforeApply(t *testing.T) {
	cp := policy.NewStore(nil)
	_ = cp.SetRuntimeStatePath(filepath.Join(t.TempDir(), "admin.json"))
	allowed := "one.example"
	enabled := true
	if err := cp.SaveTenantRestriction("one", "google_workspace", policy.TenantRestrictionPatch{AllowedValue: &allowed, Enabled: &enabled}); err != nil {
		t.Fatal(err)
	}
	cfg := cp.SnapshotTenantConfig("one")
	edge := policy.NewStore(nil)
	source := configBundleSource{tenantID: "node"}
	payload := configBundlePayload{TenantPolicies: []tenantPolicySection{{TenantID: "one", Config: &cfg}}}
	if _, err := source.apply(payload, configApplyTargets{policyStore: edge}); err != nil {
		t.Fatal(err)
	}
	if !edge.SnapshotTenantConfig("one").SaaSTenantRestrictions["google_workspace"].Enabled {
		t.Fatal("not distributed")
	}
	disabled := cfg
	disabled.SaaSTenantRestrictions = map[string]tenantrestriction.Setting{}
	invalid := policy.TenantConfigBundle{SaaSTenantRestrictions: map[string]tenantrestriction.Setting{"google_workspace": {AllowedValue: "bad\r\nheader", Enabled: true}}}
	payload.TenantPolicies = []tenantPolicySection{{TenantID: "one", Config: &disabled}, {TenantID: "two", Config: &invalid}}
	if _, err := source.apply(payload, configApplyTargets{policyStore: edge}); err == nil {
		t.Fatal("accepted corrupt configuration")
	}
	if !edge.SnapshotTenantConfig("one").SaaSTenantRestrictions["google_workspace"].Enabled {
		t.Fatal("partially applied invalid bundle")
	}
}

// Ordinary edits must distinguish invalid input from an unavailable save destination.
type managedTRFailingPersister struct {
	blobstore.FilePersister
	fail bool
}

func (p *managedTRFailingPersister) Save(raw []byte) error {
	if p.fail {
		return errors.New("private-storage-detail")
	}
	return p.FilePersister.Save(raw)
}
func TestManagedTenantRestrictionSaveFailureAndRetry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin.json")
	disk := &managedTRFailingPersister{FilePersister: blobstore.FilePersister{Path: path}}
	store := policy.NewStore(nil)
	if err := store.SetRuntimeStatePersister(disk); err != nil {
		t.Fatal(err)
	}
	h := managedTRRoutes(t, store, "")
	before := `{"provider":"google_workspace","allowed_value":"one.example","enabled":true}`
	after := `{"provider":"google_workspace","allowed_value":"two.example","enabled":false}`
	if w := managedTRRequest(h, "one", "POST", before); w.Code != 200 {
		t.Fatalf("initial save %d", w.Code)
	}
	disk.fail = true
	w := managedTRRequest(h, "one", "POST", after)
	if w.Code != 503 || strings.Contains(w.Body.String(), "private-storage-detail") {
		t.Fatalf("storage failure response: %d %s", w.Code, w.Body.String())
	}
	saved := store.SnapshotTenantConfig("one").SaaSTenantRestrictions["google_workspace"]
	restored := policy.NewStore(nil)
	if err := restored.SetRuntimeStatePath(path); err != nil {
		t.Fatal(err)
	}
	if saved.AllowedValue != "one.example" || !saved.Enabled || restored.SnapshotTenantConfig("one").SaaSTenantRestrictions["google_workspace"] != saved {
		t.Fatal("failed save changed active or durable state")
	}
	disk.fail = false
	if w := managedTRRequest(h, "one", "POST", `{"provider":"google_workspace","allowed_value":"bad domain","enabled":true}`); w.Code != 400 {
		t.Fatalf("invalid input: %d", w.Code)
	}
	if w := managedTRRequest(h, "one", "POST", after); w.Code != 200 {
		t.Fatalf("retry: %d %s", w.Code, w.Body.String())
	}
	if err := restored.SetRuntimeStatePath(path); err != nil {
		t.Fatal(err)
	}
	saved = restored.SnapshotTenantConfig("one").SaaSTenantRestrictions["google_workspace"]
	if saved.AllowedValue != "two.example" || saved.Enabled {
		t.Fatal("retry was not persisted")
	}
}
