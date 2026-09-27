package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/edgeplane"
	"github.com/lantern-networks/dsse-core/inspectionposture"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/policy"
)

func TestInspectionPostureOperatorScopePersistenceRuntimeAndAudit(t *testing.T) {
	now := time.Now()
	oldOperator := operatorTenantConfigured()
	t.Cleanup(func() { operatorTenantAuthority.Store(oldOperator) })
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store := inspectionposture.NewStore()
	p := &riskAuditPersister{base: blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "posture.json")}}
	store.SetPersister(p)
	legacy := inspectionposture.DefaultPosture()
	legacy.BypassGroups = []string{"m365_optimize", "google_optimize"}
	if _, err := store.Set(legacy); err != nil {
		t.Fatal(err)
	}
	engine := edgeplane.NewNetworkExtensionLabTLSInterceptionMatchOnly([]string{"*"})
	setter := newInspectionPostureSetter(store, func(_ string) { engine.SetInterceptHosts(inspectionposture.EffectiveInterceptHosts(store.Get())) })
	auth := newAdminAuthStore()
	for id, tenant := range map[string]string{"operator": "tenant_lab_001", "customer": "tenant_customer", "reader": "tenant_lab_001"} {
		roles := []string{"admin", "super_admin"}
		if id == "reader" {
			roles = []string{"analyst"}
		}
		auth.UpsertPrincipal(adminPrincipal{ID: id, TenantID: tenant, Roles: roles, Status: "active"})
		auth.UpsertAPIToken(adminAPIToken{ID: id, TenantID: tenant, Roles: roles, Scopes: []string{"*"}, TokenHash: adminTokenHash("test-" + id), CreatedByAdminPrincipalID: id, Status: "active", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)})
	}
	config := serverConfig{Evaluator: testEvaluator(), Writer: writer, AdminAuth: auth, OperatorTenantID: "tenant_lab_001", NetworkExtensionLabTLS: engine, InspectionPosture: store.Get, SetInspectionPosture: setter}
	h := newServerWithConfig(config)
	call := func(method, body, actor string, status int) inspectionPostureResponse {
		t.Helper()
		r := httptest.NewRequest(method, "/admin/inspection-posture", strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer test-"+actor)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != status {
			t.Fatalf("%s %s = %d want %d: %s", method, actor, w.Code, status, w.Body)
		}
		if strings.Contains(w.Body.String(), "private-runtime-location") {
			t.Fatal("storage path exposed")
		}
		var out inspectionPostureResponse
		json.Unmarshal(w.Body.Bytes(), &out)
		return out
	}
	customer := call("GET", "", "customer", 200)
	if customer.Configurable || !customer.CanManageRules || customer.Scope != "deployment" || customer.TenantID != "tenant_customer" {
		t.Fatal("scope misleading")
	}
	call("POST", `{"mode":"bypass_default"}`, "customer", 403)
	call("POST", `{"known_bypass_enabled":false}`, "reader", 403)
	p.fail.Store(true)
	rev := store.ConfigGeneration()
	call("POST", `{"mode":"bypass_default"}`, "operator", 500)
	if store.Get().Mode != inspectionposture.ModeDecryptAll || store.ConfigGeneration() != rev || !engine.Matches(edgeplane.NetworkExtensionRuntimeCopyTCPRoute{Host: "api.openai.com", Port: 443}) {
		t.Fatal("failed save changed inspection")
	}
	p.fail.Store(false)
	saved := call("POST", `{"mode":"bypass_default","decrypt_allowlist_groups":["openai"],"decrypt_allowlist_hosts":["private.internal.invalid"]}`, "operator", 200)
	if !saved.Configurable || !saved.RuntimeAvailable || !engine.Matches(edgeplane.NetworkExtensionRuntimeCopyTCPRoute{Host: "api.openai.com", Port: 443}) || engine.Matches(edgeplane.NetworkExtensionRuntimeCopyTCPRoute{Host: "unlisted.invalid", Port: 443}) {
		t.Fatal("saved settings not enforced")
	}
	call("POST", `{"known_bypass_enabled":false}`, "operator", 200)
	if store.Get().Mode != inspectionposture.ModeBypassDefault || len(store.Get().DecryptAllowlistGroups) != 1 {
		t.Fatal("partial update lost fields")
	}
	call("POST", `{"decrypt_allowlist_groups":["unknown"]}`, "operator", 400)
	call("POST", `{"decrypt_allowlist_hosts":["https://wrong.invalid/path"]}`, "operator", 400)
	beforeCleanup := store.Get()
	call("POST", `{"bypass_groups":["m365_optimize","google_optimize","zoom_media"]}`, "operator", 409)
	if !reflect.DeepEqual(store.Get(), beforeCleanup) {
		t.Fatal("new legacy selection was accepted")
	}
	p.fail.Store(true)
	call("POST", `{"bypass_groups":["m365_optimize"]}`, "operator", 500)
	if !reflect.DeepEqual(store.Get(), beforeCleanup) {
		t.Fatal("failed cleanup changed legacy selections")
	}
	p.fail.Store(false)
	call("POST", `{"bypass_groups":["m365_optimize"]}`, "operator", 200)
	if !reflect.DeepEqual(store.Get().BypassGroups, []string{"m365_optimize"}) {
		t.Fatal("cleanup did not persist")
	}
	call("POST", `{"bypass_groups":[]}`, "operator", 200)
	call("POST", `{"bypass_groups":["m365_optimize"]}`, "operator", 409)
	if len(store.Get().BypassGroups) != 0 {
		t.Fatal("removed legacy selection was reinstated")
	}
	reloaded := inspectionposture.NewStore()
	if ok, e := reloaded.SetPersister(p); !ok || e != nil || !reflect.DeepEqual(store.Get(), reloaded.Get()) {
		t.Fatal("restart differs", e)
	}
	rows := readTransportAudits(t, writer)
	domain, failed := 0, 0
	for _, a := range rows {
		if a.EventType != "admin_inspection_posture_changed" {
			continue
		}
		domain++
		if a.TenantID != "tenant_lab_001" || stringPtrValue(a.ActorUserID) != "operator" || stringPtrValue(a.TargetID) != "inspection_posture" || a.Metadata["scope"] != "deployment" {
			t.Fatalf("bad audit: %+v", a)
		}
		if stringPtrValue(a.Result) == "persistence_unconfirmed" {
			failed++
		}
	}
	if domain != 6 || failed != 2 {
		t.Fatal("audit counts", domain, failed)
	}
	raw, _ := json.Marshal(rows)
	for _, secret := range []string{"private.internal.invalid", "test-operator", "private-runtime-location"} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("audit privacy", secret)
		}
	}
	config.NetworkExtensionLabTLS = nil
	h = newServerWithConfig(config)
	if call("GET", "", "operator", 200).RuntimeAvailable {
		t.Fatal("absent engine claimed active")
	}
	config.ConfigSourceURL = "https://cp.invalid"
	h = newServerWithConfig(config)
	if call("GET", "", "operator", 200).Configurable {
		t.Fatal("sourced node editable")
	}
	call("POST", `{"mode":"decrypt_all"}`, "operator", 409)
}
func TestInspectionPostureSyncRetriesSameGenerationAfterSaveFailure(t *testing.T) {
	s := inspectionposture.NewStore()
	p := &riskAuditPersister{base: blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "posture.json")}}
	s.SetPersister(p)
	s.Set(inspectionposture.DefaultPosture())
	p.fail.Store(true)
	engine := edgeplane.NewNetworkExtensionLabTLSInterceptionMatchOnly([]string{"*"})
	setter := newInspectionPostureSetter(s, func(_ string) { engine.SetInterceptHosts(inspectionposture.EffectiveInterceptHosts(s.Get())) })
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var polls atomic.Int32
	status := &configBundleSyncStatus{}
	checks := make(chan bool, 2)
	next := inspectionposture.Posture{Mode: inspectionposture.ModeBypassDefault, DecryptAllowlistGroups: []string{"openai"}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := polls.Add(1)
		if n == 3 {
			status.mu.RLock()
			failed := !status.haveApplied && status.lastError != ""
			status.mu.RUnlock()
			checks <- failed && s.Get().Mode == inspectionposture.ModeDecryptAll
			p.fail.Store(false)
		}
		if n == 4 {
			status.mu.RLock()
			ok := status.haveApplied && status.lastAppliedGeneration == 29
			status.mu.RUnlock()
			checks <- ok && s.Get().Mode == inspectionposture.ModeBypassDefault
			cancel()
		}
		json.NewEncoder(w).Encode(configBundlePayload{Generation: 29, Epoch: "posture-retry", InspectionPosture: &inspectionPostureBundle{Posture: next}})
	}))
	defer srv.Close()
	src := configBundleSource{tenantID: "tenant_lab_001", url: srv.URL, client: srv.Client(), interval: 10 * time.Millisecond, status: status}
	src.run(ctx, configApplyTargets{policyStore: policy.NewStore(nil), inspectionPosture: s.Get, setInspectionPosture: setter})
	if len(checks) != 2 || !<-checks || !<-checks {
		t.Fatal("same generation not retried")
	}
	reload := inspectionposture.NewStore()
	if ok, err := reload.SetPersister(p); !ok || err != nil || reload.Get().Mode != inspectionposture.ModeBypassDefault {
		t.Fatal("retry not durable", err)
	}
	if _, err := applyInspectionPostureBundleSection(&inspectionPostureBundle{}, s.Get, setter, nil); err == nil {
		t.Fatal("invalid mode accepted")
	}
	if _, err := applyInspectionPostureBundleSection(&inspectionPostureBundle{Posture: next}, nil, nil, nil); err == nil {
		t.Fatal("missing target accepted")
	}
}
