package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/agentpolicy"
	"github.com/lantern-networks/dsse-core/appcatalog"
	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/dlp"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/policy"
	"github.com/lantern-networks/dsse-core/policyrule"
)

func TestDLPAllowlistBundleScopeCompatibilityAndRejectedApply(t *testing.T) {
	cp, edge := dlpStoresForTest("authority"), dlpStoresForTest("receiver")
	gen := cp.Generation()
	cp.allowlist.SetValuesDurable("own", []string{"BLUEFIN"})
	cp.allowlist.SetValuesDurable("foreign", []string{"FOREIGN"})
	if cp.Generation() <= gen {
		t.Fatal("allowlist-only edit cannot wake distribution")
	}
	scoped := cp.Snapshot().ForTenant("own")
	if len(scoped.Allowlists) != 1 || !reflect.DeepEqual(scoped.Allowlists["own"], []string{"BLUEFIN"}) {
		t.Fatal("tenant scope differs")
	}
	scoped.Allowlists["own"][0] = "MUTATED"
	if cp.allowlist.ValuesForTenant("own")[0] != "BLUEFIN" {
		t.Fatal("snapshot aliases source")
	}
	p := &checkedClassifierPersister{}
	edge.allowlist.SetPersister(p)
	if err := edge.Apply(cp.Snapshot()); err != nil {
		t.Fatal(err)
	}
	before, gen, disk := edge.Snapshot(), edge.Generation(), string(p.data)
	invalid := cp.Snapshot()
	invalid.Allowlists["own"] = []string{"valid", " "}
	if edge.Apply(invalid) == nil || !reflect.DeepEqual(edge.Snapshot(), before) || edge.Generation() != gen || string(p.data) != disk {
		t.Fatal("invalid allowlist partially published")
	}
	cp.classifiers.SetSpecs("own", classifierFixtureSpecs("NEW"))
	cp.allowlist.SetValuesDurable("own", []string{"REDCEDAR"})
	p.err = errors.New("unavailable")
	if edge.Apply(cp.Snapshot()) == nil || !reflect.DeepEqual(edge.Snapshot(), before) || edge.Generation() != gen || string(p.data) != disk {
		t.Fatal("save failure partially published detector library")
	}
	p.err = nil
	if err := edge.Apply(cp.Snapshot()); err != nil {
		t.Fatal(err)
	}
	if !edge.allowlist.AllowlistForTenant("own").Allowed("project_code", []byte("REDCEDAR")) {
		t.Fatal("receiver salt changed literal suppression")
	}
	reloaded := newDLPAllowlistRuntimeStore("receiver")
	if err := reloaded.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(reloaded.ValuesForTenant("own"), []string{"REDCEDAR"}) {
		t.Fatal("received allowlist did not survive restart")
	}
	legacy := cp.Snapshot()
	legacy.Allowlists = nil
	if err := edge.Apply(legacy); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(edge.allowlist.ValuesForTenant("own"), []string{"REDCEDAR"}) || legacy.ForTenant("own").Allowlists != nil {
		t.Fatal("legacy publisher erased known exceptions")
	}
	cp.allowlist.SetValuesDurable("own", nil)
	cp.allowlist.SetValuesDurable("foreign", nil)
	raw, err := json.Marshal(cp.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"allowlists":{}`) {
		t.Fatal("empty section omitted")
	}
	var empty dlpConfigBundle
	if err := json.Unmarshal(raw, &empty); err != nil {
		t.Fatal(err)
	}
	if err := edge.Apply(&empty); err != nil {
		t.Fatal(err)
	}
	if len(edge.allowlist.Tenants()) != 0 {
		t.Fatal("explicit empty bundle did not clear exceptions")
	}
}

func TestDLPAllowlistSyncRetriesSameGenerationAfterSaveFailure(t *testing.T) {
	cp, edge := dlpStoresForTest("authority"), dlpStoresForTest("receiver")
	p := &riskAuditPersister{base: blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "allowlist.json")}}
	edge.allowlist.SetPersister(p)
	edge.allowlist.SetValuesDurable("own", []string{"OLD"})
	p.fail.Store(true)
	cp.allowlist.SetValuesDurable("own", []string{"NEW"})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var polls atomic.Int32
	status := &configBundleSyncStatus{}
	checks := make(chan bool, 2)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := polls.Add(1)
		if n == 3 {
			status.mu.RLock()
			failed := !status.haveApplied && status.lastError != ""
			status.mu.RUnlock()
			checks <- failed && reflect.DeepEqual(edge.allowlist.ValuesForTenant("own"), []string{"OLD"})
			p.fail.Store(false)
		}
		if n == 4 {
			status.mu.RLock()
			ok := status.haveApplied && status.lastAppliedGeneration == 31
			status.mu.RUnlock()
			checks <- ok && reflect.DeepEqual(edge.allowlist.ValuesForTenant("own"), []string{"NEW"})
			cancel()
		}
		json.NewEncoder(w).Encode(configBundlePayload{Generation: 31, Epoch: "allowlist-retry", DLP: cp.Snapshot()})
	}))
	defer srv.Close()
	src := configBundleSource{tenantID: "own", url: srv.URL, client: srv.Client(), interval: 10 * time.Millisecond, status: status}
	src.run(ctx, configApplyTargets{policyStore: policy.NewStore(nil), dlp: edge})
	if len(checks) != 2 || !<-checks || !<-checks {
		t.Fatal("same generation was not retried")
	}
	reload := newDLPAllowlistRuntimeStore("receiver")
	if err := reload.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(reload.ValuesForTenant("own"), []string{"NEW"}) {
		t.Fatal("retry did not persist")
	}
}

// Exercise the production server wiring, authenticated signed publication and
// verified fetch; explicit exceptions must reach the real upload guard.
func TestConfigBundleSignedAllowlistEditAndClear(t *testing.T) {
	previous := operatorTenantConfigured()
	t.Cleanup(func() { operatorTenantAuthority.Store(previous) })
	auth := newAdminAuthStore()
	for _, tenant := range []string{"operator", "customer"} {
		auth.UpsertPrincipal(adminPrincipal{ID: tenant, TenantID: tenant, Roles: []string{"admin"}, Status: "active"})
		auth.UpsertAPIToken(adminAPIToken{ID: tenant, TenantID: tenant, TokenHash: adminTokenHash("token-" + tenant), Roles: []string{"admin"}, Scopes: []string{"*"}, CreatedByAdminPrincipalID: tenant, Status: "active", ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339)})
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "allowlist.json")
	policyPath := filepath.Join(dir, "policy.json")
	allow := newDLPAllowlistRuntimeStore("authority")
	allow.SetPersister(blobstore.FilePersister{Path: path})
	allow.SetValuesDurable("foreign", []string{"foreign@example.invalid"})
	policies := newDLPPolicyObjectStore()
	policies.SetPersister(blobstore.FilePersister{Path: policyPath})
	policies.Upsert(model.DLPPolicyObject{ID: "protect", TenantID: "customer", Name: "Protect", Identifiers: []string{"credit_card"}, OnMatch: "block", Status: "active"})
	if err := policies.PersistIfDirty(); err != nil {
		t.Fatal(err)
	}
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	signer, err := agentpolicy.LoadOrGenerateSigner("", true)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: writer, AdminAuth: auth, OperatorTenantID: "operator", DLPPolicyObjectStorePath: policyPath, DLPAllowlistStorePath: path, AgentPolicySigner: signer}))
	defer server.Close()
	src := configBundleSource{url: server.URL, client: server.Client(), token: "token-operator", tenantID: "operator", verifyPubKeyHex: signer.PublicKeyHex(), requireSigned: true}
	before, err := src.fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	edge := dlpStoresForTest("different-receiver-salt")
	cfg, _ := newDLPTestConfig(t)
	cfg.DLPPolicies = edge.policies
	cfg.DLPAllowlist = edge.allowlist
	for _, values := range [][]string{{"4111111111111111"}, {}} {
		body, _ := json.Marshal(map[string]any{"values": values})
		req, _ := http.NewRequest("POST", server.URL+"/admin/dlp-allowlist", strings.NewReader(string(body)))
		req.Header.Set("Authorization", "Bearer token-customer")
		response, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := io.ReadAll(response.Body)
		response.Body.Close()
		if response.StatusCode != 200 {
			t.Fatalf("edit %d: %s", response.StatusCode, raw)
		}
		bundle, err := src.fetch(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if bundle.DLP == nil || bundle.Generation <= before.Generation || len(bundle.DLP.Allowlists["foreign"]) != 1 {
			t.Fatal("allowlist edit missing from fleet generation or payload")
		}
		customer := src
		customer.token = "token-customer"
		customer.tenantID = "customer"
		scoped, err := customer.fetch(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := scoped.DLP.Allowlists["foreign"]; ok {
			t.Fatal("customer received foreign exception")
		}
		if _, err := src.apply(bundle, configApplyTargets{rules: policyrule.NewStore(), applications: appcatalog.NewStore(), policyStore: policy.NewStore(nil), dlp: edge}); err != nil {
			t.Fatal(err)
		}
		for _, card := range []string{"4111111111111111", "4242424242424242"} {
			req := httptest.NewRequest("POST", "https://example.invalid/upload", strings.NewReader(card))
			req.Header.Set("Content-Type", "text/plain")
			installEdgeSWGHTTPEgressDLP(req, cfg, model.AccessDecision{TenantID: "customer", Actions: []model.DecisionAction{{Type: "dlp_inspect", Metadata: map[string]any{"dlp_policy_id": "protect"}}}})
			_, err := io.ReadAll(req.Body)
			wantBlocked := len(values) == 0 || card == "4242424242424242"
			if wantBlocked && !errors.Is(err, dlp.ErrBlocked) || !wantBlocked && err != nil {
				t.Fatalf("unexpected upload guard: blocked=%t err=%v", wantBlocked, err)
			}
		}
		before = bundle
	}
}
