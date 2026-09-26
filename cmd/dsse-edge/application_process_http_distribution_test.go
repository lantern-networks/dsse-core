package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/agentpolicy"
	"github.com/lantern-networks/dsse-core/appcatalog"
	"github.com/lantern-networks/dsse-core/assetcatalog"
	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/policy"
	"github.com/lantern-networks/dsse-core/policyrule"
	_ "github.com/lib/pq"
)

const processDistributionTenant = "tenant_lab_001"
const processDistributionToken = "synthetic-process-distribution-token"

func processDistributionAuth() *adminAuthStore {
	auth := newAdminAuthStore()
	auth.UpsertPrincipal(adminPrincipal{ID: "operator", TenantID: processDistributionTenant, Roles: []string{"admin"}, Status: "active"})
	auth.UpsertAPIToken(adminAPIToken{ID: "operator", TenantID: processDistributionTenant, TokenHash: adminTokenHash(processDistributionToken),
		Roles: []string{"admin"}, Scopes: []string{"admin.policy.read", "admin.policy.write", "admin.applications.read", "admin.applications.write", "admin.endpoints.read", "admin.endpoints.write", "admin.eastwest.read", "admin.eastwest.write", "admin.swg.read", "admin.swg.write"},
		CreatedByAdminPrincipalID: "operator", Status: "active", ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)})
	return auth
}

func processDistributionAssets(t *testing.T, path string) *assetcatalog.Store {
	t.Helper()
	store := assetcatalog.NewStore()
	if err := store.SetStatePath(path); err != nil {
		t.Fatal(err)
	}
	return store
}

func processDistributionApps(t *testing.T, path string) *appcatalog.Store {
	t.Helper()
	store := appcatalog.NewStore()
	if err := store.SetStatePath(path); err != nil {
		t.Fatal(err)
	}
	return store
}

type processDistributionReady struct {
	URL       string `json:"url"`
	PublicKey string `json:"public_key"`
}

// The child is an actual product CP process. The parent is the Edge process;
// neither catalog nor signer is shared in memory between them.
func TestApplicationDistributionCPChild(t *testing.T) {
	dir := os.Getenv("DSSE_DISTRIBUTION_CP_CHILD")
	if dir == "" {
		t.Skip("helper process")
	}
	signer, err := agentpolicy.LoadOrGenerateSigner("", true)
	if err != nil {
		t.Fatal(err)
	}
	writer, err := logs.NewWriter(filepath.Join(dir, "logs"))
	if err != nil {
		t.Fatal(err)
	}
	outbox := &recordingAdminAuditOutboxDeadReader{}
	cpAssets := processDistributionAssets(t, filepath.Join(dir, "cp-assets.json"))
	cpRules := policyrule.NewStore()
	if err := cpRules.SetStatePath(filepath.Join(dir, "cp-rules.json")); err != nil {
		t.Fatal(err)
	}
	if key := os.Getenv("DSSE_DISTRIBUTION_CP_POSTGRES_KEY"); key != "" {
		db, err := sql.Open("postgres", os.Getenv("DSSE_TEST_POSTGRES_DSN"))
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		cpAssets = assetcatalog.NewStore()
		if err := cpAssets.SetPersister(postgresBlobPersister{db: db, key: key}); err != nil {
			t.Fatal(err)
		}
	}
	cpPolicy := policy.NewStore(nil)
	if err := cpPolicy.SetRuntimeStatePath(filepath.Join(dir, "cp-policy.json")); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("DSSE_DISTRIBUTION_CP_MODE") == "saas" {
		raw, err := os.ReadFile(filepath.Join("..", "..", "swghttprewrite", "testdata", "swg_saas_tenant_enforcement_preflight.json"))
		if err != nil {
			t.Fatal(err)
		}
		var fixture struct{ Policies []model.Policy }
		if err := json.Unmarshal(raw, &fixture); err != nil {
			t.Fatal(err)
		}
		pol := fixture.Policies[0]
		pol.TenantID = processDistributionTenant
		pol.Conditions = map[string]any{"service_family": "https"}
		cpPolicy.ReplaceTenant(processDistributionTenant, []model.Policy{pol}, time.Now())
	}
	cp := httptest.NewServer(newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Registry: connector.NewRegistry(),
		OperatorTenantID: processDistributionTenant, AdminAuth: processDistributionAuth(),
		ApplicationCatalogStore: processDistributionApps(t, filepath.Join(dir, "cp-apps.json")),
		AssetStore:              cpAssets,
		RuleStore:               cpRules,
		PolicyStore:             cpPolicy,
		AgentPolicySigner:       signer, Writer: writer, AdminAuditOutbox: outbox}))
	defer cp.Close()
	raw, err := json.Marshal(processDistributionReady{URL: cp.URL, PublicKey: signer.PublicKeyHex()})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ready.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(25 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(dir, "stop")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Edge did not finish before the deadline")
		}
		time.Sleep(10 * time.Millisecond)
	}
	outbox.mu.Lock()
	defer outbox.mu.Unlock()
	want := []string{"admin_application_published", "admin_application_unpublished"}
	if os.Getenv("DSSE_DISTRIBUTION_CP_MODE") == "assets" {
		want = []string{
			"admin_asset_catalog_changed",                                                               // endpoint create
			"admin_asset_catalog_changed", "admin_asset_catalog_changed", "admin_asset_catalog_changed", // group create/edit/delete
			"admin_asset_catalog_changed", "admin_asset_catalog_changed", "admin_asset_catalog_changed", // service create/edit/delete
			"admin_asset_catalog_changed", "admin_asset_catalog_changed", // endpoint edit/delete
		}
	}
	if os.Getenv("DSSE_DISTRIBUTION_CP_MODE") == "eastwest" {
		want = []string{"admin_config_change", "admin_config_change", "admin_config_change", "admin_config_change", "admin_config_change", "admin_config_change"}
	}
	if os.Getenv("DSSE_DISTRIBUTION_CP_MODE") == "saas" {
		if len(outbox.wrapperAudits) != 16 {
			t.Fatalf("SaaS audit count=%d", len(outbox.wrapperAudits))
		}
		for _, a := range outbox.wrapperAudits {
			if a.TenantID != processDistributionTenant || a.ActorUserID == nil || *a.ActorUserID != "operator" || a.TargetID == nil || *a.TargetID != "/admin/swg/tenant-restriction" || a.Result == nil || *a.Result != "success" {
				t.Fatalf("SaaS audit mismatch: %+v", a)
			}
		}
		return
	}
	audits := outbox.insertedAudits
	if os.Getenv("DSSE_DISTRIBUTION_CP_MODE") == "eastwest" {
		audits = outbox.wrapperAudits
	}
	if len(audits) != len(want) {
		t.Fatalf("CP audit count=%d, want %d", len(audits), len(want))
	}
	for i, event := range want {
		if audit := audits[i]; audit.EventType != event || audit.TargetID == nil ||
			(os.Getenv("DSSE_DISTRIBUTION_CP_MODE") == "" && *audit.TargetID != "wiki") {
			t.Fatalf("CP audit %d = %+v, want %s", i, audit, event)
		}
	}
	if os.Getenv("DSSE_DISTRIBUTION_CP_MODE") == "eastwest" {
		for i, audit := range audits {
			if audit.TenantID != processDistributionTenant || audit.ActorUserID == nil || *audit.ActorUserID != "operator" ||
				audit.TargetType == nil || *audit.TargetType != "admin_api" || *audit.TargetID != "/admin/east-west" ||
				audit.Action == nil || *audit.Action != "POST" || audit.Result == nil || *audit.Result != "success" ||
				audit.Metadata["status_code"] != 200 {
				t.Fatalf("CP east-west audit %d = %+v", i, audit)
			}
		}
	}
	if os.Getenv("DSSE_DISTRIBUTION_CP_MODE") == "assets" {
		kinds := []string{"endpoint", "group", "group", "group", "service", "service", "service", "endpoint", "endpoint"}
		actions := []string{"upsert", "upsert", "upsert", "delete", "upsert", "upsert", "delete", "upsert", "delete"}
		for i, audit := range outbox.insertedAudits {
			id := map[string]string{"endpoint": "ep-a", "group": "group-a", "service": "service-a"}[kinds[i]]
			if audit.TenantID != processDistributionTenant || audit.ActorUserID == nil || *audit.ActorUserID != "operator" ||
				audit.TargetType == nil || *audit.TargetType != "asset_"+kinds[i] || *audit.TargetID != id ||
				audit.Action == nil || *audit.Action != actions[i] || audit.Result == nil || *audit.Result != "saved" {
				t.Fatalf("CP asset audit %d = %+v, want %s/%s/%s saved by operator", i, audit, kinds[i], id, actions[i])
			}
		}
	}
}

func TestApplicationDistributionAcrossCPAndEdgeProcesses(t *testing.T) {
	testApplicationDistributionAcrossCPAndEdgeProcesses(t, false)
}

func TestApplicationDistributionAcrossCPAndEdgeProcessesPostgres(t *testing.T) {
	if os.Getenv("DSSE_TEST_POSTGRES_DSN") == "" {
		t.Skip("set DSSE_TEST_POSTGRES_DSN for the real PostgreSQL distribution check")
	}
	testApplicationDistributionAcrossCPAndEdgeProcesses(t, true)
}

func testApplicationDistributionAcrossCPAndEdgeProcesses(t *testing.T, usePostgres bool) {
	dir := t.TempDir()
	var pgDB *sql.DB
	var pgKey string
	if usePostgres {
		var err error
		pgDB, err = sql.Open("postgres", os.Getenv("DSSE_TEST_POSTGRES_DSN"))
		if err != nil {
			t.Fatal(err)
		}
		defer pgDB.Close()
		if err := pgDB.Ping(); err != nil {
			t.Fatal(err)
		}
		if _, err := pgDB.Exec(`CREATE TABLE IF NOT EXISTS cp_state_blobs (
			store_key text PRIMARY KEY, payload bytea NOT NULL, updated_at timestamptz NOT NULL DEFAULT now())`); err != nil {
			t.Fatal(err)
		}
		pgKey = fmt.Sprintf("test_process_distribution_%d", time.Now().UnixNano())
		defer pgDB.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", pgKey)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestApplicationDistributionCPChild$", "-test.v")
	child.Env = append(os.Environ(), "DSSE_DISTRIBUTION_CP_CHILD="+dir)
	if usePostgres {
		child.Env = append(child.Env, "DSSE_DISTRIBUTION_CP_POSTGRES_KEY="+pgKey)
	}
	var childOutput bytes.Buffer
	child.Stdout, child.Stderr = &childOutput, &childOutput
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if child.ProcessState == nil {
			_ = child.Process.Kill()
			_ = child.Wait()
		}
	}()
	var ready processDistributionReady
	for {
		raw, err := os.ReadFile(filepath.Join(dir, "ready.json"))
		if err == nil && json.Unmarshal(raw, &ready) == nil && ready.URL != "" {
			break
		}
		if ctx.Err() != nil {
			t.Fatal("CP process did not start before the deadline")
		}
		time.Sleep(10 * time.Millisecond)
	}
	edgeAssetPath := filepath.Join(dir, "edge-assets.json")
	edgeAssets := processDistributionAssets(t, edgeAssetPath)
	edgeApps := processDistributionApps(t, filepath.Join(dir, "edge-apps.json"))
	edge := httptest.NewServer(newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Registry: connector.NewRegistry(),
		OperatorTenantID: processDistributionTenant, AdminAuth: processDistributionAuth(),
		ApplicationCatalogStore: edgeApps, AssetStore: edgeAssets, ConfigSourceURL: ready.URL}))
	defer edge.Close()
	request := func(method, base, path, body string) []byte {
		t.Helper()
		req, err := http.NewRequest(method, base+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+processDistributionToken)
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		raw, err := io.ReadAll(resp.Body)
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("%s %s: status=%d read=%v body=%s", method, path, resp.StatusCode, err, raw)
		}
		return raw
	}
	status := &configBundleSyncStatus{source: ready.URL, interval: 20 * time.Millisecond}
	source := configBundleSource{url: ready.URL, client: http.DefaultClient, token: processDistributionToken,
		tenantID: processDistributionTenant, verifyPubKeyHex: ready.PublicKey, requireSigned: true,
		status: status, interval: 20 * time.Millisecond}
	targets := configApplyTargets{applications: edgeApps, assets: edgeAssets, rules: policyrule.NewStore(),
		policyStore: policy.NewStore(nil), dlp: dlpStoresForTest("application-process-http")}
	pollCtx, stopPoll := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { defer close(done); source.run(pollCtx, targets) }()
	defer func() { stopPoll(); <-done }()
	check := func(published bool) {
		t.Helper()
		bundle, err := source.fetch(ctx)
		if err != nil || !bundle.signatureVerified {
			t.Fatalf("CP signed bundle: verified=%v err=%v", bundle.signatureVerified, err)
		}
		deadline := time.Now().Add(4 * time.Second)
		for time.Now().Before(deadline) {
			if snapshot := status.snapshot(); snapshot["have_applied"] == true && snapshot["last_applied_generation"].(uint64) >= bundle.Generation {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if snapshot := status.snapshot(); snapshot["have_applied"] != true || snapshot["last_applied_generation"].(uint64) < bundle.Generation {
			t.Fatalf("Edge did not apply CP generation %d: %+v", bundle.Generation, snapshot)
		}
		var endpoints []assetcatalog.Endpoint
		if err := json.Unmarshal(request(http.MethodGet, edge.URL, "/admin/assets/endpoints", ""), &endpoints); err != nil {
			t.Fatal(err)
		}
		found := false
		for _, endpoint := range endpoints {
			if endpoint.ID == "app-wiki" && endpoint.Address == "wiki.example.test" {
				found = true
			}
		}
		if found != published {
			t.Fatalf("Edge HTTP destination present=%v, want %v", found, published)
		}
		var app appcatalog.Entry
		if err := json.Unmarshal(request(http.MethodGet, edge.URL, "/admin/applications/wiki", ""), &app); err != nil {
			t.Fatal(err)
		}
		if app.Published != published {
			t.Fatalf("Edge HTTP published=%v, want %v", app.Published, published)
		}
		reloadedApp, foundApp, err := processDistributionApps(t, filepath.Join(dir, "edge-apps.json")).Get(ctx, processDistributionTenant, "wiki")
		if err != nil || !foundApp || reloadedApp.Published != published {
			t.Fatalf("Edge saved application: found=%v published=%v err=%v", foundApp, reloadedApp.Published, err)
		}
		_, saved := processDistributionAssets(t, edgeAssetPath).GetEndpoint(processDistributionTenant, "app-wiki")
		if saved != published {
			t.Fatalf("Edge saved destination present=%v, want %v", saved, published)
		}
		if usePostgres {
			cpSaved := assetcatalog.NewStore()
			if err := cpSaved.SetPersister(postgresBlobPersister{db: pgDB, key: pgKey}); err != nil {
				t.Fatal(err)
			}
			_, found := cpSaved.GetEndpoint(processDistributionTenant, "app-wiki")
			if found != published {
				t.Fatalf("CP PostgreSQL destination present=%v, want %v", found, published)
			}
		}
	}
	path := "/admin/applications/wiki"
	request(http.MethodPost, ready.URL, path+"/publish", `{"name":"Wiki","destination":"wiki.example.test","destination_port":443,"publish_protocol":"web"}`)
	check(true)
	request(http.MethodPost, ready.URL, path+"/unpublish", "")
	check(false)
	stopPoll()
	<-done
	if err := os.WriteFile(filepath.Join(dir, "stop"), []byte("done"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := child.Wait(); err != nil {
		t.Fatalf("CP process or audit verification failed: %v; output=%s", err, childOutput.String())
	}
}
