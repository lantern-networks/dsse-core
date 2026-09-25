package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/appcatalog"
	"github.com/lantern-networks/dsse-core/assetcatalog"
	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/policy"
	"github.com/lantern-networks/dsse-core/policyrule"
)

func TestApplicationOrdinaryRenameKeepsSelectableDestinationInSync(t *testing.T) {
	const tenant = "tenant_lab_001"
	assets := assetcatalog.NewStore()
	path := filepath.Join(t.TempDir(), "assets.json")
	if err := assets.SetPersister(blobstore.FilePersister{Path: path}); err != nil {
		t.Fatal(err)
	}
	writer, err := logs.NewWriter(filepath.Join(t.TempDir(), "audit"))
	if err != nil {
		t.Fatal(err)
	}
	outbox := &recordingAdminAuditOutboxDeadReader{}
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Registry: connector.NewRegistry(),
		AdminAuth: newAdminAuthStore(), AssetStore: assets, Writer: writer, AdminAuditOutbox: outbox})
	call := func(method, path, body string, want int) []byte {
		t.Helper()
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(body)))
		if rec.Code != want {
			t.Fatalf("%s %s status=%d want=%d body=%s", method, path, rec.Code, want, rec.Body.String())
		}
		return rec.Body.Bytes()
	}
	call(http.MethodPost, "/admin/applications/wiki/publish", `{"name":"Old Wiki","destination":"wiki.example.test","destination_port":443,"publish_protocol":"web"}`, http.StatusOK)
	before, found := assets.GetEndpoint(tenant, "app-wiki")
	if !found || before.Alias != "Old Wiki" {
		t.Fatalf("seed destination = %+v found=%t", before, found)
	}
	var edited appcatalog.Entry
	if err := json.Unmarshal(call(http.MethodGet, "/admin/applications/wiki", "", http.StatusOK), &edited); err != nil {
		t.Fatal(err)
	}
	edited.Name = "New Wiki"
	body, err := json.Marshal(edited)
	if err != nil {
		t.Fatal(err)
	}
	call(http.MethodPost, "/admin/applications", string(body), http.StatusOK)
	if err := json.Unmarshal(call(http.MethodGet, "/admin/applications/wiki", "", http.StatusOK), &edited); err != nil || edited.Name != "New Wiki" {
		t.Fatalf("application edit was not redisplayed: %+v err=%v", edited, err)
	}
	current, found := assets.GetEndpoint(tenant, "app-wiki")
	if !found || current.Alias != "New Wiki" || current.ID != before.ID || current.Address != before.Address || current.Source != before.Source {
		t.Fatalf("rule destination drift after ordinary edit: before=%+v after=%+v found=%t", before, current, found)
	}
	reloaded := assetcatalog.NewStore()
	if err := reloaded.SetPersister(blobstore.FilePersister{Path: path}); err != nil {
		t.Fatal(err)
	}
	if saved, found := reloaded.GetEndpoint(tenant, "app-wiki"); !found || saved.Alias != "New Wiki" || saved.Address != before.Address {
		t.Fatalf("rule destination edit did not survive reload: %+v found=%t", saved, found)
	}
	if len(outbox.insertedAudits) != 2 || outbox.insertedAudits[1].EventType != "admin_application_upserted" ||
		outbox.insertedAudits[1].Result == nil || *outbox.insertedAudits[1].Result != "success" {
		t.Fatalf("ordinary edit success audit missing: %+v", outbox.insertedAudits)
	}
}

func TestApplicationRenameSaveFailureIsPartialAndRetryable(t *testing.T) {
	assets := assetcatalog.NewStore()
	stored := &memoryPersister{}
	gate := &rejectingRoutePersister{Persister: stored}
	if err := assets.SetPersister(gate); err != nil {
		t.Fatal(err)
	}
	writer, err := logs.NewWriter(filepath.Join(t.TempDir(), "audit"))
	if err != nil {
		t.Fatal(err)
	}
	outbox := &recordingAdminAuditOutboxDeadReader{}
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Registry: connector.NewRegistry(),
		AdminAuth: newAdminAuthStore(), AssetStore: assets, AdminAuditOutbox: outbox, Writer: writer})
	call := func(method, path, body string, want int) []byte {
		t.Helper()
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(body)))
		if rec.Code != want {
			t.Fatalf("%s %s status=%d want=%d body=%s", method, path, rec.Code, want, rec.Body.String())
		}
		return rec.Body.Bytes()
	}
	call(http.MethodPost, "/admin/applications/wiki/publish", `{"name":"Old Wiki","destination":"wiki.example.test","destination_port":443,"publish_protocol":"web"}`, http.StatusOK)
	var edited appcatalog.Entry
	if err := json.Unmarshal(call(http.MethodGet, "/admin/applications/wiki", "", http.StatusOK), &edited); err != nil {
		t.Fatal(err)
	}
	edited.Name = "New Wiki"
	body, err := json.Marshal(edited)
	if err != nil {
		t.Fatal(err)
	}
	before := len(outbox.insertedAudits)
	gate.fail = true
	response := call(http.MethodPost, "/admin/applications", string(body), http.StatusInternalServerError)
	var failed map[string]any
	if err := json.Unmarshal(response, &failed); err != nil || failed["partial"] != true {
		t.Fatalf("edit rejection must report partial result: %s", response)
	}
	if current, _ := assets.GetEndpoint("tenant_lab_001", "app-wiki"); current.Alias != "Old Wiki" {
		t.Fatalf("failed destination save changed live alias: %+v", current)
	}
	if len(outbox.insertedAudits) != before+1 || outbox.insertedAudits[before].Result == nil || *outbox.insertedAudits[before].Result != "partial" {
		t.Fatal("partial edit audit missing")
	}
	gate.fail = false
	call(http.MethodPost, "/admin/applications", string(body), http.StatusOK)
	if current, _ := assets.GetEndpoint("tenant_lab_001", "app-wiki"); current.Alias != "New Wiki" {
		t.Fatalf("retry did not converge destination alias: %+v", current)
	}
	reloaded := assetcatalog.NewStore()
	if err := reloaded.SetPersister(stored); err != nil {
		t.Fatal(err)
	}
	if saved, _ := reloaded.GetEndpoint("tenant_lab_001", "app-wiki"); saved.Alias != "New Wiki" {
		t.Fatalf("retry did not persist alias: %+v", saved)
	}
}

func TestApplicationRenameRejectsUnownedDestinationBeforeAppSave(t *testing.T) {
	const tenant = "tenant_lab_001"
	assets := assetcatalog.NewStore()
	if _, err := assets.UpsertEndpoint(assetcatalog.Endpoint{ID: "app-wiki", TenantID: tenant,
		Alias: "Operator Destination", Kind: assetcatalog.KindNetwork, Address: "operator.example.test", Source: assetcatalog.SourceManual}); err != nil {
		t.Fatal(err)
	}
	apps := appcatalog.NewStore()
	if _, err := apps.Upsert(context.Background(), appcatalog.Entry{ApplicationID: "wiki", TenantID: tenant,
		Name: "Old Wiki", ApplicationType: "private_app", Published: true, Status: "active",
		Destination: "wiki.example.test", DestinationPort: 443, PublishProtocol: "web"}, tenant, time.Now()); err != nil {
		t.Fatal(err)
	}
	auth := newAdminAuthStore()
	now := time.Now().UTC()
	auth.UpsertPrincipal(adminPrincipal{ID: "app-only", TenantID: tenant, Roles: []string{"admin"}, Status: "active"})
	auth.UpsertAPIToken(adminAPIToken{ID: "app-only-token", TenantID: tenant, TokenHash: adminTokenHash("app-only-fixture"),
		Roles: []string{"admin"}, Scopes: []string{"admin.applications.write", "admin.applications.read"},
		CreatedByAdminPrincipalID: "app-only", CreatedAt: now.Add(-time.Hour).Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), Status: "active"})
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Registry: connector.NewRegistry(),
		AdminAuth: auth, AssetStore: assets, ApplicationCatalogStore: apps})
	entry, _, err := apps.Get(context.Background(), tenant, "wiki")
	if err != nil {
		t.Fatal(err)
	}
	entry.Name = "New Wiki"
	body, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/applications", strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer app-only-fixture")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("unowned destination edit status=%d body=%s", rec.Code, rec.Body.String())
	}
	if current, _, _ := apps.Get(context.Background(), tenant, "wiki"); current.Name != "Old Wiki" {
		t.Fatalf("denied edit changed application: %+v", current)
	}
	if current, _ := assets.GetEndpoint(tenant, "app-wiki"); current.Alias != "Operator Destination" {
		t.Fatalf("denied edit changed destination: %+v", current)
	}
}

func TestApplicationRenameUsesLatestSharedDestination(t *testing.T) {
	const tenant = "tenant_lab_001"
	shared := &sharedCPAssetBlob{}
	first, stale := assetcatalog.NewStore(), assetcatalog.NewStore()
	for _, store := range []*assetcatalog.Store{first, stale} {
		if err := store.SetPersister(shared); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := first.UpsertApplicationEndpoint("wiki", assetcatalog.Endpoint{TenantID: tenant,
		Alias: "Old Wiki", Kind: assetcatalog.KindNetwork, Address: "first.example.test"}, false); err != nil {
		t.Fatal(err)
	}
	if _, err := first.UpsertApplicationEndpoint("wiki", assetcatalog.Endpoint{TenantID: tenant,
		Alias: "Old Wiki", Kind: assetcatalog.KindNetwork, Address: "latest.example.test", Tags: []string{"reviewed"}}, false); err != nil {
		t.Fatal(err)
	}
	if err := stale.RenameApplicationEndpoint(tenant, "wiki", "New Wiki", false); err != nil {
		t.Fatal(err)
	}
	fresh := assetcatalog.NewStore()
	if err := fresh.SetPersister(shared); err != nil {
		t.Fatal(err)
	}
	got, found := fresh.GetEndpoint(tenant, "app-wiki")
	if !found || got.Alias != "New Wiki" || got.Address != "latest.example.test" || len(got.Tags) != 1 || got.Tags[0] != "reviewed" {
		t.Fatalf("shared alias edit overwrote peer's destination: %+v found=%t", got, found)
	}
}

func TestApplicationOrdinaryRenameReachesPeerBundleAndEdge(t *testing.T) {
	const tenant = "tenant_lab_001"
	shared := &sharedCPAssetBlob{}
	first, peer := assetcatalog.NewStore(), assetcatalog.NewStore()
	for _, store := range []*assetcatalog.Store{first, peer} {
		if err := store.SetPersister(shared); err != nil {
			t.Fatal(err)
		}
	}
	apps := appcatalog.NewStore()
	admin := newAdminAuthStore()
	owner := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Registry: connector.NewRegistry(),
		AdminAuth: admin, OperatorTenantID: tenant, AssetStore: first, ApplicationCatalogStore: apps})
	seed := doAdmin(t, owner, http.MethodPost, "/admin/applications/wiki/publish",
		`{"name":"Old Wiki","destination":"wiki.example.test","destination_port":443,"publish_protocol":"web"}`)
	if seed.Code != http.StatusOK {
		t.Fatalf("publish status=%d body=%s", seed.Code, seed.Body.String())
	}
	baseline := first.ConfigGeneration()
	entry, _, err := apps.Get(context.Background(), tenant, "wiki")
	if err != nil {
		t.Fatal(err)
	}
	entry.Name = "New Wiki"
	body, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	edit := doAdmin(t, owner, http.MethodPost, "/admin/applications", string(body))
	if edit.Code != http.StatusOK || first.ConfigGeneration() <= baseline {
		t.Fatalf("edit did not advance asset generation: status=%d before=%d after=%d body=%s",
			edit.Code, baseline, first.ConfigGeneration(), edit.Body.String())
	}
	if stale, _ := peer.GetEndpoint(tenant, "app-wiki"); stale.Alias == "New Wiki" {
		t.Fatal("test requires a peer CP that has not refreshed the edit")
	}
	peerServer := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Registry: connector.NewRegistry(),
		AdminAuth: admin, OperatorTenantID: tenant, AssetStore: peer, ApplicationCatalogStore: apps,
		RuleStore: policyrule.NewStore()})
	read := doAdmin(t, peerServer, http.MethodGet, "/admin/config-bundle", "")
	var bundle configBundlePayload
	if read.Code != http.StatusOK || json.Unmarshal(read.Body.Bytes(), &bundle) != nil || bundle.Rules == nil {
		t.Fatalf("peer bundle status=%d body=%s", read.Code, read.Body.String())
	}
	if got, found := peer.GetEndpoint(tenant, "app-wiki"); !found || got.Alias != "New Wiki" {
		t.Fatalf("peer CP did not refresh rename: %+v found=%t", got, found)
	}
	edgeAssets := assetcatalog.NewStore()
	source := configBundleSource{tenantID: tenant}
	_, err = source.apply(bundle, configApplyTargets{policyStore: policy.NewStore(nil),
		rules: policyrule.NewStore(), assets: edgeAssets, applications: appcatalog.NewStore(),
		dlp: dlpStoresForTest("application-alias-edit")})
	if err != nil {
		t.Fatal(err)
	}
	if got, found := edgeAssets.GetEndpoint(tenant, "app-wiki"); !found || got.Alias != "New Wiki" ||
		got.Address != "wiki.example.test" || got.ID != "app-wiki" {
		t.Fatalf("Edge did not apply renamed destination: %+v found=%t", got, found)
	}
}
