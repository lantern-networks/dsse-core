package main

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/appcatalog"
	"github.com/lantern-networks/dsse-core/assetcatalog"
	"github.com/lantern-networks/dsse-core/blobstore"
)

func TestApplicationOrdinaryEditUpdatesDestinationAlias(t *testing.T) {
	ctx := context.Background()
	tenant := "tenant_lab_001"
	now := time.Now()
	apps := appcatalog.NewStore()
	assets := assetcatalog.NewStore()
	before, err := apps.Upsert(ctx, appcatalog.Entry{ApplicationID: "wiki", Name: "Original Wiki", ApplicationType: "private_app", Published: true, Destination: "wiki.example.invalid", DestinationPort: 443, PublishProtocol: "web", Tags: []string{"keep"}}, tenant, now)
	if err != nil {
		t.Fatal(err)
	}
	endpoint := assetcatalog.Endpoint{TenantID: tenant, Alias: before.Name, Kind: assetcatalog.KindNetwork, Address: before.Destination, Tags: []string{"keep-endpoint"}}
	original, err := assets.UpsertApplicationEndpointContext(ctx, "wiki", endpoint, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := assets.UpsertGroup(assetcatalog.Group{ID: "apps", TenantID: tenant, Alias: "Applications", StaticMembers: []string{original.ID}}); err != nil {
		t.Fatal(err)
	}
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), ApplicationCatalogStore: apps, AssetStore: assets})
	before.Name = "Updated Wiki"
	raw, _ := json.Marshal(before)
	r := httptest.NewRequest("POST", "/admin/applications", strings.NewReader(string(raw)))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("status=%d %s", w.Code, w.Body)
	}
	got, found := assets.GetEndpoint(tenant, original.ID)
	original.Alias = before.Name
	if !found || !reflect.DeepEqual(got, original) {
		t.Fatalf("destination did not follow ordinary edit: %+v", got)
	}
	groups := assets.ListGroups(tenant)
	if len(groups) != 1 || !reflect.DeepEqual(groups[0].StaticMembers, []string{original.ID}) {
		t.Fatal("group reference changed")
	}
}

func TestApplicationOrdinaryEditAliasSaveFailureReportsPartial(t *testing.T) {
	ctx := context.Background()
	tenant := "tenant_lab_001"
	now := time.Now()
	apps := appcatalog.NewStore()
	assets := assetcatalog.NewStore()
	persister := &riskAuditPersister{base: blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "assets.json")}}
	if err := assets.SetPersister(persister); err != nil {
		t.Fatal(err)
	}
	app, err := apps.Upsert(ctx, appcatalog.Entry{ApplicationID: "wiki", Name: "Original Wiki", ApplicationType: "private_app", Published: true, Destination: "wiki.example.invalid", DestinationPort: 443, PublishProtocol: "web"}, tenant, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := assets.UpsertApplicationEndpointContext(ctx, "wiki", assetcatalog.Endpoint{TenantID: tenant, Alias: app.Name, Kind: assetcatalog.KindNetwork, Address: app.Destination}, false); err != nil {
		t.Fatal(err)
	}

	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), ApplicationCatalogStore: apps, AssetStore: assets})
	app.Name = "Updated Wiki"
	persister.fail.Store(true)
	raw, _ := json.Marshal(app)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "/admin/applications", strings.NewReader(string(raw))))
	if w.Code != 500 || !strings.Contains(w.Body.String(), `"partial":true`) {
		t.Fatalf("asset save failure was misreported: %d %s", w.Code, w.Body)
	}
	stored, _, err := apps.Get(ctx, tenant, "wiki")
	if err != nil || stored.Name != app.Name {
		t.Fatal("primary save missing")
	}
	ep, _ := assets.GetEndpoint(tenant, "app-wiki")
	if ep.Alias != "Original Wiki" {
		t.Fatal("failed alias changed")
	}
	persister.fail.Store(false)
	raw, _ = json.Marshal(app)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "/admin/applications", strings.NewReader(string(raw))))
	ep, _ = assets.GetEndpoint(tenant, "app-wiki")
	if w.Code != 200 || ep.Alias != app.Name {
		t.Fatalf("retry failed: %d %s", w.Code, w.Body)
	}
}
