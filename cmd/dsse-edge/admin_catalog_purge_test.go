package main

import (
	"context"
	"encoding/json"
	"github.com/lantern-networks/dsse-core/assetcatalog"
	"github.com/lantern-networks/dsse-core/connector"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestTenantPurgeIncludesAssetCatalog(t *testing.T) {
	s := assetcatalog.NewStore()
	for _, tenant := range []string{"target", "peer"} {
		if _, err := s.UpsertGroup(assetcatalog.Group{ID: "group", TenantID: tenant, Alias: "group"}); err != nil {
			t.Fatal(err)
		}
	}
	models := newOperatorAwareAdminTenantModelStore(testEvaluator().PolicyBundle, time.Now(), "", "tenant_lab_001")
	auth := newAdminAuthStore()
	auth.UpsertPrincipal(adminPrincipal{ID: "operator", TenantID: "tenant_lab_001", Roles: []string{"owner"}, Status: "active"})
	auth.UpsertAPIToken(adminAPIToken{ID: "token", TenantID: "tenant_lab_001", CreatedByAdminPrincipalID: "operator", Roles: []string{"owner"}, Scopes: []string{"*"}, Status: "active", TokenHash: adminTokenHash("catalog-review"), ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339)})
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Registry: connector.NewRegistry(), AdminAuth: auth, OperatorTenantID: "tenant_lab_001", AssetStore: s, TenantModelStore: models})
	req := httptest.NewRequest("POST", "/admin/tenants/target/purge", strings.NewReader(`{"confirm_tenant_id":"target"}`))
	req.Header.Set("Authorization", "Bearer catalog-review")
	req.Header.Set("Content-Type", "application/json")
	r := httptest.NewRecorder()
	h.ServeHTTP(r, req)
	if r.Code != 200 {
		t.Fatalf("%d %s", r.Code, r.Body)
	}
	var result adminTenantPurgeResult
	if err := json.Unmarshal(r.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if len(s.ListGroups("target")) != 0 {
		t.Fatalf("catalog survived reported complete=%v: %s", result.Complete, r.Body)
	}
	if len(s.ListGroups("peer")) != 1 {
		t.Fatal("peer erased")
	}
	found := false
	for _, row := range result.Remaining.Stores {
		if row.Store == "asset_catalog_records" && row.Count == 0 {
			found = true
		}
	}
	if !found {
		t.Fatal("missing catalogue footprint")
	}
}

func TestPostgresCatalogErasureKeepsPeerAndAcceptedTerm(t *testing.T) {
	d, _, leader, peer := trustDistributionPostgresFixture(t)
	p := d.store.(postgresBlobPersister)
	p.key = "test_catalog_erasure"
	defer p.db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", p.key)
	fresh := func() *assetcatalog.Store {
		s := assetcatalog.NewStore()
		if err := s.SetPersister(p); err != nil {
			t.Fatal(err)
		}
		return s
	}
	stale, writer := fresh(), fresh()
	for _, tenant := range []string{"target", "peer"} {
		if _, err := writer.UpsertGroupContext(captureCPWriteLease(context.Background()), assetcatalog.Group{ID: "group", TenantID: tenant, Alias: "group"}); err != nil {
			t.Fatal(err)
		}
	}
	lease := captureCPWriteLease(context.Background())
	leader.release()
	peer.tick()
	if !peer.IsLeader() {
		t.Fatal("no successor")
	}
	cpLeaderElectorInstance = peer
	if _, err := stale.RemoveTenantContext(lease, "target"); err == nil {
		t.Fatal("old term erased")
	}
	if len(fresh().ListGroups("target")) != 1 {
		t.Fatal("old term changed target")
	}
	n, err := stale.RemoveTenantContext(captureCPWriteLease(context.Background()), "target")
	if err != nil || n != 2 {
		t.Fatal(n, err)
	}
	current := fresh()
	if len(current.ListGroups("target")) != 0 || len(current.ListGroups("peer")) != 1 {
		t.Fatal("target survived or peer lost")
	}
	if _, err := p.db.Exec("UPDATE cp_state_blobs SET payload=$1 WHERE store_key=$2", []byte(`broken`), p.key); err != nil {
		t.Fatal(err)
	}
	if _, err := current.CountTenantRecords("target"); err == nil {
		t.Fatal("broken state counted zero")
	}
}
