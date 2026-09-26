package main

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/assetcatalog"
	"github.com/lantern-networks/dsse-core/eastwestobserve"
	"github.com/lantern-networks/dsse-core/policy"
	"github.com/lantern-networks/dsse-core/policyrule"
)

func TestPostgresObservationAdoptionRefreshesPeerRules(t *testing.T) {
	db := initialBlobDB(t)
	rp, ap := initialBlob(t, db, "adoption_rules"), initialBlob(t, db, "adoption_assets")
	writerRules, readerRules := policyrule.NewStore(), policyrule.NewStore()
	writerAssets, readerAssets := assetcatalog.NewStore(), assetcatalog.NewStore()
	for _, s := range []*policyrule.Store{writerRules, readerRules} {
		if e := s.SetPersister(rp); e != nil {
			t.Fatal(e)
		}
	}
	for _, s := range []*assetcatalog.Store{writerAssets, readerAssets} {
		if e := s.SetPersister(ap); e != nil {
			t.Fatal(e)
		}
		s.SetBuiltInServices(assetcatalog.BuiltInServices())
	}
	tenant := testEvaluator().PolicyBundle.TenantID
	obs := eastwestobserve.NewStore()
	obs.Observe(tenant, "*", "", "peer.example", "ssh", 22, time.Now())
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), AdminAuth: newAdminAuthStore(), PolicyStore: policy.NewStore(nil), RuleStore: readerRules, AssetStore: readerAssets, EastWestObserveStore: obs})
	ep, e := writerAssets.UpsertEndpoint(assetcatalog.Endpoint{TenantID: tenant, Kind: assetcatalog.KindNetwork, Address: "peer.example", Alias: "peer", Source: assetcatalog.SourceManual})
	if e != nil {
		t.Fatal(e)
	}
	_, e = writerRules.Upsert(policyrule.Rule{TenantID: tenant, Plane: policyrule.PlaneEastWest, Direction: policyrule.DirectionOutbound, Name: "Peer SSH", Source: []string{"*"}, Destination: []string{ep.ID}, ServiceID: "builtin-svc-ssh", Action: policyrule.Action{Access: policyrule.AccessAllow, Inspection: policyrule.InspectionInspect}})
	if e != nil {
		t.Fatal(e)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/admin/east-west/observations", nil))
	var result struct {
		Observations []eastwestobserve.FlowObservation `json:"observations"`
	}
	if e = json.Unmarshal(w.Body.Bytes(), &result); e != nil || w.Code != 200 || len(result.Observations) != 1 || !result.Observations[0].Covered {
		t.Fatalf("peer rule missing: %d %s", w.Code, w.Body)
	}
	if _, e = db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", rp.key); e != nil {
		t.Fatal(e)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/admin/east-west/observations", nil))
	if w.Code != 503 {
		t.Fatalf("missing rules showed stale coverage: %d %s", w.Code, w.Body)
	}
}
