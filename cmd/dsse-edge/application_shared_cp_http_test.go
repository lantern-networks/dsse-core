package main

import (
	"encoding/json"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/assetcatalog"
	"github.com/lantern-networks/dsse-core/connector"
)

// Implements the same serialized blob operation as the CP Postgres persister.
type sharedCPAssetBlob struct {
	mu  sync.Mutex
	raw []byte
}

func TestPeerAssetWriteAdvancesFleetReportedGeneration(t *testing.T) {
	const tenant = "tenant_lab_001"
	blob := &sharedCPAssetBlob{}
	first, second := assetcatalog.NewStore(), assetcatalog.NewStore()
	for _, store := range []*assetcatalog.Store{first, second} {
		if err := store.SetPersister(blob); err != nil {
			t.Fatal(err)
		}
	}
	handler := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Registry: connector.NewRegistry(),
		AdminAuth: newAdminAuthStore(), OperatorTenantID: tenant, AssetStore: second,
		FleetConfigStatus: newFleetConfigStatusStore(time.Minute)})
	getGeneration := func() float64 {
		t.Helper()
		read := doAdmin(t, handler, http.MethodGet, "/admin/fleet/config-status", "")
		if read.Code != http.StatusOK {
			t.Fatalf("fleet status=%d body=%s", read.Code, read.Body.String())
		}
		var body map[string]any
		if err := json.Unmarshal(read.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		generation, ok := body["control_plane_generation"].(float64)
		if !ok {
			t.Fatalf("operator generation absent: %+v", body)
		}
		return generation
	}
	before := getGeneration()
	if _, err := first.UpsertApplicationEndpoint("wiki", assetcatalog.Endpoint{
		TenantID: tenant, Alias: "wiki", Kind: assetcatalog.KindNetwork, Address: "wiki.example.test",
	}, false); err != nil {
		t.Fatal(err)
	}
	if _, found := second.GetEndpoint(tenant, "app-wiki"); found {
		t.Fatal("test requires a stale fleet-reporting CP")
	}
	if after := getGeneration(); after <= before {
		t.Fatalf("fleet generation did not advance after peer asset write: before=%v after=%v", before, after)
	}
}

func (b *sharedCPAssetBlob) Load() ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.raw...), nil
}
func (b *sharedCPAssetBlob) Save(raw []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.raw = append([]byte(nil), raw...)
	return nil
}
func (b *sharedCPAssetBlob) Update(edit func([]byte) ([]byte, error)) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	next, err := edit(append([]byte(nil), b.raw...))
	if err != nil {
		return err
	}
	b.raw = append([]byte(nil), next...)
	return nil
}

func TestPeerControlPlaneApplicationDestinationReachesAdminReadAndBundle(t *testing.T) {
	const tenant = "tenant_lab_001"
	blob := &sharedCPAssetBlob{}
	first, second := assetcatalog.NewStore(), assetcatalog.NewStore()
	for _, store := range []*assetcatalog.Store{first, second} {
		if err := store.SetPersister(blob); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := first.UpsertApplicationEndpoint("wiki", assetcatalog.Endpoint{
		TenantID: tenant, Alias: "wiki", Kind: assetcatalog.KindNetwork, Address: "wiki.example.test",
	}, false); err != nil {
		t.Fatal(err)
	}
	if _, found := second.GetEndpoint(tenant, "app-wiki"); found {
		t.Fatal("test requires a stale second CP before its HTTP read")
	}
	handler := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Registry: connector.NewRegistry(),
		AdminAuth: newAdminAuthStore(), OperatorTenantID: tenant, AssetStore: second})
	var endpoints []assetcatalog.Endpoint
	read := doAdmin(t, handler, http.MethodGet, "/admin/assets/endpoints", "")
	if read.Code != http.StatusOK {
		t.Fatalf("admin asset read status=%d body=%s", read.Code, read.Body.String())
	}
	if err := json.Unmarshal(read.Body.Bytes(), &endpoints); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, endpoint := range endpoints {
		if endpoint.ID == "app-wiki" && endpoint.Address == "wiki.example.test" {
			found = true
		}
	}
	if !found {
		t.Fatalf("peer destination absent from admin read: %+v", endpoints)
	}
	bundleRead := doAdmin(t, handler, http.MethodGet, "/admin/config-bundle", "")
	if bundleRead.Code != http.StatusOK {
		t.Fatalf("bundle status=%d body=%s", bundleRead.Code, bundleRead.Body.String())
	}
	var bundle configBundlePayload
	if err := json.Unmarshal(bundleRead.Body.Bytes(), &bundle); err != nil {
		t.Fatal(err)
	}
	found = false
	if bundle.Rules != nil {
		for _, endpoint := range bundle.Rules.Endpoints {
			if endpoint.ID == "app-wiki" && endpoint.Address == "wiki.example.test" {
				found = true
			}
		}
	}
	if !found || bundle.Generation == 0 {
		t.Fatalf("peer destination absent from Edge bundle: generation=%d rules=%+v", bundle.Generation, bundle.Rules)
	}
}
