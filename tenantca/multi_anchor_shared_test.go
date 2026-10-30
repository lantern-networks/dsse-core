package tenantca

import (
	"encoding/json"
	"testing"
)

func TestSharedRegistryAdoptsAndRetainsEveryAnchorInOnePEM(t *testing.T) {
	first, firstPEM := selfSignedCAForTest(t, "first device authority")
	second, secondPEM := selfSignedCAForTest(t, "second device authority")
	shared, err := json.Marshal(TenantCARegistryFile{Tenants: []TenantCAEntry{{
		TenantID: "tenant-a", CAPEM: string(append(firstPEM, secondPEM...)),
	}}})
	if err != nil {
		t.Fatal(err)
	}

	reg := NewTenantCARegistry()
	if _, err := reg.Register("tenant-a", firstPEM); err != nil {
		t.Fatal(err)
	}
	added, err := reg.Adopt(shared)
	if err != nil || added != 1 || resolves(reg, second) != "tenant-a" {
		t.Fatalf("partial multi-anchor adoption: added=%d err=%v", added, err)
	}
	added, removed, err := reg.Reconcile(shared)
	if err != nil || added != 0 || removed != 0 || resolves(reg, first) != "tenant-a" || resolves(reg, second) != "tenant-a" {
		t.Fatalf("multi-anchor reconcile discarded an authority: added=%d removed=%d err=%v", added, removed, err)
	}

	fresh := NewTenantCARegistry()
	p := &memPersister{data: shared}
	added, err = fresh.LoadFrom(p)
	if err != nil || added != 2 || resolves(fresh, first) != "tenant-a" || resolves(fresh, second) != "tenant-a" {
		t.Fatalf("cold multi-anchor load missed an authority: added=%d err=%v", added, err)
	}
}
