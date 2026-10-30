package vlan

import (
	"path/filepath"
	"testing"

	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/model"
)

func TestTenantErasureDoesNotFoldTenantCase(t *testing.T) {
	s := NewStore()
	p := blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "networks.json")}
	if err := s.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	for _, tenant := range []string{"Acme", "acme"} {
		if _, err := s.UpsertObject(model.VLANObject{ID: tenant, TenantID: tenant, Class: "server", CIDRs: []string{"10.0.0.0/24"}}); err != nil {
			t.Fatal(err)
		}
		if _, err := s.UpsertPolicy(model.VLANBoundaryPolicy{ID: tenant, TenantID: tenant, SourceClass: "server", DestClass: "server", Mode: "deny"}); err != nil {
			t.Fatal(err)
		}
	}
	if objects, policies := s.CountForTenant(" Acme "); objects != 1 || policies != 1 {
		t.Errorf("footprint crossed tenant boundary: %d objects, %d policies", objects, policies)
	}
	if objects, policies, err := s.RemoveTenant(" Acme "); err != nil || objects != 1 || policies != 1 {
		t.Errorf("erasure crossed tenant boundary: %d objects, %d policies, %v", objects, policies, err)
	}
	reloaded := NewStore()
	if err := reloaded.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	if _, ok := reloaded.GetObject("Acme"); ok {
		t.Error("target object survived erasure")
	}
	if _, ok := reloaded.GetObject("acme"); !ok {
		t.Error("another tenant's object was erased")
	}
	if objects, policies := reloaded.CountForTenant("acme"); objects != 1 || policies != 1 {
		t.Error("another tenant's persisted definitions changed")
	}
}
