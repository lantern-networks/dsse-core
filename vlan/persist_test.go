package vlan

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/model"
)

// A persisted store must survive a "restart": objects + policies written through one store instance are present
// in a fresh instance that loads the same file. This is the fix for the Networks catalog going empty on every
// Edge recreate (it was in-memory only).
func TestStorePersistenceSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vlan.json")
	p := blobstore.FilePersister{Path: path}

	s := NewStore()
	if err := s.SetPersister(p); err != nil {
		t.Fatalf("SetPersister: %v", err)
	}
	if _, err := s.UpsertObject(model.VLANObject{ID: "net-tokyo", Class: "server", CIDRs: []string{"10.20.0.0/16"}, Name: "Tokyo servers"}); err != nil {
		t.Fatalf("UpsertObject: %v", err)
	}
	if _, err := s.UpsertPolicy(model.VLANBoundaryPolicy{ID: "pol-1", SourceClass: "managed_endpoint", DestClass: "server", Mode: "deny"}); err != nil {
		t.Fatalf("UpsertPolicy: %v", err)
	}

	// Fresh instance (a "restart") loading the same file.
	s2 := NewStore()
	if err := s2.SetPersister(p); err != nil {
		t.Fatalf("SetPersister reload: %v", err)
	}
	if got, ok := s2.GetObject("net-tokyo"); !ok || got.Name != "Tokyo servers" || len(got.CIDRs) != 1 {
		t.Fatalf("Named Network did not survive the restart: %#v ok=%v", got, ok)
	}
	if len(s2.ListPolicies()) != 1 {
		t.Fatalf("boundary policy did not survive the restart: %#v", s2.ListPolicies())
	}

	// A delete also persists.
	if ok, err := s2.DeleteObject("net-tokyo"); err != nil || !ok {
		t.Fatalf("DeleteObject returned false")
	}
	s3 := NewStore()
	if err := s3.SetPersister(p); err != nil {
		t.Fatalf("SetPersister reload after delete: %v", err)
	}
	if _, ok := s3.GetObject("net-tokyo"); ok {
		t.Fatalf("deleted Named Network reappeared after restart")
	}
}

// A DELETE must persist too: a network the operator removed must not rise from the dead on the next restart.
// A stale route reappearing is worse than one that never saved — it routes traffic nobody authorised.
func TestStorePersistenceDeleteSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vlan.json")
	p := blobstore.FilePersister{Path: path}

	first := NewStore()
	if err := first.SetPersister(p); err != nil {
		t.Fatalf("SetPersister: %v", err)
	}
	first.UpsertObject(model.VLANObject{ID: "vlan_a", TenantID: "t1", Name: "A", Class: "server", CIDRs: []string{"10.1.0.0/16"}})
	first.UpsertObject(model.VLANObject{ID: "vlan_b", TenantID: "t1", Name: "B", Class: "server", CIDRs: []string{"10.2.0.0/16"}})
	if ok, err := first.DeleteObject("vlan_a"); err != nil || !ok {
		t.Fatal("delete reported missing")
	}

	second := NewStore()
	if err := second.SetPersister(p); err != nil {
		t.Fatalf("SetPersister (restart): %v", err)
	}
	objects := second.ListObjects()
	if len(objects) != 1 || objects[0].ID != "vlan_b" {
		t.Fatalf("after restart objects = %#v, want only vlan_b — the delete must persist", objects)
	}
}

// A save failure must be REPORTED, never swallowed. If it is dropped, the API still returns 200 and the Console
// still shows the network, so the operator believes it is configured — and it is gone at the next restart. That
// is precisely the "Networks page is empty again" bug, recreated while looking fixed.
type failingPersister struct{ err error }

func (f failingPersister) Load() ([]byte, error) { return nil, nil }
func (f failingPersister) Save([]byte) error     { return f.err }
func (f failingPersister) Append([]byte) error   { return f.err }
func (f failingPersister) Size() (int64, error)  { return 0, nil }

func TestStorePersistErrorIsReportedNotSwallowed(t *testing.T) {
	prev := OnPersistError
	t.Cleanup(func() { OnPersistError = prev })
	var got error
	OnPersistError = func(err error) { got = err }

	s := NewStore()
	if err := s.SetPersister(failingPersister{err: errTestDiskFull}); err != nil {
		t.Fatalf("SetPersister: %v", err)
	}
	if _, err := s.UpsertObject(model.VLANObject{ID: "vlan_x", TenantID: "t1", Name: "X", Class: "server", CIDRs: []string{"10.9.0.0/16"}}); !errors.Is(err, ErrPersistence) {
		t.Fatalf("upsert should refuse unconfirmed storage: %v", err)
	}
	if got == nil {
		t.Fatal("a failed save was swallowed; the operator would believe the network is durable when it is not")
	}
	if len(s.ListObjects()) != 0 {
		t.Fatal("failed save changed live state")
	}
}

var errTestDiskFull = errors.New("disk full")
