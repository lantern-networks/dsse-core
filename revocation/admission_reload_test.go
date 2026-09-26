package revocation

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/lantern-networks/dsse-core/blobstore"
)

func TestAdmissionReloadPreservesLayersAndDoesNotWriteOrNotify(t *testing.T) {
	p := blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "admission.json")}
	a, b := NewAdmissionRevocations(), NewAdmissionRevocations()
	if err := a.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	a.Revoke("retired", "old")
	a.RevokeFromMesh("peer", "keep mesh")
	if err := b.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	b.ReplaceSynced(map[string]string{"pulled": "keep synced"})
	calls := 0
	b.SetOnRevoked(func(string, string) { calls++ })
	b.SetReporter(func(string, string) { calls++ })
	b.SetMeshReporter(func(string, string) { calls++ })
	a.Restore("retired")
	a.Revoke("new", "authored elsewhere")
	before, err := os.ReadFile(p.Path)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.ReloadFromStore(); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"new", "peer", "pulled"} {
		if _, ok := b.IsRevoked(id); !ok {
			t.Fatalf("lost %s", id)
		}
	}
	if _, ok := b.IsRevoked("retired"); ok {
		t.Fatal("retained removed authored entry")
	}
	if calls != 0 {
		t.Fatal("reload notified as a new administrator action")
	}
	after, err := os.ReadFile(p.Path)
	if err != nil || string(before) != string(after) {
		t.Fatal("reload changed storage")
	}
	generation := b.ConfigGeneration()
	if err := b.ReloadFromStore(); err != nil || b.ConfigGeneration() != generation {
		t.Fatal("unchanged reload churned")
	}
	if err := os.Remove(p.Path); err != nil {
		t.Fatal(err)
	}
	if err := b.ReloadFromStore(); err == nil {
		t.Fatal("missing state accepted after prior state")
	}
	if _, ok := b.IsRevoked("new"); !ok {
		t.Fatal("failed reload discarded live state")
	}
}

func TestAdmissionReloadFirstBootAndVolatile(t *testing.T) {
	a := NewAdmissionRevocations()
	if err := a.ReloadFromStore(); err != nil {
		t.Fatal(err)
	}
	if err := a.SetPersister(blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "first.json")}); err != nil {
		t.Fatal(err)
	}
	if err := a.ReloadFromStore(); err != nil {
		t.Fatal(err)
	}
}
