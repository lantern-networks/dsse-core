package delegatedgrant

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/model"
)

type saveGate struct {
	blobstore.FilePersister
	fail bool
}

func (p *saveGate) Save(b []byte) error {
	if p.fail {
		return errors.New("private save rejected")
	}
	return p.FilePersister.Save(b)
}
func sampleGrant(tenant, id string) model.DelegatedAccessGrant {
	return model.DelegatedAccessGrant{ID: id, TenantID: tenant, ActorNHIID: "agent", SubjectUserID: "person", Status: "active", ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}
}
func TestRejectedGrantMutationsDoNotPublishOrEvict(t *testing.T) {
	p := &saveGate{FilePersister: blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "grants.json")}}
	s := NewStore(2)
	if e := s.SetPersister(p); e != nil {
		t.Fatal(e)
	}
	for _, id := range []string{"first", "second"} {
		if _, e := s.Upsert(sampleGrant("tenant", id)); e != nil {
			t.Fatal(e)
		}
	}
	before, _ := p.Load()
	gen := s.ConfigGeneration()
	order := append([]string(nil), s.order...)
	p.fail = true
	for _, id := range []string{"first", "rejected"} {
		g := sampleGrant("tenant", id)
		g.ToolIDs = []string{"unwanted"}
		if _, e := s.Upsert(g); !errors.Is(e, ErrPersistence) {
			t.Fatalf("upsert: %v", e)
		}
	}
	if _, e := s.RevokeForTenant("tenant", "first", "review", time.Now()); !errors.Is(e, ErrPersistence) {
		t.Fatalf("revoke: %v", e)
	}
	after, _ := p.Load()
	g, _ := s.GetForTenant("tenant", "first")
	if string(before) != string(after) || s.ConfigGeneration() != gen || g.Status != "active" || len(g.ToolIDs) != 0 || s.Count() != 2 || !reflect.DeepEqual(s.order, order) {
		t.Fatal("failed write published or evicted prior state")
	}
	p.fail = false
	if _, e := s.RevokeForTenant("tenant", "first", "review", time.Now()); e != nil {
		t.Fatal(e)
	}
	if s.ConfigGeneration() != gen+1 {
		t.Fatal("revoke did not advance distribution generation")
	}
	if _, e := s.RevokeForTenant("tenant", "first", "repeat", time.Now()); e != nil || s.ConfigGeneration() != gen+1 {
		t.Fatal("idempotent revoke changed generation")
	}
	if _, e := s.Upsert(sampleGrant("tenant", "first")); e == nil {
		t.Fatal("revoked grant was reactivated")
	}
	reload := NewStore(2)
	if e := reload.SetStatePath(p.Path); e != nil {
		t.Fatal(e)
	}
	g, _ = reload.GetForTenant("tenant", "first")
	if g.Status != "revoked" || g.RevokedAt == nil || g.RevocationReason == nil || *g.RevocationReason != "review" {
		t.Fatalf("revoke missing after restart: %+v", g)
	}
	if _, ok := reload.GetForTenant("tenant", "rejected"); ok {
		t.Fatal("rejected create leaked into later save")
	}
}
func TestGrantLegacyNamespaceAndScopedRevocation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "grants.json")
	original := sampleGrant("tenant_a", "shared")
	b, _ := json.Marshal(map[string]model.DelegatedAccessGrant{"shared": original})
	if e := os.WriteFile(path, b, 0600); e != nil {
		t.Fatal(e)
	}
	s := NewStore(0)
	if e := s.SetStatePath(path); e != nil {
		t.Fatal(e)
	}
	if _, e := s.Upsert(sampleGrant("tenant_b", "shared")); e != nil {
		t.Fatal(e)
	}
	if _, ok := s.Get("shared"); ok {
		t.Fatal("unscoped lookup resolved ambiguous ID")
	}
	if _, e := s.Revoke("shared", "ambiguous", time.Now()); e == nil {
		t.Fatal("unscoped revoke selected a tenant")
	}
	if _, e := s.RevokeForTenant("tenant_a", "shared", "review", time.Now()); e != nil {
		t.Fatal(e)
	}
	reload := NewStore(0)
	if e := reload.SetStatePath(path); e != nil {
		t.Fatal(e)
	}
	for _, store := range []*Store{s, reload} {
		a, ok := store.GetForTenant("tenant_a", "shared")
		other, ok2 := store.GetForTenant("tenant_b", "shared")
		if !ok || !ok2 || a.Status != "revoked" || other.Status != "active" {
			t.Fatalf("scoped grants: %+v %+v", a, other)
		}
	}
}
func TestGrantNamespaceRejectsInvalidAndDuplicateRecords(t *testing.T) {
	for _, pair := range [][2]string{{"", "id"}, {"tenant", ""}, {"ten\x00ant", "id"}, {"tenant", "i\x00d"}, {" tenant", "id"}} {
		if _, e := NewStore(0).Upsert(sampleGrant(pair[0], pair[1])); e == nil {
			t.Fatalf("accepted key %q", pair)
		}
	}
	path := filepath.Join(t.TempDir(), "grants.json")
	g := sampleGrant("tenant", "same")
	b, _ := json.Marshal(map[string]model.DelegatedAccessGrant{"a": g, "b": g})
	os.WriteFile(path, b, 0600)
	s := NewStore(0)
	s.Upsert(sampleGrant("tenant", "keep"))
	if e := s.SetStatePath(path); e == nil {
		t.Fatal("ambiguous snapshot accepted")
	}
	if _, ok := s.GetForTenant("tenant", "keep"); !ok {
		t.Fatal("failed load replaced memory")
	}
}
func TestRemovedGrantDoesNotCorruptCapacityOrder(t *testing.T) {
	s := NewStore(2)
	s.Upsert(sampleGrant("removed", "first"))
	s.Upsert(sampleGrant("kept", "second"))
	s.RemoveTenant("removed")
	s.Upsert(sampleGrant("kept", "third"))
	s.Upsert(sampleGrant("kept", "fourth"))
	if s.Count() != 2 {
		t.Fatalf("capacity corrupted by stale order: %d", s.Count())
	}
	if _, ok := s.GetForTenant("kept", "second"); ok {
		t.Fatal("oldest surviving record not evicted")
	}
}
