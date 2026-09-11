package policyrule

import (
	"fmt"
	"strings"
	"testing"
)

// failingPersister loads fine but fails every Save — the "disk went away after boot" case behind review #17.
type failingPersister struct{ saves int }

func (p *failingPersister) Load() ([]byte, error) { return nil, nil }
func (p *failingPersister) Save([]byte) error     { p.saves++; return fmt.Errorf("disk full") }

// Review #17: a Save failure must reach the mutating caller. The old persistLocked swallowed it, so an
// authored deny rule was acknowledged while nothing hit disk — and silently vanished on the next restart.
func TestUpsertAndDeleteSurfacePersistFailure(t *testing.T) {
	s := NewStore()
	p := &failingPersister{}
	if err := s.SetPersister(p); err != nil {
		t.Fatalf("SetPersister: %v", err)
	}

	r, err := s.Upsert(ewRule())
	if err == nil || !strings.Contains(err.Error(), "not persisted") {
		t.Fatalf("Upsert must surface the persist failure, got err=%v", err)
	}
	// The rule IS live in memory (hot-applied) despite the persist failure.
	if _, ok := s.Get(r.TenantID, r.ID); !ok {
		t.Fatal("rule should still be live in memory after a persist failure")
	}

	ok, err := s.Delete(r.TenantID, r.ID)
	if !ok || err == nil || !strings.Contains(err.Error(), "not persisted") {
		t.Fatalf("Delete must surface the persist failure, got ok=%v err=%v", ok, err)
	}
	if _, present := s.Get(r.TenantID, r.ID); present {
		t.Fatal("rule should be deleted in memory despite the persist failure")
	}
	if p.saves != 2 {
		t.Fatalf("expected 2 attempted saves, got %d", p.saves)
	}
}
