package humanapproval

import (
	"fmt"
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/model"
)

type failingPersister struct{}

func (failingPersister) Load() ([]byte, error) { return nil, nil }
func (failingPersister) Save([]byte) error     { return fmt.Errorf("disk full") }

// Review #17: the most security-relevant persist failure here is a REVOKE that never hits disk — the
// approval silently resurrects on restart. Both Upsert and Revoke must surface the failure (the in-memory
// state stays applied: the running edge already enforces it).
func TestUpsertAndRevokeSurfacePersistFailure(t *testing.T) {
	s := NewStore(0)
	if err := s.SetPersister(failingPersister{}); err != nil {
		t.Fatalf("SetPersister: %v", err)
	}

	_, err := s.Upsert(model.HumanApprovalEvent{ID: "h1", TenantID: "t1", ApprovalResult: "approved"})
	if err == nil || !strings.Contains(err.Error(), "not persisted") {
		t.Fatalf("Upsert must surface the persist failure, got %v", err)
	}
	if _, ok := s.Get("h1"); !ok {
		t.Fatal("event should still be live in memory after a persist failure")
	}

	revoked, ok, err := s.Revoke("h1", "compromised")
	if !ok || err == nil || !strings.Contains(err.Error(), "resurrect") {
		t.Fatalf("Revoke must surface the persist failure, got ok=%v err=%v", ok, err)
	}
	if revoked.ApprovalResult != "revoked" {
		t.Fatal("revoke must still be applied in memory")
	}
	// Idempotent second revoke: already revoked in memory, no new save attempted, no error.
	if _, ok, err := s.Revoke("h1", "again"); !ok || err != nil {
		t.Fatalf("second revoke should be a clean no-op, got ok=%v err=%v", ok, err)
	}
}
