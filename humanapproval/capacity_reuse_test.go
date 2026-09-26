package humanapproval

import (
	"testing"
	"time"
)

func TestTerminalApprovalReleasesCapacityWithoutLosingRevocation(t *testing.T) {
	now := time.Now().UTC()
	s := NewStore(1)
	original := capacityRecord("a", "old", now)
	if _, err := s.Upsert(original); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := s.RevokeForTenant("a", "old", "finished"); err != nil || !ok {
		t.Fatal(err)
	}
	if _, err := s.Upsert(capacityRecord("a", "new", now)); err != nil {
		t.Fatalf("revoked approval prevents normal next approval: %v", err)
	}
	if _, err := s.Upsert(original); err == nil {
		t.Fatal("old approval resurrected")
	}
	if old, ok := s.GetForTenant("a", "old"); !ok || old.ApprovalResult != "revoked" {
		t.Fatal("revocation discarded")
	}
}
