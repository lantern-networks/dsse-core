package humanapproval

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

// TestHumanApprovalPersistenceRoundTrip proves an approval event (and a revocation) survive a restart.
func TestHumanApprovalPersistenceRoundTrip(t *testing.T) {
	now := time.Now().UTC()
	exp := now.Add(time.Hour).Format(time.RFC3339)
	path := filepath.Join(t.TempDir(), "approvals.json")

	s1 := NewStore(0)
	if err := s1.SetStatePath(path); err != nil {
		t.Fatalf("set state path: %v", err)
	}
	if _, err := s1.Upsert(model.HumanApprovalEvent{ID: "h1", TenantID: "acme", ApprovalResult: "approved", ExpiresAt: &exp}); err != nil {
		t.Fatal(err)
	}
	if _, err := s1.Upsert(model.HumanApprovalEvent{ID: "h2", TenantID: "acme", ApprovalResult: "approved", ExpiresAt: &exp}); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := s1.Revoke("h2", "test-revoke"); !ok || err != nil {
		t.Fatal("revoke h2 should succeed")
	}

	s2 := NewStore(0)
	if err := s2.SetStatePath(path); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if _, ok := s2.GetActive("h1", now); !ok {
		t.Fatal("h1 should still be active after restart")
	}
	h2, ok := s2.Get("h2")
	if !ok || h2.ApprovalResult != "revoked" {
		t.Fatalf("h2 should be present and revoked after restart, got ok=%v result=%q", ok, h2.ApprovalResult)
	}
}
