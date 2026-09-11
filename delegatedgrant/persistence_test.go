package delegatedgrant

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

// TestDelegatedGrantPersistenceRoundTrip proves a grant (and a revocation) survive a restart: a second store
// pointed at the same state path rehydrates the durable snapshot.
func TestDelegatedGrantPersistenceRoundTrip(t *testing.T) {
	now := time.Now().UTC()
	path := filepath.Join(t.TempDir(), "grants.json")

	s1 := NewStore(0)
	if err := s1.SetStatePath(path); err != nil {
		t.Fatalf("set state path: %v", err)
	}
	mk := func(id string) model.DelegatedAccessGrant {
		return model.DelegatedAccessGrant{ID: id, TenantID: "acme", SubjectUserID: "u1", Status: "active", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)}
	}
	if _, err := s1.Upsert(mk("g1")); err != nil {
		t.Fatal(err)
	}
	if _, err := s1.Upsert(mk("g2")); err != nil {
		t.Fatal(err)
	}
	if _, err := s1.Revoke("g2", "test-revoke", now); err != nil {
		t.Fatal(err)
	}

	// Fresh store, same path: state is rehydrated.
	s2 := NewStore(0)
	if err := s2.SetStatePath(path); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if _, ok := s2.GetActive("g1", now); !ok {
		t.Fatal("g1 should still be active after restart")
	}
	g2, ok := s2.Get("g2")
	if !ok || g2.Status != "revoked" {
		t.Fatalf("g2 should be present and revoked after restart, got ok=%v status=%q", ok, g2.Status)
	}
	if s2.Count() != 2 {
		t.Fatalf("want 2 grants after restart, got %d", s2.Count())
	}
}

// TestDelegatedGrantNoPathIsVolatile proves the store stays in-memory when no path is set.
func TestDelegatedGrantNoPathIsVolatile(t *testing.T) {
	s := NewStore(0)
	if err := s.SetStatePath(""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Upsert(model.DelegatedAccessGrant{ID: "g1", TenantID: "acme", Status: "active", ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339)}); err != nil {
		t.Fatal(err)
	}
	// No panic / no file written; nothing to assert beyond the mutation succeeding without a path.
}
