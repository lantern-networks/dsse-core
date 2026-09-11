package assetcatalog

import (
	"path/filepath"
	"testing"
	"time"
)

// TestCatalogPersistsOperatorEntriesAcrossRestart proves operator-authored endpoints/groups/services survive
// a restart (a fresh Store loading the same path), while enrolled-device endpoints are NOT persisted (they
// are re-derived from the enrolled inventory on boot).
func TestCatalogPersistsOperatorEntriesAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "catalog.json")

	s1 := NewStore()
	if err := s1.SetStatePath(path); err != nil {
		t.Fatalf("SetStatePath: %v", err)
	}
	ep, err := s1.UpsertEndpoint(Endpoint{TenantID: "t1", Kind: KindNetwork, Alias: "db-primary"})
	if err != nil {
		t.Fatalf("UpsertEndpoint: %v", err)
	}
	if _, err := s1.UpsertGroup(Group{TenantID: "t1", Alias: "servers", StaticMembers: []string{ep.ID}}); err != nil {
		t.Fatalf("UpsertGroup: %v", err)
	}
	if _, err := s1.UpsertService(Service{TenantID: "t1", Alias: "pg", Ports: []PortProto{{Protocol: "tcp", Port: 5432}}}); err != nil {
		t.Fatalf("UpsertService: %v", err)
	}
	// An enrolled device endpoint must NOT be persisted.
	s1.SyncEnrolledEndpoints("t1", []EnrolledDevice{{Identity: "device-A", Name: "laptop", Platform: "macos"}}, time.Now().UTC())

	// Restart: a fresh store loading the same file.
	s2 := NewStore()
	if err := s2.SetStatePath(path); err != nil {
		t.Fatalf("reload SetStatePath: %v", err)
	}
	got, ok := s2.GetEndpoint("t1", ep.ID)
	if !ok {
		t.Fatal("operator endpoint did not survive restart")
	}
	if got.Alias != "db-primary" {
		t.Fatalf("alias not restored: %q", got.Alias)
	}
	if len(s2.ListGroups("t1")) != 1 {
		t.Fatalf("group did not survive restart: %d", len(s2.ListGroups("t1")))
	}
	if len(s2.ListServices("t1")) != 1 {
		t.Fatalf("service did not survive restart: %d", len(s2.ListServices("t1")))
	}
	// Only the operator endpoint should be present (enrolled was not persisted).
	if n := len(s2.ListEndpoints("t1")); n != 1 {
		t.Fatalf("expected only the operator endpoint, got %d (enrolled leaked into persistence)", n)
	}
	// The new id must not collide with the persisted one (seq survived).
	ep2, err := s2.UpsertEndpoint(Endpoint{TenantID: "t1", Kind: KindNetwork, Alias: "cache"})
	if err != nil {
		t.Fatalf("post-restart upsert: %v", err)
	}
	if ep2.ID == ep.ID {
		t.Fatalf("id collision after restart: %s", ep2.ID)
	}
}
