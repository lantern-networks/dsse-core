package assetcatalog

import (
	"testing"
	"time"
)

func TestSyncEnrolledEndpointsIdempotentAndKeepsAlias(t *testing.T) {
	s := NewStore()
	now := time.Unix(1_700_000_000, 0).UTC()
	devices := []EnrolledDevice{
		{Identity: "device-cert-alice", Name: "alice-mac", Platform: "macos"},
		{Identity: "device-cert-bob", Name: "bob-win", Platform: "windows"},
	}
	first := s.SyncEnrolledEndpoints("acme", devices, now)
	if len(first) != 2 {
		t.Fatalf("first sync = %d, want 2", len(first))
	}
	if first[0].Source != SourceEnrolled || !first[0].Steered || first[0].Identity == "" {
		t.Fatalf("enrolled endpoint = %+v, want source=enrolled, steered, identity set", first[0])
	}

	// Operator renames alice's endpoint.
	if _, err := s.UpsertEndpoint(Endpoint{ID: first[0].ID, TenantID: "acme", Alias: "alice-laptop", Kind: KindSteeredDevice, Source: SourceEnrolled, Identity: first[0].Identity, Steered: true}); err != nil {
		t.Fatalf("rename: %v", err)
	}

	// Re-sync (same devices) must NOT duplicate and must KEEP the operator's alias.
	again := s.SyncEnrolledEndpoints("acme", devices, now)
	if len(again) != 2 {
		t.Fatalf("re-sync = %d, want 2", len(again))
	}
	if got := s.ListEndpoints("acme"); len(got) != 2 {
		t.Fatalf("endpoints after re-sync = %d, want 2 (no duplicates)", len(got))
	}
	renamed, _ := s.GetEndpoint("acme", first[0].ID)
	if renamed.Alias != "alice-laptop" {
		t.Fatalf("re-sync clobbered alias = %q, want alice-laptop (operator edit kept)", renamed.Alias)
	}

	// A dynamic group by platform auto-includes the enrolled devices.
	g, _ := s.UpsertGroup(Group{TenantID: "acme", Alias: "all-macs", Dynamic: &MembershipRule{Platform: strptr("macos")}})
	members := s.ResolveGroupMembers("acme", g.ID)
	if len(members) != 1 || members[0] != first[0].ID {
		t.Fatalf("dynamic group over enrolled = %v, want [%s]", members, first[0].ID)
	}
}
