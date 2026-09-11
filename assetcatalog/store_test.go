package assetcatalog

import "testing"

func TestAliasUniqueAutoSuffix(t *testing.T) {
	s := NewStore()
	// First claim honors the operator's chosen alias.
	a, err := s.UpsertEndpoint(Endpoint{TenantID: "acme", Alias: "prod-db", Kind: KindNetwork, Address: "10.0.0.1"})
	if err != nil || a.Alias != "prod-db" {
		t.Fatalf("first alias = %q err=%v, want prod-db", a.Alias, err)
	}
	// Second endpoint wanting the same alias gets a suffix.
	b, err := s.UpsertEndpoint(Endpoint{TenantID: "acme", Alias: "prod-db", Kind: KindNetwork, Address: "10.0.0.2"})
	if err != nil || b.Alias != "prod-db-2" {
		t.Fatalf("second alias = %q, want prod-db-2", b.Alias)
	}
	// A group wanting the same alias collides across kinds (shared namespace) -> next suffix.
	g, err := s.UpsertGroup(Group{TenantID: "acme", Alias: "prod-db"})
	if err != nil || g.Alias != "prod-db-3" {
		t.Fatalf("group alias = %q, want prod-db-3 (shared namespace)", g.Alias)
	}
	// A service likewise.
	svc, err := s.UpsertService(Service{TenantID: "acme", Alias: "prod-db", Ports: []PortProto{{Protocol: "tcp", Port: 5432}}})
	if err != nil || svc.Alias != "prod-db-4" {
		t.Fatalf("service alias = %q, want prod-db-4", svc.Alias)
	}
	// Different tenant is a separate namespace — the name is free again.
	o, err := s.UpsertEndpoint(Endpoint{TenantID: "other", Alias: "prod-db", Kind: KindNetwork, Address: "10.1.0.1"})
	if err != nil || o.Alias != "prod-db" {
		t.Fatalf("other-tenant alias = %q, want prod-db", o.Alias)
	}
}

func TestAliasUpdateKeepsOwnNameNoSuffix(t *testing.T) {
	s := NewStore()
	a, _ := s.UpsertEndpoint(Endpoint{TenantID: "acme", Alias: "db", Kind: KindNetwork, Address: "10.0.0.1"})
	// Re-upsert the same endpoint (same id) keeping the same alias must NOT suffix it.
	again, err := s.UpsertEndpoint(Endpoint{ID: a.ID, TenantID: "acme", Alias: "db", Kind: KindNetwork, Address: "10.0.0.9"})
	if err != nil || again.Alias != "db" {
		t.Fatalf("re-upsert alias = %q, want db (own name kept)", again.Alias)
	}
	if again.Address != "10.0.0.9" {
		t.Fatalf("re-upsert should update fields, address=%q", again.Address)
	}
	// Renaming frees the old alias for reuse by another entity.
	if _, err := s.UpsertEndpoint(Endpoint{ID: a.ID, TenantID: "acme", Alias: "db-renamed", Kind: KindNetwork, Address: "10.0.0.9"}); err != nil {
		t.Fatalf("rename: %v", err)
	}
	reuse, err := s.UpsertEndpoint(Endpoint{TenantID: "acme", Alias: "db", Kind: KindNetwork, Address: "10.0.0.2"})
	if err != nil || reuse.Alias != "db" {
		t.Fatalf("freed alias reuse = %q, want db", reuse.Alias)
	}
}

func TestUpsertValidation(t *testing.T) {
	s := NewStore()
	if _, err := s.UpsertEndpoint(Endpoint{Alias: "x", Kind: KindNetwork}); err == nil {
		t.Fatal("missing tenant_id must error")
	}
	if _, err := s.UpsertEndpoint(Endpoint{TenantID: "acme", Alias: "x", Kind: "bogus"}); err == nil {
		t.Fatal("invalid kind must error")
	}
	if _, err := s.UpsertService(Service{TenantID: "acme", Alias: "x"}); err == nil {
		t.Fatal("service without ports must error")
	}
}

func TestListSortedByAlias(t *testing.T) {
	s := NewStore()
	_, _ = s.UpsertEndpoint(Endpoint{TenantID: "acme", Alias: "zeta", Kind: KindNetwork, Address: "10.0.0.1"})
	_, _ = s.UpsertEndpoint(Endpoint{TenantID: "acme", Alias: "alpha", Kind: KindNetwork, Address: "10.0.0.2"})
	got := s.ListEndpoints("acme")
	if len(got) != 2 || got[0].Alias != "alpha" || got[1].Alias != "zeta" {
		t.Fatalf("list = %+v, want alias-sorted [alpha zeta]", got)
	}
}

func TestDeleteFreesAliasAndRemoves(t *testing.T) {
	s := NewStore()
	ep, _ := s.UpsertEndpoint(Endpoint{TenantID: "t1", Kind: KindNetwork, Alias: "prod-db", Address: "10.0.0.5"})
	grp, _ := s.UpsertGroup(Group{TenantID: "t1", Alias: "servers", StaticMembers: []string{ep.ID}})
	svc, _ := s.UpsertService(Service{TenantID: "t1", Alias: "pg", Ports: []PortProto{{Protocol: "tcp", Port: 5432}}})

	// delete the endpoint -> gone, and the group resolves gracefully (missing member skipped).
	if ok, err := s.DeleteEndpoint("t1", ep.ID); !ok || err != nil {
		t.Fatalf("DeleteEndpoint should report removed (ok=%v err=%v)", ok, err)
	}
	if _, ok := s.GetEndpoint("t1", ep.ID); ok {
		t.Fatal("endpoint should be gone after delete")
	}
	if m := s.ResolveGroupMembers("t1", grp.ID); len(m) != 0 {
		t.Fatalf("group should resolve to no members after the endpoint is deleted, got %v", m)
	}
	// the freed alias can be reclaimed without a collision suffix.
	ep2, _ := s.UpsertEndpoint(Endpoint{TenantID: "t1", Kind: KindNetwork, Alias: "prod-db", Address: "10.0.0.6"})
	if ep2.Alias != "prod-db" {
		t.Fatalf("a deleted endpoint's alias should be reusable without a suffix, got %q", ep2.Alias)
	}
	// delete group + service.
	if ok, err := s.DeleteGroup("t1", grp.ID); !ok || err != nil || len(s.ListGroups("t1")) != 0 {
		t.Fatal("DeleteGroup should remove the group")
	}
	if ok, err := s.DeleteService("t1", svc.ID); !ok || err != nil || len(s.ListServices("t1")) != 0 {
		t.Fatal("DeleteService should remove the service")
	}
	// deleting a missing id returns false.
	epGone, _ := s.DeleteEndpoint("t1", "nope")
	grpGone, _ := s.DeleteGroup("t1", "nope")
	svcGone, _ := s.DeleteService("t1", "nope")
	if epGone || grpGone || svcGone {
		t.Fatal("deleting a missing id must return false")
	}
}
