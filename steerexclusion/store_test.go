package steerexclusion

import (
	"context"
	"testing"
	"time"
)

func TestSteerExclusionUpsertValidation(t *testing.T) {
	s := NewStore()
	now := time.Now().UTC()
	// missing signing ids
	if _, err := s.Upsert(Policy{TenantID: "t", ScopeType: "tenant"}, now); err == nil {
		t.Fatal("expected error for empty excluded_app_signing_ids")
	}
	// bad scope
	if _, err := s.Upsert(Policy{TenantID: "t", ScopeType: "bogus", ExcludedAppSigningIDs: []string{"a"}}, now); err == nil {
		t.Fatal("expected error for invalid scope_type")
	}
	// device scope without scope_id
	if _, err := s.Upsert(Policy{TenantID: "t", ScopeType: "device", ExcludedAppSigningIDs: []string{"a"}}, now); err == nil {
		t.Fatal("expected error for device scope without scope_id")
	}
}

func TestSteerExclusionResolveUnion(t *testing.T) {
	s := NewStore()
	now := time.Now().UTC()
	mustUpsert := func(p Policy) {
		if _, err := s.Upsert(p, now); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}
	mustUpsert(Policy{TenantID: "t1", ScopeType: "tenant", ExcludedAppSigningIDs: []string{"com.t.tenant"}})
	mustUpsert(Policy{TenantID: "t1", ScopeType: "device_group", ScopeID: "g1", ExcludedAppSigningIDs: []string{"com.t.group"}})
	mustUpsert(Policy{TenantID: "t1", ScopeType: "device", ScopeID: "dev1", ExcludedAppSigningIDs: []string{"com.t.device"}})
	mustUpsert(Policy{TenantID: "t1", ScopeType: "device", ScopeID: "other", ExcludedAppSigningIDs: []string{"com.t.notme"}})

	got := s.ResolveForDevice("t1", "dev1", "g1")
	want := map[string]bool{"com.t.tenant": true, "com.t.group": true, "com.t.device": true}
	if len(got) != 3 {
		t.Fatalf("resolved = %v, want 3 entries (tenant+group+device union)", got)
	}
	for _, id := range got {
		if !want[id] {
			t.Fatalf("unexpected resolved id %q (must not include another device's exclusion)", id)
		}
	}

	// a device in no matching group/device gets only the tenant-scoped set
	if got := s.ResolveForDevice("t1", "devX", "gX"); len(got) != 1 || got[0] != "com.t.tenant" {
		t.Fatalf("unmatched device resolved = %v, want only the tenant exclusion", got)
	}
	// cross-tenant isolation
	if got := s.ResolveForDevice("t2", "dev1", "g1"); len(got) != 0 {
		t.Fatalf("other tenant resolved = %v, want empty", got)
	}
}

func TestSteerExclusionDurableAcrossRestart(t *testing.T) {
	p := &fakeSteerExclusionPersistence{rows: map[string]*Policy{}}
	now := time.Now().UTC()
	s1, err := NewStoreWithPersistence(p)
	if err != nil {
		t.Fatal(err)
	}
	saved, err := s1.Upsert(Policy{TenantID: "t1", ScopeType: "device", ScopeID: "dev1", ExcludedAppSigningIDs: []string{"com.x"}}, now)
	if err != nil {
		t.Fatal(err)
	}
	// "restart": new store from the same persistence
	s2, err := NewStoreWithPersistence(p)
	if err != nil {
		t.Fatal(err)
	}
	if got := s2.ResolveForDevice("t1", "dev1", ""); len(got) != 1 || got[0] != "com.x" {
		t.Fatalf("after restart resolved = %v, want [com.x]", got)
	}
	if !s2.Delete(saved.ID, "t1", now) {
		t.Fatal("delete should succeed")
	}
	if len(p.rows) != 0 {
		t.Fatalf("persistence rows after delete = %d, want 0", len(p.rows))
	}
}

type fakeSteerExclusionPersistence struct {
	rows map[string]*Policy
}

func (f *fakeSteerExclusionPersistence) LoadAll(_ context.Context) ([]*Policy, error) {
	out := []*Policy{}
	for _, p := range f.rows {
		cp := *p
		out = append(out, &cp)
	}
	return out, nil
}
func (f *fakeSteerExclusionPersistence) Upsert(_ context.Context, p *Policy) error {
	cp := *p
	f.rows[p.ID] = &cp
	return nil
}
func (f *fakeSteerExclusionPersistence) Delete(_ context.Context, id, _ string) error {
	delete(f.rows, id)
	return nil
}
