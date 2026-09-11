package configversion

import (
	"context"
	"encoding/json"
	"testing"

	steerexclusion "github.com/lantern-networks/dsse-core/steerexclusion"
)

// The versioning semantics that back rollback: monotonic version_no per resource, newest-first list, and a
// faithful snapshot round-trip so a rollback re-applies an exact prior state.
func TestConfigVersionStoreSemantics(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	const tenant, rtype, rid = "t1", ResourceSteerExclusion, "sx_1"

	v1, _ := store.Record(ctx, tenant, rtype, rid, ActionUpsert, "nagi", "v1",
		steerexclusion.Policy{ID: "sx_1", TenantID: tenant, ScopeType: "device", ScopeID: "d1", ExcludedAppSigningIDs: []string{"a"}, Status: "active"})
	v2, _ := store.Record(ctx, tenant, rtype, rid, ActionUpsert, "nagi", "v2",
		steerexclusion.Policy{ID: "sx_1", TenantID: tenant, ScopeType: "device", ScopeID: "d1", ExcludedAppSigningIDs: []string{"a", "b"}, Status: "active"})
	if v1.VersionNo != 1 || v2.VersionNo != 2 {
		t.Fatalf("version_no should be monotonic: got %d,%d", v1.VersionNo, v2.VersionNo)
	}

	list, _ := store.List(ctx, tenant, rtype, rid)
	if len(list) != 2 || list[0].VersionNo != 2 {
		t.Fatalf("List must return newest-first: %+v", list)
	}

	// Get v1 + decode the snapshot = the rollback target. It must reproduce the exact prior state.
	got, ok, _ := store.Get(ctx, tenant, rtype, rid, 1)
	if !ok {
		t.Fatal("version 1 must exist")
	}
	var snap steerexclusion.Policy
	if err := json.Unmarshal(got.Payload, &snap); err != nil {
		t.Fatal(err)
	}
	if len(snap.ExcludedAppSigningIDs) != 1 || snap.ExcludedAppSigningIDs[0] != "a" {
		t.Fatalf("v1 snapshot wrong: %+v", snap.ExcludedAppSigningIDs)
	}

	// A rollback records a NEW version (auditable) — simulate the handler's post-rollback record.
	v3, _ := store.Record(ctx, tenant, rtype, rid, ActionRollback, "nagi", "rolled back to version 1", snap)
	if v3.VersionNo != 3 || v3.Action != ActionRollback {
		t.Fatalf("rollback must append version 3 (rollback action): %+v", v3)
	}

	// Tenant isolation: another tenant's history is independent.
	other, _ := store.List(ctx, "t2", rtype, rid)
	if len(other) != 0 {
		t.Fatalf("tenant t2 must have no versions, got %d", len(other))
	}
}
