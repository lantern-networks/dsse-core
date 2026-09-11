package enrolledinventory

import "testing"

// TestReplaceAllGroupsDistributesRegistry pins the config-distribution path for the device-group registry
// (M1): a config-pulling Edge swaps in the CP-authoritative registry via ReplaceAllGroups, replacing whatever
// it had. A present-but-empty set is authoritative (empties the registry). Mirrors ReplaceAll for entries.
func TestReplaceAllGroupsDistributesRegistry(t *testing.T) {
	const now = "2026-07-22T00:00:00Z"
	l := NewLedger()
	if _, err := l.CreateGroup("stale-local", "t1", "", "high", now); err != nil {
		t.Fatalf("seed local group: %v", err)
	}

	l.ReplaceAllGroups([]Group{
		{ID: "dg_a", TenantID: "t1", Name: "finance", Risk: "high"},
		{ID: "dg_b", TenantID: "t1", Name: "contractors", Risk: "medium"},
		{ID: "", Name: "skipped-no-id"}, // empty id -> skipped
	}, now)

	if got := l.ListGroups(); len(got) != 2 {
		t.Fatalf("after ReplaceAllGroups: %d groups, want 2 (empty-id skipped)", len(got))
	}
	if r := l.GroupRiskByName("t1", "finance"); r != "high" {
		t.Fatalf("finance floor = %q, want high", r)
	}
	if r := l.GroupRiskByName("t1", "stale-local"); r != "" {
		t.Fatalf("the pre-pull local group must be gone, got floor %q", r)
	}
	if g, ok := l.GroupByID("dg_a"); !ok || g.Name != "finance" {
		t.Fatalf("GroupByID(dg_a) = %+v ok=%v, want finance", g, ok)
	}

	// A present-but-empty registry is authoritative: it empties the registry.
	l.ReplaceAllGroups([]Group{}, now)
	if got := l.ListGroups(); len(got) != 0 {
		t.Fatalf("empty ReplaceAllGroups left %d groups, want 0", len(got))
	}
}
