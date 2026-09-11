package enrolledinventory

import "testing"

func ptr(s string) *string { return &s }

func TestUpdateGroup_PartialFieldsAndImmutableID(t *testing.T) {
	l := NewLedger()
	g, err := l.CreateGroup("finance", "acme", "old desc", "medium", "t0")
	if err != nil {
		t.Fatal(err)
	}
	// PATCH only the risk: name/description untouched, id immutable.
	up, reassigned, err := l.UpdateGroup(g.ID, nil, nil, ptr("high"), "t1")
	if err != nil {
		t.Fatal(err)
	}
	if up.ID != g.ID {
		t.Fatalf("id must be immutable: %q -> %q", g.ID, up.ID)
	}
	if up.Risk != "high" || up.Name != "finance" || up.Description != "old desc" {
		t.Fatalf("partial update touched other fields: %+v", up)
	}
	if reassigned != 0 {
		t.Fatalf("no rename => no reassignments, got %d", reassigned)
	}
	if up.UpdatedAt != "t1" {
		t.Fatalf("UpdatedAt must advance: %q", up.UpdatedAt)
	}
}

func TestUpdateGroup_RenameCascadesToMemberAssignments(t *testing.T) {
	l := NewLedger()
	g, _ := l.CreateGroup("finance", "acme", "", "high", "t0")
	// two members assigned by name, one member in a different group (must not move).
	_, _ = l.EnrollGroup("dev-1", "acme", "finance", "n", "t0")
	_, _ = l.EnrollGroup("dev-2", "acme", "Finance", "n", "t0") // a spelling variant: still the same normalized group
	_, _ = l.EnrollGroup("dev-3", "acme", "sales", "n", "t0")

	gen0 := l.ConfigGeneration()
	up, reassigned, err := l.UpdateGroup(g.ID, ptr("treasury"), nil, nil, "t1")
	if err != nil {
		t.Fatal(err)
	}
	if up.Name != "treasury" {
		t.Fatalf("rename failed: %q", up.Name)
	}
	if reassigned != 2 {
		t.Fatalf("both finance members must be re-pointed, got %d", reassigned)
	}
	if g1, _ := l.GroupFor("dev-1"); g1 != "treasury" {
		t.Fatalf("dev-1 assignment not cascaded: %q", g1)
	}
	if g2, _ := l.GroupFor("dev-2"); g2 != "treasury" {
		t.Fatalf("dev-2 (a spelling variant) assignment not cascaded: %q", g2)
	}
	if g3, _ := l.GroupFor("dev-3"); g3 != "sales" {
		t.Fatalf("non-member dev-3 must not move: %q", g3)
	}
	// the name-keyed risk floor follows the rename (union-model resolution stays attached).
	if r := l.GroupRiskByName("acme", "treasury"); r != "high" {
		t.Fatalf("risk floor lost after rename: %q", r)
	}
	if r := l.GroupRiskByName("acme", "finance"); r != "" {
		t.Fatalf("old name must no longer resolve: %q", r)
	}
	if l.ConfigGeneration() <= gen0 {
		t.Fatalf("rename must bump generation for bundle re-pull")
	}
}

func TestUpdateGroup_RejectsNameCollisionAndEmptyName(t *testing.T) {
	l := NewLedger()
	a, _ := l.CreateGroup("finance", "acme", "", "", "t0")
	_, _ = l.CreateGroup("sales", "acme", "", "", "t0")

	// rename finance -> "Sales" collides (normalized) with the existing group.
	if _, _, err := l.UpdateGroup(a.ID, ptr("Sales"), nil, nil, "t1"); err == nil {
		t.Fatalf("expected a collision error renaming to an existing normalized name")
	}
	// empty new name is rejected.
	if _, _, err := l.UpdateGroup(a.ID, ptr("   "), nil, nil, "t1"); err == nil {
		t.Fatalf("expected an error for an empty new name")
	}
	// finance is unchanged after the rejected updates.
	if got, ok := l.GroupByID(a.ID); !ok || got.Name != "finance" {
		t.Fatalf("group must be untouched after rejected update: %+v ok=%v", got, ok)
	}
}

func TestUpdateGroup_RenameToSameNameIsAllowed(t *testing.T) {
	l := NewLedger()
	g, _ := l.CreateGroup("finance", "acme", "", "", "t0")
	// re-submitting the same name (only changing description) must not trip the self-collision check.
	up, reassigned, err := l.UpdateGroup(g.ID, ptr("finance"), ptr("new desc"), nil, "t1")
	if err != nil {
		t.Fatalf("renaming a group to its own name must be allowed: %v", err)
	}
	if up.Description != "new desc" || reassigned != 0 {
		t.Fatalf("unexpected result: %+v reassigned=%d", up, reassigned)
	}
}

func TestUpdateGroup_AbsentID(t *testing.T) {
	l := NewLedger()
	if _, _, err := l.UpdateGroup("dg_nope", ptr("x"), nil, nil, "t1"); err == nil {
		t.Fatalf("expected an error for an absent group id")
	}
}
