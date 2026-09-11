package enrolledinventory

import "testing"

func TestEnrollGroup_CarriesGroup(t *testing.T) {
	l := NewLedger()
	e, err := l.EnrollGroup("win-dev-1", "acme", "developers", "note", "t1")
	if err != nil {
		t.Fatal(err)
	}
	if e.Group != "developers" || e.TenantID != "acme" || !e.Enabled {
		t.Fatalf("group/tenant not recorded: %+v", e)
	}
	// the group shows up in List() (the fleet-view source)
	for _, x := range l.List() {
		if x.Identity == "win-dev-1" && x.Group != "developers" {
			t.Fatalf("List() lost group: %+v", x)
		}
	}
}

func TestGroupFor_AuthoritativeSource(t *testing.T) {
	l := NewLedger()
	// unknown identity → not present, empty group (caller falls back to tenant-only scope).
	if g, ok := l.GroupFor("nope"); ok || g != "" {
		t.Fatalf("unknown identity must be absent: g=%q ok=%v", g, ok)
	}
	_, _ = l.EnrollGroup("Win-1", "acme", "executives", "n", "t1")
	// case-insensitive identity match (NormalizeIdentity), returns the CP-assigned group.
	if g, ok := l.GroupFor("win-1"); !ok || g != "executives" {
		t.Fatalf("must return CP-assigned group: g=%q ok=%v", g, ok)
	}
	// enrolled without a group → present but empty group (NOT a fallback to anything device-supplied).
	_, _ = l.Enroll("win-2", "acme", "n", "t1")
	if g, ok := l.GroupFor("win-2"); !ok || g != "" {
		t.Fatalf("no-group enrollee: present with empty group: g=%q ok=%v", g, ok)
	}
}

func TestSetGroup_ExplicitReassignAndClear(t *testing.T) {
	l := NewLedger()
	if _, ok, _ := l.SetGroup("absent", "x", "t1"); ok {
		t.Fatalf("SetGroup on an absent identity must return false")
	}
	_, _ = l.EnrollGroup("win-1", "acme", "finance", "n", "t1")
	g0 := l.ConfigGeneration()
	// re-assign to a different group
	e, ok, _ := l.SetGroup("win-1", "executives", "t2")
	if !ok || e.Group != "executives" {
		t.Fatalf("re-assign failed: %+v ok=%v", e, ok)
	}
	if l.ConfigGeneration() <= g0 {
		t.Fatalf("SetGroup must bump generation for bundle re-pull")
	}
	// empty CLEARS (unlike EnrollGroup which preserves) → tenant-scope only
	e2, _, _ := l.SetGroup("win-1", "  ", "t3")
	if e2.Group != "" {
		t.Fatalf("empty group must clear the assignment: %q", e2.Group)
	}
	if g, ok := l.GroupFor("win-1"); !ok || g != "" {
		t.Fatalf("GroupFor after clear: present, empty: g=%q ok=%v", g, ok)
	}
}

func TestEnroll_NoGroup(t *testing.T) {
	l := NewLedger()
	e, _ := l.Enroll("d", "t", "n", "t1")
	if e.Group != "" {
		t.Fatalf("plain Enroll must not set a group: %q", e.Group)
	}
}

func TestEnrollGroup_EmptyGroupPreservesExisting(t *testing.T) {
	l := NewLedger()
	_, _ = l.EnrollGroup("d", "t", "finance", "", "t1")
	// A re-enroll (e.g. admin re-enable) with no group must NOT clear the CP-assigned group.
	e, _ := l.EnrollGroup("d", "t", "", "re-enabled", "t2")
	if e.Group != "finance" {
		t.Fatalf("empty group must preserve existing: %q", e.Group)
	}
}
