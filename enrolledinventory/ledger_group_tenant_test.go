package enrolledinventory

import "testing"

// TestEntryFor_ReturnsTenantForGuard proves EntryFor exposes an entry's TenantID (and presence) so the admin API
// can gate per-device mutations on tenant BEFORE mutating (review finding #2). Case-insensitive on identity.
func TestEntryFor_ReturnsTenantForGuard(t *testing.T) {
	l := NewLedger()
	_, _ = l.EnrollGroup("Win-Dev-1", "tenant-a", "finance", "n", "t0")
	e, ok := l.EntryFor("win-dev-1") // case-insensitive
	if !ok || e.TenantID != "tenant-a" {
		t.Fatalf("EntryFor(win-dev-1) = %+v ok=%v, want tenant-a", e, ok)
	}
	if _, ok := l.EntryFor("ghost"); ok {
		t.Fatal("EntryFor on an absent identity must report false")
	}
}

// TestUpdateGroup_RenameCascadeIsTenantScoped pins the fix for the review finding (#4): a rename cascade must
// only re-point member devices in the RENAMED GROUP'S OWN tenant. Two tenants each own a "finance" group with
// members; renaming tenant-a's group must NOT touch tenant-b's identically-named-group members, and must NOT
// drop tenant-b's floor (the floor resolves per tenant, so a cross-tenant rewrite would orphan it).
func TestUpdateGroup_RenameCascadeIsTenantScoped(t *testing.T) {
	const now = "2026-07-23T00:00:00Z"
	l := NewLedger()
	ga, _ := l.CreateGroup("finance", "tenant-a", "", "high", now)
	_, _ = l.CreateGroup("finance", "tenant-b", "", "medium", now)
	_, _ = l.EnrollGroup("a-dev", "tenant-a", "finance", "", now)
	_, _ = l.EnrollGroup("b-dev", "tenant-b", "finance", "", now)

	// Rename tenant-a's finance -> treasury.
	_, reassigned, err := l.UpdateGroup(ga.ID, ptr("treasury"), nil, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if reassigned != 1 {
		t.Fatalf("cascade must re-point ONLY tenant-a's 1 member, got %d", reassigned)
	}
	if g, _ := l.GroupFor("a-dev"); g != "treasury" {
		t.Fatalf("tenant-a device must follow the rename: %q", g)
	}
	// tenant-b's device is UNTOUCHED — still "finance".
	if g, _ := l.GroupFor("b-dev"); g != "finance" {
		t.Fatalf("tenant-b device must NOT be rewritten by tenant-a's rename: %q", g)
	}
	// tenant-b's floor still resolves (its device still points at tenant-b's finance = medium).
	if r := l.GroupRiskForDevice("b-dev"); r != "medium" {
		t.Fatalf("tenant-b floor must survive tenant-a's rename: %q", r)
	}
	// tenant-a's floor follows the new name.
	if r := l.GroupRiskForDevice("a-dev"); r != "high" {
		t.Fatalf("tenant-a floor must stay attached after rename: %q", r)
	}
}

// TestCreateGroup_SameNameAllowedAcrossTenants pins the multi-tenant premise: two DIFFERENT tenants may each own
// a group with the same (normalized) name; the collision check is per-tenant, so neither create leaks or blocks
// the other. Within ONE tenant the name is still unique.
func TestCreateGroup_SameNameAllowedAcrossTenants(t *testing.T) {
	const now = "2026-07-22T00:00:00Z"
	l := NewLedger()

	if _, err := l.CreateGroup("finance", "tenant-a", "", "high", now); err != nil {
		t.Fatalf("tenant-a finance: %v", err)
	}
	// Different tenant, same normalized name (a spelling variant) — must be allowed.
	if _, err := l.CreateGroup("Finance", "tenant-b", "", "medium", now); err != nil {
		t.Fatalf("tenant-b Finance must be allowed (different tenant): %v", err)
	}
	// Same tenant, same name — still a collision.
	if _, err := l.CreateGroup("finance", "tenant-a", "", "", now); err == nil {
		t.Fatalf("same-tenant duplicate name must still collide")
	}
	if got := len(l.ListGroups()); got != 2 {
		t.Fatalf("want 2 groups (one per tenant), got %d", got)
	}
}

// TestGroupRiskByName_ScopedToTenant proves the floor lookup is tenant-scoped: the same name resolves to each
// tenant's OWN floor, never the other's.
func TestGroupRiskByName_ScopedToTenant(t *testing.T) {
	const now = "2026-07-22T00:00:00Z"
	l := NewLedger()
	if _, err := l.CreateGroup("finance", "tenant-a", "", "high", now); err != nil {
		t.Fatal(err)
	}
	if _, err := l.CreateGroup("finance", "tenant-b", "", "medium", now); err != nil {
		t.Fatal(err)
	}
	if r := l.GroupRiskByName("tenant-a", "finance"); r != "high" {
		t.Fatalf("tenant-a finance floor = %q, want high", r)
	}
	if r := l.GroupRiskByName("tenant-b", "finance"); r != "medium" {
		t.Fatalf("tenant-b finance floor = %q, want medium", r)
	}
	// A tenant with no such group resolves to no floor (never another tenant's).
	if r := l.GroupRiskByName("tenant-c", "finance"); r != "" {
		t.Fatalf("tenant-c has no finance group; floor = %q, want empty", r)
	}
}

// TestGroupRiskForDevice_ResolvesWithinDeviceTenant proves the production floor path keys on the DEVICE's own
// tenant (the entry's TenantID): two devices in different tenants, both assigned to a "finance" group, each get
// their own tenant's floor — never the other's same-named group.
func TestGroupRiskForDevice_ResolvesWithinDeviceTenant(t *testing.T) {
	const now = "2026-07-22T00:00:00Z"
	l := NewLedger()
	if _, err := l.CreateGroup("finance", "tenant-a", "", "high", now); err != nil {
		t.Fatal(err)
	}
	if _, err := l.CreateGroup("finance", "tenant-b", "", "medium", now); err != nil {
		t.Fatal(err)
	}
	if _, err := l.EnrollGroup("dev-a", "tenant-a", "finance", "", now); err != nil {
		t.Fatal(err)
	}
	if _, err := l.EnrollGroup("dev-b", "tenant-b", "finance", "", now); err != nil {
		t.Fatal(err)
	}
	if r := l.GroupRiskForDevice("dev-a"); r != "high" {
		t.Fatalf("dev-a (tenant-a) floor = %q, want high", r)
	}
	if r := l.GroupRiskForDevice("dev-b"); r != "medium" {
		t.Fatalf("dev-b (tenant-b) floor = %q, want medium (its own tenant, not tenant-a's high)", r)
	}
	// Unknown device / unassigned device / no-floor group => no floor.
	if r := l.GroupRiskForDevice("nope"); r != "" {
		t.Fatalf("unknown device floor = %q, want empty", r)
	}
	if _, err := l.EnrollGroup("dev-plain", "tenant-a", "", "", now); err != nil {
		t.Fatal(err)
	}
	if r := l.GroupRiskForDevice("dev-plain"); r != "" {
		t.Fatalf("unassigned device floor = %q, want empty", r)
	}
}
