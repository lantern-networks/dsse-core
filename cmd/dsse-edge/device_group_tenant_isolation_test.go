package main

import "testing"

// TestDeviceGroupVisibleToTenant pins the predicate every device and device-group handler gates on: may an
// admin operating as callerTenant see — and change, and DELETE — an object carrying groupTenant?
//
// ★ THIS TEST USED TO PIN THE HOLE (2026-08-12, sixteenth review). It asserted that an object with an empty
// tenant "stays visible" to any caller, described as a lockout-safe escape hatch. Half of that reasoning was
// right and half was the leak, and writing them as one rule is what kept it alive through two tenant-isolation
// reviews: the test agreed with the code, so nothing disagreed with either.
//
//   - An empty CALLER tenant is about the operator: a deployment that could not scope them, which is how a
//     single-tenant edge with no tenant model works. Narrowing that would lock those admins out of their own
//     fleet. Unchanged.
//   - An empty OBJECT tenant is about the device: it belongs to no tenant, and "belongs to nobody" was being
//     read as "belongs to everybody" — one tenant's admin listing and deleting another's devices, in exactly
//     the states nobody pictures (a tenant just added, a migration half-done).
//
// The list endpoints report what they withheld as a count, so closing this does not make a device vanish.
func TestDeviceGroupVisibleToTenant(t *testing.T) {
	cases := []struct {
		name         string
		groupTenant  string
		callerTenant string
		want         bool
	}{
		{"same tenant is visible", "acme", "acme", true},
		{"case-insensitive tenant match", "ACME", "acme", true},
		{"different non-empty tenants are isolated", "acme", "globex", false},
		// The boundary this test exists for, and the one it used to assert the opposite of.
		{"an object in NO tenant belongs to no tenant's admin", "", "acme", false},
		{"whitespace-only object tenant is still no tenant", "  ", "acme", false},
		// The caller side is a different question and keeps its answer.
		{"an unscoped operator sees everything (lockout-safe)", "acme", "", true},
		{"both empty is visible", "", "", true},
		{"an unscoped operator sees unassigned devices too", "  ", "  ", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := deviceGroupVisibleToTenant(c.groupTenant, c.callerTenant); got != c.want {
				t.Fatalf("deviceGroupVisibleToTenant(%q, %q) = %v, want %v", c.groupTenant, c.callerTenant, got, c.want)
			}
		})
	}
}

// And the property that matters at the API: a device in no tenant is not in a tenant admin's list, and the
// answer says how many it withheld so the fleet cannot quietly shrink.
func TestAnUnassignedDeviceIsWithheldAndCounted(t *testing.T) {
	if deviceGroupVisibleToTenant("", "tenant_a") {
		t.Fatal("an unassigned device was visible to tenant_a's admin")
	}
	if deviceGroupVisibleToTenant("", "tenant_b") {
		t.Fatal("the same unassigned device was visible to tenant_b's admin — one device, two owners, which " +
			"is the cross-tenant exposure this predicate is the only thing standing in front of")
	}
}
