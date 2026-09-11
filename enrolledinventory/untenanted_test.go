package enrolledinventory

import "testing"

// Seats are counted per tenant, so an enrolled entry carrying no tenant is counted against no pool at all.
// A deployment whose inventory was SEEDED rather than enrolled therefore reports zero seats in use while
// admitting devices, and a licence that says it is enforced can never refuse anything — a state that looks
// exactly like an empty fleet from every surface that reports seat usage.
func TestUntenantedEntriesAreCountedSeparately(t *testing.T) {
	l := NewLedger()
	// Seeded entries: no tenant, which is how a static inventory arrives.
	l.Enroll("seeded-a", "", "", "2026-07-30T00:00:00Z")
	l.Enroll("seeded-b", "", "", "2026-07-30T00:00:00Z")
	// A device enrolled properly carries its tenant.
	l.Enroll("proper-1", "tenant_x", "", "2026-07-30T00:00:00Z")

	if got := l.CountAdmitted("tenant_x"); got != 1 {
		t.Fatalf("seats for tenant_x = %d, want 1", got)
	}
	if got := l.CountUntenanted(); got != 2 {
		t.Fatalf("untenanted = %d, want 2 — this is the number that explains a seat table reading zero", got)
	}

	// A disabled entry is not admitted and must not be counted as consuming anything, tagged or not.
	if _, ok := l.SetEnabled("seeded-a", false, "2026-07-30T01:00:00Z"); !ok {
		t.Fatalf("disable: entry not found")
	}
	if got := l.CountUntenanted(); got != 1 {
		t.Fatalf("untenanted after disabling one = %d, want 1", got)
	}
}
