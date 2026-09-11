package enrolledinventory

import (
	"errors"
	"testing"
)

// ★★★ A REMOVED DEVICE COULD NEVER COME BACK, AND EVERY STEP ANSWERED SUCCESS (2026-08-25, reported from
// win-dev-1 after it removed its own device and was locked out of that identity for good).
//
//	DELETE                     200 {"removed":true}
//	POST .../enable            404 "identity is not in the enrolled inventory"
//	POST .../allow-reenrolment 404 the same
//	POST /admin/enrolled-devices 200 — and removed_at stayed, so the ledger never listed it
//	/enroll                    refused: not eligible
//
// Nothing in the package cleared RemovedAt. The tombstone was permanent, and the API said success the whole
// way down. Both halves are pinned here: the named act LIFTS a removal, and the unnamed one REFUSES.
func TestARemovalCanBeLiftedAndNotWrittenOver(t *testing.T) {
	const now = "2026-08-25T00:00:00Z"
	l := NewLedger()
	if _, err := l.EnrollGroup("win-dev-1", "tenant_default", "default", "first", now); err != nil {
		t.Fatalf("enrol: %v", err)
	}
	if !l.IsAdmitted("win-dev-1") {
		t.Fatal("a freshly enrolled identity is not admitted")
	}

	if !l.Remove("win-dev-1", now) {
		t.Fatal("remove reported nothing to remove")
	}
	if l.IsAdmitted("win-dev-1") {
		t.Fatal("a removed identity is still admitted")
	}
	if !l.IsRefused("win-dev-1") {
		t.Fatal("a removed identity is not refused, so the fleet would go on admitting it")
	}

	// ★ THE GUARD: re-creating it must NOT quietly succeed. That is what made the removal permanent AND
	// invisible — the caller was told 200 and the tombstone stayed.
	if _, err := l.EnrollGroup("win-dev-1", "tenant_default", "default", "again", now); !errors.Is(err, ErrIdentityRemoved) {
		t.Fatalf("writing over a removal answered %v, want ErrIdentityRemoved", err)
	}
	if l.IsAdmitted("win-dev-1") {
		t.Fatal("writing over a removal admitted the identity anyway")
	}

	// And the named act lifts it.
	if _, _, err := l.AllowReenrolment("win-dev-1", "tenant_default", now); err != nil {
		t.Fatalf("allow re-enrolment on a removed identity: %v", err)
	}
	if !l.IsAdmitted("win-dev-1") {
		t.Fatal("the identity is still not admitted after re-enrolment was allowed")
	}
	if l.IsRefused("win-dev-1") {
		t.Fatal("the identity is still refused after re-enrolment was allowed")
	}
	if e, ok := l.EntryFor("win-dev-1"); !ok || e.RemovedAt != "" {
		t.Fatalf("the tombstone survived the act that exists to lift it: %+v", e)
	}
	// It can enrol again, which is the whole point.
	if _, err := l.EnrollGroup("win-dev-1", "tenant_default", "default", "third", now); err != nil {
		t.Fatalf("enrolling after re-enrolment was allowed: %v", err)
	}
}

// A tenant that does not own the identity cannot lift another tenant's removal.
func TestLiftingARemovalStaysInsideTheOrganization(t *testing.T) {
	const now = "2026-08-25T00:00:00Z"
	l := NewLedger()
	if _, err := l.EnrollGroup("dev-1", "tenant_a", "default", "", now); err != nil {
		t.Fatal(err)
	}
	l.Remove("dev-1", now)
	if _, _, err := l.AllowReenrolment("dev-1", "tenant_b", now); !errors.Is(err, ErrIdentityOwnedByAnotherTenant) {
		t.Fatalf("another organization lifted this removal: %v", err)
	}
	if l.IsAdmitted("dev-1") {
		t.Fatal("the refused lift admitted the identity anyway")
	}
}
