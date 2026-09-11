package enrolledinventory

import (
	"errors"
	"testing"
)

// Disabling a device is the console's revocation (see SetEnabled's own comment: "the manual revocation path"),
// and EnrollGroup sets Enabled = true on whatever entry it finds under the same normalized identity. Those two
// wrote the SAME field of the SAME map entry, so a device that re-enrolled under its old name silently undid the
// operator's decision — and overwrote the note explaining it, so the reason for the disable was lost too.
//
// The device-facing path now refuses instead. These tests pin both halves of the split: refuse when the caller is
// a device, allow when the caller is an admin who is entitled to make that call.
func TestDeviceEnrolmentRefusesADisabledIdentity(t *testing.T) {
	l := NewLedger()
	const id = "dev-revoked-then-reenrolled"

	if _, err := l.EnrollGroupUnlessDisabled(id, "tenant_a", "default", "enrolled via POST /enroll", "t0"); err != nil {
		t.Fatalf("initial enrolment: %v", err)
	}
	if !l.IsAdmitted(id) {
		t.Fatalf("a freshly enrolled device must be admitted")
	}

	// The admin revokes it. This is what POST /admin/enrolled-devices/{id}/disable does.
	if _, ok := l.SetEnabled(id, false, "t1"); !ok {
		t.Fatalf("disable must find the entry it just enrolled")
	}

	// The same name enrols again, holding whatever enrolment credential it had.
	if _, err := l.EnrollGroupUnlessDisabled(id, "tenant_a", "default", "enrolled via POST /enroll", "t2"); !errors.Is(err, ErrIdentityDisabled) {
		t.Fatalf("re-enrolment of a disabled identity must be refused, got err=%v", err)
	}
	if l.IsAdmitted(id) {
		t.Fatalf("a disabled device must stay out after re-enrolling under the same name")
	}
}

// An unknown identity is the ordinary Day-0 case and must NOT be caught by the refusal. Getting this wrong would
// make the product unable to enrol its first device, so it is worth its own test rather than an assumption.
func TestDeviceEnrolmentAllowsAnIdentityThatHasNeverEnrolled(t *testing.T) {
	l := NewLedger()
	if _, err := l.EnrollGroupUnlessDisabled("dev-brand-new", "tenant_a", "default", "note", "t0"); err != nil {
		t.Fatalf("a device that has never enrolled must be able to: %v", err)
	}
	if !l.IsAdmitted("dev-brand-new") {
		t.Fatalf("first enrolment must admit")
	}
}

// Re-enrolling a device that is enabled — a re-image, a lost key, a reinstall — must keep working. The refusal is
// about the operator's decision, not about enrolling twice.
func TestDeviceEnrolmentStillAllowsRepeatEnrolmentOfAnEnabledDevice(t *testing.T) {
	l := NewLedger()
	const id = "dev-reimaged"
	if _, err := l.EnrollGroupUnlessDisabled(id, "tenant_a", "default", "first", "t0"); err != nil {
		t.Fatalf("first: %v", err)
	}
	if _, err := l.EnrollGroupUnlessDisabled(id, "tenant_a", "default", "second", "t1"); err != nil {
		t.Fatalf("re-enrolling an ENABLED device must still work: %v", err)
	}
	if !l.IsAdmitted(id) {
		t.Fatalf("still admitted")
	}
}

// The admin route keeps the permissive call. An admin re-adding a device they disabled is the decision, made by
// someone entitled to make it — and they have enable/disable in front of them either way.
func TestAdminEnrolmentMayStillReEnableADisabledIdentity(t *testing.T) {
	l := NewLedger()
	const id = "dev-admin-readds"
	if _, err := l.EnrollGroup(id, "tenant_a", "", "", "t0"); err != nil {
		t.Fatalf("enrol: %v", err)
	}
	l.SetEnabled(id, false, "t1")
	if _, err := l.EnrollGroup(id, "tenant_a", "", "", "t2"); err != nil {
		t.Fatalf("the admin path must not be blocked: %v", err)
	}
	if !l.IsAdmitted(id) {
		t.Fatalf("an admin re-adding a device re-enables it")
	}
}

// IsExplicitlyDisabled has to separate "absent" from "present and off" — the enrolment gate is built on that
// distinction, and collapsing the two would either lock out every new device or let every revoked one back in.
func TestIsExplicitlyDisabledSeparatesAbsentFromDisabled(t *testing.T) {
	l := NewLedger()
	if l.IsExplicitlyDisabled("never-seen") {
		t.Fatalf("an identity that has never enrolled is not disabled")
	}
	l.EnrollGroup("dev-x", "tenant_a", "", "", "t0")
	if l.IsExplicitlyDisabled("dev-x") {
		t.Fatalf("an enabled device is not disabled")
	}
	l.SetEnabled("dev-x", false, "t1")
	if !l.IsExplicitlyDisabled("dev-x") {
		t.Fatalf("a disabled device is disabled")
	}
	if !l.IsExplicitlyDisabled("  DEV-X  ") {
		t.Fatalf("the check must normalize identity the same way the map key does, or case alone bypasses it")
	}
}
