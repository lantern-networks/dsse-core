package main

import (
	"strings"
	"testing"
	"time"
)

const (
	dcaOld = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	dcaNew = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// ★★★ RETIRING A DEVICE AUTHORITY REFUSES EVERY DEVICE STILL ON IT (2026-08-22).
func TestADeviceAuthorityRetirementWaitsForEveryDevice(t *testing.T) {
	enrolled := []string{"mac-dev-1", "win-dev-1"}

	// Nobody has moved.
	r := measureDeviceAuthorityRotation("tenant_reference_lab", dcaOld, dcaNew, enrolled,
		map[string]string{"mac-dev-1": dcaOld, "win-dev-1": dcaOld}, nil)
	if r.MayRetirePrevious {
		t.Fatal("retiring was allowed while every device was still on the outgoing authority")
	}
	if len(r.StillOnOutgoing) != 2 {
		t.Fatalf("the devices still on the outgoing authority were not named: %+v", r)
	}

	// One has.
	r = measureDeviceAuthorityRotation("tenant_reference_lab", dcaOld, dcaNew, enrolled,
		map[string]string{"mac-dev-1": dcaNew, "win-dev-1": dcaOld}, nil)
	if r.MayRetirePrevious {
		t.Fatal("retiring was allowed with one device still on the outgoing authority")
	}
	if !strings.Contains(r.Note, "would refuse everything still on the outgoing authority") {
		t.Fatalf("the note does not say what retiring now would do: %q", r.Note)
	}

	// ★★ SILENCE IS NOT READINESS, and this is the case the whole shape exists for: the laptop that was
	// switched off for the rotation. An empty "still on the outgoing" list must not read as "everybody moved".
	r = measureDeviceAuthorityRotation("tenant_reference_lab", dcaOld, dcaNew, enrolled, map[string]string{}, nil)
	if r.MayRetirePrevious {
		t.Fatal("retiring was allowed when NO device had been seen at all — the absence of evidence read as readiness")
	}
	if len(r.NeverSeen) != 2 || !strings.Contains(r.Note, "absence of evidence") {
		t.Fatalf("unseen devices were not reported as such: %+v", r)
	}
	// A device seen presenting neither authority is a question, not a rounding error.
	r = measureDeviceAuthorityRotation("tenant_reference_lab", dcaOld, dcaNew, enrolled,
		map[string]string{"mac-dev-1": dcaNew, "win-dev-1": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}, nil)
	if r.MayRetirePrevious || len(r.OnSomethingElse) != 1 {
		t.Fatalf("a device on a third authority did not hold the retirement: %+v", r)
	}

	// ★ THE CONTROL, and it is the whole test: when everybody HAS moved, the retirement must be allowed —
	// otherwise this is a gate that never opens and the rotation can never finish.
	r = measureDeviceAuthorityRotation("tenant_reference_lab", dcaOld, dcaNew, enrolled,
		map[string]string{"mac-dev-1": dcaNew, "win-dev-1": dcaNew}, nil)
	if !r.MayRetirePrevious {
		t.Fatalf("every device had moved and the retirement was still refused: %+v", r)
	}
	// And an organization with no rotation in flight is not "ready" either — there is nothing to retire.
	if idle := measureDeviceAuthorityRotation("tenant_reference_lab", "", "", enrolled, nil, nil); idle.Rotating ||
		idle.MayRetirePrevious {
		t.Fatalf("an organization with no rotation reported one: %+v", idle)
	}
	// Fingerprints compare case-insensitively, the way every other comparison in this tree does.
	if up := measureDeviceAuthorityRotation("t", strings.ToUpper(dcaOld), strings.ToUpper(dcaNew), enrolled,
		map[string]string{"mac-dev-1": dcaNew, "win-dev-1": dcaNew}, nil); !up.MayRetirePrevious {
		t.Fatal("a case difference in the fingerprints was read as a different authority")
	}
}

// ★★ AND THE ROTATION ITSELF: the incoming authority signs, both are anchors, and nothing is taken away
// until the retirement.
func TestARotatingDeviceAuthoritySignsWithTheNewOneAndAnchorsBoth(t *testing.T) {
	a := newTenantDeviceAuthority(nil, nil, time.Now)
	first, err := a.EnsureCA("tenant_reference_lab", "Lab Tenant")
	if err != nil {
		t.Fatalf("create the authority: %v", err)
	}
	before, err := a.IssueFor("tenant_reference_lab", time.Hour)
	if err != nil {
		t.Fatalf("issue before the rotation: %v", err)
	}
	if strings.Count(before.AnchorPEM, "BEGIN CERTIFICATE") != 1 {
		t.Fatalf("an organization with no rotation was handed more than one anchor:\n%s", before.AnchorPEM)
	}

	incoming, err := a.RotateCA("tenant_reference_lab")
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if incoming.CACertPEM == first.CACertPEM {
		t.Fatal("the rotation produced the same authority")
	}
	// One at a time, or "has everybody moved" has no single answer.
	if _, err := a.RotateCA("tenant_reference_lab"); err == nil {
		t.Fatal("a second rotation was allowed while one was already in flight")
	}

	mid, err := a.IssueFor("tenant_reference_lab", time.Hour)
	if err != nil {
		t.Fatalf("issue mid-rotation: %v", err)
	}
	if mid.CACertPEM != incoming.CACertPEM {
		t.Fatal("mid-rotation the SIGNER is not the incoming authority, so no device would ever migrate")
	}
	if strings.Count(mid.AnchorPEM, "BEGIN CERTIFICATE") != 2 {
		t.Fatalf("mid-rotation both authorities must be anchors, or every device that has not renewed is "+
			"refused at the handshake:\n%s", mid.AnchorPEM)
	}
	if !strings.Contains(mid.AnchorPEM, strings.TrimSpace(first.CACertPEM)) {
		t.Fatal("the outgoing authority stopped being an anchor while devices still hold certificates from it")
	}

	// The label survives, or the fleet is mid-rotation between two differently-named authorities.
	if !strings.Contains(deviceCALabelFrom(incoming.CACertPEM, "fallback"), "Lab Tenant") {
		t.Fatalf("the rotation lost the organization's label: %q", deviceCALabelFrom(incoming.CACertPEM, "fallback"))
	}

	promoted, err := a.RetirePrevious("tenant_reference_lab")
	if err != nil {
		t.Fatalf("retire: %v", err)
	}
	after, err := a.IssueFor("tenant_reference_lab", time.Hour)
	if err != nil {
		t.Fatalf("issue after the retirement: %v", err)
	}
	if strings.Count(after.AnchorPEM, "BEGIN CERTIFICATE") != 1 || after.CACertPEM != promoted.CACertPEM {
		t.Fatalf("after the retirement the incoming authority is not the only one:\n%s", after.AnchorPEM)
	}
	if strings.Contains(after.AnchorPEM, strings.TrimSpace(first.CACertPEM)) {
		t.Fatal("the retired authority is still an anchor")
	}
	// And retiring twice is refused rather than silently doing nothing.
	if _, err := a.RetirePrevious("tenant_reference_lab"); err == nil {
		t.Fatal("retiring with no rotation in flight was accepted")
	}
}

// ★★★ AN ORGANIZATION'S OWN OTHER AUTHORITY MUST NOT HOLD THE RETIREMENT FOR EVER (2026-08-22).
//
// Caught by running the first version of this measurement against the real lab instead of a clean room.
// tenant_reference_lab has TWO device CAs registered: one it brought itself through /admin/tenant-cas, which
// all three of its live devices present, and the managed authority the control plane holds. Those coexist by
// design. Treating the first group as "on something unknown" made retiring the SECOND impossible while a
// single device remained on the first — not a safety property, just a gate that never opens.
func TestADeviceOnTheOrganizationsOtherOwnAuthorityDoesNotHoldTheRetirement(t *testing.T) {
	const theirOwn = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	const unknown = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	enrolled := []string{"mac-dev-1", "win-dev-1", "new-laptop"}
	others := map[string]bool{theirOwn: true}

	// Two devices on the CA the customer registered itself, one enrolled under the incoming managed authority.
	r := measureDeviceAuthorityRotation("tenant_reference_lab", dcaOld, dcaNew, enrolled,
		map[string]string{"mac-dev-1": theirOwn, "win-dev-1": theirOwn, "new-laptop": dcaNew}, others)
	if !r.MayRetirePrevious {
		t.Fatalf("devices on another of the organization's own authorities blocked the retirement: %+v", r)
	}
	if len(r.OnAnotherOfTheirOwn) != 2 {
		t.Fatalf("they were not named — a denominator that shrinks silently is a gate that stopped "+
			"measuring: %+v", r)
	}
	if !strings.Contains(r.Note, "does not touch") {
		t.Fatalf("the note does not say why they do not count: %q", r.Note)
	}

	// ★ THE CONTROL, and it is what keeps this from being a hole: an authority this deployment cannot place
	// is NOT "one of their own" and still holds the retirement.
	r = measureDeviceAuthorityRotation("tenant_reference_lab", dcaOld, dcaNew, enrolled,
		map[string]string{"mac-dev-1": theirOwn, "win-dev-1": unknown, "new-laptop": dcaNew}, others)
	if r.MayRetirePrevious {
		t.Fatalf("a device on an authority this deployment cannot place did not hold the retirement: %+v", r)
	}
	if len(r.OnSomethingElse) != 1 {
		t.Fatalf("the unplaceable device was not named: %+v", r)
	}
	// And one still on the OUTGOING authority always holds it, whatever else is going on.
	r = measureDeviceAuthorityRotation("tenant_reference_lab", dcaOld, dcaNew, enrolled,
		map[string]string{"mac-dev-1": theirOwn, "win-dev-1": dcaOld, "new-laptop": dcaNew}, others)
	if r.MayRetirePrevious || len(r.StillOnOutgoing) != 1 {
		t.Fatalf("a device still on the outgoing authority did not hold the retirement: %+v", r)
	}
}

// ★★★ THE FOURTH GATE IN ONE PRODUCT TO CONFLATE TWO ZEROES (2026-08-22, measured on tenant_acme — no
// devices, a replacement started, and no way to ever finish it). The transport-name retirement, the
// authority promotion and the interception promotion had the same defect.
func TestADeviceRotationCanFinishForAnOrganizationThatHasNoDevices(t *testing.T) {
	empty := measureDeviceAuthorityRotation("t", "out", "in", nil, nil, nil)
	if !empty.MayRetirePrevious {
		t.Fatal("an organization with no device can never finish a replacement it started")
	}
	if !strings.Contains(empty.Note, "refuses nobody") {
		t.Errorf("the answer must say WHY it is allowed; \"nobody to refuse\" is not \"everybody moved\": %q", empty.Note)
	}

	// ★ And a device that exists and has not been seen still holds it shut — that is the switched-off laptop
	// this gate is for, and retiring early refuses it at the handshake.
	silent := measureDeviceAuthorityRotation("t", "out", "in", []string{"laptop-1"}, nil, nil)
	if silent.MayRetirePrevious {
		t.Error("a device that has not been seen must keep the retirement shut")
	}
}
