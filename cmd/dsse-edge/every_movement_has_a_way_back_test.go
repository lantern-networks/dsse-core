package main

import "testing"

// ★★★ EVERY MOVEMENT NEEDS A WAY BACK, AND TWO OF THE THREE TIERS DID NOT HAVE ONE (2026-08-22, found by
// reading the multi-tenant PKI roadmap against the tree).
//
// Interception could WithdrawIncoming and the transport RENAME could AbandonRename. A transport CA rotation
// and a device CA rotation could only be ENDED by retiring the previous authority — the destructive half — so
// an operator who staged the wrong CA had a choice between leaving it announced for ever and completing a
// rotation they no longer wanted.
//
// The two tiers abandon DIFFERENTLY, and the difference is the whole point:
//
//	transport  an incoming CA is only ANNOUNCED; nothing is served under it until a promotion, so dropping
//	           it takes nothing away from any device.
//	device     an incoming CA SIGNS from the moment the rotation starts — that is how devices migrate — so
//	           by the time anybody abandons, real devices hold real certificates from it. It stops signing
//	           and stays admitted.
func TestATransportRotationCanBeAbandonedAndTakesNothingAway(t *testing.T) {
	a := newTenantTransportAuthority(nil, func([]byte) error { return nil }, nil)
	if _, err := a.EnsureCA("tenant_x", "x.dsse.invalid"); err != nil {
		t.Fatalf("EnsureCA: %v", err)
	}
	if _, err := a.AbandonRotation("tenant_x"); err == nil {
		t.Fatal("abandoning with no rotation in flight must be refused, not silently succeed")
	}
	before, _, _, _, _ := a.StateFor("tenant_x")
	if _, err := a.RotateCA("tenant_x"); err != nil {
		t.Fatalf("RotateCA: %v", err)
	}
	if _, _, _, rotating, _ := a.StateFor("tenant_x"); !rotating {
		t.Fatal("the rotation did not start — the abandonment below would prove nothing")
	}
	if _, err := a.AbandonRotation("tenant_x"); err != nil {
		t.Fatalf("AbandonRotation: %v", err)
	}
	name, _, _, rotating, known := a.StateFor("tenant_x")
	if !known || rotating {
		t.Fatalf("after abandoning, the organization is on ONE authority and not rotating (known=%v rotating=%v)", known, rotating)
	}
	if name != before {
		t.Fatalf("abandoning changed the name the organization is served under: %q -> %q", before, name)
	}
}

func TestADeviceRotationAbandonsWithoutRefusingTheDevicesThatMoved(t *testing.T) {
	a := newTenantDeviceAuthority(nil, func([]byte) error { return nil }, nil)
	if _, err := a.EnsureCA("tenant_x", "Tenant X"); err != nil {
		t.Fatalf("EnsureCA: %v", err)
	}
	inForce, err := a.IssueFor("tenant_x", 0)
	if err != nil {
		t.Fatalf("IssueFor: %v", err)
	}
	if _, err := a.RotateCA("tenant_x"); err != nil {
		t.Fatalf("RotateCA: %v", err)
	}
	mid, err := a.IssueFor("tenant_x", 0)
	if err != nil {
		t.Fatalf("IssueFor during the rotation: %v", err)
	}
	if mid.CACertPEM == inForce.CACertPEM {
		t.Fatal("the incoming authority must SIGN during a rotation — otherwise devices never migrate, and " +
			"this test would not be about the case that makes abandoning hard")
	}

	if _, err := a.AbandonRotation("tenant_x"); err != nil {
		t.Fatalf("AbandonRotation: %v", err)
	}
	after, err := a.IssueFor("tenant_x", 0)
	if err != nil {
		t.Fatalf("IssueFor after abandoning: %v", err)
	}
	if after.CACertPEM != inForce.CACertPEM {
		t.Fatal("after abandoning, new certificates must come from the authority in force again")
	}
	// ★ AND THE ABANDONED ONE IS STILL ADMITTED. A device that enrolled during the overlap holds a
	// certificate from it; dropping the anchor refuses exactly the devices that did what they were told.
	if !containsPEMOf(after.AnchorPEM, mid.CACertPEM) {
		t.Fatal("the abandoned authority stopped being an anchor — every device issued during the overlap " +
			"is now refused at the handshake")
	}
	if !containsPEMOf(after.AnchorPEM, inForce.CACertPEM) {
		t.Fatal("the authority in force stopped being an anchor")
	}

	// ★ And retiring after an abandonment DROPS the abandoned one rather than promoting it — promoting would
	// install the very authority the operator just gave up on.
	if _, err := a.RetirePrevious("tenant_x"); err != nil {
		t.Fatalf("RetirePrevious after abandoning: %v", err)
	}
	end, err := a.IssueFor("tenant_x", 0)
	if err != nil {
		t.Fatalf("IssueFor after retiring: %v", err)
	}
	if end.CACertPEM != inForce.CACertPEM {
		t.Fatal("retiring after an abandonment promoted the abandoned authority")
	}
	if containsPEMOf(end.AnchorPEM, mid.CACertPEM) {
		t.Fatal("the abandoned authority is still an anchor after being retired")
	}
}

func containsPEMOf(anchors, one string) bool {
	for _, c := range certificatesInPEM([]byte(anchors)) {
		for _, w := range certificatesInPEM([]byte(one)) {
			if certFingerprint(c) == certFingerprint(w) {
				return true
			}
		}
	}
	return false
}
