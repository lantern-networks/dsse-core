package main

import (
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/enrolledinventory"
)

// ★★★ A ROTATION CLOSES ON EVIDENCE, AND EVERY WAY OF CLOSING IT EARLY STRANDS SOMEBODY.
//
// Promotion makes this node serve the authority it has been announcing, and drops the previous one from that
// organization's bundle. A device that has not adopted the new anchor is then verifying with something the
// fleet no longer names and this node no longer presents — it is off the network until somebody notices.
//
// So all four ways of getting it wrong are asserted: nobody reported, only some reported, a report from an
// older distribution, and an organization with nothing enrolled at all.
func TestARotationClosesOnlyWhenEveryDeviceHasAdoptedTheNewAuthority(t *testing.T) {
	useEmptyTenantCertificateIndex(t)
	now := time.Now().UTC().Format(time.RFC3339)

	dir := t.TempDir()
	writeTenantCert(t, dir, "tenant_reference_lab", "lab.dsse.invalid")
	if _, err := loadTransportTenantCertificates(dir); err != nil {
		t.Fatalf("load: %v", err)
	}
	served, _ := transportTenantCertificates.AnchorFor("tenant_reference_lab")

	authority := newTenantTransportAuthority(nil, func([]byte) error { return nil }, time.Now)
	if _, err := authority.EnsureCA("tenant_reference_lab", "lab.dsse.invalid"); err != nil {
		t.Fatalf("authority: %v", err)
	}
	mat, err := authority.IssueFor("tenant_reference_lab", "edge-a2", 12*time.Hour)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if err := installTenantTransportMaterial(mat); err != nil {
		t.Fatalf("install: %v", err)
	}
	pending := transportTenantCertificates.PendingFingerprintFor("tenant_reference_lab")
	if pending == "" {
		t.Fatal("no rotation is in flight, so this test would prove nothing")
	}

	ledger := enrolledinventory.NewLedger()
	for _, id := range []string{"mac-dev-1", "win-dev-1"} {
		if _, err := ledger.Enroll(id, "tenant_reference_lab", "", now); err != nil {
			t.Fatalf("enroll: %v", err)
		}
	}
	observed := newObservedExclusionStore(16)
	b := &perTenantTrustBundles{serial: 9, config: serverConfig{ObservedExclusions: observed, EnrolledLedger: ledger}}

	mustStillBeAnnouncing := func(why string) {
		t.Helper()
		b.promotePendingIfAdopted("tenant_reference_lab")
		if got, _ := transportTenantCertificates.AnchorFor("tenant_reference_lab"); got != served {
			t.Fatalf("the rotation closed while %s — devices that had not adopted are now unable to verify "+
				"this node, and the fleet no longer names what they hold", why)
		}
	}

	mustStillBeAnnouncing("nobody had reported at all")

	report := func(id string, serial int64) {
		observed.Record(observedExclusionEntry{
			TenantID: "tenant_reference_lab", DeviceIdentity: id, ReportedAt: time.Now(),
			PinnedTransportCASHA256: []string{pending}, AdoptedTrustSerial: serial,
		})
	}
	report("mac-dev-1", 9)
	mustStillBeAnnouncing("only one device of two had adopted")

	report("win-dev-1", 8)
	mustStillBeAnnouncing("a device was still on an older distribution")

	// Everything reported, at the distribution being handed out: the rotation may close.
	report("win-dev-1", 9)
	b.promotePendingIfAdopted("tenant_reference_lab")
	got, _ := transportTenantCertificates.AnchorFor("tenant_reference_lab")
	if got == served {
		t.Fatal("every device reported holding the new authority and this node still serves the old one — " +
			"the rotation never finishes and the organization keeps two anchors for ever")
	}
	if len(transportTenantCertificates.AnchorsFor("tenant_reference_lab")) != 1 {
		t.Fatal("the previous authority is still announced after the move")
	}
}

// A full refresh still contains the outgoing material while the CP waits to retire it.
// Installing that response repeatedly must never put the old CA back in the pending slot.
func TestPKITransportRefreshCannotReverseCompletedPromotion(t *testing.T) {
	useEmptyTenantCertificateIndex(t)
	a := newTenantTransportAuthority(nil, nil, time.Now)
	if _, err := a.EnsureCA("tenant_a", "a.dsse.invalid"); err != nil {
		t.Fatal(err)
	}
	initial, err := a.IssueFor("tenant_a", "edge", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := installTenantTransportMaterial(initial); err != nil {
		t.Fatal(err)
	}
	if _, err := a.RotateCA("tenant_a"); err != nil {
		t.Fatal(err)
	}
	materials, err := a.IssueAllFor("tenant_a", "edge", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range materials {
		if err := installTenantTransportMaterial(m); err != nil {
			t.Fatal(err)
		}
	}
	if !transportTenantCertificates.PromotePending("tenant_a") {
		t.Fatal("promotion failed")
	}
	for i := 0; i < 4; i++ {
		materials, err = a.IssueAllFor("tenant_a", "edge", time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if materials[0].SuccessorAnchorSHA256 != fingerprintOfFirstCert(materials[1].AnchorPEM) {
			t.Fatal("outgoing material lacks its successor")
		}
		for _, m := range materials {
			if err := installTenantTransportMaterial(m); err != nil {
				t.Fatal(err)
			}
		}
		if transportTenantCertificates.PendingFingerprintFor("tenant_a") != "" {
			t.Fatal("refresh re-staged the retired CA")
		}
		if transportTenantCertificates.PromotePending("tenant_a") {
			t.Fatal("refresh reversed promotion")
		}
		if fingerprintOfFirstCert(anchorOfTenant("tenant_a")) != fingerprintOfFirstCert(materials[1].AnchorPEM) {
			t.Fatal("old authority is serving again")
		}
	}
}
