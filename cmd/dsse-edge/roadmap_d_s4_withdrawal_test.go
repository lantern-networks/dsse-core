package main

import (
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/enrolledinventory"
)

// ★★★ ROADMAP D, S4 — AND THE HALF THAT MATTERS IS THE REFUSAL.
//
// While the shared transport anchor sits in an organization's trust bundle, whoever holds that anchor can
// impersonate this Edge to that organization's devices. D ends by taking it out of their bundle — but ONLY
// once every one of their devices has been measured holding the organization's own, because a device that
// has not taken it verifies against what it kept, and what it kept is about to stop being announced.
//
// Every "no" here is a device that would otherwise be left unable to verify its own Edge, so they are all
// asserted: silence, a device on an older distribution, an organization with nothing enrolled, and an
// organization mid-rotation with two anchors of its own.
func TestTheSharedAnchorLeavesAnOrganizationsBundleOnlyOnACompleteAnswer(t *testing.T) {
	useEmptyTenantCertificateIndex(t)
	now := time.Now().UTC().Format(time.RFC3339)

	ledger := enrolledinventory.NewLedger()
	for _, id := range []string{"mac-dev-1", "win-dev-1", "conn_lab_001"} {
		if _, err := ledger.Enroll(id, "tenant_reference_lab", "", now); err != nil {
			t.Fatalf("enroll %s: %v", id, err)
		}
	}
	if _, ok, err := ledger.SetKind("conn_lab_001", enrolledinventory.KindService, now); err != nil || !ok {
		t.Fatalf("declare the connector: ok=%v err=%v", ok, err)
	}

	// One organization with a certificate of its own, written and loaded exactly as the Edge loads them.
	dir := t.TempDir()
	writeTenantCert(t, dir, "tenant_reference_lab", "lab.dsse.invalid")
	if n, err := loadTransportTenantCertificates(dir); err != nil || n != 1 {
		t.Fatalf("loaded %d (%v)", n, err)
	}
	fp, ok := transportTenantCertificates.AnchorFingerprintFor("tenant_reference_lab")
	if !ok {
		t.Fatal("the organization's own anchor produced no fingerprint — nothing can be measured against it")
	}

	observed := newObservedExclusionStore(16)
	b := &perTenantTrustBundles{
		serial: 7,
		config: serverConfig{ObservedExclusions: observed, EnrolledLedger: ledger},
	}

	// Nobody has reported: the shared anchor stays.
	if b.sharedAnchorMayBeWithdrawn("tenant_reference_lab") {
		t.Fatal("the shared anchor was withdrawn while every device was silent — silence is not adoption, and " +
			"those devices verify with whatever they kept")
	}

	// ★★★ AND THE NAME IT DIALS, NOT ONLY THE ANCHOR IT HOLDS (2026-08-22, added after this gate took the lab
	// fleet silent). See sharedAnchorMayBeWithdrawn: a device that is still reaching this deployment on a name
	// served under the SHARED certificate needs the shared anchor, however completely it holds its own.
	own, _ := transportTenantCertificates.ServerNameFor("tenant_reference_lab")
	if strings.TrimSpace(own) == "" {
		t.Fatal("the organization has no transport name — the door half of this gate cannot be measured")
	}
	report := func(id string, serial int64) {
		observed.Record(observedExclusionEntry{
			TenantID: "tenant_reference_lab", DeviceIdentity: id, ReportedAt: time.Now(),
			PinnedTransportCASHA256: []string{fp}, AdoptedTrustSerial: serial,
			TransportServerNameSent: own,
		})
	}
	report("mac-dev-1", 7)
	if b.sharedAnchorMayBeWithdrawn("tenant_reference_lab") {
		t.Fatal("one device out of two was enough to withdraw it")
	}

	// ★★★ REVERSED ON 2026-08-20, WITH THE MEASUREMENT THAT FORCED IT. This case used to assert that a device
	// reporting an OLDER distribution could not count, however good its fingerprints were — the rule the
	// promotion gate still follows.
	//
	// It cannot be the rule here, because this decision is PUBLISHED and REVERSIBLE. Withdrawing the shared
	// anchor changes the announcement, which advances the serial, which under a serial-pinned reading makes
	// every device's report stale at once, which un-withdraws it, which advances the serial again. Measured on
	// the lab the minute the withdrawal was finally made visible to the announcement: 88, 89, 90, one per
	// minute, with the shared anchor flapping in and out of two devices' trust sets. The gate was feeding
	// itself its own output.
	//
	// What this gate needs to know is whether the device HOLDS its organization's own authority, and a device
	// can only have got that from a distribution that carried it. Which distribution it last reported is a
	// different fact. Freshness still applies — the shelf life below — so a machine that has been switched off
	// does not open the gate.
	report("win-dev-1", 6)
	if !b.sharedAnchorMayBeWithdrawn("tenant_reference_lab") {
		t.Fatal("a device that reports HOLDING its organization's own authority did not count because its last " +
			"report named an older distribution — the withdrawal then advances the serial and un-does itself")
	}

	// ★★★ THE CASE THAT WAS MISSING, AND THAT COST THE LAB ITS WHOLE MEASUREMENT PLANE (2026-08-22).
	//
	// Every device held its organization's own authority, so the shared anchor left the bundle — and both
	// devices stopped reporting within seconds of each other, because they were still reaching this deployment
	// on a name the SHARED certificate serves. Browsing kept working, so nothing looked wrong; every readiness
	// measurement in the product runs on those reports, so every rotation and every rename quietly froze. The
	// self-healing the gate promises is fed by the reports that just stopped, and a report counts as silence
	// only after fourteen days.
	observed.Record(observedExclusionEntry{
		TenantID: "tenant_reference_lab", DeviceIdentity: "win-dev-1", ReportedAt: time.Now(),
		PinnedTransportCASHA256: []string{fp}, AdoptedTrustSerial: 7,
		TransportServerNameSent: "shinmac-mini.example.invalid",
	})
	if b.sharedAnchorMayBeWithdrawn("tenant_reference_lab") {
		t.Fatal("the shared anchor was withdrawn while a device was still dialling a name the shared " +
			"certificate serves — that device loses its only way to reach this deployment, including the " +
			"reports this gate reads to undo itself")
	}
	// And a device that has not SAID which name it dials is not evidence, exactly as elsewhere.
	observed.Record(observedExclusionEntry{
		TenantID: "tenant_reference_lab", DeviceIdentity: "win-dev-1", ReportedAt: time.Now(),
		PinnedTransportCASHA256: []string{fp}, AdoptedTrustSerial: 7,
	})
	if b.sharedAnchorMayBeWithdrawn("tenant_reference_lab") {
		t.Fatal("silence about the name a device dials was read as \"it dials our own\"")
	}
	report("win-dev-1", 7)
	if !b.sharedAnchorMayBeWithdrawn("tenant_reference_lab") {
		t.Fatal("every device holds its own authority AND reports dialling its own name; the withdrawal is " +
			"exactly what the enrolment fold makes safe, and it must be allowed")
	}

	// And a report older than the shelf life is silence, whatever it says.
	observed.Record(observedExclusionEntry{
		TenantID: "tenant_reference_lab", DeviceIdentity: "win-dev-1",
		ReportedAt:              time.Now().Add(-2 * transportCAReportShelfLife),
		PinnedTransportCASHA256: []string{fp}, AdoptedTrustSerial: 7,
	})
	if b.sharedAnchorMayBeWithdrawn("tenant_reference_lab") {
		t.Fatal("a device that has not been heard from in weeks counted as holding the anchor")
	}

	// Both current: the connector is not counted (it reads no bundle), so this is complete.
	report("win-dev-1", 7)
	if !b.sharedAnchorMayBeWithdrawn("tenant_reference_lab") {
		t.Fatal("every device that adopts bundles holds the organization's own anchor and the shared one was " +
			"still being handed out — roadmap D never finishes")
	}

	// And it must come BACK when the answer stops being complete: a device enrols and has not reported.
	if _, err := ledger.Enroll("mac-dev-2", "tenant_reference_lab", "", now); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if b.sharedAnchorMayBeWithdrawn("tenant_reference_lab") {
		t.Fatal("a newly enrolled device did not put the overlap back — a withdrawal that cannot undo itself " +
			"is one nobody should make automatically")
	}

	// An organization with nothing enrolled is not "everybody holds it".
	if b.sharedAnchorMayBeWithdrawn("tenant_nobody") {
		t.Fatal("an organization with no devices had the shared anchor withdrawn from the bundle its first " +
			"device will read")
	}

}

// ★★★ AN ORGANIZATION WITH NO DEVICES COULD NEVER FINISH A ROTATION EITHER (2026-08-22, measured on
// tenant_northwind, one tier over from the rename gate that had the same defect).
//
// The promotion refused with "no devices to strand — but also nothing measured". Both halves true, the
// conclusion wrong: keeping the overlap looked free, and it also freezes which certificate the node SERVES
// and therefore which NAME it answers to. The rename completed on the control plane and the wire answered the
// old name for ever.
func TestARotationCanCloseForAnOrganizationThatHasNoDevices(t *testing.T) {
	restore := transportTenantCertificates
	transportTenantCertificates = newTransportTenantCerts()
	t.Cleanup(func() { transportTenantCertificates = restore })

	// Real material: PendingFingerprintFor parses the anchor, so a placeholder string would make this test
	// pass or fail for a reason that has nothing to do with the rule being pinned down.
	authority := newTenantTransportAuthority(nil, func([]byte) error { return nil }, nil)
	if _, err := authority.EnsureCA("tenant_empty", "old.invalid"); err != nil {
		t.Fatalf("EnsureCA: %v", err)
	}
	inForce, err := authority.IssueFor("tenant_empty", "edge-a", time.Hour)
	if err != nil {
		t.Fatalf("IssueFor: %v", err)
	}
	if err := installTenantTransportMaterial(inForce); err != nil {
		t.Fatalf("install in force: %v", err)
	}
	if _, err := authority.RotateCA("tenant_empty"); err != nil {
		t.Fatalf("RotateCA: %v", err)
	}
	mats, err := authority.IssueAllFor("tenant_empty", "edge-a", time.Hour)
	if err != nil || len(mats) != 2 {
		t.Fatalf("IssueAllFor: %d (%v)", len(mats), err)
	}
	if err := installTenantTransportMaterial(mats[1]); err != nil {
		t.Fatalf("install incoming: %v", err)
	}
	if transportTenantCertificates.PendingFingerprintFor("tenant_empty") == "" {
		t.Fatal("nothing is pending, so the promotion below would be refused for the wrong reason")
	}

	observed := newObservedExclusionStore(16)
	ledger := enrolledinventory.NewLedger()
	ledger.ReplaceAll([]enrolledinventory.Entry{}, "")
	b := &perTenantTrustBundles{serial: 9,
		config: serverConfig{ObservedExclusions: observed, EnrolledLedger: ledger}}

	if !b.promotePendingIfAdopted("tenant_empty") {
		t.Fatal("an organization with no enrolled device can never finish a rotation, so its name is frozen " +
			"for ever while the control plane reports the rename complete")
	}
	if transportTenantCertificates.PendingFingerprintFor("tenant_empty") != "" {
		t.Error("the promotion did not close the overlap; the organization is still mid-rotation")
	}
}
