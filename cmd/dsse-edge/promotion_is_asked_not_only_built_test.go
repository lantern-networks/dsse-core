package main

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/enrolledinventory"
)

// ★★★ A GATE THAT ONLY RUNS WHEN SOMETHING ELSE CHANGES IS NOT A GATE (2026-08-20, measured on the lab).
//
// The promotion that closes an overlap — this node starts SERVING the authority it has been announcing — was
// evaluated only while building a bundle, and bundles are cached by generation. The evidence it reads arrives
// asynchronously, on the devices' own schedule. So both devices reported holding the incoming authority at the
// current distribution, and the overlap stayed open, because nothing was ever going to look again.
//
// PromoteIfAdopted is the "ask" the periodic recompute performs. This pins that it exists, that it invalidates
// the cached bundles when it fires (they name an authority this node has just stopped serving), and that
// TenantsWithPendingAuthority names exactly the organizations worth asking about.
func TestAPromotionIsAskedForRatherThanWaitedOn(t *testing.T) {
	dir := t.TempDir()
	writeTenantCACert(t, dir, "tenant_northwind", "northwind.dsse.invalid")
	useEmptyTenantCertificateIndex(t)
	if _, err := loadTransportTenantCertificates(dir); err != nil {
		t.Fatal(err)
	}
	if got := transportTenantCertificates.TenantsWithPendingAuthority(); len(got) != 0 {
		t.Fatalf("an organization with nothing in flight is named as mid-rotation: %v", got)
	}

	// A second authority arrives for the same organization: announced, not yet served.
	incoming := t.TempDir()
	writeTenantCACert(t, incoming, "tenant_acme", "northwind.dsse.invalid")
	anchorPEM, err := os.ReadFile(filepath.Join(incoming, "tenant_acme.crt"))
	if err != nil {
		t.Fatal(err)
	}
	transportTenantCertificates.putPending("tenant_northwind", []string{"northwind.dsse.invalid"},
		&tls.Certificate{}, string(anchorPEM))

	pendingTenants := transportTenantCertificates.TenantsWithPendingAuthority()
	if len(pendingTenants) != 1 || pendingTenants[0] != "tenant_northwind" {
		t.Fatalf("the organization mid-rotation is not the one a promotion pass would ask about: %v",
			pendingTenants)
	}

	// With no telemetry and no ledger there is no evidence, so nothing may promote — the safe direction, and
	// the one an empty deployment lands in.
	bundles := newPerTenantTrustBundles(serverConfig{}, "tenant_reference_lab")
	bundles.PromoteIfAdopted("tenant_northwind")
	if len(transportTenantCertificates.TenantsWithPendingAuthority()) != 1 {
		t.Fatal("an overlap closed with no evidence at all")
	}
}

// ★★★ AND NOT BEFORE THIS NODE KNOWS WHAT IT DISTRIBUTES (2026-08-20). The promotion pass runs at start-up,
// before the trust store has been read, so b.serial is 0 — and the readiness question ("did every device
// report at the CURRENT distribution") degrades to "at any distribution, ever". The lab printed its own
// weakness: "every one of its 2 device(s) reported holding it at distribution 0". Promotion starts SERVING an
// authority; accepting stale evidence for that is how a fleet locks out the devices that have not moved.
func TestNothingIsPromotedBeforeTheNodeKnowsWhatItDistributes(t *testing.T) {
	dir := t.TempDir()
	writeTenantCACert(t, dir, "tenant_northwind", "northwind.dsse.invalid")
	useEmptyTenantCertificateIndex(t)
	if _, err := loadTransportTenantCertificates(dir); err != nil {
		t.Fatal(err)
	}
	incoming := t.TempDir()
	writeTenantCACert(t, incoming, "tenant_acme", "northwind.dsse.invalid")
	anchorPEM, err := os.ReadFile(filepath.Join(incoming, "tenant_acme.crt"))
	if err != nil {
		t.Fatal(err)
	}
	transportTenantCertificates.putPending("tenant_northwind", []string{"northwind.dsse.invalid"},
		&tls.Certificate{}, string(anchorPEM))

	// Everything else says yes: every enrolled device reports holding the incoming anchor.
	ledger := enrolledinventory.NewLedger()
	mustEnroll(t, ledger, "nw-laptop-001", "tenant_northwind")
	observed := newObservedExclusionStore(0)
	observed.Record(observedExclusionEntry{TenantID: "tenant_northwind", DeviceIdentity: "nw-laptop-001",
		PinnedTransportCASHA256: []string{transportTenantCertificates.PendingFingerprintFor("tenant_northwind")},
		AdoptedTrustSerial:      99, ReportedAt: time.Now()})

	bundles := newPerTenantTrustBundles(serverConfig{ObservedExclusions: observed, EnrolledLedger: ledger},
		"tenant_reference_lab")
	bundles.PromoteIfAdopted("tenant_northwind")
	if len(transportTenantCertificates.TenantsWithPendingAuthority()) == 0 {
		t.Fatal("an overlap closed on a node that does not yet know which distribution it is serving — the " +
			"serial check degrades to 'at any distribution, ever', which is the stale evidence it exists to " +
			"reject")
	}

	// With a distribution, the same evidence promotes.
	bundles.SetTransportMaterial("", 99)
	bundles.PromoteIfAdopted("tenant_northwind")
	if len(transportTenantCertificates.TenantsWithPendingAuthority()) != 0 {
		t.Fatal("the overlap did not close even with a real distribution and complete evidence")
	}
}

// ★★★ AND IT SURVIVES A RESTART, BY READING WHAT THE FLEET ALREADY PROMISED (2026-08-20, measured on the very
// next restart after the promotion first fired).
//
// Which authority a node serves for an organization is rebuilt at boot from the files on disk plus the material
// the control plane hands over, so the file-based one goes back in front and an overlap that had CLOSED on
// evidence re-opens. The periodic pass shuts it again a minute later: two serial advances per restart, and a
// fleet flapping between two anchors and one, for nothing.
//
// The durable record already existed and was already shared — the fleet's announcement. Catching up with it is
// not a new decision, and it can only move this node ONTO an authority the signed distribution already tells
// that organization's devices to trust.
func TestANodeCatchesUpWithAnOverlapTheFleetAlreadyClosed(t *testing.T) {
	dir := t.TempDir()
	writeTenantCACert(t, dir, "tenant_northwind", "northwind.dsse.invalid")
	useEmptyTenantCertificateIndex(t)
	if _, err := loadTransportTenantCertificates(dir); err != nil {
		t.Fatal(err)
	}
	serving, _ := transportTenantCertificates.AnchorFingerprintFor("tenant_northwind")

	incoming := t.TempDir()
	writeTenantCACert(t, incoming, "tenant_acme", "northwind.dsse.invalid")
	anchorPEM, err := os.ReadFile(filepath.Join(incoming, "tenant_acme.crt"))
	if err != nil {
		t.Fatal(err)
	}
	transportTenantCertificates.putPending("tenant_northwind", []string{"northwind.dsse.invalid"},
		&tls.Certificate{}, string(anchorPEM))
	pending := transportTenantCertificates.PendingFingerprintFor("tenant_northwind")

	bundles := newPerTenantTrustBundles(serverConfig{}, "tenant_reference_lab")

	// Mid-overlap: the fleet announces BOTH, so this node has not been left behind and must not move.
	bundles.CatchUpWithTheFleet("tenant_northwind", "tenant_northwind="+serving+",tenant_northwind="+pending)
	if len(transportTenantCertificates.TenantsWithPendingAuthority()) == 0 {
		t.Fatal("a node moved on during an overlap the fleet is still publishing — nothing said the devices " +
			"had arrived")
	}

	// The fleet has moved: it names the incoming authority and no longer names the one being served.
	bundles.CatchUpWithTheFleet("tenant_northwind", "tenant_northwind="+pending)
	if len(transportTenantCertificates.TenantsWithPendingAuthority()) != 0 {
		t.Fatal("the node stayed behind the fleet: it serves an authority the signed distribution no longer " +
			"tells this organization's devices to trust, and its next restart re-opens a closed overlap")
	}
}
