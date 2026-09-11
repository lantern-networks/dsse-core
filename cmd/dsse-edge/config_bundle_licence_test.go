package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/enrolledinventory"
	"github.com/lantern-networks/dsse-core/seatallocation"
	"github.com/lantern-networks/dsse-core/vendorlicense"
)

func licenceCarryFixture(t *testing.T) (*ecdsa.PrivateKey, vendorlicense.Envelope) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	env, err := vendorlicense.Sign(testLicence(500), "vendor-1", key, licenceNow())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return key, env
}

// ★★★ THE DEFECT THIS CARRIES (measured 2026-08-27 on a running deployment). Handing an Edge a vendor key turns
// licensing on, and the licence is applied on the control plane. Nothing carried it, so:
//
//	enroll_refused reason="no valid licence is installed; enrolment is held until one is applied"
//
// every enrolment in a correctly licensed deployment, 403.
func TestTheLicenceReachesTheNodeThatEnforcesIt(t *testing.T) {
	key, env := licenceCarryFixture(t)
	accepted := []*ecdsa.PublicKey{&key.PublicKey}

	// The authority: it holds the licence, so it publishes it.
	authority := newLicenseStore()
	if _, err := authority.Apply(env, accepted, "mssp_partner_a", "adm", licenceNow().Format(time.RFC3339)); err != nil {
		t.Fatalf("the authority could not accept the licence: %v", err)
	}
	section := licenceBundleSection(authority)
	if section == nil {
		t.Fatal("a control plane holding a licence must publish it, or the Edges enforce nothing")
	}
	if section.Envelope.PayloadB64 != env.PayloadB64 {
		t.Fatal("the ENVELOPE travels, byte for byte — an Edge verifies the vendor's signature itself")
	}

	// The enforcing node: same keys, no licence yet, and its gate refuses everything.
	ledger := enrolledinventory.NewLedger()
	gate := newEnrolmentLicensing(seatallocation.NewStore(), ledger, true, false)
	gate.now = licenceNow
	if reason, refused := gate.RefuseEnrolment("tenant_a"); !refused {
		t.Fatal("an Edge told to enforce licensing with nothing to enforce must refuse; it did not")
	} else if !strings.Contains(reason, "no valid licence") {
		t.Fatalf("the refusal must name the cause; it said %q", reason)
	}

	edge := newLicenseStore()
	if !applyLicenceBundleSection(section, edge, gate, accepted, "mssp_partner_a",
		licenceNow().Format(time.RFC3339), nil) {
		t.Fatal("the carried licence was not applied on the enforcing node")
	}
	if _, refused := gate.RefuseEnrolment("tenant_a"); refused {
		t.Fatal("the licence arrived and enrolment is still held — this is the 403 the defect produced")
	}

	// Idempotent: polling the same bundle must not re-apply. Re-applying would be REFUSED by the serial rule
	// the node just set itself, and an Edge would log a verification failure every poll while correctly licensed.
	if applyLicenceBundleSection(section, edge, gate, accepted, "mssp_partner_a",
		licenceNow().Format(time.RFC3339), nil) {
		t.Fatal("carrying the same licence twice reported a change; every poll would log a refusal")
	}
}

// ★ THE ENVELOPE, NEVER A VERDICT. A node that does not accept the authority's vendor key must refuse rather
// than inherit its opinion — otherwise a control plane could raise a fleet's seat count with no vendor
// signature anywhere in the path, which is the whole reason the file is signed.
func TestANodeVerifiesTheCarriedLicenceWithItsOwnKeys(t *testing.T) {
	key, env := licenceCarryFixture(t)
	authority := newLicenseStore()
	if _, err := authority.Apply(env, []*ecdsa.PublicKey{&key.PublicKey}, "mssp_partner_a", "adm",
		licenceNow().Format(time.RFC3339)); err != nil {
		t.Fatalf("apply: %v", err)
	}
	section := licenceBundleSection(authority)

	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	ledger := enrolledinventory.NewLedger()
	gate := newEnrolmentLicensing(seatallocation.NewStore(), ledger, true, false)
	gate.now = licenceNow
	edge := newLicenseStore()

	var said string
	logf := func(format string, args ...interface{}) { said = format }
	if applyLicenceBundleSection(section, edge, gate, []*ecdsa.PublicKey{&other.PublicKey}, "mssp_partner_a",
		licenceNow().Format(time.RFC3339), logf) {
		t.Fatal("a node accepted a licence signed by a key it does not trust")
	}
	if !strings.Contains(said, "config_bundle_licence_refused") {
		t.Fatalf("the refusal must be said out loud — this node holds enrolment while others admit; log was %q", said)
	}
	// And the addressee, which is what makes sign-then-encrypt safe.
	if applyLicenceBundleSection(section, newLicenseStore(), gate, []*ecdsa.PublicKey{&key.PublicKey},
		"mssp_somebody_else", licenceNow().Format(time.RFC3339), nil) {
		t.Fatal("a node accepted a licence addressed to another MSSP")
	}
}

// ★ NIL IS "I AM NOT THE AUTHORITY", NOT "UNLICENSED". A control plane that has never been given a licence
// publishes nothing and leaves each Edge holding what it already has — publishing an empty section instead
// would let a control-plane restart disarm a licensed fleet until an operator re-applied the file.
func TestAnAuthorityWithNoLicencePublishesNothing(t *testing.T) {
	if licenceBundleSection(newLicenseStore()) != nil {
		t.Fatal("a node with no licence must publish no section")
	}
	if licenceBundleSection(nil) != nil {
		t.Fatal("no store, no section")
	}
	edge := newLicenseStore()
	if applyLicenceBundleSection(nil, edge, nil, nil, "", "", nil) {
		t.Fatal("an absent section changed something")
	}
}

// ★★★ A BUNDLE WHOSE VERSION DOES NOT MOVE IS A BUNDLE NO EDGE PULLS (measured 2026-08-27, and this is the
// SIXTH section of this bundle to learn it — see the comments around the generation sum). The licence was
// carried correctly, published in every bundle, and applied by nobody: an Edge takes a bundle only when its
// generation is greater than the last it applied, and applying a licence changed the contents without changing
// the number.
func TestApplyingALicenceMovesTheBundleVersion(t *testing.T) {
	key, env := licenceCarryFixture(t)
	store := newLicenseStore()
	if store.ConfigGeneration() != 0 {
		t.Fatalf("a deployment with no licence contributes nothing; got %d", store.ConfigGeneration())
	}
	if _, err := store.Apply(env, []*ecdsa.PublicKey{&key.PublicKey}, "mssp_partner_a", "adm",
		licenceNow().Format(time.RFC3339)); err != nil {
		t.Fatalf("apply: %v", err)
	}
	first := store.ConfigGeneration()
	if first == 0 {
		t.Fatal("applying a licence did not move this store's term — every Edge would skip the bundle carrying it")
	}

	// A re-issue moves it again. The term is the accepted serial, which is already persisted and already
	// refuses to go backwards, so a restart cannot lower the sum — and a sum that goes down is a fleet that
	// never pulls again.
	next := testLicence(900)
	next.Serial = 7
	renewed, err := vendorlicense.Sign(next, "vendor-1", key, licenceNow())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := store.Apply(renewed, []*ecdsa.PublicKey{&key.PublicKey}, "mssp_partner_a", "adm",
		licenceNow().Format(time.RFC3339)); err != nil {
		t.Fatalf("re-issue: %v", err)
	}
	if store.ConfigGeneration() <= first {
		t.Fatalf("a re-issued licence must move the version forward; %d -> %d", first, store.ConfigGeneration())
	}
}
