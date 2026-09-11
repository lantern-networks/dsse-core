package vendorlicense

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
	"time"
)

func testNow() time.Time { return time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC) }

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	return k
}

// A first order: twelve months of term, a further month before enrolment stops, and service ending three
// months after that — long enough that a renewal in the post never reaches it, short enough that a holder who
// has stopped paying does not keep the product indefinitely.
func paidPayload() Payload {
	now := testNow()
	return Payload{
		MSSPID:           "mssp_partner_a",
		Serial:           1,
		Grants:           []Grant{{Seats: 5000, EndsAt: now.AddDate(0, 13, 0).Format(time.RFC3339)}},
		IssuedAt:         now.Format(time.RFC3339),
		ExpiresAt:        now.AddDate(0, 12, 0).Format(time.RFC3339),
		EnrolmentStopsAt: now.AddDate(0, 13, 0).Format(time.RFC3339),
		ServiceEndsAt:    now.AddDate(0, 16, 0).Format(time.RFC3339),
	}
}

func evalPayload() Payload {
	now := testNow()
	return Payload{
		MSSPID:           "mssp_prospect_b",
		Serial:           1,
		Grants:           []Grant{{Seats: 25, EndsAt: now.AddDate(0, 0, 30).Format(time.RFC3339)}},
		IssuedAt:         now.Format(time.RFC3339),
		ExpiresAt:        now.AddDate(0, 0, 30).Format(time.RFC3339),
		EnrolmentStopsAt: now.AddDate(0, 0, 30).Format(time.RFC3339),
		ServiceEndsAt:    now.AddDate(0, 0, 37).Format(time.RFC3339),
		IsEvaluation:     true,
	}
}

func sign(t *testing.T, p Payload, k *ecdsa.PrivateKey) Envelope {
	t.Helper()
	env, err := Sign(p, "jv-key-1", k, testNow())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return env
}

func TestAValidLicenceVerifies(t *testing.T) {
	k := newKey(t)
	got, err := Verify(sign(t, paidPayload(), k), []*ecdsa.PublicKey{&k.PublicKey}, "mssp_partner_a", 0)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.SeatsAt(testNow()) != 5000 || got.Serial != 1 {
		t.Fatalf("payload did not survive the round trip: %+v", got)
	}
}

// The reason accepted keys are a LIST. A holder that accepts one key has no recovery from that key leaking
// except updating every deployment by hand, and this cannot be retrofitted once software is in the field.
func TestAnyAcceptedVendorKeyMayHaveSignedIt(t *testing.T) {
	primary, secondary := newKey(t), newKey(t)
	accepted := []*ecdsa.PublicKey{&primary.PublicKey, &secondary.PublicKey}

	for _, signer := range []*ecdsa.PrivateKey{primary, secondary} {
		if _, err := Verify(sign(t, paidPayload(), signer), accepted, "mssp_partner_a", 0); err != nil {
			t.Fatalf("a licence from either accepted key must verify: %v", err)
		}
	}
	// And a key nobody accepted must not.
	stranger := newKey(t)
	if _, err := Verify(sign(t, paidPayload(), stranger), accepted, "mssp_partner_a", 0); err == nil {
		t.Fatalf("a licence signed by an unaccepted key must be refused")
	}
}

// The only realistic attack on a file is presenting an older one with more seats.
func TestAnOlderSerialIsRefused(t *testing.T) {
	k := newKey(t)
	old := paidPayload()
	old.Serial = 3
	old.Grants[0].Seats = 100000
	if _, err := Verify(sign(t, old, k), []*ecdsa.PublicKey{&k.PublicKey}, "mssp_partner_a", 3); err == nil {
		t.Fatalf("a serial that does not advance must be refused")
	}
	if _, err := Verify(sign(t, old, k), []*ecdsa.PublicKey{&k.PublicKey}, "mssp_partner_a", 2); err != nil {
		t.Fatalf("a serial that does advance must be accepted: %v", err)
	}
}

// Signing before encrypting lets a recipient re-encrypt the same signed licence to somebody else. Naming the
// holder inside the signed body is what closes that.
func TestALicenceAddressedElsewhereIsRefused(t *testing.T) {
	k := newKey(t)
	env := sign(t, paidPayload(), k)
	if _, err := Verify(env, []*ecdsa.PublicKey{&k.PublicKey}, "mssp_someone_else", 0); err == nil {
		t.Fatalf("a licence for another holder must be refused")
	}
	if _, err := Verify(env, []*ecdsa.PublicKey{&k.PublicKey}, "MSSP_PARTNER_A", 0); err != nil {
		t.Fatalf("the holder check must not be case-sensitive: %v", err)
	}
}

func TestATamperedPayloadIsRefused(t *testing.T) {
	k := newKey(t)
	env := sign(t, paidPayload(), k)
	env.PayloadB64 = strings.Replace(env.PayloadB64, "A", "B", 1)
	if _, err := Verify(env, []*ecdsa.PublicKey{&k.PublicKey}, "mssp_partner_a", 0); err == nil {
		t.Fatalf("an altered payload must be refused")
	}
}

// ★ Every licence must say when service ends. One that does not is a product given away: a holder who stops
// paying would keep running for ever, and there would be no business left to protect.
func TestALicenceWithNoServiceEndIsRefused(t *testing.T) {
	k := newKey(t)
	for _, p := range []Payload{paidPayload(), evalPayload()} {
		p.ServiceEndsAt = ""
		if _, err := Verify(sign(t, p, k), []*ecdsa.PublicKey{&k.PublicKey}, p.MSSPID, 0); err == nil {
			t.Fatalf("a licence that never ends must be refused (evaluation=%v)", p.IsEvaluation)
		}
	}
}

// ★ What IS enforced is the order of the steps. A holder must always meet the reversible consequence — no new
// devices — before the expensive one, and never be surprised by them arriving the other way round.
func TestServiceMayNotEndBeforeEnrolmentStops(t *testing.T) {
	k := newKey(t)
	p := paidPayload()
	p.ServiceEndsAt = testNow().AddDate(0, 12, 15).Format(time.RFC3339) // before enrolment_stops_at
	if _, err := Verify(sign(t, p, k), []*ecdsa.PublicKey{&k.PublicKey}, "mssp_partner_a", 0); err == nil {
		t.Fatalf("service ending before enrolment stops puts the steps out of order")
	}
}

func TestAnEvaluationMustSayWhenServiceEnds(t *testing.T) {
	k := newKey(t)
	p := evalPayload()
	p.ServiceEndsAt = ""
	if _, err := Verify(sign(t, p, k), []*ecdsa.PublicKey{&k.PublicKey}, "mssp_prospect_b", 0); err == nil {
		t.Fatalf("an evaluation with no end never ends, which is the thing this prevents")
	}
	// And it has to end AFTER the expiry, so there is a window in which to warn. Protection vanishing without
	// notice is the worst outcome available here.
	p = evalPayload()
	p.ServiceEndsAt = p.ExpiresAt
	if _, err := Verify(sign(t, p, k), []*ecdsa.PublicKey{&k.PublicKey}, "mssp_prospect_b", 0); err == nil {
		t.Fatalf("an evaluation must leave time to warn before service stops")
	}
}

// The runway is what protects an honest holder, not an absence of consequences. A renewal that is late by a
// month, or a payment argued over for two, must not take a deployment down — so service keeps running well past
// the point where new devices are refused, and only stops at the date the signed licence declared all along.
func TestAPaidLicenceKeepsServingThroughALateRenewal(t *testing.T) {
	p := paidPayload()
	for _, at := range []time.Time{
		testNow(),
		testNow().AddDate(0, 12, 1),  // a fortnight late: warned, still growing
		testNow().AddDate(0, 13, 1),  // a month late: cannot grow, still serving
		testNow().AddDate(0, 15, 25), // nearly four months late: still serving
	} {
		if !p.MaySteerTraffic(at) {
			t.Fatalf("a late renewal must not take the deployment down (at %s)", at)
		}
	}
	// And past the declared end, it stops. Nothing was decided after the fact — this date was in the file the
	// holder installed on day one.
	if p.MaySteerTraffic(testNow().AddDate(0, 16, 1)) {
		t.Fatalf("past its declared service end a paid licence must stop steering, or the product is free")
	}
}

func TestPaidLicenceStatesAcrossItsLife(t *testing.T) {
	p := paidPayload()
	cases := []struct {
		at    time.Time
		state State
		enrol bool
	}{
		{testNow(), Active, true},
		{testNow().AddDate(0, 11, 29), Active, true},
		{testNow().AddDate(0, 12, 1), Expired, true},            // grace: still enrolling, but warned
		{testNow().AddDate(0, 13, 1), EnrolmentStopped, false},  // no new devices; existing ones untouched
		{testNow().AddDate(0, 15, 25), EnrolmentStopped, false}, // still only that, right up to the end
		{testNow().AddDate(0, 16, 1), ServiceEnded, false},      // the declared end
	}
	for _, c := range cases {
		if got := p.StateAt(c.at); got != c.state {
			t.Errorf("at %s: state %v, want %v", c.at, got, c.state)
		}
		if got := p.MayEnrolNewDevices(c.at); got != c.enrol {
			t.Errorf("at %s: may enrol %v, want %v", c.at, got, c.enrol)
		}
	}
}

// An evaluation is the ONLY thing that stops serving, and only after its declared date.
func TestEvaluationStatesAcrossItsLife(t *testing.T) {
	p := evalPayload()
	if !p.MaySteerTraffic(testNow().AddDate(0, 0, 31)) {
		t.Fatalf("an expired evaluation must keep steering until its declared service end — that week is the warning")
	}
	if p.MayEnrolNewDevices(testNow().AddDate(0, 0, 31)) {
		t.Fatalf("an expired evaluation must not enrol new devices")
	}
	if got := p.StateAt(testNow().AddDate(0, 0, 38)); got != ServiceEnded {
		t.Fatalf("past its service end an evaluation is over, got %v", got)
	}
	if p.MaySteerTraffic(testNow().AddDate(0, 0, 38)) {
		t.Fatalf("an evaluation past its service end must stop steering")
	}
}

// An evaluation may be extended, and extension is nothing more than a higher serial. Nothing about ending is
// destructive, so the same devices carry on — that is what keeps a POC from having to re-enrol every machine.
func TestAnExtensionIsJustTheNextSerial(t *testing.T) {
	k := newKey(t)
	first := evalPayload()
	if _, err := Verify(sign(t, first, k), []*ecdsa.PublicKey{&k.PublicKey}, "mssp_prospect_b", 0); err != nil {
		t.Fatalf("first evaluation: %v", err)
	}
	ext := evalPayload()
	ext.Serial = 2
	ext.ExpiresAt = testNow().AddDate(0, 0, 60).Format(time.RFC3339)
	ext.EnrolmentStopsAt = ext.ExpiresAt
	ext.ServiceEndsAt = testNow().AddDate(0, 0, 67).Format(time.RFC3339)
	got, err := Verify(sign(t, ext, k), []*ecdsa.PublicKey{&k.PublicKey}, "mssp_prospect_b", 1)
	if err != nil {
		t.Fatalf("an extension must verify against the previous serial: %v", err)
	}
	// The day the first evaluation would have stopped serving, the extension is still serving.
	if !got.MaySteerTraffic(testNow().AddDate(0, 0, 38)) {
		t.Fatalf("an extension must resume service past the old end date")
	}

	// Converting to paid is the same move: a higher serial and much longer dates.
	paid := paidPayload()
	paid.MSSPID = "mssp_prospect_b"
	paid.Serial = 3
	converted, err := Verify(sign(t, paid, k), []*ecdsa.PublicKey{&k.PublicKey}, "mssp_prospect_b", 2)
	if err != nil {
		t.Fatalf("conversion to paid must verify: %v", err)
	}
	if converted.IsEvaluation || !converted.MaySteerTraffic(testNow().AddDate(0, 15, 0)) {
		t.Fatalf("a converted licence is an ordinary paid one and serves for its full term")
	}
}

func TestMalformedLicencesAreRefused(t *testing.T) {
	k := newKey(t)
	cases := map[string]func(p *Payload){
		"no holder":                 func(p *Payload) { p.MSSPID = "" },
		"no serial":                 func(p *Payload) { p.Serial = 0 },
		"no seats":                  func(p *Payload) { p.Grants = nil },
		"a grant with no seats":     func(p *Payload) { p.Grants[0].Seats = 0 },
		"only optional capability":  func(p *Payload) { p.Grants[0].Feature = "dspm" },
		"unparseable expiry":        func(p *Payload) { p.ExpiresAt = "next tuesday" },
		"stops enrolling too early": func(p *Payload) { p.EnrolmentStopsAt = testNow().AddDate(0, 6, 0).Format(time.RFC3339) },
	}
	for name, mangle := range cases {
		p := paidPayload()
		mangle(&p)
		if _, err := Verify(sign(t, p, k), []*ecdsa.PublicKey{&k.PublicKey}, "mssp_partner_a", 0); err == nil {
			t.Errorf("%s: must be refused", name)
		}
	}
}

func TestVerifyingWithNoConfiguredKeyIsRefused(t *testing.T) {
	k := newKey(t)
	if _, err := Verify(sign(t, paidPayload(), k), nil, "mssp_partner_a", 0); err == nil {
		t.Fatalf("with no vendor key configured nothing can be verified, and must not be assumed valid")
	}
}

func TestPublicKeysParseAsAList(t *testing.T) {
	var sb strings.Builder
	var want []*ecdsa.PublicKey
	for i := 0; i < 2; i++ {
		k := newKey(t)
		der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		sb.Write(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
		want = append(want, &k.PublicKey)
	}
	got, err := ParsePublicKeysPEM(sb.String())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("both keys must parse, got %d", len(got))
	}
	if _, err := ParsePublicKeysPEM("not a pem"); err == nil {
		t.Fatalf("a file with no key must be an error, not an empty accept-list that verifies nothing")
	}
}

// ★ A holder buys 10,000 seats for two years and adds 5,000 that only cover the second. A single seat count
// cannot say that — it would either expire the original seats early or keep the extra ones past what was paid
// for — which is why entitlement is a list of blocks.
func TestSeatsAddedMidTermCoverOnlyTheirOwnPeriod(t *testing.T) {
	k := newKey(t)
	now := testNow()
	p := Payload{
		MSSPID:   "mssp_partner_a",
		Serial:   2, // an addition is a RE-ISSUE carrying every block, not a delta
		IssuedAt: now.Format(time.RFC3339),
		Grants: []Grant{
			{Seats: 10000, EndsAt: now.AddDate(0, 24, 0).Format(time.RFC3339)},
			{Seats: 5000,
				StartsAt: now.AddDate(0, 12, 0).Format(time.RFC3339),
				EndsAt:   now.AddDate(0, 24, 0).Format(time.RFC3339)},
		},
		ExpiresAt:        now.AddDate(0, 24, 0).Format(time.RFC3339),
		EnrolmentStopsAt: now.AddDate(0, 25, 0).Format(time.RFC3339),
		ServiceEndsAt:    now.AddDate(0, 28, 0).Format(time.RFC3339),
	}
	got, err := Verify(sign(t, p, k), []*ecdsa.PublicKey{&k.PublicKey}, "mssp_partner_a", 1)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	for _, c := range []struct {
		when  time.Time
		seats int
		note  string
	}{
		{now, 10000, "year one: the base only"},
		{now.AddDate(0, 11, 29), 10000, "the day before the addition starts"},
		{now.AddDate(0, 12, 1), 15000, "year two: base plus addition"},
		{now.AddDate(0, 24, 1), 0, "both blocks have ended"},
	} {
		if seats := got.SeatsAt(c.when); seats != c.seats {
			t.Errorf("%s: %d seats, want %d", c.note, seats, c.seats)
		}
	}
	// Running out of seats refuses new enrolments; it never stops serving. That distinction is the whole of the
	// no-outage promise, so it is asserted here too rather than only where the dates are checked.
	if !got.MaySteerTraffic(now.AddDate(0, 24, 1)) {
		t.Fatalf("seats lapsing must not stop service — that is what the service end is for")
	}
}

// An optional module is bought for PART of a fleet, for PART of the term. Summing it into the seat count would
// silently grant enrolment capacity nobody bought, so a block that names a feature adds capability and not
// capacity.
func TestAnOptionalCapabilityCoversOnlyTheSeatsItWasBoughtFor(t *testing.T) {
	k := newKey(t)
	now := testNow()
	p := paidPayload()
	p.Grants = []Grant{
		{Seats: 5000, EndsAt: now.AddDate(0, 13, 0).Format(time.RFC3339)},
		{Seats: 2000, Feature: "dspm", EndsAt: now.AddDate(0, 6, 0).Format(time.RFC3339)},
	}
	got, err := Verify(sign(t, p, k), []*ecdsa.PublicKey{&k.PublicKey}, "mssp_partner_a", 0)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if seats := got.SeatsAt(now); seats != 5000 {
		t.Fatalf("a capability block must not add enrolment capacity: got %d, want 5000", seats)
	}
	if seats := got.SeatsForFeatureAt("dspm", now); seats != 2000 {
		t.Fatalf("dspm covers 2000 seats, got %d", seats)
	}
	if got.SeatsForFeatureAt("DSPM", now) != 2000 {
		t.Fatalf("a capability name must not be case-sensitive")
	}
	if got.SeatsForFeatureAt("ai-quarantine", now) != 0 {
		t.Fatalf("a capability nobody bought is not licensed")
	}
	// Past the module's own end it lapses, while the base seats carry on.
	after := now.AddDate(0, 6, 1)
	if got.SeatsForFeatureAt("dspm", after) != 0 {
		t.Fatalf("a lapsed capability is not licensed")
	}
	if got.SeatsAt(after) != 5000 {
		t.Fatalf("a lapsed capability must not touch enrolment capacity")
	}
	if len(got.FeaturesAt(now)) != 1 || got.FeaturesAt(now)[0] != "dspm" {
		t.Fatalf("features in force: %v", got.FeaturesAt(now))
	}
	if len(got.FeaturesAt(after)) != 0 {
		t.Fatalf("nothing is in force after it lapsed: %v", got.FeaturesAt(after))
	}
}

// Bundles are spelled out as separate blocks rather than inferred, so "5,000 seats with DSPM included" cannot be
// read two ways.
func TestABundleIsTwoBlocks(t *testing.T) {
	now := testNow()
	p := paidPayload()
	p.Grants = []Grant{
		{Seats: 5000, EndsAt: now.AddDate(0, 13, 0).Format(time.RFC3339)},
		{Seats: 5000, Feature: "ai-quarantine", EndsAt: now.AddDate(0, 13, 0).Format(time.RFC3339)},
	}
	if p.SeatsAt(now) != 5000 {
		t.Fatalf("a bundle grants 5000 seats, not 10000: got %d", p.SeatsAt(now))
	}
	if p.SeatsForFeatureAt("ai-quarantine", now) != 5000 {
		t.Fatalf("every seat in the bundle carries the capability")
	}
}
