// Package vendorlicense verifies the licence a vendor issues to an MSSP: how many devices it may enrol, until
// when, and whether the licence is an evaluation.
//
// ★★ WHAT A LICENCE MEANS HERE, decided 2026-08-14 and worth stating before anything else in this file:
//
//	no vendor keys configured  -> UNLIMITED. This is the open-source default, and nothing below is evaluated.
//	a signed licence present   -> the certified scope applies. This is a certified partner's deployment.
//
// So the absence of a licence is not a degraded state to be repaired; it is the ordinary one. An operator who
// runs this product without any relationship with the vendor is unlimited, and every mechanism in this package
// stays silent — requireLicence is false, no signature is checked, no serial is compared.
//
// ★ AND IT IS AN ATTESTATION, NOT AN ENFORCEMENT. The product is Apache-2.0 and fully open: a fork that
// deletes the check has no limit, and that is accepted rather than defended against. What a licence buys is a
// verifiable statement — "this partner is certified for this scope" — that an operator and their customers can
// check. Writing it down here because a reader who assumes this is a technical control will design the next
// thing wrongly.
//
// ★★ WHAT A LICENCE MAY AND MAY NOT DO. It may limit GROWTH: refuse NEW enrolments past the certified scope.
// It may not stop steering, cut existing traffic, halt an Edge, or disable features — those remain forbidden
// whatever the commercial state, because ending a relationship must not take a customer's running deployment
// down. The distinction is that growth is reversible and touches nothing already working.
//
// That boundary is held by ops/checks/no_licence_traffic_gate.sh rather than by this comment. MaySteerTraffic
// below is implemented and has no caller, deliberately: it is the shape of a decision that was NOT taken, and
// the check fails the moment anything calls it.
//
// Named for the relationship rather than "license" because it is not the repository's LICENSE file, and not the
// per-tenant feature entitlements either — those say WHICH capabilities a tenant has, this says HOW MANY devices
// an MSSP may enrol and until when.
//
// It is a FILE, verified locally, never a call home. A product that phones a vendor to decide whether it may
// keep working is a product that stops when the internet does, and this one is sold on operating inside a
// customer's own boundary. The only realistic attack on a file is presenting an older one with a larger seat
// count, which the serial answers.
//
// A licence ends in STEPS, and every step is declared in the signed file before anyone relies on it:
//
//	expires_at         the commercial expiry. Nothing stops; warnings begin.
//	enrolment_stops_at no new devices may enrol. The existing fleet is untouched.
//	service_ends_at    NOT ENFORCED IN THIS PRODUCT — see below. It stops enrolment, not steering.
//
// ★★ THE THIRD STEP IS A DESIGN, NOT A BEHAVIOUR (measured 2026-08-14). This block used to say "the agent
// stops steering", flatly, and no code in this product does that. MaySteerTraffic below is written, correct,
// and referenced by NINE tests and by nothing else — a mechanism whose call site was never added. The tests are
// what makes it hard to notice: they exercise it, they pass, and a reader concludes it runs.
//
// What service_ends_at DOES do is real and smaller: StateAt returns ServiceEnded past that date, and
// MayEnrolNewDevices refuses on it. So the date stops GROWTH — the same consequence as enrolment_stops_at,
// arriving later — and traffic is never touched by anything in here.
//
// It is stated rather than fixed because which of the two to make true is a product decision, not a cleanup:
// see ops/checks/no_licence_traffic_gate.sh, which fails the moment MaySteerTraffic acquires a caller, so the
// decision has to be taken deliberately rather than by someone wiring up a function that looked finished.
//
// The graduation is the point. A renewal in the post, a payment in transit or a dispute being worked through
// must not take a customer's deployment down — but a holder who has stopped paying for good cannot keep the
// product for ever either, or there is no business to protect. Collapsing those two into one rule was the
// original mistake here: the first needs patience, the second needs an end, and the difference between them is
// TIME, which is exactly what a declared runway measures.
//
// What the vendor still cannot do is decide any of this after the fact. There is no call home, so a licence
// cannot be revoked remotely; the dates were agreed at issue, they are visible to the holder from the first day,
// and the only way to change them is to hand over a new file the holder installs. Being generous is easy —
// re-issue with a later date — and being punitive requires the holder's cooperation.
package vendorlicense

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Schema marks a licence payload. Distinct from every other signed document so a body signed for another
// purpose cannot be replayed as a licence.
const Schema = "dsse.vendor-license.v1"

// Payload is the verified body.
//
// It carries what an Edge needs to decide and nothing else. Prices, contract terms and other customers are
// deliberately absent: the file passes through mail, ticketing systems and whoever hands it along, and the
// surest way to keep something from leaking is not to put it in.
type Payload struct {
	SchemaVersion string `json:"schema_version"`

	// MSSPID names the intended holder, and verification refuses a licence addressed to somebody else. This is
	// what makes sign-then-encrypt safe: without it, a recipient could re-encrypt the same signed licence to a
	// third party and it would verify there too.
	MSSPID string `json:"mssp_id"`

	// Serial increases with every issue for this MSSP. The holder records the highest it has accepted and
	// refuses anything at or below it, so an older file with more seats cannot be replayed.
	Serial int64 `json:"serial"`

	// Grants are the seat blocks that make up the pool, because entitlement is not one number over one period.
	// A holder who buys 10,000 seats for two years and adds 5,000 in the second cannot be described by a single
	// count: the blocks can end on different dates, and a licence that could only say "15,000" would either
	// expire the original seats early or keep the extra ones past what was paid for.
	//
	// An ADDITION is delivered as a re-issue carrying every block, not as a delta. One file always describes the
	// whole entitlement, so a holder cannot end up short by having lost an earlier one, and "what am I licensed
	// for" is answered by reading a single document.
	Grants []Grant `json:"grants"`

	IssuedAt string `json:"issued_at"`

	// ExpiresAt is the COMMERCIAL expiry — where warnings begin. Nothing stops here.
	ExpiresAt string `json:"expires_at"`

	// EnrolmentStopsAt is where new enrolments are refused. On a first term it sits a month past ExpiresAt, so
	// the month of slack is visible rather than folded into a longer term — grace nobody can see is not grace,
	// it is just a longer term, and nothing prompts anyone to renew. On a renewal the two are equal, and the
	// answer to that hard edge is to issue the renewal early: a renewal is dated from the previous expiry, so
	// issuing it months ahead costs the holder nothing.
	EnrolmentStopsAt string `json:"enrolment_stops_at"`

	// ServiceEndsAt is the date the licence DECLARES service ends. Required — a licence with no end is a
	// product given away.
	//
	// ★ WHAT IT ACTUALLY DOES HERE, since the previous comment described something else with conviction. Past
	// this date StateAt reports ServiceEnded and MayEnrolNewDevices refuses, so it stops NEW ENROLMENT. It does
	// not stop steering: MaySteerTraffic is the predicate for that and nothing calls it (see the package
	// comment). The running fleet keeps working.
	//
	// The old text said "an agent that stands aside does not merely stop inspecting, it stops carrying access to
	// private applications" — true of the design, and true of nothing this code does. A comment that describes
	// an unimplemented enforcement is worse than none: it is the sentence an operator would rely on when
	// deciding what a lapsed licence costs their users.
	ServiceEndsAt string `json:"service_ends_at"`

	IsEvaluation bool `json:"is_evaluation,omitempty"`
}

// Grant is one block of entitlement: how many seats, of what, for how long.
//
// Feature is what keeps this ONE list instead of two. Empty means enrolment capacity — how many devices may
// exist. Non-empty names an optional capability and how many seats carry it, which is how a module like DSPM or
// AI quarantine gets sold to part of a fleet for part of a term without inventing a second document.
//
// A bundle is simply two rows: "5,000 base" plus "5,000 dspm". Spelling it out beats a single row that has to be
// interpreted, because the alternative — summing rows that carry a feature into the capacity total — silently
// grants enrolment capacity nobody bought.
type Grant struct {
	Seats int `json:"seats"`
	// Feature is empty for base enrolment capacity, or names one optional capability.
	Feature string `json:"feature,omitempty"`
	// StartsAt is empty for a block in force from the beginning — the ordinary case, and the one an issuer
	// should not have to fill in.
	StartsAt string `json:"starts_at,omitempty"`
	// EndsAt is when these seats go away. A block lapsing is NOT a service event: it lowers the pool, and going
	// over the pool refuses new enrolments while leaving working devices alone, exactly as any other shortfall
	// does.
	EndsAt string `json:"ends_at"`
}

// SeatsAt is the enrolment capacity in force at a moment. Only blocks with no feature count — a DSPM block adds
// the capability to seats that were already paid for, not the right to enrol more devices.
func (p Payload) SeatsAt(now time.Time) int {
	total := 0
	for _, g := range p.Grants {
		if g.Feature == "" && g.activeAt(now) {
			total += g.Seats
		}
	}
	return total
}

// SeatsForFeatureAt is how many seats carry an optional capability right now. Zero means the holder is not
// licensed for it, which is the same answer as never having bought it — a capability whose block has lapsed is
// simply not licensed, with no separate "expired" state to reason about.
func (p Payload) SeatsForFeatureAt(feature string, now time.Time) int {
	feature = strings.TrimSpace(feature)
	if feature == "" {
		return 0
	}
	total := 0
	for _, g := range p.Grants {
		if strings.EqualFold(g.Feature, feature) && g.activeAt(now) {
			total += g.Seats
		}
	}
	return total
}

// FeaturesAt lists the optional capabilities with any entitlement right now, sorted so the answer is stable for
// an operator reading it and for anything comparing two moments.
func (p Payload) FeaturesAt(now time.Time) []string {
	seen := map[string]bool{}
	for _, g := range p.Grants {
		if g.Feature != "" && g.activeAt(now) {
			seen[strings.ToLower(strings.TrimSpace(g.Feature))] = true
		}
	}
	out := make([]string, 0, len(seen))
	for f := range seen {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}

func (g Grant) activeAt(now time.Time) bool {
	if s := strings.TrimSpace(g.StartsAt); s != "" {
		start, err := parseTime(s)
		if err != nil || now.Before(start) {
			return false
		}
	}
	end, err := parseTime(g.EndsAt)
	if err != nil {
		return false // an unreadable end is treated as lapsed: fail closed, never grant seats on a parse error
	}
	return now.Before(end)
}

// Envelope is the signed carrier. Same shape as the other signed documents here, except that the signature is
// ECDSA P-256 rather than Ed25519 — this key ends up in a PIV hardware token, and PIV does not do Ed25519.
// Choosing otherwise would narrow the set of safes the vendor's signing key can live in, for no benefit. The
// trust bundle stays Ed25519 because that key lives on an Edge and was never going near a token.
type Envelope struct {
	Type          string `json:"type"`
	SigningKeyID  string `json:"signing_key_id"`
	CreatedAt     string `json:"created_at"`
	PayloadSHA256 string `json:"payload_sha256"`
	PayloadB64    string `json:"payload_b64"`
	Signature     string `json:"signature"` // "ecdsa-p256-sha256:" + base64(ASN.1 DER)
}

const signaturePrefix = "ecdsa-p256-sha256:"

// Sign produces an envelope. The key arrives as a crypto.Signer so the vendor's issuer can hand in an HSM-backed
// one — the private key never has to exist as bytes anywhere, which is the entire point of putting it in a
// token. The same interface the interception-CA sidecar already presents.
func Sign(p Payload, keyID string, signer crypto.Signer, now time.Time) (Envelope, error) {
	if signer == nil {
		return Envelope{}, fmt.Errorf("no signer")
	}
	if _, ok := signer.Public().(*ecdsa.PublicKey); !ok {
		return Envelope{}, fmt.Errorf("licence signing key must be ECDSA P-256")
	}
	p.SchemaVersion = Schema
	body, err := json.Marshal(p)
	if err != nil {
		return Envelope{}, fmt.Errorf("marshal licence payload: %w", err)
	}
	digest := sha256.Sum256(body)
	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return Envelope{}, fmt.Errorf("sign licence: %w", err)
	}
	return Envelope{
		Type:          Schema,
		SigningKeyID:  strings.TrimSpace(keyID),
		CreatedAt:     now.UTC().Format(time.RFC3339),
		PayloadSHA256: hex.EncodeToString(digest[:]),
		PayloadB64:    base64.StdEncoding.EncodeToString(body),
		Signature:     signaturePrefix + base64.StdEncoding.EncodeToString(sig),
	}, nil
}

// Verify checks a licence and returns the payload.
//
// accepted is a LIST of vendor public keys, and that is not a convenience. A holder that accepts exactly one key
// has no recovery from that key leaking except updating every deployment by hand, and licences have no
// revocation to fall back on. Accepting several costs one line here and CANNOT be retrofitted into software
// already in the field; it also lets the vendor keep a second signing token for availability without
// duplicating a secret.
func Verify(env Envelope, accepted []*ecdsa.PublicKey, expectedMSSPID string, lastAcceptedSerial int64) (Payload, error) {
	if len(accepted) == 0 {
		return Payload{}, fmt.Errorf("no vendor public key configured; a licence cannot be verified")
	}
	raw, ok := strings.CutPrefix(strings.TrimSpace(env.Signature), signaturePrefix)
	if !ok {
		return Payload{}, fmt.Errorf("licence signature is not %s", strings.TrimSuffix(signaturePrefix, ":"))
	}
	sig, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return Payload{}, fmt.Errorf("decode licence signature: %w", err)
	}
	body, err := base64.StdEncoding.DecodeString(env.PayloadB64)
	if err != nil {
		return Payload{}, fmt.Errorf("decode licence payload: %w", err)
	}
	digest := sha256.Sum256(body)
	// The declared digest must match what was actually carried. A mismatch is a corrupted or tampered envelope,
	// not something to reconcile quietly.
	if want := strings.TrimSpace(env.PayloadSHA256); want != "" && !strings.EqualFold(want, hex.EncodeToString(digest[:])) {
		return Payload{}, fmt.Errorf("licence payload does not match its declared digest")
	}

	verified := false
	for _, pub := range accepted {
		if pub != nil && ecdsa.VerifyASN1(pub, digest[:], sig) {
			verified = true
			break
		}
	}
	if !verified {
		return Payload{}, fmt.Errorf("licence is not signed by any accepted vendor key")
	}

	var p Payload
	if err := json.Unmarshal(body, &p); err != nil {
		return Payload{}, fmt.Errorf("decode licence payload: %w", err)
	}
	if p.SchemaVersion != Schema {
		return Payload{}, fmt.Errorf("payload is %q, not a licence (%s)", p.SchemaVersion, Schema)
	}
	if err := p.validate(); err != nil {
		return Payload{}, err
	}
	if id := strings.TrimSpace(expectedMSSPID); id != "" && !strings.EqualFold(id, p.MSSPID) {
		// A licence for somebody else. Without this check a holder could re-encrypt a signed licence to a third
		// party and it would verify there — the known weakness of signing before encrypting.
		return Payload{}, fmt.Errorf("licence is addressed to %q, not %q", p.MSSPID, id)
	}
	if p.Serial <= lastAcceptedSerial {
		return Payload{}, fmt.Errorf("licence serial %d does not advance past %d — refusing a replay",
			p.Serial, lastAcceptedSerial)
	}
	return p, nil
}

func (p Payload) validate() error {
	if strings.TrimSpace(p.MSSPID) == "" {
		return fmt.Errorf("licence names no holder")
	}
	if p.Serial <= 0 {
		return fmt.Errorf("licence has no serial; a rollback could not be detected")
	}
	if len(p.Grants) == 0 {
		return fmt.Errorf("licence carries no seat grants")
	}
	for i, g := range p.Grants {
		if g.Seats <= 0 {
			return fmt.Errorf("seat grant %d carries no seats", i)
		}
		end, err := parseTime(g.EndsAt)
		if err != nil {
			return fmt.Errorf("seat grant %d end: %w", i, err)
		}
		if s := strings.TrimSpace(g.StartsAt); s != "" {
			start, err := parseTime(s)
			if err != nil {
				return fmt.Errorf("seat grant %d start: %w", i, err)
			}
			if !end.After(start) {
				return fmt.Errorf("seat grant %d ends before it starts", i)
			}
		}
	}
	expires, err := parseTime(p.ExpiresAt)
	if err != nil {
		return fmt.Errorf("licence expiry: %w", err)
	}
	stops, err := parseTime(p.EnrolmentStopsAt)
	if err != nil {
		return fmt.Errorf("licence enrolment-stop: %w", err)
	}
	if stops.Before(expires) {
		return fmt.Errorf("licence stops enrolment before it expires, which no issuer means")
	}
	// EVERY licence says when service ends — evaluations after days, paid licences after months. What is
	// enforced here is not the length but the SHAPE: service must end strictly after enrolment has already
	// stopped, so a holder always meets the reversible consequence before the expensive one and is never
	// surprised by the order of events.
	// A licence must grant enrolment capacity when it takes effect. One whose every block starts later, has
	// already lapsed, or only ever carried optional capabilities licenses nobody to enrol and is a mistake at
	// the issuer rather than a state to run in.
	issued, err := parseTime(p.IssuedAt)
	if err == nil && p.SeatsAt(issued) <= 0 {
		return fmt.Errorf("licence grants no seats at the moment it is issued")
	}
	ends, err := parseTime(p.ServiceEndsAt)
	if err != nil {
		return fmt.Errorf("a licence must say when service ends: %w", err)
	}
	if !ends.After(expires) {
		return fmt.Errorf("service must end after the licence expires, leaving a window in which to warn")
	}
	if ends.Before(stops) {
		return fmt.Errorf("service must not end before enrolment stops; the steps would arrive out of order")
	}
	return nil
}

func parseTime(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339, strings.TrimSpace(s))
	if err != nil {
		return time.Time{}, fmt.Errorf("%q is not an RFC3339 time", s)
	}
	return t, nil
}

// State is what a licence means right now.
type State int

const (
	// Active: everything normal.
	Active State = iota
	// Expired: past the commercial expiry, still fully working. This exists to be SHOWN — an operator who is not
	// told is an operator who does not renew, and the entire value of the grace is that somebody acts during it.
	Expired
	// EnrolmentStopped: no new devices may enrol. Devices already enrolled are unaffected, always.
	EnrolmentStopped
	// ServiceEnded: the agent stands aside. Reached only after both earlier steps have been visible for the
	// whole runway the signed licence declared.
	ServiceEnded
)

func (s State) String() string {
	switch s {
	case Active:
		return "active"
	case Expired:
		return "expired"
	case EnrolmentStopped:
		return "enrolment_stopped"
	case ServiceEnded:
		return "service_ended"
	}
	return "unknown"
}

// StateAt reports where a licence stands. Checked most-severe first, so an evaluation past its service end is
// not reported as merely expired.
func (p Payload) StateAt(now time.Time) State {
	if ends, err := parseTime(p.ServiceEndsAt); err == nil && !now.Before(ends) {
		return ServiceEnded
	}
	if stops, err := parseTime(p.EnrolmentStopsAt); err == nil && !now.Before(stops) {
		return EnrolmentStopped
	}
	if expires, err := parseTime(p.ExpiresAt); err == nil && !now.Before(expires) {
		return Expired
	}
	return Active
}

// MayEnrolNewDevices is the one question the enrolment path asks.
func (p Payload) MayEnrolNewDevices(now time.Time) bool {
	switch p.StateAt(now) {
	case Active, Expired:
		return true
	default:
		return false
	}
}

// MaySteerTraffic answers whether the agent should carry traffic at all.
//
// ★★ IT HAS NO CALLER, AND THAT IS A DECISION RATHER THAN AN OMISSION (2026-08-14). A licence may limit growth
// and may not stop a deployment that is already running: ending a commercial relationship must not take a
// customer's traffic down. This predicate is what that decision would look like if it had gone the other way,
// kept so the shape is legible — and ops/checks/no_licence_traffic_gate.sh fails if anything calls it.
func (p Payload) MaySteerTraffic(now time.Time) bool {
	return p.StateAt(now) != ServiceEnded
}

// ParsePublicKeysPEM reads the vendor keys a holder accepts. A LIST, for the reasons in Verify.
func ParsePublicKeysPEM(pemText string) ([]*ecdsa.PublicKey, error) {
	var out []*ecdsa.PublicKey
	rest := []byte(pemText)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "PUBLIC KEY" {
			continue
		}
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			continue
		}
		if ec, ok := pub.(*ecdsa.PublicKey); ok {
			out = append(out, ec)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no ECDSA public key found")
	}
	return out, nil
}
