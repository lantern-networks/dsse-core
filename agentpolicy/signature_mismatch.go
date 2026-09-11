package agentpolicy

// signature_mismatch.go — what a failed signature check says, and why it says more than "failed".
//
// ★★★ TWO COMPLETELY DIFFERENT SITUATIONS PRODUCE THIS ONE ERROR (2026-08-31, measured on win-dev-1):
//
//	a forged or tampered document          — someone is attacking this fleet
//	a genuine document, wrong anchor       — an operator forgot --pin
//
// Told apart, those are "make a phone call" and "run it again". Told the same, they are one sentence an
// operator cannot act on — and the operator who assumes the first one when it was the second spends a night
// on an incident that is a missing flag, while the one who assumes the second when it was the first installs
// a forged profile on the second attempt.
//
// The day this was written, `profileapply --apply` printed "signature verification failed" for the install
// profile THE MACHINE WAS ALREADY RUNNING — because the tool defaults to the anchor baked into the binary and
// the box verifies against the one it provisioned with. The sentence was true and told nobody anything: the
// only way to learn it was not a bad profile was to feed the tool a profile already known to be good and
// watch it fail identically.
//
// ★ SO THE FIX IS NOT "SAY MORE", IT IS "SAY WHICH TWO THINGS DID NOT MATCH". A signature check compares a
// document to an authority. Reporting only the verdict throws away the half that says which side to look at.
//
// ★ NOTHING HERE IS A SECRET, BY CONSTRUCTION. A key id is a label. A pinned key is a PUBLIC key — printing
// it is what an operator does by hand anyway, out of profile_signing_key.txt, to answer the same question.
// This is not a case where a diagnostic has to be weighed against disclosure; there is nothing to disclose.
// The signature and payload are deliberately NOT printed: those are the attacker-supplied halves, and a tool
// that echoes them invites an operator to compare bytes instead of asking which authority they meant.

import (
	"fmt"
	"strings"
)

// signatureMismatch describes a signature that did not verify, naming both sides of the comparison.
//
// alg is the algorithm actually used (chosen from the signature's prefix, not assumed). pinnedHex is the
// public key the caller handed in. Both are already known to the caller; the point is that they reach the
// OPERATOR, who is the one holding the context that decides which side is wrong.
func signatureMismatch(env Envelope, pinnedHex, alg string) error {
	id := strings.TrimSpace(env.SigningKeyID)
	if id == "" {
		id = "(none — the envelope names no signing key)"
	}
	return fmt.Errorf("%s signature does not verify: the envelope says it was signed by key id %q, and it was "+
		"checked against pinned public key %s. Two different faults produce this: if that pin is NOT the anchor "+
		"this device provisioned with, the document may be perfectly good and the VERIFIER is wrong (on Windows, "+
		"%%ProgramData%%\\DSSE\\profile_signing_key.txt records the adopted one); if it IS the right anchor, then "+
		"this document was not signed by that authority and must not be applied",
		alg, id, shortKey(pinnedHex))
}

// shortKey renders a public key short enough to compare by eye against the recorded one. An operator matching
// an anchor reads the ends, never the middle, and a full 64-hex line in an error wraps and stops being read.
func shortKey(hexKey string) string {
	k := strings.ToLower(strings.TrimSpace(hexKey))
	switch {
	case k == "":
		return "(none — no pin was supplied, so nothing could be verified)"
	case len(k) <= 20:
		return k
	default:
		return k[:10] + "…" + k[len(k)-6:]
	}
}
