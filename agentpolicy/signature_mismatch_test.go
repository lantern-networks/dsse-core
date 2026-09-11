package agentpolicy

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

// ★ THE POINT OF THIS TEST IS THAT ONE SENTENCE USED TO COVER TWO INCIDENTS.
//
// A forged document and a correct document checked against the wrong anchor produced identical text, so an
// operator reading it learned nothing about which one they had. Measured 2026-08-31: `profileapply --apply`
// printed it for the install profile the box was ALREADY RUNNING, because the tool defaults to the baked-in
// anchor and the device verifies against the one it provisioned with. The only way to discover it was not a
// bad profile was to feed the tool a profile already known good and watch it fail identically.
//
// What is asserted here is not wording. It is that BOTH SIDES of the comparison reach the operator, because
// the operator is the one holding the context that decides which side is wrong.

// A genuine, untampered document checked against an anchor that did not sign it. The document is fine; the
// VERIFIER is wrong. The error must leave room for that reading, or a missing flag gets escalated as an attack.
func TestAGoodDocumentCheckedAgainstTheWrongAnchorNamesBothSides(t *testing.T) {
	issuer := testSigner(t)
	stranger := testSigner(t)

	env, err := issuer.Sign(Payload{SchemaVersion: EnvelopeType, TenantID: "t"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	_, verr := Verify(env, stranger.PublicKeyHex())
	if verr == nil {
		t.Fatal("Verify accepted a document signed by a different key")
	}
	msg := verr.Error()

	// The key the envelope CLAIMS: the operator matches this against the Console that issued the document.
	if !strings.Contains(msg, issuer.KeyID()) {
		t.Errorf("the error does not name the signing key id the envelope claims (%q): %q", issuer.KeyID(), msg)
	}
	// The anchor actually USED: the operator matches this against profile_signing_key.txt.
	if !strings.Contains(msg, shortKey(stranger.PublicKeyHex())) {
		t.Errorf("the error does not name the pin it verified against: %q", msg)
	}
	// ★ and it must offer the wrong-verifier reading. Without this the message still reads as "this document
	// is bad", which is the half that sends someone to an incident channel over a forgotten --pin.
	if !strings.Contains(msg, "VERIFIER is wrong") {
		t.Errorf("the error does not offer the wrong-anchor reading, so it still reads as an attack: %q", msg)
	}
	// ★ AND IT MUST NOT BE THE OLD SENTENCE. That text was true and told nobody anything.
	if strings.TrimSpace(msg) == "signature verification failed" {
		t.Error("the error is still the bare verdict that covered two different incidents")
	}
}

// The other half: verified against the RIGHT anchor and still failing means the document is not from that
// authority. Same function, and it must not soften that into a shrug.
func TestTheRightAnchorFailingStillSaysDoNotApplyIt(t *testing.T) {
	issuer := testSigner(t)
	env, err := issuer.Sign(Payload{SchemaVersion: EnvelopeType, TenantID: "t"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	// Swap the payload for a different one and keep the checksum honest, so it is the SIGNATURE that fails
	// rather than the earlier checksum guard — this test is about the signature branch specifically.
	tampered := []byte(`{"schema_version":"` + EnvelopeType + `","tenant_id":"somewhere-else"}`)
	env.PayloadB64 = base64.StdEncoding.EncodeToString(tampered)
	sum := sha256.Sum256(tampered)
	env.PayloadSHA256 = hex.EncodeToString(sum[:])

	_, verr := Verify(env, issuer.PublicKeyHex())
	if verr == nil {
		t.Fatal("Verify accepted a tampered payload under the issuer's own key")
	}
	if !strings.Contains(verr.Error(), "must not be applied") {
		t.Errorf("a tampered document under the right anchor must be refused in plain words: %q", verr.Error())
	}
}

// An empty pin is its own situation: nothing was verified because nothing was supplied. Reporting that as a
// signature failure is how "this tool was invoked wrong" gets filed as "this document is bad".
func TestNoPinAtAllSaysSoRatherThanBlamingTheDocument(t *testing.T) {
	if got := shortKey(""); !strings.Contains(got, "no pin was supplied") {
		t.Errorf("shortKey(%q) = %q, want it to say no pin was supplied", "", got)
	}
}

// An operator matching an anchor by eye reads the ends. A full 64-hex line wraps in a terminal and stops
// being read at all, which is the failure mode this shortening exists to avoid.
func TestShortKeyKeepsBothEndsSoItCanBeMatchedByEye(t *testing.T) {
	full := "f53413bfedec3517dc46334ca3ab9762d6d77fea6e091609f98faf5c370971df"
	got := shortKey(full)
	if !strings.HasPrefix(got, full[:10]) || !strings.HasSuffix(got, full[len(full)-6:]) {
		t.Errorf("shortKey(%q) = %q, want both ends preserved", full, got)
	}
	if len(got) >= len(full) {
		t.Errorf("shortKey did not shorten: %q", got)
	}
}
