package agentpolicy

import (
	"strings"
	"testing"
	"time"
)

// VerifyAny is what makes the signing key rotatable: during the overlap a device holds both keys and policy
// keeps arriving whichever one signed it.
func TestVerifyAnyAcceptsEitherKeyDuringOverlap(t *testing.T) {
	oldSigner := testSigner(t)
	newSigner := testSigner(t)
	set := []string{oldSigner.PublicKeyHex(), newSigner.PublicKeyHex()}

	for name, s := range map[string]*Signer{"old": oldSigner, "new": newSigner} {
		env, err := s.Sign(Payload{SchemaVersion: EnvelopeType, TenantID: "t"}, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyAny(env, set); err != nil {
			t.Fatalf("a payload signed by the %s key was refused during the overlap: %v", name, err)
		}
	}

	// A key that is in NEITHER set position still cannot sign anything this device accepts.
	stranger := testSigner(t)
	env, _ := stranger.Sign(Payload{SchemaVersion: EnvelopeType}, time.Now())
	if _, err := VerifyAny(env, set); err == nil {
		t.Fatal("a payload signed by an unlisted key was accepted")
	}
}

// Malformed entries are dropped silently, and a set that contains ONLY malformed entries verifies nothing —
// "no usable key" must never read as "no checking".
func TestVerifyAnyDropsMalformedKeysAndRefusesEmptySets(t *testing.T) {
	s := testSigner(t)
	env, _ := s.Sign(Payload{SchemaVersion: EnvelopeType}, time.Now())

	// Junk beside the real key is ignored; the real key still verifies.
	mixed := []string{"", "not-hex", strings.Repeat("a", 63), strings.Repeat("z", 64), s.PublicKeyHex()}
	if _, err := VerifyAny(env, mixed); err != nil {
		t.Fatalf("a valid key beside malformed entries was not used: %v", err)
	}

	for _, empty := range [][]string{nil, {}, {"not-hex"}, {strings.Repeat("z", 64)}} {
		if _, err := VerifyAny(env, empty); err == nil {
			t.Fatalf("a set with no usable key (%v) verified something", empty)
		}
	}
}

// The single-key entry points must keep behaving exactly as before — a deployment that never publishes a set
// is unaffected by any of this.
func TestSingleKeyVerifyUnchanged(t *testing.T) {
	s := testSigner(t)
	other := testSigner(t)
	env, _ := s.Sign(Payload{SchemaVersion: EnvelopeType}, time.Now())
	if _, err := Verify(env, s.PublicKeyHex()); err != nil {
		t.Fatalf("own key must verify: %v", err)
	}
	if _, err := Verify(env, other.PublicKeyHex()); err == nil {
		t.Fatal("a different key must not verify")
	}
}
