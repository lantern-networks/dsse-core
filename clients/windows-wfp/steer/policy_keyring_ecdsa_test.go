package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/lantern-networks/dsse-core/agentpolicy"
)

func testECDSAPubHex(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(elliptic.Marshal(elliptic.P256(), key.PublicKey.X, key.PublicKey.Y))
}

// The config-signing key moves into a token as ECDSA-P256 (no crypto11 binding does Ed25519 in a token), so a
// published next-key will be a 65-byte uncompressed point, not a 32-byte Ed25519 key. This device has to STORE
// that key when it adopts the bundle carrying it; a sanitiser that only recognised Ed25519 would drop it right
// there, and the device would report nothing new, look ready for the switch, and then be unable to verify the
// first ECDSA-signed policy — the exact fleet freeze the overlap is supposed to prevent.
func TestPolicyVerificationKeysAcceptAnECDSANextKey(t *testing.T) {
	dir := t.TempDir()
	next := testECDSAPubHex(t)
	writeKeyringPointer(t, dir, []string{next})

	keys := policyVerificationKeys(testPinKey, dir)
	if len(keys) != 2 || keys[0] != testPinKey || keys[1] != next {
		t.Fatalf("keys = %v, want the Ed25519 pin first then the ECDSA next-key", keys)
	}
}

// The accept rule is the verifier's, so a device never stores a key it could not actually use. Anything that is
// the right LENGTH but not a point on P-256 is fabricated, and is dropped like any other malformed entry.
func TestPolicyVerificationKeysRejectAnOffCurveKey(t *testing.T) {
	dir := t.TempDir()
	offCurve := "04" + strings.Repeat("11", 64) // correct shape and length, not on the curve
	if len(offCurve) != 130 {
		t.Fatalf("test fixture is %d chars, want 130", len(offCurve))
	}
	if agentpolicy.AcceptedPublicKeyHex(offCurve) {
		t.Fatal("an off-curve point passed the shared key check; the rest of this test is meaningless")
	}
	writeKeyringPointer(t, dir, []string{offCurve})

	if keys := policyVerificationKeys(testPinKey, dir); len(keys) != 1 || keys[0] != testPinKey {
		t.Fatalf("keys = %v, want the pin alone", keys)
	}
}

// The report carries the set this device would verify with, which is what lets the Edge confirm every device
// holds the next key BEFORE anything is signed with it. It reports the effective set (pin + adopted), because
// the adopted part alone cannot answer "would this device accept a policy signed by key X".
func TestExclusionSyncReportsTheAcceptedKeySet(t *testing.T) {
	signer, _ := agentpolicy.LoadOrGenerateSigner("", true)
	var reportFails atomic.Bool
	var cap capturedReport
	srv := reportingPolicyServer(t, signer, nil, &reportFails, &cap)
	defer srv.Close()

	// The pin is the key actually signing here, so the fetch verifies for real and the report describes a
	// device that is genuinely working — the ECDSA key rides along as the not-yet-used next key.
	pin := signer.PublicKeyHex()
	next := testECDSAPubHex(t)
	s := &exclusionSync{
		client: srv.Client(), baseURL: srv.URL, pinHex: pin, localBaseline: []string{"example-app"},
		apply:      func([]string) {},
		policyKeys: func() []string { return []string{pin, next} },
	}
	if _, err := s.refreshOnce(context.Background()); err != nil {
		t.Fatalf("refreshOnce: %v", err)
	}
	body, _ := cap.body.Load().(map[string]any)
	got, ok := body["agent_policy_public_keys"].([]any)
	if !ok || len(got) != 2 {
		t.Fatalf("agent_policy_public_keys = %v, want the pin and the next key", body["agent_policy_public_keys"])
	}
	if got[0] != pin || got[1] != next {
		t.Fatalf("agent_policy_public_keys = %v, want the pin first", got)
	}
}

// With no usable key configured the field is ABSENT rather than an array holding an empty string: the Edge reads
// absent as "this device did not answer", and a set containing a non-key would be a worse answer than none.
func TestExclusionSyncOmitsAnUnusableKeySet(t *testing.T) {
	signer, _ := agentpolicy.LoadOrGenerateSigner("", true)
	var reportFails atomic.Bool
	var cap capturedReport
	srv := reportingPolicyServer(t, signer, nil, &reportFails, &cap)
	defer srv.Close()

	s := &exclusionSync{
		client: srv.Client(), baseURL: srv.URL, pinHex: "", localBaseline: []string{"example-app"},
		apply: func([]string) {},
	}
	if _, err := s.refreshOnce(context.Background()); err != nil {
		t.Fatalf("refreshOnce: %v", err)
	}
	body, _ := cap.body.Load().(map[string]any)
	if v, present := body["agent_policy_public_keys"]; present {
		t.Fatalf("agent_policy_public_keys must be omitted when there is no usable key, got %v", v)
	}
}
