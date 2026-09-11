package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/agentpolicy"
)

// newTestECDSASigner is the shape the config-signing key takes once it lives in a PKCS#11 token: ECDSA-P256,
// reached through crypto.Signer. An in-process key is indistinguishable from the token's for this purpose —
// what is being exercised is the signature algorithm on the wire, not where the private half is kept.
func newTestECDSASigner(t *testing.T) *agentpolicy.Signer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := agentpolicy.NewSignerFromCrypto(key)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

// The switch, end to end, on the path the agent actually runs.
//
// This is the check the macOS side asked for before the signing key moves into the token, and it is worth being
// explicit about why: the trust bundle is signed with the SAME key as agent policy, so the moment the Edge signs
// with the token's ECDSA key, every bundle is ECDSA too. A verifier that only understood "ed25519:" — or that
// only ever tried the provisioned pin — would reject every bundle from that moment on, which takes out trust
// adoption AND the recovery path a locked-out device depends on. That is what nearly happened on macOS.
//
// The sequence below is the real rollout: the key in force publishes the next key, the device adopts it, and
// only then does the signer change. Each step goes through runTrustAnchorRecoveryOnce, so nothing about the
// wiring is assumed — if the Windows agent could not follow the key into the token, this fails.
func TestWindowsFollowsThePolicyKeyIntoAnECDSATokenAcrossTrustBundles(t *testing.T) {
	ed := newTestSigner(t)      // the Ed25519 key in force today (this device's pin)
	ec := newTestECDSASigner(t) // the ECDSA-P256 key the token will hold
	ca := newTestCA(t, "current-ca")
	ln := startTransportListener(t, leafUnder(t, ca))
	tc := testTransportConfig(t, ln.Addr().String(), ca)
	dir := t.TempDir()

	// Step 1 — publish. Still signed by the Ed25519 key; the ECDSA public key rides along in the keyring.
	publish, err := ed.SignTrustBundleWithKeyring("lab", 1, string(ca.pem), "", nil,
		[]string{ec.PublicKeyHex()}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	srv := startBundleServer(t, publish, nil)
	out := runTrustAnchorRecoveryOnce(tc, trustRecoveryConfig{
		stateDir: dir, pinHex: ed.PublicKeyHex(), bundleURL: srv.URL,
		client: unverifiedChannelClient(5 * time.Second), timeout: 5 * time.Second,
	})
	if out.code != "adopted" && out.code != "adopted_while_healthy" {
		t.Fatalf("the publishing bundle was not adopted: %s (%s)", out.code, out.detail)
	}
	keys := policyVerificationKeys(ed.PublicKeyHex(), dir)
	if len(keys) != 2 || keys[1] != ec.PublicKeyHex() {
		t.Fatalf("the ECDSA next-key was not stored: %v", keys)
	}

	// Step 2 — the switch. A HIGHER serial, signed by the ECDSA token key, exactly as the Edge will send it
	// once -agent-policy-hsm-agent-* is enabled. The device has never seen this algorithm on a bundle before.
	switched, err := ec.SignTrustBundleWithKeyring("lab", 2, string(ca.pem), "", nil,
		[]string{ed.PublicKeyHex()}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(switched.Signature) < len(agentpolicy.ECDSAP256SignaturePrefix) ||
		switched.Signature[:len(agentpolicy.ECDSAP256SignaturePrefix)] != agentpolicy.ECDSAP256SignaturePrefix {
		t.Fatalf("fixture is not ECDSA-signed, so this test would prove nothing: %q", switched.Signature)
	}
	srv2 := startBundleServer(t, switched, nil)
	out = runTrustAnchorRecoveryOnce(tc, trustRecoveryConfig{
		stateDir: dir, pinHex: ed.PublicKeyHex(), bundleURL: srv2.URL,
		client: unverifiedChannelClient(5 * time.Second), timeout: 5 * time.Second,
	})
	if out.code != "adopted" && out.code != "adopted_while_healthy" {
		t.Fatalf("the ECDSA-signed bundle was REFUSED — the switch would freeze this device: %s (%s)", out.code, out.detail)
	}
	if got := lastAcceptedTrustSerial(dir); got != 2 {
		t.Fatalf("accepted serial = %d, want 2 (the ECDSA-signed bundle)", got)
	}
}

// The other half of the same claim: acceptance must come from having ADOPTED the key, not from the verifier
// having gone lax about ECDSA. A device that never received the publishing bundle holds only its Ed25519 pin,
// and must refuse the ECDSA-signed bundle — which is also why the rollout confirms adoption fleet-wide before
// the signer changes, rather than changing it and watching what breaks.
func TestAnECDSABundleIsRefusedByADeviceThatNeverAdoptedTheKey(t *testing.T) {
	ed := newTestSigner(t)
	ec := newTestECDSASigner(t)
	ca := newTestCA(t, "current-ca")
	ln := startTransportListener(t, leafUnder(t, ca))
	tc := testTransportConfig(t, ln.Addr().String(), ca)

	switched, err := ec.SignTrustBundleWithKeyring("lab", 2, string(ca.pem), "", nil,
		[]string{ed.PublicKeyHex()}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	srv := startBundleServer(t, switched, nil)
	dir := t.TempDir() // no prior adoption: the pin is all this device has

	out := runTrustAnchorRecoveryOnce(tc, trustRecoveryConfig{
		stateDir: dir, pinHex: ed.PublicKeyHex(), bundleURL: srv.URL,
		client: unverifiedChannelClient(5 * time.Second), timeout: 5 * time.Second,
	})
	if out.code == "adopted" || out.code == "adopted_while_healthy" {
		t.Fatalf("a bundle signed by a key this device never adopted was accepted: %s (%s)", out.code, out.detail)
	}
	if got := lastAcceptedTrustSerial(dir); got != 0 {
		t.Fatalf("nothing should have been accepted, serial = %d", got)
	}
}
