package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/agentpolicy"
)

const (
	testPinKey  = "b408c812edcb3d4cafc72b6619c917aae7ddeb79f5cc63f2dc46e9204d7a5e57"
	testNextKey = "1111111111111111111111111111111111111111111111111111111111111111"
)

func writeKeyringPointer(t *testing.T, dir string, keys []string) {
	t.Helper()
	raw, _ := json.MarshalIndent(adoptedTrustPointer{
		Serial: 1, AdoptedAt: "2026-08-03T00:00:00Z", AgentPolicyPublicKeys: keys,
	}, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, adoptedPointerFile), raw, 0o644); err != nil {
		t.Fatal(err)
	}
}

// The pin is always present and FIRST, and the published set is ADDITIVE. Treating a published set as a
// replacement would let one bad publication cut a device off from the only key it was provisioned to trust —
// and policy is fail-safe, so it would then freeze with nothing able to reach it.
func TestPolicyVerificationKeysAreAdditiveAndPinFirst(t *testing.T) {
	dir := t.TempDir()
	writeKeyringPointer(t, dir, []string{testNextKey})

	keys := policyVerificationKeys(testPinKey, dir)
	if len(keys) != 2 || keys[0] != testPinKey {
		t.Fatalf("keys = %v, want the pin first then the published key", keys)
	}
	if keys[1] != testNextKey {
		t.Fatalf("the published key was not added: %v", keys)
	}
}

// Nothing published, or no state at all, leaves exactly the provisioned pin — the behaviour before any of this
// existed, so a deployment that never publishes a set is untouched.
func TestPolicyVerificationKeysWithoutAPublishedSet(t *testing.T) {
	if got := policyVerificationKeys(testPinKey, t.TempDir()); len(got) != 1 || got[0] != testPinKey {
		t.Fatalf("with no adopted pointer, keys = %v, want just the pin", got)
	}
	if got := policyVerificationKeys(testPinKey, ""); len(got) != 1 || got[0] != testPinKey {
		t.Fatalf("with no state dir, keys = %v, want just the pin", got)
	}
	dir := t.TempDir()
	writeKeyringPointer(t, dir, nil)
	if got := policyVerificationKeys(testPinKey, dir); len(got) != 1 {
		t.Fatalf("an empty published set must add nothing, got %v", got)
	}
}

// Malformed entries are dropped SILENTLY — an entry here is a key the device would accept instructions from,
// so a broken one must never be carried. The pin surviving alone is the safe outcome.
func TestPolicyVerificationKeysDropMalformedEntries(t *testing.T) {
	dir := t.TempDir()
	writeKeyringPointer(t, dir, []string{
		"", "   ", "not-hex", strings.Repeat("a", 63), strings.Repeat("a", 65),
		strings.Repeat("z", 64), testNextKey, testNextKey, // duplicate too
	})
	keys := policyVerificationKeys(testPinKey, dir)
	if len(keys) != 2 || keys[0] != testPinKey || keys[1] != testNextKey {
		t.Fatalf("keys = %v, want exactly the pin plus the one well-formed key", keys)
	}
}

// Case and whitespace are normalised, and the pin is not duplicated when it is also published (the Edge always
// includes the key in force in the set it publishes).
func TestPolicyVerificationKeysNormaliseAndDedupe(t *testing.T) {
	dir := t.TempDir()
	writeKeyringPointer(t, dir, []string{"  " + strings.ToUpper(testPinKey) + "  ", testNextKey})
	keys := policyVerificationKeys(testPinKey, dir)
	if len(keys) != 2 {
		t.Fatalf("the pin published back to us must not be duplicated: %v", keys)
	}
	if keys[0] != testPinKey || keys[1] != testNextKey {
		t.Fatalf("keys = %v", keys)
	}
}

// The sync verifies against the published set when there is one, and against the pin alone otherwise — never
// against nothing.
func TestExclusionSyncVerificationKeys(t *testing.T) {
	s := &exclusionSync{pinHex: testPinKey}
	if got := s.verificationKeys(); len(got) != 1 || got[0] != testPinKey {
		t.Fatalf("with no policyKeys callback, keys = %v", got)
	}
	s.policyKeys = func() []string { return nil } // a callback that yields nothing must not empty the set
	if got := s.verificationKeys(); len(got) != 1 || got[0] != testPinKey {
		t.Fatalf("an empty callback result must fall back to the pin, got %v", got)
	}
	s.policyKeys = func() []string { return []string{testPinKey, testNextKey} }
	if got := s.verificationKeys(); len(got) != 2 {
		t.Fatalf("the published set was not used: %v", got)
	}
}

// End to end: a bundle that publishes a key set is adopted, the set is persisted, and the device then accepts
// policy signed by the NEW key — which is the whole point of the exercise. Uses the same adoption path the
// agent runs, so nothing about the wiring is assumed.
func TestAdoptingABundlePersistsTheKeySet(t *testing.T) {
	current := newTestSigner(t)
	next := newTestSigner(t)
	ca := newTestCA(t, "current-ca")
	ln := startTransportListener(t, leafUnder(t, ca))
	tc := testTransportConfig(t, ln.Addr().String(), ca)

	// The Edge publishes the next key alongside the one in force (SignTrustBundleWithKeyring puts its own first).
	env, err := current.SignTrustBundleWithKeyring("lab", 1, string(ca.pem), "", nil,
		[]string{next.PublicKeyHex()}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	srv := startBundleServer(t, env, nil)
	dir := t.TempDir()

	out := runTrustAnchorRecoveryOnce(tc, trustRecoveryConfig{
		stateDir: dir, pinHex: current.PublicKeyHex(), bundleURL: srv.URL,
		client: unverifiedChannelClient(5 * time.Second), timeout: 5 * time.Second,
	})
	if out.code != "adopted_while_healthy" && out.code != "adopted" {
		t.Fatalf("bundle not adopted: %s (%s)", out.code, out.detail)
	}

	keys := policyVerificationKeys(current.PublicKeyHex(), dir)
	if len(keys) != 2 {
		t.Fatalf("after adoption the device should accept both keys, got %v", keys)
	}
	// Policy signed by the NEXT key now verifies — the rotation can proceed without freezing this device.
	signedByNext, _ := next.Sign(agentpolicy.Payload{SchemaVersion: agentpolicy.EnvelopeType}, time.Now())
	if _, err := agentpolicy.VerifyAny(signedByNext, keys); err != nil {
		t.Fatalf("policy signed by the published next key was refused: %v", err)
	}
	// And a key nobody published still cannot sign anything.
	stranger := newTestSigner(t)
	signedByStranger, _ := stranger.Sign(agentpolicy.Payload{SchemaVersion: agentpolicy.EnvelopeType}, time.Now())
	if _, err := agentpolicy.VerifyAny(signedByStranger, keys); err == nil {
		t.Fatal("policy signed by an unpublished key was accepted")
	}
}
