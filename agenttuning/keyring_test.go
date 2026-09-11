package agenttuning

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/agentpolicy"
)

func signedTuning(t *testing.T, signer *agentpolicy.Signer) []byte {
	t.Helper()
	env, err := signer.Sign(TuningPolicy{Kind: TuningKind, Captive: &CaptiveTuning{TimeoutSec: 7}}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func ecdsaSigner(t *testing.T) *agentpolicy.Signer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := agentpolicy.NewSignerFromCrypto(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// Tuning has to accept the same key SET as every other signed-policy path. It did not, and that made it the one
// consumer a signing-key rotation could break on its own: with the Edge signing policy from the HSM's ECDSA key
// and the device still pinning Ed25519, exclusions kept applying through the adopted set while tuning failed
// once a minute with "signature is ECDSA-P256 but the pinned key is not an ECDSA-P256 public key".
func TestLoadWithKeysAcceptsAnAdoptedKeyTheDeviceDoesNotPin(t *testing.T) {
	pinned, _ := agentpolicy.LoadOrGenerateSigner("", true) // the Ed25519 key this device was provisioned with
	adopted := ecdsaSigner(t)                               // the ECDSA key the Edge moved signing to
	body := signedTuning(t, adopted)

	if _, ok, err := Load(body, pinned.PublicKeyHex()); ok || err == nil {
		t.Fatal("the pin alone must NOT verify a policy signed by the adopted key — the old behaviour is the bug")
	}
	policy, ok, err := LoadWithKeys(body, []string{pinned.PublicKeyHex(), adopted.PublicKeyHex()})
	if err != nil || !ok {
		t.Fatalf("the adopted key was refused: ok=%v err=%v", ok, err)
	}
	if policy.Captive == nil || policy.Captive.TimeoutSec != 7 {
		t.Fatalf("payload did not survive verification: %+v", policy)
	}
}

// An empty or unusable key set is a refusal, never a pass — "no keys" must not read as "no checking".
func TestLoadWithKeysRefusesAnEmptyKeySet(t *testing.T) {
	body := signedTuning(t, ecdsaSigner(t))
	for _, keys := range [][]string{nil, {}, {""}, {"   "}, {"not-hex"}} {
		if _, ok, err := LoadWithKeys(body, keys); ok || err == nil {
			t.Fatalf("key set %v was accepted", keys)
		}
	}
}

// The Syncer reads its keys per fetch, not once at construction: a device adopts the next key while this is
// already running, and a set captured up front would still be the old one when the Edge starts using the new key.
func TestSyncerPicksUpAKeyAdoptedWhileRunning(t *testing.T) {
	pinned, _ := agentpolicy.LoadOrGenerateSigner("", true)
	adopted := ecdsaSigner(t)
	body := signedTuning(t, adopted)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	keys := []string{pinned.PublicKeyHex()} // nothing adopted yet
	applied := 0
	s := Syncer{
		URL:    srv.URL,
		PinHex: pinned.PublicKeyHex(),
		Keys:   func() []string { return keys },
		Client: srv.Client(),
		Apply:  func(TuningPolicy) { applied++ },
	}
	if err := s.FetchOnce(t.Context()); err == nil {
		t.Fatal("before adoption the ECDSA-signed policy must be refused")
	}
	if applied != 0 {
		t.Fatal("an unverified policy was applied")
	}

	keys = append(keys, adopted.PublicKeyHex()) // the bundle publishes the next key; the device adopts it
	if err := s.FetchOnce(t.Context()); err != nil {
		t.Fatalf("after adoption the same policy must verify: %v", err)
	}
	if applied != 1 {
		t.Fatalf("apply count = %d, want 1", applied)
	}
}

// With no Keys callback the behaviour is exactly what it was: verify against the pin alone.
func TestSyncerWithoutAKeysCallbackUsesThePin(t *testing.T) {
	pinned, _ := agentpolicy.LoadOrGenerateSigner("", true)
	body := signedTuning(t, pinned)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	applied := 0
	s := Syncer{URL: srv.URL, PinHex: pinned.PublicKeyHex(), Client: srv.Client(), Apply: func(TuningPolicy) { applied++ }}
	if err := s.FetchOnce(t.Context()); err != nil {
		t.Fatalf("FetchOnce: %v", err)
	}
	if applied != 1 {
		t.Fatalf("apply count = %d, want 1", applied)
	}
}
