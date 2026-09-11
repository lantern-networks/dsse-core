package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

// The pool's job is to keep signing when one HSM dies, and — the part a physical two-appliance rig cannot check
// for you — to REFUSE to form if the standby holds the wrong key. These tests exercise both, plus the fail-back.

// fakeSigner is a crypto.Signer that signs with a real ECDSA key but can be told to fail on demand, so a test
// can simulate an HSM going down and coming back.
type fakeSigner struct {
	key     *ecdsa.PrivateKey
	mu      sync.Mutex
	failing bool
	signs   int
}

func newFakeSigner(t *testing.T, key *ecdsa.PrivateKey) *fakeSigner { return &fakeSigner{key: key} }

func (f *fakeSigner) Public() crypto.PublicKey { return f.key.Public() }

func (f *fakeSigner) setFailing(v bool) { f.mu.Lock(); f.failing = v; f.mu.Unlock() }

func (f *fakeSigner) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	f.mu.Lock()
	f.signs++
	failing := f.failing
	f.mu.Unlock()
	if failing {
		return nil, errors.New("hsm unreachable")
	}
	return ecdsa.SignASN1(rand.Reader, f.key, digest)
}

func mustKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func signOnce(t *testing.T, p *hsmSignerPool) ([]byte, []byte, error) {
	t.Helper()
	digest := sha256.Sum256([]byte("leaf to mint"))
	sig, err := p.Sign(rand.Reader, digest[:], crypto.SHA256)
	return digest[:], sig, err
}

// The whole point: a standby holding a DIFFERENT key must make the pool refuse to form, because failing over to
// it would mint certificates that do not verify against the CA certificate.
func TestPoolRejectsMembersWithDifferentKeys(t *testing.T) {
	a := newFakeSigner(t, mustKey(t))
	b := newFakeSigner(t, mustKey(t)) // a DIFFERENT key
	_, err := newHSMSignerPool([]namedSigner{{"primary", a}, {"standby", b}}, time.Second, time.Now, nil)
	if err == nil {
		t.Fatal("pool formed with two different keys — a failover would mint certificates that do not verify")
	}
}

// Same replicated key across members must be accepted, and every member must verify against the shared public
// key so a signature from either is valid for the same CA certificate.
func TestPoolAcceptsSameKeyAndBothVerify(t *testing.T) {
	key := mustKey(t)
	a := newFakeSigner(t, key)
	b := newFakeSigner(t, key)
	p, err := newHSMSignerPool([]namedSigner{{"primary", a}, {"standby", b}}, time.Second, time.Now, nil)
	if err != nil {
		t.Fatalf("pool refused a correctly replicated key: %v", err)
	}
	digest, sig, err := signOnce(t, p)
	if err != nil {
		t.Fatal(err)
	}
	if !ecdsa.VerifyASN1(&key.PublicKey, digest, sig) {
		t.Fatal("signature does not verify against the shared public key")
	}
}

// Primary down → the pool signs on the standby, transparently.
func TestFailsOverToStandbyWhenPrimaryFails(t *testing.T) {
	key := mustKey(t)
	prim := newFakeSigner(t, key)
	stby := newFakeSigner(t, key)
	p, _ := newHSMSignerPool([]namedSigner{{"primary", prim}, {"standby", stby}}, time.Second, time.Now, nil)

	prim.setFailing(true)
	digest, sig, err := signOnce(t, p)
	if err != nil {
		t.Fatalf("pool failed while a healthy standby was available: %v", err)
	}
	if !ecdsa.VerifyASN1(&key.PublicKey, digest, sig) {
		t.Fatal("standby signature does not verify")
	}
	if stby.signs == 0 {
		t.Fatal("standby was never asked to sign")
	}
	if p.ActiveMember() != "standby" {
		t.Fatalf("active member = %q, want standby", p.ActiveMember())
	}
}

// Once the primary recovers AND its cooldown has elapsed, the pool prefers it again — fail-back with no poller.
func TestFailsBackToPrimaryAfterCooldown(t *testing.T) {
	key := mustKey(t)
	prim := newFakeSigner(t, key)
	stby := newFakeSigner(t, key)
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return now }
	p, _ := newHSMSignerPool([]namedSigner{{"primary", prim}, {"standby", stby}}, 10*time.Second, clock, nil)

	// Primary fails → failover to standby, primary put in cooldown.
	prim.setFailing(true)
	if _, _, err := signOnce(t, p); err != nil {
		t.Fatal(err)
	}
	if p.ActiveMember() != "standby" {
		t.Fatalf("did not fail over: active=%q", p.ActiveMember())
	}

	// Primary recovers, but the cooldown has NOT elapsed yet → still on standby.
	prim.setFailing(false)
	if _, _, err := signOnce(t, p); err != nil {
		t.Fatal(err)
	}
	if p.ActiveMember() != "standby" {
		t.Fatalf("failed back before the cooldown elapsed: active=%q", p.ActiveMember())
	}

	// Cooldown elapses → primary is tried first again and, being healthy, becomes active.
	now = now.Add(11 * time.Second)
	if _, _, err := signOnce(t, p); err != nil {
		t.Fatal(err)
	}
	if p.ActiveMember() != "primary" {
		t.Fatalf("did not fail back to primary after cooldown: active=%q", p.ActiveMember())
	}
}

// Every member down → the pool errors, and the error names the members so an operator knows both failed rather
// than guessing. A stale cooldown must not stop it from trying (better a real error than a refusal to attempt).
func TestAllMembersDownReturnsErrorNamingThem(t *testing.T) {
	key := mustKey(t)
	prim := newFakeSigner(t, key)
	stby := newFakeSigner(t, key)
	p, _ := newHSMSignerPool([]namedSigner{{"primary", prim}, {"standby", stby}}, time.Second, time.Now, nil)
	prim.setFailing(true)
	stby.setFailing(true)
	_, _, err := signOnce(t, p)
	if err == nil {
		t.Fatal("pool reported success with every member down")
	}
	for _, name := range []string{"primary", "standby"} {
		if !strings.Contains(err.Error(), name) {
			t.Fatalf("error %q does not name member %q", err.Error(), name)
		}
	}
}

// Concurrent signs (the real load: many leaves minting at once) must not corrupt member state or deadlock.
func TestConcurrentSignsAreSafe(t *testing.T) {
	key := mustKey(t)
	prim := newFakeSigner(t, key)
	stby := newFakeSigner(t, key)
	p, _ := newHSMSignerPool([]namedSigner{{"primary", prim}, {"standby", stby}}, time.Second, time.Now, nil)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			digest := sha256.Sum256([]byte("x"))
			if _, err := p.Sign(rand.Reader, digest[:], crypto.SHA256); err != nil {
				t.Errorf("concurrent sign failed: %v", err)
			}
		}()
	}
	wg.Wait()
}
