package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/agentpolicy"
	"github.com/lantern-networks/dsse-core/model"
)

// TestConfigBundleFetchVerifiesSignature is the regression for the T0 fix: the live CP→Edge config-bundle pull
// must verify the control plane's Ed25519 signature and reject a tampered / unsigned bundle (a compromised CP or
// stolen bearer token must not be able to push arbitrary enforcement policy).
func TestConfigBundleFetchVerifiesSignature(t *testing.T) {
	signer, err := agentpolicy.LoadOrGenerateSigner("", true) // dev-ephemeral signer (stands in for the shared key)
	if err != nil || signer == nil {
		t.Fatalf("signer: %v", err)
	}
	bundle := configBundlePayload{Generation: 5, Epoch: "e1", Policies: []model.Policy{{ID: "p1", TenantID: "t1"}}}
	env, err := signer.Sign(bundle, time.Now())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	signedBody, _ := json.Marshal(env)

	signedSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(signedBody) }))
	defer signedSrv.Close()
	rawSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _ = json.NewEncoder(w).Encode(bundle) }))
	defer rawSrv.Close()

	// (1) Signed + correct pinned key -> the signed payload is extracted.
	src := configBundleSource{url: signedSrv.URL, client: signedSrv.Client(), verifyPubKeyHex: signer.PublicKeyHex(), requireSigned: true}
	got, err := src.fetch(context.Background())
	if err != nil {
		t.Fatalf("verified fetch failed: %v", err)
	}
	if got.Generation != 5 || len(got.Policies) != 1 || got.Policies[0].ID != "p1" {
		t.Fatalf("extracted payload wrong: %+v", got)
	}

	// (2) A DIFFERENT pinned key -> signature verification fails (rejects a forged/tampered bundle).
	other, _ := agentpolicy.LoadOrGenerateSigner("", true)
	bad := configBundleSource{url: signedSrv.URL, client: signedSrv.Client(), verifyPubKeyHex: other.PublicKeyHex(), requireSigned: true}
	if _, err := bad.fetch(context.Background()); err == nil {
		t.Fatal("expected verification failure with a mismatched pinned key")
	}

	// (3) UNSIGNED bundle while a key is pinned + requireSigned -> rejected (fail-closed).
	unsigned := configBundleSource{url: rawSrv.URL, client: rawSrv.Client(), verifyPubKeyHex: signer.PublicKeyHex(), requireSigned: true}
	if _, err := unsigned.fetch(context.Background()); err == nil {
		t.Fatal("expected rejection of an unsigned bundle when a key is pinned and signature is required")
	}

	// (4) No key pinned (lab) -> raw bundle accepted (backward-compatible).
	lab := configBundleSource{url: rawSrv.URL, client: rawSrv.Client()}
	if got, err := lab.fetch(context.Background()); err != nil || got.Generation != 5 {
		t.Fatalf("unsigned lab fetch should succeed: got=%+v err=%v", got, err)
	}
}

// TestConfigBundleVerifiesAgainstKeySet is the regression for the fix that keeps CP→Edge sync alive across a
// signing-key rotation: the edge verifies the bundle against the ACCEPTED SET (current signer + published next
// keys), so a CP that signs with a key other than the edge's first pin — the exact shape that silently killed
// the sync at the 2c Ed25519→ECDSA switch — still verifies, while a signer outside the set is still rejected.
func TestConfigBundleVerifiesAgainstKeySet(t *testing.T) {
	cur, _ := agentpolicy.LoadOrGenerateSigner("", true)  // the edge's current signer
	next, _ := agentpolicy.LoadOrGenerateSigner("", true) // a published next key (rotation overlap)
	outsider, _ := agentpolicy.LoadOrGenerateSigner("", true)

	bundle := configBundlePayload{Generation: 7, Epoch: "e2", Policies: []model.Policy{{ID: "p2", TenantID: "t1"}}}

	serve := func(s *agentpolicy.Signer) *httptest.Server {
		env, err := s.Sign(bundle, time.Now())
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		body, _ := json.Marshal(env)
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(body) }))
	}
	keySet := []string{cur.PublicKeyHex(), next.PublicKeyHex()}

	// The CP signs with the NEXT key (as during a rotation overlap) — accepted because it is in the set, even
	// though it is NOT the edge's current/first key. A single-key pin on cur would have rejected this.
	nextSrv := serve(next)
	defer nextSrv.Close()
	src := configBundleSource{url: nextSrv.URL, client: nextSrv.Client(), verifyKeys: keySet, verifyPubKeyHex: cur.PublicKeyHex(), requireSigned: true}
	if got, err := src.fetch(context.Background()); err != nil || got.Generation != 7 {
		t.Fatalf("a bundle signed by a key in the accepted set must verify: got=%+v err=%v", got, err)
	}

	// A signer OUTSIDE the accepted set is still rejected (the set is not a free pass).
	outSrv := serve(outsider)
	defer outSrv.Close()
	bad := configBundleSource{url: outSrv.URL, client: outSrv.Client(), verifyKeys: keySet, requireSigned: true}
	if _, err := bad.fetch(context.Background()); err == nil {
		t.Fatal("a bundle signed by a key OUTSIDE the accepted set must be rejected")
	}
}
