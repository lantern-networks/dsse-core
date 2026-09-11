package main

import (
	"net/http"
	"testing"
	"time"
)

func TestMeshAntiReplaySignVerifyRoundTrip(t *testing.T) {
	const secret = "mesh-s3cr3t"
	body := []byte(`{"identity":"dev-roamer","reason":"admin_kill"}`)
	now := time.Unix(1_700_000_000, 0).UTC()
	guard := newMeshReplayGuard(meshAntiReplayWindow)

	h := http.Header{}
	signMeshRequest(h, secret, body, now)
	if h.Get(meshSignatureHeader) == "" || h.Get(meshNonceHeader) == "" || h.Get(meshTimestampHeader) == "" {
		t.Fatal("signMeshRequest must set ts/nonce/sig headers")
	}

	// Fresh, authentic request verifies.
	if err := verifyMeshAntiReplay(h, secret, body, guard, now); err != nil {
		t.Fatalf("fresh request must verify: %v", err)
	}
	// Replay of the SAME request (same nonce) is rejected.
	if err := verifyMeshAntiReplay(h, secret, body, guard, now); err == nil {
		t.Fatal("replayed nonce must be rejected")
	}
}

// Review #31: a request whose timestamp is AHEAD of the receiver (sender clock skew) is retained until
// ts+window, not receiver-now+window. Otherwise the nonce is forgotten while the request is still within its
// freshness window, re-opening a replay hole. Here the sender is ahead by nearly a full window; a replay
// attempt just before the freshness window closes must still be rejected.
func TestMeshAntiReplayForwardSkewReplayIsRejected(t *testing.T) {
	const secret = "mesh-s3cr3t"
	body := []byte(`{"identity":"dev-roamer"}`)
	guard := newMeshReplayGuard(meshAntiReplayWindow)

	receiverNow := time.Unix(1_700_000_000, 0).UTC()
	// Sender clock is ahead by (window - 1s): ts is in the receiver's future but within the freshness window.
	senderTS := receiverNow.Add(meshAntiReplayWindow - time.Second)
	h := http.Header{}
	signMeshRequest(h, secret, body, senderTS)

	// First arrival verifies.
	if err := verifyMeshAntiReplay(h, secret, body, guard, receiverNow); err != nil {
		t.Fatalf("forward-skewed but in-window request must verify: %v", err)
	}
	// A replay that arrives just before the request's OWN freshness window (ts+window) closes must be
	// rejected. With the old now+window retention the nonce was already evicted by this point.
	replayAt := senderTS.Add(meshAntiReplayWindow - time.Second) // still <= ts+window (in freshness window)
	if err := verifyMeshAntiReplay(h, secret, body, guard, replayAt); err == nil {
		t.Fatal("a forward-skewed nonce must stay remembered until ts+window; replay must be rejected")
	}
}

func TestMeshAntiReplayRejections(t *testing.T) {
	const secret = "mesh-s3cr3t"
	body := []byte(`{"identity":"dev1"}`)
	now := time.Unix(1_700_000_000, 0).UTC()

	sign := func(at time.Time) http.Header {
		h := http.Header{}
		signMeshRequest(h, secret, body, at)
		return h
	}

	// Tampered body: signature no longer matches.
	h := sign(now)
	if err := verifyMeshAntiReplay(h, secret, []byte(`{"identity":"attacker"}`), newMeshReplayGuard(meshAntiReplayWindow), now); err == nil {
		t.Fatal("tampered body must fail signature check")
	}

	// Stale timestamp (outside the freshness window).
	h = sign(now.Add(-2 * meshAntiReplayWindow))
	if err := verifyMeshAntiReplay(h, secret, body, newMeshReplayGuard(meshAntiReplayWindow), now); err == nil {
		t.Fatal("stale timestamp must be rejected")
	}

	// Wrong secret: signature mismatch.
	h = sign(now)
	if err := verifyMeshAntiReplay(h, "other-secret", body, newMeshReplayGuard(meshAntiReplayWindow), now); err == nil {
		t.Fatal("wrong secret must fail")
	}

	// Missing headers with a secret configured: rejected.
	if err := verifyMeshAntiReplay(http.Header{}, secret, body, newMeshReplayGuard(meshAntiReplayWindow), now); err == nil {
		t.Fatal("missing anti-replay headers must be rejected when a secret is configured")
	}

	// No secret configured: anti-replay is a no-op (mTLS-only link).
	if err := verifyMeshAntiReplay(http.Header{}, "", body, nil, now); err != nil {
		t.Fatalf("no-secret link must skip anti-replay: %v", err)
	}
}
