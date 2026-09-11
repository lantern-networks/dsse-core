package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/revocation"
)

// TestRevocationSyncKeepsRevocationsOnEmptyFeed pins fail-open review finding #5: a 200 with an EMPTY revocation
// set must NOT wipe the CP-distributed (synced) layer — that would silently un-revoke every fleet kill-switch. The
// sync keeps the local set and logs (lockout-safe). A fetch failure already kept the set; this covers the
// successful-but-empty response the old code applied blindly.
func TestRevocationSyncKeepsRevocationsOnEmptyFeed(t *testing.T) {
	var hits int32
	cp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/revocations" {
			http.NotFound(w, r)
			return
		}
		atomic.AddInt32(&hits, 1)
		// Always answer with an EMPTY set at a NEW generation (the dangerous case: a real 200, not an error).
		_ = json.NewEncoder(w).Encode(revocationFeed{Generation: 99, Epoch: "e1", Revoked: map[string]string{}})
	}))
	defer cp.Close()

	overlay := revocation.NewAdmissionRevocations()
	// A CP-distributed revocation is already in force on this Edge (a prior non-empty pull).
	overlay.ReplaceSynced(map[string]string{"win-dev-1": "admin_kill_switch"})
	if _, ok := overlay.IsRevoked("win-dev-1"); !ok {
		t.Fatal("precondition: win-dev-1 must start revoked")
	}

	src := revocationSource{url: cp.URL, token: "t", interval: time.Hour, client: cp.Client()}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { src.run(ctx, overlay, nil); close(done) }()

	// Wait until the initial pull has hit the CP, then stop the loop.
	deadline := time.Now().Add(3 * time.Second)
	for atomic.LoadInt32(&hits) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done

	if atomic.LoadInt32(&hits) == 0 {
		t.Fatal("the sync never pulled the CP")
	}
	// The empty feed must NOT have un-revoked the fleet kill-switch.
	if _, ok := overlay.IsRevoked("win-dev-1"); !ok {
		t.Fatal("an empty CP feed silently un-revoked win-dev-1 — the lockout-safe guard failed")
	}
	if overlay.SyncedCount() != 1 {
		t.Fatalf("synced revocation was wiped by an empty feed: SyncedCount=%d, want 1", overlay.SyncedCount())
	}
}

// The other half of the same rule: an AUTHORITATIVE empty set DOES release.
//
// Keeping a non-authoritative empty set is right, but for a long time it was the only behaviour, and the
// consequence was that letting a device back in did not work. An administrator restored the identity on the
// control plane, the set went to zero, every Edge refused to believe it, and the device stayed locked out until
// somebody restarted the Edge. A kill-switch that can be pressed but not released by the path that pressed it
// is half a mechanism, and the half that is missing is the one you need while somebody cannot work.
func TestRevocationSyncReleasesOnAuthoritativeEmptyFeed(t *testing.T) {
	var hits int32
	cp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/revocations" {
			http.NotFound(w, r)
			return
		}
		atomic.AddInt32(&hits, 1)
		// The control plane stating its COMPLETE set, which happens to be empty: a real release.
		_ = json.NewEncoder(w).Encode(revocationFeed{
			Generation: 99, Epoch: "e1", Revoked: map[string]string{}, Authoritative: true,
		})
	}))
	defer cp.Close()

	overlay := revocation.NewAdmissionRevocations()
	overlay.ReplaceSynced(map[string]string{"win-dev-1": "admin_kill_switch"})
	if _, ok := overlay.IsRevoked("win-dev-1"); !ok {
		t.Fatal("precondition: win-dev-1 must start revoked")
	}

	src := revocationSource{url: cp.URL, token: "t", interval: time.Hour, client: cp.Client()}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { src.run(ctx, overlay, nil); close(done) }()

	// Wait for the EFFECT, not for the request. hits is incremented as the handler is entered, so a pull that
	// has been counted has not necessarily been applied — and this test asserts that something changed, which
	// makes it sensitive to that gap in a way its keep-local twin is not: a test asserting nothing changed
	// passes when the apply never ran. Waiting on the request was wrong here and failed roughly half the time
	// under a full-suite run.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, still := overlay.IsRevoked("win-dev-1"); !still {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done

	if atomic.LoadInt32(&hits) == 0 {
		t.Fatal("the sync never pulled the CP")
	}
	if _, ok := overlay.IsRevoked("win-dev-1"); ok {
		t.Fatal("an AUTHORITATIVE empty feed did not release win-dev-1 — an administrator's restore never reaches the fleet, and the only way back is an Edge restart")
	}
	if overlay.SyncedCount() != 0 {
		t.Fatalf("SyncedCount=%d, want 0 after an authoritative release", overlay.SyncedCount())
	}
}
