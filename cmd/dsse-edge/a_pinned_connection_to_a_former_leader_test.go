package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// ★★★ HALF A FLEET COULD NOT ENROL ANYTHING, INDEFINITELY (2026-08-27, measured on a deployment standing
// itself up). The enrolment-token authority is a PAIR behind a front door whose health check is GET /leader,
// so a standby is marked down and NEW connections reach the leader — but an established connection is kept,
// and this client pools them. An Edge that first connected while the other node led held that connection for
// ever: 400 seconds of continuous refusal, while the other Edge behind the same region door worked, so
// nothing looked broken. Recreating both Edges cleared it instantly.
//
// The answer names the wrong party: "this control plane does not hold leadership" is a fact about the
// CONNECTION, not about the token — and nothing was spent, so trying again costs nothing.
func TestAnAuthorityThatDeniesLeadershipIsAskedAgainOnAFreshConnection(t *testing.T) {
	var calls int32
	// The first request is answered by a node that does not lead; every later one by the leader. A real
	// deployment separates them by connection; this separates them by call, which is the same test of whether
	// the client tries again at all.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		if atomic.AddInt32(&calls, 1) == 1 {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error": "enrolment token refused: this control plane does not hold leadership, and an " +
					"administrative change written here would be accepted and then discarded",
			})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"token": map[string]any{"secret": "s", "tenant_id": "t1"}})
	}))
	defer srv.Close()

	authority := &remoteEnrolmentTokenAuthority{
		url:    srv.URL,
		token:  "admin",
		client: &http.Client{Timeout: 5 * time.Second},
	}
	if _, err := authority.Verify("s", "t1", time.Now()); err != nil {
		t.Fatalf("the client gave up on an answer that was about the connection: %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("the authority was asked %d time(s); it must be asked again exactly once", got)
	}
}

// ★ AND EXACTLY ONCE. If the second answer says the same thing, leadership is genuinely moving and the caller
// must be told rather than have the Edge sit in a loop while a device waits.
func TestItDoesNotChaseLeadershipForEver(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": "enrolment token refused: this control plane does not hold leadership",
		})
	}))
	defer srv.Close()

	authority := &remoteEnrolmentTokenAuthority{url: srv.URL, token: "admin",
		client: &http.Client{Timeout: 5 * time.Second}}
	if _, err := authority.Verify("s", "t1", time.Now()); err == nil {
		t.Fatal("an authority that never leads was reported as a success")
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("asked %d times; it must stop after the second", got)
	}
}

// ★ A VERDICT ON THE TOKEN IS NOT RETRIED. Retrying "already spent" would burn a second one-time credential
// and hide the first refusal behind the second.
func TestAVerdictOnTheTokenIsAskedOnce(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"error": "token already spent"})
	}))
	defer srv.Close()

	authority := &remoteEnrolmentTokenAuthority{url: srv.URL, token: "admin",
		client: &http.Client{Timeout: 5 * time.Second}}
	if _, err := authority.Verify("s", "t1", time.Now()); err == nil {
		t.Fatal("a spent token was accepted")
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("a verdict was asked %d times; it must be asked once", got)
	}
}
