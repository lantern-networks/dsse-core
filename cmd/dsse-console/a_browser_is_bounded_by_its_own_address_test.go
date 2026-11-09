package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lantern-networks/dsse-core/frontdoor"
)

// Review R2 (2026-11-07). The control plane sees every proxied sign-in arrive from the Console, so a bound
// keyed on that address punished every colleague for one person's flood. The Console is the door the
// browser knocks on, and behind the deployment's front door it learns the browser's address from the PROXY
// protocol header; this is where attempts are bounded per browser.
func TestSignInAttemptsAreBoundedPerBrowserAddress(t *testing.T) {
	upstreamHits := 0
	h := signInThrottled(frontdoor.NewTokenBucket(5, 3), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits++
		w.WriteHeader(http.StatusUnauthorized)
	}))
	codes := map[int]int{}
	for i := 0; i < 6; i++ {
		r := httptest.NewRequest(http.MethodPost, "/admin/login/password", nil)
		r.RemoteAddr = "203.0.113.9:4000"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		codes[w.Code]++
	}
	if codes[http.StatusTooManyRequests] == 0 || codes[http.StatusUnauthorized] != 3 {
		t.Fatalf("one browser's flood was not bounded at its burst: %v", codes)
	}
	other := httptest.NewRequest(http.MethodPost, "/admin/login/password", nil)
	other.RemoteAddr = "198.51.100.4:4000"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, other)
	if w.Code == http.StatusTooManyRequests {
		t.Fatal("a different browser was throttled for the first one's flood")
	}
	// Routes that carry no credential are not bounded here at all.
	page := httptest.NewRequest(http.MethodGet, "/admin/session", nil)
	page.RemoteAddr = "203.0.113.9:4000"
	w = httptest.NewRecorder()
	h.ServeHTTP(w, page)
	if w.Code == http.StatusTooManyRequests {
		t.Fatal("a route without a credential was throttled")
	}
}

func TestTheSignInPathsAreExactlyTheCredentialBearingOnes(t *testing.T) {
	for _, p := range []string{"/admin/login/password", "/admin/login/totp", "/admin/activate", "/admin/activate/password", "/admin/activate/totp/begin"} {
		if !isSignInPath(p) {
			t.Errorf("%s carries a credential and is not bounded", p)
		}
	}
	for _, p := range []string{"/admin/session", "/admin/logout", "/admin/admins", "/auth/oidc/login", "/"} {
		if isSignInPath(p) {
			t.Errorf("%s carries no credential and is bounded", p)
		}
	}
}
