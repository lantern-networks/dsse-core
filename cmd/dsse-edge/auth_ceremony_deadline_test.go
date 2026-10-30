package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestBrowserCeremonyDeadlineIsSeparateFromNativeHold(t *testing.T) {
	first, gate := ceremonyFixture(t)
	first.recoverySharedKey = true
	start := httptest.NewRecorder()
	first.startForTest(start, httptest.NewRequest(http.MethodGet,
		authTestSignedLink(gate, gate.stepUpURLFor("app:22", "corp", "", "device", "tenant")), nil))
	if start.Code != http.StatusFound {
		t.Fatalf("start: %d", start.Code)
	}
	authorize, err := url.Parse(start.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	state := authorize.Query().Get("state")
	if !strings.HasPrefix(state, sealedAuthStatePrefix) {
		t.Fatal("expected recoverable state")
	}
	first.mu.Lock()
	pending := first.pending[state]
	first.mu.Unlock()
	second := newClientlessBroker(first.registry, first.grants, nil, first.selfBaseURL, first.tenantID, time.Hour, first.signer)
	second.recoverySharedKey = true
	request := httptest.NewRequest(http.MethodGet, first.selfBaseURL+"/clientless/auth/callback", nil)
	for _, cookie := range start.Result().Cookies() {
		request.AddCookie(cookie)
	}
	for _, tc := range []struct {
		name string
		at   time.Time
		want bool
	}{
		{"native hold ended but browser login remains valid", pending.createdAt.Add(steerMuxStepUpGrantWait + time.Second), true},
		{"just before original browser deadline", pending.deadline.Add(-time.Nanosecond), true},
		{"exact browser deadline", pending.deadline, false},
		{"past browser deadline", pending.deadline.Add(time.Second), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, ok := second.recoverAuthState(request, state, tc.at); ok != tc.want {
				t.Fatalf("recovery allowed=%v, want %v", ok, tc.want)
			}
		})
	}
	// An actually expired encrypted callback must be rejected before contacting
	// the provider, and cannot mint a grant after a process restart.
	pending.createdAt = time.Now().Add(-pendingAuthTTL - time.Second)
	pending.deadline = pending.createdAt.Add(pendingAuthTTL)
	expired, err := first.sealAuthState(pending)
	if err != nil {
		t.Fatal(err)
	}
	callback := request.Clone(request.Context())
	callback.URL.RawQuery = url.Values{"state": {expired}, "code": {"not-redeemable"}}.Encode()
	response := httptest.NewRecorder()
	second.handleCallback(response, callback)
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "Sign-in link expired") || len(second.grants.ListAll()) != 0 {
		t.Fatal("expired callback was not rejected before provider exchange and grant mint")
	}
}
