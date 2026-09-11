package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/enrolltoken"
)

// The bootstrap endpoint is public and unauthenticated by construction, so the limit has to actually bite —
// but on the ATTEMPT, before any of the work an attacker is trying to cause.
func TestEnrolIsRateLimitedPerSource(t *testing.T) {
	mux, _, _ := newTokenEnrolTestMux(t)

	limited := 0
	for i := 0; i < enrolRateLimitBurst+15; i++ {
		if code, _ := enrolPost(t, mux, "probe", "not-a-real-token"); code == http.StatusTooManyRequests {
			limited++
		}
	}
	if limited == 0 {
		t.Fatalf("a flood from one source must eventually be refused with 429")
	}
	// The burst has to be spent first: a limit that engages on the first request would refuse the very first
	// device anyone tries to enrol.
	if code, _ := enrolPost(t, mux, "probe", "not-a-real-token"); code != http.StatusTooManyRequests {
		t.Fatalf("once the bucket is empty it stays empty until it refills, got %d", code)
	}
}

// A kitting run is the case this must not break: an office NAT means fifty laptops enrol from one source IP, and
// refusing there strands machines an operator has already approved. The burst has to cover a realistic batch.
func TestTheBurstCoversARealisticKittingBatch(t *testing.T) {
	mux, tokens, _ := newTokenEnrolTestMux(t)
	now := time.Now().UTC()

	for i := 0; i < 10; i++ {
		_, secret, err := tokens.Issue(enrolltoken.DefaultPolicy(), "tenant_test", "", "", "adm_alice", "",
			now.Add(time.Hour), now)
		if err != nil {
			t.Fatalf("issue %d: %v", i, err)
		}
		code, resp := enrolPost(t, mux, "laptop-batch-"+string(rune('a'+i)), secret)
		if code != http.StatusOK {
			t.Fatalf("machine %d of a batch was refused (%d, %q) — the limit is too tight for a kitting run",
				i, code, resp.Error)
		}
	}
}

// Renewal must not be throttled: it authenticates with the certificate being renewed, so it is not an
// unauthenticated surface, and throttling it would turn a fleet-wide renewal window into a fleet-wide expiry.
// This asserts the ROUTE is separate — a shared limiter would be the mistake.
func TestRenewalIsNotBehindTheEnrolmentLimiter(t *testing.T) {
	mux, _, _ := newTokenEnrolTestMux(t)
	for i := 0; i < enrolRateLimitBurst+5; i++ {
		enrolPost(t, mux, "probe", "not-a-real-token")
	}
	// The enrolment bucket is now empty. A request to the renew path must not inherit that refusal — it is not
	// registered on this mux in the test, so anything other than 429 proves the limiter is not global.
	req := httptest.NewRequest(http.MethodPost, "/enroll/renew", strings.NewReader(`{"csr_pem":"x"}`))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code == http.StatusTooManyRequests {
		t.Fatalf("renewal is sharing the enrolment rate limiter — a fleet-wide renewal window would become a fleet-wide expiry")
	}
}
