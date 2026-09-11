package agenttuning

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSyncer_FetchOnce_AppliesVerifiedTuning(t *testing.T) {
	env, pub := sign(t, TuningPolicy{TenantID: "acme", DeviceGroup: "dev", Captive: &CaptiveTuning{TimeoutSec: 300, ProbeIntervalSec: 5}})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(env)
	}))
	defer srv.Close()

	var applied *TuningPolicy
	s := Syncer{URL: srv.URL, PinHex: pub, Client: http.DefaultClient, Apply: func(p TuningPolicy) { applied = &p }}
	if err := s.FetchOnce(context.Background()); err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if applied == nil {
		t.Fatalf("Apply not called on a verified policy")
	}
	got := applied.ApplyCaptive(CaptiveSettings{TimeoutSec: 180, ProbeIntervalSec: 3})
	if got.TimeoutSec != 300 || got.ProbeIntervalSec != 5 {
		t.Fatalf("applied tuning wrong: %+v", got)
	}
}

func TestSyncer_FetchOnce_WrongPin_DoesNotApply(t *testing.T) {
	env, _ := sign(t, TuningPolicy{TenantID: "acme", Captive: &CaptiveTuning{TimeoutSec: 300}})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(env) }))
	defer srv.Close()

	other, _ := agentpolicySigner(t)
	called := false
	s := Syncer{URL: srv.URL, PinHex: other, Client: http.DefaultClient, Apply: func(TuningPolicy) { called = true }}
	if err := s.FetchOnce(context.Background()); err == nil {
		t.Fatalf("wrong pin must error")
	}
	if called {
		t.Fatalf("Apply must NOT be called on an unverified policy (keep current settings)")
	}
}

func TestSyncer_FetchOnce_ServerError_DoesNotApply(t *testing.T) {
	_, pub := sign(t, TuningPolicy{TenantID: "acme"})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }))
	defer srv.Close()

	called := false
	s := Syncer{URL: srv.URL, PinHex: pub, Client: http.DefaultClient, Apply: func(TuningPolicy) { called = true }}
	if err := s.FetchOnce(context.Background()); err == nil {
		t.Fatalf("5xx must error")
	}
	if called {
		t.Fatalf("Apply must not be called on a server error")
	}
}

func TestSyncer_FetchOnce_TimesOut(t *testing.T) {
	_, pub := sign(t, TuningPolicy{TenantID: "acme"})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done() // never respond; block until the client aborts
	}))
	defer srv.Close()

	called := false
	s := Syncer{URL: srv.URL, PinHex: pub, Client: http.DefaultClient, FetchTimeout: 200 * time.Millisecond, Apply: func(TuningPolicy) { called = true }}
	start := time.Now()
	err := s.FetchOnce(context.Background())
	if err == nil {
		t.Fatalf("a hung CP must produce an error, not hang")
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("FetchOnce did not honor the per-fetch timeout: %v", d)
	}
	if called {
		t.Fatalf("Apply must not be called on a timed-out fetch")
	}
}

func TestSyncer_Run_StopsOnContext(t *testing.T) {
	_, pub := sign(t, TuningPolicy{TenantID: "acme"})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }))
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		Syncer{URL: srv.URL, PinHex: pub, Client: http.DefaultClient, Interval: 10 * time.Millisecond}.Run(ctx)
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("Run did not stop on ctx cancel")
	}
}

// agentpolicySigner returns a fresh signer's public key hex for negative tests.
func agentpolicySigner(t *testing.T) (string, error) {
	t.Helper()
	_, pub := sign(t, TuningPolicy{TenantID: "x"})
	return pub, nil
}
