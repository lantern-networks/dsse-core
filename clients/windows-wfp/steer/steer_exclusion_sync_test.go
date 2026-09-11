package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/agentpolicy"
)

// A signed-policy server stub; failing toggles a 500 so we can assert fail-safe behavior.
func signedPolicyServer(t *testing.T, signer *agentpolicy.Signer, excluded []string, failing *atomic.Bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if failing.Load() {
			http.Error(w, "edge down", http.StatusInternalServerError)
			return
		}
		switch r.URL.Path {
		case "/steer/agent-policy/pubkey":
			json.NewEncoder(w).Encode(agentpolicy.PubKey{KeyID: signer.KeyID(), PublicKey: signer.PublicKeyHex()})
		case "/steer/agent-policy":
			env, _ := signer.Sign(map[string]any{
				"schema_version":           agentpolicy.EnvelopeType,
				"tenant_id":                "tenant_dev_lab",
				"device_identity":          "win-dev-1",
				"excluded_app_signing_ids": excluded,
			}, time.Now())
			json.NewEncoder(w).Encode(env)
		default:
			http.NotFound(w, r)
		}
	}))
}

// A signed-policy server that also carries the operator's renew_certificates_issued_before declaration.
func signedPolicyServerWithCutoff(t *testing.T, signer *agentpolicy.Signer, cutoff string, failing *atomic.Bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if failing.Load() {
			http.Error(w, "edge down", http.StatusInternalServerError)
			return
		}
		if r.URL.Path != "/steer/agent-policy" {
			http.NotFound(w, r)
			return
		}
		env, _ := signer.Sign(map[string]any{
			"schema_version":                   agentpolicy.EnvelopeType,
			"tenant_id":                        "tenant_dev_lab",
			"device_identity":                  "win-dev-1",
			"excluded_app_signing_ids":         []string{},
			"renew_certificates_issued_before": cutoff,
		}, time.Now())
		json.NewEncoder(w).Encode(env)
	}))
}

// The cutoff is published ONLY from a verified policy, and a fetch failure leaves the last verified value in
// force (fail-safe) rather than resetting it — mirroring the macOS cached-policy behaviour.
func TestExclusionSyncPublishesRenewCutoffOnlyWhenVerified(t *testing.T) {
	signer, _ := agentpolicy.LoadOrGenerateSigner("", true)
	var failing atomic.Bool
	srv := signedPolicyServerWithCutoff(t, signer, "2026-07-30T20:55:50Z", &failing)
	defer srv.Close()

	declaration := newRenewalDeclaration()
	published := &declaration.cutoff
	s := &exclusionSync{
		client:             srv.Client(),
		baseURL:            srv.URL,
		pinHex:             signer.PublicKeyHex(),
		apply:              func([]string) {},
		publishRenewCutoff: declaration.publish,
	}
	if _, err := s.refreshOnce(context.Background()); err != nil {
		t.Fatalf("refreshOnce: %v", err)
	}
	got := published.Load()
	if got == nil || !got.Equal(time.Date(2026, 7, 30, 20, 55, 50, 0, time.UTC)) {
		t.Fatalf("published cutoff = %v, want 2026-07-30T20:55:50Z", got)
	}
	select {
	case <-declaration.wake:
	default:
		t.Fatal("verified declaration did not wake renewal")
	}
	for i := 0; i < 3; i++ {
		if _, err := s.refreshOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case <-declaration.wake:
		t.Fatal("unchanged policy repeatedly woke renewal")
	default:
	}

	// The Edge goes down: refreshOnce errors, and the previously published cutoff must NOT be disturbed.
	failing.Store(true)
	if _, err := s.refreshOnce(context.Background()); err == nil {
		t.Fatal("expected a fetch error while the Edge is down")
	}
	if after := published.Load(); after == nil || !after.Equal(*got) {
		t.Fatalf("a fetch failure changed the published cutoff (%v -> %v)", got, after)
	}

	// A verified policy that OMITS the field publishes the zero time — the operator withdrew the request.
	failing.Store(false)
	srv2 := signedPolicyServer(t, signer, []string{}, &failing) // no cutoff field
	defer srv2.Close()
	s.baseURL = srv2.URL
	s.client = srv2.Client()
	if _, err := s.refreshOnce(context.Background()); err != nil {
		t.Fatalf("refreshOnce (no cutoff): %v", err)
	}
	if after := published.Load(); after == nil || !after.IsZero() {
		t.Fatalf("a verified policy without the field must publish the zero time, got %v", after)
	}
	select {
	case <-declaration.wake:
		t.Fatal("a failed fetch or withdrawn declaration woke renewal")
	default:
	}
}

func TestExclusionSyncAppliesAdditiveMerge(t *testing.T) {
	signer, _ := agentpolicy.LoadOrGenerateSigner("", true)
	var failing atomic.Bool
	srv := signedPolicyServer(t, signer, []string{"corpvpn.exe", "backup-agent.exe"}, &failing)
	defer srv.Close()

	var applied atomic.Value // []string
	s := &exclusionSync{
		client:        srv.Client(),
		baseURL:       srv.URL,
		pinHex:        signer.PublicKeyHex(),
		localBaseline: []string{"windivert-steer", "automation"}, // infra/self baseline (--bypass-app)
		apply:         func(v []string) { applied.Store(v) },
	}
	if _, err := s.refreshOnce(context.Background()); err != nil {
		t.Fatalf("refreshOnce: %v", err)
	}
	got, _ := applied.Load().([]string)
	want := []string{"windivert-steer", "automation", "corpvpn.exe", "backup-agent.exe"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("applied = %v, want %v (infra baseline kept, server set added)", got, want)
	}
}

func TestExclusionSyncFailSafeKeepsCurrentSet(t *testing.T) {
	signer, _ := agentpolicy.LoadOrGenerateSigner("", true)
	var failing atomic.Bool
	srv := signedPolicyServer(t, signer, []string{"corpvpn.exe"}, &failing)
	defer srv.Close()

	applies := 0
	s := &exclusionSync{
		client:        srv.Client(),
		baseURL:       srv.URL,
		pinHex:        signer.PublicKeyHex(),
		localBaseline: []string{"automation"},
		apply:         func([]string) { applies++ },
	}
	// First refresh succeeds and applies.
	if _, err := s.refreshOnce(context.Background()); err != nil {
		t.Fatalf("first refresh: %v", err)
	}
	// Edge goes down: refresh must error and NOT apply (the current set stays in force — never start
	// steering an excluded app because of a transient outage).
	failing.Store(true)
	if _, err := s.refreshOnce(context.Background()); err == nil {
		t.Fatal("a failing edge must return an error")
	}
	if applies != 1 {
		t.Fatalf("apply called %d times; a failed refresh must not re-apply (fail-safe)", applies)
	}
}

func TestExclusionSyncRejectsWrongPin(t *testing.T) {
	signer, _ := agentpolicy.LoadOrGenerateSigner("", true)
	var failing atomic.Bool
	srv := signedPolicyServer(t, signer, []string{"corpvpn.exe"}, &failing)
	defer srv.Close()

	applied := false
	s := &exclusionSync{
		client:        srv.Client(),
		baseURL:       srv.URL,
		pinHex:        "0000000000000000000000000000000000000000000000000000000000000000",
		localBaseline: []string{"automation"},
		apply:         func([]string) { applied = true },
	}
	if _, err := s.refreshOnce(context.Background()); err == nil {
		t.Fatal("a policy signed by an untrusted key must be rejected")
	}
	if applied {
		t.Fatal("an unverifiable policy must never be applied")
	}
}
