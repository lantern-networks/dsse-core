package agentpolicy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// steeringPostureServer stands up a test Edge that signs and serves a steering-posture envelope.
func steeringPostureServer(t *testing.T, signer *Signer, payload map[string]any) (string, *http.Client) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc(steeringPosturePath, func(w http.ResponseWriter, _ *http.Request) {
		env, err := signer.Sign(payload, time.Now())
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(env)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL, srv.Client()
}

func TestFetchVerifiedSteeringPosture_Valid(t *testing.T) {
	signer, err := LoadOrGenerateSigner("", true)
	if err != nil {
		t.Fatal(err)
	}
	payload := map[string]any{
		"schema_version":        SteeringPostureSchema,
		"tenant_id":             "tenant-a",
		"device_identity":       "win-dev-1",
		"fail_open_mode":        FailOpenTerminal,
		"fail_open_cooldown_ms": 10000,
		"region_failover":       true,
	}
	base, client := steeringPostureServer(t, signer, payload)

	got, err := FetchVerifiedSteeringPosture(context.Background(), client, base, signer.PublicKeyHex())
	if err != nil {
		t.Fatalf("valid signed posture must verify: %v", err)
	}
	if got.TenantID != "tenant-a" || got.FailOpenCooldownMS != 10000 || !got.RegionFailover {
		t.Fatalf("posture metadata wrong: %+v", got)
	}
	if !got.FailOpenPermitted() {
		t.Fatalf("fail_open_mode=terminal must permit fail-open")
	}
}

// FailOpenPermitted must be strict: only "terminal" permits fail-open; empty/unknown/typo => fail-CLOSED, so a
// malformed policy can never accidentally widen the boundary.
func TestSteeringPosture_FailOpenPermittedIsStrict(t *testing.T) {
	cases := map[string]bool{
		"terminal": true, "TERMINAL": true, " terminal ": true,
		"off": false, "": false, "open": false, "true": false, "yes": false, "termina": false,
	}
	for mode, want := range cases {
		p := SteeringPosturePayload{FailOpenMode: mode}
		if got := p.FailOpenPermitted(); got != want {
			t.Fatalf("FailOpenPermitted(%q) = %v, want %v (unknown/typo must be fail-CLOSED)", mode, got, want)
		}
	}
}

func TestFetchVerifiedSteeringPosture_WrongKeyRejected(t *testing.T) {
	signer, _ := LoadOrGenerateSigner("", true)
	attacker, _ := LoadOrGenerateSigner("", true) // a DIFFERENT key
	payload := map[string]any{"schema_version": SteeringPostureSchema, "fail_open_mode": FailOpenTerminal}
	base, client := steeringPostureServer(t, signer, payload)

	if _, err := FetchVerifiedSteeringPosture(context.Background(), client, base, attacker.PublicKeyHex()); err == nil {
		t.Fatal("a posture signed by a different key MUST be rejected (fail-closed)")
	}
}

func TestFetchVerifiedSteeringPosture_WrongSchemaRejected(t *testing.T) {
	signer, _ := LoadOrGenerateSigner("", true)
	// A correctly-signed envelope, but the payload is a steer-exclusion body, not a posture.
	payload := map[string]any{"schema_version": EnvelopeType, "excluded_app_signing_ids": []string{"com.example.vpn"}}
	base, client := steeringPostureServer(t, signer, payload)

	_, err := FetchVerifiedSteeringPosture(context.Background(), client, base, signer.PublicKeyHex())
	if err == nil || !strings.Contains(err.Error(), "schema_version") {
		t.Fatalf("a mis-schema'd (but validly signed) body MUST be rejected; got %v", err)
	}
}

func TestFetchVerifiedSteeringPosture_NoPinRejected(t *testing.T) {
	if _, err := FetchVerifiedSteeringPosture(context.Background(), http.DefaultClient, "https://x", ""); err == nil {
		t.Fatal("an empty pin MUST be rejected (no TOFU on every fetch)")
	}
}
