package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/agentpolicy"
)

// reportingPolicyServer serves the signed agent-policy AND captures the reverse-telemetry POST to
// /steer/agent-policy/effective. reportFails toggles a 500 on the effective endpoint so we can assert
// fail-safe behavior (a report failure must NOT fail refreshOnce). The captured body is stored for
// assertions.
type capturedReport struct {
	hit     atomic.Bool
	body    atomic.Value // map[string]any
	headers atomic.Value // http.Header
}

func reportingPolicyServer(t *testing.T, signer *agentpolicy.Signer, excluded []string, reportFails *atomic.Bool, cap *capturedReport) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		case "/steer/agent-policy/effective":
			cap.hit.Store(true)
			cap.headers.Store(r.Header.Clone())
			var body map[string]any
			json.NewDecoder(r.Body).Decode(&body)
			cap.body.Store(body)
			if reportFails.Load() {
				http.Error(w, "telemetry down", http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
}

// TestExclusionSyncReportsEffectiveSet asserts that after a successful refresh the agent POSTs the MERGED
// effective set (infra baseline + server set) to /steer/agent-policy/effective with platform "windows"
// and the server-set count.
func TestExclusionSyncReportsEffectiveSet(t *testing.T) {
	signer, _ := agentpolicy.LoadOrGenerateSigner("", true)
	var reportFails atomic.Bool
	var cap capturedReport
	srv := reportingPolicyServer(t, signer, []string{"corpvpn.exe", "backup-agent.exe"}, &reportFails, &cap)
	defer srv.Close()

	var applied atomic.Value // []string
	s := &exclusionSync{
		client:        srv.Client(),
		baseURL:       srv.URL,
		pinHex:        signer.PublicKeyHex(),
		localBaseline: []string{"windivert-steer", "automation"},
		apply:         func(v []string) { applied.Store(v) },
	}
	merged, err := s.refreshOnce(context.Background())
	if err != nil {
		t.Fatalf("refreshOnce: %v", err)
	}

	if !cap.hit.Load() {
		t.Fatal("expected a POST to /steer/agent-policy/effective after refresh")
	}
	body, _ := cap.body.Load().(map[string]any)
	if body == nil {
		t.Fatal("no report body captured")
	}
	if got := body["platform"]; got != "windows" {
		t.Fatalf("platform = %v, want windows", got)
	}
	// server_app_signing_id_count is the count of the SERVER-issued set (2), not the merged total.
	if got, ok := body["server_app_signing_id_count"].(float64); !ok || int(got) != 2 {
		t.Fatalf("server_app_signing_id_count = %v, want 2", body["server_app_signing_id_count"])
	}
	gotIDs := toStrings(body["effective_app_signing_ids"])
	wantIDs := []string{"windivert-steer", "automation", "corpvpn.exe", "backup-agent.exe"}
	if !reflect.DeepEqual(gotIDs, wantIDs) {
		t.Fatalf("effective_app_signing_ids = %v, want %v (the merged set the device applies)", gotIDs, wantIDs)
	}
	// The reported set must equal the applied/merged set — reverse telemetry mirrors enforcement exactly.
	if !reflect.DeepEqual(gotIDs, merged) {
		t.Fatalf("reported set %v != applied merged set %v", gotIDs, merged)
	}
	if h, _ := cap.headers.Load().(http.Header); h.Get("Content-Type") != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", h.Get("Content-Type"))
	}
}

// TestExclusionSyncReportFailureDoesNotFailRefresh asserts that a failing /effective endpoint does NOT
// fail refreshOnce: the exclusion set is still applied and refreshOnce returns no error (best-effort,
// fail-safe reverse telemetry never affects steering).
func TestExclusionSyncReportFailureDoesNotFailRefresh(t *testing.T) {
	signer, _ := agentpolicy.LoadOrGenerateSigner("", true)
	var reportFails atomic.Bool
	reportFails.Store(true) // the telemetry endpoint is broken from the start
	var cap capturedReport
	srv := reportingPolicyServer(t, signer, []string{"corpvpn.exe"}, &reportFails, &cap)
	defer srv.Close()

	var applied atomic.Value // []string
	s := &exclusionSync{
		client:        srv.Client(),
		baseURL:       srv.URL,
		pinHex:        signer.PublicKeyHex(),
		localBaseline: []string{"automation"},
		apply:         func(v []string) { applied.Store(v) },
	}
	merged, err := s.refreshOnce(context.Background())
	if err != nil {
		t.Fatalf("a failing effective-report endpoint must NOT fail refreshOnce: %v", err)
	}
	if !cap.hit.Load() {
		t.Fatal("expected the report to be attempted even though it fails")
	}
	got, _ := applied.Load().([]string)
	want := []string{"automation", "corpvpn.exe"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("applied = %v, want %v (the exclusion set is applied regardless of report failure)", got, want)
	}
	if !reflect.DeepEqual(merged, want) {
		t.Fatalf("refreshOnce returned %v, want %v", merged, want)
	}
}

// TestExclusionSyncReportsBaselineWithoutPin asserts the reverse-telemetry report is NOT gated on a signed
// policy: with an EMPTY pin (no --agent-policy-pin), refreshOnce must NOT fetch or apply, but must STILL
// POST the local --bypass-app baseline as the effective set with server_app_signing_id_count=0. This is the
// case an admin most needs to see — a device carrying only a locally-configured (unmanaged) bypass.
func TestExclusionSyncReportsBaselineWithoutPin(t *testing.T) {
	signer, _ := agentpolicy.LoadOrGenerateSigner("", true)
	var reportFails atomic.Bool
	var cap capturedReport
	// The server would serve a signed set, but with no pin the sync must never fetch it.
	srv := reportingPolicyServer(t, signer, []string{"corpvpn.exe", "backup-agent.exe"}, &reportFails, &cap)
	defer srv.Close()

	var appliedCalled atomic.Bool
	s := &exclusionSync{
		client:        srv.Client(),
		baseURL:       srv.URL,
		pinHex:        "", // no signed policy
		localBaseline: []string{"windivert-steer", "example-app"},
		apply:         func([]string) { appliedCalled.Store(true) },
	}
	merged, err := s.refreshOnce(context.Background())
	if err != nil {
		t.Fatalf("refreshOnce (no pin): %v", err)
	}
	if appliedCalled.Load() {
		t.Fatal("apply must NOT be called with no signed policy (the baseline is already in force)")
	}
	if !cap.hit.Load() {
		t.Fatal("expected the effective-set report to be POSTed even with no signed policy")
	}
	body, _ := cap.body.Load().(map[string]any)
	if body == nil {
		t.Fatal("no report body captured")
	}
	if got, ok := body["server_app_signing_id_count"].(float64); !ok || int(got) != 0 {
		t.Fatalf("server_app_signing_id_count = %v, want 0 (no server set)", body["server_app_signing_id_count"])
	}
	gotIDs := toStrings(body["effective_app_signing_ids"])
	want := []string{"windivert-steer", "example-app"}
	if !reflect.DeepEqual(gotIDs, want) {
		t.Fatalf("effective_app_signing_ids = %v, want %v (the local baseline)", gotIDs, want)
	}
	if !reflect.DeepEqual(merged, want) {
		t.Fatalf("refreshOnce returned %v, want %v", merged, want)
	}
}

// TestExclusionSyncReportsDeviceState asserts the device-state fields (posture, fail-open configured,
// region-failover, active region, server-initiated count) ride along in the effective-set report when a
// state callback is wired, so the CP/console device page sees them without a separate channel.
func TestExclusionSyncReportsDeviceState(t *testing.T) {
	var reportFails atomic.Bool
	var cap capturedReport
	signer, _ := agentpolicy.LoadOrGenerateSigner("", true)
	srv := reportingPolicyServer(t, signer, nil, &reportFails, &cap)
	defer srv.Close()

	s := &exclusionSync{
		client:        srv.Client(),
		baseURL:       srv.URL,
		pinHex:        "", // no signed policy — device-state must still be reported
		localBaseline: []string{"example-app"},
		apply:         func([]string) {},
		state: func() deviceStateExtra {
			return deviceStateExtra{
				Posture:                  "disarmed",
				FailOpenConfigured:       true,
				RegionFailoverEnabled:    true,
				ActiveRegion:             "edge-tokyo",
				ServerInitiatedRuleCount: 3,
			}
		},
	}
	if _, err := s.refreshOnce(context.Background()); err != nil {
		t.Fatalf("refreshOnce: %v", err)
	}
	body, _ := cap.body.Load().(map[string]any)
	if body == nil {
		t.Fatal("no report body captured")
	}
	if got := body["posture"]; got != "disarmed" {
		t.Fatalf("posture = %v, want disarmed", got)
	}
	if got := body["fail_open_configured"]; got != true {
		t.Fatalf("fail_open_configured = %v, want true", got)
	}
	if got := body["region_failover_enabled"]; got != true {
		t.Fatalf("region_failover_enabled = %v, want true", got)
	}
	if got := body["active_region"]; got != "edge-tokyo" {
		t.Fatalf("active_region = %v, want edge-tokyo", got)
	}
	if got, ok := body["server_initiated_rule_count"].(float64); !ok || int(got) != 3 {
		t.Fatalf("server_initiated_rule_count = %v, want 3", body["server_initiated_rule_count"])
	}
}

// The report carries the adopted trust serial NEXT TO the pinned-CA fingerprints, and both come from the same
// live transport — so the Edge's CA-withdrawal gate evaluates a serial and a fingerprint set that describe one
// reality. This is the fix for the gate opening on trust a device reports but does not actually verify with.
func TestExclusionSyncReportsAdoptedTrustSerialWithFingerprints(t *testing.T) {
	var reportFails atomic.Bool
	var cap capturedReport
	signer, _ := agentpolicy.LoadOrGenerateSigner("", true)
	srv := reportingPolicyServer(t, signer, nil, &reportFails, &cap)
	defer srv.Close()

	// A transport carrying an adopted set at serial 7: both getters must be wired to it, and both must reflect it.
	ca := newTestCA(t, "DSSE Transport CA")
	tc := &transportConfig{liveTrust: &atomic.Pointer[trustMaterial]{}}
	tc.setTrustAnchors(ca.pem, 7)

	s := &exclusionSync{
		client: srv.Client(), baseURL: srv.URL, pinHex: "", localBaseline: []string{"example-app"},
		apply:                func([]string) {},
		pinnedCAFingerprints: tc.pinnedCAFingerprints,
		adoptedTrustSerial:   tc.currentTrustSerial,
	}
	if _, err := s.refreshOnce(context.Background()); err != nil {
		t.Fatalf("refreshOnce: %v", err)
	}
	body, _ := cap.body.Load().(map[string]any)
	if got, ok := body["adopted_trust_serial"].(float64); !ok || int64(got) != 7 {
		t.Fatalf("adopted_trust_serial = %v, want 7", body["adopted_trust_serial"])
	}
	// The fingerprints reported are exactly the adopted set's — the pair is consistent.
	fps, ok := body["pinned_transport_ca_sha256"].([]any)
	if !ok || len(fps) != 1 {
		t.Fatalf("pinned_transport_ca_sha256 = %v, want one adopted fingerprint", body["pinned_transport_ca_sha256"])
	}
	sum := sha256.Sum256(ca.cert.Raw)
	if fps[0] != hex.EncodeToString(sum[:]) {
		t.Fatalf("reported fingerprint does not match the adopted anchor")
	}
}

// The report carries what the device refused, and CLEARS the journal only after the Edge accepts (2xx). A
// non-2xx keeps it — the report is the only copy, travelling over a connection that only just came back.
func TestExclusionSyncReportsAndClearsTrustRefusalsOnlyOn2xx(t *testing.T) {
	signer, _ := agentpolicy.LoadOrGenerateSigner("", true)

	// First: a server that accepts the report (204). The refusal must appear in the body AND be cleared after.
	var reportFails atomic.Bool
	var cap capturedReport
	srv := reportingPolicyServer(t, signer, nil, &reportFails, &cap)
	defer srv.Close()

	j := newTrustRefusalJournal(t.TempDir())
	j.record([]byte("served-der"), "x509: certificate signed by unknown authority", time.Now())
	s := &exclusionSync{
		client: srv.Client(), baseURL: srv.URL, pinHex: "", localBaseline: []string{"example-app"},
		apply: func([]string) {}, refusals: j,
	}
	if _, err := s.refreshOnce(context.Background()); err != nil {
		t.Fatalf("refreshOnce: %v", err)
	}
	body, _ := cap.body.Load().(map[string]any)
	refs, ok := body["trust_refusals"].([]any)
	if !ok || len(refs) != 1 {
		t.Fatalf("trust_refusals = %v, want one entry", body["trust_refusals"])
	}
	if len(j.pending()) != 0 {
		t.Fatal("a 2xx must clear the reported refusals")
	}

	// Second: a server that rejects the report (500). The refusal must be KEPT for the next attempt.
	failing := reportingPolicyServer(t, signer, nil, &reportFails, &capturedReport{})
	defer failing.Close()
	reportFails.Store(true) // makes the effective endpoint 500

	j2 := newTrustRefusalJournal(t.TempDir())
	j2.record([]byte("served-der"), "reason", time.Now())
	s2 := &exclusionSync{
		client: failing.Client(), baseURL: failing.URL, pinHex: "", localBaseline: []string{"example-app"},
		apply: func([]string) {}, refusals: j2,
	}
	_, _ = s2.refreshOnce(context.Background()) // report fails; refreshOnce itself is still fine (best-effort)
	if len(j2.pending()) != 1 {
		t.Fatal("a non-2xx report must NOT clear the refusals")
	}
}

// A device that has adopted nothing reports serial 0 as ABSENT (omitempty) — so a fleet that never uses the
// trust bundle is byte-for-byte the legacy report and the Edge keeps its prior fingerprint-only judgement.
func TestExclusionSyncOmitsAdoptedTrustSerialWhenZero(t *testing.T) {
	var reportFails atomic.Bool
	var cap capturedReport
	signer, _ := agentpolicy.LoadOrGenerateSigner("", true)
	srv := reportingPolicyServer(t, signer, nil, &reportFails, &cap)
	defer srv.Close()

	// startupAdoptedSerial 0, liveTrust never set → currentTrustSerial() == 0.
	tc := &transportConfig{liveTrust: &atomic.Pointer[trustMaterial]{}}
	s := &exclusionSync{
		client: srv.Client(), baseURL: srv.URL, pinHex: "", localBaseline: []string{"example-app"},
		apply:              func([]string) {},
		adoptedTrustSerial: tc.currentTrustSerial,
	}
	if _, err := s.refreshOnce(context.Background()); err != nil {
		t.Fatalf("refreshOnce: %v", err)
	}
	body, _ := cap.body.Load().(map[string]any)
	if _, present := body["adopted_trust_serial"]; present {
		t.Fatalf("adopted_trust_serial must be omitted when 0 (backward-compatible), got %v", body["adopted_trust_serial"])
	}
}

// TestExclusionSyncStatelessReportOmitsDeviceState asserts backward compatibility: with no state callback the
// device-state fields are omitted entirely (omitempty), so the payload is the legacy exclusion-only report.
func TestExclusionSyncStatelessReportOmitsDeviceState(t *testing.T) {
	var reportFails atomic.Bool
	var cap capturedReport
	signer, _ := agentpolicy.LoadOrGenerateSigner("", true)
	srv := reportingPolicyServer(t, signer, nil, &reportFails, &cap)
	defer srv.Close()

	s := &exclusionSync{
		client:        srv.Client(),
		baseURL:       srv.URL,
		pinHex:        "",
		localBaseline: []string{"example-app"},
		apply:         func([]string) {},
		// state == nil
	}
	if _, err := s.refreshOnce(context.Background()); err != nil {
		t.Fatalf("refreshOnce: %v", err)
	}
	body, _ := cap.body.Load().(map[string]any)
	if body == nil {
		t.Fatal("no report body captured")
	}
	for _, k := range []string{"posture", "fail_open_configured", "region_failover_enabled", "active_region", "server_initiated_rule_count"} {
		if _, present := body[k]; present {
			t.Fatalf("device-state field %q must be omitted in a stateless report", k)
		}
	}
}

// reportEffective is best-effort: a context whose deadline has passed must surface an error to the caller
// (for logging) but must never panic or block.
func TestReportEffectiveSurfacesTransportError(t *testing.T) {
	signer, _ := agentpolicy.LoadOrGenerateSigner("", true)
	var reportFails atomic.Bool
	var cap capturedReport
	srv := reportingPolicyServer(t, signer, []string{"corpvpn.exe"}, &reportFails, &cap)
	srv.Close() // server is down: the POST must error, not hang

	s := &exclusionSync{
		client:  srv.Client(),
		baseURL: srv.URL,
	}
	if err := s.reportEffective(context.Background(), []string{"automation"}, 0); err == nil {
		t.Fatal("expected an error reporting to a closed server")
	}
}

func toStrings(v any) []string {
	raw, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, it := range raw {
		if s, ok := it.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
