package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	agenttelemetry "github.com/lantern-networks/dsse-core/agenttelemetry"
	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
)

// agent_update_report_ingest_test.go — who may report an update outcome, and about which device.

func requestWithVerifiedCert(cn string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/devices/"+cn+"/agent-updates", nil)
	r.SetPathValue("device_id", cn)
	leaf := &x509.Certificate{Subject: pkix.Name{CommonName: cn}}
	r.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{leaf},
		VerifiedChains:   [][]*x509.Certificate{{leaf}},
	}
	return r
}

// ★ A DEVICE MAY ONLY REPORT ABOUT ITSELF. The handler used to bind nothing, so anything holding a connector's
// runtime secret could report an install — or a rollback that never happened — for any device in the tenant.
// A fleet view an operator makes decisions from must not accept claims about third parties.
func TestADeviceMayOnlyReportAboutItself(t *testing.T) {
	t.Run("its own identity is accepted", func(t *testing.T) {
		w := httptest.NewRecorder()
		if !authorizeDeviceSelfReport(w, requestWithVerifiedCert("mac-dev-1"), "mac-dev-1", "", false, nil, "t", true) {
			t.Fatalf("a device reporting about itself was refused: %d %s", w.Code, w.Body.String())
		}
	})
	t.Run("a body naming another device is refused", func(t *testing.T) {
		w := httptest.NewRecorder()
		if authorizeDeviceSelfReport(w, requestWithVerifiedCert("mac-dev-1"), "win-dev-9", "", false, nil, "t", true) {
			t.Fatalf("a device reported an outcome for another device")
		}
		if w.Code != http.StatusForbidden {
			t.Fatalf("status %d, want 403", w.Code)
		}
	})
	t.Run("a path naming another device is refused", func(t *testing.T) {
		r := requestWithVerifiedCert("mac-dev-1")
		r.SetPathValue("device_id", "win-dev-9")
		w := httptest.NewRecorder()
		if authorizeDeviceSelfReport(w, r, "", "", false, nil, "t", true) {
			t.Fatalf("a device reported against another device's path")
		}
	})
	t.Run("an empty body device id is fine — the certificate fills it", func(t *testing.T) {
		w := httptest.NewRecorder()
		if !authorizeDeviceSelfReport(w, requestWithVerifiedCert("mac-dev-1"), "", "", false, nil, "t", true) {
			t.Fatalf("a report that named no device in the body was refused: %s", w.Body.String())
		}
	})
}

// ★ THE SENDERS PRESENT A DEVICE CERTIFICATE AND NOTHING ELSE. Requiring connector credentials meant every
// update outcome would be answered 401 in production, and the lane built to fill an empty fleet view would
// have left it empty.
func TestADeviceCertificateIsEnoughWithoutConnectorCredentials(t *testing.T) {
	w := httptest.NewRecorder()
	// devMode false, runtime secret REQUIRED, no connector id or secret on the request: production shape.
	if !authorizeDeviceSelfReport(w, requestWithVerifiedCert("mac-dev-1"), "mac-dev-1", "s", false, nil, "t", true) {
		t.Fatalf("a device-mTLS report was refused in the production shape: %d %s", w.Code, w.Body.String())
	}
}

// ★ A RETRY IS THE SAME EVENT. The outbox retries whenever a response is lost, or when the process dies
// between "accepted" and "removed" — both ordinary — and each retry used to be audited and counted again.
func TestARepeatedEventIDIsRecognisedOnlyAfterItIsCommitted(t *testing.T) {
	if agentUpdateEventCommitted("tenant_a", "mac-dev-1", "aue_test_1") {
		t.Fatalf("a fresh id was reported as already recorded")
	}
	// ★ A RECEIPT WRITTEN BEFORE THE THING IT ACKNOWLEDGES IS NOT A RECEIPT. Marking the id seen before the
	// audit and telemetry meant a failed write answered 500 and the RETRY was waved through as a duplicate —
	// the event lost permanently, and the device deleting its copy on the 202.
	receipt, already, mine := reserveAgentUpdateEvent("tenant_a", "mac-dev-1", "aue_test_1")
	if already || !mine {
		t.Fatalf("a fresh event could not be reserved: already=%t mine=%t", already, mine)
	}
	// ★ RESERVED IS NOT COMMITTED. A concurrent retry must not be waved through while the first request is
	// still writing, and it must not be told the event was recorded either.
	if _, already2, mine2 := reserveAgentUpdateEvent("tenant_a", "mac-dev-1", "aue_test_1"); already2 || mine2 {
		t.Fatalf("a second request claimed an event that is mid-write: already=%t mine=%t", already2, mine2)
	}
	if agentUpdateEventCommitted("tenant_a", "mac-dev-1", "aue_test_1") {
		t.Fatalf("a reservation was reported as committed")
	}
	receipt.commit()
	if !agentUpdateEventCommitted("tenant_a", "mac-dev-1", "aue_test_1") {
		t.Fatalf("a committed id was not recognised: the audit and the success rate would count it twice")
	}

	// ★ THE ID IS CLIENT INPUT. Keyed on the id alone, one device could suppress another's event by choosing
	// the same string — including across tenants.
	if agentUpdateEventCommitted("tenant_a", "win-dev-9", "aue_test_1") {
		t.Fatalf("another device's event was suppressed by a colliding id")
	}
	if agentUpdateEventCommitted("tenant_b", "mac-dev-1", "aue_test_1") {
		t.Fatalf("another TENANT's event was suppressed by a colliding id")
	}

	// ★ AN UNCOMMITTED RESERVATION IS RELEASED. A request that fails half way must not make the event
	// permanently unrecordable — that is the same "lost forever" outcome as marking it before the write.
	failed, _, mineFailed := reserveAgentUpdateEvent("tenant_a", "mac-dev-1", "aue_test_2")
	if !mineFailed {
		t.Fatalf("a fresh event could not be reserved")
	}
	failed.release()
	if _, _, retry := reserveAgentUpdateEvent("tenant_a", "mac-dev-1", "aue_test_2"); !retry {
		t.Fatalf("a released reservation blocked the retry: the event could never be recorded")
	}

	// An empty id is never a duplicate: two events with no id are two events.
	if _, _, a := reserveAgentUpdateEvent("tenant_a", "mac-dev-1", ""); !a {
		t.Fatalf("an event with no id was refused")
	}
	if _, _, b := reserveAgentUpdateEvent("tenant_a", "mac-dev-1", ""); !b {
		t.Fatalf("events with no id were collapsed into one")
	}
}

// ★ A TENANT WITH NO MIGRATED ARTIFACTS MUST BE ABLE TO UPLOAD ITS FIRST ONE. The path moved under
// dir/<tenant>/ and only dir was created, so the rename failed with ENOENT for every new tenant.
func TestTheTenantArtifactDirectoryIsCreatedOnFirstUpload(t *testing.T) {
	dir := t.TempDir()
	path := artifactStorePath(dir, "tenant_brand_new", "darwin", "arm64", "0.2.7")
	if path == "" {
		t.Fatalf("no path for a valid target")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatalf("create the tenant directory: %v", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".artifact-*")
	if err != nil {
		t.Fatalf("the temp file must be created beside the destination for the rename to be atomic: %v", err)
	}
	tmp.Close()
	if err := os.Rename(tmp.Name(), path); err != nil {
		t.Fatalf("the first upload for a new tenant failed: %v", err)
	}
}

// The read path falls back to the pre-tenant flat file, which is what keeps a legacy manifest — served to
// every tenant — from naming bytes that only one tenant can find.
func TestArtifactReadsFallBackToThePreTenantPath(t *testing.T) {
	dir := t.TempDir()
	flat := filepath.Join(dir, artifactFileName("darwin", "arm64", "0.2.7"))
	if err := os.WriteFile(flat, []byte("legacy bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := artifactReadPath(dir, "tenant_that_never_published", "darwin", "arm64", "0.2.7")
	if got != flat {
		t.Fatalf("a tenant served the legacy manifest could not find its bytes: got %q, want %q", got, flat)
	}
	// And a tenant's own copy wins over the fallback.
	own := artifactStorePath(dir, "tenant_a", "darwin", "arm64", "0.2.7")
	if err := os.MkdirAll(filepath.Dir(own), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(own, []byte("tenant_a bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := artifactReadPath(dir, "tenant_a", "darwin", "arm64", "0.2.7"); got != own {
		t.Fatalf("the flat fallback shadowed a tenant's own artifact: %q", got)
	}
}

// ★ THE CONTROL PLANE HELD THE RECORDS AND ANSWERED ZERO. A device reports to its EDGE, so the Edge's
// in-process telemetry knows and the control plane's does not: the same call answered total=1 on the Edge and
// total=0 on the CP, and the CP is what the Console reads. The records DO arrive — that is what the ingest
// receiver is — so the fleet view is built there, one event at a time.
//
// ★ AND THE RECORD IS BUILT BY THE PRODUCTION BUILDER (2026-08-12, ninth review). The first version of this
// test hand-wrote the JSON it then asserted on, and got the field names WRONG — the reader looked for
// metadata.event_id and metadata.device_id while agentUpdateAuditLog writes metadata.agent_update_event_id and
// a top-level target_id. Every shipped outcome in production would have arrived with no id and no device. A
// test that writes its own fixture is a test of the fixture.
func TestAShippedUpdateOutcomeEntersTheControlPlanesFleetView(t *testing.T) {
	telemetry := agenttelemetry.NewStore()
	evaluator := decision.Evaluator{PolicyBundle: model.PolicyBundle{ID: "pb_1", TenantID: "tenant_a"}}
	shipped := func(id, device, status string) []byte {
		t.Helper()
		record := agentUpdateAuditLog(model.AgentUpdateEvent{
			ID: id, TenantID: "tenant_a", DeviceID: device,
			CurrentAgentVersion: "0.2.9", TargetAgentVersion: "0.2.9",
			ReleaseChannel: "lab", UpdateStatus: status, UpdateSource: "control_plane",
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		}, evaluator, "127.0.0.1")
		body, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		return body
	}

	body := shipped("aue_shipped_1", "mac-dev-1", "installed")
	recordShippedAgentUpdate(context.Background(), telemetry, "audit.log.jsonl", body)

	summary, err := telemetry.UpdateSummary(context.Background(), "tenant_a")
	if err != nil {
		t.Fatalf("summary: %v", err)
	}
	if summary["total"] != 1 || summary["installed_events"] != 1 {
		t.Fatalf("a shipped outcome did not reach the fleet view: %#v", summary)
	}

	// A REPLAYED shipment is the same event. The shipper retains and replays on a CP outage, so this happens
	// in ordinary operation rather than only under attack.
	recordShippedAgentUpdate(context.Background(), telemetry, "audit.log.jsonl", body)
	summary, _ = telemetry.UpdateSummary(context.Background(), "tenant_a")
	if summary["total"] != 1 {
		t.Fatalf("a replayed shipment was counted twice: %#v", summary)
	}

	// A DIFFERENT device's outcome is a different event, even with the same id — which is what a client-chosen
	// identifier makes possible.
	recordShippedAgentUpdate(context.Background(), telemetry, "audit.log.jsonl",
		shipped("aue_shipped_1", "win-dev-9", "failed"))
	summary, _ = telemetry.UpdateSummary(context.Background(), "tenant_a")
	if summary["total"] != 2 {
		t.Fatalf("another device's outcome was collapsed into the first: %#v", summary)
	}

	// And nothing else on that stream is mistaken for one.
	other, _ := json.Marshal(map[string]any{"event_type": "admin_config_change", "tenant_id": "tenant_a"})
	recordShippedAgentUpdate(context.Background(), telemetry, "audit.log.jsonl", other)
	recordShippedAgentUpdate(context.Background(), telemetry, "access.log.jsonl", body)
	summary, _ = telemetry.UpdateSummary(context.Background(), "tenant_a")
	if summary["total"] != 2 {
		t.Fatalf("an unrelated record entered the fleet view: %#v", summary)
	}
}

// ★ AN EMPTY IN-MEMORY STORE IS NOT "NOTHING HAPPENED". The telemetry store defaults to MEMORY and is always
// present, so the summary returned its zero after every restart — and the reference control plane has no
// durable backend configured, which makes that the normal case. The canonical jsonl was there and unreachable
// behind a nil check.
func TestTheFleetViewIsRebuiltFromTheLogAfterARestart(t *testing.T) {
	dir := t.TempDir()
	writer, err := logs.NewWriter(dir)
	if err != nil {
		t.Fatalf("writer: %v", err)
	}
	evaluator := decision.Evaluator{PolicyBundle: model.PolicyBundle{ID: "pb_1", TenantID: "tenant_a"}}
	append := func(id, device, status string) {
		t.Helper()
		if err := writer.Append("audit.log.jsonl", agentUpdateAuditLog(model.AgentUpdateEvent{
			ID: id, TenantID: "tenant_a", DeviceID: device, UpdateStatus: status,
			CurrentAgentVersion: "0.2.9", TargetAgentVersion: "0.2.9", ReleaseChannel: "lab",
			UpdateSource: "control_plane", Timestamp: time.Now().UTC().Format(time.RFC3339),
		}, evaluator, "127.0.0.1")); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	append("aue_1", "mac-dev-1", "installed")
	append("aue_2", "win-dev-9", "failed")
	// The same outcome shipped twice must not count twice in the rebuild either.
	append("aue_1", "mac-dev-1", "installed")

	// A restart: a fresh in-memory store, hydrated from the log this process already wrote.
	store := agenttelemetry.NewStore()
	hydrateAgentUpdateTelemetry(store, writer)

	summary, err := adminAgentUpdateEventSummaryFrom(nil, writer, store, "tenant_a")
	if err != nil {
		t.Fatalf("summary: %v", err)
	}
	if summary["total"] != 2 {
		t.Fatalf("the fleet view did not survive the restart: %#v", summary)
	}
	if summary["installed_events"] != 1 {
		t.Fatalf("the rebuilt view lost the outcome kinds: %#v", summary)
	}

	// ★ AND ONE NEW ARRIVAL MUST NOT HIDE THE HISTORY (2026-08-12, tenth review). The first fix used the log
	// only while the store was EMPTY, so the first shipment after a restart made the summary non-zero and every
	// pre-restart outcome disappeared behind that one event — a fleet view that looks populated and is wrong.
	fresh := agentUpdateAuditLog(model.AgentUpdateEvent{
		ID: "aue_3", TenantID: "tenant_a", DeviceID: "mac-dev-2", UpdateStatus: "installed",
		CurrentAgentVersion: "0.2.9", TargetAgentVersion: "0.2.9", ReleaseChannel: "lab",
		UpdateSource: "control_plane", Timestamp: time.Now().UTC().Format(time.RFC3339),
	}, evaluator, "127.0.0.1")
	body, _ := json.Marshal(fresh)
	recordShippedAgentUpdate(context.Background(), store, "audit.log.jsonl", body)

	summary, _ = adminAgentUpdateEventSummaryFrom(nil, writer, store, "tenant_a")
	if summary["total"] != 3 {
		t.Fatalf("a new arrival hid the recovered history: %#v", summary)
	}

	// ★ AND EVERY TENANT, NOT THE DEFAULT ONE (2026-08-12, eleventh review). The admin API answers for
	// whichever tenant the caller operates within, so hydrating one left every other tenant's history gone on a
	// multi-tenant control plane.
	other := decision.Evaluator{PolicyBundle: model.PolicyBundle{ID: "pb_2", TenantID: "tenant_b"}}
	if err := writer.Append("audit.log.jsonl", agentUpdateAuditLog(model.AgentUpdateEvent{
		ID: "aue_b1", TenantID: "tenant_b", DeviceID: "win-dev-1", UpdateStatus: "installed",
		CurrentAgentVersion: "0.2.9", TargetAgentVersion: "0.2.9", ReleaseChannel: "lab",
		UpdateSource: "control_plane", Timestamp: time.Now().UTC().Format(time.RFC3339),
	}, other, "127.0.0.1")); err != nil {
		t.Fatal(err)
	}
	second := agenttelemetry.NewStore()
	hydrateAgentUpdateTelemetry(second, writer)
	bSummary, _ := adminAgentUpdateEventSummaryFrom(nil, writer, second, "tenant_b")
	if bSummary["total"] != 1 {
		t.Fatalf("a second tenant's history was not recovered: %#v", bSummary)
	}
	aSummary, _ := adminAgentUpdateEventSummaryFrom(nil, writer, second, "tenant_a")
	if aSummary["total"] != 2 {
		t.Fatalf("hydrating every tenant lost the first one: %#v", aSummary)
	}
}

// ★ "darwin" CONTAINS "win". A substring test for the platform matched every Mac as Windows, so the per-device
// view looked up darwin/amd64, found nothing, and told the operator "no release is published for darwin" while
// darwin/arm64 sat in the offering it had just printed.
func TestTheArchIsNotDecidedByASubstring(t *testing.T) {
	if got := agentDeviceArch("darwin"); got != "arm64" {
		t.Fatalf("darwin resolved to %q — a Mac would be looked up as a Windows target", got)
	}
	if got := agentDeviceArch("windows"); got != "amd64" {
		t.Fatalf("windows resolved to %q", got)
	}
	// Unknown stays unknown: guessing shows a device as current against a release never meant for it.
	if got := agentDeviceArch("plan9"); got != "" {
		t.Fatalf("an unknown platform was given the arch %q", got)
	}
}

// And the state that follows from it: a device whose platform HAS a published release is judged against it.
func TestADeviceIsJudgedAgainstItsOwnPlatformsRelease(t *testing.T) {
	offering := map[string]string{"darwin/arm64": "0.2.9", "windows/amd64": "0.2.0"}
	mac := model.Device{ID: "mac-dev-1"}
	event := model.AgentUpdateEvent{
		ID: "aue_1", DeviceID: "mac-dev-1", UpdateStatus: "installed", CurrentAgentVersion: "0.2.9",
		Metadata: map[string]any{"platform": "darwin"},
	}
	if got := agentDeviceUpdateFor(mac, event, offering); got.State != agentDeviceStateUpToDate {
		t.Fatalf("a Mac running the published darwin release read as %q (target %q)", got.State, got.TargetVersion)
	}
	// An older one is pending, against the right target.
	event.CurrentAgentVersion = "0.2.4"
	got := agentDeviceUpdateFor(mac, event, offering)
	if got.State != agentDeviceStatePending || got.TargetVersion != "0.2.9" {
		t.Fatalf("an out-of-date Mac read as %q toward %q", got.State, got.TargetVersion)
	}
}
