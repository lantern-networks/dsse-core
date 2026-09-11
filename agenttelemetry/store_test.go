package agenttelemetry

import (
	"context"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

func TestAgentTelemetryStoreSummariesScopeTenant(t *testing.T) {
	store := NewStore()
	now := time.Now().UTC()
	for _, event := range []model.AgentUpdateEvent{
		{ID: "aue_store_installed", TenantID: "tenant_lab_001", DeviceID: "dev_001", UpdateStatus: "installed", Timestamp: now.Format(time.RFC3339)},
		{ID: "aue_store_failed", TenantID: "tenant_lab_001", DeviceID: "dev_002", UpdateStatus: "failed", Timestamp: now.Format(time.RFC3339)},
		{ID: "aue_store_other", TenantID: "tenant_other", DeviceID: "dev_other", UpdateStatus: "installed", Timestamp: now.Format(time.RFC3339)},
	} {
		if err := store.RecordUpdate(context.Background(), event); err != nil {
			t.Fatalf("RecordUpdate returned error: %v", err)
		}
	}
	for _, status := range []model.AgentStatus{
		{TenantID: "tenant_lab_001", DeviceID: "dev_001", Status: "healthy", Timestamp: now.Format(time.RFC3339), Metadata: map[string]any{"crash_count": 0, "steering_attempted": 4, "steering_succeeded": 4, "connect_unsupported": 2}},
		{TenantID: "tenant_lab_001", DeviceID: "dev_002", Status: "degraded", Timestamp: now.Format(time.RFC3339), Metadata: map[string]any{"crash_count": 1, "steering_attempted": 2, "steering_succeeded": 1, "steering_failed": 1, "connect_unsupported": 1}},
		{TenantID: "tenant_other", DeviceID: "dev_other", Status: "healthy", Timestamp: now.Format(time.RFC3339), Metadata: map[string]any{"crash_count": 0, "steering_attempted": 10, "steering_succeeded": 10, "connect_unsupported": 10}},
	} {
		if err := store.RecordStatus(context.Background(), status); err != nil {
			t.Fatalf("RecordStatus returned error: %v", err)
		}
	}

	updateSummary, err := store.UpdateSummary(context.Background(), "tenant_lab_001")
	if err != nil {
		t.Fatalf("UpdateSummary returned error: %v", err)
	}
	if updateSummary["total"] != 2 || updateSummary["terminal_events"] != 2 || updateSummary["installed_events"] != 1 || updateSummary["update_success_rate"] != float64(0.5) {
		t.Fatalf("update summary = %#v", updateSummary)
	}
	statusSummary, err := store.StatusSummary(context.Background(), "tenant_lab_001")
	if err != nil {
		t.Fatalf("StatusSummary returned error: %v", err)
	}
	if statusSummary["total"] != 2 || statusSummary["crash_events"] != 1 || statusSummary["steering_attempted"] != 6 || statusSummary["steering_succeeded"] != 5 || statusSummary["steering_failed"] != 1 || statusSummary["connect_unsupported"] != 3 {
		t.Fatalf("status summary = %#v", statusSummary)
	}
	if statusSummary["crash_free_rate"] != float64(0.5) || statusSummary["steering_success_rate"] != float64(5)/float64(6) {
		t.Fatalf("status rates = %#v", statusSummary)
	}
}

// ★ nil AND {} ARE THE SAME EVIDENCE (2026-08-13, twenty-ninth review). Ingest forces Metadata={}, the audit
// builder omits the field when empty, and hydration leaves it nil — so after a control-plane restart a
// device's retry of the SAME report compared unequal ("null" vs "{}"), was refused as a different outcome,
// and that device's whole report queue jammed behind a retry that can never succeed.
func TestAReportWithNoMetadataMatchesItsHydratedSelf(t *testing.T) {
	live := model.AgentUpdateEvent{ID: "aue_1", TenantID: "t", DeviceID: "d-1", UpdateStatus: "installed",
		CurrentAgentVersion: "0.2.9", TargetAgentVersion: "0.2.9", ReleaseChannel: "stable",
		UpdateSource: "control_plane", Metadata: map[string]any{}}
	hydrated := live
	hydrated.Metadata = nil

	if !sameAgentUpdateEvent(live, hydrated) {
		t.Fatal("a report with no metadata did not match its hydrated self: the device's retry is refused as a " +
			"DIFFERENT outcome and its queue never drains again")
	}
	// And genuinely different evidence still differs.
	other := live
	other.Metadata = map[string]any{"rejected_manifest_sha256": "abc"}
	if sameAgentUpdateEvent(live, other) {
		t.Fatal("two refusals carrying different evidence were collapsed as one retry")
	}
}

// ★★ THE TIE GOES TO THE ONE RECORDED LAST, AND A FIX FOR THIS FUNCTION INVERTED IT (2026-08-13, thirtieth
// review). The twenty-ninth review's change replaced a text comparison with an instant comparison and wrote
// `!recordedAfter(event, held)` — which also skips when the two are EQUAL, so a tie began keeping the EARLIER
// entry, while the comment above it went on saying arrival order decided it.
//
// Report timestamps are second-granular, so "failed, then rolled back" in one tick is a tie. Keeping the
// earlier one makes `failed` the current state for ever, and disagrees with the Postgres store, whose
// tie-break is created_at. That is the drill-down-disagrees-with-summary defect this lane has had twice; there
// is now a test instead of a sentence.
func TestTwoOutcomesInTheSameSecondKeepTheOneRecordedLast(t *testing.T) {
	store := NewStore()
	at := time.Now().UTC().Format(time.RFC3339)
	for _, event := range []model.AgentUpdateEvent{
		{ID: "aue_failed", TenantID: "t1", DeviceID: "dev_1", UpdateStatus: "failed", Timestamp: at},
		{ID: "aue_rolled_back", TenantID: "t1", DeviceID: "dev_1", UpdateStatus: "rolled_back", Timestamp: at},
	} {
		if err := store.RecordUpdate(context.Background(), event); err != nil {
			t.Fatal(err)
		}
	}
	latest, err := store.LatestUpdateByDevice(context.Background(), "t1")
	if err != nil {
		t.Fatal(err)
	}
	if got := latest["dev_1"].UpdateStatus; got != "rolled_back" {
		t.Fatalf("the device is %q — the rollback that followed the failure in the same second was discarded, so "+
			"this fleet view shows a failure that has already been recovered", got)
	}
}

// The other direction still has to hold: a genuinely NEWER outcome wins whatever order it arrives in, which is
// the property the instant comparison was introduced for. A device reporting local time must not out-sort UTC.
func TestAnOlderOutcomeArrivingLaterDoesNotWin(t *testing.T) {
	store := NewStore()
	newer := time.Date(2026, 8, 13, 0, 0, 0, 0, time.UTC)
	// The same instant written in a +09:00 offset sorts ABOVE the Z form as text, which is exactly how a stale
	// outcome used to stay current.
	older := newer.Add(-time.Hour).In(time.FixedZone("JST", 9*3600))
	for _, event := range []model.AgentUpdateEvent{
		{ID: "aue_new", TenantID: "t1", DeviceID: "dev_1", UpdateStatus: "installed", Timestamp: newer.Format(time.RFC3339)},
		{ID: "aue_old", TenantID: "t1", DeviceID: "dev_1", UpdateStatus: "failed", Timestamp: older.Format(time.RFC3339)},
	} {
		if err := store.RecordUpdate(context.Background(), event); err != nil {
			t.Fatal(err)
		}
	}
	latest, _ := store.LatestUpdateByDevice(context.Background(), "t1")
	if got := latest["dev_1"].UpdateStatus; got != "installed" {
		t.Fatalf("the device is %q — an hour-old outcome written in a +09:00 offset replaced a newer one", got)
	}
}
