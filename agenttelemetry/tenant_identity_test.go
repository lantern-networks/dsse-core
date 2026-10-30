package agenttelemetry

import (
	"context"
	"testing"

	"github.com/lantern-networks/dsse-core/model"
)

func TestCaseDistinctTenantTelemetryDoesNotMerge(t *testing.T) {
	store := NewStore()
	ctx := context.Background()
	for _, event := range []model.AgentUpdateEvent{
		{ID: "same-event", TenantID: "Acme", DeviceID: "same-device", UpdateStatus: "installed", Timestamp: "2026-10-23T00:00:00Z"},
		{ID: "same-event", TenantID: "acme", DeviceID: "same-device", UpdateStatus: "failed", Timestamp: "2026-10-23T00:00:01Z"},
	} {
		if err := store.RecordUpdate(ctx, event); err != nil {
			t.Fatalf("case-distinct tenant event rejected as a duplicate: %v", err)
		}
	}
	for _, status := range []model.AgentStatus{
		{TenantID: "Acme", DeviceID: "same-device", Status: "healthy"},
		{TenantID: "acme", DeviceID: "same-device", Status: "degraded"},
	} {
		if err := store.RecordStatus(ctx, status); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct{ tenant, outcome, health string }{
		{"Acme", "installed", "healthy"}, {"acme", "failed", "degraded"},
	} {
		updates, err := store.UpdateSummary(ctx, tc.tenant)
		if err != nil {
			t.Fatal(err)
		}
		if updates["total"] != 1 || updates["status_counts"].(map[string]int)[tc.outcome] != 1 {
			t.Fatalf("%s update summary crossed tenant boundary: %#v", tc.tenant, updates)
		}
		statuses, err := store.StatusSummary(ctx, tc.tenant)
		if err != nil {
			t.Fatal(err)
		}
		if statuses["total"] != 1 || statuses["status_counts"].(map[string]int)[tc.health] != 1 {
			t.Fatalf("%s status summary crossed tenant boundary: %#v", tc.tenant, statuses)
		}
		latest, err := store.LatestUpdateByDevice(ctx, tc.tenant)
		if err != nil {
			t.Fatal(err)
		}
		if len(latest) != 1 || latest["same-device"].UpdateStatus != tc.outcome {
			t.Fatalf("%s latest update crossed tenant boundary: %#v", tc.tenant, latest)
		}
	}
}
