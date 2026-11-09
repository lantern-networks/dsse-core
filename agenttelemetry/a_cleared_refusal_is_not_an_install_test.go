package agenttelemetry

import (
	"testing"

	"github.com/lantern-networks/dsse-core/model"
)

// One refusal and its clearing, with no install run, summed to installed_events=1,
// terminal_events=2, update_success_rate=0.5. The events are shaped as the updaters send them: a refusal as
// failed with refused=true, its clearing as installed with refusal_cleared=true.
func TestAClearedRefusalIsNotCountedAsAnInstall(t *testing.T) {
	refusal := model.AgentUpdateEvent{ID: "r1", UpdateStatus: "failed", Metadata: map[string]any{"refused": true}}
	cleared := model.AgentUpdateEvent{ID: "r2", UpdateStatus: "installed", Metadata: map[string]any{"refusal_cleared": true}}

	got := UpdateSummaryFromEvents([]model.AgentUpdateEvent{refusal, cleared})
	if got["installed_events"] != 0 || got["terminal_events"] != 1 || got["refusal_cleared_events"] != 1 {
		t.Fatalf("summary = %v", got)
	}
	if rate, _ := got["update_success_rate"].(float64); rate != 0 {
		t.Fatalf("a refusal that cleared raised the success rate to %v", got["update_success_rate"])
	}
	if counts := got["status_counts"].(map[string]int); counts["installed"] != 0 || counts["refusal_cleared"] != 1 {
		t.Fatalf("status counts = %v", counts)
	}

	// A real install is still one.
	install := model.AgentUpdateEvent{ID: "i1", UpdateStatus: "installed"}
	got = UpdateSummaryFromEvents([]model.AgentUpdateEvent{install, cleared})
	if got["installed_events"] != 1 || got["terminal_events"] != 1 || got["update_success_rate"] != 1.0 || got["total"] != 2 {
		t.Fatalf("summary = %v", got)
	}
}
