package aiops

import (
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

func at(t time.Time) string { return t.Format(time.RFC3339) }

func TestDecisionsWithinFiltersAndReportsTheOldestSeen(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	decisions := []model.AccessDecision{
		{ID: "old", Timestamp: at(now.Add(-40 * 24 * time.Hour))},
		{ID: "in-a", Timestamp: at(now.Add(-2 * time.Hour))},
		{ID: "in-b", Timestamp: at(now.Add(-30 * time.Minute))},
		{ID: "future", Timestamp: at(now.Add(time.Hour))},
		{ID: "unparseable", Timestamp: "recently"},
		{ID: "missing", Timestamp: ""},
	}
	within, oldest := DecisionsWithin(decisions, now.Add(-24*time.Hour), now)
	if len(within) != 2 {
		t.Fatalf("expected the 2 in-window decisions, got %d: %v", len(within), within)
	}
	for _, d := range within {
		if d.ID != "in-a" && d.ID != "in-b" {
			t.Fatalf("out-of-window decision %q leaked into the window", d.ID)
		}
	}
	// The oldest is reported across ALL decisions, not just the window's — the caller needs it to tell
	// "nothing older exists" from "older existed and was evicted", and the in-window minimum cannot say that.
	if want := now.Add(-40 * 24 * time.Hour); !oldest.Equal(want) {
		t.Fatalf("oldest = %s, want %s", oldest, want)
	}
}

// A decision the code cannot place in time must be dropped from a windowed view, not kept. Keeping it would
// attribute it to whatever window happens to be on screen — a number that changes meaning with the selector.
func TestDecisionsWithinDropsUndatedDecisions(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	within, oldest := DecisionsWithin([]model.AccessDecision{{ID: "undated"}}, now.Add(-24*time.Hour), now)
	if len(within) != 0 {
		t.Fatalf("an undated decision was placed in a window: %v", within)
	}
	if !oldest.IsZero() {
		t.Fatalf("oldest should stay zero when nothing could be dated, got %s", oldest)
	}
}

func TestBuildAccessTrendsReportForWindowCarriesBothRanges(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	report := BuildAccessTrendsReportForWindow(
		[]model.AccessDecision{{ID: "d1", TenantID: "acme", Decision: "deny", Timestamp: at(now)}},
		"acme", at(now),
		TrendWindow{Requested: "30d", From: at(now.Add(-30 * 24 * time.Hour)), To: at(now)},
		TrendCoverage{From: at(now.Add(-2 * time.Hour)), To: at(now), Decisions: 1, Retained: 500, Capacity: 500, Truncated: true},
	)
	if report.Window == nil || report.Window.Requested != "30d" {
		t.Fatalf("window not carried: %+v", report.Window)
	}
	if report.Coverage == nil || !report.Coverage.Truncated {
		t.Fatalf("coverage not carried: %+v", report.Coverage)
	}
	// The plain builder must stay window-free, so the bundled report does not claim a range it never resolved.
	if plain := BuildAccessTrendsReport(nil, "acme", at(now)); plain.Window != nil || plain.Coverage != nil {
		t.Fatalf("the window-free builder emitted a range: %+v %+v", plain.Window, plain.Coverage)
	}
}
