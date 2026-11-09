package hotstore

import (
	"context"
	"os"
	"testing"
)

// TestLiveClickHouseDestinationFilter runs the Logs screen's filters against a real ClickHouse with the
// events schema loaded (cmd/dsse-install/clickhouse/01-events.sql). Set DSSE_LIVE_CH to its HTTP URL
// (user and password "t"). Before the fix, destination=10.40.1.30 returned no rows for the access decision
// below, which is what the screen showed.
func TestLiveClickHouseDestinationFilter(t *testing.T) {
	url := os.Getenv("DSSE_LIVE_CH")
	if url == "" {
		t.Skip("no live ClickHouse")
	}
	s := NewClickHouseStore(url, "t", "t", "dsse", "events")
	ctx := context.Background()
	access := map[string]any{"id": "ad_1", "tenant_id": "acme", "timestamp": "2026-11-04T11:43:00Z", "decision": "authenticate_required",
		"destination": "10.40.1.30", "destination_ip": "10.40.1.30", "user_id": "tester@example.test", "source_ip": "203.0.113.10"}
	finding := map[string]any{"id": "ie_1", "tenant_id": "acme", "timestamp": "2026-11-04T11:44:00Z", "finding_type": "dlp_match",
		"metadata": map[string]any{"dlp_destination": "postman-echo.com", "dlp_action": "block"}}
	if err := s.Ingest(ctx, "access", access); err != nil {
		t.Fatal(err)
	}
	if err := s.Ingest(ctx, "inspection_events", finding); err != nil {
		t.Fatal(err)
	}
	unicode := map[string]any{"id": "ad_2", "tenant_id": "acme", "timestamp": "2026-11-04T11:45:00Z", "decision": "deny",
		"user_id": "JOSÉ@example.test", "device_id": "Mac Équipe", "destination": "bücher.example", "tool_id": "ПОЛУЧИТЬ"}
	if err := s.Ingest(ctx, "access", unicode); err != nil {
		t.Fatal(err)
	}
	count := func(stream string, filters map[string]string, text string) int {
		r, err := s.Search(ctx, SearchQuery{TenantID: "acme", Stream: stream, Filters: filters, Text: text, Limit: 50})
		if err != nil {
			t.Fatalf("%s %v %q: %v", stream, filters, text, err)
		}
		return len(r.Rows)
	}
	for _, c := range []struct {
		stream  string
		filters map[string]string
		text    string
		want    int
	}{
		{"access", map[string]string{"destination": "10.40.1.30"}, "", 1},
		{"access", map[string]string{"destination": "10.40.1"}, "", 1},
		{"access", nil, "10.40.1.30", 1},
		{"access", map[string]string{"user_id": "TESTER@"}, "", 1},
		{"access", map[string]string{"decision": "authenticate"}, "", 0},
		{"access", map[string]string{"destination": "10.40.1.31"}, "", 0},
		{"inspection_events", map[string]string{"destination": "postman"}, "", 1},
		// Case folding beyond ASCII, as the JSONL store does it.
		{"access", map[string]string{"user_id": "josé"}, "", 1},
		{"access", map[string]string{"device_id": "équipe"}, "", 1},
		{"access", map[string]string{"destination": "BÜCHER"}, "", 1},
		{"access", map[string]string{"tool_id": "получить"}, "", 1},
		{"access", nil, "получить", 1},
	} {
		if got := count(c.stream, c.filters, c.text); got != c.want {
			t.Errorf("%s %v %q: %d rows, want %d", c.stream, c.filters, c.text, got, c.want)
		}
	}
}
