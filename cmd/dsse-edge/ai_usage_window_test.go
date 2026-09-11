package main

import (
	"net/url"
	"testing"
	"time"
)

// The AI usage report's window used to be a compile-time constant that nothing declared: a busy tenant was shown
// less than 7 days of data under a screen that implied 7. These tests pin the two halves of the fix — the window
// is the caller's, and a window the caller cannot have is refused rather than quietly replaced.

func TestResolveAIUsageWindowPrecedenceAndDefault(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name      string
		query     string
		wantFrom  time.Time
		wantTo    time.Time
		requested string
	}{
		// No parameters must behave exactly as the code did before they existed, or every existing caller
		// (the Console page, the Overview tile) silently changes meaning on deploy.
		{"default is the pre-existing 7d", "", now.Add(-7 * 24 * time.Hour), now, "7d"},
		{"preset 24h", "window=24h", now.Add(-24 * time.Hour), now, "24h"},
		{"preset 30d", "window=30d", now.Add(-30 * 24 * time.Hour), now, "30d"},
		{
			"absolute range",
			"from=2026-08-01T00:00:00Z&to=2026-08-03T00:00:00Z",
			time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC),
			time.Date(2026, 8, 3, 0, 0, 0, 0, time.UTC),
			"custom",
		},
		{
			"absolute lower bound only ends now",
			"from=2026-08-05T00:00:00Z",
			time.Date(2026, 8, 5, 0, 0, 0, 0, time.UTC),
			now,
			"custom",
		},
		{
			"absolute upper bound only spans the default back from it",
			"to=2026-08-03T00:00:00Z",
			time.Date(2026, 7, 27, 0, 0, 0, 0, time.UTC),
			time.Date(2026, 8, 3, 0, 0, 0, 0, time.UTC),
			"custom",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			query, err := url.ParseQuery(tc.query)
			if err != nil {
				t.Fatalf("bad test query %q: %v", tc.query, err)
			}
			from, to, requested, err := resolveReportWindow(query, now)
			if err != nil {
				t.Fatalf("resolve %q: %v", tc.query, err)
			}
			if !from.Equal(tc.wantFrom) || !to.Equal(tc.wantTo) {
				t.Fatalf("window = [%s, %s], want [%s, %s]", from, to, tc.wantFrom, tc.wantTo)
			}
			if requested != tc.requested {
				t.Fatalf("requested = %q, want %q", requested, tc.requested)
			}
		})
	}
}

// An unknown window MUST be an error. Falling back to the default would reproduce the exact defect this work
// exists to remove — /admin/ai-ops/access-trends accepts ?window= from the Overview page and ignores it, so the
// period control there re-renders the same numbers under a different label.
func TestResolveAIUsageWindowRejects(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct{ name, query string }{
		{"unknown preset", "window=90d"},
		{"preset that is a valid duration but not offered", "window=1h"},
		{"unparseable from", "from=yesterday"},
		{"unparseable to", "to=2026-13-01T00:00:00Z"},
		{"inverted range", "from=2026-08-03T00:00:00Z&to=2026-08-01T00:00:00Z"},
		{"empty range", "from=2026-08-03T00:00:00Z&to=2026-08-03T00:00:00Z"},
		{"beyond the maximum", "from=2026-01-01T00:00:00Z&to=2026-08-01T00:00:00Z"},
		{"both forms at once", "window=7d&from=2026-08-01T00:00:00Z"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			query, err := url.ParseQuery(tc.query)
			if err != nil {
				t.Fatalf("bad test query %q: %v", tc.query, err)
			}
			if _, _, _, err := resolveReportWindow(query, now); err == nil {
				t.Fatalf("%q was accepted; it must be a 400, not a silent fallback", tc.query)
			}
		})
	}
}

// The maximum is a rejection, not a clamp: a clamped window is the same lie in a new place.
func TestResolveAIUsageWindowMaximumIsNotAClamp(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	query := url.Values{"from": {now.Add(-reportMaxWindow - time.Hour).Format(time.RFC3339)}}
	from, to, _, err := resolveReportWindow(query, now)
	if err == nil {
		t.Fatalf("a %s window was accepted and returned [%s, %s]; it must be refused", reportMaxWindow+time.Hour, from, to)
	}
}

func TestAIUsageRowTimeAcceptsTheFieldSpellingsTheBackendsUse(t *testing.T) {
	want := time.Date(2026, 8, 7, 1, 2, 3, 0, time.UTC)
	for _, field := range []string{"timestamp", "occurred_at", "created_at"} {
		got, ok := aiUsageRowTime(map[string]any{field: want.Format(time.RFC3339)})
		if !ok || !got.Equal(want) {
			t.Fatalf("%s: got (%s, %v), want (%s, true)", field, got, ok, want)
		}
	}
	if got, ok := aiUsageRowTime(map[string]any{"timestamp": "2026-08-07T01:02:03.456789Z"}); !ok || got.IsZero() {
		t.Fatalf("RFC3339Nano must parse, got (%s, %v)", got, ok)
	}
	if _, ok := aiUsageRowTime(map[string]any{"saas_application_id": "saas_openai_chatgpt"}); ok {
		t.Fatal("a row with no time field must report no time, not the zero time as valid")
	}
}
