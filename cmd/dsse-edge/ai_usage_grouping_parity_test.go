package main

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

// The AI usage report can be built from raw rows or from rows a store already grouped. The two MUST produce the
// same report — not "close", identical — because the second exists only to avoid loading the first. Parity is
// structural (one aggregation function, of the design doc); this test is what keeps it that way, and it is
// written around the trap the design got wrong on the first draft: sessions are unioned at four different
// granularities, so pre-counting distinct buckets per group and summing them double-counts any bucket that
// spans two groups.

func aiParityCatalog() []model.SaaSCatalogEntry {
	return []model.SaaSCatalogEntry{
		{SaaSApplicationID: "saas_anthropic_claude", AIService: true, AIGovernance: "approved"},
		{SaaSApplicationID: "saas_openai_chatgpt", AIService: true, AIGovernance: "tolerated"},
	}
}

// Two users on the same service inside the SAME 30-minute bucket, plus a second bucket for one of them. At the
// service level that is 2 sessions, not 3 — the shared bucket is one session however many groups touch it.
func aiParityRows() []map[string]any {
	base := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	row := func(user, device, app, svc string, at time.Time, method string, sent, recv int64) map[string]any {
		return map[string]any{
			"tenant_id":           "acme",
			"saas_application_id": svc,
			"saas_name":           svc,
			"user_id":             user,
			"device_id":           device,
			"timestamp":           at.Format(time.RFC3339),
			"metadata": map[string]any{
				"ai_app":         app,
				"http_method":    method,
				"bytes_sent":     sent,
				"bytes_received": recv,
				"ai_account":     user + "@example.com",
				"ai_email":       user + "@example.com",
			},
		}
	}
	return []map[string]any{
		// alice, bucket A, two requests (one a message)
		row("alice", "mac-1", "chrome", "saas_anthropic_claude", base, "POST", 100, 900),
		row("alice", "mac-1", "chrome", "saas_anthropic_claude", base.Add(5*time.Minute), "GET", 10, 20),
		// bob, SAME bucket A, same service — the shared bucket the naive aggregate would count twice
		row("bob", "win-1", "chrome", "saas_anthropic_claude", base.Add(10*time.Minute), "POST", 50, 400),
		// alice again, bucket B
		row("alice", "mac-1", "chrome", "saas_anthropic_claude", base.Add(40*time.Minute), "POST", 70, 300),
		// alice on a second service, and a second app, so the identity×service and activity splits are exercised
		row("alice", "mac-1", "curl", "saas_openai_chatgpt", base.Add(45*time.Minute), "POST", 5, 5),
	}
}

// groupRowsLikeAStoreWould collapses rows the way a GROUP BY over the raw fields would: one input per distinct
// (service, user, device, app), measures summed, distinct buckets listed. This is the shape the SQL aggregate
// must return, so building it here in Go is the contract the SQL will be held to.
func groupRowsLikeAStoreWould(rows []map[string]any) []aiUsageInput {
	byKey := map[string]*aiUsageInput{}
	order := []string{}
	for _, row := range rows {
		md, _ := row["metadata"].(map[string]any)
		key := stringFromRow(row, "saas_application_id") + "\x1f" + stringFromRow(row, "user_id") + "\x1f" +
			stringFromRow(row, "device_id") + "\x1f" + stringFromRow(md, "ai_app")
		in := byKey[key]
		if in == nil {
			in = &aiUsageInput{Row: row}
			byKey[key] = in
			order = append(order, key)
		}
		in.Accesses++
		in.BytesSent += bytesFromRow(row, "bytes_sent")
		in.BytesRecv += bytesFromRow(row, "bytes_received")
		if isAIMessage(row) {
			in.Messages++
		}
		if bkt, ok := sessionBucket(row); ok {
			seen := false
			for _, b := range in.Buckets {
				if b == bkt {
					seen = true
					break
				}
			}
			if !seen {
				in.Buckets = append(in.Buckets, bkt)
			}
		}
	}
	grouped := make([]aiUsageInput, 0, len(order))
	for _, k := range order {
		grouped = append(grouped, *byKey[k])
	}
	return grouped
}

func TestGroupedAndRowLoadedReportsAreIdentical(t *testing.T) {
	rows := aiParityRows()
	catalog := aiParityCatalog()
	const generatedAt = "2026-08-07T12:00:00Z"

	fromRows := buildAIUsageReport(rows, catalog, generatedAt)
	fromGroups := buildAIUsageReportFromInputs(groupRowsLikeAStoreWould(rows), catalog, generatedAt)

	// The grouping must actually collapse something, or this test proves nothing.
	if got := len(groupRowsLikeAStoreWould(rows)); got >= len(rows) {
		t.Fatalf("grouping collapsed nothing (%d groups for %d rows) — the test would pass trivially", got, len(rows))
	}

	a, err := json.Marshal(fromRows)
	if err != nil {
		t.Fatalf("marshal row-loaded report: %v", err)
	}
	b, err := json.Marshal(fromGroups)
	if err != nil {
		t.Fatalf("marshal grouped report: %v", err)
	}
	if string(a) != string(b) {
		t.Fatalf("the two paths disagree.\n row-loaded: %s\n grouped   : %s", a, b)
	}
}

// The specific number the naive design would have got wrong, pinned on its own so a regression names itself
// rather than showing up as a diff in a 4KB JSON blob.
func TestSessionsAreUnionedNotSummedAcrossGroups(t *testing.T) {
	report := buildAIUsageReportFromInputs(groupRowsLikeAStoreWould(aiParityRows()), aiParityCatalog(), "2026-08-07T12:00:00Z")
	var claude *aiUsageReportEntry
	for i := range report.Services {
		if report.Services[i].SaaSApplicationID == "saas_anthropic_claude" {
			claude = &report.Services[i]
		}
	}
	if claude == nil {
		t.Fatal("the claude service is missing from the report")
	}
	// alice and bob share the first 30-minute bucket; alice has a second. Two sessions at the service level.
	// Summing per-group distinct counts (1 for alice's bucket A + 1 for bob's bucket A + 1 for alice's B) gives 3.
	if claude.Sessions != 2 {
		t.Fatalf("service sessions = %d, want 2 — a bucket shared by two groups is ONE session, not two", claude.Sessions)
	}
	if claude.AccessCount != 4 {
		t.Fatalf("service access count = %d, want 4", claude.AccessCount)
	}
}
