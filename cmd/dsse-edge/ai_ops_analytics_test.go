package main

import (
	"testing"

	aiops "github.com/lantern-networks/dsse-core/aiops"

	"github.com/lantern-networks/dsse-core/model"
)

func sf(v string) *string { return &v }

func sampleDecisions() []model.AccessDecision {
	return []model.AccessDecision{
		{ID: "dec_1", TenantID: "t1", Decision: "allow", PolicyID: "pol_allow", ActorType: "human", ServiceFamily: sf("https"), ReasonCodes: []string{"policy_matched", "application_allowed"}, Timestamp: "2026-06-17T10:00:00Z"},
		{ID: "dec_2", TenantID: "t1", Decision: "deny", PolicyID: "pol_boundary", ActorType: "non_human", ServiceFamily: sf("https"), ReasonCodes: []string{"policy_matched", "tool_action_out_of_boundary", "tool_id_not_allowed"}, Timestamp: "2026-06-17T10:01:00Z"},
		{ID: "dec_3", TenantID: "t1", Decision: "deny", PolicyID: "pol_boundary", ActorType: "non_human", ServiceFamily: sf("ssh"), ReasonCodes: []string{"policy_matched", "tool_action_out_of_boundary", "tool_action_not_allowed"}, Timestamp: "2026-06-17T10:02:00Z"},
		{ID: "dec_4", TenantID: "t1", Decision: "require_human_approval", PolicyID: "pol_approval", ActorType: "human", ServiceFamily: sf("https"), ReasonCodes: []string{"policy_matched", "human_approval_required"}, Timestamp: "2026-06-17T10:03:00Z"},
	}
}

func TestBuildAccessTrendsReport(t *testing.T) {
	rep := aiops.BuildAccessTrendsReport(sampleDecisions(), "t1", "2026-06-17T10:05:00Z")

	if rep.SchemaVersion != "ai_ops_access_trends.v1" || rep.GenerationMethod != "deterministic_no_llm" || !rep.NoSecretAttestation {
		t.Fatalf("bad header: %+v", rep)
	}
	if rep.WindowDecisions != 4 {
		t.Fatalf("window = %d, want 4", rep.WindowDecisions)
	}
	if rep.DenyCount != 2 {
		t.Fatalf("deny_count = %d, want 2", rep.DenyCount)
	}
	if rep.StepUpCount != 1 {
		t.Fatalf("step_up_count = %d, want 1", rep.StepUpCount)
	}
	// 2/4 = 50%.
	if rep.DenyRatePercent != 50 {
		t.Fatalf("deny_rate = %d, want 50", rep.DenyRatePercent)
	}
	if rep.ByDecision["deny"] != 2 || rep.ByDecision["allow"] != 1 || rep.ByDecision["require_human_approval"] != 1 {
		t.Fatalf("by_decision wrong: %v", rep.ByDecision)
	}
	if rep.ByActorType["non_human"] != 2 || rep.ByActorType["human"] != 2 {
		t.Fatalf("by_actor_type wrong: %v", rep.ByActorType)
	}
	if rep.ByServiceFamily["https"] != 3 || rep.ByServiceFamily["ssh"] != 1 {
		t.Fatalf("by_service_family wrong: %v", rep.ByServiceFamily)
	}
	// policy_matched is excluded from deny reasons; tool_action_out_of_boundary appears on both denies.
	top := map[string]int{}
	for _, r := range rep.TopDenyReasonCodes {
		top[r.Key] = r.Count
	}
	if top["policy_matched"] != 0 {
		t.Fatalf("policy_matched must be excluded from deny reasons, got %v", rep.TopDenyReasonCodes)
	}
	if top["tool_action_out_of_boundary"] != 2 {
		t.Fatalf("tool_action_out_of_boundary should be 2, got %v", rep.TopDenyReasonCodes)
	}
	if len(rep.TopDeniedPolicies) != 1 || rep.TopDeniedPolicies[0].Key != "pol_boundary" || rep.TopDeniedPolicies[0].Count != 2 {
		t.Fatalf("top_denied_policies wrong: %v", rep.TopDeniedPolicies)
	}
}

func TestBuildAccessTrendsReportEmpty(t *testing.T) {
	rep := aiops.BuildAccessTrendsReport(nil, "t1", "2026-06-17T10:05:00Z")
	if rep.WindowDecisions != 0 || rep.DenyCount != 0 || rep.DenyRatePercent != 0 {
		t.Fatalf("empty report should be zeroed: %+v", rep)
	}
}

func TestBuildIncidentTimeline(t *testing.T) {
	tl := aiops.BuildIncidentTimeline(sampleDecisions(), "t1", "2026-06-17T10:05:00Z", 100)

	if tl.SchemaVersion != "ai_ops_incident_timeline.v1" || !tl.NoSecretAttestation {
		t.Fatalf("bad header: %+v", tl)
	}
	if tl.WindowDecisions != 4 {
		t.Fatalf("window = %d, want 4", tl.WindowDecisions)
	}
	// Notable = 2 denies + 1 step-up (allow is excluded). 3 entries.
	if tl.EntryCount != 3 || len(tl.Entries) != 3 {
		t.Fatalf("entry_count = %d, want 3 (entries=%d)", tl.EntryCount, len(tl.Entries))
	}
	// Most recent first: dec_4 (10:03) leads.
	if tl.Entries[0].DecisionID != "dec_4" {
		t.Fatalf("most recent should lead, got %q", tl.Entries[0].DecisionID)
	}
	if tl.Entries[len(tl.Entries)-1].DecisionID != "dec_2" {
		t.Fatalf("oldest notable should be last, got %q", tl.Entries[len(tl.Entries)-1].DecisionID)
	}
	// The boundary deny carries a critical primary code.
	var boundary aiops.IncidentTimelineEntry
	for _, e := range tl.Entries {
		if e.DecisionID == "dec_2" {
			boundary = e
		}
	}
	if boundary.Severity != "critical" || boundary.PrimaryCode == "" {
		t.Fatalf("boundary deny should be critical with a primary code: %+v", boundary)
	}
	if boundary.SummaryEN == "" {
		t.Fatalf("timeline entry should carry grounded summaries")
	}
}

func TestBuildIncidentTimelineExcludesPlainAllow(t *testing.T) {
	allows := []model.AccessDecision{
		{ID: "a1", TenantID: "t1", Decision: "allow", ReasonCodes: []string{"policy_matched", "application_allowed"}, Timestamp: "2026-06-17T10:00:00Z"},
	}
	tl := aiops.BuildIncidentTimeline(allows, "t1", "2026-06-17T10:05:00Z", 100)
	if tl.EntryCount != 0 {
		t.Fatalf("a plain allow should not be a timeline entry, got %d", tl.EntryCount)
	}
}

func TestClampQueryLimit(t *testing.T) {
	cases := []struct {
		raw                  string
		def, max, wantResult int
	}{
		{"", 100, 500, 100},
		{"abc", 100, 500, 100},
		{"0", 100, 500, 100},
		{"-5", 100, 500, 100},
		{"50", 100, 500, 50},
		{"999", 100, 500, 500},
	}
	for _, c := range cases {
		if got := aiops.ClampQueryLimit(c.raw, c.def, c.max); got != c.wantResult {
			t.Fatalf("aiops.ClampQueryLimit(%q,%d,%d) = %d, want %d", c.raw, c.def, c.max, got, c.wantResult)
		}
	}
}
