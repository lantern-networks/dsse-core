package aiops

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

// ClampQueryLimit parses a limit query value, returning defaultLimit when empty/invalid and clamping
// into [1, maxLimit].
func ClampQueryLimit(raw string, defaultLimit, maxLimit int) int {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return defaultLimit
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 {
		return defaultLimit
	}
	if n > maxLimit {
		return maxLimit
	}
	return n
}

// AI Operations Assistant — deterministic analytics. Two grounded summaries computed
// purely over the retained access-decision records: an access-trends summary and an
// incident timeline. No LLM, no external call — counts + enums only, so the
// optional self-hosted OSS-LLM narrative layer can render prose on top without inventing facts.

type aiOpsCountRow struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

// TrendWindow is the range the caller asked for; TrendCoverage is the range the answer actually covers. Same
// field names and JSON shape as the AI usage report's, deliberately: the two reports are offered through the
// same period control, and one Console helper renders both. Pointers with omitempty so a caller that does not
// resolve a window (the bundled report builder) emits neither rather than emitting empty strings that read as
// "covers nothing".
type TrendWindow struct {
	Requested string `json:"requested"`
	From      string `json:"from"`
	To        string `json:"to"`
}

// TrendCoverage explains a shortfall. These decisions live in a bounded in-memory store, so the honest failure
// is eviction, not a row cap: when the store is FULL and its oldest surviving decision is newer than the window
// start, older activity existed and is gone. Truncated says exactly that, and only that — a store with room to
// spare that simply holds nothing older is a quiet tenant, not a lossy one, and must not be reported as loss.
type TrendCoverage struct {
	From      string `json:"from"`
	To        string `json:"to"`
	Decisions int    `json:"decisions"`
	Retained  int    `json:"retained"`
	Capacity  int    `json:"capacity"`
	Truncated bool   `json:"truncated"`
}

type accessTrendsReport struct {
	SchemaVersion       string          `json:"schema_version"`
	TenantID            string          `json:"tenant_id"`
	GeneratedAt         string          `json:"generated_at"`
	Window              *TrendWindow    `json:"window,omitempty"`
	Coverage            *TrendCoverage  `json:"coverage,omitempty"`
	WindowDecisions     int             `json:"window_decisions"`
	ByDecision          map[string]int  `json:"by_decision"`
	DenyCount           int             `json:"deny_count"`
	DenyRatePercent     int             `json:"deny_rate_percent"`
	StepUpCount         int             `json:"step_up_count"`
	ByActorType         map[string]int  `json:"by_actor_type"`
	ByServiceFamily     map[string]int  `json:"by_service_family"`
	TopDenyReasonCodes  []aiOpsCountRow `json:"top_deny_reason_codes"`
	TopDeniedPolicies   []aiOpsCountRow `json:"top_denied_policies"`
	GenerationMethod    string          `json:"generation_method"`
	NoSecretAttestation bool            `json:"no_secret_attestation"`
}

// decisionIsStepUp reports whether a decision is a step-up requirement (not a terminal allow/deny).
func decisionIsStepUp(decision string) bool {
	return strings.HasPrefix(decision, "require_")
}

// BuildAccessTrendsReportForWindow is BuildAccessTrendsReport plus the two facts that make the numbers
// readable: which window was asked for, and which one the retained decisions could actually answer. The
// endpoint accepted a ?window= for months and ignored it, so the Console's period control re-rendered
// identical numbers under a changed label — the shape of that bug is a report that cannot state its own range.
func BuildAccessTrendsReportForWindow(decisions []model.AccessDecision, tenantID, generatedAt string, window TrendWindow, coverage TrendCoverage) accessTrendsReport {
	report := BuildAccessTrendsReport(decisions, tenantID, generatedAt)
	report.Window = &window
	report.Coverage = &coverage
	return report
}

// DecisionsWithin returns the decisions whose own Timestamp falls in [from, to], and the oldest timestamp seen
// across ALL of the supplied decisions — the caller needs the second value to tell "nothing older exists" from
// "older existed and was evicted". A decision with an unparseable or missing timestamp is DROPPED from a
// windowed view rather than kept: keeping it would silently attribute it to whatever window is on screen.
func DecisionsWithin(decisions []model.AccessDecision, from, to time.Time) (within []model.AccessDecision, oldest time.Time) {
	for _, dec := range decisions {
		t, err := time.Parse(time.RFC3339, strings.TrimSpace(dec.Timestamp))
		if err != nil {
			continue
		}
		if oldest.IsZero() || t.Before(oldest) {
			oldest = t
		}
		if t.Before(from) || t.After(to) {
			continue
		}
		within = append(within, dec)
	}
	return within, oldest
}

// BuildAccessTrendsReport aggregates the supplied decisions (already tenant-scoped) into a trends
// summary. Pure over its inputs.
func BuildAccessTrendsReport(decisions []model.AccessDecision, tenantID, generatedAt string) accessTrendsReport {
	byDecision := map[string]int{}
	byActor := map[string]int{}
	byService := map[string]int{}
	denyReason := map[string]int{}
	deniedPolicy := map[string]int{}
	denyCount, stepUpCount := 0, 0

	for _, dec := range decisions {
		d := strings.TrimSpace(dec.Decision)
		if d == "" {
			d = "unknown"
		}
		byDecision[d]++
		byActor[ValueOrUnknown(dec.ActorType)]++
		byService[ValueOrUnknown(stringPtrValue(dec.ServiceFamily))]++
		switch {
		case d == "deny":
			denyCount++
			for _, code := range dec.ReasonCodes {
				// policy_matched is structural noise on a deny; the salient codes are the cause.
				if code == "policy_matched" {
					continue
				}
				denyReason[code]++
			}
			if pid := strings.TrimSpace(dec.PolicyID); pid != "" {
				deniedPolicy[pid]++
			}
		case decisionIsStepUp(d):
			stepUpCount++
		}
	}

	total := len(decisions)
	denyRate := 0
	if total > 0 {
		denyRate = (denyCount*100 + total/2) / total // rounded integer percent
	}
	return accessTrendsReport{
		SchemaVersion:       "ai_ops_access_trends.v1",
		TenantID:            tenantID,
		GeneratedAt:         generatedAt,
		WindowDecisions:     total,
		ByDecision:          byDecision,
		DenyCount:           denyCount,
		DenyRatePercent:     denyRate,
		StepUpCount:         stepUpCount,
		ByActorType:         byActor,
		ByServiceFamily:     byService,
		TopDenyReasonCodes:  topCountRows(denyReason, 10),
		TopDeniedPolicies:   topCountRows(deniedPolicy, 10),
		GenerationMethod:    "deterministic_no_llm",
		NoSecretAttestation: true,
	}
}

func ValueOrUnknown(v string) string {
	if strings.TrimSpace(v) == "" {
		return "unknown"
	}
	return v
}

// topCountRows returns the counts sorted by descending count, then ascending key, capped at limit.
func topCountRows(counts map[string]int, limit int) []aiOpsCountRow {
	rows := make([]aiOpsCountRow, 0, len(counts))
	for k, c := range counts {
		rows = append(rows, aiOpsCountRow{Key: k, Count: c})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Count != rows[j].Count {
			return rows[i].Count > rows[j].Count
		}
		return rows[i].Key < rows[j].Key
	})
	if limit > 0 && len(rows) > limit {
		rows = rows[:limit]
	}
	return rows
}

type IncidentTimelineEntry struct {
	Timestamp     string `json:"timestamp"`
	DecisionID    string `json:"decision_id"`
	Decision      string `json:"decision"`
	PolicyID      string `json:"policy_id,omitempty"`
	ActorType     string `json:"actor_type"`
	ServiceFamily string `json:"service_family,omitempty"`
	Severity      string `json:"severity"`
	PrimaryCode   string `json:"primary_code,omitempty"`
	SummaryEN     string `json:"summary_en"`
}

type incidentTimeline struct {
	SchemaVersion       string                  `json:"schema_version"`
	TenantID            string                  `json:"tenant_id"`
	GeneratedAt         string                  `json:"generated_at"`
	WindowDecisions     int                     `json:"window_decisions"`
	EntryCount          int                     `json:"entry_count"`
	Entries             []IncidentTimelineEntry `json:"entries"`
	GenerationMethod    string                  `json:"generation_method"`
	NoSecretAttestation bool                    `json:"no_secret_attestation"`
}

// BuildIncidentTimeline selects the notable decisions (any non-allow outcome, or one carrying a
// critical reason code) and renders a time-ordered (most recent first) timeline, reusing the grounded
// explainer for per-entry labels. Pure over its inputs.
func BuildIncidentTimeline(decisions []model.AccessDecision, tenantID, generatedAt string, limit int) incidentTimeline {
	entries := make([]IncidentTimelineEntry, 0)
	for _, dec := range decisions {
		notable := strings.TrimSpace(dec.Decision) != "allow"
		salient, hasSalient := mostSalientCode(explainReasonCodes(dec.ReasonCodes))
		if !notable && !(hasSalient && salient.Severity == "critical") {
			continue
		}
		summaryEN := decisionSummary(dec.Decision, explainReasonCodes(dec.ReasonCodes))
		entry := IncidentTimelineEntry{
			Timestamp:     dec.Timestamp,
			DecisionID:    dec.ID,
			Decision:      dec.Decision,
			PolicyID:      dec.PolicyID,
			ActorType:     ValueOrUnknown(dec.ActorType),
			ServiceFamily: stringPtrValue(dec.ServiceFamily),
			Severity:      "warning",
			SummaryEN:     summaryEN,
		}
		if hasSalient {
			entry.PrimaryCode = salient.Code
			entry.Severity = salient.Severity
		}
		entries = append(entries, entry)
	}
	// Most recent first; ties broken by decision id for determinism.
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Timestamp != entries[j].Timestamp {
			return entries[i].Timestamp > entries[j].Timestamp
		}
		return entries[i].DecisionID > entries[j].DecisionID
	})
	if limit > 0 && len(entries) > limit {
		entries = entries[:limit]
	}
	return incidentTimeline{
		SchemaVersion:       "ai_ops_incident_timeline.v1",
		TenantID:            tenantID,
		GeneratedAt:         generatedAt,
		WindowDecisions:     len(decisions),
		EntryCount:          len(entries),
		Entries:             entries,
		GenerationMethod:    "deterministic_no_llm",
		NoSecretAttestation: true,
	}
}

// explainReasonCodes maps a list of reason codes to explanations (helper shared with the timeline).
func explainReasonCodes(codes []string) []ReasonCodeExplanation {
	out := make([]ReasonCodeExplanation, 0, len(codes))
	for _, code := range codes {
		out = append(out, ExplainReasonCode(code))
	}
	return out
}
