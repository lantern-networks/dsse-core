package main

// (AI Operations Assistant) + (AI Security Visibility) admin routes, moved
// verbatim out of newServerWithConfig (Phase 2 route-registration split,
// ). The group's private services
// (the narrative-renderer registry and the opt-in local-LLM chat client) are constructed
// here because nothing outside these routes uses them. Parameter names match the
// constructor's locals so the handler bodies are untouched.

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	accessdecision "github.com/lantern-networks/dsse-core/accessdecision"
	"github.com/lantern-networks/dsse-core/aiops"
	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/hotstore"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/policy"
)

func registerAIOpsRoutes(mux *http.ServeMux, adminEndpoint func(string, http.HandlerFunc) http.HandlerFunc, evaluator decision.Evaluator, policyStore policy.RuntimeStore, decisionStore *accessdecision.Store, adminHotStore hotstore.Store) {
	mux.HandleFunc("GET /admin/ai-usage-report", adminEndpoint("admin.ai.read", func(w http.ResponseWriter, r *http.Request) {
		// AI Security Visibility: identify known generative-AI service usage from access logs,
		// classify (approved|tolerated|prohibited via the SaaS catalog / built-in defaults), and report.
		// tenant isolation: the access log is shared storage; the report MUST be scoped to the
		// requesting admin's (authenticated, non-spoofable) tenant — never aggregate across tenants.
		tenantID := adminTenantIDFromRequest(r)
		if strings.TrimSpace(tenantID) == "" {
			writeError(w, http.StatusForbidden, fmt.Errorf("admin tenant is required for the AI usage report"))
			return
		}
		// The window is the caller's (?window=24h|7d|30d, or ?from=&to=), defaulting to reportDefaultWindow so
		// callers that pass nothing see no change. Rejected, not clamped, when out of range — see
		//
		now := time.Now().UTC()
		from, to, requested, err := resolveReportWindow(r.URL.Query(), now)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		catalog := runtimeEvaluatorForPolicyStore(evaluator, policyStore).PolicyBundle.SaaSCatalog
		// Prefer letting the store GROUP BY when it can (Postgres): the report's cardinality is
		// users × devices × apps × services, which is hundreds, against a row count that is not bounded by
		// anything the operator controls. Both paths reach the same aggregation function, and the response says
		// which one answered — a serving path that changes silently is one nobody can rule out later.
		if grouper, ok := adminHotStore.(hotstore.FieldGroupCapable); ok && aiUsageAggregateEnabled {
			grouped, err := grouper.GroupRowsByFields(r.Context(), aiUsageGroupQuery(tenantID, from, to))
			if err != nil {
				writeError(w, http.StatusInternalServerError, fmt.Errorf("group access log: %w", err))
				return
			}
			report := buildAIUsageReportFromInputs(aiUsageInputsFromGroups(grouped.Groups), catalog, now.Format(time.RFC3339))
			report.Window = aiUsageWindow{Requested: requested, From: from.Format(time.RFC3339), To: to.Format(time.RFC3339)}
			// tenant isolation on this path rests on the bound tenant_id in the statement's WHERE, where
			// the row-loading path below ALSO re-filters in Go (accessRowsForTenant). The asymmetry is deliberate
			// and worth naming: the Go filter guards against a store that ignores the scope it was given, which a
			// parameterised SQL predicate cannot do. If a backend is ever added whose scoping is less certain
			// than a bound parameter, it does not get to serve this without an equivalent second check.
			aggregateCoverage := aiUsageCoverage{
				Source: "aggregate",
				From:   from.Format(time.RFC3339),
				To:     to.Format(time.RFC3339),
				Rows:   grouped.TotalRows,
				// Zero, not the group cap: nothing is row-loaded here, so there is no row cap. Putting the group
				// cap in a field named row_cap would invite the comparison rows >= row_cap, which on this path
				// compares events against groups and is meaningless. Truncation is reported by its own flag.
				RowCap:    0,
				Truncated: grouped.Truncated,
			}
			if !grouped.OldestMatchedAt.IsZero() && grouped.OldestMatchedAt.After(from) {
				aggregateCoverage.RetainedFrom = grouped.OldestMatchedAt.UTC().Format(time.RFC3339)
			}
			report.Coverage = aggregateCoverage
			writeJSON(w, http.StatusOK, report)
			return
		}
		// Read AI-usage rows through the HOT STORE, not the local jsonl file directly: with -hot-store=postgres
		// this reads from Postgres (offloading the dataplane edge), identical on the jsonl backend. ExportRows so
		// the aggregation sees ALL rows in the window; bounded so a large, growing Postgres table is not fully
		// scanned on every load (the raw rows stay for arbitrary historical graphing).
		var rows []map[string]any
		var oldest time.Time
		export, err := adminHotStore.ExportRows(r.Context(), hotstore.SearchQuery{TenantID: tenantID, Stream: "access", From: &from, To: &to, Limit: aiUsageReportRowCap, IncludeOldestMatched: true}, func(row map[string]any) error {
			rows = append(rows, row)
			// Track the earliest row by comparison rather than by trusting the backends' newest-first ordering:
			// this is what tells the operator the cap cut the window short, so it must not depend on ORDER BY.
			if t, ok := aiUsageRowTime(row); ok && (oldest.IsZero() || t.Before(oldest)) {
				oldest = t
			}
			return nil
		})
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("read access log: %w", err))
			return
		}
		report := buildAIUsageReport(accessRowsForTenant(rows, tenantID), catalog, now.Format(time.RFC3339))
		report.Window = aiUsageWindow{Requested: requested, From: from.Format(time.RFC3339), To: to.Format(time.RFC3339)}
		// Truncated means the cap, not the window, decided where the data starts. Report the coverage actually
		// achieved: a report that is silently three days when it says seven is the defect this replaces.
		truncated := len(rows) >= aiUsageReportRowCap
		coverageFrom := from
		if truncated && !oldest.IsZero() {
			coverageFrom = oldest.UTC()
		}
		coverage := aiUsageCoverage{
			Source:    "rows",
			From:      coverageFrom.Format(time.RFC3339),
			To:        to.Format(time.RFC3339),
			Rows:      len(rows),
			RowCap:    aiUsageReportRowCap,
			Truncated: truncated,
		}
		// The second way a window can be wider than the answer: no records exist that far back. Report the
		// horizon as a fact and let the reader draw the conclusion — a quiet tenant and one whose old records
		// rotated away are indistinguishable from here, so this must not be dressed up as data loss.
		if !export.OldestMatchedAt.IsZero() && export.OldestMatchedAt.After(from) {
			coverage.RetainedFrom = export.OldestMatchedAt.UTC().Format(time.RFC3339)
		}
		report.Coverage = coverage
		writeJSON(w, http.StatusOK, report)
	}))
	mux.HandleFunc("GET /admin/ai-ops/access-trends", adminEndpoint("admin.ai.read", func(w http.ResponseWriter, r *http.Request) {
		// AI Operations Assistant (access-trend summary): deterministic aggregate of the retained
		// access decisions for the tenant (by decision / actor / service, deny rate, top deny reasons +
		// policies). No LLM, no external call — counts + enums only.
		tenantID := adminTenantIDFromRequest(r)
		// ?window= is the SAME control the Console offers on the AI usage report, resolved by the same code.
		// It was accepted and ignored here: the Overview period switcher re-rendered identical numbers under a
		// changed label, which is worse than having no switcher.
		now := time.Now().UTC()
		from, to, requested, err := resolveReportWindow(r.URL.Query(), now)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		// Whose decisions are these? The deployment's, not this process's — so read them from the hot store,
		// which holds every edge's and survives a restart. The node's own ring is the fallback for a standalone
		// edge with no hot store wired, and ONLY that: an empty answer from the hot store is authoritative.
		// See a_deployments_decisions_outlive_the_node_that_made_them.go for what this replaced.
		var within []model.AccessDecision
		var coverage aiops.TrendCoverage
		if decisions, oldestRead, oldestHeld, capped, served := accessTrendsFromHotStore(r.Context(), adminHotStore, tenantID, from, to); served {
			within, _ = aiops.DecisionsWithin(decisions, from, to)
			// Truncated here means the row cap, not the window, decided where the data starts — the same
			// distinction the AI-usage report draws above. Capacity is the cap that applied, so the two
			// numbers beside it stay comparable.
			coverageFrom := from
			if capped && !oldestRead.IsZero() {
				coverageFrom = oldestRead
			} else if !oldestHeld.IsZero() && oldestHeld.After(from) {
				// Not truncation: the deployment simply holds nothing that far back. Reporting the horizon as
				// a fact is what lets the reader tell a quiet window from one whose records have aged out.
				coverageFrom = oldestHeld.UTC()
			}
			coverage = aiops.TrendCoverage{
				From:      coverageFrom.Format(time.RFC3339),
				To:        to.Format(time.RFC3339),
				Decisions: len(within),
				Retained:  len(decisions),
				Capacity:  accessTrendsHotStoreRowCap,
				Truncated: capped,
			}
		} else {
			var oldest time.Time
			within, oldest = aiops.DecisionsWithin(decisionStore.SnapshotByTenant(tenantID), from, to)
			// These decisions live in a bounded in-memory store. Report a shortfall only when the store is FULL
			// and its oldest survivor is newer than the window start — that is eviction. A store with room to
			// spare that holds nothing older is a quiet tenant, and calling that "truncated" would cry wolf on
			// every freshly restarted edge.
			full := decisionStore.Capacity() > 0 && decisionStore.Count() >= decisionStore.Capacity()
			coverageFrom := from
			if full && !oldest.IsZero() && oldest.After(from) {
				coverageFrom = oldest.UTC()
			}
			coverage = aiops.TrendCoverage{
				From:      coverageFrom.Format(time.RFC3339),
				To:        to.Format(time.RFC3339),
				Decisions: len(within),
				Retained:  decisionStore.Count(),
				Capacity:  decisionStore.Capacity(),
				Truncated: coverageFrom != from,
			}
		}
		report := aiops.BuildAccessTrendsReportForWindow(within, tenantID, now.Format(time.RFC3339),
			aiops.TrendWindow{Requested: requested, From: from.Format(time.RFC3339), To: to.Format(time.RFC3339)},
			coverage)
		writeJSON(w, http.StatusOK, report)
	}))
}
