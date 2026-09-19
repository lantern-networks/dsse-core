package main

// Logs / audit-integrity / retention admin routes — access-decision detail, log
// query/export, legal hold, tamper-evident audit-chain verify, and runtime retention
// config — moved verbatim out of newServerWithConfig (Phase 2 route-registration split).
// Only mechanical change: config.ColdArchive / config.LegalHold /
// config.RetentionOverride became the coldArchive / legalHold / retentionOverride
// parameters.

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	accessdecision "github.com/lantern-networks/dsse-core/accessdecision"
	"github.com/lantern-networks/dsse-core/archive"
	"github.com/lantern-networks/dsse-core/hotstore"
)

// A deployment audit query reads only the reserved deployment namespace. It is
// not an all-tenant query, and selecting a customer disables this operating mode.
// Default queries keep their existing authenticated-tenant scope.
func adminLogReadScope(w http.ResponseWriter, r *http.Request) (string, bool) {
	tenant := adminTenantIDFromRequest(r)
	values, present := r.URL.Query()["audit_scope"]
	if !present {
		return tenant, true
	}
	if len(values) != 1 || (values[0] != "tenant" && values[0] != "deployment") {
		writeError(w, http.StatusBadRequest, fmt.Errorf("audit_scope must be tenant or deployment"))
		return "", false
	}
	if values[0] == "tenant" {
		return tenant, true
	}
	file, known := adminLogStreamFilename(r.PathValue("stream"))
	if !known || file != "audit.log.jsonl" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("deployment scope is available only for audit records"))
		return "", false
	}
	identity, authenticated := adminIdentityFromRequest(r)
	if !authenticated || !adminIdentityMayActAcrossOrganizations(identity) || !adminAnsweringForTheDeployment(r) {
		writeError(w, http.StatusForbidden, fmt.Errorf("deployment audit records require an operator outside a selected organization"))
		return "", false
	}
	return agentUpdateCatalogueScope, true
}

func registerLogsRetentionRoutes(mux *http.ServeMux, adminEndpoint func(string, http.HandlerFunc) http.HandlerFunc, adminHotStore hotstore.Store, decisionStore *accessdecision.Store, coldArchive archive.ColdArchive, legalHold *legalHoldStore, retentionOverride *retentionOverrideStore) {
	mux.HandleFunc("GET /admin/access-decisions/{decision_id}", adminEndpoint("admin.state.read", func(w http.ResponseWriter, r *http.Request) {
		detail, err := adminAccessDecisionDetail(adminHotStore, decisionStore, adminTenantIDFromRequest(r), r.PathValue("decision_id"))
		if err != nil {
			writeError(w, statusForAdminDecisionDetailError(err), err)
			return
		}
		writeJSON(w, http.StatusOK, detail)
	}))
	mux.HandleFunc("GET /admin/logs/{stream}", adminEndpoint("admin.logs.read", func(w http.ResponseWriter, r *http.Request) {
		tenant, allowed := adminLogReadScope(w, r)
		if !allowed {
			return
		}
		result, err := adminLogQuery(adminHotStore, tenant, r.PathValue("stream"), r.URL.Query())
		if err != nil {
			writeError(w, statusForAdminLogQueryError(err), err)
			return
		}
		writeJSON(w, http.StatusOK, result)
	}))
	mux.HandleFunc("GET /admin/logs/{stream}/export", adminEndpoint("admin.logs.export.preview", func(w http.ResponseWriter, r *http.Request) {
		tenant, allowed := adminLogReadScope(w, r)
		if !allowed {
			return
		}
		result, err := adminLogExport(adminHotStore, tenant, r.PathValue("stream"), r.URL.Query())
		if err != nil {
			writeError(w, statusForAdminLogQueryError(err), err)
			return
		}
		if result.regionCoverage != nil {
			w.Header().Set("X-DSSE-Region-Coverage", result.regionCoverage.Status)
			w.Header().Set("X-DSSE-Region-Notice", "Records without a region are excluded")
			if result.regionCoverage.UnknownRegionCount != nil {
				w.Header().Set("X-DSSE-Unknown-Region-Count", fmt.Sprint(*result.regionCoverage.UnknownRegionCount))
			}
		}
		writeAdminPreviewJSONL(w, http.StatusOK, result.rows, result.limit)
	}))
	// Legal hold (litigation / e-discovery): freeze retention for the tenant so ALL its logs are preserved.
	// ★★ A LEGAL HOLD NAMES AN ORGANIZATION UNDER INVESTIGATION (2026-08-17). List() returns every hold on the
	// node — tenant id, who set it, and the REASON — and both routes handed the whole list to whoever asked.
	// "tenant_x, retained for the Fujiwara matter" is the most sensitive sentence this product stores about a
	// customer, and it was readable by every other customer. Scoped like every other per-tenant read; the
	// operator, answering for the deployment, still sees all of them because acting on one is their job.
	holdsFor := func(r *http.Request) []legalHoldRecord {
		all := legalHold.List()
		if _, wholeDeployment := adminAnswerScope(r); wholeDeployment {
			return all
		}
		caller := strings.TrimSpace(adminTenantIDFromRequest(r))
		mine := make([]legalHoldRecord, 0, 1)
		for _, h := range all {
			if strings.EqualFold(strings.TrimSpace(h.TenantID), caller) {
				mine = append(mine, h)
			}
		}
		return mine
	}
	mux.HandleFunc("GET /admin/legal-hold", adminEndpoint("admin.retention.read", func(w http.ResponseWriter, r *http.Request) {
		if err := legalHold.Health(); err != nil {
			writeError(w, http.StatusServiceUnavailable, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"holds": holdsFor(r), "tenant_held": legalHold.IsHeld(adminTenantIDFromRequest(r))})
	}))
	mux.HandleFunc("POST /admin/legal-hold", adminEndpoint("admin.retention.write", func(w http.ResponseWriter, r *http.Request) {
		if err := legalHold.Health(); err != nil {
			writeError(w, http.StatusServiceUnavailable, err)
			return
		}
		var req struct {
			Active bool   `json:"active"`
			Reason string `json:"reason"`
		}
		if err := decodeLimitedJSONBody(w, r, &req, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("invalid request body: %w", err))
			return
		}
		tenantID := adminTenantIDFromRequest(r)
		if tenantID == "" {
			writeError(w, http.StatusForbidden, fmt.Errorf("tenant scope is required"))
			return
		}
		if err := legalHold.Set(tenantID, adminPrincipalIDFromRequest(r), strings.TrimSpace(req.Reason), req.Active, time.Now()); err != nil {
			logErrorf("legal hold update failed: %v", err)
			writeError(w, http.StatusInternalServerError, fmt.Errorf("legal hold update could not be saved"))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"holds": holdsFor(r), "tenant_held": legalHold.IsHeld(tenantID)})
	}))
	// Verify the tamper-evident hash chain of the tenant's archived audit segments (compliance integrity check).
	mux.HandleFunc("GET /admin/audit-chain/verify", adminEndpoint("admin.retention.read", func(w http.ResponseWriter, r *http.Request) {
		if coldArchive == nil {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("no cold archive configured"))
			return
		}
		res, err := verifyAuditChain(r.Context(), coldArchive, adminTenantIDFromRequest(r))
		if err != nil {
			writeError(w, http.StatusBadGateway, fmt.Errorf("verify audit chain: %w", err))
			return
		}
		writeJSON(w, http.StatusOK, res)
	}))
	// Admin-configurable per-stream retention (days), overriding the startup flags at runtime (no redeploy).
	mux.HandleFunc("GET /admin/retention-config", adminEndpoint("admin.retention.read", func(w http.ResponseWriter, r *http.Request) {
		if retentionOverride == nil || retentionOverride.Health() != nil {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("retention settings are unavailable"))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"overrides_days": retentionOverride.All()})
	}))
	mux.HandleFunc("POST /admin/retention-config", adminEndpoint("admin.retention.write", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Stream string `json:"stream"`
			Days   *int   `json:"days"`
			Clear  bool   `json:"clear"`
		}
		if err := decodeLimitedJSONBody(w, r, &req, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("invalid request body: %w", err))
			return
		}
		if strings.TrimSpace(req.Stream) == "" {
			writeError(w, http.StatusBadRequest, fmt.Errorf("stream is required"))
			return
		}
		// ★★ HOW LONG THIS NODE KEEPS ITS LOGS IS THE DEPLOYMENT'S (2026-08-17, measured as a customer
		// administrator: the route reached its handler and answered 400 only because the body was malformed).
		// The override is per STREAM and node-wide — there is no tenant in it — so a customer setting audit
		// retention to a day would drop every organization's history, including their own regulator's evidence.
		//
		// Gated here rather than by moving admin.retention.write to the operator, because the same scope also
		// carries POST /admin/legal-hold, which IS a customer's own act on their own organization. Taking that
		// away to close this would be closing an operator hole by removing a customer's right.
		if _, wholeDeployment := adminAnswerScope(r); !wholeDeployment {
			writeError(w, http.StatusForbidden, fmt.Errorf(
				"log retention is set for this deployment, not per organization, so it is the operator's to change"))
			return
		}
		if retentionOverride == nil || retentionOverride.Health() != nil {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("retention settings are unavailable"))
			return
		}
		days := -1
		if !req.Clear && req.Days == nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("retention days are required"))
			return
		}
		if req.Days != nil {
			days = *req.Days
		}
		if req.Clear {
			days = -1
		} else if days < 0 || days > maxRetentionDays {
			writeError(w, http.StatusBadRequest, fmt.Errorf("retention days are out of range"))
			return
		}
		if err := retentionOverride.Set(strings.TrimSpace(req.Stream), days); err != nil {
			logErrorf("retention override update failed: %v", err)
			writeError(w, http.StatusInternalServerError, fmt.Errorf("retention settings could not be saved"))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"overrides_days": retentionOverride.All()})
	}))
}
