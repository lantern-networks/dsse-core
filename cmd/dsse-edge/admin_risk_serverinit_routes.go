package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/policy"
	"github.com/lantern-networks/dsse-core/revocation"
)

// Risk-signal overlay, server-initiated access, and legacy-exception admin routes,
// moved verbatim out of newServerWithConfig (Phase 2 route-registration split). Takes
// serverConfig whole for the high-risk overlay / server-initiated store fields.
func registerRiskServerInitiatedRoutes(mux *http.ServeMux, adminEndpoint func(string, http.HandlerFunc) http.HandlerFunc, config serverConfig, evaluator decision.Evaluator, writer *logs.Writer, policyStore policy.RuntimeStore, deviceStore deviceRuntimeStore, configSourceURL string) {
	mux.HandleFunc("POST /admin/risk-signals", adminEndpoint("admin.risk.write", func(w http.ResponseWriter, r *http.Request) {
		// Risk State: ingest a risk signal (incl. Manual High Risk Marking). High risk folds into
		// the device's risk state (decisions react via risk_state_severity/admin_high_risk) and revokes
		// the device's standing east-west grants (acceleration). Phase 3: the high-risk marking is
		// CP-authoritative + fleet-distributed, so author it on the control plane.
		if configWriteRejectedWhenSourced(w, configSourceURL, "risk signals (high-risk marking)") {
			return
		}
		var sig model.RiskSignal
		if err := json.NewDecoder(r.Body).Decode(&sig); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("invalid request body: %w", err))
			return
		}
		if strings.EqualFold(strings.TrimSpace(sig.EntityType), "user") || strings.EqualFold(strings.TrimSpace(sig.EntityType), "human") {
			resp, tenant, ok := writeUserRisk(w, r, config, sig)
			if !ok {
				return
			}
			now := time.Now().UTC()
			_ = appendAdminAudit(r.Context(), writer, config.AdminAuditOutbox, userRiskAuditLog(r, tenant, resp, evaluator, now), now)
			writeJSON(w, http.StatusOK, resp)
			return
		}
		// ★★★ AND THE ENTITY HAS TO BE THEIRS (2026-08-22, measured — see
		// a_risk_mark_names_someone_elses_device.go). The READ was scoped on 2026-08-18 and this write was
		// missed beside it. A customer marked another organization's named laptop critical and every node's
		// decision path began treating it as high risk.
		//
		// 404 rather than 403, like the kill-switch and the concern report: whether an entity exists on this
		// node is itself the answer being withheld.
		if _, wholeDeployment := adminAnswerScope(r); !wholeDeployment {
			if owned, why := riskEntityOwnedByCaller(r.Context(), sig.EntityType, sig.EntityID,
				adminTenantIDFromRequest(r), config.EnrolledLedger, config.HumanIdentities); !owned {
				writeError(w, http.StatusNotFound, fmt.Errorf("%s", why))
				return
			}
		}
		resp, err := applyAdminRiskSignal(deviceStore, adminTenantIDFromRequest(r), sig, time.Now())
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		// Phase 3: reflect the marking into the shared high-risk overlay so EVERY node's decision path
		// treats the device as high-risk (fleet-consistent risk-based deny/re-auth; reconnect-elsewhere blocked).
		if config.HighRiskOverlay != nil && strings.EqualFold(resp.EntityType, "device") {
			// The overlay carries the GRADED severity (medium|high|critical) so a policy can gate on any level
			// (risk_state_severity). AdminHighRisk (the high-risk behaviours) is derived from high|critical only,
			// in the decision enrichment — a medium mark is a policy signal, not a "high-risk" device/user.
			switch strings.ToLower(strings.TrimSpace(resp.Severity)) {
			case "medium", "high", "critical":
				config.HighRiskOverlay.Mark(resp.EntityID, strings.ToLower(strings.TrimSpace(resp.Severity)))
			default:
				config.HighRiskOverlay.Clear(resp.EntityID)
			}
		}
		writeJSON(w, http.StatusOK, resp)
	}))
	// An unattributed v1 mark is intentionally outside both typed namespaces.
	// Only an operator can explicitly discard it after inspecting the raw-ID
	// list; normal device/user edits never resolve an ambiguous mark.
	mux.HandleFunc("POST /admin/risk-signals/legacy-unattributed/resolve", adminEndpoint("admin.risk.write", func(w http.ResponseWriter, r *http.Request) {
		if !adminCallerIsOperator(r) {
			writeError(w, http.StatusForbidden, fmt.Errorf("operator access required"))
			return
		}
		if configWriteRejectedWhenSourced(w, configSourceURL, "legacy risk resolution") {
			return
		}
		if config.HighRiskOverlay == nil {
			writeError(w, http.StatusServiceUnavailable, revocation.ErrRiskUnavailable)
			return
		}
		var req struct {
			ID               string `json:"id"`
			ExpectedSeverity string `json:"expected_severity"`
			Reason           string `json:"reason"`
			ConfirmDiscard   bool   `json:"confirm_discard"`
		}
		if err := decodeLimitedJSONBody(w, r, &req, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("invalid request body: %w", err))
			return
		}
		if !req.ConfirmDiscard || strings.TrimSpace(req.Reason) == "" {
			writeError(w, http.StatusBadRequest, fmt.Errorf("confirm_discard and reason are required"))
			return
		}
		warning, err := config.HighRiskOverlay.DiscardLegacyUnattributed(req.ID, req.ExpectedSeverity)
		if err != nil {
			switch {
			case errors.Is(err, revocation.ErrLegacyRiskNotFound):
				writeError(w, http.StatusNotFound, err)
			case errors.Is(err, revocation.ErrLegacyRiskChanged):
				writeError(w, http.StatusConflict, err)
			case errors.Is(err, revocation.ErrRiskSave), errors.Is(err, revocation.ErrRiskUnavailable):
				writeError(w, http.StatusServiceUnavailable, err)
			default:
				writeError(w, http.StatusBadRequest, err)
			}
			return
		}
		now := time.Now().UTC()
		idHash := sha256.Sum256([]byte(strings.TrimSpace(req.ID)))
		idDigest := fmt.Sprintf("%x", idHash[:])
		result := "success"
		if warning {
			result = "partial"
		}
		audit := model.AuditLog{
			ID: randomEdgeID("audit_legacy_risk_", now), ActorUserID: auditActorPrincipal(r),
			EventType: "legacy_unattributed_risk_discarded", TargetType: stringPtr("legacy_risk_id_sha256"),
			TargetID: stringPtr(idDigest), Action: stringPtr("discard_legacy_risk"), Result: stringPtr(result),
			PolicyBundleID: &evaluator.PolicyBundle.ID, EdgeRegionID: &evaluator.EdgeRegionID,
			EdgeClusterID: &evaluator.EdgeClusterID, SourceIP: stringPtr(sourceIPFromRequest(r)),
			Timestamp: now.Format(time.RFC3339),
			Metadata:  map[string]any{"expected_severity": req.ExpectedSeverity, "reason_provided": true, "save_non_atomic": warning},
		}
		_ = appendAdminAudit(r.Context(), writer, config.AdminAuditOutbox, audit, now)
		writeJSON(w, http.StatusOK, map[string]any{"resolved": true, "legacy_unattributed_count": config.HighRiskOverlay.LegacyUnattributedCount(), "save_non_atomic": warning})
	}))
	// GET /admin/risk-signals: device marks by default, or typed, tenant-scoped user marks when requested.
	mux.HandleFunc("GET /admin/risk-signals", adminEndpoint("admin.risk.read", func(w http.ResponseWriter, r *http.Request) {
		snap := map[string]string{}
		var users []revocation.UserRisk
		if config.HighRiskOverlay != nil {
			var err error
			snap, users, err = config.HighRiskOverlay.CheckedSnapshot()
			if err != nil {
				writeError(w, http.StatusServiceUnavailable, fmt.Errorf("risk state is unavailable"))
				return
			}
		}
		if r.URL.Query().Get("entity_type") == "user" {
			if config.HighRiskOverlay == nil {
				writeError(w, http.StatusServiceUnavailable, fmt.Errorf("risk state is unavailable"))
				return
			}
			tenant := adminTenantIDFromRequest(r)
			mine := map[string]string{}
			for _, mark := range users {
				if mark.TenantID == tenant {
					mine[mark.ID] = mark.Severity
				}
			}
			resp := map[string]any{"entity_type": "user", "tenant_id": tenant, "high_risk": mine}
			if adminCallerIsOperator(r) {
				resp["legacy_unattributed_count"] = config.HighRiskOverlay.LegacyUnattributedCount()
				resp["legacy_unattributed"] = config.HighRiskOverlay.LegacyUnattributedSnapshot()
			}
			writeJSON(w, http.StatusOK, resp)
			return
		}
		// ★★ SCOPED, LIKE THE KILL-SWITCH LIST NEXT DOOR (2026-08-18). This overlay names every entity the
		// deployment currently considers high risk, with the severity, and it was handed whole to any caller
		// holding admin.risk.read — a permission every tenant administrator has. "win-dev-1: critical" is a
		// statement about another customer's incident when it is not the caller's, which is the sentence
		// GET /admin/transport-admission was scoped for in the August per-device sweep. This one was three
		// files away and was missed.
		//
		// Entities the enrolled ledger cannot place are counted rather than listed, the same way that list
		// does it: a marked entity that has since been deleted is an ordinary end state, and dropping it
		// silently would let the answer read as "nothing is at risk".
		withheld := 0
		if _, wholeDeployment := adminAnswerScope(r); !wholeDeployment {
			callerTenant := adminTenantIDFromRequest(r)
			mine := make(map[string]string, len(snap))
			for entity, severity := range snap {
				belongs, placeable := identityBelongsToTenant(config.EnrolledLedger, entity, callerTenant)
				if belongs && placeable {
					mine[entity] = severity
					continue
				}
				// ★ ANOTHER ORGANIZATION'S DEVICE IS NOT "UNATTRIBUTABLE", AND COUNTING IT AS ONE WOULD PUBLISH
				// THE SIZE OF THEIR INCIDENT. Only entities the ledger cannot place at all are counted — a mark
				// on something since deleted, which is an ordinary end state and the reason a count exists.
				if !placeable {
					withheld++
				}
			}
			snap = mine
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"high_risk": snap,
			// Named rather than dropped, so a customer is never shown a smaller version of their own risk
			// picture without being told a smaller version is what they are looking at.
			"withheld_unattributable": withheld,
		})
	}))
	mux.HandleFunc("POST /admin/server-initiated", adminEndpoint("admin.serverinitiated.write", func(w http.ResponseWriter, r *http.Request) {
		if configWriteRejectedWhenSourced(w, configSourceURL, "server-initiated config") {
			return
		}
		// toggle server-initiated (server->client) default-deny enforcement for the tenant.
		var req struct {
			Enabled bool `json:"enabled"`
		}
		if err := decodeLimitedJSONBody(w, r, &req, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("invalid request body: %w", err))
			return
		}
		if s, ok := policyStore.(interface {
			SetServerInitiatedEnabled(string, bool)
		}); ok {
			s.SetServerInitiatedEnabled(adminTenantIDFromRequest(r), req.Enabled)
		}
		writeJSON(w, http.StatusOK, map[string]any{"server_initiated_enabled": req.Enabled})
	}))
	mux.HandleFunc("GET /admin/server-initiated", adminEndpoint("admin.serverinitiated.read", func(w http.ResponseWriter, r *http.Request) {
		// The live default for incoming (server-initiated) connections, so the Console shows which is in effect.
		enabled := false
		if s, ok := policyStore.(interface {
			ServerInitiatedEnabledFor(string) bool
		}); ok {
			enabled = s.ServerInitiatedEnabledFor(adminTenantIDFromRequest(r))
		}
		writeJSON(w, http.StatusOK, map[string]any{"server_initiated_enabled": enabled})
	}))
	mux.HandleFunc("POST /admin/legacy-exceptions", adminEndpoint("admin.serverinitiated.write", func(w http.ResponseWriter, r *http.Request) {
		if configWriteRejectedWhenSourced(w, configSourceURL, "legacy exceptions") {
			return
		}
		// register/update a Legacy Exception (explicit governed allow for a server-initiated flow).
		var ex model.LegacyException
		if err := json.NewDecoder(r.Body).Decode(&ex); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("invalid request body: %w", err))
			return
		}
		// A legacy exception is an explicit governed ALLOW for a server-initiated flow. Whose it is comes from
		// the caller, not from the body they wrote.
		tenantForWrite, terr := adminTenantForWrite(r, ex.TenantID)
		if terr != nil {
			writeError(w, http.StatusForbidden, terr)
			return
		}
		ex.TenantID = tenantForWrite
		if strings.TrimSpace(ex.Status) == "" {
			ex.Status = "active"
		}
		if err := validateLegacyException(ex); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if s, ok := policyStore.(interface {
			UpsertLegacyException(string, model.LegacyException)
		}); ok {
			s.UpsertLegacyException(ex.TenantID, ex)
		}
		writeJSON(w, http.StatusOK, ex)
	}))
	mux.HandleFunc("DELETE /admin/legacy-exceptions/{id}", adminEndpoint("admin.serverinitiated.write", func(w http.ResponseWriter, r *http.Request) {
		if configWriteRejectedWhenSourced(w, configSourceURL, "legacy exceptions") {
			return
		}
		removed := false
		if s, ok := policyStore.(interface {
			RemoveLegacyException(string, string) bool
		}); ok {
			removed = s.RemoveLegacyException(adminTenantIDFromRequest(r), r.PathValue("id"))
		}
		if !removed {
			writeError(w, http.StatusNotFound, fmt.Errorf("exception %s not found", r.PathValue("id")))
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"id": r.PathValue("id"), "status": "deleted"})
	}))
	mux.HandleFunc("GET /admin/legacy-exceptions", adminEndpoint("admin.serverinitiated.read", func(w http.ResponseWriter, r *http.Request) {
		var exs []model.LegacyException
		if s, ok := policyStore.(interface {
			LegacyExceptionsFor(string) []model.LegacyException
		}); ok {
			exs = s.LegacyExceptionsFor(adminTenantIDFromRequest(r))
		}
		writeJSON(w, http.StatusOK, buildLegacyExceptionList(exs, time.Now()))
	}))
	mux.HandleFunc("GET /admin/legacy-exceptions/export", adminEndpoint("admin.serverinitiated.read", func(w http.ResponseWriter, r *http.Request) {
		// S2: export active Legacy Exceptions as Firewall / L3 rules (default-deny + explicit allow)
		// for agentless / VLAN-boundary enforcement of server-initiated traffic.
		exp, err := incomingExportForTenant(policyStore, adminTenantIDFromRequest(r), time.Now())
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("Incoming policy cannot be exported safely: %w", err))
			return
		}
		writeJSON(w, http.StatusOK, exp)
	}))
}
