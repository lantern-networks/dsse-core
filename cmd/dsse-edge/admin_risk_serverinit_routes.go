package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/policy"
)

// Risk-signal overlay, server-initiated access, and legacy-exception admin routes,
// moved verbatim out of newServerWithConfig (Phase 2 route-registration split). Takes
// serverConfig whole for the high-risk overlay / server-initiated store fields.
func registerRiskServerInitiatedRoutes(mux *http.ServeMux, adminEndpoint func(string, http.HandlerFunc) http.HandlerFunc, config serverConfig, evaluator decision.Evaluator, writer *logs.Writer, policyStore policy.RuntimeStore, deviceStore deviceRuntimeStore, configSourceURL string) {
	mux.HandleFunc("POST /admin/risk-signals", adminEndpoint("admin.risk.write", func(w http.ResponseWriter, r *http.Request) {
		// Risk State: ingest a risk signal (incl. Manual High Risk Marking). High risk folds into
		// the device's risk state (decisions react via risk_state_severity/admin_high_risk); enforcement
		// is determined by policy, not by ingesting the signal. Phase 3: the high-risk marking is
		// CP-authoritative + fleet-distributed, so author it on the control plane.
		if configWriteRejectedWhenSourced(w, configSourceURL, "risk signals (high-risk marking)") {
			return
		}
		var sig model.RiskSignal
		if err := json.NewDecoder(r.Body).Decode(&sig); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("invalid request body: %w", err))
			return
		}
		// ★★★ AND THE ENTITY HAS TO BE THEIRS (2026-08-22, measured — see
		// a_risk_mark_names_someone_elses_device.go). The READ was scoped on 2026-08-18 and this write was
		// missed beside it. A customer marked another organization's named laptop critical and every node's
		// decision path began treating it as high risk.
		//
		// 404 rather than 403, like the kill-switch and the concern report: whether an entity exists on this
		// node is itself the answer being withheld.
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
		if _, wholeDeployment := adminAnswerScope(r); !wholeDeployment {
			if owned, why := riskEntityOwnedByCaller(r.Context(), sig.EntityType, sig.EntityID,
				adminTenantIDFromRequest(r), config.EnrolledLedger, config.HumanIdentities); !owned {
				writeError(w, http.StatusNotFound, fmt.Errorf("%s", why))
				return
			}
		}
		_, entityID, err := validateAdminRiskSignal(deviceStore, sig)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		tenantID := adminTenantIDFromRequest(r)
		if config.EnrolledLedger != nil {
			if entry, ok := config.EnrolledLedger.EntryFor(entityID); ok && strings.TrimSpace(entry.TenantID) != "" {
				tenantID = entry.TenantID
			}
		}
		warning, err := config.HighRiskOverlay.SetDeviceRisk(entityID, sig.Severity)
		if err != nil {
			now := time.Now().UTC()
			failure := deviceRiskAuditLog(r, tenantID, adminRiskSignalResponse{EntityType: "device", EntityID: entityID, Severity: strings.ToLower(strings.TrimSpace(sig.Severity))}, evaluator, now)
			failure.EventType = "device_risk_change_failed"
			failure.Result = stringPtr("error")
			failure.Metadata["requested_severity"] = failure.Metadata["severity"]
			delete(failure.Metadata, "severity")
			delete(failure.Metadata, "high_risk")
			_ = appendAdminAudit(r.Context(), writer, config.AdminAuditOutbox, failure, now)
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("device risk save was not confirmed; the live overlay and runtime were not changed"))
			return
		}
		resp, err := applyAdminRiskSignal(deviceStore, adminTenantIDFromRequest(r), sig, time.Now())
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		resp.OverlayPersistenceWarning = warning
		if warning {
			if resp.NotStoredDurably != "" {
				resp.NotStoredDurably += " "
			}
			resp.NotStoredDurably += "Risk is applied with a volatile or non-atomic overlay save. Reapply after storage is healthy."
		}
		if resp.EntityType == "device" {
			now := time.Now().UTC()
			_ = appendAdminAudit(r.Context(), writer, config.AdminAuditOutbox,
				deviceRiskAuditLog(r, tenantID, resp, evaluator, now), now)
		}
		writeJSON(w, http.StatusOK, resp)
	}))
	// GET /admin/risk-signals: the current high-risk overlay (entity id -> severity), so the console can show a
	// current-risk badge on its own row. The explicit user query uses a tenant-scoped namespace.
	mux.HandleFunc("GET /admin/risk-signals", adminEndpoint("admin.risk.read", func(w http.ResponseWriter, r *http.Request) {
		if riskReadRefusedOnAStandby(w) {
			return
		}
		snap, users, err := config.HighRiskOverlay.CheckedSnapshot()
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("risk state is unavailable"))
			return
		}
		if r.URL.Query().Get("entity_type") == "user" {
			tenant := adminTenantIDFromRequest(r)
			snap := map[string]string{}
			for _, mark := range users {
				if mark.TenantID == tenant {
					snap[mark.ID] = mark.Severity
				}
			}
			writeJSON(w, 200, map[string]any{"entity_type": "user", "tenant_id": tenant, "high_risk": snap})
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
			"entity_type": "device",
			"tenant_id":   adminTenantIDFromRequest(r),
			"high_risk":   snap,
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
		var exs []model.LegacyException
		if s, ok := policyStore.(interface {
			LegacyExceptionsFor(string) []model.LegacyException
		}); ok {
			exs = s.LegacyExceptionsFor(adminTenantIDFromRequest(r))
		}
		exp := buildServerInitiatedExport(exs, time.Now())
		// Reflect the tenant's Incoming-Connections default toggle (POST /admin/server-initiated) into the
		// export: "allow by default" (enabled=false) => default_action=allow, telling the consuming enforcement
		// point (e.g. the Windows firewall inbound backend) that DSSE is NOT managing inbound and its rules
		// should be withdrawn. Enabled => the historical default-deny contract, unchanged.
		if s, ok := policyStore.(interface {
			ServerInitiatedEnabledFor(string) bool
		}); ok && !s.ServerInitiatedEnabledFor(adminTenantIDFromRequest(r)) {
			exp.DefaultAction = "allow"
		}
		writeJSON(w, http.StatusOK, exp)
	}))
}
