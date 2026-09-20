package main

import (
	"context"
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
		warning, err := config.HighRiskOverlay.SetDeviceRiskContext(r.Context(), entityID, sig.Severity)
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
	auditIncoming := func(r *http.Request, tenant, target, action string, err error) {
		now := time.Now().UTC()
		result := "success"
		if err != nil {
			result = "error"
		}
		row := model.AuditLog{ID: randomEdgeID("audit_incoming_", now), TenantID: tenant, ActorUserID: auditActorPrincipal(r), EventType: "admin_incoming_changed", TargetType: stringPtr("incoming_policy"), TargetID: stringPtr(target), Action: stringPtr(action), Result: &result, Timestamp: now.Format(time.RFC3339), EdgeRegionID: &evaluator.EdgeRegionID, EdgeClusterID: &evaluator.EdgeClusterID}
		row.Metadata = map[string]any{"target_tenant_id": tenant}
		if identity, ok := adminIdentityFromRequest(r); ok && strings.TrimSpace(identity.TenantID) != "" && !strings.EqualFold(identity.TenantID, tenant) {
			stampOperatorActor(row.Metadata, identity)
		}
		_ = appendAdminAudit(r.Context(), writer, config.AdminAuditOutbox, row, now)
	}
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
		setter, ok := policyStore.(interface {
			SetServerInitiatedEnabledContext(context.Context, string, bool) error
		})
		if !ok {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("incoming policy storage is unavailable"))
			return
		}
		err := setter.SetServerInitiatedEnabledContext(r.Context(), adminTenantIDFromRequest(r), req.Enabled)
		action := "allow_default"
		if req.Enabled {
			action = "block_default"
		}
		auditIncoming(r, adminTenantIDFromRequest(r), adminTenantIDFromRequest(r), action, err)
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("Incoming policy save could not be confirmed. Reload before retrying."))
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{"server_initiated_enabled": req.Enabled})
	}))
	mux.HandleFunc("GET /admin/server-initiated", adminEndpoint("admin.serverinitiated.read", func(w http.ResponseWriter, r *http.Request) {
		if !refreshRuntimeManagement(w, policyStore) {
			return
		}

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
		var patch map[string]json.RawMessage
		if err := decodeLimitedJSONBody(w, r, &patch, maxEdgeRuntimeJSONBodyBytes); err != nil || patch == nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("invalid incoming exception object"))
			return
		}
		var key struct {
			ID       string `json:"id"`
			TenantID string `json:"tenant_id"`
		}
		raw, _ := json.Marshal(patch)
		if err := json.Unmarshal(raw, &key); err != nil || strings.TrimSpace(key.ID) == "" {
			writeError(w, http.StatusBadRequest, fmt.Errorf("id is required"))
			return
		}
		tenantForWrite, err := adminTenantForWrite(r, key.TenantID)
		if err != nil {
			writeError(w, http.StatusForbidden, err)
			return
		}
		setter, ok := policyStore.(interface {
			MutateLegacyExceptionContext(context.Context, string, string, func(model.LegacyException) (model.LegacyException, error)) (model.LegacyException, error)
		})
		if !ok {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("incoming policy storage is unavailable"))
			return
		}
		ex, err := setter.MutateLegacyExceptionContext(r.Context(), tenantForWrite, key.ID, func(current model.LegacyException) (model.LegacyException, error) {
			return mergeLegacyException(current, patch, tenantForWrite)
		})
		auditIncoming(r, tenantForWrite, key.ID, "upsert_exception", err)
		if err != nil {
			if errors.Is(err, policy.ErrPolicyPersistence) {
				writeError(w, http.StatusServiceUnavailable, fmt.Errorf("Incoming exception save could not be confirmed. Reload before retrying."))
			} else {
				writeError(w, http.StatusBadRequest, err)
			}
			return
		}

		writeJSON(w, http.StatusOK, ex)
	}))
	mux.HandleFunc("DELETE /admin/legacy-exceptions/{id}", adminEndpoint("admin.serverinitiated.write", func(w http.ResponseWriter, r *http.Request) {
		if configWriteRejectedWhenSourced(w, configSourceURL, "legacy exceptions") {
			return
		}
		setter, ok := policyStore.(interface {
			RemoveLegacyExceptionContext(context.Context, string, string) (bool, error)
		})
		if !ok {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("incoming policy storage is unavailable"))
			return
		}
		removed, err := setter.RemoveLegacyExceptionContext(r.Context(), adminTenantIDFromRequest(r), r.PathValue("id"))
		if err != nil {
			auditIncoming(r, adminTenantIDFromRequest(r), r.PathValue("id"), "remove_exception", err)
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("Incoming exception removal could not be confirmed. Reload before retrying."))
			return
		}
		if removed {
			auditIncoming(r, adminTenantIDFromRequest(r), r.PathValue("id"), "remove_exception", nil)
		}

		if !removed {
			writeError(w, http.StatusNotFound, fmt.Errorf("exception %s not found", r.PathValue("id")))
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"id": r.PathValue("id"), "status": "deleted"})
	}))
	mux.HandleFunc("GET /admin/legacy-exceptions", adminEndpoint("admin.serverinitiated.read", func(w http.ResponseWriter, r *http.Request) {
		if !refreshRuntimeManagement(w, policyStore) {
			return
		}

		var exs []model.LegacyException
		if s, ok := policyStore.(interface {
			LegacyExceptionsFor(string) []model.LegacyException
		}); ok {
			exs = s.LegacyExceptionsFor(adminTenantIDFromRequest(r))
		}
		writeJSON(w, http.StatusOK, buildLegacyExceptionList(exs, time.Now()))
	}))
	mux.HandleFunc("GET /admin/legacy-exceptions/export", adminEndpoint("admin.serverinitiated.read", func(w http.ResponseWriter, r *http.Request) {
		if !refreshRuntimeManagement(w, policyStore) {
			return
		}

		exp, err := incomingExportForTenant(policyStore, adminTenantIDFromRequest(r), time.Now())
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("Incoming policy cannot be exported safely: %w", err))
			return
		}
		writeJSON(w, http.StatusOK, exp)
	}))
}
