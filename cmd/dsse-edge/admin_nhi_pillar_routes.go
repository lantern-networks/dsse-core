package main

// NHI / AI-agent pillar admin routes — agent-tool registry, tool-call audit events,
// delegated-access grants, and human-approval events — moved verbatim out of
// newServerWithConfig (Phase 2 route-registration split). Parameter names match the
// constructor's locals so the handler bodies are untouched.

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/agenttool"
	"github.com/lantern-networks/dsse-core/decision"
	delegatedgrant "github.com/lantern-networks/dsse-core/delegatedgrant"
	humanapproval "github.com/lantern-networks/dsse-core/humanapproval"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
	nhi "github.com/lantern-networks/dsse-core/nhi"
	"github.com/lantern-networks/dsse-core/toolcallaudit"
)

func registerNHIPillarRoutes(mux *http.ServeMux, adminEndpoint func(string, http.HandlerFunc) http.HandlerFunc, evaluator decision.Evaluator, writer *logs.Writer, adminAuditOutbox adminAuditOutboxDeadReader, agentToolStore agenttool.RuntimeStore, toolCallEventAuditStore toolcallaudit.RuntimeStore, delegatedGrants *delegatedgrant.Store, humanApprovals *humanapproval.Store, configSourceURL string) {
	mux.HandleFunc("GET /admin/agent-tools", adminEndpoint("admin.agent_tools.read", func(w http.ResponseWriter, r *http.Request) {
		options := agenttool.ListOptions{
			Status:     strings.TrimSpace(r.URL.Query().Get("status")),
			ActionType: strings.TrimSpace(r.URL.Query().Get("action_type")),
			Limit:      boundedIntQuery(r.URL.Query().Get("limit"), 100, 1, 1000),
		}
		result, err := agentToolStore.List(r.Context(), adminTenantIDFromRequest(r), options)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, result)
	}))
	mux.HandleFunc("GET /admin/agent-tools/{tool_id}", adminEndpoint("admin.agent_tools.read", func(w http.ResponseWriter, r *http.Request) {
		tool, found, err := agentToolStore.Get(r.Context(), adminTenantIDFromRequest(r), r.PathValue("tool_id"))
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if !found {
			writeError(w, http.StatusNotFound, fmt.Errorf("agent tool %s is absent", r.PathValue("tool_id")))
			return
		}
		writeJSON(w, http.StatusOK, tool)
	}))
	mux.HandleFunc("POST /admin/agent-tools", adminEndpoint("admin.agent_tools.write", func(w http.ResponseWriter, r *http.Request) {
		var tool agenttool.Tool
		if err := decodeLimitedJSONBody(w, r, &tool, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode agent tool: %w", err))
			return
		}
		now := time.Now()
		upserted, err := agentToolStore.Upsert(r.Context(), tool, adminTenantIDFromRequest(r), now)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox, adminAgentToolAuditLog(upserted, evaluator, now), now)
		writeJSON(w, http.StatusOK, upserted)
	}))
	mux.HandleFunc("GET /admin/tool-call-events", adminEndpoint("admin.tool_call_events.read", func(w http.ResponseWriter, r *http.Request) {
		options := toolcallaudit.ListOptions{
			ToolID:     strings.TrimSpace(r.URL.Query().Get("tool_id")),
			ActorNHIID: strings.TrimSpace(r.URL.Query().Get("actor_nhi_id")),
			Decision:   strings.TrimSpace(r.URL.Query().Get("decision")),
			Status:     strings.TrimSpace(r.URL.Query().Get("status")),
			Limit:      boundedIntQuery(r.URL.Query().Get("limit"), 100, 1, 1000),
		}
		result, err := toolCallEventAuditStore.List(r.Context(), adminTenantIDFromRequest(r), options)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, result)
	}))
	mux.HandleFunc("GET /admin/tool-call-events/{event_id}", adminEndpoint("admin.tool_call_events.read", func(w http.ResponseWriter, r *http.Request) {
		event, found, err := toolCallEventAuditStore.Get(r.Context(), adminTenantIDFromRequest(r), r.PathValue("event_id"))
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if !found {
			writeError(w, http.StatusNotFound, fmt.Errorf("tool call event %s is absent", r.PathValue("event_id")))
			return
		}
		writeJSON(w, http.StatusOK, event)
	}))
	mux.HandleFunc("POST /admin/tool-call-events", adminEndpoint("admin.tool_call_events.write", func(w http.ResponseWriter, r *http.Request) {
		var event model.ToolCallEvent
		if err := decodeLimitedJSONBody(w, r, &event, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode tool call event audit: %w", err))
			return
		}
		now := time.Now()
		upserted, err := toolCallEventAuditStore.Upsert(r.Context(), event, adminTenantIDFromRequest(r), now)
		if err != nil {
			writeError(w, statusForToolCallEventError(err), err)
			return
		}
		_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox, adminToolCallEventAuditLog(upserted, evaluator, now), now)
		writeJSON(w, http.StatusOK, upserted)
	}))
	mux.HandleFunc("GET /admin/delegated-grants", adminEndpoint("admin.delegated_grants.read", func(w http.ResponseWriter, r *http.Request) {
		options := adminDelegatedAccessGrantListOptions{
			Status:        strings.TrimSpace(r.URL.Query().Get("status")),
			ActorNHIID:    strings.TrimSpace(r.URL.Query().Get("actor_nhi_id")),
			SubjectUserID: strings.TrimSpace(r.URL.Query().Get("subject_user_id")),
			Limit:         boundedIntQuery(r.URL.Query().Get("limit"), 100, 1, 1000),
		}
		result, err := adminListDelegatedAccessGrant(delegatedGrants, r.Context(), adminTenantIDFromRequest(r), options)
		if err != nil {
			writeError(w, statusForDelegatedGrantError(err), err)
			return
		}
		writeJSON(w, http.StatusOK, result)
	}))
	mux.HandleFunc("GET /admin/delegated-grants/{grant_id}", adminEndpoint("admin.delegated_grants.read", func(w http.ResponseWriter, r *http.Request) {
		grant, found, err := adminGetDelegatedAccessGrant(delegatedGrants, r.Context(), adminTenantIDFromRequest(r), r.PathValue("grant_id"))
		if err != nil {
			writeError(w, statusForDelegatedGrantError(err), err)
			return
		}
		if !found {
			writeError(w, http.StatusNotFound, fmt.Errorf("delegated access grant %s is absent", r.PathValue("grant_id")))
			return
		}
		writeJSON(w, http.StatusOK, grant)
	}))
	mux.HandleFunc("POST /admin/delegated-grants", adminEndpoint("admin.delegated_grants.write", func(w http.ResponseWriter, r *http.Request) {
		if configWriteRejectedWhenSourced(w, configSourceURL, "delegated grants") {
			return
		}
		var grant adminDelegatedAccessGrant
		if err := decodeLimitedJSONBody(w, r, &grant, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode delegated access grant: %w", err))
			return
		}
		now := time.Now()
		upserted, err := adminUpsertDelegatedAccessGrant(delegatedGrants, r.Context(), grant, adminTenantIDFromRequest(r), now)
		if err != nil {
			writeError(w, statusForDelegatedGrantError(err), err)
			return
		}
		audit := adminDelegatedAccessGrantAuditLog("admin_delegated_access_grant_upserted", upserted, evaluator, now)
		audit.ActorUserID = auditActorPrincipal(r)
		_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox, audit, now)
		writeJSON(w, http.StatusOK, upserted)
	}))
	mux.HandleFunc("POST /admin/delegated-grants/{grant_id}/revoke", adminEndpoint("admin.delegated_grants.revoke", func(w http.ResponseWriter, r *http.Request) {
		if configWriteRejectedWhenSourced(w, configSourceURL, "delegated grants") {
			return
		}
		var request adminDelegatedAccessGrantRevokeRequest
		if err := decodeLimitedJSONBody(w, r, &request, maxEdgeRuntimeJSONBodyBytes); err != nil && err != io.EOF {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode delegated access grant revoke request: %w", err))
			return
		}
		now := time.Now()
		revoked, found, err := adminRevokeDelegatedAccessGrant(delegatedGrants, r.Context(), adminTenantIDFromRequest(r), r.PathValue("grant_id"), request, now)
		if err != nil {
			writeError(w, statusForDelegatedGrantError(err), err)
			return
		}
		if !found {
			writeError(w, http.StatusNotFound, fmt.Errorf("delegated access grant %s is absent", r.PathValue("grant_id")))
			return
		}
		audit := adminDelegatedAccessGrantAuditLog("admin_delegated_access_grant_revoked", revoked, evaluator, now)
		audit.ActorUserID = auditActorPrincipal(r)
		_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox, audit, now)
		writeJSON(w, http.StatusOK, revoked)
	}))
	mux.HandleFunc("GET /admin/human-approval-events", adminEndpoint("admin.approval.read", func(w http.ResponseWriter, r *http.Request) {
		options := adminHumanApprovalEventListOptions{
			ApprovalResult:         strings.TrimSpace(r.URL.Query().Get("approval_result")),
			ActorNHIID:             strings.TrimSpace(r.URL.Query().Get("actor_nhi_id")),
			SubjectUserID:          strings.TrimSpace(r.URL.Query().Get("subject_user_id")),
			DelegatedAccessGrantID: strings.TrimSpace(r.URL.Query().Get("delegated_access_grant_id")),
			Limit:                  boundedIntQuery(r.URL.Query().Get("limit"), 100, 1, 1000),
		}
		result, err := adminListHumanApprovalEvent(humanApprovals, r.Context(), adminTenantIDFromRequest(r), options)
		if err != nil {
			writeError(w, statusForHumanApprovalEventError(err), err)
			return
		}
		writeJSON(w, http.StatusOK, result)
	}))
	mux.HandleFunc("GET /admin/human-approval-events/{approval_id}", adminEndpoint("admin.approval.read", func(w http.ResponseWriter, r *http.Request) {
		approval, found, err := adminGetHumanApprovalEvent(humanApprovals, r.Context(), adminTenantIDFromRequest(r), r.PathValue("approval_id"))
		if err != nil {
			writeError(w, statusForHumanApprovalEventError(err), err)
			return
		}
		if !found {
			writeError(w, http.StatusNotFound, fmt.Errorf("human approval event %s is absent", r.PathValue("approval_id")))
			return
		}
		writeJSON(w, http.StatusOK, approval)
	}))
	mux.HandleFunc("POST /admin/human-approval-events", adminEndpoint("admin.approval.write", func(w http.ResponseWriter, r *http.Request) {
		var approval adminHumanApprovalEvent
		if err := decodeLimitedJSONBody(w, r, &approval, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode human approval event: %w", err))
			return
		}
		now := time.Now()
		upserted, err := adminUpsertHumanApprovalEvent(humanApprovals, r.Context(), approval, adminTenantIDFromRequest(r), now)
		if err != nil {
			writeError(w, statusForHumanApprovalEventError(err), err)
			return
		}
		_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox, adminHumanApprovalMutationAuditLog(r, "admin_human_approval_event_upserted", upserted, evaluator, now, false), now)
		writeJSON(w, http.StatusOK, upserted)
	}))
	mux.HandleFunc("POST /admin/human-approval-events/{approval_id}/revoke", adminEndpoint("admin.approval.write", func(w http.ResponseWriter, r *http.Request) {
		var request adminHumanApprovalEventRevokeRequest
		if err := decodeLimitedJSONBody(w, r, &request, maxEdgeRuntimeJSONBodyBytes); err != nil && err != io.EOF {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode human approval event revoke request: %w", err))
			return
		}
		now := time.Now()
		revoked, found, err := adminRevokeHumanApprovalEvent(humanApprovals, r.Context(), adminTenantIDFromRequest(r), r.PathValue("approval_id"), request, now)
		if err != nil {
			if found && errors.Is(err, humanapproval.ErrPersistence) {
				_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox, adminHumanApprovalMutationAuditLog(r, "admin_human_approval_event_revoked", revoked, evaluator, now, true), now)
				writeJSON(w, http.StatusInternalServerError, map[string]any{"status": "partial", "applied": true, "tenant_id": revoked.TenantID, "approval_id": revoked.ID, "persistence": "unconfirmed", "error": "Approval revoked on this server, but persistence is unconfirmed. Retry revocation before restarting."})
				return
			}
			writeError(w, statusForHumanApprovalEventError(err), err)
			return
		}
		if !found {
			writeError(w, http.StatusNotFound, fmt.Errorf("human approval event %s is absent", r.PathValue("approval_id")))
			return
		}
		_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox, adminHumanApprovalMutationAuditLog(r, "admin_human_approval_event_revoked", revoked, evaluator, now, false), now)
		writeJSON(w, http.StatusOK, revoked)
	}))
}

// Non-human-identity registry admin routes (list/risk/upsert), moved verbatim out of
// newServerWithConfig (Phase 2 route-registration split); same pillar as the routes above.
func registerNHIRegistryRoutes(mux *http.ServeMux, adminEndpoint func(string, http.HandlerFunc) http.HandlerFunc, evaluator decision.Evaluator, writer *logs.Writer, adminAuditOutbox adminAuditOutboxDeadReader, nonHumanIdentities nhi.RuntimeStore, configSourceURL string) {
	mux.HandleFunc("GET /admin/non-human-identities", adminEndpoint("admin.nhi.read", func(w http.ResponseWriter, r *http.Request) {
		result, err := nhi.List(r.Context(), nonHumanIdentities, adminTenantIDFromRequest(r), time.Now())
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("non-human identity registry is unavailable"))
			return
		}
		writeJSON(w, http.StatusOK, result)
	}))
	mux.HandleFunc("GET /admin/non-human-identities/risk", adminEndpoint("admin.nhi.read", func(w http.ResponseWriter, r *http.Request) {
		// /NHI risk report (owner_unset / long-lived / over-broad scope / unused).
		tenantID := adminTenantIDFromRequest(r)
		now := time.Now()
		list, err := nonHumanIdentities.List(r.Context(), tenantID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("non-human identity registry is unavailable"))
			return
		}
		writeJSON(w, http.StatusOK, nhi.BuildRiskReport(tenantID, list, now, now.UTC().Format(time.RFC3339)))
	}))
	mux.HandleFunc("POST /admin/non-human-identities", adminEndpoint("admin.nhi.write", func(w http.ResponseWriter, r *http.Request) {
		if configWriteRejectedWhenSourced(w, configSourceURL, "NHI registry") {
			return
		}
		var identity model.NonHumanIdentity
		if err := decodeLimitedJSONBody(w, r, &identity, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode non-human identity: %w", err))
			return
		}
		now := time.Now()
		created, err := nonHumanIdentities.Upsert(r.Context(), identity, adminTenantIDFromRequest(r), now)
		if err != nil {
			if errors.Is(err, nhi.ErrPersistence) {
				writeError(w, http.StatusInternalServerError, nhi.ErrPersistence)
				return
			}
			writeError(w, http.StatusBadRequest, err)
			return
		}
		_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox, nonHumanIdentityAuditLog(created, r, evaluator, now), now)
		writeJSON(w, http.StatusOK, created)
	}))
}
