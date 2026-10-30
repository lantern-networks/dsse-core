package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
)

func manualHotLogDeleteDeploymentHistoryAllowed(r *http.Request) bool {
	identity, authenticated := adminIdentityFromRequest(r)
	return authenticated && adminIdentityMayActAcrossOrganizations(identity) && adminAnsweringForTheDeployment(r)
}

func registerManualHotLogDeleteRoutes(mux *http.ServeMux, adminEndpoint func(string, http.HandlerFunc) http.HandlerFunc, manager *manualHotLogDeleteManager, evaluator decision.Evaluator, writer *logs.Writer, auditOutbox adminAuditOutboxDeadReader) {
	read := func(w http.ResponseWriter, r *http.Request) (manualHotLogDeleteJob, bool) {
		if manager == nil {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("shared manual hot-log deletion is unavailable"))
			return manualHotLogDeleteJob{}, false
		}
		id := strings.TrimSpace(r.PathValue("job_id"))
		if id == "" || len(id) > 100 {
			writeError(w, http.StatusBadRequest, fmt.Errorf("invalid job ID"))
			return manualHotLogDeleteJob{}, false
		}
		job, err := manager.get(r.Context(), id)
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, fmt.Errorf("job not found"))
			return job, false
		}
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("job is unavailable"))
			return job, false
		}
		if job.Tenant != adminTenantIDFromRequest(r) {
			writeError(w, http.StatusNotFound, fmt.Errorf("job not found"))
			return job, false
		}
		return job, true
	}
	mux.HandleFunc("POST /admin/manual-hot-log-delete/preview", adminEndpoint("admin.retention.write", func(w http.ResponseWriter, r *http.Request) {
		if manager == nil {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("shared manual hot-log deletion is unavailable"))
			return
		}
		var req struct {
			Tenant string `json:"tenant_id"`
			Stream string `json:"stream"`
			Before string `json:"before"`
		}
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("invalid preview request"))
			return
		}
		var extra any
		if dec.Decode(&extra) != io.EOF {
			writeError(w, http.StatusBadRequest, fmt.Errorf("invalid preview request"))
			return
		}
		tenant := adminTenantIDFromRequest(r)
		if req.Tenant == "" || req.Tenant != tenant || tenant == agentUpdateCatalogueScope {
			writeError(w, http.StatusForbidden, fmt.Errorf("explicit effective tenant is required"))
			return
		}
		before, err := time.Parse(time.RFC3339Nano, req.Before)
		if err != nil || !strings.HasSuffix(req.Before, "Z") {
			writeError(w, http.StatusBadRequest, fmt.Errorf("before must be an explicit UTC RFC3339 timestamp"))
			return
		}
		job, err := manager.preview(r.Context(), tenant, req.Stream, before, adminPrincipalIDFromRequest(r))
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("manual deletion preview failed; no rows deleted"))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"job": job, "warning": "This permanently removes only the previewed hot rows. Rows not yet archived to S3 will be lost; archived objects and Object Lock remain unchanged."})
	}))
	mux.HandleFunc("GET /admin/manual-hot-log-delete", adminEndpoint("admin.retention.read", func(w http.ResponseWriter, r *http.Request) {
		if manager == nil {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("shared manual hot-log deletion is unavailable"))
			return
		}
		tenant := adminTenantIDFromRequest(r)
		if tenant == "" || tenant == agentUpdateCatalogueScope {
			writeError(w, http.StatusForbidden, fmt.Errorf("effective tenant is required"))
			return
		}
		jobs, err := manager.list(r.Context(), tenant)
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("deletion history is unavailable"))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"jobs": jobs})
	}))
	mux.HandleFunc("GET /admin/manual-hot-log-delete/all", adminEndpoint("admin.tenant.admin", func(w http.ResponseWriter, r *http.Request) {
		if manager == nil {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("shared manual hot-log deletion is unavailable"))
			return
		}
		if !manualHotLogDeleteDeploymentHistoryAllowed(r) {
			writeError(w, http.StatusForbidden, fmt.Errorf("deployment-wide deletion history is operator-only"))
			return
		}
		jobs, err := manager.list(r.Context(), "")
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("deletion history is unavailable"))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"jobs": jobs})
	}))
	mux.HandleFunc("GET /admin/manual-hot-log-delete/{job_id}", adminEndpoint("admin.retention.read", func(w http.ResponseWriter, r *http.Request) {
		job, ok := read(w, r)
		if !ok {
			return
		}
		writeJSON(w, http.StatusOK, job)
	}))
	mux.HandleFunc("POST /admin/manual-hot-log-delete/{job_id}/confirm", adminEndpoint("admin.retention.write", func(w http.ResponseWriter, r *http.Request) {
		job, ok := read(w, r)
		if !ok {
			return
		}
		var req struct {
			PreviewDigest string `json:"preview_digest"`
			Confirm       bool   `json:"confirm"`
		}
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("invalid confirmation"))
			return
		}
		var extra any
		if dec.Decode(&extra) != io.EOF || !req.Confirm {
			writeError(w, http.StatusBadRequest, fmt.Errorf("explicit confirmation is required"))
			return
		}
		now := time.Now().UTC()
		if req.PreviewDigest != job.PreviewDigest || job.Status != "preview_ready" && job.Status != "failed" {
			writeError(w, http.StatusConflict, fmt.Errorf("job confirmation changed"))
			return
		}
		// The audit must be durable before any irreversible job can be queued.
		// It records the request, since the subsequent scope/hold check may refuse it.
		action, result, target := "manual_hot_log_delete_confirm_requested", "requested", "manual_hot_log_delete_job"
		audit := model.AuditLog{ID: randomEdgeID("audit_manual_hot_delete_", now), TenantID: job.Tenant, ActorUserID: stringPtr(adminPrincipalIDFromRequest(r)), EventType: "manual_hot_log_delete_confirm_requested", TargetType: &target, TargetID: &job.ID, Action: &action, Result: &result, EdgeRegionID: &evaluator.EdgeRegionID, EdgeClusterID: &evaluator.EdgeClusterID, SourceIP: stringPtr(sourceIPFromRequest(r)), Timestamp: now.Format(time.RFC3339), Metadata: map[string]any{"stream": job.Stream, "before": job.Cutoff.Format(time.RFC3339Nano), "preview_count": job.PreviewCount, "job_id": job.ID, "hot_only": true, "s3_untouched": true}}
		if err := appendAdminAudit(r.Context(), writer, auditOutbox, audit, now); err != nil {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("audit unavailable; deletion was not queued"))
			return
		}
		updated, err := manager.confirm(r.Context(), job.ID, job.Tenant, req.PreviewDigest)
		if err != nil {
			writeError(w, http.StatusConflict, fmt.Errorf("job scope, legal hold, store identity, or confirmation changed"))
			return
		}
		writeJSON(w, http.StatusAccepted, updated)
	}))
	mux.HandleFunc("POST /admin/manual-hot-log-delete/{job_id}/cancel", adminEndpoint("admin.tenant.admin", func(w http.ResponseWriter, r *http.Request) {
		if manager == nil || manager.hotCH == nil || !manualHotLogDeleteDeploymentHistoryAllowed(r) {
			writeError(w, http.StatusForbidden, fmt.Errorf("deployment operator is required"))
			return
		}
		id := strings.TrimSpace(r.PathValue("job_id"))
		if id == "" || len(id) > 100 {
			writeError(w, http.StatusBadRequest, fmt.Errorf("invalid job ID"))
			return
		}
		job, err := manager.get(r.Context(), id)
		if err != nil || job.Status != "running" {
			writeError(w, http.StatusConflict, fmt.Errorf("running job not found"))
			return
		}
		var req struct {
			Confirm bool   `json:"confirm"`
			Reason  string `json:"reason"`
		}
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
		dec.DisallowUnknownFields()
		if dec.Decode(&req) != nil || strings.TrimSpace(req.Reason) == "" || len(req.Reason) > 500 || !req.Confirm {
			writeError(w, http.StatusBadRequest, fmt.Errorf("explicit reason and confirmation are required"))
			return
		}
		var extra any
		if dec.Decode(&extra) != io.EOF {
			writeError(w, http.StatusBadRequest, fmt.Errorf("invalid cancellation request"))
			return
		}
		now := time.Now().UTC()
		action, result, target := "manual_hot_log_delete_cancel_requested", "requested", "manual_hot_log_delete_job"
		audit := model.AuditLog{ID: randomEdgeID("audit_manual_hot_cancel_", now), TenantID: job.Tenant, ActorUserID: stringPtr(adminPrincipalIDFromRequest(r)), EventType: action, TargetType: &target, TargetID: &job.ID, Action: &action, Result: &result, EdgeRegionID: &evaluator.EdgeRegionID, EdgeClusterID: &evaluator.EdgeClusterID, SourceIP: stringPtr(sourceIPFromRequest(r)), Timestamp: now.Format(time.RFC3339), Metadata: map[string]any{"reason": strings.TrimSpace(req.Reason), "job_id": job.ID}}
		if err := appendAdminAudit(r.Context(), writer, auditOutbox, audit, now); err != nil {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("audit unavailable; cancellation was not sent"))
			return
		}
		updated, err := manager.cancel(r.Context(), id)
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("mutation cancellation is unconfirmed; job remains fenced"))
			return
		}
		writeJSON(w, http.StatusAccepted, updated)
	}))
}
