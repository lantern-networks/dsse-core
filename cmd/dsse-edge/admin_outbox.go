package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	_ "net/http/pprof" // DIAGNOSTIC: registers /debug/pprof on http.DefaultServeMux; served only when -pprof-listen is set
	"net/url"
	"path"
	"path/filepath"
	"strings"
	"time"

	// The IANA timezone database, compiled in. The runtime image is FROM scratch, so there is no
	// /usr/share/zoneinfo and time.LoadLocation would fail for EVERY zone — including the ones an operator
	// just typed into the Console. Validation that passes on a developer's machine and rejects everything in
	// the container is worse than no validation, because it looks like the operator's mistake.
	_ "time/tzdata"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
)

type adminAuditOutboxReplayRequest struct {
	Reason string `json:"reason"`
}

const (
	adminAuditOutboxPendingStaleAfter     = 15 * time.Minute
	adminAuditOutboxPublishingStaleAfter  = 5 * time.Minute
	domainEventOutboxPendingStaleAfter    = 15 * time.Minute
	domainEventOutboxPublishingStaleAfter = 5 * time.Minute
)

type adminAuditOutboxHealth struct {
	TenantID   string                        `json:"tenant_id"`
	Status     string                        `json:"status"`
	Reasons    []string                      `json:"reasons"`
	CheckedAt  string                        `json:"checked_at"`
	Thresholds map[string]int                `json:"thresholds"`
	Stats      postgresAdminAuditOutboxStats `json:"stats"`
}

type domainEventOutboxHealth struct {
	TenantID   string                         `json:"tenant_id"`
	EventPlane string                         `json:"event_plane"`
	Status     string                         `json:"status"`
	Reasons    []string                       `json:"reasons"`
	CheckedAt  string                         `json:"checked_at"`
	Thresholds map[string]int                 `json:"thresholds"`
	Stats      postgresDomainEventOutboxStats `json:"stats"`
}

type domainEventOutboxObjectManifestListResponse struct {
	EventPlane string                                      `json:"event_plane,omitempty"`
	Prefix     string                                      `json:"prefix"`
	Limit      int                                         `json:"limit"`
	Returned   int                                         `json:"returned"`
	Rows       []domainEventOutboxObjectManifestListRecord `json:"rows"`
}

type domainEventOutboxObjectManifestListRecord struct {
	ManifestRef string `json:"manifest_ref"`
}

func adminAuditOutboxHealthFromStats(stats postgresAdminAuditOutboxStats, now time.Time) adminAuditOutboxHealth {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	health := adminAuditOutboxHealth{
		TenantID:  stats.TenantID,
		Status:    "ok",
		Reasons:   []string{},
		CheckedAt: now.UTC().Format(time.RFC3339),
		Thresholds: map[string]int{
			"pending_stale_seconds":    int(adminAuditOutboxPendingStaleAfter.Seconds()),
			"publishing_stale_seconds": int(adminAuditOutboxPublishingStaleAfter.Seconds()),
		},
		Stats: stats,
	}
	if stats.Dead > 0 {
		health.Reasons = append(health.Reasons, "dead_rows_present")
	}
	if stats.OldestPendingAt != nil && now.UTC().Sub(stats.OldestPendingAt.UTC()) > adminAuditOutboxPendingStaleAfter {
		health.Reasons = append(health.Reasons, "pending_backlog_stale")
	}
	if stats.OldestPublishingAt != nil && now.UTC().Sub(stats.OldestPublishingAt.UTC()) > adminAuditOutboxPublishingStaleAfter {
		health.Reasons = append(health.Reasons, "publishing_lock_stale")
	}
	if len(health.Reasons) > 0 {
		health.Status = "degraded"
	}
	return health
}

func domainEventOutboxHealthFromStats(stats postgresDomainEventOutboxStats, now time.Time) domainEventOutboxHealth {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	health := domainEventOutboxHealth{
		TenantID:   stats.TenantID,
		EventPlane: stats.EventPlane,
		Status:     "ok",
		Reasons:    []string{},
		CheckedAt:  now.UTC().Format(time.RFC3339),
		Thresholds: map[string]int{
			"pending_stale_seconds":    int(domainEventOutboxPendingStaleAfter.Seconds()),
			"publishing_stale_seconds": int(domainEventOutboxPublishingStaleAfter.Seconds()),
		},
		Stats: stats,
	}
	if stats.Dead > 0 {
		health.Reasons = append(health.Reasons, "dead_rows_present")
	}
	if stats.OldestPendingAt != nil && now.UTC().Sub(stats.OldestPendingAt.UTC()) > domainEventOutboxPendingStaleAfter {
		health.Reasons = append(health.Reasons, "pending_backlog_stale")
	}
	if stats.OldestPublishingAt != nil && now.UTC().Sub(stats.OldestPublishingAt.UTC()) > domainEventOutboxPublishingStaleAfter {
		health.Reasons = append(health.Reasons, "publishing_lock_stale")
	}
	if len(health.Reasons) > 0 {
		health.Status = "degraded"
	}
	return health
}

func appendAuthenticationDomainEvent(ctx context.Context, domainEventOutbox domainEventOutboxWriter, event model.AuthenticationEvent, now time.Time) {
	if envelope, err := domainEventOutboxEnvelopeFromAuthenticationEvent(event, now); err != nil {
		log.Printf("domain event outbox authentication envelope: %v", err)
	} else {
		appendDomainEventOutbox(ctx, domainEventOutbox, envelope, now)
	}
}

func appendDelegatedGrantDomainEvent(ctx context.Context, domainEventOutbox domainEventOutboxWriter, grant model.DelegatedAccessGrant, eventType, occurredAtValue string, now time.Time) {
	if envelope, err := domainEventOutboxEnvelopeFromDelegatedAccessGrant(grant, eventType, occurredAtValue, now); err != nil {
		log.Printf("domain event outbox delegated grant envelope: %v", err)
	} else {
		appendDomainEventOutbox(ctx, domainEventOutbox, envelope, now)
	}
}

func appendDeviceDomainEvent(ctx context.Context, domainEventOutbox domainEventOutboxWriter, dev model.Device, eventType, occurredAtValue string, now time.Time) {
	if envelope, err := domainEventOutboxEnvelopeFromDevice(dev, eventType, occurredAtValue, now); err != nil {
		log.Printf("domain event outbox device envelope: %v", err)
	} else {
		appendDomainEventOutbox(ctx, domainEventOutbox, envelope, now)
	}
}

func appendAgentUpdateDomainEvent(ctx context.Context, domainEventOutbox domainEventOutboxWriter, event model.AgentUpdateEvent, now time.Time) {
	if err := appendAgentUpdateDomainEventErr(ctx, domainEventOutbox, event, now); err != nil {
		log.Printf("domain event outbox agent update: %v", err)
	}
}

// appendAgentUpdateDomainEventErr is the same write, with the failure REPORTED rather than logged.
//
// ★ THE DEVICE DELETES ITS ONLY COPY ON A 202 (2026-08-12, eighth review). The handler acknowledged an update
// outcome and then wrote the downstream event best-effort — so an outbox failure meant the event existed
// nowhere: not on the device, which had dropped it, and not downstream. An acknowledgement is a promise that
// everything the caller relies on has been written, and the caller here is an endpoint that acts on it.
func appendAgentUpdateDomainEventErr(ctx context.Context, domainEventOutbox domainEventOutboxWriter,
	event model.AgentUpdateEvent, now time.Time) error {
	envelope, err := domainEventOutboxEnvelopeFromAgentUpdateEvent(event, now)
	if err != nil {
		return fmt.Errorf("build the agent-update domain event: %w", err)
	}
	if domainEventOutbox == nil {
		// No outbox configured is not a failure: there is nothing downstream to miss it.
		return nil
	}
	if ierr := domainEventOutbox.InsertEvent(ctx, envelope, now); ierr != nil {
		return fmt.Errorf("insert the agent-update domain event: %w", ierr)
	}
	return nil
}

func domainEventOutboxPlaneFromRequest(r *http.Request) (string, error) {
	eventPlane := strings.TrimSpace(r.URL.Query().Get("event_plane"))
	if eventPlane == "" {
		eventPlane = "domain"
	}
	if !domainEventOutboxPlaneAllowed(eventPlane) {
		return "", fmt.Errorf("domain event outbox event_plane is invalid: %s", eventPlane)
	}
	return eventPlane, nil
}

func domainEventOutboxManifestRefFromRequest(r *http.Request, tenantID string) (string, error) {
	manifestRef := strings.TrimSpace(r.URL.Query().Get("manifest_ref"))
	if manifestRef == "" {
		return "", fmt.Errorf("manifest_ref is required")
	}
	if !strings.HasPrefix(manifestRef, "domain-events/") || !strings.HasSuffix(manifestRef, ".manifest.ndjson.gz") {
		return "", fmt.Errorf("manifest_ref must point to a domain event object manifest")
	}
	if tenantPrefix := domainEventOutboxTenantObjectPrefix(tenantID); !strings.HasPrefix(manifestRef, tenantPrefix) {
		return "", fmt.Errorf("manifest_ref must be scoped to the authenticated tenant")
	}
	// An object-store ref is a slash-separated key, not a filesystem path, so it is checked with path/* and not
	// filepath/*. The distinction is invisible on Linux and wrong twice on Windows: filepath.Clean rewrites the
	// separators, so every legitimate ref failed the "is it already clean" test, and filepath.IsAbs is false for
	// "/etc/passwd" there because it wants a drive letter — a traversal guard should not depend on the host OS.
	if path.IsAbs(manifestRef) || strings.Contains(manifestRef, "\\") {
		return "", fmt.Errorf("manifest_ref must be a relative object path")
	}
	clean := path.Clean(manifestRef)
	if clean != manifestRef || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("manifest_ref must be a clean relative object path")
	}
	return manifestRef, nil
}

func domainEventOutboxManifestList(store adminExportObjectStore, tenantID string, query url.Values) (domainEventOutboxObjectManifestListResponse, error) {
	eventPlane := strings.TrimSpace(query.Get("event_plane"))
	if eventPlane != "" && !domainEventOutboxPlaneAllowed(eventPlane) {
		return domainEventOutboxObjectManifestListResponse{}, fmt.Errorf("domain event outbox event_plane is invalid: %s", eventPlane)
	}
	prefix, err := domainEventOutboxManifestListPrefix(query.Get("prefix"), tenantID, eventPlane)
	if err != nil {
		return domainEventOutboxObjectManifestListResponse{}, err
	}
	limit := boundedIntQuery(query.Get("limit"), 50, 1, 200)
	files, err := store.ListGeneratedFiles(prefix, ".manifest.ndjson.gz", limit)
	if err != nil {
		return domainEventOutboxObjectManifestListResponse{}, err
	}
	rows := make([]domainEventOutboxObjectManifestListRecord, 0, len(files))
	for _, file := range files {
		rows = append(rows, domainEventOutboxObjectManifestListRecord{ManifestRef: file})
	}
	return domainEventOutboxObjectManifestListResponse{
		EventPlane: eventPlane,
		Prefix:     prefix,
		Limit:      limit,
		Returned:   len(rows),
		Rows:       rows,
	}, nil
}

func domainEventOutboxManifestListPrefix(raw, tenantID, eventPlane string) (string, error) {
	tenantPrefix := domainEventOutboxTenantObjectPrefix(tenantID)
	prefix := strings.TrimSpace(raw)
	if prefix == "" {
		if eventPlane != "" {
			return tenantPrefix + safeDomainEventOutboxObjectSegment(eventPlane) + "/", nil
		}
		return tenantPrefix, nil
	}
	if filepath.IsAbs(prefix) || strings.Contains(prefix, "\\") {
		return "", fmt.Errorf("prefix must be a relative domain event object path")
	}
	trimmed := strings.TrimSuffix(prefix, "/")
	clean := filepath.Clean(trimmed)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) || clean != trimmed {
		return "", fmt.Errorf("prefix must be a clean relative domain event object path")
	}
	if clean != "domain-events" && !strings.HasPrefix(clean, "domain-events/") {
		return "", fmt.Errorf("prefix must point under domain-events/")
	}
	clean = filepath.ToSlash(clean)
	if strings.HasSuffix(prefix, "/") || clean == "domain-events" {
		clean += "/"
	}
	if clean == strings.TrimSuffix(tenantPrefix, "/") {
		clean = tenantPrefix
	}
	if !strings.HasPrefix(clean, tenantPrefix) {
		return "", fmt.Errorf("prefix must be scoped to the authenticated tenant")
	}
	return clean, nil
}

func domainEventOutboxTenantObjectPrefix(tenantID string) string {
	return "domain-events/" + safeDomainEventOutboxObjectSegment(tenantID) + "/"
}

func adminAuditOutboxReplayAuditLog(result postgresAdminAuditOutboxReplayResult, evaluator decision.Evaluator, adminPrincipalID, sourceIP, userAgent, reason string) model.AuditLog {
	action := "audit_outbox_replay"
	auditResult := "success"
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = "admin_replay"
	}
	audit := model.AuditLog{
		ID:            randomEdgeID("audit_admin_audit_outbox_replayed_", time.Now().UTC()),
		TenantID:      evaluator.PolicyBundle.TenantID,
		ActorUserID:   stringPtr(adminPrincipalID),
		EventType:     "admin_audit_outbox_replayed",
		TargetType:    stringPtr("admin_audit_outbox"),
		TargetID:      stringPtr(result.OutboxID),
		Action:        &action,
		Result:        &auditResult,
		EdgeRegionID:  &evaluator.EdgeRegionID,
		EdgeClusterID: &evaluator.EdgeClusterID,
		SourceIP:      stringPtr(sourceIP),
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
		Metadata: map[string]any{
			"outbox_id":                result.OutboxID,
			"status":                   result.Status,
			"publish_attempt":          result.PublishAttempt,
			"updated_at":               result.UpdatedAt.UTC().Format(time.RFC3339),
			"previous_publish_attempt": result.PreviousPublishAttempt,
			"previous_last_error":      result.PreviousLastError,
			"reason":                   reason,
			"user_agent":               userAgent,
		},
	}
	if result.PreviousDeadAt != nil {
		audit.Metadata["previous_dead_at"] = result.PreviousDeadAt.UTC().Format(time.RFC3339)
	}
	return audit
}

func domainEventOutboxReplayAuditLog(result postgresDomainEventOutboxReplayResult, evaluator decision.Evaluator, adminPrincipalID, sourceIP, userAgent, reason string) model.AuditLog {
	action := "domain_event_outbox_replay"
	auditResult := "success"
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = "admin_replay"
	}
	audit := model.AuditLog{
		ID:            randomEdgeID("audit_domain_event_outbox_replayed_", time.Now().UTC()),
		TenantID:      evaluator.PolicyBundle.TenantID,
		ActorUserID:   stringPtr(adminPrincipalID),
		EventType:     "admin_domain_event_outbox_replayed",
		TargetType:    stringPtr("domain_event_outbox"),
		TargetID:      stringPtr(result.OutboxID),
		Action:        &action,
		Result:        &auditResult,
		EdgeRegionID:  &evaluator.EdgeRegionID,
		EdgeClusterID: &evaluator.EdgeClusterID,
		SourceIP:      stringPtr(sourceIP),
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
		Metadata: map[string]any{
			"outbox_id":                result.OutboxID,
			"event_plane":              result.EventPlane,
			"status":                   result.Status,
			"publish_attempt":          result.PublishAttempt,
			"updated_at":               result.UpdatedAt.UTC().Format(time.RFC3339),
			"previous_publish_attempt": result.PreviousPublishAttempt,
			"previous_last_error":      result.PreviousLastError,
			"reason":                   reason,
			"user_agent":               userAgent,
		},
	}
	if result.PreviousDeadAt != nil {
		audit.Metadata["previous_dead_at"] = result.PreviousDeadAt.UTC().Format(time.RFC3339)
	}
	return audit
}

// Hot-store health plus the embedded outbox admin surface (off by default in the
// production binary; see -embedded-outbox-admin). // Moved verbatim out of newServerWithConfig (Phase 2 route-registration split,
func registerOutboxAdminRoutes(mux *http.ServeMux, adminEndpoint func(string, http.HandlerFunc) http.HandlerFunc, config serverConfig, evaluator decision.Evaluator, writer *logs.Writer, adminAuditOutbox adminAuditOutboxDeadReader, domainEventOutbox domainEventOutboxWriter, domainEventMirror *domainEventOutboxMirrorMonitor, hotStoreMirror *hotStoreAppendMirrorMonitor, exportObjectStore adminExportObjectStore) {
	mux.HandleFunc("GET /admin/hot-store/health", adminEndpoint("admin.logs.read", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, hotStoreMirror.Health(time.Now()))
	}))
	// Audit/persistence decoupling (docs/edge_audit_persistence_decoupling_design.md): the durable outbox
	// delivery + management belongs to the separate audit/control plane, not the data-plane Edge. These
	// endpoints are OFF by default in the production binary (see -embedded-outbox-admin); kept registered for
	// callers/tests that pass the default serverConfig (DisableEmbeddedOutboxAdmin=false).
	if !config.DisableEmbeddedOutboxAdmin {
		mux.HandleFunc("GET /admin/audit-outbox/dead", adminEndpoint("admin.audit.delivery.read", func(w http.ResponseWriter, r *http.Request) {
			if adminAuditOutbox == nil {
				writeError(w, http.StatusNotImplemented, fmt.Errorf("admin audit outbox dead row reader is not configured"))
				return
			}
			limit := boundedIntQuery(r.URL.Query().Get("limit"), 25, 1, 1000)
			rows, err := adminAuditOutbox.ListDead(r.Context(), adminTenantIDFromRequest(r), limit)
			if err != nil {
				writeError(w, http.StatusInternalServerError, err)
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"limit":    limit,
				"returned": len(rows),
				"rows":     rows,
			})
		}))
		mux.HandleFunc("GET /admin/audit-outbox/stats", adminEndpoint("admin.audit.delivery.read", func(w http.ResponseWriter, r *http.Request) {
			statsReader, ok := adminAuditOutbox.(adminAuditOutboxStatsReader)
			if !ok {
				writeError(w, http.StatusNotImplemented, fmt.Errorf("admin audit outbox stats reader is not configured"))
				return
			}
			stats, err := statsReader.Stats(r.Context(), adminTenantIDFromRequest(r))
			if err != nil {
				writeError(w, http.StatusInternalServerError, err)
				return
			}
			writeJSON(w, http.StatusOK, stats)
		}))
		mux.HandleFunc("GET /admin/audit-outbox/health", adminEndpoint("admin.audit.delivery.read", func(w http.ResponseWriter, r *http.Request) {
			statsReader, ok := adminAuditOutbox.(adminAuditOutboxStatsReader)
			if !ok {
				writeError(w, http.StatusNotImplemented, fmt.Errorf("admin audit outbox health reader is not configured"))
				return
			}
			stats, err := statsReader.Stats(r.Context(), adminTenantIDFromRequest(r))
			if err != nil {
				writeError(w, http.StatusInternalServerError, err)
				return
			}
			writeJSON(w, http.StatusOK, adminAuditOutboxHealthFromStats(stats, time.Now()))
		}))
		mux.HandleFunc("GET /admin/audit-outbox/dead/{outbox_id}", adminEndpoint("admin.audit.delivery.read", func(w http.ResponseWriter, r *http.Request) {
			getter, ok := adminAuditOutbox.(adminAuditOutboxDeadGetter)
			if !ok {
				writeError(w, http.StatusNotImplemented, fmt.Errorf("admin audit outbox dead row getter is not configured"))
				return
			}
			row, found, err := getter.GetDead(r.Context(), adminTenantIDFromRequest(r), r.PathValue("outbox_id"))
			if err != nil {
				writeError(w, http.StatusInternalServerError, err)
				return
			}
			if !found {
				writeError(w, http.StatusNotFound, fmt.Errorf("dead audit outbox row %s is absent", r.PathValue("outbox_id")))
				return
			}
			writeJSON(w, http.StatusOK, row)
		}))
		mux.HandleFunc("POST /admin/audit-outbox/dead/{outbox_id}/replay", adminEndpoint("admin.audit.delivery.replay", func(w http.ResponseWriter, r *http.Request) {
			var req adminAuditOutboxReplayRequest
			if err := decodeLimitedJSONBody(w, r, &req, maxEdgeRuntimeJSONBodyBytes); err != nil && !errors.Is(err, io.EOF) {
				writeError(w, http.StatusBadRequest, fmt.Errorf("decode audit outbox replay request: %w", err))
				return
			}
			replayer, ok := adminAuditOutbox.(adminAuditOutboxDeadReplayer)
			if !ok {
				writeError(w, http.StatusNotImplemented, fmt.Errorf("admin audit outbox replay is not configured"))
				return
			}
			result, found, err := replayer.ReplayDead(r.Context(), adminTenantIDFromRequest(r), r.PathValue("outbox_id"), time.Now())
			if err != nil {
				writeError(w, http.StatusInternalServerError, err)
				return
			}
			if !found {
				writeError(w, http.StatusNotFound, fmt.Errorf("dead audit outbox row %s is absent", r.PathValue("outbox_id")))
				return
			}
			_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox, adminAuditOutboxReplayAuditLog(result, evaluator, adminPrincipalIDFromRequest(r), sourceIPFromRequest(r), r.UserAgent(), req.Reason), time.Now())
			writeJSON(w, http.StatusOK, result)
		}))
		mux.HandleFunc("GET /admin/domain-event-outbox/dead", adminEndpoint("admin.domain_events.delivery.read", func(w http.ResponseWriter, r *http.Request) {
			reader, ok := domainEventOutbox.(domainEventOutboxDeadReader)
			if !ok {
				writeError(w, http.StatusNotImplemented, fmt.Errorf("domain event outbox dead row reader is not configured"))
				return
			}
			eventPlane, err := domainEventOutboxPlaneFromRequest(r)
			if err != nil {
				writeError(w, http.StatusBadRequest, err)
				return
			}
			limit := boundedIntQuery(r.URL.Query().Get("limit"), 25, 1, 1000)
			rows, err := reader.ListDead(r.Context(), adminTenantIDFromRequest(r), eventPlane, limit)
			if err != nil {
				writeError(w, http.StatusInternalServerError, err)
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"event_plane": eventPlane,
				"limit":       limit,
				"returned":    len(rows),
				"rows":        rows,
			})
		}))
		mux.HandleFunc("GET /admin/domain-event-outbox/stats", adminEndpoint("admin.domain_events.delivery.read", func(w http.ResponseWriter, r *http.Request) {
			statsReader, ok := domainEventOutbox.(domainEventOutboxStatsReader)
			if !ok {
				writeError(w, http.StatusNotImplemented, fmt.Errorf("domain event outbox stats reader is not configured"))
				return
			}
			eventPlane, err := domainEventOutboxPlaneFromRequest(r)
			if err != nil {
				writeError(w, http.StatusBadRequest, err)
				return
			}
			stats, err := statsReader.Stats(r.Context(), adminTenantIDFromRequest(r), eventPlane)
			if err != nil {
				writeError(w, http.StatusInternalServerError, err)
				return
			}
			writeJSON(w, http.StatusOK, stats)
		}))
		mux.HandleFunc("GET /admin/domain-event-outbox/health", adminEndpoint("admin.domain_events.delivery.read", func(w http.ResponseWriter, r *http.Request) {
			statsReader, ok := domainEventOutbox.(domainEventOutboxStatsReader)
			if !ok {
				writeError(w, http.StatusNotImplemented, fmt.Errorf("domain event outbox health reader is not configured"))
				return
			}
			eventPlane, err := domainEventOutboxPlaneFromRequest(r)
			if err != nil {
				writeError(w, http.StatusBadRequest, err)
				return
			}
			stats, err := statsReader.Stats(r.Context(), adminTenantIDFromRequest(r), eventPlane)
			if err != nil {
				writeError(w, http.StatusInternalServerError, err)
				return
			}
			writeJSON(w, http.StatusOK, domainEventOutboxHealthFromStats(stats, time.Now()))
		}))
		mux.HandleFunc("GET /admin/domain-event-outbox/mirror-health", adminEndpoint("admin.domain_events.delivery.read", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, domainEventMirror.Health(time.Now()))
		}))
		mux.HandleFunc("GET /admin/domain-event-outbox/object-manifests", adminEndpoint("admin.domain_events.delivery.read", func(w http.ResponseWriter, r *http.Request) {
			if exportObjectStore == nil {
				writeError(w, http.StatusNotImplemented, fmt.Errorf("domain event object store is not configured"))
				return
			}
			result, err := domainEventOutboxManifestList(exportObjectStore, adminTenantIDFromRequest(r), r.URL.Query())
			if err != nil {
				writeError(w, http.StatusBadRequest, err)
				return
			}
			writeJSON(w, http.StatusOK, result)
		}))
		mux.HandleFunc("GET /admin/domain-event-outbox/object-manifests/verify", adminEndpoint("admin.domain_events.delivery.read", func(w http.ResponseWriter, r *http.Request) {
			if exportObjectStore == nil {
				writeError(w, http.StatusNotImplemented, fmt.Errorf("domain event object store is not configured"))
				return
			}
			manifestRef, err := domainEventOutboxManifestRefFromRequest(r, adminTenantIDFromRequest(r))
			if err != nil {
				writeError(w, http.StatusBadRequest, err)
				return
			}
			result, err := verifyDomainEventOutboxObjectManifest(exportObjectStore, manifestRef)
			if err != nil {
				status, responseErr := domainEventOutboxObjectVerificationHTTPError(err)
				log.Printf("domain event object manifest verification failed for %q status=%d: %v", manifestRef, status, err)
				writeError(w, status, responseErr)
				return
			}
			writeJSON(w, http.StatusOK, result)
		}))
		mux.HandleFunc("POST /admin/domain-event-outbox/dead/{outbox_id}/replay", adminEndpoint("admin.domain_events.delivery.replay", func(w http.ResponseWriter, r *http.Request) {
			var req adminAuditOutboxReplayRequest
			if err := decodeLimitedJSONBody(w, r, &req, maxEdgeRuntimeJSONBodyBytes); err != nil && !errors.Is(err, io.EOF) {
				writeError(w, http.StatusBadRequest, fmt.Errorf("decode domain event outbox replay request: %w", err))
				return
			}
			replayer, ok := domainEventOutbox.(domainEventOutboxDeadReplayer)
			if !ok {
				writeError(w, http.StatusNotImplemented, fmt.Errorf("domain event outbox replay is not configured"))
				return
			}
			eventPlane, err := domainEventOutboxPlaneFromRequest(r)
			if err != nil {
				writeError(w, http.StatusBadRequest, err)
				return
			}
			result, found, err := replayer.ReplayDead(r.Context(), adminTenantIDFromRequest(r), eventPlane, r.PathValue("outbox_id"), time.Now())
			if err != nil {
				writeError(w, http.StatusInternalServerError, err)
				return
			}
			if !found {
				writeError(w, http.StatusNotFound, fmt.Errorf("dead domain event outbox row %s is absent", r.PathValue("outbox_id")))
				return
			}
			_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox, domainEventOutboxReplayAuditLog(result, evaluator, adminPrincipalIDFromRequest(r), sourceIPFromRequest(r), r.UserAgent(), req.Reason), time.Now())
			writeJSON(w, http.StatusOK, result)
		}))
	} // end embedded outbox admin endpoints (audit/persistence decoupling)
}
