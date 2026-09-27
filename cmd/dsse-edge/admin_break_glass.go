package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
)

const (
	breakGlassAuthMethod    = "break_glass"
	breakGlassIDPID         = "break_glass_admin_console"
	breakGlassSessionPrefix = "sess_bg_"
	breakGlassACR           = "urn:break-glass:admin"
)

type breakGlassSessionRequest struct {
	TenantID        string `json:"tenant_id"`
	UserID          string `json:"user_id"`
	SubjectUserID   string `json:"subject_user_id"`
	DeviceID        string `json:"device_id"`
	Reason          string `json:"reason"`
	TicketID        string `json:"ticket_id"`
	DurationSeconds int    `json:"duration_seconds"`
}

type breakGlassAccessRequest struct {
	ID              string `json:"id"`
	TenantID        string `json:"tenant_id"`
	UserID          string `json:"user_id"`
	SubjectUserID   string `json:"subject_user_id"`
	DeviceID        string `json:"device_id"`
	Reason          string `json:"reason"`
	TicketID        string `json:"ticket_id"`
	DurationSeconds int    `json:"duration_seconds"`
	RequestedBy     string `json:"requested_by"`
	ApproverUserID  string `json:"approver_user_id"`
	ApprovalReason  string `json:"approval_reason"`
	SessionID       string `json:"session_id"`
	Status          string `json:"status"`
	CreatedAt       string `json:"created_at"`
	ApprovedAt      string `json:"approved_at"`
	IssuedAt        string `json:"issued_at"`
}

type breakGlassApprovalRequest struct {
	ApproverUserID string `json:"approver_user_id"`
	Reason         string `json:"reason"`
}

type breakGlassRequestStore struct {
	mu             sync.RWMutex
	requests       map[string]breakGlassAccessRequest
	persister      blobstore.Persister
	authorityKnown bool
}

// SetStatePath enables durable file persistence (historical behaviour); a back-compat convenience over
// SetPersister(blobstore.FilePersister{...}).
func (s *breakGlassRequestStore) SetStatePath(path string) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return s.SetPersister(nil)
	}
	return s.SetPersister(blobstore.FilePersister{Path: path})
}

// SetPersister enables durable persistence via any Persister (file or shared Postgres): a pending/approved
// emergency-access request survives a CP restart — and, on a shared persister, a CP failover.
func (s *breakGlassRequestStore) SetPersister(p blobstore.Persister) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p == nil {
		s.persister = nil
		return nil
	}
	data, err := p.Load()
	if err != nil {
		return err
	}
	if data == nil {
		if s.authorityKnown {
			return fmt.Errorf("break-glass authority disappeared")
		}
		s.persister = p
		return nil
	}
	next, err := decodeBreakGlassRequests(data)
	if err != nil {
		return err
	}
	s.persister, s.requests, s.authorityKnown = p, next, true
	return nil
}

var errBreakGlassPersistence = errors.New("break-glass persistence could not be confirmed")
var errBreakGlassAbsent = errors.New("break-glass request is absent")

type breakGlassContextUpdater interface {
	UpdateContext(context.Context, func([]byte) ([]byte, error)) error
}
type breakGlassUpdater interface {
	Update(func([]byte) ([]byte, error)) error
}

func decodeBreakGlassRequests(raw []byte) (map[string]breakGlassAccessRequest, error) {
	var rows map[string]breakGlassAccessRequest
	if err := json.Unmarshal(raw, &rows); err != nil {
		return nil, err
	}
	if rows == nil {
		return nil, fmt.Errorf("null break-glass authority")
	}
	for id, item := range rows {
		if id == "" || item.ID != id || item.UserID == "" || item.TenantID == "" {
			return nil, fmt.Errorf("invalid break-glass identity")
		}
		switch item.Status {
		case "requested", "approved", "session_issued":
		default:
			return nil, fmt.Errorf("invalid break-glass status")
		}
		if item.Status != "requested" && item.ApproverUserID == "" {
			return nil, fmt.Errorf("missing break-glass approver")
		}
		if item.Status == "session_issued" && item.SessionID == "" {
			return nil, fmt.Errorf("missing break-glass session")
		}
	}
	return rows, nil
}

// Edit the latest shared authority, not a stale process snapshot. Only a confirmed
// save may publish authorization. The request's captured leadership term is kept.
func (s *breakGlassRequestStore) editLocked(ctx context.Context, edit func(map[string]breakGlassAccessRequest) error) error {
	var next map[string]breakGlassAccessRequest
	var mutationErr error
	build := func(raw []byte) ([]byte, error) {
		var err error
		if raw == nil {
			if s.authorityKnown {
				return nil, fmt.Errorf("break-glass authority disappeared")
			}
			raw, err = json.Marshal(s.requests)
			if err != nil {
				return nil, err
			}
		}
		next, err = decodeBreakGlassRequests(raw)
		if err != nil {
			return nil, err
		}
		if err = edit(next); err != nil {
			mutationErr = err
			return nil, err
		}
		return json.Marshal(next)
	}
	var err error
	shared := false
	switch p := s.persister.(type) {
	case breakGlassContextUpdater:
		shared = true
		err = p.UpdateContext(ctx, build)
	case breakGlassUpdater:
		shared = true
		err = p.Update(build)
	default:
		var raw []byte
		raw, err = json.Marshal(s.requests)
		if err == nil {
			raw, err = build(raw)
		}
		if err == nil && p != nil {
			err = p.Save(raw)
		}
	}
	if err != nil {
		if mutationErr != nil {
			return mutationErr
		}
		if shared || !errors.Is(err, blobstore.ErrSavedWithoutAtomicity) || errors.Is(err, blobstore.ErrDurabilityUnconfirmed) {
			return fmt.Errorf("%w: %v", errBreakGlassPersistence, err)
		}
	}
	s.requests = next
	if s.persister != nil {
		s.authorityKnown = true
	}
	return nil
}

// The checked read is used before issuing a session; failure must not fall back
// to a cached approved request. Mutations independently validate the latest row.
func (s *breakGlassRequestStore) GetChecked(id string) (breakGlassAccessRequest, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, shared := s.persister.(breakGlassUpdater)
	if _, ok := s.persister.(breakGlassContextUpdater); ok {
		shared = true
	}
	if shared {
		raw, err := s.persister.Load()
		if err != nil {
			return breakGlassAccessRequest{}, false, errBreakGlassPersistence
		}
		if raw == nil {
			if s.authorityKnown {
				return breakGlassAccessRequest{}, false, errBreakGlassPersistence
			}
		} else {
			next, err := decodeBreakGlassRequests(raw)
			if err != nil {
				return breakGlassAccessRequest{}, false, errBreakGlassPersistence
			}
			s.requests = next
			s.authorityKnown = true
		}
	}
	item, ok := s.requests[id]
	return item, ok, nil
}

func writeBreakGlassError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errBreakGlassPersistence):
		writeError(w, http.StatusServiceUnavailable, errBreakGlassPersistence)
	case errors.Is(err, errBreakGlassAbsent):
		writeError(w, http.StatusNotFound, errBreakGlassAbsent)
	default:
		writeError(w, http.StatusBadRequest, err)
	}
}

func newBreakGlassRequestStore() *breakGlassRequestStore {
	return &breakGlassRequestStore{requests: map[string]breakGlassAccessRequest{}}
}

func (s *breakGlassRequestStore) Create(req breakGlassSessionRequest, expectedTenantID string, now time.Time) (breakGlassAccessRequest, error) {
	return s.CreateContext(context.Background(), req, expectedTenantID, now)
}
func (s *breakGlassRequestStore) CreateContext(ctx context.Context, req breakGlassSessionRequest, expectedTenantID string, now time.Time) (breakGlassAccessRequest, error) {
	tenantID := valueOrDefault(req.TenantID, expectedTenantID)
	if tenantID == "" {
		return breakGlassAccessRequest{}, fmt.Errorf("break-glass tenant_id is required")
	}
	if expectedTenantID != "" && tenantID != expectedTenantID {
		return breakGlassAccessRequest{}, fmt.Errorf("break-glass tenant_id %s does not match edge tenant_id %s", tenantID, expectedTenantID)
	}
	if req.UserID == "" {
		return breakGlassAccessRequest{}, fmt.Errorf("break-glass user_id is required")
	}
	if req.Reason == "" {
		return breakGlassAccessRequest{}, fmt.Errorf("break-glass reason is required")
	}
	duration := req.DurationSeconds
	if duration <= 0 {
		duration = 900
	}
	if duration > 3600 {
		duration = 3600
	}
	requestedBy := valueOrDefault(req.SubjectUserID, req.UserID)
	item := breakGlassAccessRequest{
		ID:              randomEdgeID("bgr_", now),
		TenantID:        tenantID,
		UserID:          req.UserID,
		SubjectUserID:   valueOrDefault(req.SubjectUserID, req.UserID),
		DeviceID:        valueOrDefault(req.DeviceID, "dev_lab_001"),
		Reason:          req.Reason,
		TicketID:        req.TicketID,
		DurationSeconds: duration,
		RequestedBy:     requestedBy,
		Status:          "requested",
		CreatedAt:       now.UTC().Format(time.RFC3339),
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.editLocked(ctx, func(rows map[string]breakGlassAccessRequest) error { rows[item.ID] = item; return nil })
	if err != nil {
		return breakGlassAccessRequest{}, err
	}
	return item, nil
}

func (s *breakGlassRequestStore) Approve(id string, req breakGlassApprovalRequest, now time.Time) (breakGlassAccessRequest, error) {
	return s.ApproveContext(context.Background(), id, req, now, nil)
}
func (s *breakGlassRequestStore) ApproveContext(ctx context.Context, id string, req breakGlassApprovalRequest, now time.Time, visible func(breakGlassAccessRequest) bool) (breakGlassAccessRequest, error) {
	if req.ApproverUserID == "" {
		return breakGlassAccessRequest{}, fmt.Errorf("break-glass approver_user_id is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var item breakGlassAccessRequest
	err := s.editLocked(ctx, func(rows map[string]breakGlassAccessRequest) error {
		var ok bool
		item, ok = rows[id]
		if !ok || (visible != nil && !visible(item)) {
			return errBreakGlassAbsent
		}
		if item.Status != "requested" {
			return fmt.Errorf("break-glass request %s status is %s", id, item.Status)
		}
		item.Status = "approved"
		item.ApproverUserID = req.ApproverUserID
		item.ApprovalReason = req.Reason
		item.ApprovedAt = now.UTC().Format(time.RFC3339)
		rows[id] = item
		return nil
	})
	if err != nil {
		return breakGlassAccessRequest{}, err
	}
	return item, nil
}

func (s *breakGlassRequestStore) Get(id string) (breakGlassAccessRequest, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	item, ok := s.requests[id]
	return item, ok
}

func (s *breakGlassRequestStore) MarkSessionIssued(id, sessionID string, now time.Time) (breakGlassAccessRequest, error) {
	return s.MarkSessionIssuedContext(context.Background(), id, sessionID, now, nil)
}
func (s *breakGlassRequestStore) MarkSessionIssuedContext(ctx context.Context, id, sessionID string, now time.Time, visible func(breakGlassAccessRequest) bool) (breakGlassAccessRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sessionID == "" {
		return breakGlassAccessRequest{}, fmt.Errorf("session id is required")
	}
	var item breakGlassAccessRequest
	err := s.editLocked(ctx, func(rows map[string]breakGlassAccessRequest) error {
		var ok bool
		item, ok = rows[id]
		if !ok || (visible != nil && !visible(item)) {
			return errBreakGlassAbsent
		}
		if item.Status != "approved" {
			return fmt.Errorf("break-glass request %s status is %s", id, item.Status)
		}
		item.Status = "session_issued"
		item.SessionID = sessionID
		item.IssuedAt = now.UTC().Format(time.RFC3339)
		rows[id] = item
		return nil
	})
	if err != nil {
		return breakGlassAccessRequest{}, err
	}
	return item, nil
}

func (item breakGlassAccessRequest) SessionRequest() breakGlassSessionRequest {
	return breakGlassSessionRequest{
		TenantID:        item.TenantID,
		UserID:          item.UserID,
		SubjectUserID:   item.SubjectUserID,
		DeviceID:        item.DeviceID,
		Reason:          item.Reason,
		TicketID:        item.TicketID,
		DurationSeconds: item.DurationSeconds,
	}
}

func appendBreakGlassDomainEvent(ctx context.Context, domainEventOutbox domainEventOutboxWriter, item breakGlassAccessRequest, eventType, occurredAtValue string, now time.Time) {
	if envelope, err := domainEventOutboxEnvelopeFromBreakGlassAccessRequest(item, eventType, occurredAtValue, now); err != nil {
		log.Printf("domain event outbox break-glass envelope: %v", err)
	} else {
		appendDomainEventOutbox(ctx, domainEventOutbox, envelope, now)
	}
}

func breakGlassAuthenticationEvent(req breakGlassSessionRequest, expectedTenantID string, r *http.Request, now time.Time) (model.AuthenticationEvent, error) {
	tenantID := valueOrDefault(req.TenantID, expectedTenantID)
	if expectedTenantID != "" && tenantID != expectedTenantID {
		return model.AuthenticationEvent{}, fmt.Errorf("break-glass tenant_id %s does not match edge tenant_id %s", tenantID, expectedTenantID)
	}
	if req.UserID == "" {
		return model.AuthenticationEvent{}, fmt.Errorf("break-glass user_id is required")
	}
	if req.Reason == "" {
		return model.AuthenticationEvent{}, fmt.Errorf("break-glass reason is required")
	}
	duration := req.DurationSeconds
	if duration <= 0 {
		duration = 900
	}
	if duration > 3600 {
		duration = 3600
	}
	expiresAt := now.UTC().Add(time.Duration(duration) * time.Second).Format(time.RFC3339)
	sourceIP := sourceIPFromRequest(r)
	deviceID := valueOrDefault(req.DeviceID, "dev_lab_001")
	subjectUserID := valueOrDefault(req.SubjectUserID, req.UserID)
	acr := breakGlassACR
	return model.AuthenticationEvent{
		ID:            randomEdgeID("auth_bg_", now),
		TenantID:      tenantID,
		UserID:        req.UserID,
		SubjectUserID: &subjectUserID,
		SessionID:     randomEdgeID(breakGlassSessionPrefix, now),
		IDPID:         breakGlassIDPID,
		Method:        breakGlassAuthMethod,
		AMR:           []string{"pwd", "otp", breakGlassAuthMethod},
		ACR:           &acr,
		MFAState:      "fresh",
		AuthTime:      now.UTC().Format(time.RFC3339),
		ExpiresAt:     &expiresAt,
		SourceIP:      &sourceIP,
		DeviceID:      &deviceID,
		Result:        "success",
		Timestamp:     now.UTC().Format(time.RFC3339),
		Metadata: map[string]any{
			"break_glass_reason": req.Reason,
			"ticket_id":          req.TicketID,
		},
	}, nil
}

func breakGlassExportEvents(writer *logs.Writer) ([]map[string]any, error) {
	auditRows, err := writer.ReadJSONL("audit.log.jsonl")
	if err != nil {
		return nil, err
	}
	accessRows, err := writer.ReadJSONL("access.log.jsonl")
	if err != nil {
		return nil, err
	}

	events := []map[string]any{}
	issuedSessionIDs := map[string]struct{}{}
	authIssuedRows := []map[string]any{}
	for _, row := range auditRows {
		eventType := stringValue(row["event_type"])
		if eventType == "break_glass_session_issued" {
			events = append(events, breakGlassSessionIssuedExportEvent(row))
			if sessionID := stringValue(row["session_id"]); sessionID != "" {
				issuedSessionIDs[sessionID] = struct{}{}
			}
			continue
		}
		if eventType == "authentication_event_recorded" && isBreakGlassAuditRow(row) {
			authIssuedRows = append(authIssuedRows, row)
		}
	}
	for _, row := range authIssuedRows {
		sessionID := stringValue(row["session_id"])
		if _, ok := issuedSessionIDs[sessionID]; ok {
			continue
		}
		events = append(events, breakGlassSessionIssuedExportEvent(row))
	}

	for _, row := range accessRows {
		if !isBreakGlassAccessRow(row) {
			continue
		}
		metadata := mapMetadata(row["metadata"])
		events = append(events, map[string]any{
			"event_type":         "break_glass_session_used",
			"tenant_id":          row["tenant_id"],
			"actor_user_id":      row["user_id"],
			"request_id":         metadata["break_glass_request_id"],
			"session_id":         row["session_id"],
			"access_decision_id": row["access_decision_id"],
			"application_id":     row["application_id"],
			"decision":           row["decision"],
			"reason_codes":       row["reason_codes"],
			"reason_recorded":    metadata["break_glass_reason_present"],
			"ticket_id_recorded": metadata["break_glass_ticket_id_present"],
			"edge_region_id":     row["edge_region_id"],
			"edge_cluster_id":    row["edge_cluster_id"],
			"connector_id":       row["connector_id"],
			"timestamp":          row["timestamp"],
		})
	}

	return events, nil
}

func breakGlassSessionIssuedExportEvent(row map[string]any) map[string]any {
	metadata := mapMetadata(row["metadata"])
	return map[string]any{
		"event_type":              "break_glass_session_issued",
		"tenant_id":               row["tenant_id"],
		"actor_user_id":           row["actor_user_id"],
		"request_id":              metadata["request_id"],
		"session_id":              row["session_id"],
		"authentication_event_id": row["authentication_event_id"],
		"policy_bundle_id":        row["policy_bundle_id"],
		"edge_region_id":          row["edge_region_id"],
		"edge_cluster_id":         row["edge_cluster_id"],
		"source_ip":               row["source_ip"],
		"reason":                  metadata["break_glass_reason"],
		"ticket_id":               metadata["ticket_id"],
		"timestamp":               row["timestamp"],
	}
}

func isBreakGlassAuditRow(row map[string]any) bool {
	metadata := mapMetadata(row["metadata"])
	if stringValue(metadata["auth_method"]) == breakGlassAuthMethod {
		return true
	}
	return stringValue(metadata["idp_id"]) == breakGlassIDPID
}

func isBreakGlassAccessRow(row map[string]any) bool {
	metadata := mapMetadata(row["metadata"])
	if stringValue(metadata["auth_method"]) == breakGlassAuthMethod {
		return true
	}
	return strings.HasPrefix(stringValue(row["session_id"]), breakGlassSessionPrefix)
}

// Administrative execution and the target identity are different actors. Body
// fields remain explicit metadata; they must not impersonate the authenticated caller.
func breakGlassLifecycleAuditForRequest(r *http.Request, eventType string, item breakGlassAccessRequest, evaluator decision.Evaluator, sourceIP, sessionID, authenticationEventID string) model.AuditLog {
	row := breakGlassLifecycleAuditLog(eventType, item, evaluator, sourceIP, sessionID, authenticationEventID)
	row.ActorUserID = auditActorPrincipal(r)
	return row
}

func breakGlassLifecycleAuditLog(eventType string, item breakGlassAccessRequest, evaluator decision.Evaluator, sourceIP, sessionID, authenticationEventID string) model.AuditLog {
	action := strings.TrimPrefix(eventType, "break_glass_")
	result := "success"
	reason := item.Reason
	targetType := "break_glass_request"
	targetID := item.ID
	actorUserID := item.RequestedBy
	if item.ApproverUserID != "" {
		actorUserID = item.ApproverUserID
	}
	return model.AuditLog{
		ID:                    randomEdgeID("audit_", time.Now().UTC()),
		TenantID:              item.TenantID,
		ActorUserID:           &actorUserID,
		EventType:             eventType,
		TargetType:            &targetType,
		TargetID:              &targetID,
		Action:                &action,
		Result:                &result,
		Reason:                &reason,
		PolicyBundleID:        &evaluator.PolicyBundle.ID,
		EdgeRegionID:          &evaluator.EdgeRegionID,
		EdgeClusterID:         &evaluator.EdgeClusterID,
		SessionID:             stringPtr(sessionID),
		AuthenticationEventID: stringPtr(authenticationEventID),
		SourceIP:              &sourceIP,
		Timestamp:             time.Now().UTC().Format(time.RFC3339),
		Metadata: map[string]any{
			"request_id":          item.ID,
			"status":              item.Status,
			"requested_by":        item.RequestedBy,
			"approver_user_id":    item.ApproverUserID,
			"approval_reason":     item.ApprovalReason,
			"break_glass_reason":  item.Reason,
			"ticket_id":           item.TicketID,
			"duration_seconds":    item.DurationSeconds,
			"target_user_id":      item.UserID,
			"target_subject_user": item.SubjectUserID,
			"target_device_id":    item.DeviceID,
			"auth_method":         breakGlassAuthMethod,
			"idp_id":              breakGlassIDPID,
		},
	}
}

func breakGlassDecisionAuditRequired(dec model.AccessDecision) bool {
	if boolMetadata(dec.Metadata, "break_glass_audit_event_required") {
		return true
	}
	return stringMetadata(dec.Metadata, "auth_method") == breakGlassAuthMethod
}

func breakGlassDecisionAuditLog(dec model.AccessDecision, now time.Time) model.AuditLog {
	eventType := "break_glass_session_used"
	action := "access"
	result := dec.Decision
	reason := "Break-glass access decision audited."
	targetType := "application"
	targetID := dec.ApplicationID
	return model.AuditLog{
		ID:                    randomEdgeID("audit_", now),
		TenantID:              dec.TenantID,
		ActorUserID:           dec.UserID,
		EventType:             eventType,
		TargetType:            &targetType,
		TargetID:              &targetID,
		Action:                &action,
		Result:                &result,
		Reason:                &reason,
		AccessDecisionID:      &dec.ID,
		PolicyID:              &dec.PolicyID,
		PolicyBundleID:        &dec.PolicyBundleID,
		EdgeRegionID:          dec.EdgeRegionID,
		EdgeClusterID:         dec.EdgeClusterID,
		SessionID:             dec.SessionID,
		AuthenticationEventID: dec.AuthenticationEventID,
		SourceIP:              dec.SourceIP,
		Timestamp:             now.UTC().Format(time.RFC3339),
		Metadata: map[string]any{
			"break_glass_policy":                boolMetadata(dec.Metadata, "break_glass_policy"),
			"break_glass_identity_id":           stringMetadata(dec.Metadata, "break_glass_identity_id"),
			"break_glass_request_id":            stringMetadata(dec.Metadata, "break_glass_request_id"),
			"break_glass_max_session_seconds":   intMapValue(dec.Metadata, "break_glass_max_session_seconds"),
			"break_glass_strong_auth_required":  boolMetadata(dec.Metadata, "break_glass_strong_auth_required"),
			"break_glass_strong_auth_satisfied": boolMetadata(dec.Metadata, "break_glass_strong_auth_satisfied"),
			"break_glass_audit_required":        boolMetadata(dec.Metadata, "break_glass_audit_required"),
			"break_glass_auth_freshness":        stringMetadata(dec.Metadata, "break_glass_auth_freshness"),
			"break_glass_reason_present":        boolMetadata(dec.Metadata, "break_glass_reason_present"),
			"break_glass_ticket_id_present":     boolMetadata(dec.Metadata, "break_glass_ticket_id_present"),
			"auth_method":                       stringMetadata(dec.Metadata, "auth_method"),
		},
	}
}

func breakGlassExportAuditLog(r *http.Request, evaluator decision.Evaluator, exportedCount int) model.AuditLog {
	action := "export"
	result := "success"
	reason := "Break-glass audit events exported."
	targetType := "break_glass_events"
	sourceIP := sourceIPFromRequest(r)
	return model.AuditLog{
		ID:             randomEdgeID("audit_", time.Now().UTC()),
		TenantID:       evaluator.PolicyBundle.TenantID,
		EventType:      "break_glass_exported",
		TargetType:     &targetType,
		Action:         &action,
		Result:         &result,
		Reason:         &reason,
		PolicyBundleID: &evaluator.PolicyBundle.ID,
		EdgeRegionID:   &evaluator.EdgeRegionID,
		EdgeClusterID:  &evaluator.EdgeClusterID,
		SourceIP:       &sourceIP,
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		Metadata: map[string]any{
			"exported_count": exportedCount,
		},
	}
}
