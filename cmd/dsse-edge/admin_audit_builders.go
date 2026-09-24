package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	_ "net/http/pprof" // DIAGNOSTIC: registers /debug/pprof on http.DefaultServeMux; served only when -pprof-listen is set
	"strings"
	"time"

	agentpolicy "github.com/lantern-networks/dsse-core/agentpolicy"
	agentrollout "github.com/lantern-networks/dsse-core/agentrollout"
	agentupdate "github.com/lantern-networks/dsse-core/agentupdate"
	humanidentity "github.com/lantern-networks/dsse-core/humanidentity"

	// The IANA timezone database, compiled in. The runtime image is FROM scratch, so there is no
	// /usr/share/zoneinfo and time.LoadLocation would fail for EVERY zone — including the ones an operator
	// just typed into the Console. Validation that passes on a developer's machine and rejects everything in
	// the container is worse than no validation, because it looks like the operator's mistake.
	_ "time/tzdata"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
)

func appendAdminAudit(ctx context.Context, writer *logs.Writer, outbox adminAuditOutboxDeadReader, audit model.AuditLog, now time.Time) error {
	if writer == nil {
		return fmt.Errorf("admin audit writer is not configured")
	}
	if err := writer.Append("audit.log.jsonl", audit); err != nil {
		// Every caller discards this error (`_ = appendAdminAudit(...)`), so without this line a failed audit
		// write is COMPLETELY silent: the mutation succeeds and the operator believes there is a trail. An audit
		// that fails invisibly is worse than none. Log it here — one place covers every call site — per
		// ("audit infra error logs: KEEP ERROR"). The mirror failure below is already logged; the PRIMARY record
		// failing was not. This does not fail the request: dropping admin operations because the log store is
		// unhappy is a separate call, and it is not this function's to make.
		logErrorf("admin_audit_write_failed event=%q target=%q tenant=%q: %v", audit.EventType, audit.TargetType, audit.TenantID, err)
		return err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if outbox != nil {
		if err := outbox.InsertAudit(ctx, audit, now); err != nil {
			log.Printf("admin audit outbox mirror failed: %v", err)
		}
	}
	return nil
}

func adminDownloadAuditLog(eventType string, token adminDownloadToken, evaluator decision.Evaluator, sourceIP, userAgent string) model.AuditLog {
	action := "download"
	result := "success"
	reason := "Export download URL lifecycle event."
	actorUserID := stringPtr(token.IssuedByAdminPrincipalID)
	downloadActorKnown := true
	if eventType == "admin_export_downloaded" || eventType == "admin_export_download_failed" {
		actorUserID = stringPtr("anonymous_token_bearer")
		downloadActorKnown = false
	}
	if eventType == "admin_export_download_failed" {
		result = "failure"
		reason = "Download token spend was not confirmed; no bytes released."
	}
	return model.AuditLog{
		ID:            randomEdgeID("audit_"+eventType+"_", time.Now().UTC()),
		TenantID:      token.TenantID,
		ActorUserID:   actorUserID,
		EventType:     eventType,
		TargetType:    stringPtr("export_job"),
		TargetID:      stringPtr(token.ExportJobID),
		Action:        &action,
		Result:        &result,
		Reason:        &reason,
		EdgeRegionID:  &evaluator.EdgeRegionID,
		EdgeClusterID: &evaluator.EdgeClusterID,
		SourceIP:      stringPtr(sourceIP),
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
		Metadata: map[string]any{
			"object_ref":                   token.ObjectRef,
			"payload_checksum":             token.PayloadChecksum,
			"expires_at":                   token.ExpiresAt,
			"issued_by_admin_principal_id": token.IssuedByAdminPrincipalID,
			"download_actor_known":         downloadActorKnown,
			"user_agent":                   userAgent,
		},
	}
}

func adminAPITokenAuditLog(eventType string, token adminAPIToken, evaluator decision.Evaluator, sourceIP string) model.AuditLog {
	action := "api_token"
	result := "success"
	return model.AuditLog{
		ID:             randomEdgeID("audit_"+eventType+"_", time.Now().UTC()),
		TenantID:       evaluator.PolicyBundle.TenantID,
		ActorUserID:    &token.CreatedByAdminPrincipalID,
		EventType:      eventType,
		TargetType:     stringPtr("admin_api_token"),
		TargetID:       stringPtr(token.ID),
		Action:         &action,
		Result:         &result,
		EdgeRegionID:   &evaluator.EdgeRegionID,
		EdgeClusterID:  &evaluator.EdgeClusterID,
		SourceIP:       stringPtr(sourceIP),
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		PolicyID:       stringPtr("admin_api_token"),
		PolicyBundleID: &evaluator.PolicyBundle.ID,
		Metadata: map[string]any{
			"admin_api_token_id": token.ID,
			"token_name":         token.Name,
			"token_status":       token.Status,
			"reason_codes":       []string{"admin_api_token_lifecycle"},
			"roles":              token.Roles,
			"scopes":             token.Scopes,
		},
	}
}

func adminLoginAuditLog(eventType string, principal *adminPrincipal, session *adminSession, evaluator decision.Evaluator, r *http.Request, reason string) model.AuditLog {
	action := "admin_login"
	result := "success"
	if strings.HasSuffix(eventType, "_failed") {
		result = "failure"
	}
	var actorUserID *string
	var targetID *string
	metadata := map[string]any{
		"reason":     reason,
		"user_agent": r.UserAgent(),
	}
	// ★ WHOSE SIGN-IN IS THIS? (2026-08-17, measured on the lab.) The tenant on the record was the NODE's —
	// evaluator.PolicyBundle.TenantID — so a Northwind administrator signing in and out through the console
	// produced two rows in tenant_reference_lab's audit log and NONE in Northwind's. Two things wrong at once:
	// the customer cannot see who signed into their own console, which is the first question anyone asks of an
	// audit trail; and the node's own organization accumulates other organizations' authentication events,
	// down to the email address, in a log a different customer reads.
	//
	// A sign-in belongs to the organization of whoever signed in. When nobody could be identified — a bad
	// email, a password that matched no account — there IS no organization to file it under, and GUESSING one
	// would put a stranger's failed attempts into a customer's trail. Those stay with the node, which is the
	// only party the event is actually about.
	tenantID := evaluator.PolicyBundle.TenantID
	if principal != nil {
		actorUserID = &principal.ID
		metadata["email"] = principal.Email
		metadata["roles"] = principal.Roles
		metadata["idp_id"] = principal.IDPID
		if strings.TrimSpace(principal.TenantID) != "" {
			tenantID = principal.TenantID
		}
	}
	if session != nil {
		targetID = &session.ID
		metadata["session_id"] = session.ID
		metadata["mfa_state"] = session.MFAState
		metadata["auth_time"] = session.AuthTime
	}
	return model.AuditLog{
		ID:            randomEdgeID("audit_"+eventType+"_", time.Now().UTC()),
		TenantID:      tenantID,
		ActorUserID:   actorUserID,
		EventType:     eventType,
		TargetType:    stringPtr("admin_session"),
		TargetID:      targetID,
		Action:        &action,
		Result:        &result,
		EdgeRegionID:  &evaluator.EdgeRegionID,
		EdgeClusterID: &evaluator.EdgeClusterID,
		SourceIP:      stringPtr(sourceIPFromRequest(r)),
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
		Metadata:      metadata,
	}
}

// adminAccountLifecycleAuditLog records a tenant-scoped admin account management action (suspend / reactivate /
// delete / role change). Like adminLoginAuditLog this is an account-plane event that legitimately references the
// acting and target principals, so it is in the deferred (non-sentinel-scanned) audit set.
func adminAccountLifecycleAuditLog(eventType, tenantID, actorPrincipalID, targetPrincipalID string, roles []string, evaluator decision.Evaluator, r *http.Request) model.AuditLog {
	action := "admin_account_lifecycle"
	result := "success"
	if strings.HasSuffix(eventType, "_failed") {
		result = "failure"
	}
	if strings.TrimSpace(tenantID) == "" {
		tenantID = evaluator.PolicyBundle.TenantID
	}
	return model.AuditLog{
		ID:            randomEdgeID("audit_"+eventType+"_", time.Now().UTC()),
		TenantID:      tenantID,
		ActorUserID:   stringPtr(actorPrincipalID),
		EventType:     eventType,
		TargetType:    stringPtr("admin_account"),
		TargetID:      stringPtr(targetPrincipalID),
		Action:        &action,
		Result:        &result,
		EdgeRegionID:  &evaluator.EdgeRegionID,
		EdgeClusterID: &evaluator.EdgeClusterID,
		SourceIP:      stringPtr(sourceIPFromRequest(r)),
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
		Metadata: map[string]any{
			"target_principal_id": targetPrincipalID,
			"roles":               append([]string(nil), roles...),
			"user_agent":          r.UserAgent(),
		},
	}
}

// stampOperatorActor writes "this act was performed by the operator, inside your organization" onto an audit
// record's metadata, in the ONE vocabulary the console reads.
//
// ★ MEASURED (2026-08-17, in a probe organization's own audit trail). Three rows describing one operator
// session rendered three different ways on the customer's audit screen: the organization's creation as
// "System", the first-administrator seating as a bare adm_fa6e5d24…, and only the operate-within row as a
// person. All three records HELD the actor. They disagreed about what to call the field — actor_admin_
// principal_id here, operator_principal_id there, nothing on the third — and the screen reads one of those
// names. A shared emitter is what keeps that from happening a fourth time; the keys are not a free choice at
// each call site.
//
// The label is what a customer can actually use: an id belonging to the operator's organization cannot be
// resolved by the directory a customer's console holds, so a row carrying only an id is a row that names
// nobody to the one reader it is for.
func stampOperatorActor(meta map[string]any, identity adminIdentity) {
	if meta == nil {
		return
	}
	meta["operator_principal_id"] = strings.TrimSpace(identity.PrincipalID)
	meta["operator_tenant_id"] = strings.TrimSpace(identity.TenantID)
	if label := strings.TrimSpace(identity.PrincipalLabel); label != "" {
		meta["email"] = label
		meta["display_name"] = label
	}
}

// adminOperateWithinTenantAuditLog records an operator (admin.tenant.admin) acting inside a selected tenant via
// X-Operate-Tenant (Multi-Tenant Admin Console design/: "audit the operator"). The audit is tenant'd to
// the TARGET tenant (so it surfaces in that tenant's operator-access transparency view) and names the operator
// principal + their home tenant. Non-sensitive fields only; no secrets are carried.
func adminOperateWithinTenantAuditLog(identity adminIdentity, targetTenant, method, path string, evaluator decision.Evaluator, sourceIP, userAgent string) model.AuditLog {
	path, grantRef := accessGrantAuditPath(path)
	action := "admin_operate_within_tenant"
	result := "success"
	targetTenant = strings.TrimSpace(targetTenant)
	record := model.AuditLog{
		ID:            randomEdgeID("audit_admin_operate_within_tenant_", time.Now().UTC()),
		TenantID:      targetTenant,
		ActorUserID:   stringPtr(identity.PrincipalID),
		EventType:     "admin_operate_within_tenant",
		TargetType:    stringPtr("tenant"),
		TargetID:      stringPtr(targetTenant),
		Action:        &action,
		Result:        &result,
		EdgeRegionID:  &evaluator.EdgeRegionID,
		EdgeClusterID: &evaluator.EdgeClusterID,
		SourceIP:      stringPtr(sourceIP),
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
		Metadata: map[string]any{
			"target_tenant_id": targetTenant,
			"method":           method,
			"path":             path,
			"roles":            identity.Roles,
			"user_agent":       userAgent,
		},
	}
	// ★ WHO, NOT JUST WHICH ID (2026-08-17, read in the customer's own audit trail). The row an organization
	// reads to answer "somebody outside my organization was working in it" carried the operator's principal id
	// and nothing else — and the directory a customer's console resolves ids against is its OWN administrators,
	// so it stayed a bare adm_1e9a9d5698…. The config-change rows beside it name the person, because they carry
	// the label; this one does too, so one act does not appear under two different identities on the same
	// screen. Written through the shared stamp, because the other two emitters of this same fact each invented
	// their own key names and the screen only reads one set.
	stampOperatorActor(record.Metadata, identity)
	if grantRef != "" {
		record.Metadata["grant_ref"] = grantRef
	}
	return record
}

// adminAuditStatusRecorder wraps the ResponseWriter so the admin-audit wrapper can record the outcome status of
// a mutating admin request without changing the handler. Defaults to 200 (Go's default when WriteHeader is
// never called). Preserves the Flusher/Hijacker surfaces streaming admin handlers may rely on is not needed here
// (admin write endpoints are unary JSON), so a minimal wrapper suffices.
type adminAuditStatusRecorder struct {
	http.ResponseWriter
	status int
	// A typed business refusal can keep HTTP 200 while still being an audit failure.
	businessFailure bool
}

func (rec *adminAuditStatusRecorder) WriteHeader(status int) {
	rec.status = status
	rec.ResponseWriter.WriteHeader(status)
}

func (rec *adminAuditStatusRecorder) statusOrDefault() int {
	if rec.status == 0 {
		return http.StatusOK
	}
	return rec.status
}

// adminConfigChangeAuditLog records ONE non-secret audit row for a successful-or-failed admin MUTATION (the
// uniform API-write audit added at the adminEndpoint wrapper, b). It
// captures WHO (principal id + resolved email/display-name + roles + auth method + api-token id), WHAT
// (method + path), and the OUTCOME (status → success/error). This is the coverage floor: every admin write —
// Console session, named API token, or the legacy owner bearer — leaves a trail, independent of whether the
// handler also emits a richer domain-specific audit.
func adminConfigChangeAuditLog(identity adminIdentity, email, displayName, method, path string, status int, evaluator decision.Evaluator, tenantID, sourceIP, userAgent string) model.AuditLog {
	path, grantRef := accessGrantAuditPath(path)
	action := strings.ToUpper(strings.TrimSpace(method))
	result := "success"
	if status >= 400 {
		result = "error"
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		tenantID = identity.TenantID
	}
	meta := map[string]any{
		"principal_id": identity.PrincipalID,
		"auth_method":  identity.AuthMethod,
		"method":       action,
		"path":         path,
		"status_code":  status,
		"roles":        identity.Roles,
		"user_agent":   userAgent,
	}
	if grantRef != "" {
		meta["grant_ref"] = grantRef
	}
	if strings.TrimSpace(email) != "" {
		meta["email"] = email
	}
	if strings.TrimSpace(displayName) != "" {
		meta["display_name"] = displayName
	}
	if strings.TrimSpace(identity.APITokenID) != "" {
		meta["api_token_id"] = identity.APITokenID
	}
	return model.AuditLog{
		ID:            randomEdgeID("audit_admin_config_change_", time.Now().UTC()),
		TenantID:      tenantID,
		ActorUserID:   stringPtr(identity.PrincipalID),
		EventType:     "admin_config_change",
		TargetType:    stringPtr("admin_api"),
		TargetID:      stringPtr(path),
		Action:        &action,
		Result:        &result,
		EdgeRegionID:  &evaluator.EdgeRegionID,
		EdgeClusterID: &evaluator.EdgeClusterID,
		SourceIP:      stringPtr(sourceIP),
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
		Metadata:      meta,
	}
}

func delegatedAccessDecisionAuditLog(dec model.AccessDecision, now time.Time) model.AuditLog {
	eventType := "nhi_delegated_access_decision_evaluated"
	action := valueOrDefault(stringPtrValue(dec.ToolActionType), "access")
	result := dec.Decision
	reason := "NHI delegated access decision audited."
	targetType := "delegated_access_grant"
	targetID := stringPtrValue(dec.DelegatedAccessGrantID)
	if targetID == "" {
		targetType = "non_human_identity"
		targetID = stringPtrValue(dec.ActorNHIID)
	}
	metadata := map[string]any{
		"actor_type":                   dec.ActorType,
		"subject_user_id":              stringPtrValue(dec.SubjectUserID),
		"request_user_id":              stringPtrValue(dec.UserID),
		"actor_nhi_id":                 stringPtrValue(dec.ActorNHIID),
		"delegated_access_grant_id":    stringPtrValue(dec.DelegatedAccessGrantID),
		"human_approval_event_id":      stringPtrValue(dec.HumanApprovalEventID),
		"agent_task_session_id":        stringPtrValue(dec.AgentTaskSessionID),
		"tool_id":                      stringPtrValue(dec.ToolID),
		"tool_action_type":             stringPtrValue(dec.ToolActionType),
		"tool_permission_profile":      stringMetadata(dec.Metadata, "tool_permission_profile"),
		"tool_version":                 stringMetadata(dec.Metadata, "tool_version"),
		"tool_signature_state":         stringMetadata(dec.Metadata, "tool_signature_state"),
		"agent_tool_metadata_scope":    stringMetadata(dec.Metadata, "agent_tool_metadata_scope"),
		"mcp_server_id":                stringMetadata(dec.Metadata, "mcp_server_id"),
		"mcp_resource_uri":             stringMetadata(dec.Metadata, "mcp_resource_uri"),
		"mcp_audience":                 stringMetadata(dec.Metadata, "mcp_audience"),
		"mcp_token_passthrough_policy": stringMetadata(dec.Metadata, "mcp_token_passthrough_policy"),
		"mcp_metadata_scope":           stringMetadata(dec.Metadata, "mcp_metadata_scope"),
		"runtime_environment_id":       stringMetadata(dec.Metadata, "runtime_environment_id"),
		"tool_payload_recorded":        boolMetadata(dec.Metadata, "tool_payload_recorded"),
		"tool_secret_recorded":         boolMetadata(dec.Metadata, "tool_secret_recorded"),
		"tool_credentials_recorded":    boolMetadata(dec.Metadata, "tool_credentials_recorded"),
		"context_boundary_id":          stringPtrValue(dec.ContextBoundaryID),
		"data_classification":          stringPtrValue(dec.DataClassification),
		"runtime_evidence_result":      stringMetadata(dec.Metadata, "runtime_evidence_result"),
		"delegated_grant_status":       stringMetadata(dec.Metadata, "delegated_grant_status"),
		"delegated_grant_expires_at":   stringMetadata(dec.Metadata, "delegated_grant_expires_at"),
		"approval_result":              stringMetadata(dec.Metadata, "approval_result"),
		"approval_expires_at":          stringMetadata(dec.Metadata, "approval_expires_at"),
		"reason_codes":                 append([]string(nil), dec.ReasonCodes...),
	}
	return model.AuditLog{
		ID:                    randomEdgeID("audit_", now),
		TenantID:              dec.TenantID,
		ActorNHIID:            dec.ActorNHIID,
		EventType:             eventType,
		TargetType:            &targetType,
		TargetID:              stringPtr(targetID),
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
		Metadata:              metadata,
	}
}

func deviceAuditLog(eventType string, dev model.Device, evaluator decision.Evaluator, sourceIP string) model.AuditLog {
	action := strings.TrimPrefix(eventType, "device_")
	result := "success"
	reason := "Device state updated."
	targetType := "device"
	return model.AuditLog{
		ID:             randomEdgeID("audit_", time.Now().UTC()),
		TenantID:       dev.TenantID,
		ActorUserID:    stringPtr(dev.UserID),
		EventType:      eventType,
		TargetType:     &targetType,
		TargetID:       &dev.ID,
		Action:         &action,
		Result:         &result,
		Reason:         &reason,
		PolicyBundleID: &evaluator.PolicyBundle.ID,
		EdgeRegionID:   &evaluator.EdgeRegionID,
		EdgeClusterID:  &evaluator.EdgeClusterID,
		SourceIP:       &sourceIP,
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		Metadata: map[string]any{
			"device_trust_level":     dev.DeviceTrustLevel,
			"agent_version":          dev.AgentVersion,
			"policy_bundle_id":       dev.PolicyBundleID,
			"policy_bundle_version":  dev.PolicyBundleVersion,
			"os":                     dev.OS,
			"os_version":             dev.OSVersion,
			"status":                 dev.Status,
			"registered_at":          dev.RegisteredAt,
			"last_seen_at":           dev.LastSeenAt,
			"device_metadata_digest": fmt.Sprintf("%d", len(dev.Metadata)),
		},
	}
}

func agentUpdateAuditLog(event model.AgentUpdateEvent, evaluator decision.Evaluator, sourceIP string) model.AuditLog {
	action := "agent_update"
	result := "success"
	reason := "Agent update event recorded."
	targetType := "device"
	return model.AuditLog{
		ID:             randomEdgeID("audit_", time.Now().UTC()),
		TenantID:       event.TenantID,
		ActorUserID:    stringPtr(event.UserID),
		EventType:      "agent_update_event_recorded",
		TargetType:     &targetType,
		TargetID:       &event.DeviceID,
		Action:         &action,
		Result:         &result,
		Reason:         &reason,
		PolicyBundleID: &evaluator.PolicyBundle.ID,
		EdgeRegionID:   &evaluator.EdgeRegionID,
		EdgeClusterID:  &evaluator.EdgeClusterID,
		SourceIP:       &sourceIP,
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		// ★ THE EVIDENCE HAS TO SURVIVE THE SHIPPING (2026-08-12, eleventh review). This record is what the Edge
		// ships to the control plane, so anything not copied here NEVER REACHES IT — and the fields left out
		// were the diagnostic ones: the failure reason, the artifact checksum and signature, and the device's
		// own metadata, which is where `rejected_manifest_sha256` and `dropped_before` live. A refusal arrived
		// at the CP as "something failed" with the two things that identify it stripped off.
		//
		// The device's metadata is nested rather than merged, so a device cannot overwrite a field this builder
		// sets by choosing its name.
		Metadata: agentUpdateAuditMetadata(event),
	}
}

func agentUpdateAuditMetadata(event model.AgentUpdateEvent) map[string]any {
	metadata := map[string]any{
		"agent_update_event_id": event.ID,
		"current_agent_version": event.CurrentAgentVersion,
		"target_agent_version":  event.TargetAgentVersion,
		"release_channel":       event.ReleaseChannel,
		"update_status":         event.UpdateStatus,
		"update_source":         event.UpdateSource,
		"event_timestamp":       event.Timestamp,
	}
	// ★ THE USER ID IS PART OF WHAT MAKES TWO REPORTS THE SAME REPORT (2026-08-13, twenty-eighth review). It
	// was recorded only as the audit record's ActorUserID, which the hydration decoder does not read — so after
	// a control-plane restart the rebuilt event carried UserID="" while the device's retry still carried "u1",
	// sameAgentUpdateEvent saw a DIFFERENT outcome under the same id, and the route answered 500 "keep it and
	// send it again". Permanently: that device's whole report queue is stuck behind a retry that can never
	// succeed. A field the equality check reads has to survive the round trip that check is compared across.
	if strings.TrimSpace(event.UserID) != "" {
		metadata["user_id"] = event.UserID
	}
	if event.FailureReason != nil {
		metadata["failure_reason"] = *event.FailureReason
	}
	if event.PackageChecksum != nil {
		metadata["package_checksum"] = *event.PackageChecksum
	}
	if event.PackageSignature != nil {
		metadata["package_signature"] = *event.PackageSignature
	}
	if len(event.Metadata) > 0 {
		metadata["device_metadata"] = event.Metadata
		// The platform is lifted OUT of the device's metadata as well as nested with it: the per-device view
		// needs it to say which release applies, and digging into a nested blob for one field is how a reader
		// ends up not having it. Nested copy stays, so nothing is lost either way.
		if platform := stringValue(event.Metadata["platform"]); platform != "" {
			metadata["platform"] = platform
		}
	}
	return metadata
}

// agentRolloutScheduleAuditLog records what a rollout change actually MOVED, previous value beside new one.
//
// ★ THE OLD RECORD COULD NOT EXPRESS A SCHEDULE (2026-08-12, fourth review). It carried the desired version,
// the intent and the reason — so an operator who changed the pilot ring's start date or the maintenance window
// left an audit entry that said "agent_rollout_schedule_updated" and nothing about what the schedule became.
// An audit trail that cannot answer "what did this change" is a list of times somebody touched something.
//
// Canonical JSON of both sides rather than a prose diff: the reader is usually asking "what was it before",
// and a rendering that summarises has to be trusted not to have dropped the field they care about.
func agentRolloutScheduleAuditLog(tenantID string, before, after agentrollout.AgentRolloutPlan,
	evaluator decision.Evaluator, sourceIP string) model.AuditLog {
	rec := agentRolloutAuditLog(tenantID, after, evaluator, sourceIP)
	rec.EventType = "agent_rollout_plan_applied"
	if rec.Metadata == nil {
		rec.Metadata = map[string]any{}
	}
	rec.Metadata["schedule_before"] = canonicalSchedule(before)
	rec.Metadata["schedule_after"] = canonicalSchedule(after)
	rec.Metadata["frozen_before"] = before.Frozen
	rec.Metadata["frozen_after"] = after.Frozen
	return rec
}

// canonicalSchedule renders the parts of a plan that describe WHEN, stably.
func canonicalSchedule(p agentrollout.AgentRolloutPlan) string {
	b, err := json.Marshal(map[string]any{"waves": p.Waves, "window": p.Window})
	if err != nil {
		return "(unrenderable)"
	}
	return string(b)
}

// agentUpdatePublishAuditLog records WHICH BUILD was put in front of a fleet, and under which signature.
//
// ★ WHY THE UNIFORM API-WRITE AUDIT IS NOT ENOUGH (2026-08-12, fifth review). The generic record says an admin
// PUT /admin/agent-updates and got a 200. The question anyone actually asks afterwards — which version, with
// what artifact digest, signed under which key, for which tenant and target — is answered nowhere, because the
// published set holds ONE envelope per target and the next publication overwrites it. By the time somebody
// asks what was being offered on the day a fleet broke, the evidence has been replaced by its successor.
//
// So the digest and the signing key id are carried here explicitly: they are the two fields that let a reader
// tie an installed build on a device back to a decision a named person made.
//
// ★ signing_key_id IS DERIVED FROM VERIFICATION, NOT READ OFF THE ENVELOPE (2026-08-12, sixth review). The
// envelope's own field sits OUTSIDE the signed payload: it can be rewritten without invalidating the
// signature, so recording it would let an admin leave a trail naming a key that did not sign anything. The
// caller passes the key that actually verified; when it is empty the record says so rather than falling back
// to the annotation, because a plausible wrong answer is worse here than a visible gap.
func agentUpdatePublishAuditLog(tenantID string, m agentupdate.Manifest, env agentpolicy.Envelope,
	evaluator decision.Evaluator, sourceIP string, actor adminIdentity, verifiedKeyHex string) model.AuditLog {
	action := "agent_update_publish"
	result := "success"
	reason := fmt.Sprintf("Agent %s published for %s/%s (%s delivery).", m.Version, m.Platform, m.Arch, m.Delivery)
	targetType := "tenant"
	tid := tenantID
	return model.AuditLog{
		ID:             randomEdgeID("audit_", time.Now().UTC()),
		TenantID:       tenantID,
		EventType:      "agent_update_published",
		TargetType:     &targetType,
		TargetID:       &tid,
		Action:         &action,
		Result:         &result,
		Reason:         &reason,
		PolicyBundleID: &evaluator.PolicyBundle.ID,
		EdgeRegionID:   &evaluator.EdgeRegionID,
		EdgeClusterID:  &evaluator.EdgeClusterID,
		SourceIP:       &sourceIP,
		// ★ THE ACTOR BELONGS IN THIS RECORD (2026-08-12, sixth review). The uniform API-write audit carries
		// who; this one carries which build. Splitting them across two entries means an incident reader has to
		// JOIN them — and if either is lost, nothing ties a named person to a digest. Both halves live here.
		ActorUserID: stringPtr(actor.PrincipalID),
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		Metadata: map[string]any{
			"actor_principal": actor.PrincipalID,
			"actor_tenant":    actor.TenantID,
			"actor_method":    actor.AuthMethod,
			"actor_label":     actor.PrincipalLabel,
			"actor_token_id":  actor.APITokenID,
			"platform":        m.Platform,
			"arch":            m.Arch,
			"agent_version":   m.Version,
			"release_channel": m.Channel,
			"delivery":        m.Delivery,
			"artifact_sha256": m.ArtifactSHA256,
			"artifact_size":   m.ArtifactSize,
			"artifact_url":    m.ArtifactURL,
			"signing_key_id":  verifiedSigningKeyID(verifiedKeyHex),
			// The unverified label the publisher attached, kept only so a mismatch is visible to a reader.
			"signing_key_id_claimed": env.SigningKeyID,
			"manifest_sha256":        env.PayloadSHA256,
			"released_at":            m.ReleasedAt,
			"not_after":              m.NotAfter,
		},
	}
}

// verifiedSigningKeyID names the key that actually verified a signature, or says it is unknown.
//
// ★ ONE DERIVATION, AND IT IS NOT THIS FILE'S (2026-08-12, seventh review). This grew a local copy that hashed
// the hex CHARACTERS while agentupdate hashes the decoded key bytes — so a correctly verified key produced an
// audit id that could never equal the manifest's own, and every record read as a mismatch between the
// verified key and the claimed one. The canonical helper is exported now and this defers to it.
func verifiedSigningKeyID(pubKeyHex string) string {
	pubKeyHex = strings.TrimSpace(pubKeyHex)
	if pubKeyHex == "" {
		return "unknown (the verifying key was not recorded)"
	}
	return agentupdate.KeyIDFor(pubKeyHex)
}

// agentRolloutAuditLog records an admin rollout/rollback/freeze change (lifecycle is audited).
func agentRolloutAuditLog(tenantID string, plan agentrollout.AgentRolloutPlan, evaluator decision.Evaluator, sourceIP string) model.AuditLog {
	action := "agent_rollout_" + valueOrDefault(plan.Intent, agentrollout.AgentRolloutIntentRollout)
	result := "success"
	reason := valueOrDefault(plan.Reason, "Agent rollout plan updated by admin.")
	targetType := "tenant"
	tid := tenantID
	return model.AuditLog{
		ID:             randomEdgeID("audit_", time.Now().UTC()),
		TenantID:       tenantID,
		EventType:      "agent_rollout_plan_updated",
		TargetType:     &targetType,
		TargetID:       &tid,
		Action:         &action,
		Result:         &result,
		Reason:         &reason,
		PolicyBundleID: &evaluator.PolicyBundle.ID,
		EdgeRegionID:   &evaluator.EdgeRegionID,
		EdgeClusterID:  &evaluator.EdgeClusterID,
		SourceIP:       &sourceIP,
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		Metadata: map[string]any{
			"rollout_intent":  plan.Intent,
			"desired_version": plan.DesiredVersion,
			"release_channel": plan.ReleaseChannel,
			"frozen":          plan.Frozen,
		},
	}
}

func agentStatusAuditLog(status model.AgentStatus, evaluator decision.Evaluator, sourceIP string) model.AuditLog {
	action := "agent_status"
	result := "success"
	reason := "Agent status reported."
	targetType := "device"
	return model.AuditLog{
		ID:             randomEdgeID("audit_", time.Now().UTC()),
		TenantID:       status.TenantID,
		EventType:      "agent_status_reported",
		TargetType:     &targetType,
		TargetID:       &status.DeviceID,
		Action:         &action,
		Result:         &result,
		Reason:         &reason,
		PolicyBundleID: &evaluator.PolicyBundle.ID,
		EdgeRegionID:   &evaluator.EdgeRegionID,
		EdgeClusterID:  &evaluator.EdgeClusterID,
		SourceIP:       &sourceIP,
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		Metadata: map[string]any{
			"agent_status":          status.Status,
			"bundle_source":         status.BundleSource,
			"device_trust_level":    status.DeviceTrustLevel,
			"policy_bundle_id":      status.PolicyBundleID,
			"policy_bundle_version": status.PolicyBundleVersion,
			"event_timestamp":       status.Timestamp,
			"crash_count":           intMetadataValue(status.Metadata, "crash_count", 0),
			"steering_attempted":    intMetadataValue(status.Metadata, "steering_attempted", 0),
			"steering_succeeded":    intMetadataValue(status.Metadata, "steering_succeeded", 0),
			"steering_failed":       intMetadataValue(status.Metadata, "steering_failed", 0),
			"connect_unsupported":   intMetadataValue(status.Metadata, "connect_unsupported", 0),
		},
	}
}

func humanApprovalEventAuditLog(event model.HumanApprovalEvent, evaluator decision.Evaluator, now time.Time) model.AuditLog {
	action := "human_approval_" + event.ApprovalResult
	result := event.ApprovalResult
	reason := "Human approval event recorded."
	targetType := "human_approval_event"
	return model.AuditLog{
		ID:             randomEdgeID("audit_", now),
		TenantID:       event.TenantID,
		EventType:      "human_approval_event_recorded",
		TargetType:     &targetType,
		TargetID:       &event.ID,
		Action:         &action,
		Result:         &result,
		Reason:         &reason,
		PolicyBundleID: &evaluator.PolicyBundle.ID,
		EdgeRegionID:   &evaluator.EdgeRegionID,
		EdgeClusterID:  &evaluator.EdgeClusterID,
		Timestamp:      now.UTC().Format(time.RFC3339),
		Metadata: map[string]any{
			"approval_source":                        event.ApprovalSource,
			"approval_result":                        event.ApprovalResult,
			"approver_user_id_present":               event.ApproverUserID != nil && strings.TrimSpace(*event.ApproverUserID) != "",
			"subject_user_id_present":                event.SubjectUserID != nil && strings.TrimSpace(*event.SubjectUserID) != "",
			"actor_nhi_id_present":                   event.ActorNHIID != nil && strings.TrimSpace(*event.ActorNHIID) != "",
			"delegated_access_grant_id_present":      event.DelegatedAccessGrantID != nil && strings.TrimSpace(*event.DelegatedAccessGrantID) != "",
			"agent_task_session_id_present":          event.AgentTaskSessionID != nil && strings.TrimSpace(*event.AgentTaskSessionID) != "",
			"application_id_present":                 event.ApplicationID != nil && strings.TrimSpace(*event.ApplicationID) != "",
			"audience_present":                       event.Audience != nil && strings.TrimSpace(*event.Audience) != "",
			"resource_present":                       event.Resource != nil && strings.TrimSpace(*event.Resource) != "",
			"action_type_present":                    event.ActionType != nil && strings.TrimSpace(*event.ActionType) != "",
			"task_id_present":                        event.TaskID != nil && strings.TrimSpace(*event.TaskID) != "",
			"run_id_present":                         event.RunID != nil && strings.TrimSpace(*event.RunID) != "",
			"requested_scope_count":                  len(event.RequestedScopes),
			"reason_present":                         event.Reason != nil && strings.TrimSpace(*event.Reason) != "",
			"evidence_link_present":                  event.EvidenceLink != nil && strings.TrimSpace(*event.EvidenceLink) != "",
			"activated_at_present":                   event.ActivatedAt != nil && strings.TrimSpace(*event.ActivatedAt) != "",
			"expires_at_present":                     event.ExpiresAt != nil && strings.TrimSpace(*event.ExpiresAt) != "",
			"created_at_present":                     strings.TrimSpace(event.CreatedAt) != "",
			"metadata_key_count":                     len(event.Metadata),
			"human_approval_metadata_recorded_scope": "none",
			"runtime_hot_reload":                     false,
			"reason_codes":                           []string{"runtime_human_approval_event_lifecycle"},
		},
	}
}

func nonHumanIdentityAuditLog(identity model.NonHumanIdentity, r *http.Request, evaluator decision.Evaluator, now time.Time) model.AuditLog {
	action := "upsert"
	result := "success"
	reason := "Non-human identity registry entry upserted."
	targetType := "non_human_identity"
	return model.AuditLog{
		ID:             randomEdgeID("audit_", now),
		TenantID:       identity.TenantID,
		ActorUserID:    auditActorPrincipal(r),
		EventType:      "non_human_identity_upserted",
		TargetType:     &targetType,
		TargetID:       &identity.ID,
		Action:         &action,
		Result:         &result,
		Reason:         &reason,
		PolicyBundleID: &evaluator.PolicyBundle.ID,
		EdgeRegionID:   &evaluator.EdgeRegionID,
		EdgeClusterID:  &evaluator.EdgeClusterID,
		Timestamp:      now.UTC().Format(time.RFC3339),
		Metadata: map[string]any{
			"name_present":                 strings.TrimSpace(identity.Name) != "",
			"nhi_type":                     identity.NHIType,
			"owner_user_id_present":        strings.TrimSpace(identity.OwnerUserID) != "",
			"status":                       identity.Status,
			"trust_domain_present":         identity.TrustDomain != nil && strings.TrimSpace(*identity.TrustDomain) != "",
			"issuer_present":               identity.Issuer != nil && strings.TrimSpace(*identity.Issuer) != "",
			"subject_present":              identity.Subject != nil && strings.TrimSpace(*identity.Subject) != "",
			"credential_type_present":      identity.CredentialType != nil && strings.TrimSpace(*identity.CredentialType) != "",
			"allowed_application_id_count": len(identity.AllowedApplicationIDs),
			"allowed_scope_count":          len(identity.AllowedScopes),
			"allowlist_enforced":           identity.AllowlistEnforced,
			"last_used_at_present":         identity.LastUsedAt != nil && strings.TrimSpace(*identity.LastUsedAt) != "",
			"expires_at_present":           identity.ExpiresAt != nil && strings.TrimSpace(*identity.ExpiresAt) != "",
			"metadata_key_count":           len(identity.Metadata),
			"nhi_metadata_recorded_scope":  "none",
			"runtime_hot_reload":           false,
			"reason_codes":                 []string{"admin_nhi_registry_lifecycle"},
		},
	}
}

// ★★ THE ROW SAID WHAT CHANGED AND NOT WHO (2026-08-19, read from Northwind's own audit screen as its
// administrator; fixed by operator decision).
//
// Three rows land together when an operator edits a directory entry inside a customer's organization.
// admin_operate_within_tenant and admin_config_change name the operator; this one — the row that says WHAT
// changed — named nobody, so a customer could see their people directory had been edited and had to correlate
// by timestamp to learn by whom. The envelope's whole premise is that an operator's act is attributable.
//
// It was not an oversight: a contract test asserted ActorUserID must be nil, grouped with SourceIP as a "raw
// source/user field". That grouping is what was wrong. The minimisation this audit exists for is about the
// DIRECTORY SUBJECT — the person in the record, whose subject, email, display name, department and metadata
// are all deliberately reduced to *_present booleans. The acting ADMINISTRATOR is not that person. Recording
// who performed the act takes nothing away from the subject.
func humanIdentityAuditLog(identity model.HumanIdentity, r *http.Request, evaluator decision.Evaluator, now time.Time) model.AuditLog {
	action := "upsert"
	result := "success"
	reason := "Human identity directory entry upserted."
	targetType := "human_identity"
	return model.AuditLog{
		ID:             randomEdgeID("audit_", now),
		TenantID:       identity.TenantID,
		ActorUserID:    auditActorPrincipal(r),
		EventType:      "human_identity_upserted",
		TargetType:     &targetType,
		TargetID:       &identity.ID,
		Action:         &action,
		Result:         &result,
		Reason:         &reason,
		PolicyBundleID: &evaluator.PolicyBundle.ID,
		EdgeRegionID:   &evaluator.EdgeRegionID,
		EdgeClusterID:  &evaluator.EdgeClusterID,
		Timestamp:      now.UTC().Format(time.RFC3339),
		Metadata: map[string]any{
			"subject_present":                        strings.TrimSpace(identity.Subject) != "",
			"email_present":                          identity.Email != nil && strings.TrimSpace(*identity.Email) != "",
			"display_name_present":                   identity.DisplayName != nil && strings.TrimSpace(*identity.DisplayName) != "",
			"source":                                 identity.Source,
			"department_present":                     identity.Department != nil && strings.TrimSpace(*identity.Department) != "",
			"status":                                 identity.Status,
			"last_seen_at_present":                   identity.LastSeenAt != nil && strings.TrimSpace(*identity.LastSeenAt) != "",
			"expires_at_present":                     identity.ExpiresAt != nil && strings.TrimSpace(*identity.ExpiresAt) != "",
			"metadata_key_count":                     len(identity.Metadata),
			"human_identity_metadata_recorded_scope": "none",
			"runtime_hot_reload":                     false,
			"reason_codes":                           []string{"admin_human_identity_directory_lifecycle"},
		},
	}
}

func humanIdentityImportAuditLog(importResult humanidentity.HumanIdentityDirectoryImportResponse, r *http.Request, evaluator decision.Evaluator, now time.Time) model.AuditLog {
	action := "import"
	result := "success"
	reason := "Human identity directory import completed."
	targetType := "human_identity_directory"
	metadata := map[string]any{
		"source":                importResult.Source,
		"import_run_id_present": strings.TrimSpace(importResult.ImportRunID) != "",
		"checkpoint_present":    strings.TrimSpace(importResult.Checkpoint) != "",
		"dry_run":               importResult.DryRun,
		"reconcile_missing":     importResult.ReconcileMissing,
		"requested":             importResult.Requested,
		"upserted":              importResult.Upserted,
		"deactivated":           importResult.Deactivated,
		"active_count":          importResult.ActiveCount,
		"identity_count":        len(importResult.Identities),
		"human_identity_import_metadata_recorded_scope": "none",
		"runtime_hot_reload":                            false,
		"reason_codes":                                  []string{"admin_human_identity_import_lifecycle"},
	}
	return model.AuditLog{
		ID:             randomEdgeID("audit_", now),
		TenantID:       importResult.TenantID,
		ActorUserID:    auditActorPrincipal(r),
		EventType:      "human_identities_imported",
		TargetType:     &targetType,
		Action:         &action,
		Result:         &result,
		Reason:         &reason,
		PolicyBundleID: &evaluator.PolicyBundle.ID,
		EdgeRegionID:   &evaluator.EdgeRegionID,
		EdgeClusterID:  &evaluator.EdgeClusterID,
		Timestamp:      now.UTC().Format(time.RFC3339),
		Metadata:       metadata,
	}
}

func humanIdentitySourcePolicyAuditLog(policy humanidentity.HumanIdentitySourcePolicy, r *http.Request, evaluator decision.Evaluator, now time.Time) model.AuditLog {
	action := "upsert"
	result := "success"
	reason := "Human identity source policy upserted."
	targetType := "human_identity_source_policy"
	return model.AuditLog{
		ID:             randomEdgeID("audit_", now),
		TenantID:       policy.TenantID,
		ActorUserID:    auditActorPrincipal(r),
		EventType:      "human_identity_source_policy_upserted",
		TargetType:     &targetType,
		TargetID:       &policy.Source,
		Action:         &action,
		Result:         &result,
		Reason:         &reason,
		PolicyBundleID: &evaluator.PolicyBundle.ID,
		EdgeRegionID:   &evaluator.EdgeRegionID,
		EdgeClusterID:  &evaluator.EdgeClusterID,
		Timestamp:      now.UTC().Format(time.RFC3339),
		Metadata: map[string]any{
			"source_present":            strings.TrimSpace(policy.Source) != "",
			"connector_type_present":    strings.TrimSpace(policy.ConnectorType) != "",
			"enabled":                   policy.Enabled,
			"reconcile_missing":         policy.ReconcileMissing,
			"expected_interval_seconds": policy.ExpectedIntervalSeconds,
			"stale_after_seconds":       policy.StaleAfterSeconds,
			"metadata_key_count":        len(policy.Metadata),
			"human_identity_source_policy_metadata_recorded_scope": "none",
			"runtime_hot_reload": false,
			"reason_codes":       []string{"admin_human_identity_source_policy_lifecycle"},
		},
	}
}

func delegatedAccessGrantAuditLog(eventType string, grant model.DelegatedAccessGrant, evaluator decision.Evaluator, now time.Time) model.AuditLog {
	action := strings.TrimPrefix(eventType, "delegated_access_grant_")
	result := grant.Status
	reason := "Delegated access grant event recorded."
	targetType := "delegated_access_grant"
	return model.AuditLog{
		ID:             randomEdgeID("audit_", now),
		TenantID:       grant.TenantID,
		EventType:      eventType,
		TargetType:     &targetType,
		TargetID:       &grant.ID,
		Action:         &action,
		Result:         &result,
		Reason:         &reason,
		PolicyBundleID: &evaluator.PolicyBundle.ID,
		EdgeRegionID:   &evaluator.EdgeRegionID,
		EdgeClusterID:  &evaluator.EdgeClusterID,
		Timestamp:      now.UTC().Format(time.RFC3339),
		Metadata: map[string]any{
			"status":                                  grant.Status,
			"subject_user_id_present":                 strings.TrimSpace(grant.SubjectUserID) != "",
			"actor_nhi_id_present":                    strings.TrimSpace(grant.ActorNHIID) != "",
			"device_id_present":                       grant.DeviceID != nil && strings.TrimSpace(*grant.DeviceID) != "",
			"application_id_present":                  grant.ApplicationID != nil && strings.TrimSpace(*grant.ApplicationID) != "",
			"audience_present":                        grant.Audience != nil && strings.TrimSpace(*grant.Audience) != "",
			"resource_present":                        grant.Resource != nil && strings.TrimSpace(*grant.Resource) != "",
			"scope_count":                             len(grant.Scopes),
			"purpose_present":                         grant.Purpose != nil && strings.TrimSpace(*grant.Purpose) != "",
			"task_id_present":                         grant.TaskID != nil && strings.TrimSpace(*grant.TaskID) != "",
			"run_id_present":                          grant.RunID != nil && strings.TrimSpace(*grant.RunID) != "",
			"tool_id_count":                           len(grant.ToolIDs),
			"approval_event_id_present":               grant.ApprovalEventID != nil && strings.TrimSpace(*grant.ApprovalEventID) != "",
			"token_binding_required":                  grant.TokenBindingRequired,
			"max_session_duration_present":            grant.MaxSessionDuration != nil,
			"expires_at_present":                      strings.TrimSpace(grant.ExpiresAt) != "",
			"created_at_present":                      grant.CreatedAt != nil && strings.TrimSpace(*grant.CreatedAt) != "",
			"revoked_at_present":                      grant.RevokedAt != nil && strings.TrimSpace(*grant.RevokedAt) != "",
			"revocation_reason_present":               grant.RevocationReason != nil && strings.TrimSpace(*grant.RevocationReason) != "",
			"metadata_key_count":                      len(grant.Metadata),
			"delegated_grant_metadata_recorded_scope": "none",
			"runtime_hot_reload":                      false,
			"reason_codes":                            []string{"runtime_delegated_access_grant_lifecycle"},
		},
	}
}

func inspectionEventAuditLog(event model.InspectionEvent, evaluator decision.Evaluator, now time.Time) model.AuditLog {
	action := "record_inspection"
	result := "recorded"
	reason := "Inspection event recorded."
	targetType := "inspection_event"
	return model.AuditLog{
		ID:               randomEdgeID("audit_", now),
		TenantID:         event.TenantID,
		EventType:        "inspection_event_recorded",
		TargetType:       &targetType,
		TargetID:         &event.ID,
		Action:           &action,
		Result:           &result,
		Reason:           &reason,
		AccessDecisionID: event.AccessDecisionID,
		PolicyBundleID:   &evaluator.PolicyBundle.ID,
		EdgeRegionID:     &evaluator.EdgeRegionID,
		EdgeClusterID:    &evaluator.EdgeClusterID,
		Timestamp:        now.UTC().Format(time.RFC3339),
		Metadata: map[string]any{
			"tool_call_event_id_present":         event.ToolCallEventID != nil && strings.TrimSpace(*event.ToolCallEventID) != "",
			"session_id_present":                 event.SessionID != nil && strings.TrimSpace(*event.SessionID) != "",
			"user_id_present":                    event.UserID != nil && strings.TrimSpace(*event.UserID) != "",
			"device_id_present":                  event.DeviceID != nil && strings.TrimSpace(*event.DeviceID) != "",
			"application_id_present":             event.ApplicationID != nil && strings.TrimSpace(*event.ApplicationID) != "",
			"inspection_profile_id_present":      event.InspectionProfileID != nil && strings.TrimSpace(*event.InspectionProfileID) != "",
			"inspection_mode_present":            event.InspectionMode != nil && strings.TrimSpace(*event.InspectionMode) != "",
			"content_type_present":               event.ContentType != nil && strings.TrimSpace(*event.ContentType) != "",
			"finding_type_present":               event.FindingType != nil && strings.TrimSpace(*event.FindingType) != "",
			"severity_present":                   event.Severity != nil && strings.TrimSpace(*event.Severity) != "",
			"payload_stored":                     event.PayloadStored,
			"payload_ref_present":                event.PayloadRef != nil && strings.TrimSpace(*event.PayloadRef) != "",
			"masked":                             event.Masked,
			"retention_policy_present":           event.RetentionPolicy != nil && strings.TrimSpace(*event.RetentionPolicy) != "",
			"event_timestamp_present":            strings.TrimSpace(event.Timestamp) != "",
			"metadata_key_count":                 len(event.Metadata),
			"inspection_metadata_recorded_scope": "none",
			"runtime_hot_reload":                 false,
			"reason_codes":                       []string{"runtime_inspection_event_lifecycle"},
		},
	}
}

func toolCallEventAuditLog(event model.ToolCallEvent, evaluator decision.Evaluator, now time.Time) model.AuditLog {
	action := event.ActionType
	result := "recorded"
	if event.Status != nil && *event.Status != "" {
		result = *event.Status
	}
	reason := "Tool call event recorded."
	targetType := "agent_tool"
	return model.AuditLog{
		ID:               randomEdgeID("audit_", now),
		TenantID:         event.TenantID,
		EventType:        "tool_call_event_recorded",
		TargetType:       &targetType,
		TargetID:         stringPtr(event.ToolID),
		Action:           &action,
		Result:           &result,
		Reason:           &reason,
		AccessDecisionID: event.AccessDecisionID,
		PolicyID:         event.PolicyID,
		PolicyBundleID:   &evaluator.PolicyBundle.ID,
		EdgeRegionID:     &evaluator.EdgeRegionID,
		EdgeClusterID:    &evaluator.EdgeClusterID,
		Timestamp:        now.UTC().Format(time.RFC3339),
		Metadata: map[string]any{
			"actor_type":                        "delegated_agent",
			"actor_nhi_id_present":              strings.TrimSpace(event.ActorNHIID) != "",
			"tool_call_event_id_present":        strings.TrimSpace(event.ID) != "",
			"agent_tool_id_present":             strings.TrimSpace(event.ToolID) != "",
			"tool_id_present":                   strings.TrimSpace(event.ToolID) != "",
			"tool_action_type_present":          strings.TrimSpace(event.ActionType) != "",
			"agent_tool_metadata_scope":         "none",
			"agent_task_session_id_present":     event.AgentTaskSessionID != nil && strings.TrimSpace(*event.AgentTaskSessionID) != "",
			"subject_user_id_present":           event.SubjectUserID != nil && strings.TrimSpace(*event.SubjectUserID) != "",
			"delegated_access_grant_id_present": event.DelegatedAccessGrantID != nil && strings.TrimSpace(*event.DelegatedAccessGrantID) != "",
			"human_approval_event_id_present":   event.HumanApprovalEventID != nil && strings.TrimSpace(*event.HumanApprovalEventID) != "",
			"inspection_event_id_present":       event.InspectionEventID != nil && strings.TrimSpace(*event.InspectionEventID) != "",
			"mcp_server_id_present":             event.MCPServerID != nil && strings.TrimSpace(*event.MCPServerID) != "",
			"mcp_metadata_scope":                "none",
			"runtime_environment_id_present":    event.RuntimeEnvironmentID != nil && strings.TrimSpace(*event.RuntimeEnvironmentID) != "",
			"application_id_present":            event.ApplicationID != nil && strings.TrimSpace(*event.ApplicationID) != "",
			"context_boundary_id_present":       event.ContextBoundaryID != nil && strings.TrimSpace(*event.ContextBoundaryID) != "",
			"data_classification_present":       event.DataClassification != nil && strings.TrimSpace(*event.DataClassification) != "",
			"destination_present":               event.Destination != nil && strings.TrimSpace(*event.Destination) != "",
			"token_audience_present":            event.TokenAudience != nil && strings.TrimSpace(*event.TokenAudience) != "",
			"decision_present":                  event.Decision != nil && strings.TrimSpace(*event.Decision) != "",
			"result_summary_present":            event.ResultSummary != nil && strings.TrimSpace(*event.ResultSummary) != "",
			"result_summary_scope":              event.ResultSummaryScope,
			"masked":                            event.Masked,
			"payload_ref_present":               event.PayloadRef != nil && strings.TrimSpace(*event.PayloadRef) != "",
			"retention_policy_present":          event.RetentionPolicy != nil && strings.TrimSpace(*event.RetentionPolicy) != "",
			"tool_payload_recorded":             false,
			"tool_secret_recorded":              false,
			"tool_credentials_recorded":         false,
			"event_timestamp_present":           strings.TrimSpace(event.Timestamp) != "",
			"metadata_key_count":                len(event.Metadata),
			"tool_call_metadata_recorded_scope": "none",
			"runtime_hot_reload":                false,
			"reason_codes":                      []string{"runtime_tool_call_event_lifecycle"},
		},
	}
}

func authenticationEventAuditLog(event model.AuthenticationEvent, session model.Session, evaluator decision.Evaluator) model.AuditLog {
	action := "create_session"
	result := "success"
	reason := "Authentication event created an active session."
	targetType := "session"
	return model.AuditLog{
		ID:                    randomEdgeID("audit_", time.Now().UTC()),
		TenantID:              event.TenantID,
		ActorUserID:           &event.UserID,
		EventType:             "authentication_event_recorded",
		TargetType:            &targetType,
		TargetID:              &session.ID,
		Action:                &action,
		Result:                &result,
		Reason:                &reason,
		PolicyBundleID:        &evaluator.PolicyBundle.ID,
		EdgeRegionID:          &evaluator.EdgeRegionID,
		EdgeClusterID:         &evaluator.EdgeClusterID,
		SessionID:             &session.ID,
		AuthenticationEventID: &event.ID,
		SourceIP:              event.SourceIP,
		Timestamp:             time.Now().UTC().Format(time.RFC3339),
		Metadata: map[string]any{
			"idp_id":             event.IDPID,
			"auth_method":        event.Method,
			"mfa_state":          event.MFAState,
			"amr":                event.AMR,
			"acr":                event.ACR,
			"groups":             event.Metadata["groups"],
			"email":              event.Metadata["email"],
			"break_glass_reason": event.Metadata["break_glass_reason"],
			"ticket_id":          event.Metadata["ticket_id"],
		},
	}
}

func authenticationEventFailureAuditLog(err error, r *http.Request, evaluator decision.Evaluator) model.AuditLog {
	action := "create_session"
	result := "failure"
	reason := err.Error()
	targetType := "authentication_event"
	sourceIP := sourceIPFromRequest(r)
	return model.AuditLog{
		ID:             randomEdgeID("audit_", time.Now().UTC()),
		TenantID:       evaluator.PolicyBundle.TenantID,
		EventType:      "authentication_event_failed",
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
			"path": r.URL.Path,
		},
	}
}

// auditActorPrincipal is who is making THIS request, for the builders that record an administrator's act.
//
// Returns nil rather than a pointer to "" when there is no resolved identity: a row with no actor is a row
// nobody claimed, and a row claiming an empty principal is a row that claims nobody. Only the first is honest.
// Tolerates a nil request — some builders are reachable from paths with no caller, and a nil dereference in an
// audit builder would take down the very write it was recording.
func auditActorPrincipal(r *http.Request) *string {
	if r == nil {
		return nil
	}
	caller, ok := adminIdentityFromRequest(r)
	if !ok {
		return nil
	}
	principal := strings.TrimSpace(caller.PrincipalID)
	if principal == "" {
		return nil
	}
	return &principal
}
