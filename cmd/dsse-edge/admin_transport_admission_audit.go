package main

import (
	"net/http"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/enrolledinventory"
	"github.com/lantern-networks/dsse-core/model"
)

// The common API audit names the caller and route, but the device is in the request body.
// Record that target and the accepted revocation reason separately, without copying the
// request, credentials, or unrelated fields into the audit trail.
func transportAdmissionAuditLog(r *http.Request, tenantID, action, identity, reason string, evaluator decision.Evaluator, now time.Time) model.AuditLog {
	identity = enrolledinventory.NormalizeIdentity(identity)
	metadata := map[string]any{"identity": identity, "action": action}
	record := model.AuditLog{
		ID:             randomEdgeID("audit_transport_admission_", now),
		TenantID:       strings.TrimSpace(tenantID),
		ActorUserID:    auditActorPrincipal(r),
		EventType:      "transport_admission_changed",
		TargetType:     stringPtr("device"),
		TargetID:       stringPtr(identity),
		Action:         stringPtr("transport_admission_" + action),
		Result:         stringPtr("success"),
		PolicyBundleID: &evaluator.PolicyBundle.ID,
		EdgeRegionID:   &evaluator.EdgeRegionID,
		EdgeClusterID:  &evaluator.EdgeClusterID,
		SourceIP:       stringPtr(sourceIPFromRequest(r)),
		Timestamp:      now.UTC().Format(time.RFC3339),
		Metadata:       metadata,
	}
	if action == "revoke" {
		reason = strings.TrimSpace(reason)
		record.Reason = stringPtr(reason)
		metadata["reason"] = reason
	}
	if caller, ok := adminIdentityFromRequest(r); ok && record.TenantID != "" &&
		!strings.EqualFold(record.TenantID, strings.TrimSpace(caller.TenantID)) {
		stampOperatorActor(metadata, caller)
	}
	return record
}
