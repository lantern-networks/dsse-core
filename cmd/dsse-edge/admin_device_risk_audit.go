package main

import (
	"net/http"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/enrolledinventory"
	"github.com/lantern-networks/dsse-core/model"
)

// Record the accepted device risk and runtime-save outcome, without the signal body or store error.
func deviceRiskAuditLog(r *http.Request, tenantID string, response adminRiskSignalResponse, evaluator decision.Evaluator, now time.Time) model.AuditLog {
	identity := enrolledinventory.NormalizeIdentity(response.EntityID)
	warning := response.NotStoredDurably != ""
	result := "success"
	if warning {
		result = "partial"
	}
	metadata := map[string]any{"identity": identity, "severity": response.Severity,
		"applied": response.Applied, "high_risk": response.HighRisk, "runtime_persistence_warning": warning}
	record := model.AuditLog{
		ID:             randomEdgeID("audit_device_risk_", now),
		TenantID:       strings.TrimSpace(tenantID),
		ActorUserID:    auditActorPrincipal(r),
		EventType:      "device_risk_changed",
		TargetType:     stringPtr("device"),
		TargetID:       stringPtr(identity),
		Action:         stringPtr("set_device_risk"),
		Result:         stringPtr(result),
		PolicyBundleID: &evaluator.PolicyBundle.ID,
		EdgeRegionID:   &evaluator.EdgeRegionID,
		EdgeClusterID:  &evaluator.EdgeClusterID,
		SourceIP:       stringPtr(sourceIPFromRequest(r)),
		Timestamp:      now.UTC().Format(time.RFC3339),
		Metadata:       metadata,
	}
	if caller, ok := adminIdentityFromRequest(r); ok && record.TenantID != "" &&
		!strings.EqualFold(record.TenantID, strings.TrimSpace(caller.TenantID)) {
		stampOperatorActor(metadata, caller)
	}
	return record
}
