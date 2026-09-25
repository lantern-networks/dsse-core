package main

import (
	"net/http"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/model"
)

func userRiskAuditLog(r *http.Request, tenant string, response adminRiskSignalResponse, evaluator decision.Evaluator, now time.Time) model.AuditLog {
	result := "success"
	if response.NotStoredDurably != "" {
		result = "partial"
	}
	metadata := map[string]any{
		"severity":                 response.Severity,
		"applied":                  response.Applied,
		"high_risk":                response.HighRisk,
		"user_persistence_warning": response.NotStoredDurably != "",
	}
	record := model.AuditLog{
		ID: randomEdgeID("audit_user_risk_", now), TenantID: strings.TrimSpace(tenant),
		ActorUserID: auditActorPrincipal(r), EventType: "user_risk_changed",
		TargetType: stringPtr("human_identity"), TargetID: stringPtr(response.EntityID),
		Action: stringPtr("set_user_risk"), Result: stringPtr(result),
		PolicyBundleID: &evaluator.PolicyBundle.ID, EdgeRegionID: &evaluator.EdgeRegionID,
		EdgeClusterID: &evaluator.EdgeClusterID, SourceIP: stringPtr(sourceIPFromRequest(r)),
		Timestamp: now.UTC().Format(time.RFC3339), Metadata: metadata,
	}
	if caller, ok := adminIdentityFromRequest(r); ok && record.TenantID != "" && !strings.EqualFold(record.TenantID, strings.TrimSpace(caller.TenantID)) {
		stampOperatorActor(metadata, caller)
	}
	return record
}
