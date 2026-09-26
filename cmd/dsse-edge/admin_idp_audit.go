package main

import (
	"net/http"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/model"
)

// Audit the accepted target and operation, never connection credentials or endpoints.
func adminIdPChangeAuditLog(r *http.Request, tenant, id, action string, evaluator decision.Evaluator, now time.Time) model.AuditLog {
	metadata := map[string]any{"applied": true}
	audit := model.AuditLog{
		ID: randomEdgeID("audit_idp_", now), TenantID: tenant,
		ActorUserID: auditActorPrincipal(r), EventType: "idp_connection_" + action,
		TargetType: stringPtr("idp_connection"), TargetID: stringPtr(id),
		Action: stringPtr(action), Result: stringPtr("success"),
		PolicyBundleID: &evaluator.PolicyBundle.ID, EdgeRegionID: &evaluator.EdgeRegionID,
		EdgeClusterID: &evaluator.EdgeClusterID, Timestamp: now.Format(time.RFC3339), Metadata: metadata,
	}
	if caller, ok := adminIdentityFromRequest(r); ok && !strings.EqualFold(tenant, caller.TenantID) {
		stampOperatorActor(metadata, caller)
	}
	return audit
}
