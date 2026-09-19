package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/inspectionposture"
	"github.com/lantern-networks/dsse-core/model"
)

// Record scope and the chosen controls without copying private destination lists.
func inspectionPostureAuditLog(r *http.Request, before, next inspectionposture.Posture, result string, evaluator decision.Evaluator, now time.Time) model.AuditLog {
	encoded, _ := json.Marshal(next.Normalized())
	meta := map[string]any{"scope": "deployment", "before_mode": before.Mode, "requested_mode": next.Mode, "known_bypass_enabled": next.KnownBypassEnabled, "host_count": len(next.DecryptAllowlistHosts), "decrypt_group_count": len(next.DecryptAllowlistGroups), "bypass_group_count": len(next.BypassGroups), "posture_sha256": fmt.Sprintf("%x", sha256.Sum256(encoded))}
	return model.AuditLog{ID: randomEdgeID("audit_", now), TenantID: adminTenantIDFromRequest(r), ActorUserID: auditActorPrincipal(r), EventType: "admin_inspection_posture_changed", TargetType: stringPtr("deployment_configuration"), TargetID: stringPtr("inspection_posture"), Action: stringPtr("update"), Result: &result, EdgeRegionID: &evaluator.EdgeRegionID, EdgeClusterID: &evaluator.EdgeClusterID, Timestamp: now.UTC().Format(time.RFC3339), Metadata: meta}
}
