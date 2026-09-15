package main

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/grantstore"
	"github.com/lantern-networks/dsse-core/model"
)

// Grant IDs are also bearer-cookie values. Audits use a stable digest instead of that credential.
// accessGrantAuditPath removes bearer credentials before a route is recorded.
func accessGrantAuditPath(path string) (string, string) {
	for _, prefix := range []string{"/admin/grants/", "/control/admin/grants/"} {
		if strings.HasPrefix(path, prefix) {
			id := strings.TrimSuffix(strings.TrimPrefix(path, prefix), "/revoke")
			return prefix + "{grant_id}/revoke", accessGrantAuditReference(id)
		}
	}
	return path, ""
}
func accessGrantAuditReference(id string) string {
	return fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(strings.TrimSpace(id))))
}
func adminAccessGrantRevocationAuditLog(r *http.Request, g grantstore.Grant, evaluator decision.Evaluator, now time.Time, partial bool) model.AuditLog {
	result := "revoked"
	meta := map[string]any{"applied": true, "user_present": g.UserID != "", "device_bound": g.DeviceID != "", "scope_present": g.Scope != ""}
	if partial {
		result = "partial"
		meta["persistence"] = "unconfirmed"
	}
	if identity, ok := adminIdentityFromRequest(r); ok && identity.TenantID != "" && identity.TenantID != g.TenantID {
		stampOperatorActor(meta, identity)
	}
	return model.AuditLog{ID: randomEdgeID("audit_", now), TenantID: g.TenantID, ActorUserID: auditActorPrincipal(r), EventType: "admin_access_grant_revoked", TargetType: stringPtr("access_grant"), TargetID: stringPtr(accessGrantAuditReference(g.GrantID)), Action: stringPtr("revoke"), Result: &result, EdgeRegionID: &evaluator.EdgeRegionID, EdgeClusterID: &evaluator.EdgeClusterID, Timestamp: now.Format(time.RFC3339), Metadata: meta}
}
