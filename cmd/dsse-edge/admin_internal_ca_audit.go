package main

import (
	"crypto/sha256"
	"encoding/pem"
	"fmt"
	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/internalca"
	"github.com/lantern-networks/dsse-core/model"
	"net/http"
	"time"
)

// Correlate the authority and outcome without copying certificate material, keys, names or subjects.
func internalAuthorityAuditLog(r *http.Request, a internalca.Authority, action, result string, evaluator decision.Evaluator, now time.Time) model.AuditLog {
	meta := map[string]any{}
	if block, _ := pem.Decode([]byte(a.CertificatePEM)); block != nil && block.Type == "CERTIFICATE" {
		meta["certificate_sha256"] = fmt.Sprintf("%x", sha256.Sum256(block.Bytes))
	}
	if identity, ok := adminIdentityFromRequest(r); ok && identity.TenantID != "" && identity.TenantID != a.TenantID {
		stampOperatorActor(meta, identity)
	}
	return model.AuditLog{ID: randomEdgeID("audit_", now), TenantID: a.TenantID, ActorUserID: auditActorPrincipal(r), EventType: "admin_internal_ca_changed", TargetType: stringPtr("internal_ca"), TargetID: stringPtr(a.ID), Action: &action, Result: &result, EdgeRegionID: &evaluator.EdgeRegionID, EdgeClusterID: &evaluator.EdgeClusterID, Timestamp: now.UTC().Format(time.RFC3339), Metadata: meta}
}
