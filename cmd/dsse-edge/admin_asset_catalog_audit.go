package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/lantern-networks/dsse-core/assetcatalog"
	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/model"
)

// Record identity and outcome without names, addresses, members or storage errors.
func assetCatalogAuditLog(r *http.Request, kind, id, operation, result string, value any, evaluator decision.Evaluator, now time.Time) model.AuditLog {
	if id == "" {
		id = "new_asset"
	}
	tenant := adminTenantIDFromRequest(r)
	switch item := value.(type) {
	case assetcatalog.Endpoint:
		tenant = item.TenantID
	case assetcatalog.Group:
		tenant = item.TenantID
	case assetcatalog.Service:
		tenant = item.TenantID
	}
	metadata := map[string]any{}
	if value != nil {
		encoded, _ := json.Marshal(value)
		metadata["asset_sha256"] = fmt.Sprintf("%x", sha256.Sum256(encoded))
	}
	return model.AuditLog{ID: randomEdgeID("audit_", now), TenantID: tenant, ActorUserID: auditActorPrincipal(r), EventType: "admin_asset_catalog_changed", TargetType: stringPtr("asset_" + kind), TargetID: &id, Action: &operation, Result: &result, Timestamp: now.UTC().Format(time.RFC3339), EdgeRegionID: &evaluator.EdgeRegionID, EdgeClusterID: &evaluator.EdgeClusterID, Metadata: metadata}
}
