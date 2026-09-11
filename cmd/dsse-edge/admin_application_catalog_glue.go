package main

import (
	"context"
	"strings"
	"time"

	appcatalog "github.com/lantern-networks/dsse-core/appcatalog"
	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/edgeplane"
	"github.com/lantern-networks/dsse-core/model"
)

// newAdminApplicationCatalogStore builds the catalog from the Edge's route profiles + the SaaS catalog. This
// stays in cmd/edge (not internal/appcatalog) because it depends on the edgeplane.ApplicationRouteProfile route logic
// and model.SaaSCatalogEntry; it populates the pure store via Upsert.
func newAdminApplicationCatalogStore(tenantID string, routeProfiles map[string]edgeplane.ApplicationRouteProfile, saasCatalog []model.SaaSCatalogEntry) *appcatalog.Store {
	store := appcatalog.NewStore()
	now := time.Now().UTC()
	ctx := context.Background()
	for applicationID, profile := range routeProfiles {
		p := profile.WithDefaults(applicationID)
		entry := appcatalog.Entry{
			ApplicationID:          applicationID,
			TenantID:               tenantID,
			Name:                   applicationID,
			ApplicationType:        "private_app",
			ServiceFamily:          p.ServiceFamily,
			Protocol:               p.Protocol,
			DestinationRole:        p.DestinationRole,
			ApplicationSensitivity: p.ApplicationSensitivity,
			RouteRef:               "route_profile_configured",
			Status:                 "active",
		}
		// A normalization failure skips the entry (same as the original direct construction).
		_, _ = store.Upsert(ctx, entry, tenantID, now)
	}
	for _, saas := range saasCatalog {
		entryTenantID := strings.TrimSpace(saas.TenantID)
		if entryTenantID == "" {
			entryTenantID = tenantID
		}
		entry := appcatalog.Entry{
			ApplicationID:      saas.SaaSApplicationID,
			TenantID:           entryTenantID,
			Name:               saas.Name,
			ApplicationType:    "saas",
			ServiceFamily:      "saas",
			Protocol:           "https",
			SaaSProvider:       saas.Provider,
			SaaSCategory:       saas.Category,
			SaaSRiskTier:       saas.RiskTier,
			DomainPatternCount: len(saas.DomainPatterns),
			SNIPatternCount:    len(saas.SNIPatterns),
			Tags:               saas.Tags,
			Status:             "active",
		}
		_, _ = store.Upsert(ctx, entry, tenantID, now)
	}
	return store
}

// adminApplicationCatalogAuditLog builds the audit record for a catalog upsert. Kept in cmd/edge for the
// decision.Evaluator binding + the shared audit-id mint.
func adminApplicationCatalogAuditLog(application appcatalog.Entry, evaluator decision.Evaluator, now time.Time) model.AuditLog {
	action := "upsert"
	result := "success"
	reason := "Application Catalog entry upserted."
	targetType := "admin_application"
	return model.AuditLog{
		ID:             randomEdgeID("audit_", now),
		TenantID:       application.TenantID,
		EventType:      "admin_application_upserted",
		TargetType:     &targetType,
		TargetID:       &application.ApplicationID,
		Action:         &action,
		Result:         &result,
		Reason:         &reason,
		PolicyBundleID: &evaluator.PolicyBundle.ID,
		EdgeRegionID:   &evaluator.EdgeRegionID,
		EdgeClusterID:  &evaluator.EdgeClusterID,
		Timestamp:      now.UTC().Format(time.RFC3339),
		Metadata: map[string]any{
			"application_type":                    application.ApplicationType,
			"status":                              application.Status,
			"service_family":                      application.ServiceFamily,
			"protocol":                            application.Protocol,
			"destination_role":                    application.DestinationRole,
			"application_sensitivity":             application.ApplicationSensitivity,
			"route_ref_present":                   application.RouteRef != "",
			"domain_pattern_count":                application.DomainPatternCount,
			"sni_pattern_count":                   application.SNIPatternCount,
			"published":                           application.Published,
			"publish_protocol":                    application.PublishProtocol,
			"destination_present":                 application.Destination != "",
			"connector_group_present":             application.ConnectorGroupID != "",
			"application_metadata_recorded_scope": "none",
			"reason_codes":                        []string{"admin_application_lifecycle"},
		},
	}
}

// adminApplicationDeleteAuditLog builds the audit record for a catalog delete. Secret-safe: only the
// tenant-scoped application id and the lifecycle verb are recorded (no destination/connector material), the same
// non-secret boundary as the upsert/publish audits.
func adminApplicationDeleteAuditLog(tenantID, applicationID string, evaluator decision.Evaluator, now time.Time) model.AuditLog {
	action := "delete"
	result := "success"
	reason := "Application Catalog entry deleted (operator-authored; reachability withdrawn if it was published)."
	targetType := "admin_application"
	return model.AuditLog{
		ID:             randomEdgeID("audit_", now),
		TenantID:       tenantID,
		EventType:      "admin_application_deleted",
		TargetType:     &targetType,
		TargetID:       &applicationID,
		Action:         &action,
		Result:         &result,
		Reason:         &reason,
		PolicyBundleID: &evaluator.PolicyBundle.ID,
		EdgeRegionID:   &evaluator.EdgeRegionID,
		EdgeClusterID:  &evaluator.EdgeClusterID,
		Timestamp:      now.UTC().Format(time.RFC3339),
		Metadata: map[string]any{
			"application_metadata_recorded_scope": "none",
			"reason_codes":                        []string{"admin_application_lifecycle"},
		},
	}
}

// adminApplicationPublishAuditLog builds the audit record for a Slice 2 publish / unpublish. It is non-secret:
// the destination host and connector group id are recorded only as presence booleans — never the raw values —
// alongside the publish app-type enum, so the audit trail proves the lifecycle event without leaking endpoints.
func adminApplicationPublishAuditLog(application appcatalog.Entry, evaluator decision.Evaluator, now time.Time, published bool) model.AuditLog {
	action := "publish"
	reason := "Private App published (reachability only; authorization stays with policy)."
	eventType := "admin_application_published"
	if !published {
		action = "unpublish"
		reason = "Private App unpublished (route reachability withdrawn)."
		eventType = "admin_application_unpublished"
	}
	result := "success"
	targetType := "admin_application"
	return model.AuditLog{
		ID:             randomEdgeID("audit_", now),
		TenantID:       application.TenantID,
		EventType:      eventType,
		TargetType:     &targetType,
		TargetID:       &application.ApplicationID,
		Action:         &action,
		Result:         &result,
		Reason:         &reason,
		PolicyBundleID: &evaluator.PolicyBundle.ID,
		EdgeRegionID:   &evaluator.EdgeRegionID,
		EdgeClusterID:  &evaluator.EdgeClusterID,
		Timestamp:      now.UTC().Format(time.RFC3339),
		Metadata: map[string]any{
			"application_type":                    application.ApplicationType,
			"status":                              application.Status,
			"service_family":                      application.ServiceFamily,
			"application_sensitivity":             application.ApplicationSensitivity,
			"published":                           application.Published,
			"publish_protocol":                    application.PublishProtocol,
			"destination_present":                 application.Destination != "",
			"connector_group_present":             application.ConnectorGroupID != "",
			"application_metadata_recorded_scope": "none",
			"reason_codes":                        []string{"admin_application_publish_lifecycle"},
		},
	}
}
