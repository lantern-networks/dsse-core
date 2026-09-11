package main

import (
	"context"
	"net"
	"strings"
	"time"

	appcatalog "github.com/lantern-networks/dsse-core/appcatalog"
	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/model"
)

// connector_cidr_collision.go — Connector UX Slice 5 ( #10 / decision ⑥).
// Publishing a network (CIDR) Private App is collision-prone: overlapping private ranges across sites silently
// shadow one another. This layer detects, at publish time, whether a candidate CIDR overlaps an existing route in
// the SAME scope (namespace or site), and the publish handler blocks it with 409 unless an authorized operator
// supplies an explicit high-risk override. FQDN/web/tcp host routes are never in the CIDR collision domain.
//
// The reachability semantics are unchanged: this guard only governs whether a network route may be PUBLISHED.
// It never authorizes a flow (Published != Allow) and never widens reachability — on any read error it fails
// closed by returning the error to the caller, which blocks the publish.

// detectPublishCIDRCollisions runs the Slice 5 collision check for a candidate network publish. It returns nil
// (no collision) when the destination is not a CIDR — FQDN/web/tcp host routes are out of scope — or when no
// existing route overlaps in the same scope. The existing-route set is the tenant's OTHER published network
// catalog entries plus every connector's declared reachable_routes CIDRs. Tenant-scoped; fail-closed (a catalog
// or registry read error is surfaced, so the publish is blocked rather than allowed on stale/empty state).
func detectPublishCIDRCollisions(ctx context.Context, catalog appcatalog.RuntimeStore, registry connectorRegistryStore, tenantID, applicationID, destination, namespace, site string) ([]connector.CIDRCollision, error) {
	destination = strings.TrimSpace(destination)
	if _, _, err := net.ParseCIDR(destination); err != nil {
		return nil, nil // host destination -> not in the CIDR collision domain
	}
	existing, err := publishedCIDRRoutes(ctx, catalog, registry, tenantID, applicationID)
	if err != nil {
		return nil, err
	}
	candidate := connector.CIDRRoute{CIDR: destination, Namespace: namespace, Site: site}
	return connector.DetectCIDRCollisions(candidate, existing), nil
}

// publishedCIDRRoutes gathers every CIDR-addressed route already known for a tenant: the published network
// catalog entries (excluding the candidate application) and the connectors' declared reachable_routes CIDRs. Each
// route carries its scope (namespace + site/connector-group) and a non-secret source label for the UX report.
func publishedCIDRRoutes(ctx context.Context, catalog appcatalog.RuntimeStore, registry connectorRegistryStore, tenantID, excludeApplicationID string) ([]connector.CIDRRoute, error) {
	tenantID = strings.TrimSpace(tenantID)
	excludeApplicationID = strings.TrimSpace(excludeApplicationID)
	routes := []connector.CIDRRoute{}
	if catalog != nil && tenantID != "" {
		resp, err := catalog.List(ctx, tenantID, appcatalog.ListOptions{ApplicationType: "private_app", Limit: 1000})
		if err != nil {
			return nil, err
		}
		for _, entry := range resp.Applications {
			if !entry.Published || entry.ApplicationID == excludeApplicationID {
				continue
			}
			if strings.TrimSpace(entry.PublishProtocol) != "network" {
				continue // only network (CIDR) routes participate in CIDR collision
			}
			cidr := strings.TrimSpace(entry.Destination)
			if _, _, err := net.ParseCIDR(cidr); err != nil {
				continue
			}
			routes = append(routes, connector.CIDRRoute{
				CIDR:      cidr,
				Namespace: strings.TrimSpace(entry.RoutingNamespace),
				Site:      strings.TrimSpace(entry.ConnectorGroupID),
				Source:    "published_app:" + entry.ApplicationID,
			})
		}
	}
	connectors, err := connectorRegistrationsForTenantWithContext(ctx, registry, tenantID)
	if err != nil {
		return nil, err
	}
	for _, conn := range connectors {
		site := strings.TrimSpace(conn.ConnectorGroupID)
		for _, cidr := range conn.ReachableRoutes.CIDRs {
			cidr = strings.TrimSpace(cidr)
			if _, _, err := net.ParseCIDR(cidr); err != nil {
				continue
			}
			source := "connector:" + conn.ID
			if site != "" {
				source = "site:" + site
			}
			routes = append(routes, connector.CIDRRoute{
				CIDR:      cidr,
				Namespace: strings.TrimSpace(conn.ReachableRoutes.Namespace),
				Site:      site,
				Source:    source,
			})
		}
	}
	return routes, nil
}

// cidrCollisionOverrideAuthorized reports whether a CIDR collision may be overridden: the caller must explicitly
// request the override AND hold admin.connectors.write (the route-infrastructure permission). admin.applications.write
// alone (the publish permission) cannot override a route collision — that is the "explicit high-risk approval".
func cidrCollisionOverrideAuthorized(roles []string, overrideRequested bool) bool {
	return overrideRequested && adminPermissionAllowed(roles, "admin.connectors.write")
}

// cidrCollisionChoices is the set of recommended ways to resolve a CIDR collision, returned in the 409 body so
// the API and the Console wizard present the same guidance. FQDN is recommended; the high-risk override is flagged
// as requiring admin.connectors.write.
func cidrCollisionChoices() []map[string]any {
	return []map[string]any{
		{"id": "use_fqdn", "recommended": true, "label": "Use an FQDN route instead of a CIDR"},
		{"id": "assign_namespace", "label": "Assign a routing namespace to scope this CIDR"},
		{"id": "bind_site", "label": "Bind this route to a specific Site / Connector Group"},
		{"id": "narrow_host_route", "label": "Create a narrow host route instead of a broad CIDR"},
		{"id": "high_risk_override", "label": "Override with explicit high-risk approval", "requires_permission": "admin.connectors.write"},
	}
}

// adminApplicationCIDRCollisionOverrideAuditLog records an approved high-risk CIDR collision override. It is
// secret-safe: the raw destination CIDR, connector group, and namespace are recorded only as presence booleans
// alongside the collision count and publish app-type — never the raw values — so the audit proves the override
// without leaking route endpoints.
func adminApplicationCIDRCollisionOverrideAuditLog(application appcatalog.Entry, collisions []connector.CIDRCollision, evaluator decision.Evaluator, now time.Time) model.AuditLog {
	action := "override"
	result := "success"
	reason := "CIDR route collision override approved (explicit high-risk publish)."
	eventType := "admin_route_collision_override_approved"
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
			"publish_protocol":                    application.PublishProtocol,
			"collision_count":                     len(collisions),
			"namespace_present":                   strings.TrimSpace(application.RoutingNamespace) != "",
			"site_present":                        strings.TrimSpace(application.ConnectorGroupID) != "",
			"destination_present":                 strings.TrimSpace(application.Destination) != "",
			"ambiguous":                           strings.TrimSpace(application.RoutingNamespace) == "",
			"application_metadata_recorded_scope": "none",
			"reason_codes":                        []string{"admin_route_collision_override"},
		},
	}
}
