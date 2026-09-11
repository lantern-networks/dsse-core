package main

import (
	"context"
	"fmt"
	"strings"

	appcatalog "github.com/lantern-networks/dsse-core/appcatalog"
	"github.com/lantern-networks/dsse-core/edgeplane"
)

// admin_site_ha_region.go — Connector UX Slice 6 (HA / multi-region visibility, docs/connector_ux_design.md
//// #11, decision ⑦). The Site is the unit of HA, so failover readiness, capacity warnings,
// and the count of IMPACTED apps/routes are surfaced at the Site DETAIL level — never at a single connector. The
// region dimension shows the connectors' home region, the serving edge region, the residency-filtered
// advertised regions, and the tenant residency boundary; when a connector's home region is OUTSIDE that boundary
// the route is unusable for a RESIDENCY reason, surfaced SEPARATELY from any policy denial.
//
// This is ADDITIVE and DETAIL-ONLY: the Site list shape (and the lab-invariant empty-fleet output) is unchanged.
// Both blocks are omitempty pointers, computed only for GET /admin/sites/{site_id}. Secret-safe by construction:
// every input is the admin-safe adminSite / adminConnector projection plus non-secret counts and region tokens.

// adminSiteFailoverReadiness is the HA roll-up for a Site detail. It reuses the Slice 1b expected→degraded
// rule: an online count below the expected count means failover capacity is below target (capacity_warning),
// even when every present connector is online. Failover is "ready" only with at least one spare online connector
// beyond a single point of failure AND no capacity shortfall. Multiple connectors fronting the same route are
// selected health-aware — there is deliberately no fixed active/standby role here.
type adminSiteFailoverReadiness struct {
	ExpectedConnectorCount int    `json:"expected_connector_count"`
	OnlineCount            int    `json:"online_count"`
	FailoverReady          bool   `json:"failover_ready"`
	CapacityWarning        bool   `json:"capacity_warning"`
	DegradedReason         string `json:"degraded_reason,omitempty"`
	AffectedAppCount       int    `json:"affected_app_count"`
	AffectedRouteCount     int    `json:"affected_route_count"`
	ConnectorSelection     string `json:"connector_selection"`
	LastHeartbeatAt        string `json:"last_heartbeat_at,omitempty"`
}

// adminSiteRegionInfo is the multi-region roll-up for a Site detail. home_regions are the connectors' own
// regions; serving_edge_region is THIS edge's region; advertised_regions are the residency-filtered region-map
// endpoints a tenant agent may land on; residency_boundary is the tenant's allowed regions ([] = unrestricted).
// out_of_boundary_regions are connector home regions OUTSIDE the boundary — each makes its route unusable for a
// residency reason (residency_error), which is distinct from a policy denial.
type adminSiteRegionInfo struct {
	HomeRegions          []string `json:"home_regions"`
	ServingEdgeRegion    string   `json:"serving_edge_region,omitempty"`
	AdvertisedRegions    []string `json:"advertised_regions,omitempty"`
	ResidencyBoundary    []string `json:"residency_boundary,omitempty"`
	ResidencyRestricted  bool     `json:"residency_restricted"`
	OutOfBoundaryRegions []string `json:"out_of_boundary_regions,omitempty"`
	ResidencyError       bool     `json:"residency_error"`
}

// computeAdminSiteFailover folds a Site detail (its aggregate + member connectors) plus the count of published
// apps fronted by the Site into the HA readiness block. expected <= 0 (a projection-only / unmanaged Site)
// keeps the population-based reasoning. The route count is the Site's distinct FQDN + CIDR routes — the routes
// that go dark if every connector in the Site is lost.
func computeAdminSiteFailover(detail adminSiteDetail, affectedAppCount int) adminSiteFailoverReadiness {
	expected := detail.ExpectedConnectorCount
	online := detail.OnlineCount
	routeCount := detail.RouteSummary.FQDNDomainCount + detail.RouteSummary.CIDRCount
	capacityWarning := expected > 0 && online < expected
	failoverReady := online >= 2 && !capacityWarning
	reason := ""
	switch {
	case online == 0:
		reason = "No connectors are online; the Site cannot serve its routes."
	case capacityWarning:
		reason = fmt.Sprintf("Failover capacity below target (%d online of %d expected).", online, expected)
	case online == 1:
		reason = "Only one connector is online; there is no failover redundancy."
	}
	return adminSiteFailoverReadiness{
		ExpectedConnectorCount: expected,
		OnlineCount:            online,
		FailoverReady:          failoverReady,
		CapacityWarning:        capacityWarning,
		DegradedReason:         reason,
		AffectedAppCount:       affectedAppCount,
		AffectedRouteCount:     routeCount,
		ConnectorSelection:     "health_aware",
		LastHeartbeatAt:        detail.LastHeartbeatAt,
	}
}

// computeAdminSiteRegionInfo builds the region block for a Site detail. allowedRegions is the tenant residency
// boundary (empty = unrestricted); advertisedRegions is the residency-filtered region-map (already scoped by the
// caller). A connector home region not in a non-empty boundary is reported as out-of-boundary — the route through
// it is unavailable for a residency reason, kept separate from policy.
func computeAdminSiteRegionInfo(detail adminSiteDetail, localRegion string, allowedRegions, advertisedRegions []string) adminSiteRegionInfo {
	homeRegions := append([]string(nil), detail.Regions...)
	if homeRegions == nil {
		homeRegions = []string{}
	}
	restricted := false
	for _, r := range allowedRegions {
		if strings.TrimSpace(r) != "" {
			restricted = true
			break
		}
	}
	info := adminSiteRegionInfo{
		HomeRegions:         homeRegions,
		ServingEdgeRegion:   strings.TrimSpace(localRegion),
		AdvertisedRegions:   advertisedRegions,
		ResidencyRestricted: restricted,
	}
	if restricted {
		info.ResidencyBoundary = append([]string(nil), allowedRegions...)
		out := map[string]struct{}{}
		for _, hr := range homeRegions {
			hr = strings.TrimSpace(hr)
			if hr == "" {
				continue
			}
			if !edgeplane.ContainsRegionFold(allowedRegions, hr) {
				out[hr] = struct{}{}
			}
		}
		if len(out) > 0 {
			info.OutOfBoundaryRegions = adminSiteSortedKeys(out)
			info.ResidencyError = true
		}
	}
	return info
}

// publishedAppCountForSite counts the tenant's PUBLISHED apps fronted by a Site (connector_group_id == siteID) —
// the apps impacted if the Site is degraded/lost. It is tenant-scoped (the catalog filters by tenant) and
// secret-safe (only a count is returned). The synthetic ungrouped bucket and a nil catalog count zero.
func publishedAppCountForSite(ctx context.Context, catalog appcatalog.RuntimeStore, tenantID, siteID string) int {
	siteID = strings.TrimSpace(siteID)
	if catalog == nil || siteID == "" || siteID == adminSiteUngroupedID {
		return 0
	}
	resp, err := catalog.List(ctx, strings.TrimSpace(tenantID), appcatalog.ListOptions{Limit: 1000})
	if err != nil {
		return 0
	}
	count := 0
	for _, entry := range resp.Applications {
		if entry.Published && strings.TrimSpace(entry.ConnectorGroupID) == siteID {
			count++
		}
	}
	return count
}

// adminSiteEnrichDetail layers the Slice 6 HA + region blocks onto a Site detail. It is additive and tolerant of
// nil dependencies: a nil catalog yields a zero affected-app count; a nil tenant-model store / region catalog
// yields an unrestricted region block. It NEVER mutates the underlying projection / connector DTOs.
func adminSiteEnrichDetail(ctx context.Context, detail adminSiteDetail, tenantID string, catalog appcatalog.RuntimeStore, tenantModel adminTenantModelRuntimeStore, regionCatalog *regionEndpointCatalog, localRegion string) adminSiteDetail {
	affectedApps := publishedAppCountForSite(ctx, catalog, tenantID, detail.SiteID)
	failover := computeAdminSiteFailover(detail, affectedApps)
	detail.Failover = &failover

	var allowedRegions []string
	if tenantModel != nil {
		if tenant, err := tenantModel.Get(ctx, strings.TrimSpace(tenantID)); err == nil {
			allowedRegions = tenant.AllowedRegions
		}
	}
	var advertised []string
	if regionCatalog != nil {
		for _, ep := range regionCatalog.allowedRegionEndpoints(allowedRegions, localRegion) {
			advertised = append(advertised, ep.Region)
		}
	}
	region := computeAdminSiteRegionInfo(detail, localRegion, allowedRegions, advertised)
	detail.Region = &region
	return detail
}
