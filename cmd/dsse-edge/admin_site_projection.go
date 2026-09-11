package main

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// admin_site_projection.go — Connector UX Slice 1 (/). A Site /
// Connector Group is the primary product object; an individual connector is infrastructure behind a Site. This
// is a READ-ONLY projection: connectors are aggregated by connector_group_id into Sites. There is no Site store
// yet (Slice 1b adds persistence), so a Site exists only while at least one connector references its group id.
//
// Secret-safe by construction: the projection is built from the existing admin-safe adminConnector DTO, so raw
// private base URLs / runtime secrets / hashes can never reach a Site response. Tenant scope and fail-closed
// behaviour are inherited from adminConnectorList (tenant_id required; cross-tenant connectors are excluded by
// the registry).

// adminSiteUngroupedID is the synthetic Site id used to bucket connectors that declare no connector_group_id.
const adminSiteUngroupedID = "(ungrouped)"

// adminSiteHeartbeatFreshness bounds how recent a connector heartbeat must be to count as online when live
// tunnel liveness is unknown (no tunnel manager / older Edge). Tunnel state, when known, always wins.
const adminSiteHeartbeatFreshness = 2 * time.Minute

type adminSiteListResponse struct {
	Sites []adminSite `json:"sites"`
	Count int         `json:"count"`
}

// adminSite is the aggregated, secret-safe view of a Site / Connector Group. It carries only counts and
// distinct sets derived from the connectors in the group — never per-connector secrets. Slice 1b merges in the
// persistent Site metadata (name/region/expected/namespace/deployment/HA) when a Site record exists; those
// fields are all omitempty so a projection-only Site (no persistent record) keeps the Slice 1 shape exactly.
type adminSite struct {
	SiteID          string                `json:"site_id"`
	ConnectorCount  int                   `json:"connector_count"`
	OnlineCount     int                   `json:"online_count"`
	Regions         []string              `json:"regions"`
	RouteSummary    adminSiteRouteSummary `json:"route_summary"`
	Health          string                `json:"health"`
	LastHeartbeatAt string                `json:"last_heartbeat_at,omitempty"`
	// Slice 1b persistent-Site metadata. Present only when a Site record exists; managed = true marks a persistent
	// (admin-created) Site, distinguishing it from a projection-only Site that exists solely because a connector
	// references its group id.
	Managed                bool   `json:"managed,omitempty"`
	Name                   string `json:"name,omitempty"`
	Region                 string `json:"region,omitempty"`
	ExpectedConnectorCount int    `json:"expected_connector_count,omitempty"`
	RoutingNamespace       string `json:"routing_namespace,omitempty"`
	DeploymentType         string `json:"deployment_type,omitempty"`
	HAPolicy               string `json:"ha_policy,omitempty"`
}

// adminSiteRouteSummary aggregates the route layer across every connector in a Site. Counts (not the raw
// destination lists) are surfaced at the Site level for an at-a-glance summary; namespaces are a small distinct
// set used to flag overlapping-CIDR scoping. Destinations themselves are not secrets but are kept at the
// connector drill-down level to keep the Site view compact.
type adminSiteRouteSummary struct {
	FQDNDomainCount int      `json:"fqdn_domain_count"`
	CIDRCount       int      `json:"cidr_count"`
	Namespaces      []string `json:"namespaces"`
}

// adminSiteDetail is a Site plus its member connectors (reusing the existing admin-safe adminConnector DTO).
// Slice 6 adds the (additive, omitempty) HA failover-readiness and multi-region blocks — see
// admin_site_ha_region.go. They are populated only on the single-Site GET, so the Site LIST shape is unchanged.
type adminSiteDetail struct {
	adminSite
	Connectors []adminConnector            `json:"connectors"`
	Failover   *adminSiteFailoverReadiness `json:"failover,omitempty"`
	Region     *adminSiteRegionInfo        `json:"region,omitempty"`
}

// adminSiteList aggregates the authenticated tenant's connectors into Sites by connector_group_id. It is built
// on top of adminConnectorList so tenant scope, fail-closed tenant validation, and secret-safe projection are
// all inherited.
func adminSiteList(ctx context.Context, registry connectorRegistryStore, tenantID string, tunnelStatus connectorTunnelStatusResolver, now time.Time) (adminSiteListResponse, error) {
	listResp, err := adminConnectorList(ctx, registry, tenantID, tunnelStatus)
	if err != nil {
		return adminSiteListResponse{}, err
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	sites := aggregateAdminSites(listResp.Connectors, now)
	return adminSiteListResponse{Sites: sites, Count: len(sites)}, nil
}

// adminSiteGet returns one Site (its aggregate plus member connector DTOs). An unknown / empty Site is reported
// as not-found (false), the same shape as adminConnectorGet, so a cross-tenant or absent group id never leaks.
func adminSiteGet(ctx context.Context, registry connectorRegistryStore, tenantID, siteID string, tunnelStatus connectorTunnelStatusResolver, now time.Time) (adminSiteDetail, bool, error) {
	tenantID = strings.TrimSpace(tenantID)
	siteID = strings.TrimSpace(siteID)
	if tenantID == "" {
		return adminSiteDetail{}, false, fmt.Errorf("tenant_id is required")
	}
	if siteID == "" {
		return adminSiteDetail{}, false, fmt.Errorf("site_id is required")
	}
	if strings.Contains(siteID, "/") {
		return adminSiteDetail{}, false, fmt.Errorf("site_id cannot contain slash")
	}
	listResp, err := adminConnectorList(ctx, registry, tenantID, tunnelStatus)
	if err != nil {
		return adminSiteDetail{}, false, err
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	members := make([]adminConnector, 0, len(listResp.Connectors))
	for _, c := range listResp.Connectors {
		if adminSiteIDForConnector(c) == siteID {
			members = append(members, c)
		}
	}
	if len(members) == 0 {
		return adminSiteDetail{}, false, nil
	}
	// All members share the same site id, so aggregation yields exactly one Site.
	sites := aggregateAdminSites(members, now)
	return adminSiteDetail{adminSite: sites[0], Connectors: members}, true, nil
}

// adminSiteIDForConnector resolves the Site id a connector belongs to: its connector_group_id, or the synthetic
// ungrouped bucket when it declares none.
func adminSiteIDForConnector(c adminConnector) string {
	if gid := strings.TrimSpace(c.ConnectorGroupID); gid != "" {
		return gid
	}
	return adminSiteUngroupedID
}

// aggregateAdminSites folds connector DTOs into Sites by group id. Input is already the admin-safe DTO so the
// result cannot contain secrets.
func aggregateAdminSites(connectors []adminConnector, now time.Time) []adminSite {
	type bucket struct {
		connectorCount int
		onlineCount    int
		regions        map[string]struct{}
		fqdn           map[string]struct{}
		cidr           map[string]struct{}
		namespaces     map[string]struct{}
		lastHeartbeat  string
	}
	buckets := map[string]*bucket{}
	for _, c := range connectors {
		siteID := adminSiteIDForConnector(c)
		b := buckets[siteID]
		if b == nil {
			b = &bucket{
				regions:    map[string]struct{}{},
				fqdn:       map[string]struct{}{},
				cidr:       map[string]struct{}{},
				namespaces: map[string]struct{}{},
			}
			buckets[siteID] = b
		}
		b.connectorCount++
		if adminConnectorOnline(c, now) {
			b.onlineCount++
		}
		if region := strings.TrimSpace(c.EdgeRegionID); region != "" {
			b.regions[region] = struct{}{}
		}
		if c.ReachableRoutes != nil {
			for _, d := range c.ReachableRoutes.FQDNDomains {
				if d = strings.TrimSpace(d); d != "" {
					b.fqdn[d] = struct{}{}
				}
			}
			for _, d := range c.ReachableRoutes.CIDRs {
				if d = strings.TrimSpace(d); d != "" {
					b.cidr[d] = struct{}{}
				}
			}
			if ns := strings.TrimSpace(c.ReachableRoutes.Namespace); ns != "" {
				b.namespaces[ns] = struct{}{}
			}
		}
		if c.LastHeartbeatAt != "" && (b.lastHeartbeat == "" || adminHeartbeatAfter(c.LastHeartbeatAt, b.lastHeartbeat)) {
			b.lastHeartbeat = c.LastHeartbeatAt
		}
	}
	sites := make([]adminSite, 0, len(buckets))
	for siteID, b := range buckets {
		sites = append(sites, adminSite{
			SiteID:         siteID,
			ConnectorCount: b.connectorCount,
			OnlineCount:    b.onlineCount,
			Regions:        adminSiteSortedKeys(b.regions),
			RouteSummary: adminSiteRouteSummary{
				FQDNDomainCount: len(b.fqdn),
				CIDRCount:       len(b.cidr),
				Namespaces:      adminSiteSortedKeys(b.namespaces),
			},
			Health:          adminSiteHealth(b.connectorCount, b.onlineCount),
			LastHeartbeatAt: b.lastHeartbeat,
		})
	}
	sort.Slice(sites, func(i, j int) bool { return sites[i].SiteID < sites[j].SiteID })
	return sites
}

// adminSiteListMerged is the Slice 1b list: the Slice 1 connector projection unioned with the persistent Site
// metadata for the tenant. When siteStore is nil it is exactly adminSiteList (the lab-invariant path). A Site that
// exists only in the projection (a connector references its group id, no record) keeps the projection shape; a
// persistent Site with no connectors yet appears with its metadata and zero counts; both worlds merge on site_id.
func adminSiteListMerged(ctx context.Context, registry connectorRegistryStore, siteStore adminSiteStore, tenantID string, tunnelStatus connectorTunnelStatusResolver, now time.Time) (adminSiteListResponse, error) {
	projection, err := adminSiteList(ctx, registry, tenantID, tunnelStatus, now)
	if err != nil {
		return adminSiteListResponse{}, err
	}
	if siteStore == nil {
		return projection, nil
	}
	metas, err := siteStore.List(ctx, strings.TrimSpace(tenantID))
	if err != nil {
		return adminSiteListResponse{}, err
	}
	byID := map[string]adminSite{}
	order := make([]string, 0, len(projection.Sites)+len(metas))
	for _, s := range projection.Sites {
		if _, ok := byID[s.SiteID]; !ok {
			order = append(order, s.SiteID)
		}
		byID[s.SiteID] = s
	}
	for _, meta := range metas {
		site, ok := byID[meta.SiteID]
		if !ok {
			site = adminSite{SiteID: meta.SiteID, Regions: []string{}, RouteSummary: adminSiteRouteSummary{Namespaces: []string{}}, Health: adminSiteHealth(0, 0)}
			order = append(order, meta.SiteID)
		}
		byID[meta.SiteID] = adminSiteApplyMeta(site, meta)
	}
	sort.Strings(order)
	sites := make([]adminSite, 0, len(order))
	for _, id := range order {
		sites = append(sites, byID[id])
	}
	return adminSiteListResponse{Sites: sites, Count: len(sites)}, nil
}

// adminSiteGetMerged is adminSiteGet plus the persistent Site metadata. A Site that exists only as a persistent
// record (no connector enrolled yet) is still found here (found=true with zero connectors), so an administrator
// can create a Site and immediately open it before any connector is online.
func adminSiteGetMerged(ctx context.Context, registry connectorRegistryStore, siteStore adminSiteStore, tenantID, siteID string, tunnelStatus connectorTunnelStatusResolver, now time.Time) (adminSiteDetail, bool, error) {
	detail, found, err := adminSiteGet(ctx, registry, tenantID, siteID, tunnelStatus, now)
	if err != nil {
		return adminSiteDetail{}, false, err
	}
	if siteStore == nil {
		return detail, found, nil
	}
	meta, ok, err := siteStore.Get(ctx, strings.TrimSpace(tenantID), strings.TrimSpace(siteID))
	if err != nil {
		return adminSiteDetail{}, false, err
	}
	if !found {
		if !ok {
			return adminSiteDetail{}, false, nil
		}
		// Persistent Site with no connectors yet: synthesize an empty projection so it is visible immediately.
		detail = adminSiteDetail{
			adminSite:  adminSite{SiteID: meta.SiteID, Regions: []string{}, RouteSummary: adminSiteRouteSummary{Namespaces: []string{}}, Health: adminSiteHealth(0, 0)},
			Connectors: []adminConnector{},
		}
		found = true
	}
	if ok {
		detail.adminSite = adminSiteApplyMeta(detail.adminSite, meta)
	}
	return detail, found, nil
}

// adminSiteApplyMeta overlays persistent Site metadata onto a projection adminSite and re-derives health using
// the expected connector count: an online count below the expected count is degraded even when every present
// connector is online, because failover capacity is below target.
func adminSiteApplyMeta(site adminSite, meta adminSiteModel) adminSite {
	site.Managed = true
	site.Name = strings.TrimSpace(meta.Name)
	site.Region = strings.TrimSpace(meta.Region)
	site.ExpectedConnectorCount = meta.ExpectedConnectorCount
	site.RoutingNamespace = strings.TrimSpace(meta.RoutingNamespace)
	site.DeploymentType = strings.TrimSpace(meta.DeploymentType)
	site.HAPolicy = strings.TrimSpace(meta.HAPolicy)
	site.Health = adminSiteHealthWithExpected(site.ConnectorCount, site.OnlineCount, meta.ExpectedConnectorCount)
	return site
}

// adminSiteHealthWithExpected derives health when an expected connector count is known. expected <= 0 keeps the
// Slice 1 population-based health. expected > 0: zero online is down, online below expected is degraded (failover
// capacity below target), online at/above expected is healthy.
func adminSiteHealthWithExpected(connectorCount, onlineCount, expected int) string {
	if expected <= 0 {
		return adminSiteHealth(connectorCount, onlineCount)
	}
	switch {
	case onlineCount == 0:
		return "down"
	case onlineCount < expected:
		return "degraded"
	default:
		return "healthy"
	}
}

// adminConnectorOnline reports whether a connector counts as online. Live tunnel state (when known) is
// authoritative; otherwise fall back to heartbeat freshness. Unknown tunnel + stale/absent heartbeat == offline
// (fail-closed: never assert online without evidence).
func adminConnectorOnline(c adminConnector, now time.Time) bool {
	if c.TunnelConnected != nil {
		return *c.TunnelConnected
	}
	heartbeat := strings.TrimSpace(c.LastHeartbeatAt)
	if heartbeat == "" {
		return false
	}
	ts, err := time.Parse(time.RFC3339, heartbeat)
	if err != nil {
		return false
	}
	return !ts.Add(adminSiteHeartbeatFreshness).Before(now)
}

// adminSiteHealth derives a Site health label from connector population and online count.
func adminSiteHealth(connectorCount, onlineCount int) string {
	switch {
	case connectorCount == 0:
		return "unknown"
	case onlineCount == 0:
		return "down"
	case onlineCount == connectorCount:
		return "healthy"
	default:
		return "degraded"
	}
}

// adminHeartbeatAfter reports whether RFC3339 timestamp a is later than b, falling back to lexical comparison
// when either fails to parse (RFC3339 is lexically ordered for the same offset, so this stays sensible).
func adminHeartbeatAfter(a, b string) bool {
	ta, errA := time.Parse(time.RFC3339, a)
	tb, errB := time.Parse(time.RFC3339, b)
	if errA == nil && errB == nil {
		return ta.After(tb)
	}
	return a > b
}

func adminSiteSortedKeys(set map[string]struct{}) []string {
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
