package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	appcatalog "github.com/lantern-networks/dsse-core/appcatalog"
	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/edgeplane"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/tunnel"
)

// stubTenantResidencyStore is a minimal adminTenantModelRuntimeStore returning a fixed residency boundary, so the
// Slice 6 region / reachability-residency paths can be driven without a real tenant catalog.
type stubTenantResidencyStore struct{ allowed []string }

func (s stubTenantResidencyStore) Get(context.Context, string) (adminTenantModel, error) {
	return adminTenantModel{TenantID: "tenant_lab_001", AllowedRegions: s.allowed}, nil
}
func (s stubTenantResidencyStore) Update(_ context.Context, t adminTenantModel, _ string, _ time.Time) (adminTenantModel, error) {
	return t, nil
}

// TestComputeAdminSiteFailover proves the HA roll-up: capacity warning derives from expected vs online,
// failover readiness needs a spare online connector AND no shortfall, and the affected app / route counts flow
// through. It mirrors the Slice 1b expected→degraded rule.
func TestComputeAdminSiteFailover(t *testing.T) {
	mkDetail := func(expected, online int) adminSiteDetail {
		return adminSiteDetail{adminSite: adminSite{
			SiteID:                 "tokyo-dc",
			ConnectorCount:         online,
			OnlineCount:            online,
			ExpectedConnectorCount: expected,
			RouteSummary:           adminSiteRouteSummary{FQDNDomainCount: 4, CIDRCount: 2},
			LastHeartbeatAt:        "2026-06-28T12:00:00Z",
		}}
	}
	cases := []struct {
		name            string
		expected        int
		online          int
		wantWarning     bool
		wantReady       bool
		wantReasonEmpty bool
	}{
		{"below_target", 3, 2, true, false, false}, // online < expected -> capacity below target
		{"at_target_redundant", 2, 2, false, true, true},
		{"single_no_redundancy", 1, 1, false, false, false}, // one online -> no failover
		{"none_online", 2, 0, true, false, false},
		{"unmanaged_redundant", 0, 3, false, true, true}, // expected unset -> population only
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := computeAdminSiteFailover(mkDetail(tc.expected, tc.online), 14)
			if f.CapacityWarning != tc.wantWarning {
				t.Fatalf("capacity_warning = %v, want %v (reason=%q)", f.CapacityWarning, tc.wantWarning, f.DegradedReason)
			}
			if f.FailoverReady != tc.wantReady {
				t.Fatalf("failover_ready = %v, want %v", f.FailoverReady, tc.wantReady)
			}
			if (f.DegradedReason == "") != tc.wantReasonEmpty {
				t.Fatalf("degraded_reason = %q, want empty=%v", f.DegradedReason, tc.wantReasonEmpty)
			}
			if f.AffectedAppCount != 14 {
				t.Fatalf("affected_app_count = %d, want 14", f.AffectedAppCount)
			}
			if f.AffectedRouteCount != 6 { // 4 fqdn + 2 cidr
				t.Fatalf("affected_route_count = %d, want 6", f.AffectedRouteCount)
			}
			if f.ConnectorSelection != "health_aware" {
				t.Fatalf("connector_selection = %q, want health_aware (no fixed active/standby)", f.ConnectorSelection)
			}
		})
	}
}

// TestComputeAdminSiteRegionInfo proves the region roll-up: a connector home region outside a non-empty
// residency boundary surfaces as an out-of-boundary route-level residency error; an in-boundary or unrestricted
// tenant has none.
func TestComputeAdminSiteRegionInfo(t *testing.T) {
	detail := adminSiteDetail{adminSite: adminSite{SiteID: "tokyo-dc", Regions: []string{"jp", "us"}}}

	// Restricted to jp only; the us connector region is out of boundary -> residency error.
	r := computeAdminSiteRegionInfo(detail, "local", []string{"jp"}, []string{"jp"})
	if !r.ResidencyRestricted {
		t.Fatal("residency_restricted should be true with a non-empty boundary")
	}
	if !r.ResidencyError || len(r.OutOfBoundaryRegions) != 1 || r.OutOfBoundaryRegions[0] != "us" {
		t.Fatalf("out_of_boundary = %#v / residency_error = %v, want [us]/true", r.OutOfBoundaryRegions, r.ResidencyError)
	}
	if r.ServingEdgeRegion != "local" {
		t.Fatalf("serving_edge_region = %q, want local", r.ServingEdgeRegion)
	}

	// Unrestricted tenant: no boundary, no residency error even with multiple home regions.
	u := computeAdminSiteRegionInfo(detail, "local", nil, nil)
	if u.ResidencyRestricted || u.ResidencyError || len(u.OutOfBoundaryRegions) != 0 {
		t.Fatalf("unrestricted region info = %#v, want no residency restriction/error", u)
	}
}

// TestPublishedAppCountForSite proves the impacted-app count is tenant-scoped and counts ONLY published apps whose
// connector_group_id matches the Site.
func TestPublishedAppCountForSite(t *testing.T) {
	store := appcatalog.NewStore()
	ctx := context.Background()
	now := time.Now().UTC()
	mk := func(id, tenant, group string, published bool) {
		if _, err := store.Upsert(ctx, appcatalog.Entry{
			ApplicationID: id, TenantID: tenant, Name: id, ApplicationType: "private_app",
			ConnectorGroupID: group, Published: published, Destination: "h.internal", PublishProtocol: "web",
		}, tenant, now); err != nil {
			t.Fatalf("upsert %s: %v", id, err)
		}
	}
	mk("app_a", "tenant_lab_001", "tokyo-dc", true)
	mk("app_b", "tenant_lab_001", "tokyo-dc", true)
	mk("app_c", "tenant_lab_001", "tokyo-dc", false)  // not published -> excluded
	mk("app_d", "tenant_lab_001", "osaka-dc", true)   // other site -> excluded
	mk("app_e", "tenant_other_999", "tokyo-dc", true) // other tenant -> excluded

	if got := publishedAppCountForSite(ctx, store, "tenant_lab_001", "tokyo-dc"); got != 2 {
		t.Fatalf("tokyo-dc published count = %d, want 2", got)
	}
	if got := publishedAppCountForSite(ctx, store, "tenant_lab_001", adminSiteUngroupedID); got != 0 {
		t.Fatalf("ungrouped published count = %d, want 0", got)
	}
	if got := publishedAppCountForSite(ctx, nil, "tenant_lab_001", "tokyo-dc"); got != 0 {
		t.Fatalf("nil-catalog count = %d, want 0", got)
	}
}

// TestEvaluateReachabilityResidencySeparateFromPolicy proves the route-level residency error is produced ONLY for
// an out-of-boundary connector region and is independent of policy: local / in-boundary / mesh-eligible cases
// return nil (no route error), while an out-of-boundary region returns a residency error.
func TestEvaluateReachabilityResidency(t *testing.T) {
	// Local region (connector co-located) -> no residency error.
	if e := evaluateReachabilityResidency("local", "local", []string{"local"}, nil, "h.internal"); e != nil {
		t.Fatalf("local connector should have no route error: %#v", e)
	}
	// Remote but in-boundary -> no residency error (hairpin/served by the other region).
	if e := evaluateReachabilityResidency("jp", "local", []string{"local", "jp"}, nil, "h.internal"); e != nil {
		t.Fatalf("in-boundary remote should have no route error: %#v", e)
	}
	// Remote, out of boundary -> residency error.
	e := evaluateReachabilityResidency("jp", "local", []string{"local", "us"}, nil, "h.internal")
	if e == nil || e.Kind != "residency" || e.ConnectorRegion != "jp" {
		t.Fatalf("out-of-boundary route error = %#v, want residency/jp", e)
	}
	// Mesh-eligible out-of-region destination: NOT a residency denial (mesh is in-boundary by definition only when
	// allowed; here the region IS allowed via mesh path) — guard the mesh branch returns nil when allowed.
	if e := evaluateReachabilityResidency("jp", "local", []string{"local", "jp"}, func(string) bool { return true }, "h.internal"); e != nil {
		t.Fatalf("mesh-eligible in-boundary should have no route error: %#v", e)
	}
}

// TestAdminSiteDetailIncludesHAAndRegion drives the full HTTP path: a managed Site with expected=3 but only 2
// online connectors yields a capacity warning + affected app count, and a residency boundary excluding the
// connector region surfaces a site-level residency error. Secret-safe (no private base URLs / hashes).
func TestAdminSiteDetailIncludesHAAndRegion(t *testing.T) {
	registry := connector.NewRegistry()
	now := time.Now().UTC()
	fresh := now.Add(-30 * time.Second).Format(time.RFC3339)
	for _, reg := range []model.ConnectorRegistration{
		{ID: "ha_c1", TenantID: "tenant_lab_001", ConnectorGroupID: "tokyo-dc", Name: "Tokyo 1", EdgeRegionID: "jp",
			PrivateBaseURL: "http://c1-private.example.test", LastHeartbeatAt: fresh, Status: "healthy",
			ReachableRoutes: model.ConnectorReachableRoutes{FQDNDomains: []string{"a.internal", "b.internal"}, CIDRs: []string{"10.0.0.0/16"}}},
		{ID: "ha_c2", TenantID: "tenant_lab_001", ConnectorGroupID: "tokyo-dc", Name: "Tokyo 2", EdgeRegionID: "jp",
			PrivateBaseURL: "http://c2-private.example.test", LastHeartbeatAt: fresh, Status: "healthy"},
	} {
		if _, err := registry.Register(reg, now); err != nil {
			t.Fatalf("register %s: %v", reg.ID, err)
		}
	}

	siteStore := newAdminSiteStore()
	if _, err := siteStore.Upsert(context.Background(), adminSiteModel{SiteID: "tokyo-dc", TenantID: "tenant_lab_001", Name: "Tokyo DC", ExpectedConnectorCount: 3}, now); err != nil {
		t.Fatalf("upsert site: %v", err)
	}

	catalog := appcatalog.NewStore()
	for _, id := range []string{"pub_app_1", "pub_app_2"} {
		if _, err := catalog.Upsert(context.Background(), appcatalog.Entry{ApplicationID: id, TenantID: "tenant_lab_001", Name: id, ApplicationType: "private_app", ConnectorGroupID: "tokyo-dc", Published: true, Destination: "x.internal", PublishProtocol: "web"}, "tenant_lab_001", now); err != nil {
			t.Fatalf("publish %s: %v", id, err)
		}
	}

	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	// Two LIVE tunnels => both connectors online (online 2 of expected 3 => capacity warning, not failover-ready).
	tunnelManager := tunnel.NewManager()
	for _, id := range []string{"ha_c1", "ha_c2"} {
		clientRaw, serverRaw := net.Pipe()
		t.Cleanup(func() { clientRaw.Close(); serverRaw.Close() })
		tunnelManager.Register(id, "tun_"+id, tunnel.NewInProcessConn(clientRaw, true))
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator:               testEvaluator(),
		Writer:                  writer,
		Registry:                registry,
		TunnelManager:           tunnelManager,
		AdminAuth:               newAdminAuthStore(),
		SiteStore:               siteStore,
		ApplicationCatalogStore: catalog,
		TenantModelStore:        stubTenantResidencyStore{allowed: []string{"local", "us"}}, // jp connector is OUT of boundary
	})

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin/sites/tokyo-dc", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Contains(body, "private.example.test") || strings.Contains(body, "runtime_secret_hash") || strings.Contains(body, "sha256:") {
		t.Fatalf("site detail leaked secret/private material: %s", body)
	}
	var detail adminSiteDetail
	if err := json.Unmarshal(rec.Body.Bytes(), &detail); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if detail.Failover == nil {
		t.Fatal("failover block missing")
	}
	if detail.Failover.ExpectedConnectorCount != 3 || detail.Failover.OnlineCount != 2 {
		t.Fatalf("failover counts = %#v, want expected 3 / online 2", detail.Failover)
	}
	if !detail.Failover.CapacityWarning || detail.Failover.FailoverReady {
		t.Fatalf("failover = %#v, want capacity_warning + not ready", detail.Failover)
	}
	if detail.Failover.AffectedAppCount != 2 {
		t.Fatalf("affected_app_count = %d, want 2", detail.Failover.AffectedAppCount)
	}
	// a.internal + b.internal -> 2 distinct FQDN; 10.0.0.0/16 -> 1 CIDR => 3 routes go dark if the Site is lost.
	if detail.Failover.AffectedRouteCount != 3 {
		t.Fatalf("affected_route_count = %d, want 3 (2 fqdn + 1 cidr)", detail.Failover.AffectedRouteCount)
	}
	if detail.Region == nil {
		t.Fatal("region block missing")
	}
	if detail.Region.ServingEdgeRegion != "local" {
		t.Fatalf("serving_edge_region = %q, want local", detail.Region.ServingEdgeRegion)
	}
	if !detail.Region.ResidencyError || len(detail.Region.OutOfBoundaryRegions) != 1 || detail.Region.OutOfBoundaryRegions[0] != "jp" {
		t.Fatalf("region residency = %#v, want residency_error + [jp] out of boundary", detail.Region)
	}
}

// TestReachabilityRouteLevelResidencyError drives the reachability HTTP path with a connector whose region is
// outside the tenant's residency boundary: the result carries a ROUTE-LEVEL residency error that is SEPARATE from
// the policy simulation.
func TestReachabilityRouteLevelResidencyError(t *testing.T) {
	const appID = "app_resid_001"
	registry := connector.NewRegistry()
	now := time.Now().UTC()
	if _, err := registry.Register(model.ConnectorRegistration{
		ID: "conn_resid_001", TenantID: "tenant_lab_001", ConnectorGroupID: "tokyo-dc", Name: "Tokyo DC",
		EdgeRegionID: "jp", EdgeClusterID: "jp-edge-001", ApplicationIDs: []string{appID},
		PrivateBaseURL: "http://connector.local", LastHeartbeatAt: now.Add(-30 * time.Second).Format(time.RFC3339),
		Status: "registered", Metadata: map[string]any{},
	}, now); err != nil {
		t.Fatalf("register: %v", err)
	}

	routeProfiles := map[string]edgeplane.ApplicationRouteProfile{
		appID: {Destination: "jira.internal.example.com", DestinationPort: 8443, Protocol: "tcp", ServiceFamily: "https", DestinationRole: "private_app", ApplicationSensitivity: "medium"},
	}
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator:        testEvaluator(),
		Writer:           writer,
		Registry:         registry,
		RouteProfiles:    routeProfiles,
		AdminAuth:        newAdminAuthStore(),
		TenantModelStore: stubTenantResidencyStore{allowed: []string{"local", "us"}}, // jp is OUT of boundary
	})

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/admin/applications/"+appID+"/reachability", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	var res reachabilityResult
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if res.RouteError == nil || res.RouteError.Kind != "residency" || res.RouteError.ConnectorRegion != "jp" {
		t.Fatalf("route_error = %#v, want residency/jp", res.RouteError)
	}
	// The residency error is SEPARATE from policy: the policy simulation is still present and independent.
	if res.PolicySimulation == nil || res.PolicySimulation["evaluated"] != true {
		t.Fatalf("policy simulation must still be present and independent of the route error: %#v", res.PolicySimulation)
	}
}
