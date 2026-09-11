package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/model"
)

func TestAdminSiteOpenAPIContract(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "openapi", "admin_api.yaml"))
	if err != nil {
		t.Fatalf("read admin OpenAPI contract: %v", err)
	}
	contract := string(data)
	for _, want := range []string{
		"    AdminSite:",
		"    AdminSiteRouteSummary:",
		"    AdminSiteList:",
		"    AdminSiteDetail:",
		"    AdminSiteFailoverReadiness:",
		"    AdminSiteRegionInfo:",
		"  /admin/sites:",
		"  /admin/sites/{site_id}:",
		`$ref: "#/components/schemas/AdminSiteList"`,
		`$ref: "#/components/schemas/AdminSiteDetail"`,
	} {
		if !strings.Contains(contract, want) {
			t.Fatalf("admin OpenAPI contract missing %q", want)
		}
	}
}

func TestAggregateAdminSitesGroupsHealthAndRoutes(t *testing.T) {
	now := time.Date(2026, 6, 28, 12, 0, 0, 0, time.UTC)
	fresh := now.Add(-30 * time.Second).Format(time.RFC3339)
	stale := now.Add(-2 * time.Hour).Format(time.RFC3339)
	connectors := []adminConnector{
		// Tokyo DC: two connectors, one online (tunnel up) one offline (tunnel down) -> degraded.
		{ID: "c1", ConnectorGroupID: "tokyo-dc", EdgeRegionID: "jp", TunnelConnected: boolPtr(true), LastHeartbeatAt: fresh,
			ReachableRoutes: &adminConnectorReachableRoutes{FQDNDomains: []string{"a.internal", "b.internal"}, CIDRs: []string{"10.0.0.0/16"}, Namespace: "site-tokyo"}},
		{ID: "c2", ConnectorGroupID: "tokyo-dc", EdgeRegionID: "jp2", TunnelConnected: boolPtr(false), LastHeartbeatAt: stale,
			ReachableRoutes: &adminConnectorReachableRoutes{FQDNDomains: []string{"b.internal", "c.internal"}, Namespace: "site-tokyo"}},
		// Osaka DC: single connector, online -> healthy.
		{ID: "c3", ConnectorGroupID: "osaka-dc", EdgeRegionID: "jp", TunnelConnected: boolPtr(true), LastHeartbeatAt: fresh},
		// Ungrouped: tunnel unknown but fresh heartbeat -> online -> healthy.
		{ID: "c4", ConnectorGroupID: "", EdgeRegionID: "us", TunnelConnected: nil, LastHeartbeatAt: fresh},
	}

	sites := aggregateAdminSites(connectors, now)
	if len(sites) != 3 {
		t.Fatalf("sites = %d, want 3 (tokyo-dc, osaka-dc, ungrouped)", len(sites))
	}
	byID := map[string]adminSite{}
	for _, s := range sites {
		byID[s.SiteID] = s
	}

	tokyo, ok := byID["tokyo-dc"]
	if !ok {
		t.Fatalf("missing tokyo-dc site: %#v", sites)
	}
	if tokyo.ConnectorCount != 2 || tokyo.OnlineCount != 1 || tokyo.Health != "degraded" {
		t.Fatalf("tokyo-dc = %#v, want 2 connectors / 1 online / degraded", tokyo)
	}
	if len(tokyo.Regions) != 2 || tokyo.Regions[0] != "jp" || tokyo.Regions[1] != "jp2" {
		t.Fatalf("tokyo-dc regions = %#v, want sorted [jp jp2]", tokyo.Regions)
	}
	// Distinct FQDNs across both connectors: a,b,c -> 3. One CIDR. One namespace.
	if tokyo.RouteSummary.FQDNDomainCount != 3 || tokyo.RouteSummary.CIDRCount != 1 {
		t.Fatalf("tokyo-dc route summary = %#v, want 3 fqdn / 1 cidr", tokyo.RouteSummary)
	}
	if len(tokyo.RouteSummary.Namespaces) != 1 || tokyo.RouteSummary.Namespaces[0] != "site-tokyo" {
		t.Fatalf("tokyo-dc namespaces = %#v, want [site-tokyo]", tokyo.RouteSummary.Namespaces)
	}
	if tokyo.LastHeartbeatAt != fresh {
		t.Fatalf("tokyo-dc last heartbeat = %q, want freshest %q", tokyo.LastHeartbeatAt, fresh)
	}

	if osaka := byID["osaka-dc"]; osaka.Health != "healthy" || osaka.OnlineCount != 1 {
		t.Fatalf("osaka-dc = %#v, want healthy / 1 online", osaka)
	}
	ungrouped, ok := byID[adminSiteUngroupedID]
	if !ok {
		t.Fatalf("missing ungrouped bucket: %#v", sites)
	}
	if ungrouped.Health != "healthy" || ungrouped.OnlineCount != 1 {
		t.Fatalf("ungrouped = %#v, want healthy via heartbeat fallback", ungrouped)
	}
}

func TestAdminSiteHealthBoundaries(t *testing.T) {
	cases := []struct {
		total, online int
		want          string
	}{
		{0, 0, "unknown"},
		{2, 0, "down"},
		{2, 1, "degraded"},
		{2, 2, "healthy"},
	}
	for _, tc := range cases {
		if got := adminSiteHealth(tc.total, tc.online); got != tc.want {
			t.Fatalf("adminSiteHealth(%d,%d) = %q, want %q", tc.total, tc.online, got, tc.want)
		}
	}
}

func TestAdminConnectorOnlineFallsBackToHeartbeatFreshness(t *testing.T) {
	now := time.Date(2026, 6, 28, 12, 0, 0, 0, time.UTC)
	// Tunnel state, when known, is authoritative even with a stale heartbeat.
	if adminConnectorOnline(adminConnector{TunnelConnected: boolPtr(true), LastHeartbeatAt: now.Add(-time.Hour).Format(time.RFC3339)}, now) != true {
		t.Fatal("known tunnel-up should be online regardless of heartbeat")
	}
	if adminConnectorOnline(adminConnector{TunnelConnected: boolPtr(false), LastHeartbeatAt: now.Format(time.RFC3339)}, now) != false {
		t.Fatal("known tunnel-down should be offline regardless of heartbeat")
	}
	// Unknown tunnel -> heartbeat freshness decides.
	if adminConnectorOnline(adminConnector{LastHeartbeatAt: now.Add(-30 * time.Second).Format(time.RFC3339)}, now) != true {
		t.Fatal("unknown tunnel + fresh heartbeat should be online")
	}
	if adminConnectorOnline(adminConnector{LastHeartbeatAt: now.Add(-time.Hour).Format(time.RFC3339)}, now) != false {
		t.Fatal("unknown tunnel + stale heartbeat should be offline")
	}
	if adminConnectorOnline(adminConnector{}, now) != false {
		t.Fatal("unknown tunnel + no heartbeat should be offline (fail-closed)")
	}
}

func TestAdminSiteAPIAggregatesTenantScopedAndSecretSafe(t *testing.T) {
	registry := seedAdminSiteRegistry(t)
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(),
		Registry:  registry,
		AdminAuth: newAdminAuthStore(),
	})

	req := httptest.NewRequest(http.MethodGet, "/admin/sites", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Contains(body, "runtime_secret_hash") || strings.Contains(body, "sha256:") ||
		strings.Contains(body, "private.example.test") || strings.Contains(body, "private_base_url\"") {
		t.Fatalf("site list leaked secret/private material: %s", body)
	}
	var list adminSiteListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode site list: %v", err)
	}
	// Only tenant_lab_001 connectors are aggregated; the other tenant's group must not appear.
	if list.Count != 2 {
		t.Fatalf("site count = %d, want 2 (tokyo-dc + ungrouped), sites=%#v", list.Count, list.Sites)
	}
	byID := map[string]adminSite{}
	for _, s := range list.Sites {
		byID[s.SiteID] = s
		if s.SiteID == "other-tenant-group" {
			t.Fatalf("cross-tenant site leaked: %#v", list.Sites)
		}
	}
	tokyo, ok := byID["tokyo-dc"]
	if !ok {
		t.Fatalf("missing tokyo-dc: %#v", list.Sites)
	}
	if tokyo.ConnectorCount != 2 {
		t.Fatalf("tokyo-dc connector_count = %d, want 2", tokyo.ConnectorCount)
	}
	if _, ok := byID[adminSiteUngroupedID]; !ok {
		t.Fatalf("missing ungrouped bucket: %#v", list.Sites)
	}

	// Detail for a real Site returns member connectors using the secret-safe DTO.
	detailReq := httptest.NewRequest(http.MethodGet, "/admin/sites/tokyo-dc", nil)
	detailRec := httptest.NewRecorder()
	handler.ServeHTTP(detailRec, detailReq)
	if detailRec.Code != http.StatusOK {
		t.Fatalf("detail status = %d, body=%s", detailRec.Code, detailRec.Body.String())
	}
	if strings.Contains(detailRec.Body.String(), "private.example.test") || strings.Contains(detailRec.Body.String(), "runtime_secret_hash") {
		t.Fatalf("site detail leaked secret/private material: %s", detailRec.Body.String())
	}
	var detail adminSiteDetail
	if err := json.Unmarshal(detailRec.Body.Bytes(), &detail); err != nil {
		t.Fatalf("decode site detail: %v", err)
	}
	if detail.SiteID != "tokyo-dc" || len(detail.Connectors) != 2 {
		t.Fatalf("site detail = %#v, want tokyo-dc with 2 connectors", detail)
	}

	// Cross-tenant / unknown Site id is 404, never a leak.
	for _, path := range []string{"/admin/sites/other-tenant-group", "/admin/sites/does-not-exist"} {
		missReq := httptest.NewRequest(http.MethodGet, path, nil)
		missRec := httptest.NewRecorder()
		handler.ServeHTTP(missRec, missReq)
		if missRec.Code != http.StatusNotFound {
			t.Fatalf("GET %s status = %d, want 404", path, missRec.Code)
		}
	}
}

func TestAdminSiteAPIEmptyWhenNoConnectors(t *testing.T) {
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(),
		Registry:  connector.NewRegistry(),
		AdminAuth: newAdminAuthStore(),
	})
	req := httptest.NewRequest(http.MethodGet, "/admin/sites", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var list adminSiteListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode site list: %v", err)
	}
	if list.Count != 0 || len(list.Sites) != 0 {
		t.Fatalf("empty fleet site list = %#v, want zero sites (lab-invariant)", list)
	}
}

func seedAdminSiteRegistry(t *testing.T) *connector.Registry {
	t.Helper()
	registry := connector.NewRegistry()
	now := time.Date(2026, 6, 1, 1, 2, 3, 0, time.UTC)
	regs := []model.ConnectorRegistration{
		{
			ID: "site_conn_001", TenantID: "tenant_lab_001", ConnectorGroupID: "tokyo-dc", Name: "Tokyo 1",
			EdgeRegionID: "jp", PrivateBaseURL: "http://conn1-private.example.test", Status: "healthy",
			ReachableRoutes: model.ConnectorReachableRoutes{FQDNDomains: []string{"a.internal.example.test"}, CIDRs: []string{"10.20.0.0/16"}, Namespace: "site-tokyo"},
			Metadata:        map[string]any{"runtime_secret_hash": connectorRuntimeSecretHash("seed-secret-aaaa-0001")},
		},
		{
			ID: "site_conn_002", TenantID: "tenant_lab_001", ConnectorGroupID: "tokyo-dc", Name: "Tokyo 2",
			EdgeRegionID: "jp", PrivateBaseURL: "http://conn2-private.example.test", Status: "healthy",
		},
		{
			ID: "site_conn_003", TenantID: "tenant_lab_001", Name: "Loose connector",
			EdgeRegionID: "us", PrivateBaseURL: "http://conn3-private.example.test", Status: "healthy",
		},
		{
			ID: "site_conn_other", TenantID: "tenant_other_001", ConnectorGroupID: "other-tenant-group",
			PrivateBaseURL: "http://other-private.example.test", Status: "healthy",
		},
	}
	for _, reg := range regs {
		if _, err := registry.Register(reg, now); err != nil {
			t.Fatalf("register %s: %v", reg.ID, err)
		}
	}
	return registry
}
