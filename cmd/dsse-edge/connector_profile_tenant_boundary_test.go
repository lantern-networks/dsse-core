package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestConnectorProfileDistinguishesUnavailableTenantAuthorityFromEmptyAllowedDoors(t *testing.T) {
	store := newAdminTenantModelStore(testEvaluator().PolicyBundle, time.Now())
	if _, err := store.Put(context.Background(), adminTenantModel{
		TenantID: "tenant-b", AllowedRegions: []string{"region-b"}, HomeRegion: "region-b",
	}, time.Now()); err != nil {
		t.Fatal(err)
	}
	catalog := mustCatalog(t, "region-a=https://a.example")
	request := func(tenantStore adminTenantModelRuntimeStore) *httptest.ResponseRecorder {
		t.Helper()
		mux := http.NewServeMux()
		registerConnectorProfileRoute(mux,
			func(http.ResponseWriter, *http.Request, string) (string, bool) { return "tenant-b", true },
			"https://fallback.example", func(ctx context.Context, tenant string) ([]regionEndpoint, error) {
				return tenantProfileRegionEndpointsChecked(ctx, catalog, tenantStore, tenant, "https://fallback.example", "region-a")
			}, nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/connectors/conn-b/profile", nil))
		return w
	}
	// The model is readable, and none of its allowed regions is present: this is an authoritative empty list.
	if w := request(store); w.Code != http.StatusOK {
		t.Fatalf("authoritative empty status=%d, want 200", w.Code)
	} else {
		var profile connectorProfile
		if err := json.Unmarshal(w.Body.Bytes(), &profile); err != nil {
			t.Fatal(err)
		}
		if profile.TenantID != "tenant-b" || profile.EdgeEndpoints == nil || len(profile.EdgeEndpoints) != 0 {
			t.Fatalf("authority with zero permitted doors returned %+v", profile)
		}
	}
	// A failed model read cannot be presented as the same valid empty list; the connector must retain its
	// last known good state on the transient error.
	if w := request(unavailableProfileTenantStore{store}); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("unavailable authority status=%d, want 503", w.Code)
	}
}

func TestConnectorProfileUsesAuthenticatedTenantOnSharedEdge(t *testing.T) {
	mux := http.NewServeMux()
	registerConnectorProfileRoute(mux,
		func(http.ResponseWriter, *http.Request, string) (string, bool) { return "tenant-b", true },
		"https://node-a.example", func(_ context.Context, tenant string) ([]regionEndpoint, error) {
			if tenant == "tenant-b" {
				return []regionEndpoint{{Region: "region-b", Endpoint: "https://b.example"}}, nil
			}
			return []regionEndpoint{{Region: "region-a", Endpoint: "https://a.example"}}, nil
		}, nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/connectors/conn-b/profile", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("profile status = %d", w.Code)
	}
	var profile connectorProfile
	if err := json.Unmarshal(w.Body.Bytes(), &profile); err != nil {
		t.Fatal(err)
	}
	if profile.TenantID != "tenant-b" || len(profile.EdgeEndpoints) != 1 || profile.EdgeEndpoints[0] != "region-b=https://b.example" {
		t.Fatalf("profile was not scoped to the authenticated connector tenant: %+v", profile)
	}
}

func TestConnectorProfileRefusesUnverifiedTenant(t *testing.T) {
	mux := http.NewServeMux()
	registerConnectorProfileRoute(mux,
		func(http.ResponseWriter, *http.Request, string) (string, bool) { return "", true },
		"https://node-a.example", nil, nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/connectors/conn-b/profile", nil))
	if w.Code != http.StatusForbidden {
		t.Fatalf("profile status with unverified tenant = %d, want 403", w.Code)
	}
}

func TestConnectorEnrollmentBootstrapIsTenantAllowed(t *testing.T) {
	previous := connectorEnrollmentRegions
	t.Cleanup(func() { connectorEnrollmentRegions = previous })
	queries := 0
	connectorEnrollmentRegions = func(tenant string) []regionEndpoint {
		queries++
		if tenant != "tenant-b" {
			return nil
		}
		return []regionEndpoint{{Region: "region-b", Endpoint: "https://b.example"}}
	}
	if _, _, err := connectorEnrollmentMaterial("tenant-b", "https://a.example"); err == nil {
		t.Fatal("an out-of-boundary bootstrap Edge URL was accepted")
	}
	url, list, err := connectorEnrollmentMaterial("tenant-b", "")
	if err != nil || url != "https://b.example" || list != "region-b=https://b.example" {
		t.Fatalf("one permitted region: url=%q list=%q err=%v", url, list, err)
	}
	if queries != 2 {
		t.Fatalf("each issuance must read exactly one allowed-region snapshot, got %d calls", queries)
	}
	if _, _, err := connectorEnrollmentMaterial("unknown", "https://a.example"); err == nil {
		t.Fatal("unknown tenant acquired a bootstrap door through the fallback")
	}
	connectorEnrollmentRegions = nil
	if url, list, err := connectorEnrollmentMaterial("legacy", "https://single.example"); err != nil || url != "https://single.example" || list != "" {
		t.Fatalf("legacy single-region bootstrap changed: url=%q list=%q err=%v", url, list, err)
	}
}

func TestConnectorEnrollmentCommandRejectsOutOfBoundaryBootstrapBeforeIssuing(t *testing.T) {
	catalog := mustCatalog(t, "region-a=https://a.example;region-b=https://b.example")
	previous := regionMap.Catalog()
	regionMap.Set(catalog)
	t.Cleanup(func() { regionMap.Set(previous) })
	tenants := connectorTestTenantModel(t, "tenant-b")
	if _, err := tenants.Put(t.Context(), adminTenantModel{
		TenantID: "tenant-b", AllowedRegions: []string{"region-b"}, HomeRegion: "region-b", OperatorManaged: true,
	}, time.Now()); err != nil {
		t.Fatal(err)
	}
	h := newServerWithConfig(serverConfig{
		Evaluator:                    testEvaluator(),
		Registry:                     seedAdminSiteRegistry(t),
		SiteStore:                    newAdminSiteStore(),
		TenantModelStore:             tenants,
		AdminAuth:                    newAdminAuthStore(),
		RegionEndpoints:              catalog,
		ConnectorEnrollmentEdgeURL:   "https://b.example",
		ConnectorEnrollmentEdgeCAPEM: "-----BEGIN CERTIFICATE-----\ntest-anchor\n-----END CERTIFICATE-----\n",
	})
	request := func(body string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(http.MethodPost, "/admin/sites/hq/enrollment-command", strings.NewReader(body))
		r.Header.Set("x-operate-tenant", "tenant-b")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	create := httptest.NewRequest(http.MethodPost, "/admin/sites", strings.NewReader(`{"site_id":"hq","name":"HQ","region":"region-b","expected_connector_count":1}`))
	create.Header.Set("x-operate-tenant", "tenant-b")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, create)
	if w.Code != http.StatusOK {
		t.Fatalf("site create status = %d", w.Code)
	}
	if w = request(`{"edge_url":"https://a.example"}`); w.Code != http.StatusConflict {
		t.Fatalf("out-of-boundary issuance status = %d, want 409", w.Code)
	}
	w = request(`{}`)
	if w.Code != http.StatusOK {
		t.Fatalf("permitted issuance status = %d", w.Code)
	}
	var issued adminSiteEnrollmentCommandResponse
	if err := json.Unmarshal(w.Body.Bytes(), &issued); err != nil {
		t.Fatal(err)
	}
	payload := decodeEnrolmentToken(t, issued.Token)
	if payload["edge_url"] != "https://b.example" || payload["edge_endpoints"] != "region-b=https://b.example" {
		t.Fatalf("issued bootstrap or failover list is outside the permitted region")
	}
}
