package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The Console asks for a connector command with an empty body. Answered by a control plane in a region the
// organization is not held to, the node's own door was taken as an operator's override and refused — measured
// on a three-region deployment once leadership moved to region-c for an organization held to region-a.
func TestAConnectorCommandAnsweredInAnotherRegionUsesTheOrganizationsDoor(t *testing.T) {
	catalog := mustCatalog(t, "region-a=https://a.example;region-c=https://c.example")
	previous := regionMap.Catalog()
	regionMap.Set(catalog)
	t.Cleanup(func() { regionMap.Set(previous) })
	tenants := connectorTestTenantModel(t, "tenant-a")
	if _, err := tenants.Put(t.Context(), adminTenantModel{
		TenantID: "tenant-a", AllowedRegions: []string{"region-a"}, HomeRegion: "region-a", OperatorManaged: true,
	}, time.Now()); err != nil {
		t.Fatal(err)
	}
	h := newServerWithConfig(serverConfig{
		Evaluator:        testEvaluator(),
		Registry:         seedAdminSiteRegistry(t),
		SiteStore:        newAdminSiteStore(),
		TenantModelStore: tenants,
		AdminAuth:        newAdminAuthStore(),
		RegionEndpoints:  catalog,
		// This node runs in region-c.
		ConnectorEnrollmentEdgeURL:   "https://c.example",
		ConnectorEnrollmentEdgeCAPEM: "-----BEGIN CERTIFICATE-----\ntest-anchor\n-----END CERTIFICATE-----\n",
	})
	request := func(method, path, body string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("x-operate-tenant", "tenant-a")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if w := request(http.MethodPost, "/admin/sites", `{"site_id":"hq","name":"HQ","expected_connector_count":1}`); w.Code != http.StatusOK {
		t.Fatalf("site create status = %d", w.Code)
	}
	w := request(http.MethodPost, "/admin/sites/hq/enrollment-command", `{}`)
	if w.Code != http.StatusOK {
		t.Fatalf("the Console's request, answered in region-c, status = %d (%s)", w.Code, w.Body.String())
	}
	var issued adminSiteEnrollmentCommandResponse
	if err := json.Unmarshal(w.Body.Bytes(), &issued); err != nil {
		t.Fatal(err)
	}
	payload := decodeEnrolmentToken(t, issued.Token)
	if payload["edge_url"] != "https://a.example" || payload["edge_endpoints"] != "region-a=https://a.example" {
		t.Fatalf("the command does not send the connector to the organization's own region: %v / %v",
			payload["edge_url"], payload["edge_endpoints"])
	}
	// A door the operator names is still held to the organization's regions.
	if w := request(http.MethodPost, "/admin/sites/hq/enrollment-command", `{"edge_url":"https://c.example"}`); w.Code != http.StatusConflict {
		t.Fatalf("a named out-of-boundary door was accepted: status %d", w.Code)
	}
}
