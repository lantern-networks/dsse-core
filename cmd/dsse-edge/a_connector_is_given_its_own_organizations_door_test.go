package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// EdgeEndpoints has been per-organization since 2026-08-29 — connectorEnrollmentEndpointList(tenantID). The
// line UNDER it took ConnectorEnrollmentEdgeCAPEM, a node-wide flag holding the deployment anchor, and there
// was no field for the organization's name at all. So a connector was handed its organization's REGIONS and
// the deployment's NAME and ROOT, on a deployment where every region already served that organization's own
// certificate for its own name (measured 2026-09-07 across twenty organizations: twenty connectors, twenty
// deployment-root pins).
//
// ★ THIS TESTS THE ROUTE, NOT THE BUILDER. The builder took what it was given and always had; the defect was
// in what the call site read.

func issueEnrolmentCommand(t *testing.T, handler http.Handler, tenant string) adminSiteEnrollmentCommandResponse {
	t.Helper()
	create := httptest.NewRequest(http.MethodPost, "/admin/sites",
		strings.NewReader(`{"site_id":"hq","name":"HQ","region":"ap-northeast-1","expected_connector_count":1}`))
	create.Header.Set("x-operate-tenant", tenant)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, create)
	if rec.Code != http.StatusOK {
		t.Fatalf("create site: %d %s", rec.Code, rec.Body.String())
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/sites/hq/enrollment-command",
		strings.NewReader(`{"edge_url":"https://agents.example.test"}`))
	req.Header.Set("x-operate-tenant", tenant)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("enrollment command: %d %s", rec.Code, rec.Body.String())
	}
	var resp adminSiteEnrollmentCommandResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return resp
}

func decodeEnrolmentToken(t *testing.T, token string) map[string]any {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(token))
	if err != nil {
		t.Fatalf("token is not base64url: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("token payload: %v", err)
	}
	return payload
}

func TestAConnectorIsGivenItsOwnOrganizationsDoor(t *testing.T) {
	authority := newTenantTransportAuthority(nil, func([]byte) error { return nil }, nil)
	if _, err := authority.EnsureCA("tenant_kaede", "kaede.example.test"); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator:                    testEvaluator(),
		Registry:                     seedAdminSiteRegistry(t),
		SiteStore:                    newAdminSiteStore(),
		AdminAuth:                    newAdminAuthStore(),
		ConnectorEnrollmentEdgeCAPEM: "-----BEGIN CERTIFICATE-----\ndeployment-anchor\n-----END CERTIFICATE-----\n",
		TenantTransportAuthority:     authority,
	})

	resp := issueEnrolmentCommand(t, handler, "tenant_kaede")

	if resp.Profile.OrganizationServerName != "kaede.example.test" {
		t.Fatalf("the profile does not tell this connector which name to ask for: %+v — it will dial the "+
			"shared name and be served the deployment's certificate, which is what every connector of every "+
			"organization did", resp.Profile)
	}
	if resp.Profile.OrganizationEnrolmentServerName != "enrol.kaede.example.test" {
		t.Fatalf("the connection that carries the CSR needs the enrolment name, got %q",
			resp.Profile.OrganizationEnrolmentServerName)
	}
	if a := resp.Profile.OrganizationAnchorsPEM; !strings.Contains(a, "BEGIN CERTIFICATE") ||
		strings.Contains(a, "deployment-anchor") {
		t.Fatalf("the connector must verify the name above against its ORGANIZATION's authority, got %q", a)
	}

	// The printed command carries only the token, so a connector installed from it must reach the same place
	// as one installed from the file.
	payload := decodeEnrolmentToken(t, resp.Token)
	if payload["org_server_name"] != "kaede.example.test" || payload["org_enrol_server_name"] != "enrol.kaede.example.test" {
		t.Fatalf("the token does not carry the organization's door: %v", payload)
	}
	if a, _ := payload["org_anchors"].(string); !strings.Contains(a, "BEGIN CERTIFICATE") {
		t.Fatalf("the token does not carry the organization's authority: %v", payload)
	}
}

// ★ AND AN ORGANIZATION WITHOUT A DOOR OF ITS OWN IS LEFT ALONE. Absent means the deployment's shared
// certificate, which is what a connector has always been given and stays correct here.
func TestAConnectorOfAnOrganizationWithoutADoorIsUnchanged(t *testing.T) {
	handler := newServerWithConfig(serverConfig{
		Evaluator:                    testEvaluator(),
		Registry:                     seedAdminSiteRegistry(t),
		SiteStore:                    newAdminSiteStore(),
		AdminAuth:                    newAdminAuthStore(),
		ConnectorEnrollmentEdgeCAPEM: "-----BEGIN CERTIFICATE-----\ndeployment-anchor\n-----END CERTIFICATE-----\n",
		TenantTransportAuthority:     newTenantTransportAuthority(nil, func([]byte) error { return nil }, nil),
	})

	resp := issueEnrolmentCommand(t, handler, "tenant_without_a_door")

	if resp.Profile.OrganizationServerName != "" || resp.Profile.OrganizationAnchorsPEM != "" {
		t.Fatalf("an organization with no authority must be offered no name and no anchors: %+v", resp.Profile)
	}
	if !strings.Contains(resp.Profile.EdgeCAPEM, "deployment-anchor") {
		t.Fatalf("the deployment anchor must still be what it pins: %+v", resp.Profile)
	}
	payload := decodeEnrolmentToken(t, resp.Token)
	if _, present := payload["org_server_name"]; present {
		t.Fatalf("the token must not name a door this organization does not have: %v", payload)
	}
}
