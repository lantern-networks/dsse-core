package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	appcatalog "github.com/lantern-networks/dsse-core/appcatalog"
	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
)

// seedCIDRConnector registers a connector that fronts a CIDR range (Slice 5 collision fixture).
func seedCIDRConnector(t *testing.T, registry *connector.Registry, id, tenant, site, namespace, cidr string) {
	t.Helper()
	if _, err := registry.Register(model.ConnectorRegistration{
		ID:               id,
		TenantID:         tenant,
		ConnectorGroupID: site,
		Name:             id,
		EdgeRegionID:     "local",
		EdgeClusterID:    "local-edge-001",
		PrivateBaseURL:   "http://connector.local",
		Status:           "registered",
		ReachableRoutes:  model.ConnectorReachableRoutes{CIDRs: []string{cidr}, Namespace: namespace},
	}, time.Now().UTC()); err != nil {
		t.Fatalf("seed connector %s: %v", id, err)
	}
}

func publishNetworkApp(t *testing.T, handler http.Handler, appID string, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/applications/"+appID+"/publish", strings.NewReader(body))
	req.Header.Set("content-type", "application/json")
	handler.ServeHTTP(rec, req)
	return rec
}

// TestPrivateAppPublishCIDRCollision drives the full Slice 5 publish path: a network route that overlaps a
// connector's reachable CIDR in the same scope is blocked with 409; a differing namespace or site avoids it; an
// FQDN/web app is never in scope; and an authorized high-risk override (owner role -> admin.connectors.write)
// publishes despite the collision and records the override audit.
func TestPrivateAppPublishCIDRCollision(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	registry := connector.NewRegistry()
	// Connector for the lab tenant fronts 10.0.0.0/8 in namespace "tokyo" / site "site-tokyo".
	seedCIDRConnector(t, registry, "conn_tokyo", "tenant_lab_001", "site-tokyo", "tokyo", "10.0.0.0/8")

	outbox := &recordingAdminAuditOutboxDeadReader{}
	handler := newServerWithConfig(serverConfig{
		Evaluator:        testEvaluator(),
		Writer:           writer,
		Registry:         registry,
		AdminAuth:        newAdminAuthStore(),
		AdminAuditOutbox: outbox,
	})

	// 1) Overlapping CIDR, NO namespace -> ambiguous -> 409 blocked (default), no override audit.
	rec := publishNetworkApp(t, handler, "app_net_ambiguous", `{"name":"Net","destination":"10.10.0.0/16","publish_protocol":"network"}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("ambiguous publish status = %d body=%s, want 409", rec.Code, rec.Body.String())
	}
	var coll struct {
		Error      string `json:"error"`
		Ambiguous  bool   `json:"ambiguous"`
		Collisions []struct {
			WithCIDR string `json:"with_cidr"`
			Relation string `json:"relation"`
		} `json:"collisions"`
		Choices []map[string]any `json:"choices"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &coll); err != nil {
		t.Fatalf("decode collision: %v", err)
	}
	if coll.Error != "cidr_route_collision" || !coll.Ambiguous {
		t.Fatalf("collision body = %#v, want cidr_route_collision + ambiguous", coll)
	}
	if len(coll.Collisions) != 1 || coll.Collisions[0].WithCIDR != "10.0.0.0/8" || coll.Collisions[0].Relation != "contained_by" {
		t.Fatalf("collisions = %#v, want one contained_by 10.0.0.0/8", coll.Collisions)
	}
	if len(coll.Choices) == 0 {
		t.Fatalf("expected the documented resolution choices in 409 body")
	}

	// 2) Same overlap but a DIFFERENT namespace -> separated -> 200.
	if rec := publishNetworkApp(t, handler, "app_net_osaka", `{"name":"Net","destination":"10.10.0.0/16","publish_protocol":"network","routing_namespace":"osaka"}`); rec.Code != http.StatusOK {
		t.Fatalf("different-namespace publish status = %d body=%s, want 200", rec.Code, rec.Body.String())
	}

	// 3) Same namespace but a DIFFERENT site -> separated -> 200.
	if rec := publishNetworkApp(t, handler, "app_net_site_osaka", `{"name":"Net","destination":"10.20.0.0/16","publish_protocol":"network","routing_namespace":"tokyo","connector_group_id":"site-osaka"}`); rec.Code != http.StatusOK {
		t.Fatalf("different-site publish status = %d body=%s, want 200", rec.Code, rec.Body.String())
	}

	// 4) An FQDN/web app is never in the CIDR collision domain -> 200 even with no namespace.
	if rec := publishNetworkApp(t, handler, "app_web", `{"name":"Web","destination":"jira.internal.example.com","destination_port":8443,"publish_protocol":"web"}`); rec.Code != http.StatusOK {
		t.Fatalf("web publish status = %d body=%s, want 200 (not a CIDR)", rec.Code, rec.Body.String())
	}

	// 5) Same-scope overlap (namespace tokyo + site site-tokyo) -> 409 without override.
	if rec := publishNetworkApp(t, handler, "app_net_dup", `{"name":"Dup","destination":"10.10.0.0/16","publish_protocol":"network","routing_namespace":"tokyo","connector_group_id":"site-tokyo"}`); rec.Code != http.StatusConflict {
		t.Fatalf("same-scope publish status = %d body=%s, want 409", rec.Code, rec.Body.String())
	}

	// 6) Same-scope overlap WITH explicit override (owner role holds admin.connectors.write) -> 200 + override audit.
	if rec := publishNetworkApp(t, handler, "app_net_dup", `{"name":"Dup","destination":"10.10.0.0/16","publish_protocol":"network","routing_namespace":"tokyo","connector_group_id":"site-tokyo","override_cidr_collision":true}`); rec.Code != http.StatusOK {
		t.Fatalf("override publish status = %d body=%s, want 200", rec.Code, rec.Body.String())
	}
	foundOverrideAudit := false
	for _, a := range outbox.insertedAudits {
		if a.EventType == "admin_route_collision_override_approved" {
			foundOverrideAudit = true
			encoded, _ := json.Marshal(a)
			if strings.Contains(string(encoded), "10.10.0.0/16") || strings.Contains(string(encoded), "site-tokyo") {
				t.Fatalf("override audit leaked route detail: %s", string(encoded))
			}
		}
	}
	if !foundOverrideAudit {
		t.Fatalf("expected admin_route_collision_override_approved audit, got %v", auditLogEventTypes(outbox.insertedAudits))
	}
}

// TestDetectPublishCIDRCollisionsTenantScoped proves the collision domain is tenant-scoped: a connector under a
// DIFFERENT tenant fronting the same CIDR does not collide; the same tenant's published network entry does.
func TestDetectPublishCIDRCollisionsTenantScoped(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	registry := connector.NewRegistry()
	seedCIDRConnector(t, registry, "conn_other", "tenant_other", "site-x", "ns-x", "10.0.0.0/8")

	catalog := appcatalog.NewStore()
	// Published network route for tenant_lab_001 in the SAME scope as the candidate.
	if _, err := catalog.Upsert(ctx, appcatalog.Entry{
		ApplicationID: "app_existing", TenantID: "tenant_lab_001", ApplicationType: "private_app",
		Destination: "10.0.0.0/8", PublishProtocol: "network", RoutingNamespace: "tokyo", ConnectorGroupID: "site-tokyo",
		Published: true, Status: "active",
	}, "tenant_lab_001", now); err != nil {
		t.Fatalf("seed published entry: %v", err)
	}

	// Candidate for tenant_lab_001 overlapping the OTHER tenant's connector but NOT its own published route's scope.
	// The cross-tenant connector must be ignored; the same-tenant published route in the same scope must collide.
	collisions, err := detectPublishCIDRCollisions(ctx, catalog, registry, "tenant_lab_001", "app_new", "10.10.0.0/16", "tokyo", "site-tokyo")
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if len(collisions) != 1 || collisions[0].Source != "published_app:app_existing" {
		t.Fatalf("collisions = %#v, want exactly the same-tenant published route", collisions)
	}

	// The cross-tenant connector alone (no same-tenant route in scope) -> no collision for tenant_lab_001.
	emptyCatalog := appcatalog.NewStore()
	if got, err := detectPublishCIDRCollisions(ctx, emptyCatalog, registry, "tenant_lab_001", "app_new", "10.10.0.0/16", "ns-x", "site-x"); err != nil || len(got) != 0 {
		t.Fatalf("cross-tenant connector must not collide: got %#v err %v", got, err)
	}
}

// TestCIDRCollisionOverrideAuthorized covers the override permission gate: the override is honored only when it is
// requested AND the caller holds admin.connectors.write — admin.applications.write alone cannot override.
func TestCIDRCollisionOverrideAuthorized(t *testing.T) {
	cases := []struct {
		name     string
		roles    []string
		override bool
		want     bool
	}{
		{"owner-override", []string{"owner"}, true, true},
		{"admin-override", []string{"admin"}, true, true},
		{"admin-no-flag", []string{"admin"}, false, false},
		{"analyst-override", []string{"analyst"}, true, false},   // analyst lacks admin.connectors.write
		{"unknown-role-override", []string{"none"}, true, false}, // no such role -> no permission
	}
	for _, tc := range cases {
		if got := cidrCollisionOverrideAuthorized(tc.roles, tc.override); got != tc.want {
			t.Errorf("%s: cidrCollisionOverrideAuthorized(%v,%v) = %v, want %v", tc.name, tc.roles, tc.override, got, tc.want)
		}
	}
}
