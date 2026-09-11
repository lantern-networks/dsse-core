package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
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
)

// TestRouteProfilesWithPublishedCatalogMergeAndFallback covers the runtime publish->route merge (Slice 2):
// a PUBLISHED catalog entry contributes a route, an UN-published entry does not (lab invariant), the merge is
// tenant-scoped, and the startup file routes survive as the fallback.
func TestRouteProfilesWithPublishedCatalogMergeAndFallback(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	store := appcatalog.NewStore()
	// Published web app for tenant A -> should become a route.
	if _, err := store.Upsert(ctx, appcatalog.Entry{
		ApplicationID:   "app_pub_web_001",
		TenantID:        "tenant_a",
		ApplicationType: "private_app",
		Destination:     "jira.internal.example.com",
		DestinationPort: 8443,
		PublishProtocol: "web",
		Published:       true,
		Status:          "active",
	}, "tenant_a", now); err != nil {
		t.Fatalf("upsert published web app: %v", err)
	}
	// Authored-but-not-published app for tenant A -> must NOT contribute a route.
	if _, err := store.Upsert(ctx, appcatalog.Entry{
		ApplicationID:   "app_draft_002",
		TenantID:        "tenant_a",
		ApplicationType: "private_app",
		Destination:     "draft.internal.example.com",
		DestinationPort: 9000,
		PublishProtocol: "tcp",
		Published:       false,
		Status:          "draft",
	}, "tenant_a", now); err != nil {
		t.Fatalf("upsert draft app: %v", err)
	}
	// Published app under a DIFFERENT tenant -> must not leak across tenants.
	if _, err := store.Upsert(ctx, appcatalog.Entry{
		ApplicationID:   "app_other_tenant_003",
		TenantID:        "tenant_b",
		ApplicationType: "private_app",
		Destination:     "secret.tenantb.example.com",
		DestinationPort: 443,
		PublishProtocol: "web",
		Published:       true,
		Status:          "active",
	}, "tenant_b", now); err != nil {
		t.Fatalf("upsert other-tenant app: %v", err)
	}

	base := map[string]edgeplane.ApplicationRouteProfile{
		"app_file_route_001": {Destination: "file.internal.example.com", DestinationPort: 22, Protocol: "tcp", ServiceFamily: "ssh"},
	}

	merged := edgeplane.RouteProfilesWithPublishedCatalog(base, store, "tenant_a")

	// File route survives as the fallback.
	fileRoute, ok := merged["app_file_route_001"]
	if !ok || fileRoute.Destination != "file.internal.example.com" {
		t.Fatalf("file route missing/altered: %#v", merged["app_file_route_001"])
	}
	// Published web app is now a resolvable route with the published destination/port.
	pub, ok := merged["app_pub_web_001"]
	if !ok {
		t.Fatalf("published web app not merged: %#v", merged)
	}
	if pub.Destination != "jira.internal.example.com" || pub.DestinationPort != 8443 || pub.ServiceFamily != "https" {
		t.Fatalf("published route = %#v, want jira.internal.example.com:8443 https", pub)
	}
	// Un-published app does not appear.
	if _, ok := merged["app_draft_002"]; ok {
		t.Fatalf("un-published draft app must not produce a route: %#v", merged["app_draft_002"])
	}
	// Tenant isolation: tenant_b's published app must not be in tenant_a's merge.
	if _, ok := merged["app_other_tenant_003"]; ok {
		t.Fatalf("cross-tenant published app leaked into tenant_a merge")
	}

	// No published apps for a tenant -> base returned unchanged (byte-for-byte same map: lab invariant).
	baseForB := map[string]edgeplane.ApplicationRouteProfile{"only": {Destination: "x"}}
	emptyStore := appcatalog.NewStore()
	if got := edgeplane.RouteProfilesWithPublishedCatalog(baseForB, emptyStore, "tenant_a"); len(got) != 1 || got["only"].Destination != "x" {
		t.Fatalf("empty-catalog merge altered base: %#v", got)
	}
	// Nil store / empty tenant -> base unchanged (fail-closed to startup routes).
	if got := edgeplane.RouteProfilesWithPublishedCatalog(base, nil, "tenant_a"); len(got) != 1 {
		t.Fatalf("nil store should return base unchanged: %#v", got)
	}
}

// TestApplicationRouteProfileFromPublishedEntryProtocolMapping covers the publish app-type -> service-family
// mapping and the fail-closed empty-destination guard.
func TestApplicationRouteProfileFromPublishedEntryProtocolMapping(t *testing.T) {
	web, ok := edgeplane.ApplicationRouteProfileFromPublishedEntry(appcatalog.Entry{ApplicationID: "a", Destination: "w.example.com", DestinationPort: 8443, PublishProtocol: "web"})
	if !ok || web.ServiceFamily != "https" || web.DestinationPort != 8443 {
		t.Fatalf("web mapping = %#v ok=%v", web, ok)
	}
	tcp, ok := edgeplane.ApplicationRouteProfileFromPublishedEntry(appcatalog.Entry{ApplicationID: "a", Destination: "db.example.com", DestinationPort: 5432, PublishProtocol: "tcp"})
	if !ok || tcp.ServiceFamily != "tcp" || tcp.DestinationPort != 5432 {
		t.Fatalf("tcp mapping = %#v ok=%v", tcp, ok)
	}
	if _, ok := edgeplane.ApplicationRouteProfileFromPublishedEntry(appcatalog.Entry{ApplicationID: "a", Destination: "  ", PublishProtocol: "web"}); ok {
		t.Fatalf("empty destination must be un-routable (fail-closed)")
	}
}

// TestPrivateAppPublishIsNotAllow drives the full edge path: publishing a Private App creates reachability,
// but the flow stays DENY until a policy authorizes it. It also verifies that the publish that flips a route
// (a non-default port) actually changes the live decision once a matching policy exists.
func TestPrivateAppPublishIsNotAllow(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	// Allow policy bound specifically to the published app on its PUBLISHED port (8443). Until the app is
	// published on 8443 the route resolves to the default https/443 and this policy cannot match.
	evaluator := testEvaluatorWithPolicies([]model.Policy{{
		ID:       "pol_pub_web_allow_001",
		TenantID: "tenant_lab_001",
		Priority: 100,
		Conditions: map[string]any{
			"actor_type":       "human",
			"application_id":   "app_pub_web_001",
			"service_family":   "https",
			"destination_port": "8443",
		},
		Action: model.PolicyAction{Decision: "allow"},
		Status: "active",
	}})
	handler := newServerWithClient(evaluator, writer, connector.NewRegistry(), &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"content-type": []string{"application/json"}},
			Body:       io.NopCloser(bytes.NewBufferString(`{"status":"reachable_via_connector"}`)),
		}, nil
	})})

	registerReq := httptest.NewRequest(http.MethodPost, "/connectors/register", strings.NewReader(`{
		"id":"conn_pub_001",
		"tenant_id":"tenant_lab_001",
		"connector_group_id":"cgrp_lab_001",
		"name":"Lab Connector",
		"edge_region_id":"local",
		"edge_cluster_id":"local-edge-001",
		"application_ids":["app_pub_web_001","app_pub_noallow_001"],
		"private_base_url":"http://connector.local",
		"status":"registered",
		"metadata":{}
	}`))
	registerReq.Header.Set(connectorSecretHeader, defaultConnectorSecret)
	registerRec := httptest.NewRecorder()
	handler.ServeHTTP(registerRec, registerReq)
	if registerRec.Code != http.StatusCreated {
		t.Fatalf("register status = %d body=%s", registerRec.Code, registerRec.Body.String())
	}

	route := func(appID string) int {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/apps/"+appID+"?connector_id=conn_pub_001", nil))
		return rec.Code
	}

	// Before publish: the app resolves to the default https/443 route -> policy bound to :8443 cannot match ->
	// default-deny (fail-closed). Reachability is not yet established on the published port.
	if code := route("app_pub_web_001"); code != http.StatusForbidden {
		t.Fatalf("pre-publish route status = %d, want 403 (no published route yet)", code)
	}

	// Publish the web app on the non-default port 8443.
	publishRec := httptest.NewRecorder()
	publishReq := httptest.NewRequest(http.MethodPost, "/admin/applications/app_pub_web_001/publish", strings.NewReader(`{
		"name":"Internal Jira",
		"destination":"jira.internal.example.com",
		"destination_port":8443,
		"publish_protocol":"web",
		"connector_group_id":"cgrp_lab_001"
	}`))
	publishReq.Header.Set("content-type", "application/json")
	handler.ServeHTTP(publishRec, publishReq)
	if publishRec.Code != http.StatusOK {
		t.Fatalf("publish status = %d body=%s", publishRec.Code, publishRec.Body.String())
	}
	var publishResp struct {
		SchemaVersion string           `json:"schema_version"`
		Application   appcatalog.Entry `json:"application"`
		Review        struct {
			PublishedRoute  bool `json:"published_route"`
			PolicyAssigned  bool `json:"policy_assigned"`
			UsersAllowedNow int  `json:"users_allowed_now"`
		} `json:"review"`
	}
	if err := json.Unmarshal(publishRec.Body.Bytes(), &publishResp); err != nil {
		t.Fatalf("decode publish response: %v", err)
	}
	if !publishResp.Application.Published || publishResp.Application.Destination != "jira.internal.example.com" {
		t.Fatalf("published entry = %#v", publishResp.Application)
	}
	// Published != Allow review: route exists, policy IS assigned (a matching allow policy exists).
	if !publishResp.Review.PublishedRoute || !publishResp.Review.PolicyAssigned {
		t.Fatalf("review = %#v, want published_route + policy_assigned true", publishResp.Review)
	}

	// After publish: the route now resolves to :8443 -> the allow policy matches -> allow (200). This proves the
	// publish merged into the live runtime route resolution.
	if code := route("app_pub_web_001"); code != http.StatusOK {
		t.Fatalf("post-publish route status = %d, want 200 (published route + allow policy)", code)
	}

	// Published-but-NO-policy app: publishing alone must not authorize anyone (fail-closed deny).
	noAllowRec := httptest.NewRecorder()
	noAllowReq := httptest.NewRequest(http.MethodPost, "/admin/applications/app_pub_noallow_001/publish", strings.NewReader(`{
		"name":"Unbound App",
		"destination":"unbound.internal.example.com",
		"destination_port":8443,
		"publish_protocol":"web"
	}`))
	noAllowReq.Header.Set("content-type", "application/json")
	handler.ServeHTTP(noAllowRec, noAllowReq)
	if noAllowRec.Code != http.StatusOK {
		t.Fatalf("publish (no-allow) status = %d body=%s", noAllowRec.Code, noAllowRec.Body.String())
	}
	var noAllowResp struct {
		Review struct {
			PublishedRoute  bool `json:"published_route"`
			PolicyAssigned  bool `json:"policy_assigned"`
			UsersAllowedNow int  `json:"users_allowed_now"`
		} `json:"review"`
	}
	if err := json.Unmarshal(noAllowRec.Body.Bytes(), &noAllowResp); err != nil {
		t.Fatalf("decode no-allow publish response: %v", err)
	}
	// THE core Published != Allow assertion: published, but no policy -> 0 users allowed.
	if !noAllowResp.Review.PublishedRoute || noAllowResp.Review.PolicyAssigned || noAllowResp.Review.UsersAllowedNow != 0 {
		t.Fatalf("no-allow review = %#v, want published_route true, policy_assigned false, users_allowed_now 0", noAllowResp.Review)
	}
	if code := route("app_pub_noallow_001"); code != http.StatusForbidden {
		t.Fatalf("published-no-policy route status = %d, want 403 (Published != Allow)", code)
	}

	// Unpublish withdraws the route overlay; reachability on :8443 is gone -> previously-allowed app denies.
	unpubRec := httptest.NewRecorder()
	handler.ServeHTTP(unpubRec, httptest.NewRequest(http.MethodPost, "/admin/applications/app_pub_web_001/unpublish", nil))
	if unpubRec.Code != http.StatusOK {
		t.Fatalf("unpublish status = %d body=%s", unpubRec.Code, unpubRec.Body.String())
	}
	if code := route("app_pub_web_001"); code != http.StatusForbidden {
		t.Fatalf("post-unpublish route status = %d, want 403 (route overlay withdrawn)", code)
	}
}

// TestPrivateAppPublishAuditIsSecretSafe verifies the publish audit records presence booleans, never the raw
// destination host or connector group id.
func TestPrivateAppPublishAuditIsSecretSafe(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	outbox := &recordingAdminAuditOutboxDeadReader{}
	handler := newServerWithConfig(serverConfig{
		Evaluator:        testEvaluator(),
		Writer:           writer,
		Registry:         connector.NewRegistry(),
		AdminAuth:        newAdminAuthStore(),
		AdminAuditOutbox: outbox,
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/applications/app_secret_safe_001/publish", strings.NewReader(`{
		"destination":"super-secret-host.internal.example.com",
		"destination_port":8443,
		"publish_protocol":"web",
		"connector_group_id":"cgrp-secret"
	}`))
	req.Header.Set("content-type", "application/json")
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("publish status = %d body=%s", rec.Code, rec.Body.String())
	}
	if len(outbox.insertedAudits) != 1 || outbox.insertedAudits[0].EventType != "admin_application_published" {
		t.Fatalf("audits = %#v, want one admin_application_published", outbox.insertedAudits)
	}
	encoded, err := json.Marshal(outbox.insertedAudits[0])
	if err != nil {
		t.Fatalf("marshal audit: %v", err)
	}
	body := string(encoded)
	for _, secret := range []string{"super-secret-host.internal.example.com", "cgrp-secret"} {
		if strings.Contains(body, secret) {
			t.Fatalf("publish audit leaked %q: %s", secret, body)
		}
	}
	if !strings.Contains(body, `"destination_present":true`) || !strings.Contains(body, `"connector_group_present":true`) {
		t.Fatalf("publish audit missing presence booleans: %s", body)
	}
}
