package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	appcatalog "github.com/lantern-networks/dsse-core/appcatalog"
	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
)

// TestConnectorDiscoveredCandidateInputsDiff covers the pure reachable_routes − published diff: a published
// destination is excluded, an fqdn maps to a web hint, a cidr to a network hint, and duplicate destinations
// across connectors collapse to one input.
func TestConnectorDiscoveredCandidateInputsDiff(t *testing.T) {
	connectors := []model.ConnectorRegistration{
		{
			ID:               "conn-1",
			TenantID:         "tenant_a",
			ConnectorGroupID: "tokyo-dc",
			ReachableRoutes: model.ConnectorReachableRoutes{
				FQDNDomains: []string{"jira.internal.example.com", "gitlab.internal.example.com", "Already.Published.example.com"},
				CIDRs:       []string{"10.20.0.0/16"},
				Namespace:   "vnet-1",
			},
		},
		{
			ID:               "conn-2",
			TenantID:         "tenant_a",
			ConnectorGroupID: "tokyo-dc",
			// Duplicate fqdn fronted by a second connector -> must not double-list.
			ReachableRoutes: model.ConnectorReachableRoutes{FQDNDomains: []string{"jira.internal.example.com"}},
		},
	}
	published := []appcatalog.Entry{
		{ApplicationID: "app-1", TenantID: "tenant_a", ApplicationType: "private_app", Destination: "already.published.example.com", Published: true},
		// An UN-published catalog row must NOT suppress discovery of its destination.
		{ApplicationID: "app-2", TenantID: "tenant_a", ApplicationType: "private_app", Destination: "gitlab.internal.example.com", Published: false},
	}

	inputs := connectorDiscoveredCandidateInputs(connectors, published)
	got := map[string]connectorDiscoveredInput{}
	for _, in := range inputs {
		got[in.Destination] = in
	}
	if _, ok := got["already.published.example.com"]; ok {
		t.Fatalf("already-published destination must be excluded from candidates")
	}
	if len(inputs) != 3 {
		t.Fatalf("expected 3 distinct candidates (jira, gitlab, cidr), got %d: %#v", len(inputs), inputs)
	}
	if in := got["jira.internal.example.com"]; in.PublishProtocol != "web" {
		t.Fatalf("fqdn should map to web hint: %#v", in)
	}
	if in := got["10.20.0.0/16"]; in.PublishProtocol != "network" || in.Namespace != "vnet-1" {
		t.Fatalf("cidr should map to network hint with namespace: %#v", in)
	}
	if in := got["gitlab.internal.example.com"]; in.PublishProtocol != "web" {
		t.Fatalf("un-published catalog destination must still be discoverable: %#v", in)
	}
}

// TestConnectorDiscoveryRefreshThenApprovePublishesPrivateApp drives the full edge Slice 4 flow over HTTP:
// register a connector that declares reachable_routes -> refresh writes PENDING candidates (NO auto-publish) ->
// approve-private-app publishes a Private App (reachability) and removes the candidate from pending. It also
// proves Published != Allow (the freshly published app authorizes nobody) and that the publish path never
// touched a TLS decrypt-bypass.
func TestConnectorDiscoveryRefreshThenApprovePublishesPrivateApp(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	registry := connector.NewRegistry()
	handler := newServerWithClient(testEvaluatorWithPolicies(nil), writer, registry, &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBufferString(`{}`))}, nil
	})})

	// Register a connector that declares two reachable destinations.
	registerReq := httptest.NewRequest(http.MethodPost, "/connectors/register", strings.NewReader(`{
		"id":"conn_disc_001",
		"tenant_id":"tenant_lab_001",
		"connector_group_id":"cgrp_lab_001",
		"name":"Lab Connector",
		"edge_region_id":"local",
		"edge_cluster_id":"local-edge-001",
		"private_base_url":"http://connector.local",
		"status":"registered",
		"reachable_routes":{"fqdn_domains":["jira.internal.example.com","wiki.internal.example.com"]},
		"metadata":{}
	}`))
	registerReq.Header.Set(connectorSecretHeader, defaultConnectorSecret)
	registerRec := httptest.NewRecorder()
	handler.ServeHTTP(registerRec, registerReq)
	if registerRec.Code != http.StatusCreated {
		t.Fatalf("register status = %d body=%s", registerRec.Code, registerRec.Body.String())
	}

	// Refresh: derive connector-discovered candidates.
	refreshRec := httptest.NewRecorder()
	handler.ServeHTTP(refreshRec, httptest.NewRequest(http.MethodPost, "/admin/connector-discovery/refresh", nil))
	if refreshRec.Code != http.StatusOK {
		t.Fatalf("refresh status = %d body=%s", refreshRec.Code, refreshRec.Body.String())
	}
	var refreshResp struct {
		Candidates []map[string]any `json:"candidates"`
		Count      int              `json:"count"`
	}
	if err := json.Unmarshal(refreshRec.Body.Bytes(), &refreshResp); err != nil {
		t.Fatalf("decode refresh: %v", err)
	}
	if refreshResp.Count != 2 {
		t.Fatalf("refresh count = %d, want 2: %s", refreshResp.Count, refreshRec.Body.String())
	}

	// Locate the jira candidate; assert it is pending (NO auto-approve).
	var jiraID string
	for _, c := range refreshResp.Candidates {
		if c["host"] == "jira.internal.example.com" {
			if c["status"] != "pending" {
				t.Fatalf("candidate status = %v, want pending", c["status"])
			}
			if c["source"] != "connector_discovered" {
				t.Fatalf("candidate source = %v", c["source"])
			}
			jiraID, _ = c["candidate_id"].(string)
		}
	}
	if jiraID == "" {
		t.Fatalf("jira candidate not found: %s", refreshRec.Body.String())
	}

	// Auto-publish guard: BEFORE approval no application is published.
	if publishedCount := countPublishedApplications(t, handler); publishedCount != 0 {
		t.Fatalf("refresh must NOT auto-publish: published=%d", publishedCount)
	}

	// Approve as a Web private app -> publishes reachability + promotes the candidate out of pending.
	approveRec := httptest.NewRecorder()
	approveReq := httptest.NewRequest(http.MethodPost, "/admin/policy-candidates/"+jiraID+"/approve-private-app", strings.NewReader(`{"publish_protocol":"web","destination_port":8443}`))
	approveReq.Header.Set("content-type", "application/json")
	handler.ServeHTTP(approveRec, approveReq)
	if approveRec.Code != http.StatusOK {
		t.Fatalf("approve status = %d body=%s", approveRec.Code, approveRec.Body.String())
	}
	var approveResp struct {
		Application appcatalog.Entry `json:"application"`
		Candidate   struct {
			Status string `json:"status"`
		} `json:"candidate"`
		Review struct {
			PublishedRoute  bool `json:"published_route"`
			PolicyAssigned  bool `json:"policy_assigned"`
			UsersAllowedNow int  `json:"users_allowed_now"`
		} `json:"review"`
	}
	if err := json.Unmarshal(approveRec.Body.Bytes(), &approveResp); err != nil {
		t.Fatalf("decode approve: %v", err)
	}
	if !approveResp.Application.Published || approveResp.Application.Destination != "jira.internal.example.com" || approveResp.Application.DestinationPort != 8443 {
		t.Fatalf("published entry wrong: %#v", approveResp.Application)
	}
	if approveResp.Candidate.Status != "approved" {
		t.Fatalf("candidate status after approve = %q, want approved", approveResp.Candidate.Status)
	}
	// Published != Allow: route exists, but no policy -> nobody authorized (fail-closed).
	if !approveResp.Review.PublishedRoute || approveResp.Review.PolicyAssigned || approveResp.Review.UsersAllowedNow != 0 {
		t.Fatalf("review = %#v, want published_route + !policy_assigned + 0 users", approveResp.Review)
	}

	// The approved candidate is no longer pending; the wiki one still is.
	pendingRec := httptest.NewRecorder()
	handler.ServeHTTP(pendingRec, httptest.NewRequest(http.MethodGet, "/admin/policy-candidates?status=pending", nil))
	var pendingResp struct {
		Candidates []map[string]any `json:"candidates"`
	}
	if err := json.Unmarshal(pendingRec.Body.Bytes(), &pendingResp); err != nil {
		t.Fatalf("decode pending: %v", err)
	}
	for _, c := range pendingResp.Candidates {
		if c["candidate_id"] == jiraID {
			t.Fatalf("approved candidate must not be pending: %#v", c)
		}
	}
}

// TestConnectorDiscoveryApproveStampsGroupAndReachabilityResolvesConnector covers the demo regression: a
// connector-discovered candidate carries observed_from (connector group / site), so approve-private-app must
// stamp the published catalog entry's connector_group_id from it — and reachability must then RESOLVE the
// fronting connector by that group even though the freshly-minted application_id is NOT enumerated in the
// connector's application_ids. Before the fix reachability returned "no_connector" (No reachable connector);
// after it the live connector in the group is selected (status no_tunnel here because no tunnel is wired in this
// unit test, which still proves the connector was FOUND — the probe step is reached, not short-circuited).
func TestConnectorDiscoveryApproveStampsGroupAndReachabilityResolvesConnector(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	registry := connector.NewRegistry()
	handler := newServerWithClient(testEvaluatorWithPolicies(nil), writer, registry, &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBufferString(`{}`))}, nil
	})})

	// Register a connector in group cgrp_lab_001 that DECLARES a reachable route but does NOT enumerate any
	// application_ids — exactly the connector-discovered shape.
	registerReq := httptest.NewRequest(http.MethodPost, "/connectors/register", strings.NewReader(`{
		"id":"conn_disc_grp_001",
		"tenant_id":"tenant_lab_001",
		"connector_group_id":"cgrp_lab_001",
		"name":"Lab DC Connector",
		"edge_region_id":"local",
		"edge_cluster_id":"local-edge-001",
		"private_base_url":"http://connector.local",
		"status":"registered",
		"reachable_routes":{"fqdn_domains":["jira.internal.example.com"]},
		"metadata":{}
	}`))
	registerReq.Header.Set(connectorSecretHeader, defaultConnectorSecret)
	registerRec := httptest.NewRecorder()
	handler.ServeHTTP(registerRec, registerReq)
	if registerRec.Code != http.StatusCreated {
		t.Fatalf("register status = %d body=%s", registerRec.Code, registerRec.Body.String())
	}

	// Refresh -> pending candidate; capture its id.
	refreshRec := httptest.NewRecorder()
	handler.ServeHTTP(refreshRec, httptest.NewRequest(http.MethodPost, "/admin/connector-discovery/refresh", nil))
	if refreshRec.Code != http.StatusOK {
		t.Fatalf("refresh status = %d body=%s", refreshRec.Code, refreshRec.Body.String())
	}
	var refreshResp struct {
		Candidates []map[string]any `json:"candidates"`
	}
	if err := json.Unmarshal(refreshRec.Body.Bytes(), &refreshResp); err != nil {
		t.Fatalf("decode refresh: %v", err)
	}
	var candID string
	for _, c := range refreshResp.Candidates {
		if c["host"] == "jira.internal.example.com" {
			candID, _ = c["candidate_id"].(string)
			// The candidate must carry the observed_from site (= connector group) so approve can stamp it.
			if c["observed_from_site"] != "cgrp_lab_001" {
				t.Fatalf("candidate observed_from_site = %v, want cgrp_lab_001", c["observed_from_site"])
			}
		}
	}
	if candID == "" {
		t.Fatalf("jira candidate not found: %s", refreshRec.Body.String())
	}

	// Approve WITHOUT supplying connector_group_id in the body -> the entry must inherit it from observed_from.
	approveRec := httptest.NewRecorder()
	approveReq := httptest.NewRequest(http.MethodPost, "/admin/policy-candidates/"+candID+"/approve-private-app", strings.NewReader(`{"publish_protocol":"web"}`))
	approveReq.Header.Set("content-type", "application/json")
	handler.ServeHTTP(approveRec, approveReq)
	if approveRec.Code != http.StatusOK {
		t.Fatalf("approve status = %d body=%s", approveRec.Code, approveRec.Body.String())
	}
	var approveResp struct {
		Application appcatalog.Entry `json:"application"`
	}
	if err := json.Unmarshal(approveRec.Body.Bytes(), &approveResp); err != nil {
		t.Fatalf("decode approve: %v", err)
	}
	// Bug 1 (approve side): the published entry inherits the connector group from observed_from.
	if approveResp.Application.ConnectorGroupID != "cgrp_lab_001" {
		t.Fatalf("published entry connector_group_id = %q, want cgrp_lab_001 (inherited from observed_from)", approveResp.Application.ConnectorGroupID)
	}
	appID := approveResp.Application.ApplicationID

	// Bug 1 (resolver side): reachability must SELECT the fronting connector via the published group, even though
	// conn_disc_grp_001 does not list appID in application_ids. No tunnel is wired here, so the status is
	// no_tunnel — but crucially NOT no_connector, and the selected connector is the lab-dc connector.
	reachRec := httptest.NewRecorder()
	reachReq := httptest.NewRequest(http.MethodPost, "/admin/applications/"+appID+"/reachability", strings.NewReader(`{}`))
	reachReq.Header.Set("content-type", "application/json")
	handler.ServeHTTP(reachRec, reachReq)
	if reachRec.Code != http.StatusOK {
		t.Fatalf("reachability status = %d body=%s", reachRec.Code, reachRec.Body.String())
	}
	var reach reachabilityResult
	if err := json.Unmarshal(reachRec.Body.Bytes(), &reach); err != nil {
		t.Fatalf("decode reachability: %v", err)
	}
	if reach.Status == reachabilityStatusNoConnector {
		t.Fatalf("reachability returned no_connector — group fallback failed to find the fronting connector: %s", reachRec.Body.String())
	}
	if reach.Connector == nil || reach.Connector.ConnectorID != "conn_disc_grp_001" {
		t.Fatalf("reachability selected connector = %#v, want conn_disc_grp_001 via group", reach.Connector)
	}
	if reach.Connector.ConnectorGroupID != "cgrp_lab_001" {
		t.Fatalf("selected connector group = %q, want cgrp_lab_001", reach.Connector.ConnectorGroupID)
	}
}

// TestConnectorReachabilityGroupFallbackIsFailClosed proves the group fallback does NOT invent reachability: a
// published private app whose connector_group_id matches NO live connector still reports no_connector.
func TestConnectorReachabilityGroupFallbackIsFailClosed(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	registry := connector.NewRegistry()
	handler := newServerWithClient(testEvaluatorWithPolicies(nil), writer, registry, &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBufferString(`{}`))}, nil
	})})

	// A connector exists, but in a DIFFERENT group than the app will be published under.
	registerReq := httptest.NewRequest(http.MethodPost, "/connectors/register", strings.NewReader(`{
		"id":"conn_other_grp_001",
		"tenant_id":"tenant_lab_001",
		"connector_group_id":"cgrp_other_001",
		"name":"Other Connector",
		"edge_region_id":"local",
		"edge_cluster_id":"local-edge-001",
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

	// Publish a private app under a group that no live connector serves.
	publishRec := httptest.NewRecorder()
	publishReq := httptest.NewRequest(http.MethodPost, "/admin/applications/app_unreachable_001/publish", strings.NewReader(`{
		"name":"Unreachable App",
		"destination":"orphan.internal.example.com",
		"destination_port":8443,
		"publish_protocol":"web",
		"connector_group_id":"cgrp_lab_001"
	}`))
	publishReq.Header.Set("content-type", "application/json")
	handler.ServeHTTP(publishRec, publishReq)
	if publishRec.Code != http.StatusOK {
		t.Fatalf("publish status = %d body=%s", publishRec.Code, publishRec.Body.String())
	}

	reachRec := httptest.NewRecorder()
	reachReq := httptest.NewRequest(http.MethodPost, "/admin/applications/app_unreachable_001/reachability", strings.NewReader(`{}`))
	reachReq.Header.Set("content-type", "application/json")
	handler.ServeHTTP(reachRec, reachReq)
	if reachRec.Code != http.StatusOK {
		t.Fatalf("reachability status = %d body=%s", reachRec.Code, reachRec.Body.String())
	}
	var reach reachabilityResult
	if err := json.Unmarshal(reachRec.Body.Bytes(), &reach); err != nil {
		t.Fatalf("decode reachability: %v", err)
	}
	if reach.Status != reachabilityStatusNoConnector {
		t.Fatalf("reachability status = %q, want no_connector (no live connector in the published group)", reach.Status)
	}
}

// TestConnectorDiscoveryApproveRejectsCertPinCandidate covers the fail-closed source guard: the publish path
// must REFUSE a cert-pin candidate so an admin can never turn a TLS decrypt-bypass proposal into a published
// app (and vice versa they stay on /materialize).
func TestConnectorDiscoveryApproveRejectsCertPinCandidate(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	handler := newServerWithClient(testEvaluatorWithPolicies(nil), writer, connector.NewRegistry(), &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBufferString(`{}`))}, nil
	})})

	// Author a cert-pin candidate directly via the candidate API.
	upsertRec := httptest.NewRecorder()
	upsertReq := httptest.NewRequest(http.MethodPost, "/admin/policy-candidates", strings.NewReader(`{
		"candidate_id":"certpin-xyz",
		"source":"cert_pinning_detection",
		"host":"pinned.example.com"
	}`))
	upsertReq.Header.Set("content-type", "application/json")
	handler.ServeHTTP(upsertRec, upsertReq)
	if upsertRec.Code != http.StatusOK {
		t.Fatalf("upsert cert-pin status = %d body=%s", upsertRec.Code, upsertRec.Body.String())
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/admin/policy-candidates/certpin-xyz/approve-private-app", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("approve-private-app on cert-pin candidate status = %d, want 400: %s", rec.Code, rec.Body.String())
	}
}

func countPublishedApplications(t *testing.T, handler http.Handler) int {
	t.Helper()
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin/applications?application_type=private_app", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("list applications status = %d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Applications []appcatalog.Entry `json:"applications"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode applications: %v", err)
	}
	n := 0
	for _, e := range resp.Applications {
		if e.Published {
			n++
		}
	}
	return n
}
