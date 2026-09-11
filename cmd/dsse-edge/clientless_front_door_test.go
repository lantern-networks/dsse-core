package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
)

// is DEFERRED + OFF by default (attack-surface decision): without -clientless-access the public
// clientless web front door must not exist (404), so there is no pre-auth web surface in the default build.
func TestClientlessFrontDoorDisabledByDefault(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(),
		Writer:    writer,
		Registry:  connector.NewRegistry(),
		AdminAuth: newAdminAuthStore(),
		LabMode:   boolPtr(true),
		// ClientlessAccessEnabled omitted => false (default OFF)
	})
	req := httptest.NewRequest(http.MethodGet, "/clientless/apps/anything", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("clientless front door must be 404 (closed) when -clientless-access is off; got %d", rec.Code)
	}
}

// the clientless front door derives identity from a VERIFIED IdP session (not client-claimed),
// redirects an unauthenticated browser to login, authorizes against the published-app catalog, and on
// allow HANDS THE FLOW TO THE CONNECTOR RELAY (404 when no connector is registered for the app).
func TestClientlessFrontDoor(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator:               testEvaluator(),
		ClientlessAccessEnabled: true,
		Writer:                  writer,
		Registry:                connector.NewRegistry(),
		AdminAuth:               newAdminAuthStore(),
		LabMode:                 boolPtr(true), // enables the mock auth callback used to mint a test session
	})
	do := func(method, path string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, nil)
		for _, c := range cookies {
			req.AddCookie(c)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}
	post := func(path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.Header.Set("content-type", "application/json")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	if rec := post("/admin/applications", `{"application_id":"wiki","name":"Wiki","application_type":"private_app","status":"active"}`); rec.Code != http.StatusOK {
		t.Fatalf("seed app: %d %s", rec.Code, rec.Body.String())
	}

	// Unauthenticated (no session, no OIDC configured) -> 401, NOT a grant.
	if rec := do(http.MethodGet, "/clientless/apps/wiki"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated must be 401; got %d body=%s", rec.Code, rec.Body.String())
	}

	// Mint a verified session via the lab mock callback, capture the session_id cookie.
	mintRec := do(http.MethodGet, "/auth/mock/callback?user_id=u1")
	if mintRec.Code != http.StatusCreated {
		t.Fatalf("mock callback: %d %s", mintRec.Code, mintRec.Body.String())
	}
	var sessionCookie *http.Cookie
	for _, c := range mintRec.Result().Cookies() {
		if c.Name == "session_id" {
			sessionCookie = c
		}
	}
	if sessionCookie == nil {
		t.Fatal("mock callback did not set a session_id cookie")
	}

	// Authenticated + published, but NO connector registered -> the relay is attempted and returns 404
	// (proves the front door now delegates to the connector data path, not a static JSON grant).
	if rec := do(http.MethodGet, "/clientless/apps/wiki", sessionCookie); rec.Code != http.StatusNotFound {
		t.Fatalf("authorized clientless with no connector should 404 from the relay; got %d body=%s", rec.Code, rec.Body.String())
	}
	// Authenticated but app not published -> 403 (clientless authz denies before the relay).
	if rec := do(http.MethodGet, "/clientless/apps/ghost", sessionCookie); rec.Code != http.StatusForbidden {
		t.Fatalf("unpublished app must be 403; got %d", rec.Code)
	}
}

// live relay: an authorized clientless browser request is reverse-proxied through the connector
// publish data path to the backend (the byte relay, not just an authorization grant).
func TestClientlessFrontDoorLiveRelay(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	evaluator := testEvaluatorWithPolicies([]model.Policy{{
		ID:         "pol_clientless_allow",
		TenantID:   "tenant_lab_001",
		Priority:   100,
		Conditions: map[string]any{"actor_type": "human", "application_id": "wiki"},
		Action:     model.PolicyAction{Decision: "allow"},
		Status:     "active",
	}})
	// Fake backend behind the connector (HTTP proxy mode via private_base_url).
	proxyClient := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"content-type": []string{"application/json"}},
			Body:       io.NopCloser(bytes.NewBufferString(`{"app":"wiki","body":"published_app_reached"}`)),
		}, nil
	})}
	handler := newServerWithConfig(serverConfig{
		Evaluator:               evaluator,
		Writer:                  writer,
		Registry:                connector.NewRegistry(),
		AdminAuth:               newAdminAuthStore(),
		ProxyClient:             proxyClient,
		ConnectorSecret:         defaultConnectorSecret,
		ClientlessAccessEnabled: true,
		LabMode:                 boolPtr(true),
	})
	rawPost := func(path, body string, header map[string]string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.Header.Set("content-type", "application/json")
		for k, v := range header {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	// Register a connector that serves the published app over its private_base_url.
	if rec := rawPost("/connectors/register", `{
		"id":"conn_lab_001","tenant_id":"tenant_lab_001","connector_group_id":"cgrp_lab_001",
		"name":"Lab Connector","edge_region_id":"local","edge_cluster_id":"local-edge-001",
		"application_ids":["wiki"],"private_base_url":"http://connector.local","status":"registered","metadata":{}
	}`, map[string]string{connectorSecretHeader: defaultConnectorSecret}); rec.Code != http.StatusCreated {
		t.Fatalf("register connector: %d %s", rec.Code, rec.Body.String())
	}
	// Publish the app in the catalog.
	if rec := rawPost("/admin/applications", `{"application_id":"wiki","name":"Wiki","application_type":"private_app","status":"active"}`, nil); rec.Code != http.StatusOK {
		t.Fatalf("seed app: %d %s", rec.Code, rec.Body.String())
	}
	// Mint a verified session.
	mint := httptest.NewRequest(http.MethodGet, "/auth/mock/callback?user_id=u1", nil)
	mintRec := httptest.NewRecorder()
	handler.ServeHTTP(mintRec, mint)
	var sessionCookie *http.Cookie
	for _, c := range mintRec.Result().Cookies() {
		if c.Name == "session_id" {
			sessionCookie = c
		}
	}
	if sessionCookie == nil {
		t.Fatalf("no session cookie; mint=%d %s", mintRec.Code, mintRec.Body.String())
	}

	// Clientless browser request -> reverse-proxied through the connector to the backend.
	req := httptest.NewRequest(http.MethodGet, "/clientless/apps/wiki", nil)
	req.AddCookie(sessionCookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "published_app_reached") {
		t.Fatalf("clientless live relay should reach the published app: %d %s", rec.Code, rec.Body.String())
	}
}
