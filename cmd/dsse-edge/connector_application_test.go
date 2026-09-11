package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/edgeplane"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
)

func TestDecisionRequestForApplicationRouteSetsSaaSCatalogMatchInputsFromRouteProfile(t *testing.T) {
	routeProfiles := map[string]edgeplane.ApplicationRouteProfile{
		"app_saas_slack": {
			Destination:            "engineering.slack.com",
			DestinationPort:        443,
			Protocol:               "tcp",
			ServiceFamily:          "https",
			DestinationRole:        "saas_application",
			ApplicationSensitivity: "medium",
		},
	}
	req := httptest.NewRequest(http.MethodGet, "/apps/app_saas_slack?fqdn=evil.example&sni=evil.example", nil)
	req.RemoteAddr = "192.0.2.10:55123"
	conn := model.ConnectorRegistration{ID: "conn_lab_001", TenantID: "tenant_lab_001"}

	decisionReq := decisionRequestForApplicationRoute(req, conn, "app_saas_slack", routeProfiles)

	if decisionReq.FQDN != "engineering.slack.com" || decisionReq.SNI != "engineering.slack.com" {
		t.Fatalf("decision request FQDN/SNI = %q/%q, want route profile destination", decisionReq.FQDN, decisionReq.SNI)
	}
	if decisionReq.DestinationRole != "saas_application" || decisionReq.ServiceFamily != "https" {
		t.Fatalf("decision request = %+v, want SaaS route profile context", decisionReq)
	}
}

func TestLoadApplicationRouteProfilesFromProtectedAppMap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "protected_app_map.json")
	data := []byte(`{
		"tenant_id":"tenant_lab_001",
		"version":"2026.05.22.001",
		"applications":[{
			"application_id":"app_custom_ssh",
			"fqdn":"custom-ssh.local",
			"service_family":"ssh",
			"destination_port":2022,
			"steering_mode":"network_extension",
			"connector_group_id":"cg_lab_001",
			"metadata":{
				"destination_role":"ssh_server",
				"private_path":"/private-app/custom-ssh",
				"sensitivity":"high"
			}
		}]
	}`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	profiles, err := edgeplane.LoadApplicationRouteProfiles(path)
	if err != nil {
		t.Fatalf("edgeplane.LoadApplicationRouteProfiles returned error: %v", err)
	}
	profile := edgeplane.ApplicationRouteProfileFor("app_custom_ssh", profiles)
	if profile.ServiceFamily != "ssh" || profile.DestinationPort != 2022 || profile.PrivatePath != "/private-app/custom-ssh" {
		t.Fatalf("profile = %#v, want protected app map values", profile)
	}
	if profile.ApplicationSensitivity != "high" {
		t.Fatalf("sensitivity = %q, want high", profile.ApplicationSensitivity)
	}
}

func TestConnectorApplicationRouteSurfacesRegistryLookupFailure(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(),
		Writer:    writer,
		Registry:  postgresConnectorRegistryStore{},
		LabMode:   boolPtr(true),
	})
	req := httptest.NewRequest(http.MethodGet, "/apps/app_dummy_https", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("connector route status = %d, want %d, body=%s", rec.Code, http.StatusInternalServerError, rec.Body.String())
	}
}

func TestConnectorApplicationConnectRequiresTunnelAndDoesNotDirectFallback(t *testing.T) {
	logDir := t.TempDir()
	writer, err := logs.NewWriter(logDir)
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	registry := connector.NewRegistry()
	if _, err := registry.Register(model.ConnectorRegistration{
		ID:               "conn_lab_001",
		TenantID:         "tenant_lab_001",
		ConnectorGroupID: "cgrp_lab_001",
		ApplicationIDs:   []string{"app_dummy_https"},
		PrivateBaseURL:   "http://connector.local",
		Status:           "registered",
		Metadata:         map[string]any{},
	}, time.Now()); err != nil {
		t.Fatalf("register connector returned error: %v", err)
	}
	directFallbackCalled := false
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(),
		Writer:    writer,
		Registry:  registry,
		ProxyClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			directFallbackCalled = true
			return nil, fmt.Errorf("direct fallback should not be used for CONNECT")
		})},
		RouteProfiles: map[string]edgeplane.ApplicationRouteProfile{
			"app_dummy_https": {
				Destination:            "route-profile.internal",
				DestinationPort:        8443,
				Protocol:               "tcp",
				ServiceFamily:          "https",
				DestinationRole:        "private_app",
				ApplicationSensitivity: "medium",
				PrivatePath:            "/private-app/dummy",
			},
		},
		LabMode: boolPtr(true),
	})
	req := httptest.NewRequest(http.MethodConnect, "/apps/app_dummy_https?connector_id=conn_lab_001", nil)
	req.Host = "edge.local"
	req.RequestURI = "/apps/app_dummy_https?connector_id=conn_lab_001"
	req.Header.Set(edgeplane.ConnectAuthorityHeader, "route-profile.internal:8443")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("CONNECT status = %d, want %d, body=%s", rec.Code, http.StatusBadGateway, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "connector tunnel is required") {
		t.Fatalf("body = %s, want connector tunnel required", rec.Body.String())
	}
	if directFallbackCalled {
		t.Fatal("CONNECT route used direct HTTP fallback client")
	}
	assertLogExists(t, logDir, "connector.log.jsonl")
}
