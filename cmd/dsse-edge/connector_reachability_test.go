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

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/edgeplane"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/tunnel"
)

const reachabilityTestTenant = "tenant_lab_001"

func reachabilityTestProfile() edgeplane.ApplicationRouteProfile {
	return edgeplane.ApplicationRouteProfile{
		Destination:            "jira.internal.example.com",
		DestinationPort:        8443,
		Protocol:               "tcp",
		ServiceFamily:          "https",
		DestinationRole:        "private_app",
		ApplicationSensitivity: "medium",
	}
}

// TestBuildReachabilityResultNoConnectorFailClosed proves the lab-with-0-connectors path: no connected
// connector => no_connector status, not reachable, NO probe — but the policy simulation is still returned so
// the operator sees authorization state.
func TestBuildReachabilityResultNoConnectorFailClosed(t *testing.T) {
	evaluator := testEvaluatorWithPolicies(nil)
	result := buildReachabilityResult(context.Background(), evaluator, reachabilityTestTenant, "app_x",
		model.ConnectorRegistration{}, false /* connectorFound */, false /* tunnelConnected */, reachabilityTestProfile(), nil)

	if result.Status != reachabilityStatusNoConnector {
		t.Fatalf("status = %q, want no_connector", result.Status)
	}
	if result.Reachable {
		t.Fatal("must not be reachable with no connector")
	}
	if result.Probe != nil {
		t.Fatalf("no probe must run without a connector: %+v", result.Probe)
	}
	if result.PolicySimulation == nil || result.PolicySimulation["evaluated"] != true {
		t.Fatalf("policy simulation must still be present: %+v", result.PolicySimulation)
	}
	if result.SuggestedAction == "" {
		t.Fatal("a no_connector result should carry a suggested action")
	}
}

// TestBuildReachabilityResultNoTunnelFailClosed: a registered connector with no live tunnel => no_tunnel, no
// probe, policy simulation present, connector summary present (secret-safe fields only).
func TestBuildReachabilityResultNoTunnelFailClosed(t *testing.T) {
	conn := model.ConnectorRegistration{ID: "conn_1", TenantID: reachabilityTestTenant, Name: "Tokyo DC", ConnectorGroupID: "cgrp_1"}
	result := buildReachabilityResult(context.Background(), testEvaluatorWithPolicies(nil), reachabilityTestTenant, "app_x",
		conn, true /* connectorFound */, false /* tunnelConnected */, reachabilityTestProfile(), nil)
	if result.Status != reachabilityStatusNoTunnel {
		t.Fatalf("status = %q, want no_tunnel", result.Status)
	}
	if result.Connector == nil || result.Connector.ConnectorID != "conn_1" || result.Connector.TunnelConnected {
		t.Fatalf("connector summary = %+v, want conn_1 tunnel_connected=false", result.Connector)
	}
	if result.Probe != nil {
		t.Fatal("no probe must run without a tunnel")
	}
}

// TestReachabilityPolicySimulationIsPureDryRun proves the policy step is a dry-run: it never flows traffic and
// reflects the bound policy. An allow policy referencing the app yields permitted=true + policy_assigned=true;
// no policy yields default-deny permitted=false (Published != Allow).
func TestReachabilityPolicySimulationIsPureDryRun(t *testing.T) {
	// A policy bound to the app (no user-specific gate) allows the generic managed-endpoint probe flow and is
	// reported as assigned, with the distinct named principal counted in users_allowed_now.
	allow := testEvaluatorWithPolicies([]model.Policy{{
		ID:       "pol_app_allow",
		TenantID: reachabilityTestTenant,
		Priority: 100,
		Conditions: map[string]any{
			"application_id": "app_x",
			"service_family": "https",
			"user_id":        "alice",
		},
		Action: model.PolicyAction{Decision: "allow"},
		Status: "active",
	}, {
		ID:       "pol_app_allow_generic",
		TenantID: reachabilityTestTenant,
		Priority: 90,
		Conditions: map[string]any{
			"application_id": "app_x",
			"service_family": "https",
		},
		Action: model.PolicyAction{Decision: "allow"},
		Status: "active",
	}})
	sim := reachabilityPolicySimulation(allow, reachabilityTestTenant, "app_x", "conn_1", reachabilityTestProfile())
	if sim["permitted"] != true || sim["policy_assigned"] != true {
		t.Fatalf("allow sim = %+v, want permitted+policy_assigned", sim)
	}
	if sim["users_allowed_now"].(int) != 1 {
		t.Fatalf("users_allowed_now = %v, want 1 (distinct named principal alice)", sim["users_allowed_now"])
	}

	deny := reachabilityPolicySimulation(testEvaluatorWithPolicies(nil), reachabilityTestTenant, "app_x", "conn_1", reachabilityTestProfile())
	if deny["permitted"] != false || deny["policy_assigned"] != false {
		t.Fatalf("no-policy sim = %+v, want fail-closed deny", deny)
	}
}

// TestReachabilityAuditIsSecretSafe verifies the audit projection records the verdict + presence booleans and
// NEVER the destination host, resolved IPs, certificate fields, or HTTP status.
func TestReachabilityAuditIsSecretSafe(t *testing.T) {
	result := reachabilityResult{
		ApplicationID: "app_x",
		Status:        reachabilityStatusOK,
		Reachable:     true,
		Destination:   reachabilityTarget{Host: "super-secret-host.internal.example.com", Port: 8443, ProbeProtocol: "web"},
		Connector:     &reachabilityConnector{ConnectorID: "conn_1", TunnelConnected: true},
		Probe: &tunnel.ProbeResult{
			Reachable:   true,
			ResolvedIPs: []string{"10.10.4.99"},
			HTTPStatus:  200,
			TLSCert:     &tunnel.ProbeTLSCertInfo{Subject: "secret-cn.internal", Issuer: "secret-ca"},
		},
		PolicySimulation: map[string]any{"decision": "allow", "permitted": true},
	}
	details := reachabilityAuditDetails("app_x", result)
	encoded, err := json.Marshal(details)
	if err != nil {
		t.Fatalf("marshal audit: %v", err)
	}
	body := string(encoded)
	for _, secret := range []string{"super-secret-host.internal.example.com", "10.10.4.99", "secret-cn.internal", "secret-ca"} {
		if strings.Contains(body, secret) {
			t.Fatalf("reachability audit leaked %q: %s", secret, body)
		}
	}
	if !strings.Contains(body, `"destination_present":true`) || !strings.Contains(body, `"reachable":true`) {
		t.Fatalf("audit missing expected non-secret fields: %s", body)
	}
}

// TestApplicationReachabilityEndpointIntegration drives the full edge HTTP path with an in-process tunnel whose
// connector half answers a probe_request with a synthetic probe_result. It proves: route resolution, the tunnel
// round-trip, response shaping (per-layer + connector + policy_simulation), and tenant scoping.
func TestApplicationReachabilityEndpointIntegration(t *testing.T) {
	const appID = "app_reach_web_001"
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	registry := connector.NewRegistry()
	if _, err := registry.Register(model.ConnectorRegistration{
		ID: "conn_reach_001", TenantID: reachabilityTestTenant, ConnectorGroupID: "cgrp_lab_001", Name: "Tokyo DC",
		EdgeRegionID: "local", EdgeClusterID: "local-edge-001", ApplicationIDs: []string{appID},
		PrivateBaseURL: "http://connector.local", Status: "registered", Metadata: map[string]any{},
	}, time.Now()); err != nil {
		t.Fatalf("Register: %v", err)
	}

	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()
	tunnelManager := tunnel.NewManagerWithRequestTimeout(2 * time.Second)
	session, _ := tunnelManager.Register("conn_reach_001", "tun_reach_001", tunnel.NewInProcessConn(clientRaw, true))
	serverTunnelConn := tunnel.NewInProcessConn(serverRaw, false)
	go func() { _ = session.Run() }()

	// Connector half: answer probe_request with a synthetic OK probe_result (this stands in for runConnectorProbe,
	// which is unit-tested in the connector package).
	go func() {
		for {
			var f tunnel.Frame
			if err := serverTunnelConn.ReadJSON(&f); err != nil {
				return
			}
			if f.Type != tunnel.FrameProbeRequest {
				continue
			}
			if f.TenantID != reachabilityTestTenant || f.ProbeConnectorID != "conn_reach_001" {
				t.Errorf("diagnostic lost its authorized tenant/connector: tenant=%q connector=%q", f.TenantID, f.ProbeConnectorID)
			}
			_ = serverTunnelConn.WriteJSON(tunnel.Frame{
				Type:      tunnel.FrameProbeResult,
				RequestID: f.RequestID,
				TunnelID:  f.TunnelID,
				Probe: &tunnel.ProbeResult{
					Host: f.Host, Port: f.Port, Protocol: f.ProbeProtocol, Reachable: true,
					DNS:         tunnel.ProbeLayerResult{Attempted: true, OK: true, LatencyMillis: 2},
					TCP:         tunnel.ProbeLayerResult{Attempted: true, OK: true, LatencyMillis: 5},
					TLS:         tunnel.ProbeLayerResult{Attempted: true, OK: true},
					HTTP:        tunnel.ProbeLayerResult{Attempted: true, OK: true},
					ResolvedIPs: []string{"10.10.4.12"},
					HTTPStatus:  200,
				},
			})
		}
	}()

	routeProfiles := map[string]edgeplane.ApplicationRouteProfile{
		appID: {Destination: "jira.internal.example.com", DestinationPort: 8443, Protocol: "tcp", ServiceFamily: "https", DestinationRole: "private_app", ApplicationSensitivity: "medium"},
	}
	evaluator := testEvaluatorWithPolicies([]model.Policy{{
		ID: "pol_reach_allow", TenantID: reachabilityTestTenant, Priority: 100,
		Conditions: map[string]any{"application_id": appID, "service_family": "https"},
		Action:     model.PolicyAction{Decision: "allow"}, Status: "active",
	}})

	handler := newServerWithConfig(serverConfig{
		Evaluator:     evaluator,
		Writer:        writer,
		Registry:      registry,
		TunnelManager: tunnelManager,
		RouteProfiles: routeProfiles,
	})

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/admin/applications/"+appID+"/reachability", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("reachability status = %d body=%s", rec.Code, rec.Body.String())
	}
	var resp reachabilityResult
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v body=%s", err, rec.Body.String())
	}
	if resp.Status != reachabilityStatusOK || !resp.Reachable {
		t.Fatalf("resp = %+v, want ok+reachable", resp)
	}
	if resp.Connector == nil || resp.Connector.ConnectorID != "conn_reach_001" || !resp.Connector.TunnelConnected {
		t.Fatalf("connector = %+v", resp.Connector)
	}
	if resp.Probe == nil || !resp.Probe.DNS.OK || resp.Probe.HTTPStatus != 200 {
		t.Fatalf("probe = %+v", resp.Probe)
	}
	if resp.PolicySimulation["permitted"] != true {
		t.Fatalf("policy simulation = %+v, want permitted", resp.PolicySimulation)
	}

	// Tenant scoping: a different tenant scope sees no connector for this app -> fail-closed no_connector.
	otherEval := testEvaluatorWithPolicies(nil)
	otherEval.PolicyBundle.TenantID = "tenant_other_999"
	otherHandler := newServerWithConfig(serverConfig{
		Evaluator: otherEval, Writer: writer, Registry: registry, TunnelManager: tunnelManager, RouteProfiles: routeProfiles,
	})
	otherRec := httptest.NewRecorder()
	otherHandler.ServeHTTP(otherRec, httptest.NewRequest(http.MethodPost, "/admin/applications/"+appID+"/reachability", nil))
	var otherResp reachabilityResult
	if err := json.Unmarshal(otherRec.Body.Bytes(), &otherResp); err != nil {
		t.Fatalf("decode other: %v", err)
	}
	if otherResp.Status != reachabilityStatusNoConnector {
		t.Fatalf("cross-tenant status = %q, want no_connector (tenant isolation)", otherResp.Status)
	}
}
