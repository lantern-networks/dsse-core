package main

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/edgeplane"
	"github.com/lantern-networks/dsse-core/policy"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/tunnel"
)

// TestEastWestConnectRealFlowHoldsThenReleasesWithGrant drives a REAL private-app CONNECT flow (raw TCP
// over the in-process edge<->connector tunnel, the same mechanism the project uses for "real flow"
// verification) through the east-west authorization path -- not the synthetic /decisions/evaluate.
//
// It proves on the real data path: (1) authenticate mode HOLDS the flow -- the upstream TCP is never
// opened (no tcp_open frame), the CONNECT returns 401; (2) a valid grant RELEASES it -- the tunnel emits
// a real tcp_open for the destination. This is E1/E2/E3 verified on real traffic.
func TestEastWestConnectRealFlowHoldsThenReleasesWithGrant(t *testing.T) {
	const tenant = "tenant_lab_001"
	const appID = "app_dc01_ssh"

	logDir := t.TempDir()
	writer, err := logs.NewWriter(logDir)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	registry := connector.NewRegistry()
	if _, err := registry.Register(model.ConnectorRegistration{
		ID: "conn_lab_001", TenantID: tenant, ConnectorGroupID: "cgrp_lab_001", Name: "Lab Connector",
		EdgeRegionID: "local", EdgeClusterID: "local-edge-001", ApplicationIDs: []string{appID},
		PrivateBaseURL: "http://connector.local", Status: "registered", Metadata: map[string]any{},
	}, time.Now()); err != nil {
		t.Fatalf("Register: %v", err)
	}

	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()
	tunnelManager := tunnel.NewManagerWithRequestTimeout(500 * time.Millisecond)
	session, _ := tunnelManager.Register("conn_lab_001", "tun_lab_001", tunnel.NewInProcessConn(clientRaw, true))
	serverTunnelConn := tunnel.NewInProcessConn(serverRaw, false)
	go func() { _ = session.Run() }()

	routeProfiles := map[string]edgeplane.ApplicationRouteProfile{
		appID: {Destination: "dc-01", DestinationPort: 22, Protocol: "tcp", ServiceFamily: "ssh", DestinationRole: "private_app", ApplicationSensitivity: "high"},
	}

	// East-west: authenticate mode for this SSH app. Bind rule/grant to the application id (always present
	// on the connect request).
	policyStore := policy.NewStore(nil)
	policyStore.SetEastWestEnabled(tenant, true)
	policyStore.SetEastWestRules(tenant, []decision.EastWestRule{
		{ID: "r-ssh", Priority: 10, Destinations: []string{appID, "dc-01"}, Protocols: []string{"ssh"}, Mode: decision.EastWestModeAuthenticate},
	})

	handler := newServerWithConfig(serverConfig{
		Evaluator:     testEvaluatorWithPolicies(nil),
		Writer:        writer,
		Registry:      registry,
		TunnelManager: tunnelManager,
		RouteProfiles: routeProfiles,
		PolicyStore:   policyStore,
		ProxyClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			t.Fatalf("proxy client must not be called for an east-west CONNECT")
			return nil, nil
		})},
	})

	connectReq := func() *http.Request {
		req := httptest.NewRequest(http.MethodConnect, "/apps/"+appID+"?connector_id=conn_lab_001&service_family=ssh", nil)
		req.Header.Set(edgeplane.ConnectAuthorityHeader, "dc-01:22")
		return req
	}

	// (1) No grant -> HOLD: 401 and NO tcp_open frame reaches the connector (upstream never opened).
	holdRec := httptest.NewRecorder()
	handler.ServeHTTP(holdRec, connectReq())
	if holdRec.Code != http.StatusUnauthorized {
		t.Fatalf("hold status = %d, want 401; body=%s", holdRec.Code, holdRec.Body.String())
	}
	var holdResp map[string]any
	if err := json.Unmarshal(holdRec.Body.Bytes(), &holdResp); err == nil {
		if holdResp["decision"] != "authenticate_required" {
			t.Fatalf("hold decision = %v, want authenticate_required", holdResp["decision"])
		}
	}
	if err := serverRaw.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	var leaked tunnel.Frame
	if err := serverTunnelConn.ReadJSON(&leaked); err == nil {
		t.Fatalf("held CONNECT emitted tunnel frame %+v, want NO tcp_open (upstream must not open)", leaked)
	} else if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		t.Fatalf("held CONNECT tunnel read err = %v, want timeout (no frame)", err)
	}
	if err := serverRaw.SetReadDeadline(time.Time{}); err != nil {
		t.Fatalf("clear deadline: %v", err)
	}

	// (2) Issue a grant bound to the app/protocol -> RELEASE: the CONNECT now opens the upstream TCP
	// (a real tcp_open frame for dc-01:22 reaches the connector).
	policyStore.IssueEastWestGrant(tenant, decision.EastWestGrant{
		Destination: appID, Protocol: "ssh", ExpiresAt: time.Now().Add(time.Hour), LastUsedAt: time.Now(),
	})

	go func() {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, connectReq())
	}()

	if err := serverRaw.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	var openFrame tunnel.Frame
	if err := serverTunnelConn.ReadJSON(&openFrame); err != nil {
		t.Fatalf("after grant, expected a real tcp_open frame; got err %v", err)
	}
	if openFrame.Type != tunnel.FrameTCPOpen || openFrame.Host != "dc-01" || openFrame.Port != 22 {
		t.Fatalf("openFrame = %+v, want tcp_open dc-01:22 (grant released the held flow)", openFrame)
	}
}
