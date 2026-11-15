package main

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/edgeplane"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/tunnel"
)

// A site with two connectors, the first of which has stopped: its registration stays in the registry and is
// not "offline" there, and it holds no tunnel. The second is connected and fronts the same application.
func twoConnectorsTheFirstStopped(t *testing.T, appID string) (*connector.Registry, *tunnel.Manager, *tunnel.Conn) {
	t.Helper()
	registry := connector.NewRegistry()
	for _, id := range []string{"conn_a_stopped", "conn_b_connected"} {
		if _, err := registry.Register(model.ConnectorRegistration{
			ID: id, TenantID: reachabilityTestTenant, ConnectorGroupID: "cgrp_lab_001", Name: id,
			EdgeRegionID: "local", EdgeClusterID: "local-edge-001", ApplicationIDs: []string{appID},
			PrivateBaseURL: "http://connector.local", Status: "registered", Metadata: map[string]any{},
		}, time.Now()); err != nil {
			t.Fatalf("Register %s: %v", id, err)
		}
	}
	clientRaw, serverRaw := net.Pipe()
	t.Cleanup(func() { _ = clientRaw.Close(); _ = serverRaw.Close() })
	tunnels := tunnel.NewManagerWithRequestTimeout(2 * time.Second)
	session, _ := tunnels.Register("conn_b_connected", "tun_b", tunnel.NewInProcessConn(clientRaw, true))
	go func() { _ = session.Run() }()
	return registry, tunnels, tunnel.NewInProcessConn(serverRaw, false)
}

func TestAmongConnectorsFrontingAnApplicationTheReachableOneIsChosen(t *testing.T) {
	const appID = "app_two_connectors"
	registry, tunnels, _ := twoConnectorsTheFirstStopped(t, appID)
	held := func(c model.ConnectorRegistration) bool { _, ok := tunnels.Get(c.ID); return ok }
	req := httptest.NewRequest(http.MethodGet, "/apps/"+appID, nil)

	// The registry lists in no particular order, so the choice is made many times: with a preference it must
	// never be the stopped one.
	for i := 0; i < 50; i++ {
		chosen, ok, err := connectorForApplicationPreferring(req.Context(), req, registry, nil, reachabilityTestTenant, appID, held)
		if err != nil || !ok || chosen.ID != "conn_b_connected" {
			t.Fatalf("preferring a held tunnel: %q ok=%v err=%v, want conn_b_connected", chosen.ID, ok, err)
		}
	}
	// None reachable: a connector is still named, so the caller can say what is wrong with it.
	none, ok, err := connectorForApplicationPreferring(req.Context(), req, registry, nil, reachabilityTestTenant, appID,
		func(model.ConnectorRegistration) bool { return false })
	if err != nil || !ok || none.ID == "" {
		t.Fatalf("none reachable: %q ok=%v err=%v, want a connector named all the same", none.ID, ok, err)
	}
	// A connector the request names is never traded for another.
	named := httptest.NewRequest(http.MethodGet, "/apps/"+appID+"?connector_id=conn_a_stopped", nil)
	asked, ok, err := connectorForApplicationPreferring(named.Context(), named, registry, nil, reachabilityTestTenant, appID, held)
	if err != nil || !ok || asked.ID != "conn_a_stopped" {
		t.Fatalf("named connector: %q ok=%v err=%v, want conn_a_stopped", asked.ID, ok, err)
	}
}

func TestReachabilityIsTestedThroughTheConnectedConnectorNotTheStoppedOne(t *testing.T) {
	const appID = "app_two_connectors"
	registry, tunnels, connectorHalf := twoConnectorsTheFirstStopped(t, appID)
	go func() {
		for {
			var f tunnel.Frame
			if err := connectorHalf.ReadJSON(&f); err != nil {
				return
			}
			if f.Type != tunnel.FrameProbeRequest {
				continue
			}
			_ = connectorHalf.WriteJSON(tunnel.Frame{
				Type: tunnel.FrameProbeResult, RequestID: f.RequestID, TunnelID: f.TunnelID,
				Probe: &tunnel.ProbeResult{Host: f.Host, Port: f.Port, Protocol: f.ProbeProtocol, Reachable: true,
					TCP: tunnel.ProbeLayerResult{Attempted: true, OK: true}},
			})
		}
	}()
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluatorWithPolicies(nil), Writer: writer, Registry: registry, TunnelManager: tunnels,
		RouteProfiles: map[string]edgeplane.ApplicationRouteProfile{
			appID: {Destination: "wiki.internal.example.com", DestinationPort: 8443, Protocol: "tcp", ServiceFamily: "https", DestinationRole: "private_app"},
		},
	})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/admin/applications/"+appID+"/reachability", nil))
	var resp reachabilityResult
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v status=%d body=%s", err, rec.Code, rec.Body.String())
	}
	if resp.Status != reachabilityStatusOK || !resp.Reachable {
		t.Fatalf("status=%q reachable=%v, want ok and reachable: a connected connector fronts this application", resp.Status, resp.Reachable)
	}
	if resp.Connector == nil || resp.Connector.ConnectorID != "conn_b_connected" || !resp.Connector.TunnelConnected {
		t.Fatalf("connector = %+v, want conn_b_connected with its tunnel connected", resp.Connector)
	}
}
