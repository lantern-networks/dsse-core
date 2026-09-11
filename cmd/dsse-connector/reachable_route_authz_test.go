package main

import (
	"context"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/tunnel"
)

func routeDrivenOpenFrame(host string, port int) tunnel.Frame {
	return tunnel.Frame{
		Type:                        tunnel.FrameTCPOpen,
		RequestID:                   "req_route_001",
		ApplicationID:               host, // destination-driven open: the host stands in as the application id
		Host:                        host,
		Port:                        port,
		ConnectTimeoutMillis:        int((5 * time.Second) / time.Millisecond),
		MaxConnectionLifetimeMillis: int((5 * time.Minute) / time.Millisecond),
		IdleTimeoutMillis:           int((30 * time.Second) / time.Millisecond),
		ByteCap:                     64 << 20,
		ConcurrentConnectionCap:     32,
	}
}

func TestReachableRouteAuthorizes(t *testing.T) {
	reachable := model.ConnectorReachableRoutes{FQDNDomains: []string{"corp.internal"}, CIDRs: []string{"10.0.0.0/8"}, Namespace: "tokyo"}
	cases := []struct {
		host string
		want bool
	}{
		{"host.corp.internal", true}, // under the FQDN route
		{"corp.internal", true},      // the apex
		{"10.1.2.3", true},           // under the CIDR (namespace matches the route)
		{"host.other.test", false},   // no route
		{"192.0.2.1", false},         // outside the CIDR
	}
	for _, tc := range cases {
		if got := reachableRouteAuthorizes(routeDrivenOpenFrame(tc.host, 443), reachable); got != tc.want {
			t.Errorf("reachableRouteAuthorizes(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}
	// With no reachable routes configured, nothing is route-authorized (protected-app-map only).
	if reachableRouteAuthorizes(routeDrivenOpenFrame("host.corp.internal", 443), model.ConnectorReachableRoutes{}) {
		t.Fatal("empty reachable routes must authorize nothing")
	}
}

// TestDispatcherAuthorizesDestinationDrivenOpenByRoute proves the connector independently admits a
// destination-driven TCP open (NO protected-app-map entry) when its reachable routes front the destination, and
// denies one they do not — defense in depth on top of the Edge's connector selection.
func TestDispatcherAuthorizesDestinationDrivenOpenByRoute(t *testing.T) {
	build := func() (*connectorTunnelTCPDispatcher, *recordingTCPConnectionDialer) {
		dialer := &recordingTCPConnectionDialer{conn: newRecordingTCPConnection("")}
		dispatcher := newConnectorTunnelTCPDispatcher(nil /* empty protected-app-map */, dialer, fixedConnectorTestNow())
		dispatcher.SetReachableRoutes(model.ConnectorReachableRoutes{FQDNDomains: []string{"corp.internal"}})
		return dispatcher, dialer
	}

	// Fronted by a reachable route -> authorized -> the connector dials the destination.
	dispatcher, dialer := build()
	frames, err := dispatcher.HandleFrame(context.Background(), routeDrivenOpenFrame("host.corp.internal", 443))
	if err != nil {
		t.Fatalf("HandleFrame: %v", err)
	}
	if len(frames) != 1 || frames[0].Type != tunnel.FrameTCPOpenResult || frames[0].Error != "" {
		t.Fatalf("route-fronted open = %+v, want a clean FrameTCPOpenResult", frames)
	}
	if len(dialer.routes) != 1 || dialer.routes[0].Host != "host.corp.internal" || dialer.routes[0].Port != 443 {
		t.Fatalf("dialed routes = %+v, want host.corp.internal:443", dialer.routes)
	}

	// NOT fronted by any reachable route (and no app-map entry) -> denied -> nothing dialed.
	dispatcher, dialer = build()
	frames, err = dispatcher.HandleFrame(context.Background(), routeDrivenOpenFrame("evil.example.com", 443))
	if err != nil {
		t.Fatalf("HandleFrame: %v", err)
	}
	if len(frames) != 1 || frames[0].Type != tunnel.FrameTCPOpenResult || frames[0].Error == "" {
		t.Fatalf("unfronted open = %+v, want a FrameTCPOpenResult carrying an error", frames)
	}
	if len(dialer.routes) != 0 {
		t.Fatalf("an unauthorized destination must NOT be dialed; dialed %+v", dialer.routes)
	}
}
