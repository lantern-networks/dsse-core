package main

import (
	"os"
	"strings"
	"testing"
)

// ★ THE REACHABILITY TEST MUST NOT ASK A NARROWER QUESTION THAN THE FLOW (2026-09-03, measured).
//
// It answered "Connector tunnel not connected" for a connector sitting on another region's door while a
// steered device fetched the app through this same Edge over the peer-Edge relay. The cause was one lookup:
// tunnelManager.Get(conn.ID), which is true only for a connector attached HERE.
func TestReachabilityUsesTheSameReachResolutionAsAFlow(t *testing.T) {
	body, err := os.ReadFile("admin_application_routes.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(body)
	probe := strings.Index(src, "edgeplane.ConnectorProbeSession(")
	if probe < 0 {
		t.Fatal("the reachability probe no longer resolves the session the way the data path does, so a " +
			"connector reachable only over the peer-Edge relay reads as \"tunnel not connected\"")
	}
	// The old lookup must not be what decides tunnelConnected any more.
	if i := strings.Index(src, "session, tunnelConnected = tunnelManager.Get(conn.ID)"); i >= 0 {
		t.Error("tunnelConnected is decided by this node's own tunnel manager again")
	}
	if !strings.Contains(src, "config.PeerEdges") {
		t.Error("the probe cannot reach across regions: no peer-Edge provider is passed")
	}
}
