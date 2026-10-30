package main

import "testing"

// The requirement has to exempt the thing it requires. The control plane runs this same binary, so a check
// written only for Edges takes the control plane down with it — and it does so on the NEXT restart, not at
// deploy time, which is the worst possible moment to discover it. That is exactly what the first version of
// this gate did; it shipped in a state where the lab's control plane would have failed to come back.
//
// controlPlaneRequired is the decision alone, split out so it can be tested without a process that exits.
func TestControlPlaneRequirementExemptsTheControlPlaneItself(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		mode                  string
		isControlPlane        bool
		configSourceURL       string
		configSourceEndpoints string
		noControlPlane        bool
		wantRefuse            bool
	}{
		{name: "a plain Edge with no control plane is refused", mode: "edge", wantRefuse: true},
		{name: "an Edge pulling from one CP is fine", mode: "edge", configSourceURL: "https://cp:9443"},
		{name: "an Edge pulling from a region list is fine", mode: "edge", configSourceEndpoints: "region-a=https://cp:9443"},
		{name: "a HTTPS root origin with trailing slash is fine", mode: "edge", configSourceEndpoints: "region-a=https://cp:9443/"},
		{name: "an invalid region list is not a control plane", mode: "edge", configSourceEndpoints: "bad", wantRefuse: true},
		{name: "a partially invalid region list is not a reliable control plane", mode: "edge", configSourceEndpoints: "region-a=https://cp:9443;bad", wantRefuse: true},
		{name: "a malformed failover list cannot silently use the fixed URL", mode: "edge", configSourceURL: "https://cp:9443", configSourceEndpoints: "bad", wantRefuse: true},
		{name: "an insecure region list is not a control plane", mode: "edge", configSourceEndpoints: "region-a=http://cp:9443", wantRefuse: true},
		{name: "a query delimiter is not a CP origin", mode: "edge", configSourceEndpoints: "region-a=https://cp:9443?", wantRefuse: true},
		{name: "a zero port is not a CP origin", mode: "edge", configSourceEndpoints: "region-a=https://cp:0", wantRefuse: true},
		{name: "duplicate region names are not a control plane", mode: "edge", configSourceEndpoints: "region-a=https://cp-a:9443;REGION-A=https://cp-b:9443", wantRefuse: true},
		{name: "the control plane does not need a control plane", mode: "edge", isControlPlane: true},
		{name: "a batch worker enforces nothing and is exempt", mode: "postgres-export-worker"},
		{name: "a test harness may say so explicitly", mode: "edge", noControlPlane: true},
		// An empty mode is the zero value a caller gets wrong before it is the deliberate choice of a worker,
		// so it is treated as an Edge and held to the requirement.
		{name: "an unset mode is treated as an Edge", mode: "", wantRefuse: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := controlPlaneRequired(tc.mode, tc.isControlPlane, tc.configSourceURL, tc.configSourceEndpoints, tc.noControlPlane)
			if got != tc.wantRefuse {
				t.Fatalf("refuse = %v, want %v", got, tc.wantRefuse)
			}
		})
	}
}
