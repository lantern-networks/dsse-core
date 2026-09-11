package main

import "testing"

func TestNetworkExtensionRuntimeCopyDownstreamPassthroughConfigDefaultsLabTLSRealEdge(t *testing.T) {
	identifiers, defaultTunnel := networkExtensionRuntimeCopyDownstreamPassthroughConfig(true, "*", "real_edge", "", false)
	if len(identifiers) != 1 || identifiers[0] != "a.out" {
		t.Fatalf("identifiers = %#v, want a.out lab default", identifiers)
	}
	if !defaultTunnel {
		t.Fatal("defaultTunnel = false, want true for lab TLS real_edge default")
	}
}

func TestNetworkExtensionRuntimeCopyDownstreamPassthroughConfigPreservesExplicitInput(t *testing.T) {
	identifiers, defaultTunnel := networkExtensionRuntimeCopyDownstreamPassthroughConfig(true, "*", "real_edge", "edge.helper,edge.worker", false)
	if len(identifiers) != 2 || identifiers[0] != "edge.helper" || identifiers[1] != "edge.worker" {
		t.Fatalf("identifiers = %#v, want explicit identifiers", identifiers)
	}
	if defaultTunnel {
		t.Fatal("defaultTunnel = true, want explicit false preserved")
	}
}

func TestNetworkExtensionRuntimeCopyDownstreamPassthroughConfigDoesNotDefaultOutsideLabTLSRealEdge(t *testing.T) {
	tests := []struct {
		name      string
		devMode   bool
		hosts     string
		transport string
	}{
		{name: "not lab", devMode: false, hosts: "*", transport: "real_edge"},
		{name: "no lab TLS hosts", devMode: true, hosts: "", transport: "real_edge"},
		{name: "lab endpoint", devMode: true, hosts: "*", transport: "lab_endpoint"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			identifiers, defaultTunnel := networkExtensionRuntimeCopyDownstreamPassthroughConfig(tt.devMode, tt.hosts, tt.transport, "", false)
			if len(identifiers) != 0 {
				t.Fatalf("identifiers = %#v, want none", identifiers)
			}
			if defaultTunnel {
				t.Fatal("defaultTunnel = true, want false")
			}
		})
	}
}
