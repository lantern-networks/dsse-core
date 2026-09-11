package main

import "testing"

func newTransportContractPublisher(t *testing.T, cfg localNetworkExtensionSnapshotPublisherConfig) *localNetworkExtensionSnapshotPublisher {
	t.Helper()
	if cfg.OutputDir == "" {
		cfg.OutputDir = t.TempDir()
	}
	if cfg.EdgeURL == "" {
		cfg.EdgeURL = "https://203.0.113.10:18090"
	}
	if cfg.RuntimeCopyTransportScope == "" {
		cfg.RuntimeCopyTransportScope = "real_edge"
	}
	pub, err := newLocalNetworkExtensionSnapshotPublisher(cfg)
	if err != nil {
		t.Fatalf("new publisher: %v", err)
	}
	if pub == nil {
		t.Fatalf("expected a publisher")
	}
	return pub
}

func TestAgentConfigPublishesTransportContractWhenConfigured(t *testing.T) {
	pub := newTransportContractPublisher(t, localNetworkExtensionSnapshotPublisherConfig{
		TransportTLSURL:       "https://203.0.113.10:18543",
		TransportPinnedCARef:  "transport_ca.pem",
		TransportMTLSRequired: true,
	})
	cfg := pub.agentConfig("tenant_lab_001")
	raw, ok := cfg["network_extension_transport"]
	if !ok {
		t.Fatalf("expected network_extension_transport block when transport TLS URL is set")
	}
	transport, ok := raw.(map[string]any)
	if !ok {
		t.Fatalf("transport block has wrong type: %T", raw)
	}
	if transport["transport_tls_url"] != "https://203.0.113.10:18543" {
		t.Fatalf("transport_tls_url = %v", transport["transport_tls_url"])
	}
	if transport["mtls_required"] != true {
		t.Fatalf("mtls_required = %v, want true", transport["mtls_required"])
	}
	if transport["pinned_ca_ref"] != "transport_ca.pem" {
		t.Fatalf("pinned_ca_ref = %v", transport["pinned_ca_ref"])
	}
	// DNS-over-tunnel default path is published so the NE knows where to send DNS.
	if transport["dns_over_tunnel_path"] != networkExtensionSnapshotDefaultDNSOverTunnelPath {
		t.Fatalf("dns_over_tunnel_path = %v, want %q", transport["dns_over_tunnel_path"], networkExtensionSnapshotDefaultDNSOverTunnelPath)
	}
	if transport["dns_over_tunnel_supported"] != true {
		t.Fatalf("dns_over_tunnel_supported should be true")
	}
}

func TestAgentConfigOmitsTransportContractWhenUnset(t *testing.T) {
	pub := newTransportContractPublisher(t, localNetworkExtensionSnapshotPublisherConfig{})
	if _, ok := pub.agentConfig("tenant_lab_001")["network_extension_transport"]; ok {
		t.Fatalf("transport block must be omitted when no transport TLS URL is configured (additive, non-breaking)")
	}
}

func TestAgentConfigTransportContractOmitsPinnedCARefWhenEmpty(t *testing.T) {
	pub := newTransportContractPublisher(t, localNetworkExtensionSnapshotPublisherConfig{
		TransportTLSURL: "https://203.0.113.10:18543",
	})
	transport := pub.agentConfig("tenant_lab_001")["network_extension_transport"].(map[string]any)
	if _, ok := transport["pinned_ca_ref"]; ok {
		t.Fatalf("pinned_ca_ref should be omitted when not configured")
	}
	// Default DNS path still present.
	if transport["dns_over_tunnel_path"] != networkExtensionSnapshotDefaultDNSOverTunnelPath {
		t.Fatalf("expected default dns path")
	}
}

// The recovery endpoint has to reach endpoints through this snapshot: it is a FLEET-WIDE value, which is
// exactly what this config can carry, and without it a device that expired while switched off has nowhere to
// renew and needs manual re-enrolment.
func TestTransportContractPublishesTheRenewalRecoveryEndpoint(t *testing.T) {
	pub := newTransportContractPublisher(t, localNetworkExtensionSnapshotPublisherConfig{
		TransportTLSURL:         "https://203.0.113.10:18543",
		TransportPinnedCARef:    "transport_ca.pem",
		RenewalRecoveryEndpoint: "203.0.113.10:18545",
	})
	transport, ok := pub.agentConfig("tenant_lab_001")["network_extension_transport"].(map[string]any)
	if !ok {
		t.Fatal("expected a network_extension_transport block")
	}
	if got := transport["renewal_recovery_endpoint"]; got != "203.0.113.10:18545" {
		t.Fatalf("renewal_recovery_endpoint = %v, want the configured endpoint", got)
	}

	// Unset stays absent, so an endpoint that has never been told about recovery simply does not attempt it
	// rather than dialling an empty target.
	bare := newTransportContractPublisher(t, localNetworkExtensionSnapshotPublisherConfig{
		TransportTLSURL: "https://203.0.113.10:18543",
	})
	bareTransport, _ := bare.agentConfig("tenant_lab_001")["network_extension_transport"].(map[string]any)
	if _, present := bareTransport["renewal_recovery_endpoint"]; present {
		t.Fatal("an unconfigured recovery endpoint must be omitted, not published empty")
	}
}
