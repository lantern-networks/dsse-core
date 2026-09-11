package main

import "testing"

func TestValidateConnectorStartupModeAllowsDefaultEdgeRegistration(t *testing.T) {
	err := validateConnectorStartupMode(connectorStartupMode{
		SkipEdgeRegistration: false,
		EnableTunnel:         true,
		IdentitySync:         true,
	})
	if err != nil {
		t.Fatalf("default Edge registration mode returned error: %v", err)
	}
}

func TestValidateConnectorStartupModeAllowsLocalEndpointOnly(t *testing.T) {
	err := validateConnectorStartupMode(connectorStartupMode{
		SkipEdgeRegistration: true,
		EnableTunnel:         false,
		IdentitySync:         false,
	})
	if err != nil {
		t.Fatalf("local endpoint-only startup mode returned error: %v", err)
	}
}

func TestValidateConnectorStartupModeRejectsTunnelWithoutRegistration(t *testing.T) {
	err := validateConnectorStartupMode(connectorStartupMode{
		SkipEdgeRegistration: true,
		EnableTunnel:         true,
		IdentitySync:         false,
	})
	if err == nil {
		t.Fatal("expected tunnel without Edge registration to be rejected")
	}
}

func TestValidateConnectorStartupModeRejectsIdentitySyncWithoutRegistration(t *testing.T) {
	err := validateConnectorStartupMode(connectorStartupMode{
		SkipEdgeRegistration: true,
		EnableTunnel:         false,
		IdentitySync:         true,
	})
	if err == nil {
		t.Fatal("expected identity sync without Edge registration to be rejected")
	}
}
