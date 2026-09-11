package decision

import (
	"testing"

	"github.com/lantern-networks/dsse-core/model"
)

// TestTransportClientCertVerifiedCondition verifies W2: a policy can require a verified mTLS
// device identity via transport_client_cert_verified, and gate on the transport_device_identity value.
func TestTransportClientCertVerifiedCondition(t *testing.T) {
	policy := model.Policy{
		ID: "pol_require_mtls", TenantID: "t", Status: "active", Priority: 10,
		Conditions: map[string]any{"service_family": "https", "transport_client_cert_verified": "true"},
		Action:     model.PolicyAction{Decision: "allow"},
	}
	ev := Evaluator{Policies: []model.Policy{policy}, PolicyBundle: model.PolicyBundle{TenantID: "t"}}
	base := model.DecisionRequest{TenantID: "t", ServiceFamily: "https", Destination: "app", DestinationPort: 443}

	// Verified mTLS -> matches -> allow.
	v := base
	v.TransportClientCertVerified = true
	if d := ev.Evaluate(v); d.Decision != "allow" {
		t.Fatalf("verified mTLS should allow, got %q (codes=%v)", d.Decision, d.ReasonCodes)
	}

	// Not verified (e.g., plaintext transport) -> policy does not match -> default deny.
	if d := ev.Evaluate(base); d.Decision == "allow" {
		t.Fatalf("unverified transport must not match an mTLS-required policy, got %q", d.Decision)
	}

	// Gate on a specific device identity value.
	idPolicy := model.Policy{
		ID: "pol_device_id", TenantID: "t", Status: "active", Priority: 10,
		Conditions: map[string]any{"transport_device_identity": "device-123"},
		Action:     model.PolicyAction{Decision: "allow"},
	}
	ev2 := Evaluator{Policies: []model.Policy{idPolicy}, PolicyBundle: model.PolicyBundle{TenantID: "t"}}
	match := base
	match.TransportDeviceIdentity = "device-123"
	if d := ev2.Evaluate(match); d.Decision != "allow" {
		t.Fatalf("matching device identity should allow, got %q", d.Decision)
	}
	other := base
	other.TransportDeviceIdentity = "device-999"
	if d := ev2.Evaluate(other); d.Decision == "allow" {
		t.Fatalf("non-matching device identity must not allow, got %q", d.Decision)
	}
}
