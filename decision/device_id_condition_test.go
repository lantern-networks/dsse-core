package decision

import (
	"testing"

	"github.com/lantern-networks/dsse-core/model"
)

// A policy with a device_id condition (a list => "in") gates on req.DeviceID, AND-combined with fqdn — the
// shape the egress access compiler emits to source-restrict an authored egress rule by device.
func TestPolicyDeviceIDCondition(t *testing.T) {
	policy := model.Policy{
		ID:         "p1",
		Status:     "active",
		Conditions: map[string]any{"fqdn": "evil.example.com", "device_id": []any{"dev-alice", "dev-bob"}},
		Action:     model.PolicyAction{Decision: "deny"},
	}
	if ok, _ := matchPolicy(policy, model.DecisionRequest{FQDN: "evil.example.com", DeviceID: "dev-alice"}, "human"); !ok {
		t.Fatalf("should match a listed device at the fqdn")
	}
	if ok, _ := matchPolicy(policy, model.DecisionRequest{FQDN: "evil.example.com", DeviceID: "dev-eve"}, "human"); ok {
		t.Fatalf("must NOT match an unlisted device (source restricted)")
	}
	if ok, _ := matchPolicy(policy, model.DecisionRequest{FQDN: "ok.example.com", DeviceID: "dev-alice"}, "human"); ok {
		t.Fatalf("must NOT match a different fqdn (AND of conditions)")
	}
}
