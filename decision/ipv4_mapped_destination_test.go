package decision

import (
	"testing"

	"github.com/lantern-networks/dsse-core/model"
)

// Windows dual-stack sockets report an IPv4 destination as ::ffff:a.b.c.d.
// A deny rule for that address must still win over a later allow-all rule.
func TestIPv4MappedDestinationCannotEvadeEndpointDeny(t *testing.T) {
	for name, endpoint := range map[string]any{
		"address": "10.200.0.10",
		"cidr":    "10.200.0.0/24",
	} {
		t.Run(name, func(t *testing.T) {
			evaluator := testEvaluatorWithPolicies([]model.Policy{
				{ID: "endpoint-deny", TenantID: "tenant_lab_001", Priority: 1,
					Conditions: map[string]any{"fqdn": endpoint, "destination_port": 18082},
					Action:     model.PolicyAction{Decision: "deny"}, Status: "active"},
				{ID: "fallback-allow", TenantID: "tenant_lab_001", Priority: 100,
					Action: model.PolicyAction{Decision: "allow"}, Status: "active"},
			})
			for _, tc := range []struct {
				destination string
				port        int
				wantPolicy  string
			}{
				{"10.200.0.10", 18082, "endpoint-deny"},
				{"::ffff:10.200.0.10", 18082, "endpoint-deny"},
				{"::ffff:ac8:a", 18082, "endpoint-deny"},
				{"::ffff:10.200.0.10", 18081, "fallback-allow"},
				{"::ffff:10.201.0.10", 18082, "fallback-allow"},
				{"2001:db8::10", 18082, "fallback-allow"},
				{"private.example.test", 18082, "fallback-allow"},
			} {
				got := evaluator.Evaluate(model.DecisionRequest{TenantID: "tenant_lab_001", ActorType: "human",
					Destination: tc.destination, DestinationPort: tc.port, Protocol: "tcp"})
				if got.PolicyID != tc.wantPolicy {
					t.Errorf("%s:%d matched %q (%s), want %q", tc.destination, tc.port, got.PolicyID, got.Decision, tc.wantPolicy)
				}
			}
		})
	}
}

func TestCIDRConditionMatchesIPv4MappedAddress(t *testing.T) {
	for _, tc := range []struct {
		address string
		prefix  string
		want    bool
	}{
		{"::ffff:10.200.0.10", "10.200.0.0/24", true},
		{"::ffff:10.201.0.10", "10.200.0.0/24", false},
		{"::ffff:10.200.0.10", "::ffff:10.200.0.0/120", true},
		{"2001:db8::10", "2001:db8::/64", true},
		{"2001:db9::10", "2001:db8::/64", false},
		{"2001:db8::10", "10.200.0.0/24", false},
	} {
		if got := conditionMatches([]string{tc.address}, map[string]any{"op": "cidr_contains", "value": tc.prefix}); got != tc.want {
			t.Errorf("%s within %s = %v, want %v", tc.address, tc.prefix, got, tc.want)
		}
	}
}
