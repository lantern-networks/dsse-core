package policyrule

import (
	"reflect"
	"testing"
)

// TestCompileEastWestCarriesRiskAtLeast is the regression guard for the silent risk-gate drop: the Console
// renders and POSTs risk_at_least for BOTH planes (console/rules.js:779,810), but CompileEastWest used to
// ignore it, so an authored "east-west / risk>=high / deny" saved successfully and compiled to an UNGATED
// deny — it bit at every risk level, the opposite of the operator's intent, with no warning.
func TestCompileEastWestCarriesRiskAtLeast(t *testing.T) {
	resolver := fakeEWResolver{
		src:   map[string][]string{"grp-clients": {"dev-alice"}},
		dest:  map[string][]string{"grp-servers": {"db.internal"}},
		proto: map[string][]string{"svc-ssh": {"ssh"}},
	}
	rules := []Rule{
		{ID: "gated", TenantID: "acme", Plane: PlaneEastWest, Direction: DirectionOutbound, Status: StatusActive, Priority: 100,
			Source: []string{"grp-clients"}, Destination: []string{"grp-servers"}, ServiceID: "svc-ssh",
			RiskAtLeast: "high", Action: Action{Access: AccessDeny}},
		{ID: "ungated", TenantID: "acme", Plane: PlaneEastWest, Direction: DirectionOutbound, Status: StatusActive, Priority: 200,
			Source: []string{"grp-clients"}, Destination: []string{"grp-servers"}, ServiceID: "svc-ssh",
			Action: Action{Access: AccessAllow}},
	}

	got := CompileEastWest("acme", rules, resolver)
	if len(got) != 2 {
		t.Fatalf("compiled %d rules, want 2: %#v", len(got), got)
	}

	// The authored threshold must reach the enforcement primitive, expanded to "that level or higher" — the
	// same expansion the egress compiler applies, so one authored value means the same thing on both planes.
	if want := []string{"high", "critical"}; !reflect.DeepEqual(got[0].RiskSeverities, want) {
		t.Fatalf("gated rule RiskSeverities = %#v, want %#v", got[0].RiskSeverities, want)
	}
	// An unauthored gate stays empty = wildcard, so ungated rules keep their previous behavior exactly.
	if len(got[1].RiskSeverities) != 0 {
		t.Fatalf("ungated rule RiskSeverities = %#v, want empty (no gate)", got[1].RiskSeverities)
	}
}

// TestCompileEastWestRiskAtLeastNoneIsNoGate pins that the "no gate" spellings compile to a wildcard rather
// than to a set that would never match.
func TestCompileEastWestRiskAtLeastNoneIsNoGate(t *testing.T) {
	resolver := fakeEWResolver{
		dest:  map[string][]string{"grp-servers": {"db.internal"}},
		proto: map[string][]string{"svc-ssh": {"ssh"}},
	}
	for _, threshold := range []string{"", "none", "NONE", "  "} {
		rules := []Rule{
			{ID: "r", TenantID: "acme", Plane: PlaneEastWest, Direction: DirectionOutbound, Status: StatusActive,
				Source: []string{SubjectAny}, Destination: []string{"grp-servers"}, ServiceID: "svc-ssh",
				RiskAtLeast: threshold, Action: Action{Access: AccessAllow}},
		}
		got := CompileEastWest("acme", rules, resolver)
		if len(got) != 1 {
			t.Fatalf("threshold %q: compiled %d rules, want 1", threshold, len(got))
		}
		if len(got[0].RiskSeverities) != 0 {
			t.Fatalf("threshold %q: RiskSeverities = %#v, want empty (no gate)", threshold, got[0].RiskSeverities)
		}
	}
}
