package policyrule

import "testing"

// TestCompileEastWestUnresolvedDestinationFailsClosed pins fail-open review finding #10 (east-west destination): a
// non-Any destination that resolves to ZERO tokens must NOT collapse to the any-destination wildcard; it emits
// the no-match sentinel so the rule matches nothing (symmetric with the source path).
func TestCompileEastWestUnresolvedDestinationFailsClosed(t *testing.T) {
	resolver := fakeEWResolver{
		src:   map[string][]string{"grp-clients": {"dev-a"}},
		proto: map[string][]string{"svc-ssh": {"ssh"}},
		// dest map empty => the destination resolves to zero tokens.
	}
	rules := []Rule{{
		ID: "r-deny", TenantID: "acme", Plane: PlaneEastWest, Direction: DirectionOutbound, Status: StatusActive,
		Priority: 100, Source: []string{"grp-clients"}, Destination: []string{"grp-gone"}, ServiceID: "svc-ssh",
		Action: Action{Access: "deny"},
	}}
	got := CompileEastWest("acme", rules, resolver)
	if len(got) != 1 {
		t.Fatalf("compiled %d rules, want 1", len(got))
	}
	dests := got[0].Destinations
	if len(dests) != 1 || dests[0] != destinationNoMatchSentinel {
		t.Fatalf("unresolved non-Any destination must be the no-match sentinel (not empty=wildcard), got %v", dests)
	}
}

// TestCompileEgressUnresolvedDestinationDoesNotVanish pins fail-open review finding #10 (egress destination): a
// non-Any destination that resolves to ZERO addresses must NOT emit no policy at all (a DENY would silently stop
// enforcing). It emits a match-nothing sentinel policy so the rule stays present.
func TestCompileEgressUnresolvedDestinationDoesNotVanish(t *testing.T) {
	resolver := fakeEgressResolver{src: map[string][]string{"grp": {"dev-a"}}} // addr map empty => destination resolves to nothing
	rules := []Rule{{ID: "deny-gone", Plane: PlaneEgress, Status: StatusActive, Source: []string{"grp"}, Destination: []string{"ep-removed"}, Action: Action{Access: AccessDeny}}}
	got := CompileEgressPolicies("acme", rules, resolver)
	if len(got) == 0 {
		t.Fatal("an unresolved-destination deny must NOT vanish — expected a match-nothing sentinel policy")
	}
	for _, p := range got {
		if p.Conditions["fqdn"] != destinationNoMatchSentinel {
			t.Fatalf("expected the sentinel fqdn (match-nothing), got %v", p.Conditions["fqdn"])
		}
	}
}

// A missing named service must not acquire an unrelated HTTPS meaning.
func TestCompileEgressNamedServiceZeroPortsMatchesNothing(t *testing.T) {
	resolver := fakeEgressResolver{
		src:   map[string][]string{"grp": {"dev-a"}},
		addr:  map[string][]string{"ep": {"site.example.com"}},
		ports: map[string][]int{}, // svc-x resolves to zero ports
	}
	rules := []Rule{{ID: "r", Plane: PlaneEgress, Status: StatusActive, Source: []string{"grp"}, Destination: []string{"ep"}, ServiceID: "svc-x", Action: Action{Access: AccessDeny}}}
	got := CompileEgressPolicies("acme", rules, resolver)
	if len(got) == 0 {
		t.Fatal("expected compiled policies")
	}
	for _, p := range got {
		if values, ok := p.Conditions["protocol"].([]any); !ok || len(values) != 0 {
			t.Fatalf("missing service must match no protocol, got %v", p.Conditions)
		}
	}

	// A NO-service rule (empty ServiceID) stays intentionally port-agnostic (no destination_port condition).
	noSvc := []Rule{{ID: "r2", Plane: PlaneEgress, Status: StatusActive, Source: []string{"grp"}, Destination: []string{"ep"}, Action: Action{Access: AccessDeny}}}
	for _, p := range CompileEgressPolicies("acme", noSvc, resolver) {
		if _, ok := p.Conditions["destination_port"]; ok {
			t.Fatalf("a no-service rule must stay port-agnostic, got destination_port=%v", p.Conditions["destination_port"])
		}
	}
}
