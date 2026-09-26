package policyrule

import (
	"reflect"
	"testing"
)

// fakeResolver maps subject ids to addresses for compiler tests.
type fakeResolver map[string][]string

func (f fakeResolver) EndpointAddresses(tenant string, ids []string) []string {
	var out []string
	for _, id := range ids {
		out = append(out, f[id]...)
	}
	return out
}

func TestEgressBypassFQDNs(t *testing.T) {
	resolver := fakeResolver{
		"ep-saas": {"app.example.com"},
		"grp-cdn": {"cdn1.example.net", "cdn2.example.net"},
		"ep-mac":  nil, // a steered device — no address
	}
	rules := []Rule{
		// An active Any-source bypass rule contributes tenant-wide destinations.
		// Device-only and unresolved sources are covered by inspection_source_scope_test.go.
		{ID: "r1", TenantID: "acme", Plane: PlaneEgress, Status: StatusActive, Source: []string{"*"}, Destination: []string{"ep-saas", "grp-cdn"}, Action: Action{Access: AccessAllow, Inspection: InspectionBypass}},
		// An egress rule that inspects (not bypass) -> excluded.
		{ID: "r2", TenantID: "acme", Plane: PlaneEgress, Status: StatusActive, Source: []string{"*"}, Destination: []string{"ep-saas"}, Action: Action{Access: AccessAllow, Inspection: InspectionInspect}},
		// A disabled bypass rule -> excluded.
		{ID: "r3", TenantID: "acme", Plane: PlaneEgress, Status: StatusDisabled, Source: []string{"*"}, Destination: []string{"ep-saas"}, Action: Action{Access: AccessAllow, Inspection: InspectionBypass}},
		// An east-west rule -> excluded (egress-only).
		{ID: "r4", TenantID: "acme", Plane: PlaneEastWest, Direction: DirectionOutbound, Status: StatusActive, Source: []string{"*"}, Destination: []string{"ep-saas"}, Action: Action{Access: AccessAllow, Inspection: InspectionBypass}},
	}
	got := EgressBypassFQDNs("acme", rules, resolver)
	want := []string{"app.example.com", "cdn1.example.net", "cdn2.example.net"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("EgressBypassFQDNs = %v, want %v", got, want)
	}

	// No bypass rules -> empty.
	if got := EgressBypassFQDNs("acme", rules[1:2], resolver); len(got) != 0 {
		t.Fatalf("inspect-only = %v, want empty", got)
	}
}

func TestEgressInspectFQDNs(t *testing.T) {
	resolver := fakeResolver{
		"ep-saas": {"app.example.com"},
		"grp-cdn": {"cdn1.example.net", "cdn2.example.net"},
		"ep-deny": {"blocked.example.com"},
	}
	rules := []Rule{
		// Active allow+inspect -> contributes (the "decrypt these under bypass-default" case).
		{ID: "r1", TenantID: "acme", Plane: PlaneEgress, Status: StatusActive, Source: []string{"*"}, Destination: []string{"ep-saas", "grp-cdn"}, Action: Action{Access: AccessAllow, Inspection: InspectionInspect}},
		// A bypass rule -> excluded (it raw-forwards, never decrypts).
		{ID: "r2", TenantID: "acme", Plane: PlaneEgress, Status: StatusActive, Source: []string{"*"}, Destination: []string{"ep-saas"}, Action: Action{Access: AccessAllow, Inspection: InspectionBypass}},
		// A deny rule inspects by model, but a denied flow is blocked, not decrypted -> excluded.
		{ID: "r3", TenantID: "acme", Plane: PlaneEgress, Status: StatusActive, Source: []string{"*"}, Destination: []string{"ep-deny"}, Action: Action{Access: AccessDeny, Inspection: InspectionInspect}},
		// A disabled inspect rule -> excluded.
		{ID: "r4", TenantID: "acme", Plane: PlaneEgress, Status: StatusDisabled, Source: []string{"*"}, Destination: []string{"ep-saas"}, Action: Action{Access: AccessAllow, Inspection: InspectionInspect}},
		// An authenticate+inspect rule -> contributes (a step-up flow is decrypted once allowed).
		{ID: "r5", TenantID: "acme", Plane: PlaneEgress, Status: StatusActive, Source: []string{"*"}, Destination: []string{"ep-deny"}, Action: Action{Access: AccessAuthenticate, Inspection: InspectionInspect}},
		// An east-west rule -> excluded (egress-only).
		{ID: "r6", TenantID: "acme", Plane: PlaneEastWest, Direction: DirectionOutbound, Status: StatusActive, Source: []string{"*"}, Destination: []string{"ep-saas"}, Action: Action{Access: AccessAllow, Inspection: InspectionInspect}},
	}
	got := EgressInspectFQDNs("acme", rules, resolver)
	// app.example.com + the two CDNs (r1) + blocked.example.com (r5 authenticate). Sorted.
	want := []string{"app.example.com", "blocked.example.com", "cdn1.example.net", "cdn2.example.net"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("EgressInspectFQDNs = %v, want %v", got, want)
	}
	// Only a bypass rule -> empty.
	if got := EgressInspectFQDNs("acme", rules[1:2], resolver); len(got) != 0 {
		t.Fatalf("bypass-only = %v, want empty", got)
	}
}
