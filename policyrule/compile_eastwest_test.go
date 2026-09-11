package policyrule

import (
	"reflect"
	"testing"
)

type fakeEWResolver struct {
	src   map[string][]string
	dest  map[string][]string
	proto map[string][]string
}

func (f fakeEWResolver) SourceDeviceTokens(tenant string, ids []string) []string {
	var out []string
	for _, id := range ids {
		out = append(out, f.src[id]...)
	}
	return out
}
func (f fakeEWResolver) DestinationTokens(tenant string, ids []string) []string {
	var out []string
	for _, id := range ids {
		out = append(out, f.dest[id]...)
	}
	return out
}
func (f fakeEWResolver) ServiceProtocols(tenant, serviceID string) []string {
	return f.proto[serviceID]
}

func TestCompileEastWest(t *testing.T) {
	resolver := fakeEWResolver{
		src:   map[string][]string{"grp-clients": {"dev-alice", "dev-bob"}},
		dest:  map[string][]string{"grp-servers": {"db.internal", "fs.internal"}},
		proto: map[string][]string{"svc-smb": {"smb"}},
	}
	rules := []Rule{
		// Active outbound authenticate rule -> compiles, source wildcard, TTL carried.
		{ID: "r1", TenantID: "acme", Plane: PlaneEastWest, Direction: DirectionOutbound, Status: StatusActive, Priority: 100,
			Source: []string{"grp-clients"}, Destination: []string{"grp-servers"}, ServiceID: "svc-smb",
			Action: Action{Access: AccessAuthenticate, GrantTTLSeconds: 3600, DeviceAttestedAuto: true}},
		// Inbound rule -> NOT compiled (WFP enforces inbound).
		{ID: "r2", TenantID: "acme", Plane: PlaneEastWest, Direction: DirectionInbound, Status: StatusActive,
			Source: []string{"grp-servers"}, Destination: []string{"grp-servers"}, Action: Action{Access: AccessAllow}},
		// Disabled -> excluded.
		{ID: "r3", TenantID: "acme", Plane: PlaneEastWest, Direction: DirectionOutbound, Status: StatusDisabled,
			Source: []string{"grp-clients"}, Destination: []string{"grp-servers"}, Action: Action{Access: AccessDeny}},
		// Egress -> excluded.
		{ID: "r4", TenantID: "acme", Plane: PlaneEgress, Status: StatusActive,
			Source: []string{"grp-clients"}, Destination: []string{"grp-servers"}, Action: Action{Access: AccessAllow}},
	}

	got := CompileEastWest("acme", rules, resolver)
	if len(got) != 1 {
		t.Fatalf("compiled %d rules, want 1 (only the active outbound rule): %#v", len(got), got)
	}
	ew := got[0]
	if ew.ID != "r1" || ew.Priority != 100 || ew.Mode != "authenticate" || ew.MaxTTLSeconds != 3600 {
		t.Fatalf("compiled rule = %#v, want r1 authenticate ttl 3600", ew)
	}
	// "Sensitivity decides the mechanism": the authored DeviceAttestedAuto opt-in must reach the enforcement rule
	// (it used to be dropped by CompileEastWest, so device-attested was unreachable via authored/Console rules).
	if !ew.DeviceAttestedAuto {
		t.Fatalf("DeviceAttestedAuto = false, want it carried from the authored action")
	}
	if !reflect.DeepEqual(ew.Destinations, []string{"db.internal", "fs.internal"}) {
		t.Fatalf("destinations = %v, want resolved server tokens", ew.Destinations)
	}
	if !reflect.DeepEqual(ew.Protocols, []string{"smb"}) {
		t.Fatalf("protocols = %v, want [smb]", ew.Protocols)
	}
	// Source is RESTRICTED to the authored source's device identities (not wildcard).
	if !reflect.DeepEqual(ew.SourceDevices, []string{"dev-alice", "dev-bob"}) {
		t.Fatalf("source devices = %v, want the authored source devices", ew.SourceDevices)
	}

	// Explicit Any source/destination -> wildcard (no SourceDevices, no Destinations).
	anyRule := []Rule{{ID: "rA", TenantID: "acme", Plane: PlaneEastWest, Direction: DirectionOutbound, Status: StatusActive,
		Source: []string{SubjectAny}, Destination: []string{SubjectAny}, ServiceID: "svc-smb", Action: Action{Access: AccessDeny}}}
	gotA := CompileEastWest("acme", anyRule, resolver)
	if len(gotA) != 1 || len(gotA[0].SourceDevices) != 0 || len(gotA[0].Destinations) != 0 {
		t.Fatalf("Any source/dest = %#v, want wildcard (empty SourceDevices + Destinations)", gotA)
	}
	// A rule that does NOT opt in stays device-attested-off (high-sensitivity default: machine flow fails closed).
	if gotA[0].DeviceAttestedAuto {
		t.Fatalf("DeviceAttestedAuto = true for a rule that did not opt in, want false")
	}

	// A rule whose source resolves to no enrolled device compiles fail-closed (never-matching sentinel),
	// NOT wildcard.
	unresolved := []Rule{{ID: "r9", TenantID: "acme", Plane: PlaneEastWest, Direction: DirectionOutbound, Status: StatusActive,
		Source: []string{"grp-unenrolled"}, Destination: []string{"grp-servers"}, ServiceID: "svc-smb", Action: Action{Access: AccessDeny}}}
	gotU := CompileEastWest("acme", unresolved, resolver)
	if len(gotU) != 1 || len(gotU[0].SourceDevices) != 1 || gotU[0].SourceDevices[0] == "" || gotU[0].SourceDevices[0] != sourceNoMatchSentinel {
		t.Fatalf("unresolved source = %#v, want fail-closed sentinel", gotU)
	}
}
