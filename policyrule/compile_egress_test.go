package policyrule

import (
	"strings"
	"testing"
)

type fakeEgressResolver struct {
	src   map[string][]string
	addr  map[string][]string
	ports map[string][]int
}

func (f fakeEgressResolver) SourceDeviceTokens(tenant string, ids []string) []string {
	var out []string
	for _, id := range ids {
		out = append(out, f.src[id]...)
	}
	return out
}
func (f fakeEgressResolver) EndpointAddresses(tenant string, ids []string) []string {
	var out []string
	for _, id := range ids {
		out = append(out, f.addr[id]...)
	}
	return out
}
func (f fakeEgressResolver) ServicePorts(tenant string, serviceID string) []int {
	return f.ports[serviceID]
}

func TestCompileEgressPolicies(t *testing.T) {
	resolver := fakeEgressResolver{
		src:  map[string][]string{"grp-macs": {"dev-alice"}},
		addr: map[string][]string{"ep-bad": {"evil.example.com"}},
	}
	rules := []Rule{
		{ID: "r1", Plane: PlaneEgress, Status: StatusActive, Priority: 10, Source: []string{"grp-macs"}, Destination: []string{"ep-bad"}, Action: Action{Access: AccessDeny, Inspection: InspectionInspect}},
		{ID: "r2", Plane: PlaneEgress, Status: StatusActive, Priority: 20, Source: []string{"grp-macs"}, Destination: []string{"ep-bad"}, Action: Action{Access: AccessAuthenticate, RequiredIdPID: "idp_okta", MinACR: "phr", RequiredAMR: []string{"fido"}, MaxAgeSeconds: 900}},
		{ID: "r3", Plane: PlaneEastWest, Direction: DirectionOutbound, Status: StatusActive, Source: []string{"grp-macs"}, Destination: []string{"ep-bad"}, Action: Action{Access: AccessAllow}}, // wrong plane -> skipped
	}
	got := CompileEgressPolicies("acme", rules, resolver)
	// each specific-destination rule emits BOTH an fqdn-keyed and an sni-keyed policy (a steered browser flow is
	// identified by SNI), so deny x{fqdn,sni} + authenticate x{fqdn,sni} = 4.
	if len(got) != 4 {
		t.Fatalf("compiled %d policies, want 4: %#v", len(got), got)
	}
	denyFqdn, denySni, authSni := false, false, false
	for _, p := range got {
		devs, _ := p.Conditions["device_id"].([]any)
		srcOK := len(devs) == 1 && devs[0] == "dev-alice"
		if p.Action.Decision == "deny" && p.Conditions["fqdn"] == "evil.example.com" && srcOK {
			denyFqdn = true
		}
		if p.Action.Decision == "deny" && p.Conditions["sni"] == "evil.example.com" && srcOK {
			denySni = true
		}
		if p.Action.Decision == "require_reauthentication" && p.Conditions["sni"] == "evil.example.com" {
			authSni = true
			if p.Metadata["required_idp_id"] != "idp_okta" || p.Metadata["min_acr"] != "phr" || p.Metadata["required_amr"] != "fido" || p.Metadata["max_age_seconds"] != 900 {
				t.Fatalf("authenticate metadata = %#v, want idp_okta/phr/fido/900", p.Metadata)
			}
		}
	}
	if !denyFqdn || !denySni {
		t.Fatalf("deny rule must emit both fqdn and sni policies (fqdn=%v sni=%v)", denyFqdn, denySni)
	}
	if !authSni {
		t.Fatal("authenticate rule must emit an sni policy with require_reauthentication + step-up metadata")
	}

	// A source that resolves to no device compiles fail-closed (sentinel), never any-source.
	unresolved := []Rule{{ID: "r9", Plane: PlaneEgress, Status: StatusActive, Source: []string{"grp-empty"}, Destination: []string{"ep-bad"}, Action: Action{Access: AccessAllow}}}
	gu := CompileEgressPolicies("acme", unresolved, resolver)
	if len(gu) != 2 { // fqdn + sni
		t.Fatalf("unresolved compiled %d, want 2", len(gu))
	}
	for _, p := range gu {
		if devs, _ := p.Conditions["device_id"].([]any); len(devs) != 1 || devs[0] != sourceNoMatchSentinel {
			t.Fatalf("unresolved device_id = %v, want fail-closed sentinel", p.Conditions["device_id"])
		}
	}
}

func TestCompileEgressPortScope(t *testing.T) {
	resolver := fakeEgressResolver{
		src:   map[string][]string{"grp-macs": {"dev-alice"}},
		addr:  map[string][]string{"ep-ssh": {"ssh.example.com"}},
		ports: map[string][]int{"svc-ssh": {22}},
	}
	// An egress rule for the SSH service (tcp/22) must compile a destination_port=22 condition — NOT match
	// every port. A rule with no service falls back to the egress default 443.
	rules := []Rule{
		{ID: "r-ssh", Plane: PlaneEgress, Status: StatusActive, Source: []string{"grp-macs"}, Destination: []string{"ep-ssh"}, ServiceID: "svc-ssh", Action: Action{Access: AccessAuthenticate}},
		{ID: "r-web", Plane: PlaneEgress, Status: StatusActive, Source: []string{"grp-macs"}, Destination: []string{"ep-ssh"}, Action: Action{Access: AccessDeny}},
	}
	got := CompileEgressPolicies("acme", rules, resolver)
	for _, p := range got {
		dp, has := p.Conditions["destination_port"]
		if strings.Contains(p.ID, "r-ssh") {
			if dp != 22 {
				t.Errorf("SSH-service policy %s destination_port=%v, want 22 (service must scope the port, not match all)", p.ID, dp)
			}
		} else if has { // r-web has no service -> stays port-agnostic (a broad rule must keep matching any port)
			t.Errorf("no-service policy %s got destination_port=%v, want none (any port)", p.ID, dp)
		}
	}
}

func TestCompileEgressPoliciesAny(t *testing.T) {
	resolver := fakeEgressResolver{
		src:  map[string][]string{"grp-macs": {"dev-alice"}},
		addr: map[string][]string{"ep-bad": {"evil.example.com"}},
	}
	// Any source -> no device_id; a specific destination emits fqdn + sni policies.
	anySrc := CompileEgressPolicies("acme", []Rule{{ID: "r1", Plane: PlaneEgress, Status: StatusActive, Source: []string{SubjectAny}, Destination: []string{"ep-bad"}, Action: Action{Access: AccessDeny}}}, resolver)
	if len(anySrc) != 2 {
		t.Fatalf("any-source specific-dest compiled %d, want 2 (fqdn+sni)", len(anySrc))
	}
	gotFqdn, gotSni := false, false
	for _, p := range anySrc {
		if _, has := p.Conditions["device_id"]; has {
			t.Fatalf("Any source must omit device_id, got %v", p.Conditions)
		}
		if p.Conditions["fqdn"] == "evil.example.com" {
			gotFqdn = true
		}
		if p.Conditions["sni"] == "evil.example.com" {
			gotSni = true
		}
	}
	if !gotFqdn || !gotSni {
		t.Fatalf("specific destination should emit both fqdn and sni, got %#v", anySrc)
	}

	// Any destination -> one policy with no host condition; specific source keeps device_id.
	anyDst := CompileEgressPolicies("acme", []Rule{{ID: "r2", Plane: PlaneEgress, Status: StatusActive, Source: []string{"grp-macs"}, Destination: []string{SubjectAny}, Action: Action{Access: AccessAllow}}}, resolver)
	if len(anyDst) != 1 {
		t.Fatalf("any-dest compiled %d, want 1", len(anyDst))
	}
	if _, has := anyDst[0].Conditions["fqdn"]; has {
		t.Fatalf("Any destination must omit fqdn, got %v", anyDst[0].Conditions)
	}
	if _, has := anyDst[0].Conditions["sni"]; has {
		t.Fatalf("Any destination must omit sni, got %v", anyDst[0].Conditions)
	}
	if _, has := anyDst[0].Conditions["device_id"]; !has {
		t.Fatalf("specific source should keep device_id, got %v", anyDst[0].Conditions)
	}

	// Any -> Any: a catch-all policy with no conditions.
	anyAny := CompileEgressPolicies("acme", []Rule{{ID: "r3", Plane: PlaneEgress, Status: StatusActive, Source: []string{SubjectAny}, Destination: []string{SubjectAny}, Action: Action{Access: AccessDeny}}}, resolver)
	if len(anyAny) != 1 || len(anyAny[0].Conditions) != 0 {
		t.Fatalf("Any->Any = %#v, want one policy with no conditions", anyAny)
	}
}

func TestCompileEgressIdentitySource(t *testing.T) {
	resolver := fakeEgressResolver{
		src:  map[string][]string{"grp-macs": {"dev-alice"}},
		addr: map[string][]string{"ep-app": {"corp.internal"}},
	}
	// A published-app access rule: the "Who" is an IdP identity group (idgroup:Contractors), not a device.
	// It must compile to a user_groups condition (matched against the session's groups) and carry NO device_id.
	rules := []Rule{
		{ID: "id1", Plane: PlaneEgress, Status: StatusActive, Priority: 50, Source: []string{"idgroup:Contractors"}, Destination: []string{"ep-app"}, Action: Action{Access: AccessAllow, Inspection: InspectionBypass}},
	}
	got := CompileEgressPolicies("acme", rules, resolver)
	if len(got) != 2 { // fqdn + sni
		t.Fatalf("compiled %d policies, want 2: %#v", len(got), got)
	}
	for _, p := range got {
		if _, hasDevice := p.Conditions["device_id"]; hasDevice {
			t.Fatalf("identity-source rule must not emit a device_id condition: %#v", p.Conditions)
		}
		groups, ok := p.Conditions["user_groups"].([]any)
		if !ok || len(groups) != 1 || groups[0] != "Contractors" {
			t.Fatalf("want user_groups=[Contractors], got %#v", p.Conditions["user_groups"])
		}
		if p.Action.Decision != "allow" {
			t.Fatalf("want allow, got %q", p.Action.Decision)
		}
	}

	// A mixed source (device OR identity) compiles as an OR: one device_id policy + one user_groups policy per
	// destination key.
	mixed := []Rule{
		{ID: "id2", Plane: PlaneEgress, Status: StatusActive, Priority: 50, Source: []string{"grp-macs", "idgroup:Contractors"}, Destination: []string{"ep-app"}, Action: Action{Access: AccessAllow}},
	}
	gotMixed := CompileEgressPolicies("acme", mixed, resolver)
	if len(gotMixed) != 4 { // {fqdn,sni} x {device,identity}
		t.Fatalf("mixed source compiled %d policies, want 4: %#v", len(gotMixed), gotMixed)
	}
	device, identity := 0, 0
	for _, p := range gotMixed {
		if _, ok := p.Conditions["device_id"]; ok {
			device++
		}
		if _, ok := p.Conditions["user_groups"]; ok {
			identity++
		}
	}
	if device != 2 || identity != 2 {
		t.Fatalf("want 2 device + 2 identity policies, got device=%d identity=%d", device, identity)
	}
}

func TestCompileEgressAgentSource(t *testing.T) {
	resolver := fakeEgressResolver{}
	// An agent rule: the "Who" is an NHI (nhi:agent-x), the target is a TOOL boundary (no network destination),
	// the action allows within it. Compiles to ONE policy: actor_nhi_id condition + AllowedToolIDs, no device_id.
	rules := []Rule{
		{ID: "ar1", Plane: PlaneEgress, Status: StatusActive, Priority: 50, Source: []string{"nhi:agent-x"}, Destination: []string{SubjectAny}, AllowedToolIDs: []string{"read_repo", "open_pr"}, Action: Action{Access: AccessAllow}},
	}
	got := CompileEgressPolicies("acme", rules, resolver)
	if len(got) != 1 {
		t.Fatalf("agent rule compiled %d policies, want 1: %#v", len(got), got)
	}
	p := got[0]
	if _, hasDevice := p.Conditions["device_id"]; hasDevice {
		t.Fatalf("agent rule must not emit a device_id condition: %#v", p.Conditions)
	}
	actors, ok := p.Conditions["actor_nhi_id"].([]any)
	if !ok || len(actors) != 1 || actors[0] != "agent-x" {
		t.Fatalf("want actor_nhi_id=[agent-x], got %#v", p.Conditions["actor_nhi_id"])
	}
	if len(p.AllowedToolIDs) != 2 || p.AllowedToolIDs[0] != "read_repo" || p.AllowedToolIDs[1] != "open_pr" {
		t.Fatalf("want AllowedToolIDs=[read_repo open_pr], got %#v", p.AllowedToolIDs)
	}
	if p.Action.Decision != "allow" {
		t.Fatalf("want allow, got %q", p.Action.Decision)
	}
}

func TestCompileEgressIndividualUserSource(t *testing.T) {
	resolver := fakeEgressResolver{}
	// An individual-user rule: the "Who" is one IdP person (iduser:alice-sub). Compiles to ONE policy with a
	// user_id condition (matched against the request's user_id), never a device_id — one person from any device.
	rules := []Rule{
		{ID: "ur1", Plane: PlaneEgress, Status: StatusActive, Priority: 40, Source: []string{"iduser:alice-sub"}, Destination: []string{SubjectAny}, Action: Action{Access: AccessAllow}},
	}
	got := CompileEgressPolicies("acme", rules, resolver)
	if len(got) != 1 {
		t.Fatalf("individual-user rule compiled %d policies, want 1: %#v", len(got), got)
	}
	p := got[0]
	if _, hasDevice := p.Conditions["device_id"]; hasDevice {
		t.Fatalf("individual-user rule must not emit a device_id condition: %#v", p.Conditions)
	}
	users, ok := p.Conditions["user_id"].([]any)
	if !ok || len(users) != 1 || users[0] != "alice-sub" {
		t.Fatalf("want user_id=[alice-sub], got %#v", p.Conditions["user_id"])
	}
}

func TestIdentityUserToken(t *testing.T) {
	if u, ok := IdentityUserToken("iduser:alice-sub"); !ok || u != "alice-sub" {
		t.Fatalf("IdentityUserToken(iduser:alice-sub) = %q,%v", u, ok)
	}
	if _, ok := IdentityUserToken("idgroup:Engineering"); ok {
		t.Fatalf("IdentityUserToken must not match an idgroup")
	}
	if _, ok := IdentityUserToken("iduser:"); ok {
		t.Fatalf("IdentityUserToken must reject an empty id")
	}
}

func TestCompileEgressRiskAtLeast(t *testing.T) {
	resolver := fakeEgressResolver{}
	// A risk-gated rule: any source, but only bites when the subject's risk is >= high (device or user marked
	// high-risk), and then forces re-auth (access=authenticate). Compiles to a risk_state_severity condition.
	rules := []Rule{
		{ID: "rk1", Plane: PlaneEgress, Status: StatusActive, Priority: 10, Source: []string{SubjectAny}, Destination: []string{SubjectAny}, RiskAtLeast: "high", Action: Action{Access: AccessAuthenticate}},
	}
	got := CompileEgressPolicies("acme", rules, resolver)
	if len(got) == 0 {
		t.Fatalf("risk-gated rule compiled 0 policies")
	}
	rv, ok := got[0].Conditions["risk_state_severity"].([]any)
	if !ok {
		t.Fatalf("want a risk_state_severity condition, got %#v", got[0].Conditions)
	}
	set := map[string]bool{}
	for _, v := range rv {
		set[v.(string)] = true
	}
	if !set["high"] || !set["critical"] || set["low"] || set["medium"] {
		t.Fatalf("risk_at_least=high should match {high,critical}, got %#v", rv)
	}
	if got[0].Action.Decision != "require_reauthentication" {
		t.Fatalf("want require_reauthentication (authenticate), got %q", got[0].Action.Decision)
	}
}

func TestRiskSeveritiesAtLeast(t *testing.T) {
	if s := RiskSeveritiesAtLeast("high"); len(s) != 2 || s[0] != "high" || s[1] != "critical" {
		t.Fatalf("RiskSeveritiesAtLeast(high) = %#v", s)
	}
	if s := RiskSeveritiesAtLeast(""); s != nil {
		t.Fatalf("empty threshold should be nil, got %#v", s)
	}
	if s := RiskSeveritiesAtLeast("none"); s != nil {
		t.Fatalf("none should be nil, got %#v", s)
	}
}
