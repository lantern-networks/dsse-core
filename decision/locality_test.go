package decision

import (
	"testing"

	"github.com/lantern-networks/dsse-core/model"
)

// The reported flow, as it actually arrived on win-dev-1: the WFP redirect recovers the ORIGINAL destination,
// so a connect-by-name shows up here as the address it resolved to.
func githubSSH() model.DecisionRequest {
	return model.DecisionRequest{
		TenantID: "t", Destination: "20.27.177.113", DestinationPort: 22,
		Protocol: "tcp", ServiceFamily: "ssh", SteeringMode: "steer",
	}
}

func labSSH() model.DecisionRequest {
	r := githubSSH()
	r.Destination = "192.168.100.10"
	return r
}

// ★ The bug. Before this, plane membership came from the service family alone, so this request was held for
// an out-of-band IdP ceremony and dropped at 2m0s — with a step-up window on the desktop for a public code
// host, presenting to the operator as a broken network.
func TestSSHToAPublicHostIsNotLateralMovement(t *testing.T) {
	e := Evaluator{EastWestEnabled: true}
	if e.isEastWestFlow(githubSSH()) {
		t.Fatal("ssh to a public address must not be governed on the east-west plane")
	}
	// The protocol set itself is unchanged — the precondition is what was added.
	if !IsEastWestProtocol("ssh") {
		t.Fatal("ssh must remain an east-west protocol; only the locality precondition is new")
	}
}

// And the thing the plane exists for must still work. If this ever fails, the fix has switched off the
// lateral-movement control instead of narrowing it.
func TestSSHToAPrivateHostIsStillLateralMovement(t *testing.T) {
	e := Evaluator{EastWestEnabled: true}
	if !e.isEastWestFlow(labSSH()) {
		t.Fatal("ssh to a private address must stay on the east-west plane")
	}
}

func TestClassifyDestinationLocality(t *testing.T) {
	for _, tc := range []struct {
		name string
		req  model.DecisionRequest
		want DestinationLocality
	}{
		{"public v4 (github)", githubSSH(), LocalityPublic},
		{"rfc1918 10/8", model.DecisionRequest{Destination: "10.1.2.3"}, LocalityInternal},
		{"rfc1918 192.168", model.DecisionRequest{Destination: "192.168.100.10"}, LocalityInternal},
		{"rfc1918 172.16", model.DecisionRequest{Destination: "172.16.0.9"}, LocalityInternal},
		{"172.32 is PUBLIC, not rfc1918", model.DecisionRequest{Destination: "172.32.0.9"}, LocalityPublic},
		{"loopback", model.DecisionRequest{Destination: "127.0.0.1"}, LocalityInternal},
		{"link-local", model.DecisionRequest{Destination: "169.254.1.1"}, LocalityInternal},
		{"cgnat 100.64/10", model.DecisionRequest{Destination: "100.100.1.1"}, LocalityInternal},
		{"100.128 is PUBLIC, outside cgnat", model.DecisionRequest{Destination: "100.128.0.1"}, LocalityPublic},
		{"ipv6 ULA", model.DecisionRequest{Destination: "fd00::1"}, LocalityInternal},
		{"ipv6 link-local", model.DecisionRequest{Destination: "fe80::1"}, LocalityInternal},
		{"ipv6 public", model.DecisionRequest{Destination: "2606:4700::1111"}, LocalityPublic},
		{"host:port form", model.DecisionRequest{Destination: "192.168.100.10:22"}, LocalityInternal},
		{"bracketed ipv6 with port", model.DecisionRequest{Destination: "[fd00::1]:22"}, LocalityInternal},
		{"ipv4-mapped ipv6 classifies as its v4 self", model.DecisionRequest{Destination: "::ffff:10.0.0.1"}, LocalityInternal},
		{"DestinationIP when Destination is a name", model.DecisionRequest{Destination: "host.example", DestinationIP: "10.0.0.5"}, LocalityInternal},
		{"name only, nothing declared", model.DecisionRequest{Destination: "github.com"}, LocalityUnknown},
		{"empty", model.DecisionRequest{}, LocalityUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ClassifyDestinationLocality(tc.req, InternalNetworks{}); got != tc.want {
				t.Fatalf("got %s, want %s", got, tc.want)
			}
		})
	}
}

// A customer can route public-range addresses internally, so a declaration must be able to pull an address
// onto the lateral plane. This is the "adopted internal asset" case.
func TestADeclaredNetworkMakesAPublicAddressInternal(t *testing.T) {
	// A PUBLIC range, deliberately: the point of this case is that a declaration pulls an address that is not
	// private onto the lateral plane.
	declared := InternalNetworks{CIDRs: []string{"203.0.113.0/24"}}
	req := model.DecisionRequest{Destination: "203.0.113.9", ServiceFamily: "ssh"}
	if got := ClassifyDestinationLocality(req, declared); got != LocalityInternal {
		t.Fatalf("got %s, want internal", got)
	}
	e := Evaluator{EastWestEnabled: true, EastWestInternalNetworks: declared}
	if !e.isEastWestFlow(req) {
		t.Fatal("a declared-internal destination must be governed on the east-west plane")
	}
	// The same address without the declaration is internet access.
	if e2 := (Evaluator{EastWestEnabled: true}); e2.isEastWestFlow(req) {
		t.Fatal("without the declaration this is a public address")
	}
}

// The declaration extends the lateral plane and must never shrink it. Nothing an operator writes may make a
// private address "public" — that is how a lateral-movement control gets quietly switched off.
func TestADeclarationCannotTakeAPrivateAddressOffTheLateralPlane(t *testing.T) {
	// Even a declaration that names an unrelated network leaves RFC1918 internal.
	declared := InternalNetworks{CIDRs: []string{"192.168.100.0/24"}}
	if got := ClassifyDestinationLocality(labSSH(), declared); got != LocalityInternal {
		t.Fatalf("got %s, want internal", got)
	}
}

func TestDeclaredDomainsMatchOnLabelBoundaries(t *testing.T) {
	declared := InternalNetworks{Domains: []string{"corp.example.com", "*.internal.test"}}
	for _, tc := range []struct {
		fqdn string
		want DestinationLocality
	}{
		{"corp.example.com", LocalityInternal},
		{"db01.corp.example.com", LocalityInternal},
		{"CORP.EXAMPLE.COM", LocalityInternal},
		{"corp.example.com.", LocalityInternal}, // trailing dot
		{"host.internal.test", LocalityInternal},
		{"internal.test", LocalityInternal},
		// The one that matters: a suffix match on the STRING rather than on a label boundary would call this
		// internal, and an attacker registering it would get a destination the operator believes is theirs.
		{"notcorp.example.com", LocalityUnknown},
		{"corp.example.com.evil.test", LocalityUnknown},
	} {
		req := model.DecisionRequest{FQDN: tc.fqdn}
		if got := ClassifyDestinationLocality(req, declared); got != tc.want {
			t.Errorf("%s: got %s, want %s", tc.fqdn, got, tc.want)
		}
	}
}

func TestAMalformedDeclarationIsDroppedNotTreatedAsMatchAll(t *testing.T) {
	declared := InternalNetworks{CIDRs: []string{"not-a-cidr", "10.0.0.0/8"}, Domains: []string{"", "  "}}
	if got := ClassifyDestinationLocality(githubSSH(), declared); got != LocalityPublic {
		t.Fatalf("a malformed CIDR must not make everything internal: got %s", got)
	}
	if got := ClassifyDestinationLocality(model.DecisionRequest{Destination: "10.9.9.9"}, declared); got != LocalityInternal {
		t.Fatalf("the well-formed entry must still work: got %s", got)
	}
}

// ★ The asymmetry that decides the Unknown case. A request the Edge could not classify KEEPS its
// lateral-movement enforcement: the wrong answer in that direction is a visible stall, and the wrong answer
// in the other direction is a lateral hop that silently skips per-hop authorization.
func TestAnUnclassifiableDestinationKeepsItsEastWestEnforcement(t *testing.T) {
	if !EastWestLocalityAdmits(LocalityUnknown) {
		t.Fatal("unknown must not silently drop off the lateral plane")
	}
	if !EastWestLocalityAdmits(LocalityInternal) {
		t.Fatal("internal must be admitted")
	}
	if EastWestLocalityAdmits(LocalityPublic) {
		t.Fatal("public must be excluded — that is the whole change")
	}

	e := Evaluator{EastWestEnabled: true}
	req := model.DecisionRequest{Destination: "somehost", ServiceFamily: "ssh"} // no address anywhere
	if !e.isEastWestFlow(req) {
		t.Fatal("a request with no usable destination must keep east-west enforcement")
	}
}

// End to end through Evaluate: the public flow must not come back holding for a ceremony, and the internal
// one must. This is the pair the operator experienced, so it is asserted on the decision and not just the
// classifier.
func TestEvaluateHoldsTheLabSSHAndDoesNotHoldGitHub(t *testing.T) {
	rules := []EastWestRule{{ID: "rule-82", Priority: 50, Mode: EastWestModeAuthenticate, Protocols: []string{"ssh"}}}
	e := Evaluator{EastWestEnabled: true, EastWestRules: rules}

	lab := e.Evaluate(labSSH())
	if lab.Decision != "authenticate_required" {
		t.Fatalf("lab ssh: got %q, want authenticate_required — the lateral plane must still bite", lab.Decision)
	}

	gh := e.Evaluate(githubSSH())
	if gh.Decision == "authenticate_required" {
		t.Fatalf("github ssh must not be held for an east-west ceremony; got %q reason=%q", gh.Decision, valueOrEmpty(gh.Reason))
	}
	// It must have been evaluated on the north-bound plane instead — not merely skipped.
	if gh.PolicyID == "east_west_policy" {
		t.Fatalf("github ssh was still decided by the east-west plane: %+v", gh)
	}
}

// The locality is reported on east-west decisions so an operator can tell WHY a flow was on that plane —
// especially the Unknown case, which is otherwise indistinguishable from a correctly-classified internal one.
func TestEastWestDecisionsReportTheLocalityTheyWereClassifiedOn(t *testing.T) {
	e := Evaluator{EastWestEnabled: true, EastWestRules: []EastWestRule{{Mode: EastWestModeAllow, Protocols: []string{"ssh"}}}}
	res := e.Evaluate(labSSH())
	got, ok := res.Metadata["destination_locality"]
	if !ok {
		t.Fatal("an east-west decision must record the locality it was classified on")
	}
	if got != "internal" {
		t.Fatalf("destination_locality = %v, want internal", got)
	}
}

func valueOrEmpty(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
