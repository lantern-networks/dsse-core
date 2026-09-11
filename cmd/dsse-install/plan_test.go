package main

import (
	"strings"
	"testing"
)

// plan_test.go — the properties a deployment must have, whatever shape it is.
//
// ★★★ EVERY ONE OF THESE IS A FAILURE THIS DEPLOYMENT HAD, ON REAL MACHINES, IN ONE DAY (2026-08-28). They
// were found by standing a two-site deployment up by hand, and each was silent: the machine came up, the
// screens were green, and something that mattered was wrong. What they have in common is that the answer was
// KNOWN before anything was installed — it is the description of the deployment — and was typed onto each
// machine instead of derived from it.
//
// So they are asserted here against SHAPES rather than against one lab: one region, two regions, three, and
// a region that holds no state. A property that only holds for the shape somebody happened to build is not a
// property.

func planOfRegions(ids ...string) *Plan {
	p := &Plan{Deployment: "dsse.example", Publisher: "TEAMID1234"}
	for i, id := range ids {
		octet := 20 + i
		r := PlanRegion{ID: id, Founding: i == 0, HoldsState: true}
		r.Machines = []PlanMachine{
			{Name: "cp-" + id, Holds: heldComponents{"control-plane"},
				Addresses: []string{fmtIP(octet, 1), fmtIP(octet, 2)},
				Reachable: "cp-" + id + ".dsse.example", ReachableAddress: fmtIP(100+octet, 1)},
			{Name: "edge-" + id, Holds: heldComponents{"edges"},
				Addresses: []string{fmtIP(octet, 3), fmtIP(octet, 4)},
				Reachable: "edge-" + id + ".dsse.example", ReachableAddress: fmtIP(100+octet, 3)},
		}
		p.Regions = append(p.Regions, r)
	}
	return p
}

func fmtIP(octet, host int) string {
	return "10." + itoa(octet) + ".1." + itoa(host)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	digits := ""
	for n > 0 {
		digits = string(rune('0'+n%10)) + digits
		n /= 10
	}
	return digits
}

func shapes() map[string]*Plan {
	return map[string]*Plan{
		"one region":    planOfRegions("region-a"),
		"two regions":   planOfRegions("region-a", "region-b"),
		"three regions": planOfRegions("region-a", "region-b", "region-c"),
	}
}

// ★★★ NO MACHINE HOLDS ANOTHER MACHINE'S ADDRESS. Carried by hand, a joining region arrived with the founding
// region's — docker refused with "cannot assign requested address", which is the LUCKY case. The advertise
// values fail the other way: a database member in the second region announces itself at the FIRST region's
// address, in the component that holds the deployment's state.
func TestNoMachineIsGivenAnotherMachinesAddress(t *testing.T) {
	for name, p := range shapes() {
		owner := map[string]string{}
		for _, r := range p.Regions {
			for _, m := range r.Machines {
				for _, a := range m.Addresses {
					owner[a] = m.Name
				}
			}
		}
		for _, r := range p.Regions {
			for _, m := range r.Machines {
				env, err := p.MachineEnvironment(m.Name)
				if err != nil {
					t.Fatalf("%s: %v", name, err)
				}
				for key, value := range env {
					if !strings.Contains(key, "PUBLISH") && !strings.Contains(key, "BIND") {
						continue
					}
					host := strings.TrimSuffix(strings.SplitN(value, ":", 2)[0], ":")
					if got, known := owner[host]; known && got != m.Name {
						t.Errorf("%s: %s on %s is %s, which belongs to %s", name, key, m.Name, value, got)
					}
				}
			}
		}
	}
}

// ★★★ EVERY DOOR IS ON 443. A deployment that publishes its doorway on anything else is one an enterprise
// proxy stops at, and the substitution a machine-per-component deployment exists to end.
//
// ★ THE PAIR IS GONE (2026-09-02). There used to be two doors on two addresses so a region survived losing
// one; a device whose door stops answering fails over to another region instead, which the product already
// does and which is measured at about thirty seconds.
func TestEveryDoorIsOn443(t *testing.T) {
	for name, p := range shapes() {
		for _, r := range p.Regions {
			for _, m := range r.Machines {
				env, err := p.MachineEnvironment(m.Name)
				if err != nil {
					t.Fatalf("%s: %v", name, err)
				}
				// ★ A MACHINE THAT RUNS ONLY EDGES IS BEHIND THE DOOR, NOT ONE (2026-09-02). It publishes no
				// 443 at all — the region's doorway, on the control-plane machine, reaches it on its Edge
				// ports and names it in DSSE_EDGE_BACKENDS. The rule below is about doorways, and that
				// machine has none.
				if !m.Holds.has("control-plane") && m.Holds.has("edges") {
					if env["DSSE_REGION_PORT"] != "" || env["DSSE_REGION_BIND_A"] != "" {
						t.Errorf("%s/%s runs only Edges and still binds a doorway (%s on %s) — it sits behind "+
							"the region's door", name, m.Name, env["DSSE_REGION_PORT"], env["DSSE_REGION_BIND_A"])
					}
					continue
				}
				if env["DSSE_REGION_PORT"] != "443" {
					t.Errorf("%s/%s publishes its doorway on %s, not 443", name, m.Name, env["DSSE_REGION_PORT"])
				}
				if strings.TrimSpace(env["DSSE_REGION_BIND_A"]) == "" {
					t.Errorf("%s/%s binds its door to nothing", name, m.Name)
				}
			}
		}
	}
}

// ★★★ EACH REGION KNOWS ITS OWN NAME. Carried by hand, a machine packed for region-b arrived saying
// region-a — the name devices use to CHOOSE a region. A device "failing over" would have chosen the region it
// was already in.
func TestEachMachineIsToldTheRegionItIsIn(t *testing.T) {
	for name, p := range shapes() {
		for _, r := range p.Regions {
			for _, m := range r.Machines {
				env, _ := p.MachineEnvironment(m.Name)
				if env["DSSE_EDGE_REGION"] != r.ID {
					t.Errorf("%s: %s is in %s and is told it is in %s", name, m.Name, r.ID, env["DSSE_EDGE_REGION"])
				}
			}
		}
	}
}

// ★★★ EVERY MACHINE IS HANDED THE SAME MAP, WITH ONE ENTRY PER REGION, ALL DIFFERENT. An Edge holding a
// shorter map is healthy and hands its devices a map missing the region it never heard about; two entries
// naming one place is a failover to where you already are.
func TestTheRegionMapIsCompleteIdenticalAndDistinct(t *testing.T) {
	for name, p := range shapes() {
		want := ""
		for _, r := range p.Regions {
			for _, m := range r.Machines {
				env, _ := p.MachineEnvironment(m.Name)
				got := env["DSSE_REGION_ENDPOINTS"]
				if want == "" {
					want = got
				}
				if got != want {
					t.Errorf("%s: %s is handed a different region map than its fleet:\n  %s\n  %s", name, m.Name, got, want)
				}
				entries := strings.Split(got, ";")
				if len(entries) != len(p.Regions) {
					t.Errorf("%s: %s is handed %d region(s) of %d", name, m.Name, len(entries), len(p.Regions))
				}
				seen := map[string]bool{}
				for _, e := range entries {
					_, address, _ := strings.Cut(e, "=")
					if seen[address] {
						t.Errorf("%s: two regions in the map answer at %s, so a device cannot fail over between them", name, address)
					}
					seen[address] = true
				}
			}
		}
	}
}

// ★★★ NO TWO DATABASE MEMBERS CALL THEMSELVES THE SAME THING. One cluster spans every region, and the
// default name is the compose service name — identical everywhere — so the second region's first member is
// refused outright: "there is already a node named 'dsse-postgres-a' running".
func TestEveryDatabaseMemberHasItsOwnNameAcrossTheDeployment(t *testing.T) {
	for name, p := range shapes() {
		seen := map[string]string{}
		for _, r := range p.Regions {
			for _, m := range r.Machines {
				env, _ := p.MachineEnvironment(m.Name)
				for _, key := range []string{"DSSE_PG_A_NAME", "DSSE_PG_B_NAME"} {
					member := env[key]
					if member == "" {
						continue
					}
					if other, taken := seen[member]; taken {
						t.Errorf("%s: %s and %s both call a member %q", name, other, m.Name, member)
					}
					seen[member] = m.Name
				}
			}
		}
	}
}

// ★★★ EVERY REGION CAN REACH THE PRIMARY WHEREVER IT IS. The deployment has ONE primary and it can be in any
// region; a door knowing only local members has no backend the moment it moves. Measured: the leader moved to
// the second region and the FIRST region's database init looped, taking its control planes with it.
func TestEveryRegionCanFindAPrimaryInAnotherRegion(t *testing.T) {
	for name, p := range shapes() {
		if len(p.Regions) < 2 {
			continue
		}
		for _, r := range p.Regions {
			for _, m := range r.Machines {
				env, _ := p.MachineEnvironment(m.Name)
				peers := env["DSSE_PG_PEERS"]
				for _, other := range p.Regions {
					if strings.EqualFold(other.ID, r.ID) {
						continue
					}
					// ★ AT THE ADDRESS, not by the name: this door resolves nothing at run time. See
					// PlanMachine.ReachableAddress.
					if !strings.Contains(peers, other.controlPlane().reachableAt()) {
						t.Errorf("%s: %s cannot reach %s's database, so it stops entirely whenever the primary "+
							"is there: %q", name, m.Name, other.ID, peers)
					}
				}
			}
		}
	}
}

// ★★★ EVERY REGION REACHES THE ONE CONSENSUS STORE. A joining region is told where it is; -holds-state says
// it "requires DSSE_ETCD_HOSTS to name the deployment's consensus store, reachable from here", and every
// default published loopback — reachable from nowhere.
func TestEveryRegionIsToldWhereTheConsensusStoreIs(t *testing.T) {
	for name, p := range shapes() {
		founding := p.foundingRegion().controlPlane()
		for _, r := range p.Regions {
			for _, m := range r.Machines {
				env, _ := p.MachineEnvironment(m.Name)
				if !strings.Contains(env["DSSE_ETCD_HOSTS"], founding.reachableName()) {
					t.Errorf("%s: %s is not told where the deployment's consensus store is: %q",
						name, m.Name, env["DSSE_ETCD_HOSTS"])
				}
				if strings.Contains(env["DSSE_ETCD_HOSTS"], "127.0.0.1") {
					t.Errorf("%s: %s is pointed at a consensus store on loopback, which is reachable from nowhere", name, m.Name)
				}
			}
		}
	}
}

// ★★★ THE STATE A REGION HOLDS IS ADVERTISED BY A NAME, NOT BY ITS OWN PRIVATE ADDRESS. Advertise is what a
// member tells the cluster to reach it at, so an address that only means something inside one site makes that
// member unreachable from every other.
func TestAControlPlaneAdvertisesItselfByANameTheOtherRegionsCanUse(t *testing.T) {
	for name, p := range shapes() {
		for _, r := range p.Regions {
			cp := r.controlPlane()
			env, _ := p.MachineEnvironment(cp.Name)
			for _, key := range []string{"DSSE_PG_A_ADVERTISE", "DSSE_PG_B_ADVERTISE"} {
				if !strings.HasPrefix(env[key], cp.Reachable) {
					t.Errorf("%s: %s advertises itself as %q rather than by the name other regions reach it by (%s)",
						name, cp.Name, env[key], cp.Reachable)
				}
			}
		}
	}
}

// ★★★ ONLY THE FOUNDING REGION STANDS UP THE CONSENSUS STORE. There is one per deployment with a member per
// region; a second cluster is a second opinion about which database is primary.
func TestOnlyTheFoundingRegionPublishesAConsensusStore(t *testing.T) {
	p := planOfRegions("region-a", "region-b", "region-c")
	for _, r := range p.Regions {
		env, _ := p.MachineEnvironment(r.controlPlane().Name)
		_, publishes := env["DSSE_ETCD_A_PUBLISH"]
		if !publishes {
			t.Errorf("%s publishes no consensus store: there is one per deployment WITH A MEMBER PER REGION, "+
				"and a region that publishes none is a client of somebody else's — which is what made the "+
				"founding region's loss take the deployment's authority with it", r.ID)
		}
		// ★★★ THE INVARIANT IS ONE CLUSTER, NOT ONE MEMBER (2026-08-31, this test measured the wrong one).
		//
		// It used to fail any region but the founding one for publishing a store at all, and said in its own
		// message that the danger was "a second cluster ... a second opinion about which database is primary".
		// A MEMBER of the deployment's one cluster is not that — it is exactly what the store's comment has
		// always said it should have. What the test measured was the implementation of the day: three members
		// in the founding region and everyone else a client.
		//
		// What actually separates a member from a second cluster is who BOOTSTRAPS one. Exactly one region may
		// start a cluster; every other joins the cluster that exists.
		state := env["DSSE_ETCD_INITIAL_CLUSTER_STATE"]
		if r.Founding && state != "new" {
			t.Errorf("the founding region bootstraps as %q; nothing else is allowed to start a cluster, so it "+
				"must be the one that does", state)
		}
		if !r.Founding && state != "existing" {
			t.Errorf("%s bootstraps as %q — anything but \"existing\" is a second cluster, which is a second "+
				"opinion about which database is primary", r.ID, state)
		}
	}
}

// ★★★ EVERY PLANE HAS A NAME THAT SAYS WHICH REGION. agents. and admin. are answered by every site with its
// own doorway, which is what makes a client reach the region it is in — and is exactly why neither can name
// the OTHER one.
func TestEveryPlaneOfEveryRegionHasANameOfItsOwn(t *testing.T) {
	p := planOfRegions("region-a", "region-b")
	seen := map[string]string{}
	for _, r := range p.Regions {
		for plane, name := range p.PlaneNamesFor(r.ID) {
			if !strings.Contains(name, r.ID) {
				t.Errorf("%s of %s is called %q, which does not say which region it is", plane, r.ID, name)
			}
			if other, taken := seen[name]; taken {
				t.Errorf("%q names both %s and %s", name, other, r.ID+"/"+plane)
			}
			seen[name] = r.ID + "/" + plane
		}
	}
	// ★ AND ALL OF THEM ARE IN THE CERTIFICATE, or the name resolves and nothing verifies.
	certificate := strings.Join(p.CertificateNames(), " ")
	for _, r := range p.Regions {
		for _, name := range p.PlaneNamesFor(r.ID) {
			if !strings.Contains(certificate, name) {
				t.Errorf("%q is not in the certificate this deployment presents", name)
			}
		}
	}
}

// ★★★ NO NAME IN THE CERTIFICATE IS MALFORMED. One bad entry costs the DEPLOYMENT, not the entry: macOS
// answered "unsupported or invalid name syntax" for EVERY name in it, including four plane names that had
// been working all morning.
func TestNoCertificateNameIsMalformed(t *testing.T) {
	for name, p := range shapes() {
		for _, n := range p.CertificateNames() {
			if strings.Count(n, "*") > 1 || strings.TrimSpace(n) == "" || strings.Contains(n, " ") {
				t.Errorf("%s: the certificate would carry %q, which is not a DNS name", name, n)
			}
		}
	}
}

// ★★★ A DEPLOYMENT NO ENDPOINT CAN JOIN IS REFUSED BEFORE IT IS BUILT. The endpoint installer will not
// install a configuration that names no publisher, so a deployment that cannot say one comes up healthy and
// no device can ever join it.
func TestAPlanCarriesTheAnswersOnlyAnOperatorHas(t *testing.T) {
	p := planOfRegions("region-a")
	env, _ := p.MachineEnvironment(p.Regions[0].controlPlane().Name)
	if env["DSSE_AGENT_PUBLISHER"] == "" {
		t.Error("the plan named a publisher and the machine was not told it — every endpoint install against " +
			"this deployment stops at 'the agent configuration names no update_publisher_team_id'")
	}
}

// ★ AND A PLAN THAT CANNOT DESCRIBE A WORKING DEPLOYMENT IS REFUSED, NAMING WHAT TO FIX. Each of these is a
// state a hand-built deployment was actually in.
func TestAPlanThatCannotWorkIsRefused(t *testing.T) {
	for _, c := range []struct {
		what, want string
		mutate     func(*Plan)
	}{
		// ★ "a machine with one address" was here until 2026-09-02, when the doorway stopped being a pair:
		// a region whose door stops answering is a region a device fails over out of, and the pair cost every
		// machine a second address and made "an Edge node behind the region's door" impossible to declare.
		{"a machine with no address", "address", func(p *Plan) {
			p.Regions[0].Machines[0].Addresses = nil
		}},
		{"two regions of one name", "two regions are called", func(p *Plan) {
			p.Regions[1].ID = p.Regions[0].ID
		}},
		{"two founding regions", "founding", func(p *Plan) { p.Regions[1].Founding = true }},
		{"no founding region", "founding", func(p *Plan) { p.Regions[0].Founding = false }},
		{"a region with no Edges", "no machine running Edges", func(p *Plan) {
			p.Regions[1].Machines = p.Regions[1].Machines[:1]
		}},
		{"one address in two places", "given to both", func(p *Plan) {
			p.Regions[1].Machines[0].Addresses[0] = p.Regions[0].Machines[0].Addresses[0]
		}},
		{"a deployment named by an address", "ADDRESS", func(p *Plan) { p.Deployment = "203.0.113.10" }},
	} {
		p := planOfRegions("region-a", "region-b")
		c.mutate(p)
		err := p.Validate()
		if err == nil {
			t.Errorf("%s was accepted", c.what)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s was refused without saying why (%q does not mention %q)", c.what, err, c.want)
		}
	}
}

// ★ AND A PLAN THAT DESCRIBES A WORKING DEPLOYMENT IS ACCEPTED — the control, without which every refusal
// above would be satisfied by refusing everything.
func TestAWorkablePlanIsAccepted(t *testing.T) {
	for name, p := range shapes() {
		if err := p.Validate(); err != nil {
			t.Errorf("%s was refused: %v", name, err)
		}
	}
}

// ★★★ EVERY VALUE SURVIVES BEING SOURCED (2026-08-28, caught by reading a packed machine). deployment.env is a
// shell file that every node sources, and etcd wants its hosts quoted individually — so wrapping that value
// in quotes again produced DSSE_ETCD_HOSTS=”cp-a:12379','cp-b:12380”, which a shell reads as something else.
// Nothing reports it: the file sources without error and the consensus store is simply somewhere else.
func TestEveryPlannedValueSurvivesBeingSourced(t *testing.T) {
	p := planOfRegions("region-a", "region-b")
	for _, r := range p.Regions {
		for _, m := range r.Machines {
			values, _ := p.MachineEnvironment(m.Name)
			env := PlanEnvironmentFor("", values)
			for _, line := range strings.Split(env, "\n") {
				key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
				if !ok || key == "" {
					continue
				}
				if unquoted, good := readShellValue(value); !good || unquoted != values[key] {
					t.Errorf("%s reads back as %q, not %q — a shell sources this file", key, unquoted, values[key])
				}
			}
		}
	}
}

// readShellValue is what a shell does with one quoted word: it is deliberately strict, because the failure
// being measured is a value that PARSES and means something else.
func readShellValue(raw string) (string, bool) {
	switch {
	case strings.HasPrefix(raw, "'") && strings.HasSuffix(raw, "'") && len(raw) >= 2:
		inner := raw[1 : len(raw)-1]
		if strings.Contains(inner, "'") {
			return inner, false
		}
		return inner, true
	case strings.HasPrefix(raw, `"`) && strings.HasSuffix(raw, `"`) && len(raw) >= 2:
		inner := raw[1 : len(raw)-1]
		if strings.Contains(inner, `"`) || strings.Contains(inner, "$") {
			return inner, false
		}
		return inner, true
	}
	return raw, false
}

// ★★★ NO TWO NODES OF THE DEPLOYMENT ANSWER TO ONE NAME (2026-08-28, reported by -verify on a two-region
// deployment). Every region runs services called control-plane-a and edge-a, so <node>.admin.<host> named two
// different machines in two different regions — and the check asking "is exactly one control plane the
// leader" asked the same two nodes twice and answered "none of them holds leadership" about a deployment that
// had one.
func TestNoTwoNodesOfTheDeploymentShareAName(t *testing.T) {
	for name, p := range shapes() {
		seen := map[string]bool{}
		for _, target := range append(p.verifyControlPlanes(), p.verifyEdgeAdmins()...) {
			node, _, _ := strings.Cut(strings.TrimPrefix(target, "https://"), "@")
			if seen[node] {
				t.Errorf("%s: two nodes answer to %s, so a fleet question asked of both asks one twice", name, node)
			}
			seen[node] = true
		}
	}
}

// ★ AND EACH IS ONE LABEL DEEP, because the certificate carries *.admin.<host> and a wildcard matches exactly
// one label. region-a-control-plane-a.admin.<host> verifies; control-plane-a.region-a.admin.<host> does not.
func TestEveryNodeNameFitsTheWildcardTheCertificateCarries(t *testing.T) {
	p := planOfRegions("region-a", "region-b")
	for _, target := range append(p.verifyControlPlanes(), p.verifyEdgeAdmins()...) {
		node, _, _ := strings.Cut(strings.TrimPrefix(target, "https://"), "@")
		label, rest, _ := strings.Cut(node, ".")
		if strings.Contains(label, " ") || rest != "admin."+p.Deployment {
			t.Errorf("%q is not <one-label>.admin.%s, so *.admin.%s does not cover it",
				node, p.Deployment, p.Deployment)
		}
	}
}

// ★★★ AND EVERY EDGE IS TOLD WHERE ELSE IT MAY ASK. A deployment spanning regions whose Edges take
// configuration from ONE address loses all of them — in every region — when that region dies: they serve what
// they last applied, with nowhere to ask and nothing to show for it.
func TestEveryEdgeIsToldEveryRegionsControlPlane(t *testing.T) {
	for name, p := range shapes() {
		for _, r := range p.Regions {
			for _, m := range r.Machines {
				env, _ := p.MachineEnvironment(m.Name)
				for _, other := range p.Regions {
					// ★ region=URL, which is the shape start-edge.sh reads. A list of bare URLs is accepted by
					// the file and used by nothing.
					want := other.ID + "=https://" + p.PlaneNamesFor(other.ID)["admin"]
					if !strings.Contains(env["DSSE_CP_ENDPOINTS"], want) {
						t.Errorf("%s: %s is not told it may ask %s: %q",
							name, m.Name, other.ID, env["DSSE_CP_ENDPOINTS"])
					}
				}
			}
		}
	}
}
