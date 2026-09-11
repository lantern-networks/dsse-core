package main

import (
	"strings"
	"testing"
)

// ★★★ THE MESH WAS NAMED EVERYWHERE AND PRODUCED NOWHERE (2026-09-01). start-edge.sh has read
// DSSE_MESH_PEERS since 2026-08-25, the printed order names the mesh as a step after every region exists, and
// -verify says a connector in another region is unreachable without it — while nothing in this installer ever
// wrote a single peer. An operator following that order had to compose the URLs by hand, per region, from
// names this plan already holds, and a typo produces a region that can be dialled and cannot dial.
func TestTheMeshIsDerivedForEveryRegionThatDeclaredOne(t *testing.T) {
	p := &Plan{
		Deployment: "kaede.lab",
		Regions: []PlanRegion{
			{ID: "tokyo-east", Founding: true},
			{ID: "tokyo-west"},
			{ID: "osaka"},
		},
	}
	got := p.MeshPeersFor("tokyo-east")
	for _, want := range []string{
		"osaka=wss://agents.osaka.kaede.lab/mesh/ingress/tunnel",
		"tokyo-west=wss://agents.tokyo-west.kaede.lab/mesh/ingress/tunnel",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("tokyo-east cannot reach %s\ngot: %s", want, got)
		}
	}
	// ★ AND NEVER ITSELF. A region pointed at its own doorway dials a loop that looks like a working mesh
	// until a flow needs the other side of it.
	if strings.Contains(got, "tokyo-east=") {
		t.Errorf("a region was given itself as a peer: %s", got)
	}

	// ★★ MUTUAL, BECAUSE A LINK THAT ONLY ONE SIDE HAS LOOKS LIKE A NETWORK FAULT. Each region must name
	// every other, which is what makes hand-typing this the wrong shape: three regions is six lines.
	for _, region := range []string{"tokyo-east", "tokyo-west", "osaka"} {
		peers := p.MeshPeersFor(region)
		if n := strings.Count(peers, "wss://"); n != 2 {
			t.Errorf("%s names %d peer(s), want 2: %s", region, n, peers)
		}
	}
}

// ★ EMPTY IS A DECISION AND STAYS THE DEFAULT. A deployment whose regions must not relay to each other keeps
// residency by construction, and a flow that needs a missing link is refused BY NAME rather than finding
// another way out. Declaring nothing must never turn that on.
func TestTurningTheMeshOffIsSaidOnceByWhoeverMeansIt(t *testing.T) {
	// ★ SAYING NOTHING IS NOT SAYING NO. Every multi-region deployment this installer built came up with no
	// mesh, and the shape it came up in read as deliberate — "fail-closed, which is the default". It was an
	// omission wearing a posture, and a second region that cannot be reached is not residency.
	silent := &Plan{Deployment: "kaede.lab", Regions: []PlanRegion{{ID: "a"}, {ID: "b"}}}
	if got := silent.MeshPeersFor("a"); got == "" {
		t.Error("a three-region-shaped plan that said nothing came up with no mesh — that is the hole")
	}
	// And the real posture is still available, written down once by whoever means it.
	off := false
	refused := &Plan{Deployment: "kaede.lab", Mesh: &off, Regions: []PlanRegion{{ID: "a"}, {ID: "b"}}}
	if got := refused.MeshPeersFor("a"); got != "" {
		t.Errorf("a plan that said mesh:false produced %q", got)
	}
	// A single region has nobody to relay to, whatever it said.
	on := true
	one := &Plan{Deployment: "kaede.lab", Mesh: &on, Regions: []PlanRegion{{ID: "only"}}}
	if got := one.MeshPeersFor("only"); got != "" {
		t.Errorf("the only region was given a peer: %q", got)
	}
}

// ★★ AND IT REACHES THE FILE THE START SCRIPT READS. The value being correct in a function is the half that
// was never missing: this deployment's recurring shape is a correct value that no call site asks for.
func TestTheMeshReachesTheEnvironmentTheEdgeReads(t *testing.T) {
	p := &Plan{
		Deployment: "kaede.lab",
		Regions: []PlanRegion{
			{ID: "tokyo-east", Founding: true, Machines: []PlanMachine{{Name: "n1", Holds: heldComponents{"edges"}, Addresses: []string{"10.0.0.1", "10.0.0.2"}, ReachableAddress: "1.2.3.4"}}},
			{ID: "osaka", Machines: []PlanMachine{{Name: "n2", Holds: heldComponents{"edges"}, Addresses: []string{"10.1.0.1", "10.1.0.2"}, ReachableAddress: "5.6.7.8"}}},
		},
	}
	env, err := p.MachineEnvironment("n1")
	if err != nil {
		t.Fatalf("MachineEnvironment: %v", err)
	}
	if !strings.Contains(env["DSSE_MESH_PEERS"], "osaka=wss://agents.osaka.kaede.lab/mesh/ingress/tunnel") {
		t.Errorf("DSSE_MESH_PEERS = %q — start-edge.sh reads this name and turns it into -mesh-peers",
			env["DSSE_MESH_PEERS"])
	}
}
