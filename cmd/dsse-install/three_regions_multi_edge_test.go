package main

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

func threeRegionsMultiEdgePlan() *Plan {
	p := planOfRegions("region-a", "region-b", "region-c")
	p.Profile = "three-regions-multi-edge"
	for i := range p.Regions {
		r := &p.Regions[i]
		r.Machines[0].FailureDomain = r.ID + "-cp"
		r.Machines[1].FailureDomain = r.ID + "-edge-1"
		r.Machines = append(r.Machines, PlanMachine{
			Name:             "edge-2-" + r.ID,
			Holds:            heldComponents{"edges"},
			Addresses:        []string{fmtIP(20+i, 5)},
			Reachable:        "edge-2-" + r.ID + ".dsse.example",
			ReachableAddress: fmtIP(120+i, 5),
			FailureDomain:    r.ID + "-edge-2",
		})
	}
	return p
}

func TestThreeRegionsMultiEdgePlanKeepsOneDoorAndMultipleBackendsPerRegion(t *testing.T) {
	p := threeRegionsMultiEdgePlan()
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	if got := p.RegionEndpoints(); strings.Count(got, "=https://") != 3 {
		t.Fatalf("expected one agent-selected door per DSSE region, got %q", got)
	}
	for _, r := range p.Regions {
		cp := r.Machines[0]
		env, err := p.MachineEnvironment(cp.Name)
		if err != nil {
			t.Fatal(err)
		}
		if got := env["DSSE_EDGE_BACKENDS"]; !strings.Contains(got, r.Machines[1].reachableAt()) || !strings.Contains(got, r.Machines[2].reachableAt()) {
			t.Fatalf("%s front door omits a dedicated Edge: %q", r.ID, got)
		}
		wantBackends := []string{r.Machines[1].reachableAt() + ":8443", r.Machines[2].reachableAt() + ":8443"}
		slices.Sort(wantBackends)
		if got := strings.Split(env["DSSE_EDGE_BACKENDS"], ","); !slices.Equal(got, wantBackends) {
			t.Fatalf("%s front door must select exactly its local Edges: %v", r.ID, got)
		}
		var portals []regionPortalTarget
		if err := json.Unmarshal([]byte(env[threeRegionPortalsKey]), &portals); err != nil || len(portals) != 2 {
			t.Fatalf("%s must have exactly two local Portal backends: %v", r.ID, err)
		}
		for _, target := range portals {
			if target.Name != p.regionPortalName(r.ID) || (target.Address != r.Machines[1].reachableAt() && target.Address != r.Machines[2].reachableAt()) {
				t.Fatalf("%s Portal crosses Regions: %+v", r.ID, target)
			}
		}
		for _, edge := range r.Machines[1:] {
			edgeEnv, err := p.MachineEnvironment(edge.Name)
			if err != nil {
				t.Fatal(err)
			}
			if edgeEnv["DSSE_REGION_BIND_A"] != "" || edgeEnv["DSSE_REGION_PORT"] != "" {
				t.Fatalf("%s unexpectedly publishes a public door", edge.Name)
			}
		}
	}
}

func TestThreeRegionsMultiEdgeRejectsIncompleteOrMixedPlacement(t *testing.T) {
	tests := []struct {
		name string
		edit func(*Plan)
	}{
		{"missing region", func(p *Plan) { p.Regions = p.Regions[:2] }},
		{"single Edge", func(p *Plan) { p.Regions[0].Machines = p.Regions[0].Machines[:2] }},
		{"CP also holds Edge", func(p *Plan) { p.Regions[0].Machines[0].Holds = heldComponents{"control-plane", "edges"} }},
		{"second CP", func(p *Plan) { p.Regions[0].Machines[1].Holds = heldComponents{"control-plane"} }},
		{"stateless region", func(p *Plan) { p.Regions[0].HoldsState = false }},
		{"shared fault domain", func(p *Plan) { p.Regions[0].Machines[2].FailureDomain = p.Regions[0].Machines[1].FailureDomain }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := threeRegionsMultiEdgePlan()
			tc.edit(p)
			if err := p.Validate(); err == nil {
				t.Fatal("invalid dedicated-node placement was accepted")
			}
		})
	}
}

func TestThreeRegionsMultiEdgeRefusesAmbiguousRouting(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*Plan)
	}{
		{"shared peer IP", func(p *Plan) { p.Regions[1].Machines[0].ReachableAddress = p.Regions[0].Machines[0].ReachableAddress }},
		{"shared peer name", func(p *Plan) { p.Regions[1].Machines[0].Reachable = p.Regions[0].Machines[0].Reachable }},
		{"peer shadows regional Portal", func(p *Plan) { p.Regions[1].Machines[1].Reachable = p.regionPortalName("region-a") }},
		{"alias shadows regional Portal", func(p *Plan) { p.Names = append(p.Names, p.regionPortalName("region-b")) }},
		{"Edge owns another Region Portal", func(p *Plan) { p.Regions[0].Machines[1].Portal = p.regionPortalName("region-c") }},
		{"legacy per-Edge override", func(p *Plan) { p.Regions[0].Machines[1].Portal = "portal-node.example" }},
		{"portal shadows agents", func(p *Plan) { p.Regions[0].Machines[1].Portal = p.PlaneNamesFor(p.Regions[0].ID)["agents"] }},
		{"portal shadows admin", func(p *Plan) {
			p.Regions[0].Machines[1].Portal = p.nodeAdminTargets()[0].Label + ".admin." + p.Deployment
		}},
		{"portal shadows peer", func(p *Plan) { p.Regions[0].Machines[1].Portal = p.Regions[0].Machines[0].Reachable }},
		{"unsafe region", func(p *Plan) { p.Regions[0].ID = "a\ninvalid" }},
		{"unsafe additional bind", func(p *Plan) {
			p.Regions[0].Machines[0].Addresses = append(p.Regions[0].Machines[0].Addresses, "bad\naddress")
		}},
		{"wildcard peer", func(p *Plan) { p.Regions[0].Machines[0].ReachableAddress = "0.0.0.0" }},
		{"case ambiguous region", func(p *Plan) { p.Regions[0].ID = "Region-A" }},
		{"unsafe bind", func(p *Plan) { p.Regions[0].Machines[0].Addresses[0] = "not-an-address" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := threeRegionsMultiEdgePlan()
			tc.edit(p)
			if err := p.Validate(); err == nil {
				t.Fatal("ambiguous or unsafe route accepted")
			}
		})
	}
}

func TestThreeRegionsMultiEdgeExamplePlan(t *testing.T) {
	p, err := LoadPlan("../../docs/plans/three-regions-multi-edge.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(p.machines()) != 9 || p.Profile != "three-regions-multi-edge" {
		t.Fatal("example no longer describes dedicated nodes")
	}
}
