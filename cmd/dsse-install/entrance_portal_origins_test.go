package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestGeneratedEntrancePortalMappingUsesIngressAcrossAllEdges(t *testing.T) {
	for _, p := range []*Plan{threeNodesOneRegionPlan(), threeRegionsMultiEdgePlan()} {
		if err := p.Validate(); err != nil {
			t.Fatal(err)
		}
		var want string
		for _, r := range p.Regions {
			for _, m := range r.Machines {
				env, err := p.MachineEnvironment(m.Name)
				if err != nil {
					t.Fatal(err)
				}
				raw := env[entrancePortalOriginsKey]
				if want == "" {
					want = raw
				}
				if raw == "" || raw != want {
					t.Fatal("different machines disagree on ingress-to-Portal identity")
				}
			}
		}
		var mapping map[string]string
		if err := json.Unmarshal([]byte(want), &mapping); err != nil {
			t.Fatal(err)
		}
		if p.oneRegionThreeNodes() {
			for _, m := range p.Regions[0].Machines {
				if mapping["agents."+m.Reachable] != "https://"+p.edgePortalName(m) {
					t.Fatal("node entrance points at a different Portal")
				}
			}
		} else {
			for _, r := range p.Regions {
				for _, plane := range []string{"agents", "recovery"} {
					if mapping[p.PlaneNamesFor(r.ID)[plane]] != "https://"+p.regionPortalName(r.ID) {
						t.Fatal("regional entrance lost its Portal")
					}
				}
			}
		}
		entry := p.Regions[0].Machines[1]
		if p.dedicatedMultiEdge() {
			entry = p.Regions[1].Machines[0]
		}
		p.SharedEntryMachine = entry.Name
		if err := p.Validate(); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal([]byte(p.entrancePortalOrigins()), &mapping); err != nil {
			t.Fatal(err)
		}
		origin := "https://" + p.edgePortalName(entry)
		if p.dedicatedMultiEdge() {
			origin = "https://" + p.regionPortalName(p.Regions[1].ID)
		}
		for _, alias := range []string{p.Deployment, "agents." + p.Deployment, "recovery." + p.Deployment} {
			if mapping[alias] != origin {
				t.Fatal("generic name does not follow chosen entrance")
			}
		}
		ips := map[string]string{}
		for i, r := range p.Regions {
			for j, m := range r.Machines {
				if !p.dedicatedMultiEdge() || m.Name == r.controlPlane().Name {
					ips[m.Name] = fmtIP(100+i, j+1)
				}
			}
		}
		if _, err := p.RenderClientHostsWithNodeIPs(ips[entry.Name], ips, nil); err != nil {
			t.Fatal(err)
		}
		if _, err := p.RenderClientHostsWithNodeIPs("203.0.113.250", ips, nil); err == nil || !strings.Contains(err.Error(), "shared entry") {
			t.Fatal("DNS silently disagrees with signed ingress mapping")
		}
		p.SharedEntryMachine = "not-declared"
		if err := p.Validate(); err == nil {
			t.Fatal("unknown generic entrance accepted")
		}
	}
	p := threeRegionsMultiEdgePlan()
	p.SharedEntryMachine = p.Regions[0].Machines[1].Name
	if err := p.Validate(); err == nil {
		t.Fatal("Edge-only node accepted as public entrance")
	}
}
