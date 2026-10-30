package main

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestPlanGeneratesConsoleLeaderRedirectCandidates(t *testing.T) {
	for _, p := range []*Plan{threeNodesOneRegionPlan(), threeRegionsMultiEdgePlan(), oneRegionMultiEdgePlan()} {
		if err := p.Validate(); err != nil {
			t.Fatal(err)
		}
		for _, region := range p.Regions {
			for _, machine := range region.Machines {
				env, err := p.MachineEnvironment(machine.Name)
				if err != nil {
					t.Fatal(err)
				}
				raw := env[consoleLeaderRoutingKey]
				if !machine.Holds.has("control-plane") {
					if raw != "" {
						t.Fatal("Edge-only host published management routing")
					}
					continue
				}
				// Decode exact JSON names as used by the separate Console executable.
				var exact struct {
					LocalNode  string `json:"local_node"`
					Candidates []struct {
						Node          string `json:"node"`
						LeaderURL     string `json:"leader_url"`
						TLSName       string `json:"tls_name"`
						ConsoleOrigin string `json:"console_origin"`
					} `json:"candidates"`
				}
				if err := json.Unmarshal([]byte(raw), &exact); err != nil {
					t.Fatal(err)
				}
				expected := 3
				if p.oneRegionMultiEdge() {
					expected = 1
				}
				if exact.LocalNode != machine.Name || len(exact.Candidates) != expected {
					t.Fatal("missing local identity or complete CP candidates")
				}
				for _, candidate := range exact.Candidates {
					r, cp, found := p.find(candidate.Node)
					if !found || !cp.Holds.has("control-plane") || candidate.LeaderURL != fmt.Sprintf("https://%s:%d/leader", cp.reachableAt(), planCPAdminPortA) || candidate.TLSName != p.PlaneNamesFor(r.ID)["admin"] || candidate.ConsoleOrigin != "https://"+p.PlaneNamesFor(r.ID)["console"] {
						t.Fatal("candidate points at an entrance or undeclared Console")
					}
				}
			}
		}
	}
}
