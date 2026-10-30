package main

import (
	"encoding/json"
	"fmt"
)

const consoleLeaderRoutingKey = "DSSE_CONSOLE_LEADER_ROUTING"

// Direct private CP probes cannot mistake a leader-aware public entrance for
// its colocated CP. Destination origins are the existing shared Console names.
func (p *Plan) consoleLeaderRouting(machine PlanMachine) string {
	if !declaredNodeMapProfile(p.Profile) || !machine.Holds.has("control-plane") {
		return ""
	}
	type candidate struct {
		Node          string `json:"node"`
		LeaderURL     string `json:"leader_url"`
		TLSName       string `json:"tls_name"`
		ConsoleOrigin string `json:"console_origin"`
	}
	config := struct {
		LocalNode  string      `json:"local_node"`
		Candidates []candidate `json:"candidates"`
	}{LocalNode: machine.Name}
	for _, region := range p.Regions {
		for _, cp := range region.Machines {
			if !cp.Holds.has("control-plane") {
				continue
			}
			config.Candidates = append(config.Candidates, candidate{Node: cp.Name, LeaderURL: fmt.Sprintf("https://%s:%d/leader", cp.reachableAt(), planCPAdminPortA), TLSName: p.PlaneNamesFor(region.ID)["admin"], ConsoleOrigin: "https://" + p.PlaneNamesFor(region.ID)["console"]})
		}
	}
	raw, _ := json.Marshal(config)
	return string(raw)
}
