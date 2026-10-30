package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
)

const planNodeAdminKey = "DSSE_NODE_ADMIN_TARGETS"

// This map is identical on every doorway. A node-owned name has exactly one
// owner, including when that owner is unavailable.
type planNodeAdminTarget struct {
	Machine string `json:"machine"`
	Role    string `json:"role"`
	Label   string `json:"label"`
	Address string `json:"address"`
}

func nodeAdminLabel(region, machine, component string) string {
	return strings.ToLower(strings.TrimSpace(region) + "-" + strings.TrimSpace(machine) + "-" + component)
}

func (p *Plan) nodeAdminTargets() []planNodeAdminTarget {
	var targets []planNodeAdminTarget
	for _, r := range p.Regions {
		for _, m := range r.Machines {
			for _, component := range []struct {
				name, role string
				port       int
			}{
				{"edge-a", "edge", planEdgeBehindDoorAdminPort},
				{"control-plane-a", "control-plane", planCPAdminPortA},
			} {
				if component.role == "edge" && !m.Holds.has("edges") || component.role == "control-plane" && !m.Holds.has("control-plane") {
					continue
				}
				targets = append(targets, planNodeAdminTarget{Machine: strings.TrimSpace(m.Name), Role: component.role,
					Label:   nodeAdminLabel(r.ID, m.Name, component.name),
					Address: net.JoinHostPort(m.reachableAt(), strconv.Itoa(component.port))})
			}
		}
	}
	return targets
}

func readPlanNodeAdminTargets(env map[string]string) ([]planNodeAdminTarget, error) {
	var targets []planNodeAdminTarget
	dec := json.NewDecoder(strings.NewReader(env[planNodeAdminKey]))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&targets); err != nil {
		return nil, fmt.Errorf("invalid %s: %w; regenerate this machine from its plan", planNodeAdminKey, err)
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("invalid %s: trailing JSON", planNodeAdminKey)
	}
	multi := dedicatedMultiEdgeProfile(env["DSSE_TOPOLOGY_PROFILE"])
	if (!multi && len(targets) != 6) || (multi && len(targets) < 3) {
		return nil, fmt.Errorf("%s must name the six owned admin surfaces", planNodeAdminKey)
	}
	labels, owners, addresses := map[string]bool{}, map[string]bool{}, map[string]string{}
	for _, t := range targets {
		component, port := "edge-a", planEdgeBehindDoorAdminPort
		if t.Role == "control-plane" {
			component, port = "control-plane-a", planCPAdminPortA
		} else if t.Role != "edge" {
			return nil, fmt.Errorf("invalid admin role %q", t.Role)
		}
		host, gotPort, err := net.SplitHostPort(t.Address)
		if err != nil || net.ParseIP(host).To4() == nil || gotPort != strconv.Itoa(port) {
			return nil, fmt.Errorf("invalid private admin address for %s", t.Label)
		}
		if !validPlanDNSLabel(t.Machine) || !validPlanDNSLabel(t.Label) || t.Label != nodeAdminLabel(env["DSSE_EDGE_REGION"], t.Machine, component) || labels[t.Label] || owners[t.Machine+"/"+t.Role] {
			return nil, fmt.Errorf("invalid or duplicate owned admin name %q", t.Label)
		}
		if previous, exists := addresses[t.Machine]; exists && previous != host {
			return nil, fmt.Errorf("admin surfaces for %s disagree on their owner address", t.Machine)
		}
		addresses[t.Machine], labels[t.Label], owners[t.Machine+"/"+t.Role] = host, true, true
	}
	if (!multi && len(addresses) != 3) || (multi && len(addresses) != len(targets)) {
		return nil, fmt.Errorf("admin surfaces must belong to three machines")
	}
	if multi {
		cpCount := 0
		for _, t := range targets {
			if t.Role == "control-plane" {
				cpCount++
			}
		}
		if cpCount != 1 {
			return nil, fmt.Errorf("a multi-edge region needs exactly one admin CP owner")
		}
	}
	unique := map[string]bool{}
	for machine, address := range addresses {
		if unique[address] || (!multi && (!owners[machine+"/edge"] || !owners[machine+"/control-plane"])) {
			return nil, fmt.Errorf("admin owners must have distinct addresses and both roles")
		}
		unique[address] = true
	}
	if _, exists := addresses[env["DSSE_NODE_NAME"]]; !exists {
		return nil, fmt.Errorf("local machine is missing from admin owners")
	}
	return targets, nil
}
