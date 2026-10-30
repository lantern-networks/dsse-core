package main

import (
	"net"
	"net/url"
	"slices"
	"strconv"
)

type installNetworkRule struct {
	Sources     []string `json:"source_machines"`
	Destination string   `json:"destination_machine"`
	Address     string   `json:"peer_address"`
	TCPPorts    []int    `json:"tcp_ports"`
	Purpose     string   `json:"purpose"`
	Exposure    string   `json:"exposure"`
}

// Requirements, not firewall changes. Public DNS/NAT addresses are an operator
// input; peer_address is the plan's reachable private address. Never permit the
// private rows from the Internet merely because they appear in this report.
func planNetworkRequirements(p *Plan) []installNetworkRule {
	var cp, edges []string
	localCP := map[string][]string{}
	for _, region := range p.Regions {
		for _, machine := range region.Machines {
			if machine.Holds.has("control-plane") {
				localCP[region.ID] = append(localCP[region.ID], machine.Name)
			}
		}
	}
	for _, m := range p.machines() {
		if m.Holds.has("control-plane") {
			cp = append(cp, m.Name)
		}
		if m.Holds.has("edges") {
			edges = append(edges, m.Name)
		}
	}
	var rules []installNetworkRule
	add := func(from []string, m PlanMachine, ports []int, purpose, exposure string) {
		if len(from) == 0 || len(ports) == 0 {
			return
		}
		slices.Sort(ports)
		ports = slices.Compact(ports)
		rules = append(rules, installNetworkRule{append([]string{}, from...), m.Name, m.reachableAt(), ports, purpose, exposure})
	}
	for _, m := range p.machines() {
		env, _ := p.MachineEnvironment(m.Name)
		region, _, _ := p.find(m.Name)
		if m.Holds.has("control-plane") {
			add([]string{"authorized clients and declared peers"}, m, []int{443}, "TLS entrances; public DNS/NAT may use a different address", "entrance")
			add(cp, m, []int{planCPAdminPortA, planCPDataPortA, planConsolePortA}, "CP/L4 leader-aware management, data and Console forwarding", "private")
			var state []int
			for _, key := range []string{"DSSE_ETCD_A_PUBLISH", "DSSE_ETCD_A_PEER_PUBLISH", "DSSE_PG_A_MEMBER_PUBLISH", "DSSE_PG_A_API_PUBLISH", "DSSE_CLICKHOUSE_PUBLISH"} {
				host, port, err := net.SplitHostPort(env[key])
				if err != nil {
					continue
				}
				ip := net.ParseIP(host)
				if ip != nil && ip.IsLoopback() {
					continue
				}
				if n, e := strconv.Atoi(port); e == nil {
					state = append(state, n)
				}
			}
			add(cp, m, state, "declared state replication, consensus and distributed state services", "private")
		}
		if m.Holds.has("edges") {
			entrances := cp
			if p.threeRegionsMultiEdge() {
				entrances = localCP[region.ID]
			}
			add(entrances, m, []int{planEdgeBehindDoorAgentPort, planEdgeBehindDoorAdminPort}, "L4 traffic and verified Edge health/admin routing", "private")
			add(edges, m, []int{planEdgeBehindDoorAgentPort}, "Edge mesh relay", "private")
		}
	}
	if p.Archive != nil {
		// Archive is an optional external service. Only CPs write it; the
		// network plan must not imply that Edge hosts need S3 access.
		host, port, err := net.SplitHostPort(p.Archive.Endpoint)
		if err == nil {
			if n, parseErr := strconv.Atoi(port); parseErr == nil {
				rules = append(rules, installNetworkRule{
					Sources: append([]string{}, cp...), Destination: "external S3 archive",
					Address: host, TCPPorts: []int{n},
					Purpose: "optional CP cold-archive TLS egress", Exposure: "outbound",
				})
			}
		}
		if receiver, err := url.Parse(p.Archive.WebhookURL); err == nil && receiver.Hostname() != "" {
			port := 443
			if receiver.Port() != "" {
				if n, parseErr := strconv.Atoi(receiver.Port()); parseErr == nil {
					port = n
				}
			}
			rules = append(rules, installNetworkRule{Sources: append([]string{}, cp...), Destination: "archive alert receiver",
				Address: receiver.Hostname(), TCPPorts: []int{port}, Purpose: "signed archive-health webhook delivery", Exposure: "outbound"})
		}
	}
	return rules
}
