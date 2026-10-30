package main

import (
	"bufio"
	"fmt"
	"net"
	"sort"
	"strings"
)

// ClientHostNames is the outside view of the region's doors. Container aliases
// deliberately keep their private peer addresses; this map must not.
func (p *Plan) ClientHostNames(tenantLabels []string) ([]string, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if p.dedicatedMultiEdge() {
		if len(tenantLabels) != 0 {
			return nil, fmt.Errorf("multi-edge tenants use shared hostnames")
		}
		names := []string{}
		for name := range p.threeRegionClientNameOwners() {
			names = append(names, name)
		}
		sort.Strings(names)
		return names, nil
	}
	if !p.oneRegionThreeNodes() {
		return nil, fmt.Errorf("client hosts require the one-region-three-nodes profile")
	}
	names := map[string]bool{p.Deployment: true}
	for _, plane := range []string{"admin", "authority", "agents", "console", "recovery"} {
		names[plane+"."+p.Deployment] = true
	}
	for _, name := range p.PlaneNamesFor(p.Regions[0].ID) {
		names[name] = true
	}
	for _, target := range p.nodeAdminTargets() {
		names[target.Label+".admin."+p.Deployment] = true
	}
	for _, m := range p.machines() {
		names[m.Reachable], names[m.Portal] = true, true
		names["agents."+strings.ToLower(strings.TrimSpace(m.Reachable))] = true
	}
	for _, name := range p.Names {
		names[name] = true
	}
	for _, label := range tenantLabels {
		if !validPlanDNSLabel(label) {
			return nil, fmt.Errorf("invalid server-issued tenant DNS label %q", label)
		}
		for _, prefix := range []string{"", "enrol.", "recovery."} {
			names[prefix+label+"."+p.Deployment] = true
		}
	}
	out := make([]string, 0, len(names))
	for name := range names {
		if !validPlanDNSName(name) {
			return nil, fmt.Errorf("invalid client host name %q", name)
		}
		out = append(out, name)
	}
	sort.Strings(out)
	return out, nil
}

// RenderClientHosts does not edit the operator's hosts or change trust.
// Regenerate it with the new labels after tenants are created.
func (p *Plan) RenderClientHosts(entryIP string, tenantLabels []string) (string, error) {
	return p.RenderClientHostsWithNodeIPs(entryIP, nil, tenantLabels)
}

// RenderClientHostsWithNodeIPs puts each Node's agent, portal and admin names on its own
// public address. Shared names stay on entryIP (one chosen Node), so the three signed
// agent endpoints are distinct without requiring DNS load balancing or EIP reassociation.
func (p *Plan) RenderClientHostsWithNodeIPs(entryIP string, nodeIPs map[string]string, tenantLabels []string) (string, error) {
	if p.dedicatedMultiEdge() {
		return p.renderThreeRegionClientHosts(entryIP, nodeIPs, tenantLabels)
	}
	if p.oneRegionThreeNodes() && p.Regions[0].Entry == nil && len(nodeIPs) == 0 {
		return "", fmt.Errorf("three independent doors require -node-entry-ips; one address would silently disable agent failover")
	}
	ip := net.ParseIP(entryIP)
	if ip == nil || !ip.IsGlobalUnicast() || ip.IsLoopback() {
		return "", fmt.Errorf("-entry-ip must name the stable regional entry address")
	}
	names, err := p.ClientHostNames(tenantLabels)
	if err != nil {
		return "", err
	}
	marker := p.Deployment
	if len(nodeIPs) > 0 {
		marker += " MULTI"
	}
	lines := []string{"# BEGIN DSSE HOSTS " + marker}
	addressFor := map[string]string{}
	if len(nodeIPs) > 0 {
		if len(nodeIPs) != len(p.Regions[0].Machines) {
			return "", fmt.Errorf("node entry addresses must name every Node")
		}
		seenIP := map[string]bool{}
		for _, m := range p.Regions[0].Machines {
			address := strings.TrimSpace(nodeIPs[m.Name])
			parsed := net.ParseIP(address)
			if parsed == nil || !parsed.IsGlobalUnicast() || parsed.IsLoopback() || seenIP[parsed.String()] {
				return "", fmt.Errorf("Node %q needs a distinct public entry address", m.Name)
			}
			seenIP[parsed.String()] = true
			addressFor[m.Reachable] = parsed.String()
			addressFor[m.Portal] = parsed.String()
			addressFor["agents."+strings.ToLower(strings.TrimSpace(m.Reachable))] = parsed.String()
			for _, target := range p.nodeAdminTargets() {
				if target.Machine == m.Name {
					addressFor[target.Label+".admin."+p.Deployment] = parsed.String()
				}
			}
		}
		if err := p.validateSharedEntryAddress(ip.String(), nodeIPs); err != nil {
			return "", err
		}
		if !seenIP[ip.String()] {
			return "", fmt.Errorf("shared entry address must be one of the three Node entry addresses")
		}
	}
	for _, name := range names {
		address := ip.String()
		if own := addressFor[name]; own != "" {
			address = own
		}
		lines = append(lines, address+" "+name)
	}
	lines = append(lines, "# END DSSE HOSTS "+marker)
	return strings.Join(lines, "\n") + "\n", nil
}

type clientHostEntry struct {
	Name string
	IP   net.IP
}

func (p *Plan) validateClientHostEntries(entries []clientHostEntry, tenantLabels []string) error {
	names, err := p.ClientHostNames(tenantLabels)
	if err != nil {
		return err
	}
	wanted := make(map[string]bool, len(names))
	addresses := make(map[string]string, len(entries))
	for _, name := range names {
		wanted[name] = true
	}
	for _, entry := range entries {
		if !wanted[entry.Name] {
			return fmt.Errorf("hosts contains a name outside this plan and tenant set: %s", entry.Name)
		}
		delete(wanted, entry.Name)
		addresses[entry.Name] = entry.IP.String()
	}
	if len(wanted) != 0 {
		return fmt.Errorf("hosts omits %d names required by the plan and tenant set", len(wanted))
	}
	if p.dedicatedMultiEdge() {
		return p.validateThreeRegionClientAddresses(addresses)
	}
	if p.oneRegionThreeNodes() && p.Regions[0].Entry == nil {
		nodeIPs := map[string]string{}
		for _, m := range p.machines() {
			nodeIPs[m.Name] = addresses["agents."+m.Reachable]
		}
		if err := p.validateSharedEntryAddress(addresses[p.Deployment], nodeIPs); err != nil {
			return err
		}
		seen := map[string]bool{}
		for _, m := range p.Regions[0].Machines {
			agent := "agents." + strings.ToLower(strings.TrimSpace(m.Reachable))
			ip := addresses[agent]
			if ip == "" || seen[ip] || addresses[m.Reachable] != ip || addresses[m.Portal] != ip {
				return fmt.Errorf("Node %q agent, portal and peer names must resolve to its own distinct entry", m.Name)
			}
			seen[ip] = true
			for _, target := range p.nodeAdminTargets() {
				if target.Machine == m.Name && addresses[target.Label+".admin."+p.Deployment] != ip {
					return fmt.Errorf("Node %q admin name must resolve to its entry", m.Name)
				}
			}
		}
	}
	return nil
}

func parseClientHosts(block string) ([]clientHostEntry, error) {
	var entries []clientHostEntry
	seen := map[string]bool{}
	var deployment string
	multi := false
	var entryIP net.IP
	started, ended := false, false
	scanner := bufio.NewScanner(strings.NewReader(block))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "# BEGIN DSSE HOSTS ") {
			if started {
				return nil, fmt.Errorf("duplicate hosts block")
			}
			deployment = strings.TrimPrefix(line, "# BEGIN DSSE HOSTS ")
			if strings.HasSuffix(deployment, " MULTI") {
				multi = true
				deployment = strings.TrimSuffix(deployment, " MULTI")
			}
			if !validPlanDNSName(deployment) {
				return nil, fmt.Errorf("invalid deployment marker")
			}
			started = true
			continue
		}
		if strings.HasPrefix(line, "# END DSSE HOSTS ") {
			marker := deployment
			if multi {
				marker += " MULTI"
			}
			if !started || ended || line != "# END DSSE HOSTS "+marker {
				return nil, fmt.Errorf("mismatched hosts markers")
			}
			ended = true
			continue
		}
		if strings.HasPrefix(line, "#") || !started || ended {
			return nil, fmt.Errorf("unexpected content outside the hosts block")
		}
		fields := strings.Fields(line)
		if len(fields) != 2 || !validPlanDNSName(fields[1]) || seen[fields[1]] {
			return nil, fmt.Errorf("invalid or duplicate hosts entry")
		}
		ip := net.ParseIP(fields[0])
		if ip == nil || !ip.IsGlobalUnicast() || ip.IsLoopback() {
			return nil, fmt.Errorf("invalid entry address")
		}
		if !multi && entryIP != nil && !entryIP.Equal(ip) {
			return nil, fmt.Errorf("client names must share one stable entry address")
		}
		entryIP = ip
		seen[fields[1]] = true
		entries = append(entries, clientHostEntry{Name: fields[1], IP: ip})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if !started || !ended || len(entries) == 0 {
		return nil, fmt.Errorf("missing or empty marked hosts block")
	}
	return entries, nil
}
