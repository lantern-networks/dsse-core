package main

import (
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"
)

const threeRegionPortalsKey = "DSSE_REGION_PORTAL_TARGETS"

func threeVoterProfile(profile string) bool {
	return profile == "one-region-three-nodes" || profile == "three-regions-multi-edge"
}

// Each entrance owns a DNS origin, but every Edge serves all declared origins.
// No hostname is derived from a tenant identity.
func (p *Plan) edgePortalName(m PlanMachine) string {
	if p.dedicatedMultiEdge() {
		for _, r := range p.Regions {
			for _, member := range r.Machines {
				if member.Name == m.Name {
					return p.regionPortalName(r.ID)
				}
			}
		}
		return "" // An unknown machine must never borrow another Region's origin.
	}
	if m.Portal != "" {
		return m.Portal
	}
	return "portal-" + m.Name + "." + p.Deployment
}

type regionPortalTarget struct {
	Name    string `json:"name"`
	Address string `json:"address"`
}

func (p *Plan) validateThreeRegionNames() error {
	if !validPlanDNSName(p.Deployment) || p.Deployment != strings.ToLower(p.Deployment) {
		return fmt.Errorf("multi-edge deployment needs a DNS-safe name")
	}
	names, addresses := map[string]bool{}, map[string]bool{}
	// Reserve all plane names before checking machine and portal names.
	for _, r := range p.Regions {
		if !validPlanDNSLabel(r.ID) || r.ID != strings.ToLower(r.ID) {
			return fmt.Errorf("invalid region ID %q", r.ID)
		}
		for _, n := range p.PlaneNamesFor(r.ID) {
			names[strings.ToLower(n)] = true
		}
	}
	if p.dedicatedMultiEdge() {
		for _, r := range p.Regions {
			portal := p.regionPortalName(r.ID)
			if !validPlanDNSName(portal) || names[portal] {
				return fmt.Errorf("invalid or duplicate shared region portal %q", portal)
			}
			for _, alias := range p.Names {
				if strings.EqualFold(alias, portal) {
					return fmt.Errorf("deployment alias shadows shared region portal %q", portal)
				}
			}
			names[portal] = true
		}
	}
	for _, target := range p.nodeAdminTargets() {
		names[strings.ToLower(target.Label+".admin."+p.Deployment)] = true
	}
	names[strings.ToLower(p.Deployment)] = true
	for _, plane := range []string{"agents", "admin", "authority", "console", "recovery"} {
		names[plane+"."+strings.ToLower(p.Deployment)] = true
	}
	for _, r := range p.Regions {
		for _, m := range r.Machines {
			if !validPlanDNSLabel(m.Name) || m.Name != strings.ToLower(m.Name) {
				return fmt.Errorf("invalid machine name %q", m.Name)
			}
			// These private management listeners currently use IPv4. This does not
			// restrict IPv6 client traffic or Edge egress; it is an explicit plan contract.
			if len(m.Addresses) == 0 || net.ParseIP(m.Addresses[0]).To4() == nil || net.ParseIP(m.ReachableAddress).To4() == nil {
				return fmt.Errorf("machine %q needs IPv4 bind and inter-node addresses for private management", m.Name)
			}
			for _, bind := range m.Addresses {
				if ip := net.ParseIP(bind); ip == nil || !ip.IsGlobalUnicast() {
					return fmt.Errorf("machine %q has an invalid bind address", m.Name)
				}
			}
			if !net.ParseIP(m.ReachableAddress).IsGlobalUnicast() {
				return fmt.Errorf("machine %q needs a unicast inter-node address", m.Name)
			}
			ip := net.ParseIP(m.ReachableAddress).String()
			if addresses[ip] {
				return fmt.Errorf("duplicate inter-node address on %q", m.Name)
			}
			addresses[ip] = true
			nodeNames := []string{m.Reachable}
			if m.Holds.has("edges") {
				if p.dedicatedMultiEdge() {
					if m.Portal != "" && m.Portal != p.regionPortalName(r.ID) {
						return fmt.Errorf("Edge %q must use shared region portal %q", m.Name, p.regionPortalName(r.ID))
					}
				} else {
					nodeNames = append(nodeNames, p.edgePortalName(m))
				}
			} else if !m.Holds.has("edges") && m.Portal != "" {
				return fmt.Errorf("CP-only machine %q cannot own an Edge portal", m.Name)
			}
			for _, n := range nodeNames {
				key := strings.ToLower(n)
				if !validPlanDNSName(n) || n != key || names[key] {
					return fmt.Errorf("invalid or duplicate plane/node/portal name %q", n)
				}
				names[key] = true
			}
			for _, role := range []string{"edges", "control-plane"} {
				if !m.Holds.has(role) {
					continue
				}
				component := "edge-a"
				if role == "control-plane" {
					component = "control-plane-a"
				}
				if !validPlanDNSLabel(nodeAdminLabel(r.ID, m.Name, component)) {
					return fmt.Errorf("admin label for %q exceeds DNS limits", m.Name)
				}
			}
		}
	}
	return nil
}

func (p *Plan) regionAdminTargets(region PlanRegion) []planNodeAdminTarget {
	wanted := map[string]bool{}
	for _, m := range region.Machines {
		wanted[m.Name] = true
	}
	var out []planNodeAdminTarget
	for _, t := range p.nodeAdminTargets() {
		if wanted[t.Machine] {
			out = append(out, t)
		}
	}
	return out
}

func (p *Plan) threeRegionEnvironment(region PlanRegion, machine PlanMachine, env map[string]string) {
	env["DSSE_TOPOLOGY_PROFILE"] = p.Profile
	env["DSSE_NODE_ROLE"] = "control-plane"
	if !machine.Holds.has("control-plane") {
		env["DSSE_NODE_ROLE"] = "edge"
		env["DSSE_REGION_BIND_A"], env["DSSE_REGION_PORT"] = "", ""
	}
	octet := regionSubnetOctet(region.ID)
	env["DSSE_SUBNET"] = fmt.Sprintf("10.%d.0.0/16", octet)
	env["DSSE_SUBNET_RANGE"] = fmt.Sprintf("10.%d.1.0/24", octet)
	env["DSSE_SUBNET_V6"] = fmt.Sprintf("fd00:d55e:%d::/64", octet)
	env["DSSE_FRONT_DOOR_A"] = fmt.Sprintf("10.%d.0.5", octet)
	env["DSSE_EDGE_BALANCE"], env["DSSE_STEER_MUX_ONLY"] = "leastconn", "true"
	env["DSSE_EDGE_CHECK_TLS_NAME"] = p.PlaneNamesFor(region.ID)["agents"]
	env["DSSE_EDGE_BIND"] = machine.Addresses[0] + ":"
	env["DSSE_NODE_PORTAL_NAME"], env["DSSE_CLIENTLESS_BASE_URL"] = "", ""
	if machine.Holds.has("edges") {
		env["DSSE_NODE_PORTAL_NAME"] = p.edgePortalName(machine)
		env["DSSE_CLIENTLESS_BASE_URL"] = "https://" + p.edgePortalName(machine)
		// Only this Region's CP/L4 forwards client traffic to this Edge.
		// Trust its private source addresses for PROXY metadata, never another
		// Region's doorway or a whole subnet. Agents select another Region's
		// entrance when this Region is unhealthy.
		doors := []string{}
		cp := region.controlPlane()
		doors = append(doors, dedupeSorted(cp.Addresses, cp.reachableAt())...)
		sort.Strings(doors)
		env["DSSE_TRUSTED_FRONT_DOORS"] = strings.Join(doors, ",")
	}
	targets, _ := json.Marshal(p.regionAdminTargets(region))
	env[planNodeAdminKey] = string(targets)
	portals := []regionPortalTarget{}
	for _, m := range p.doorwayEdgeCandidates(region) {
		if m.Holds.has("edges") {
			portals = append(portals, regionPortalTarget{p.edgePortalName(m), m.reachableAt()})
		}
	}
	sort.Slice(portals, func(i, j int) bool { return portals[i].Address < portals[j].Address })
	encoded, _ := json.Marshal(portals)
	env[threeRegionPortalsKey] = string(encoded)

	aliases := map[string]string{}
	localDoor := region.controlPlane().reachableAt()
	if machine.Holds.has("control-plane") {
		localDoor = env["DSSE_FRONT_DOOR_A"]
	}
	aliases[p.Deployment] = localDoor
	for _, plane := range []string{"agents", "admin", "authority", "console", "recovery"} {
		aliases[plane+"."+p.Deployment] = localDoor
	}
	quorum, consoles, adminPeers, dataPeers, origins := []string{}, []string{}, []string{}, []string{}, []string{"https://console." + p.Deployment}
	portalOrigins := []string{}
	for _, r := range p.Regions {
		cp := r.controlPlane()
		door := cp.reachableAt()
		if r.ID == region.ID {
			door = localDoor
		}
		for _, name := range p.PlaneNamesFor(r.ID) {
			aliases[name] = door
		}
		for _, t := range p.regionAdminTargets(r) {
			aliases[t.Label+".admin."+p.Deployment] = door
		}
		for _, m := range r.Machines {
			aliases[m.Reachable] = m.reachableAt()
			if m.Holds.has("edges") {
				aliases[p.edgePortalName(m)] = door
				portalOrigins = append(portalOrigins, "https://"+p.edgePortalName(m))
			}
		}
		quorum = append(quorum, fmt.Sprintf("https://%s:%d", cp.reachableName(), planEtcdPortA))
		consoles = append(consoles, fmt.Sprintf("%s:%d", cp.reachableAt(), planConsolePortA))
		origins = append(origins, "https://"+p.PlaneNamesFor(r.ID)["console"])
		if r.ID != region.ID {
			adminPeers = append(adminPeers, fmt.Sprintf("https://admin.%s@%s:%d", p.Deployment, cp.reachableAt(), planCPAdminPortA))
			dataPeers = append(dataPeers, fmt.Sprintf("%s:%d:%d", cp.reachableAt(), planCPDataPortA, planCPAdminPortA))
		}
	}
	encoded, _ = json.Marshal(aliases)
	env[planHostAliasesKey] = string(encoded)
	env["ADMIN_CONSOLE_ORIGINS"] = strings.Join(origins, ",")
	portalOrigins = dedupeSorted(portalOrigins, portalOrigins[0])
	sort.Strings(portalOrigins)
	env["DSSE_STEPUP_PORTAL_ORIGINS"] = strings.Join(portalOrigins, ",")
	if machine.Holds.has("control-plane") {
		env["DSSE_CP_A_BIND"], env["DSSE_CONSOLE_BIND"] = machine.Addresses[0]+":", machine.Addresses[0]+":"
		env["DSSE_CP_A_ADMIN_PORT"], env["DSSE_CP_A_DATA_PORT"], env["DSSE_CONSOLE_PORT"] = fmt.Sprint(planCPAdminPortA), fmt.Sprint(planCPDataPortA), fmt.Sprint(planConsolePortA)
		env["DSSE_CONSOLE_LOCAL_CP_LEADER_URL"] = "https://dsse-control-plane-a:9443/leader"
		env["DSSE_CONSOLE_LOCAL_CP_LEADER_NAME"] = "admin." + p.Deployment
		sort.Strings(consoles)
		env["DSSE_CONSOLE_BACKENDS"] = strings.Join(consoles, ",")
		sort.Strings(adminPeers)
		env["DSSE_CP_PEERS"] = strings.Join(adminPeers, ",")
		sort.Strings(dataPeers)
		env["DSSE_CP_DATA_PEERS"] = strings.Join(dataPeers, ",")
		encoded, _ = json.Marshal(quorum)
		env["DSSE_CP_QUORUM_ENDPOINTS"] = string(encoded)
	}
}

// Client-facing names go only to Region doors. Private Edge/node addresses
// stay in the inter-node map; a shared Portal resolves to its Region doorway.
func (p *Plan) threeRegionClientNameOwners() map[string]string {
	owners := map[string]string{p.Deployment: ""}
	for _, plane := range []string{"agents", "admin", "authority", "console", "recovery"} {
		owners[plane+"."+p.Deployment] = ""
	}
	for _, r := range p.Regions {
		owner := r.controlPlane().Name
		for _, name := range p.PlaneNamesFor(r.ID) {
			owners[name] = owner
		}
		for _, t := range p.regionAdminTargets(r) {
			owners[t.Label+".admin."+p.Deployment] = owner
		}
		for _, m := range r.Machines {
			if m.Holds.has("edges") {
				owners[p.edgePortalName(m)] = owner
			}
		}
	}
	return owners
}

func (p *Plan) renderThreeRegionClientHosts(entryIP string, nodeIPs map[string]string, tenantLabels []string) (string, error) {
	if err := p.Validate(); err != nil {
		return "", err
	}
	if len(tenantLabels) != 0 {
		return "", fmt.Errorf("multi-edge tenants use shared hostnames; tenant labels must be empty")
	}
	if p.oneRegionMultiEdge() && len(nodeIPs) == 0 {
		nodeIPs = map[string]string{p.Regions[0].controlPlane().Name: entryIP}
	}
	if len(nodeIPs) != len(p.Regions) {
		return "", fmt.Errorf("provide exactly one CP/L4 entry address per DSSE region")
	}
	seen := map[string]bool{}
	for _, r := range p.Regions {
		ip := net.ParseIP(nodeIPs[r.controlPlane().Name])
		if ip == nil || !ip.IsGlobalUnicast() || ip.IsLoopback() || seen[ip.String()] {
			return "", fmt.Errorf("each Region needs a distinct unicast entry address")
		}
		seen[ip.String()] = true
	}
	if err := p.validateSharedEntryAddress(entryIP, nodeIPs); err != nil {
		return "", err
	}
	shared := net.ParseIP(entryIP)
	if shared == nil || !seen[shared.String()] {
		return "", fmt.Errorf("shared entry must be one of the three CP/L4 entries")
	}
	owners := p.threeRegionClientNameOwners()
	names := []string{}
	for n := range owners {
		names = append(names, n)
	}
	sort.Strings(names)
	lines := []string{"# BEGIN DSSE HOSTS " + p.Deployment + " MULTI"}
	for _, n := range names {
		ip := shared.String()
		if owners[n] != "" {
			ip = net.ParseIP(nodeIPs[owners[n]]).String()
		}
		lines = append(lines, ip+" "+n)
	}
	lines = append(lines, "# END DSSE HOSTS "+p.Deployment+" MULTI")
	return strings.Join(lines, "\n") + "\n", nil
}

func (p *Plan) validateThreeRegionClientAddresses(addresses map[string]string) error {
	entries := map[string]string{}
	seen := map[string]bool{}
	for _, r := range p.Regions {
		ip := addresses[p.PlaneNamesFor(r.ID)["agents"]]
		if ip == "" || seen[ip] {
			return fmt.Errorf("Region entries must have three distinct addresses")
		}
		seen[ip] = true
		entries[r.controlPlane().Name] = ip
	}
	if err := p.validateSharedEntryAddress(addresses[p.Deployment], entries); err != nil {
		return err
	}
	shared := addresses[p.Deployment]
	if !seen[shared] {
		return fmt.Errorf("shared entry must be one of the Region entries")
	}
	for n, owner := range p.threeRegionClientNameOwners() {
		want := shared
		if owner != "" {
			want = entries[owner]
		}
		if addresses[n] != want {
			return fmt.Errorf("%s must resolve to its owning Region entry", n)
		}
	}
	return nil
}

// Every entrance balances only the Edge machines in its own Region. Agents
// and Connectors switch to another Region's entrance using their health map;
// the L4 proxy never forwards client traffic across Regions. CP quorum,
// replication and the Edge mesh retain their separate cross-Region paths.
func (p *Plan) doorwayEdgeCandidates(region PlanRegion) []PlanMachine {
	return region.Machines
}
