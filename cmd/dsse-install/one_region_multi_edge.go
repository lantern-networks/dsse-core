package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
)

func (p *Plan) oneRegionMultiEdge() bool { return p.Profile == "one-region-multi-edge" }
func dedicatedMultiEdgeProfile(profile string) bool {
	return profile == "one-region-multi-edge" || profile == "three-regions-multi-edge"
}
func (p *Plan) dedicatedMultiEdge() bool { return dedicatedMultiEdgeProfile(p.Profile) }
func declaredNodeMapProfile(profile string) bool {
	return threeVoterProfile(profile) || profile == "one-region-multi-edge"
}

func (p *Plan) sharedPortalName() string {
	return p.regionPortalName(p.Regions[0].ID)
}

func (p *Plan) regionPortalName(regionID string) string {
	return "portal." + regionID + "." + p.Deployment
}

// This is deliberately a single authority and doorway, not a quorum profile.
// Only the dedicated Edge tier survives losing a machine in this topology.
func (p *Plan) validateOneRegionMultiEdge() error {
	if len(p.Regions) != 1 || !p.Regions[0].HoldsState {
		return fmt.Errorf("one-region-multi-edge requires one state-bearing DSSE region")
	}
	if err := p.validateThreeRegionNames(); err != nil {
		return err
	}
	cpCount, edgeCount := 0, 0
	domains := map[string]bool{}
	portal := p.sharedPortalName()
	if !validPlanDNSName(portal) {
		return fmt.Errorf("invalid shared region portal name")
	}
	for _, m := range p.Regions[0].Machines {
		if m.Reachable == portal {
			return fmt.Errorf("shared portal cannot shadow a peer name")
		}
		if m.FailureDomain == "" || domains[m.FailureDomain] {
			return fmt.Errorf("dedicated nodes need distinct failure domains")
		}
		domains[m.FailureDomain] = true
		switch {
		case m.Holds.has("control-plane") && !m.Holds.has("edges"):
			cpCount++
		case m.Holds.has("edges") && !m.Holds.has("control-plane"):
			edgeCount++
			if m.Portal != "" && m.Portal != portal {
				return fmt.Errorf("all dedicated Edges must use the shared region portal %s", portal)
			}
		default:
			return fmt.Errorf("one-region-multi-edge requires dedicated CP/L4 and Edge machines")
		}
	}
	if cpCount != 1 || edgeCount < 2 {
		return fmt.Errorf("one-region-multi-edge needs one CP/L4 and at least two Edges")
	}
	for _, name := range p.Names {
		if !validPlanDNSName(name) || name == portal {
			return fmt.Errorf("invalid alias or alias shadowing the shared portal")
		}
	}
	return nil
}

func singleCPMultiEdgeBackends(env map[string]string, adminName, consoleName string) (string, string, string, error) {
	host := strings.TrimSuffix(env["DSSE_CP_A_BIND"], ":")
	if net.ParseIP(host).To4() == nil || !validPlanDNSName(adminName) || !validPlanDNSName(consoleName) {
		return "", "", "", fmt.Errorf("single CP needs a private IPv4 bind and valid TLS names")
	}
	check := "check check-ssl check-sni " + adminName + " verify required ca-file /deployment/deployment-anchor.pem verifyhost " + adminName
	admin := fmt.Sprintf("    server cp-a %s:%d %s\n", host, planCPAdminPortA, check)
	data := fmt.Sprintf("    server cp-a %s:%d %s\n", host, planCPDataPortA, check)
	console := "    option httpchk GET /ready\n    http-check expect status 200\n" + oneRegionThreeNodesManagementServerDefaults + fmt.Sprintf("    server console %s:%d check check-ssl check-sni %s verify none\n", host, planConsolePortA, consoleName)
	return admin, data, console, nil
}

// Every browser request has the same origin. Sealed ceremony state, the shared
// binding key and the CP's one-time-result store allow another Edge to finish it.
// Enable ceremony-recovery-v1 through fleet capability consensus before admitting
// browser authentication; backend health alone does not prove that readiness.
func sharedRegionPortalRoutes(env map[string]string) (string, string, error) {
	var targets []regionPortalTarget
	if err := json.Unmarshal([]byte(env[threeRegionPortalsKey]), &targets); err != nil || len(targets) < 2 {
		return "", "", fmt.Errorf("shared region portal needs at least two Edge targets")
	}
	checkName := env["DSSE_EDGE_CHECK_TLS_NAME"]
	portals := map[string]bool{}
	for _, raw := range strings.Split(env["DSSE_STEPUP_PORTAL_ORIGINS"], ",") {
		if raw == "" {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "https" || u.User != nil || u.Host != u.Hostname() || u.RawQuery != "" || u.Fragment != "" || u.Path != "" || !validPlanDNSName(u.Hostname()) {
			return "", "", fmt.Errorf("invalid shared Portal origin")
		}
		portals[u.Hostname()] = true
	}
	if len(portals) == 0 {
		portals[targets[0].Name] = true
	}
	if !validPlanDNSName(checkName) {
		return "", "", fmt.Errorf("invalid shared portal or health TLS name")
	}
	var backend strings.Builder
	backend.WriteString("backend edge_region_portal\n    balance roundrobin\n    timeout check 2s\n    default-server inter 1s fall 2 rise 2\n    option httpchk GET /healthz\n    http-check expect status 200\n")
	seen := map[string]bool{}
	for i, t := range targets {
		ip := net.ParseIP(t.Address)
		if !validPlanDNSName(t.Name) || !portals[t.Name] || ip.To4() == nil || !ip.IsGlobalUnicast() || seen[ip.String()] {
			return "", "", fmt.Errorf("portal targets need declared origins and distinct unicast Edge addresses")
		}
		seen[ip.String()] = true
		fmt.Fprintf(&backend, "    server portal-edge-%d %s:%d check check-ssl check-sni %s verify required ca-file /deployment/deployment-anchor.pem verifyhost %s port %d send-proxy\n", i+1, ip.String(), planEdgeBehindDoorAgentPort, checkName, checkName, planEdgeBehindDoorAdminPort)
	}
	if env["DSSE_TOPOLOGY_PROFILE"] == "three-regions-multi-edge" {
		// The local Edge pair shares only its own Region Portal origin.
		localPortal := targets[0].Name
		if !strings.HasPrefix(localPortal, "portal."+env["DSSE_EDGE_REGION"]+".") {
			return "", "", fmt.Errorf("regional Portal target does not belong to this Region")
		}
		for _, target := range targets {
			if target.Name != localPortal {
				return "", "", fmt.Errorf("regional Portal targets must share the owning Region's origin")
			}
		}
		portals = map[string]bool{localPortal: true}
	}
	names := []string{}
	for name := range portals {
		if !validPlanDNSName(name) {
			return "", "", fmt.Errorf("invalid shared Portal name")
		}
		names = append(names, name)
	}
	sort.Strings(names)
	routes := ""
	for _, name := range names {
		routes += fmt.Sprintf("    use_backend edge_region_portal if { req.ssl_sni -i %s }\n", name)
	}
	return routes, backend.String(), nil
}

// A foreign Portal name must not fall through to the device Edge backend.
// Keep these rules before the ClientHello accept rule in the TCP frontend.
func regionalForeignPortalRejectRules(env map[string]string) (string, error) {
	if env["DSSE_TOPOLOGY_PROFILE"] != "three-regions-multi-edge" {
		return "", nil
	}
	var targets []regionPortalTarget
	if err := json.Unmarshal([]byte(env[threeRegionPortalsKey]), &targets); err != nil || len(targets) < 2 {
		return "", fmt.Errorf("regional Portal needs at least two Edge targets")
	}
	local := targets[0].Name
	if !validPlanDNSName(local) || !strings.HasPrefix(local, "portal."+env["DSSE_EDGE_REGION"]+".") {
		return "", fmt.Errorf("invalid owning Region Portal")
	}
	var foreign []string
	foundLocal := false
	for _, raw := range strings.Split(env["DSSE_STEPUP_PORTAL_ORIGINS"], ",") {
		if raw == "" {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "https" || u.User != nil || u.Host != u.Hostname() || u.RawQuery != "" || u.Fragment != "" || u.Path != "" || !validPlanDNSName(u.Hostname()) {
			return "", fmt.Errorf("invalid regional Portal origin")
		}
		if u.Hostname() == local {
			foundLocal = true
		} else {
			foreign = append(foreign, u.Hostname())
		}
	}
	if !foundLocal || len(foreign) == 0 {
		return "", fmt.Errorf("regional Portal origins must include the local and foreign Regions")
	}
	sort.Strings(foreign)
	var rules strings.Builder
	for _, name := range foreign {
		fmt.Fprintf(&rules, "    tcp-request content reject if { req.ssl_sni -i %s }\n", name)
	}
	return rules.String(), nil
}
