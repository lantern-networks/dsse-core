package main

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
)

// An OIDC ceremony keeps a one-time pending state in the Edge that starts it.
// The Node-specific public name routes its browser round trip to this Node's
// own Edge, while ordinary agent mux connections can still use edge_fleet.
func portalRouting(env map[string]string) string {
	name := env["DSSE_NODE_PORTAL_NAME"]
	if name == "" {
		return ""
	}
	return fmt.Sprintf("    use_backend edge_local_portal if { req.ssl_sni -i %s }\n", name)
}

func portalBackend(env map[string]string) string {
	name := env["DSSE_NODE_PORTAL_NAME"]
	if name == "" {
		return ""
	}
	// The health probe goes to the Edge's admin port, which presents the
	// deployment certificate. The browser-facing portal certificate on 8443
	// may instead be issued by a public CA and is checked by the browser.
	checkName := env["DSSE_EDGE_CHECK_TLS_NAME"]
	return fmt.Sprintf(`backend edge_local_portal
    option httpchk GET /healthz
    http-check expect status 200
    server portal-edge dsse-edge-a:8443 check check-ssl check-sni %[1]s verify required ca-file /deployment/deployment-anchor.pem verifyhost %[1]s port 9443 send-proxy resolvers containers init-addr last,libc,none resolve-prefer ipv4
`, checkName)
}

// oneRegionThreeNodesPortalRoutes balances all three browser origins across
// all three Edges. Sealed ceremony recovery and CP one-time consumption replace
// the former process affinity; the browser keeps its original origin.
func oneRegionThreeNodesPortalRoutes(env map[string]string) (string, string, error) {
	local := env["DSSE_NODE_PORTAL_NAME"]
	checkName := env["DSSE_EDGE_CHECK_TLS_NAME"]
	localAddress := strings.TrimSuffix(env["DSSE_EDGE_BIND"], ":")
	if !validPlanDNSName(local) || !validPlanDNSName(checkName) || net.ParseIP(localAddress).To4() == nil {
		return "", "", fmt.Errorf("one-region-three-nodes needs local portal and Edge TLS names and a direct Node address")
	}
	peers := strings.Split(env["DSSE_PORTAL_PEERS"], ",")
	if len(peers) != 2 {
		return "", "", fmt.Errorf("one-region-three-nodes needs two direct Node portal peers")
	}
	targets := []regionPortalTarget{{local, localAddress}}
	origins := []string{"https://" + local}
	seenNames, seenHosts := map[string]bool{local: true}, map[string]bool{localAddress: true}
	for i, peer := range peers {
		name, host, ok := strings.Cut(peer, "@")
		if !ok || !validPlanDNSName(name) || seenNames[name] || net.ParseIP(host).To4() == nil || seenHosts[host] {
			return "", "", fmt.Errorf("one-region-three-nodes portal peer %d needs a distinct name and direct IPv4 Node address", i+1)
		}
		seenNames[name], seenHosts[host] = true, true
		targets = append(targets, regionPortalTarget{name, host})
		origins = append(origins, "https://"+name)
	}
	// Colocated traffic stays on the container network; peer traffic uses
	// declared private listeners. Avoid host-port hairpin NAT for the local Edge.
	encoded, _ := json.Marshal(targets)
	shared := map[string]string{
		threeRegionPortalsKey:        string(encoded),
		"DSSE_EDGE_CHECK_TLS_NAME":   checkName,
		"DSSE_STEPUP_PORTAL_ORIGINS": strings.Join(origins, ","),
	}
	routes, backends, err := sharedRegionPortalRoutes(shared)
	if err != nil {
		return "", "", err
	}
	lines := strings.Split(backends, "\n")
	for i, line := range lines {
		if strings.Contains(line, " "+localAddress+":8443 ") {
			lines[i] = strings.Replace(line, " "+localAddress+":8443 ", " dsse-edge-a:8443 ", 1) + " resolvers containers init-addr last,libc,none resolve-prefer ipv4"
		}
	}
	return routes, strings.Join(lines, "\n"), nil
}
