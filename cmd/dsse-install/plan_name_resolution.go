package main

import (
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strings"
)

const planHostAliasesKey = "DSSE_PLAN_HOST_ALIASES"

// Local plane names reach this node's SNI doorway; peer names reach the
// explicitly declared peer address. Host /etc/hosts is not shared by containers.
func (p *Plan) oneRegionHostAliases(region PlanRegion) string {
	aliases := map[string]string{}
	local := fmt.Sprintf("10.%d.0.5", regionSubnetOctet(region.ID))
	aliases[p.Deployment] = local
	for _, plane := range []string{"admin", "authority", "agents", "console", "recovery"} {
		aliases[plane+"."+p.Deployment] = local
	}
	for _, name := range p.PlaneNamesFor(region.ID) {
		aliases[name] = local
	}
	for _, target := range p.nodeAdminTargets() {
		aliases[target.Label+".admin."+p.Deployment] = local
	}
	for _, m := range region.Machines {
		if m.Reachable != "" && net.ParseIP(m.reachableAt()) != nil {
			aliases[m.Reachable] = m.reachableAt()
		}
		if m.Portal != "" {
			aliases[m.Portal] = local
		}
	}
	b, _ := json.Marshal(aliases)
	return string(b)
}

var composeServiceHeader = regexp.MustCompile(`(?m)^  ([a-zA-Z0-9_-]+):[^\n]*\n`)
var composeHostAliasesBlock = regexp.MustCompile(`(?m)^    extra_hosts:\n(?:      [^\n]*\n)+`)

func composeWithPlanNameResolution(body string, env map[string]string) (string, error) {
	if !declaredNodeMapProfile(env["DSSE_TOPOLOGY_PROFILE"]) {
		return body, nil
	}
	var aliases map[string]string
	if err := json.Unmarshal([]byte(env[planHostAliasesKey]), &aliases); err != nil {
		return "", fmt.Errorf("invalid plan host aliases: %w", err)
	}
	for name, ip := range aliases {
		if strings.ContainsAny(name, "\r\n: ") || net.ParseIP(ip) == nil {
			return "", fmt.Errorf("invalid plan host alias")
		}
	}
	encoded, _ := json.Marshal(aliases)
	// Only clients of named planes/peers need this map. Existing explicit alias
	// slots remain untouched for profiles without the declared three-node map.
	clients := map[string]bool{"dsse-store-a": true, "dsse-postgres-a": true, "dsse-control-plane-a": true, "dsse-edge-a": true, "dsse-console": true, "dsse-postgres-init": true}
	headers := composeServiceHeader.FindAllStringSubmatchIndex(body, -1)
	for i := len(headers) - 1; i >= 0; i-- {
		h := headers[i]
		name := body[h[2]:h[3]]
		if !clients[name] {
			continue
		}
		end := len(body)
		if i+1 < len(headers) {
			end = headers[i+1][0]
		}
		block := body[h[0]:end]
		block = composeHostAliasesBlock.ReplaceAllString(block, "")
		relativeEnd := h[1] - h[0]
		if at := strings.Index(block, "    restart:"); at >= 0 {
			if end := strings.IndexByte(block[at:], '\n'); end >= 0 {
				relativeEnd = at + end + 1
			}
		}
		block = block[:relativeEnd] + "    extra_hosts: " + string(encoded) + "\n" + block[relativeEnd:]
		body = body[:h[0]] + block + body[end:]
	}
	return body, nil
}
