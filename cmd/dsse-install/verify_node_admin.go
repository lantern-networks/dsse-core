package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// Ports alone cannot prove ownership: six aliases of one live node are still
// six successful requests. Check the declared name and the identity it serves.
func verifyNodeAdminOwners(client *http.Client, env map[string]string, deployment string, edgeAdmins []string, cpPeers string) verifyResult {
	result := verifyResult{name: "each admin name reaches its owning Node"}
	targets, err := readPlanNodeAdminTargets(env)
	if err != nil {
		result.note = err.Error()
		return result
	}
	expected := map[string]planNodeAdminTarget{}
	for _, t := range targets {
		expected[t.Label+".admin."+strings.ToLower(deployment)] = t
	}
	seen := map[string]bool{}
	groups := []struct {
		urls []string
		role string
	}{{edgeAdmins, "edge"}, {strings.Split(cpPeers, ","), "control-plane"}}
	for _, group := range groups {
		for _, raw := range group.urls {
			u, err := url.Parse(strings.TrimSpace(raw))
			if err != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" && u.Path != "/" || u.Port() != "" && u.Port() != "443" {
				result.note = "require all six unique node-owned HTTPS admin URLs on 443"
				return result
			}
			host := strings.ToLower(u.Hostname())
			t, exists := expected[host]
			if !exists || seen[host] || t.Role != group.role {
				result.note = "missing, duplicated or incorrectly named admin owner: " + u.Hostname()
				return result
			}
			seen[host] = true
			status, body, err := get(client, strings.TrimRight(strings.TrimSpace(raw), "/")+"/healthz", "")
			var health struct{ Machine, Role, Status string }
			if err != nil || status != http.StatusOK || json.Unmarshal(body, &health) != nil || health.Status != "ok" || health.Machine != t.Machine || health.Role != t.Role {
				result.note = fmt.Sprintf("%s did not return healthy owner %s/%s", u.Hostname(), t.Machine, t.Role)
				return result
			}
		}
	}
	if len(seen) != len(expected) {
		result.note = "require all three Edge owners and all three control-plane owners"
		return result
	}
	result.ok, result.note = true, "all six HTTPS names on 443 returned their declared machine and role"
	return result
}
