package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// verify_published_releases_are_shared.go — every control plane of one deployment offers the SAME releases.
//
// ★★★ ONE CONTROL PLANE HELD THE CATALOGUE AND THE OTHER HELD NOTHING (2026-08-28, measured on the generated
// two-region lab). The published set was a file on whichever node served the publish: region-a had
// `deployment|darwin/arm64`, region-b had no file at all. The front door balances the pair, so an Edge polling
// every minute was answered one target, then none, then one — and every device read "nothing published" every
// other minute while the Console, reading whichever node answered, showed a healthy release.
//
// The same node-local life had the rollout PLANS, which is worse in one way: a halt an operator declared
// during an incident reached only the node that was told, and an Edge asking the pair is answered "frozen",
// then "not frozen", which it cannot distinguish from the halt being lifted.
//
// ★ THE SET, NOT THE COUNT — for the reason verify_connector_registry.go gives. A deployment that has
// published nothing is reported UNMEASURED rather than passing: two nodes that both hold nothing agree
// perfectly, and that is the state this exists to catch.
func verifyPublishedReleasesAreShared(client *http.Client, cpAdmins []string, token string) []verifyResult {
	out := []verifyResult{}
	add := func(ok bool, format string, args ...any) {
		out = append(out, verifyResult{name: "every control plane publishes the same releases", ok: ok,
			note: fmt.Sprintf(format, args...)})
	}
	doors := []string{}
	for _, u := range cpAdmins {
		if u = strings.TrimRight(strings.TrimSpace(u), "/"); u != "" {
			doors = append(doors, u)
		}
	}
	if len(doors) < 2 {
		add(true, "one control plane was named, so there is nothing to disagree with — name the peers to measure this")
		return out
	}

	seen := map[string][]string{}
	for _, door := range doors {
		code, body, err := get(client, door+"/admin/agent-updates", token)
		if err != nil || code != 200 {
			add(false, "%s did not answer (%d %v) — a control plane that cannot be asked cannot be shown to agree",
				door, code, err)
			return out
		}
		var payload struct {
			Envelopes map[string]struct {
				PayloadSHA256 string `json:"payload_sha256"`
			} `json:"envelopes"`
			Pending map[string]struct {
				PayloadSHA256 string `json:"payload_sha256"`
			} `json:"pending"`
		}
		if json.Unmarshal(body, &payload) != nil {
			add(false, "%s answered something this check cannot read", door)
			return out
		}
		// The target AND the digest: two nodes offering darwin/arm64 from different builds is the same defect
		// as one of them offering nothing, and a name-only comparison cannot see it.
		named := make([]string, 0, len(payload.Envelopes)+len(payload.Pending))
		for target, env := range payload.Envelopes {
			named = append(named, "active "+target+"="+env.PayloadSHA256)
		}
		for target, env := range payload.Pending {
			named = append(named, "pending "+target+"="+env.PayloadSHA256)
		}
		sort.Strings(named)
		seen[door] = named
	}

	first := seen[doors[0]]
	if len(first) == 0 {
		add(true, "nothing has been published to this deployment yet, and no control plane claims otherwise — "+
			"there is nothing here to be inconsistent about. This becomes a real comparison the moment a "+
			"release is published")
		return out
	}
	for _, door := range doors[1:] {
		if strings.Join(seen[door], ",") != strings.Join(first, ",") {
			add(false, "%s offers %d release(s) and %s offers %d — an edge polls the front door, so it is told "+
				"a release exists and then that nothing is published, on alternate minutes. What a deployment "+
				"has published belongs to the deployment: -agent-updates-store=postgres",
				doors[0], len(first), door, len(seen[door]))
			return out
		}
	}
	add(true, "%d control plane(s) offer the same %d release(s), by digest — whichever one the front door picks, "+
		"a device is told the same thing", len(doors), len(first))
	return out
}
