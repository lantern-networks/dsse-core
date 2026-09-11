package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// verify_mesh.go — the multi-region install order's data-plane mesh step: the data-plane mesh, and whether "no mesh" is a decision or an outage.
//
// ★★★ THE INSTALLER NAMED THIS STEP AND PRODUCED NOTHING FOR IT (2026-08-25). The install order printed by
// -region lists the data-plane mesh among the three things done once every region exists. No flag for it was
// ever generated, so an operator following that order had nothing to do it with. The launch script now emits
// the mesh when DSSE_MESH_PEERS is set, and emits nothing when it is not — which is the architecture's
// default and has to stay the default.
//
// ★ SO THIS CHECK DOES NOT REQUIRE A MESH. It requires the deployment to be able to SAY which it is. A
// deployment with no mesh and a deployment whose links are all down refuse the same flow with the same
// message; one is a choice and the other is an incident, and until now nothing distinguished them.
//
// ★ AND IT REPORTS THE SECOND GATE. Links that are up relay nothing unless a destination opts in. A
// deployment with live links and no eligible hosts behaves exactly like one with no links at all, which is
// the other way this reads as a network fault.
func verifyMesh(client *http.Client, edgeAdmins []string) []verifyResult {
	out := []verifyResult{}
	add := func(name string, ok bool, format string, args ...any) {
		out = append(out, verifyResult{name: name, ok: ok, note: fmt.Sprintf(format, args...)})
	}

	type nodeMesh struct {
		url        string
		region     string
		configured bool
		peers      []string
		live       []string
		eligible   int64
	}
	nodes := []nodeMesh{}
	for _, admin := range edgeAdmins {
		admin = strings.TrimRight(strings.TrimSpace(admin), "/")
		if admin == "" {
			continue
		}
		code, raw, err := get(client, admin+"/healthz", "")
		if err != nil || code != 200 {
			continue
		}
		var health struct {
			Role   string `json:"role"`
			Region string `json:"region"`
			Mesh   *struct {
				Configured    bool     `json:"configured"`
				PeerRegions   []string `json:"peer_regions"`
				LiveToRegions []string `json:"live_to_regions"`
				EligibleHosts int64    `json:"eligible_hosts"`
			} `json:"mesh"`
		}
		if json.Unmarshal(raw, &health) != nil || health.Role != "edge" {
			continue
		}
		if health.Mesh == nil {
			// An Edge that does not report this is running a build from before it did. Said rather than
			// skipped: a silent absence here reads as "no mesh", which is one of the two answers.
			add("the deployment says whether it has a data-plane mesh", false,
				"%s does not report its mesh state at all, so which of the two this deployment is could not "+
					"be established", admin)
			return out
		}
		nodes = append(nodes, nodeMesh{url: admin, region: health.Region, configured: health.Mesh.Configured,
			peers: health.Mesh.PeerRegions, live: health.Mesh.LiveToRegions, eligible: health.Mesh.EligibleHosts})
	}
	if len(nodes) == 0 {
		return out
	}

	configured, unconfigured := []string{}, []string{}
	for _, n := range nodes {
		where := n.region
		if where == "" {
			where = n.url
		}
		if n.configured {
			configured = append(configured, where)
		} else {
			unconfigured = append(unconfigured, where)
		}
	}
	sort.Strings(configured)
	sort.Strings(unconfigured)

	// How many regions actually answered. A deployment with one region has nobody to relay to; a deployment
	// with more was given them so that a device in one can reach an asset in another.
	regions := map[string]struct{}{}
	for _, n := range nodes {
		if r := strings.TrimSpace(n.region); r != "" {
			regions[r] = struct{}{}
		}
	}

	switch {
	case len(configured) == 0 && len(regions) > 1:
		// ★★★ THIS WAS A PASS UNTIL 2026-09-01, AND IT SAID "fail-closed, which is the default" (the
		// operator's decision that day: "a three-region build with the mesh missing is a hole; fixing it is
		// required"). Nothing in this installer ever wrote a mesh peer, so EVERY multi-region deployment it
		// built came up without one — and this check described that as a posture. It was an omission wearing
		// a posture, and the check helped it wear one.
		//
		// The real posture still exists and is now written down: a plan carrying "mesh": false means the
		// regions must not relay, and the installer then produces no peers deliberately. That case fails here
		// too, and it should: this check reads the DEPLOYMENT, not the plan, and a reader who meant it can
		// see their own decision named in the failure rather than having it inferred for them.
		add("the deployment says whether it has a data-plane mesh", false,
			"this deployment has %d regions and NO Edge relays to another, so a connector in any region is "+
				"unreachable from every other one. A device that needs one is refused by name. The installer "+
				"derives the peers from the plan; a deployment that means to refuse cross-region flows says "+
				"so with \"mesh\": false in its plan, and this check will still name it",
			len(regions))
	case len(configured) == 0:
		// One region: there is nothing to relay to, and saying so is not the same as having no mesh.
		add("the deployment says whether it has a data-plane mesh", true,
			"this deployment has one region, so there is nowhere to relay to and no mesh to configure")
	case len(unconfigured) > 0:
		// ★ A MESH LINK IS MUTUAL. Half a deployment configured is the shape that looks like a network fault.
		add("the deployment says whether it has a data-plane mesh", false,
			"the mesh is configured on %s and NOT on %s. A link is mutual: the half without peers can neither "+
				"reach nor be reached, and the half with them will log a link that never comes up",
			strings.Join(configured, ", "), strings.Join(unconfigured, ", "))
	default:
		down := []string{}
		// ★ NOT A SUM. The first version added the per-node counts, so one eligible destination on a fleet of
		// four Edges was reported as "4 destination(s) are eligible" — a number that grows with the fleet and
		// describes nothing. The list is meant to be the SAME on every node, so what matters is the value and
		// whether they agree.
		eligible := nodes[0].eligible
		disagree := false
		for _, n := range nodes {
			if n.eligible != eligible {
				disagree = true
			}
			liveSet := map[string]bool{}
			for _, r := range n.live {
				liveSet[r] = true
			}
			for _, want := range n.peers {
				if !liveSet[want] {
					down = append(down, fmt.Sprintf("%s→%s", n.region, want))
				}
			}
		}
		sort.Strings(down)
		switch {
		case len(down) > 0:
			add("the deployment says whether it has a data-plane mesh", false,
				"every Edge has mesh peers, but %d link(s) are NOT up (%s). This refuses exactly the flows an "+
					"unconfigured mesh refuses, so it would otherwise look like the default",
				len(down), strings.Join(down, ", "))
		case disagree:
			// Same shape as an Edge holding a shorter region map: healthy, and quietly serving a different
			// rule from its siblings.
			add("the deployment says whether it has a data-plane mesh", false,
				"the Edges do not agree on how many destinations may cross a region, so which flows mesh "+
					"depends on which Edge a device happens to be served by")
		case eligible == 0:
			// ★★★ THIS CHECK COUNTED A LIST THAT NO LONGER DECIDES (2026-09-01, seen the day after cross-region
			// private access was measured working from a real endpoint). It read the DSSE_MESH_ELIGIBLE_HOSTS
			// entries, found none, and reported "nothing crosses a region and the deployment behaves exactly as
			// if it had no mesh" — while a device in one region was reaching a connector in another, over the
			// mesh, in front of it. A check that fails a working deployment is worse than no check: it teaches
			// its reader to skip past a red line.
			//
			// Eligibility stopped being a hand-kept list of hostnames when connectors got a route layer. A
			// destination the route layer has already resolved to a connector is eligible when this Edge holds a
			// live link to that connector's region — reaching the dialer at all means the destination was
			// chosen. The named list only ADDS to that, for destinations no connector fronts.
			add("the deployment says whether it has a data-plane mesh", true,
				"every Edge's mesh link is up, and a destination a connector fronts crosses to that connector's "+
					"region whenever the link is live, so nothing has to be named by hand. No destination is "+
					"additionally listed in DSSE_MESH_ELIGIBLE_HOSTS")
		default:
			add("the deployment says whether it has a data-plane mesh", true,
				"every Edge's mesh link is up, and all %d Edge(s) allow the same %d destination(s) to cross a "+
					"region", len(nodes), eligible)
		}
	}
	return out
}

// verifyEgressAddressFamily — can the Edges carry what the agents are told to capture?
//
// ★★★ AN AGENT CAPTURES ALL OUTBOUND TCP, IPv6 INCLUDED, AND NOBODY MEASURED WHETHER THE EDGE COULD CARRY IT
// (2026-08-25, reported from a real endpoint with the Edge's own logs as evidence). Over seventeen minutes:
// 572 IPv4 flows carried bytes and none were empty; of 342 IPv6 flows, 185 carried nothing at all. The Edge's
// container network had no IPv6 — `ip -6 addr` showed only ::1 — so every one of those flows arrived, could
// not be egressed, and was closed with zero bytes.
//
// It survived only because applications fall back to IPv4 and because fail-open was on, a posture whose own
// flag says STABILIZATION ONLY. Under the posture this is meant to ship with, an IPv6-only destination is
// simply unreachable and every IPv6 attempt is a wasted round trip. From the operator's chair it reads as
// "somehow slow", which is how it was in fact reported.
//
// ★ THIS DOES NOT REQUIRE IPv6. Plenty of deployments will not have it, and that is a decision. What it
// requires is that the deployment SAY so, because the agent's capture default is the other half of the same
// question and today the two are set independently.
func verifyEgressAddressFamily(client *http.Client, edgeAdmins []string) []verifyResult {
	out := []verifyResult{}
	noV6, unmeasured, total := []string{}, []string{}, 0
	for _, admin := range edgeAdmins {
		admin = strings.TrimRight(strings.TrimSpace(admin), "/")
		if admin == "" {
			continue
		}
		code, raw, err := get(client, admin+"/healthz", "")
		if err != nil || code != 200 {
			continue
		}
		var health struct {
			Role   string `json:"role"`
			Region string `json:"region"`
			Egress *struct {
				IPv4 bool `json:"ipv4"`
				IPv6 bool `json:"ipv6"`
			} `json:"egress_address_family"`
		}
		if json.Unmarshal(raw, &health) != nil || health.Role != "edge" {
			continue
		}
		total++
		where := health.Region
		if where == "" {
			where = admin
		}
		switch {
		case health.Egress == nil:
			unmeasured = append(unmeasured, where)
		case !health.Egress.IPv6:
			noV6 = append(noV6, where)
		}
	}
	if total == 0 {
		return out
	}
	sort.Strings(noV6)
	sort.Strings(unmeasured)
	switch {
	case len(unmeasured) > 0:
		out = append(out, verifyResult{name: "the deployment can carry what the agents capture",
			note: fmt.Sprintf("%d of %d Edge(s) do not report which address families they can egress in (%s), "+
				"so whether they can carry what an agent steers into them was NOT measured",
				len(unmeasured), total, strings.Join(unmeasured, ", "))})
	case len(noV6) == total:
		// ★ THIS USED TO FAIL, AND THE REASON IT NO LONGER DOES IS THAT THE DEPLOYMENT NOW SAYS SO
		// (2026-08-25, decided). An agent captures all outbound TCP; a deployment with no IPv6 leg used to
		// receive every one of those flows and close them with no bytes. The Edges now declare which families
		// they can egress, in the signed posture document, and an agent closes a flow in a family the
		// deployment cannot carry rather than spending a round trip on it — so the application falls back and
		// that flow is steered normally.
		//
		// What remains is a property of where this deployment runs, not a defect: a destination that is
		// IPv6-ONLY cannot be reached through it. That is worth saying every time and is not a failure.
		out = append(out, verifyResult{ok: true, name: "the deployment can carry what the agents capture",
			note: fmt.Sprintf("all %d Edge(s) egress in IPv4 only, and they declare it — agents do not steer "+
				"IPv6 into a deployment that cannot carry it. ★ A destination that is IPv6-ONLY is "+
				"unreachable through this deployment; give the Edges IPv6 egress if that matters here", total)})
	case len(noV6) > 0:
		out = append(out, verifyResult{name: "the deployment can carry what the agents capture",
			note: fmt.Sprintf("%d of %d Edge(s) have no IPv6 egress (%s) while the others do, so whether an "+
				"IPv6 flow works depends on which Edge a device is served by",
				len(noV6), total, strings.Join(noV6, ", "))})
	default:
		out = append(out, verifyResult{ok: true, name: "the deployment can carry what the agents capture",
			note: fmt.Sprintf("all %d Edge(s) can egress in both address families", total)})
	}
	return out
}
