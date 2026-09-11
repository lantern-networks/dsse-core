package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// verify_control_channel.go — the multi-region install order's control-plane failover step: can an Edge still be reached by the authority when the region that
// currently holds it is gone?
//
// ★★★ THE INSTALLER NAMED THIS STEP AND PRODUCED NOTHING FOR IT EITHER (2026-08-25). Every Edge it generated
// took a single -config-source-url. The deployment has ONE leader, wherever the Postgres primary is, so losing
// that region does not mean "the control plane is down for a while" — it means an Edge pointed at it has
// nowhere to ask, keeps serving what it last applied, and reports healthy while doing it. There is no
// symptom: the enforcement it already has goes on working, and everything authored from then on never
// arrives.
//
// The launch script now emits -config-source-endpoints when DSSE_CP_ENDPOINTS is set, and the Edge reports
// what it ended up with. This reads that.
//
// ★ IT DOES NOT REQUIRE FAILOVER. A single-region deployment cannot have it and is not wrong. What it
// requires is that the deployment SAYS which shape it is — because "one control plane" and "four" look
// identical right up to the moment it matters, and the difference is a decision somebody should make on
// purpose rather than discover.
func verifyControlChannel(client *http.Client, edgeAdmins []string) []verifyResult {
	out := []verifyResult{}
	add := func(name string, ok bool, format string, args ...any) {
		out = append(out, verifyResult{name: name, ok: ok, note: fmt.Sprintf(format, args...)})
	}

	type nodeChannel struct {
		url      string
		region   string
		failover bool
		regions  []string
		state    string
		// deploymentRegions is how many regions this node hands its DEVICES. A deployment that has more than
		// one region and gives its Edges one control-plane address has made a decision it probably did not
		// mean to; a single-region one has not.
		deploymentRegions int
	}
	nodes := []nodeChannel{}
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
			Role           string   `json:"role"`
			Region         string   `json:"region"`
			Regions        []string `json:"region_endpoints"`
			ControlChannel *struct {
				Failover bool     `json:"failover"`
				Regions  []string `json:"regions"`
				State    string   `json:"state"`
			} `json:"control_channel"`
		}
		if json.Unmarshal(raw, &health) != nil || health.Role != "edge" {
			continue
		}
		if health.ControlChannel == nil {
			add("the deployment says whether its control channel survives a region", false,
				"%s does not report where it takes configuration from, so this could not be established", admin)
			return out
		}
		nodes = append(nodes, nodeChannel{url: admin, region: health.Region,
			failover: health.ControlChannel.Failover, regions: health.ControlChannel.Regions,
			state: health.ControlChannel.State, deploymentRegions: len(health.Regions)})
	}
	if len(nodes) == 0 {
		return out
	}

	fixed, disconnected := []string{}, []string{}
	regionsSeen := map[string]bool{}
	for _, n := range nodes {
		where := n.region
		if where == "" {
			where = n.url
		}
		if !n.failover {
			fixed = append(fixed, where)
			continue
		}
		for _, r := range n.regions {
			regionsSeen[r] = true
		}
		// "connected" is the selector's word for "pulling from a region that answered /leader 200". Anything
		// else means this node is running on what it last applied.
		if !strings.EqualFold(n.state, "connected") {
			disconnected = append(disconnected, where+" ("+n.state+")")
		}
	}
	sort.Strings(fixed)
	sort.Strings(disconnected)
	known := make([]string, 0, len(regionsSeen))
	for r := range regionsSeen {
		known = append(known, r)
	}
	sort.Strings(known)

	multiRegion := false
	for _, n := range nodes {
		if n.deploymentRegions > 1 {
			multiRegion = true
		}
	}

	switch {
	case len(fixed) == len(nodes) && !multiRegion:
		add("the deployment says whether its control channel survives a region", true,
			"every Edge takes configuration from ONE control-plane address. This deployment has one region, "+
				"so there is nowhere else leadership could be; set DSSE_CP_ENDPOINTS on every region once "+
				"there is more than one")
	case len(fixed) == len(nodes):
		// ★ THE ONE THIS DEPLOYMENT IS IN. More than one region, and every Edge pointed at a single
		// control-plane address — so losing the region that answers it takes the control channel of the
		// WHOLE deployment, including the Edges that are still running perfectly well somewhere else.
		add("the deployment says whether its control channel survives a region", false,
			"this deployment spans more than one region and every Edge takes configuration from ONE "+
				"control-plane address. Losing the region that answers it leaves every Edge — in every "+
				"region — serving what it last applied, with nowhere to ask and nothing to show for it. Set "+
				"DSSE_CP_ENDPOINTS to the per-region list, which needs a control plane in more than one "+
				"region to be worth setting")
	case len(fixed) > 0:
		// ★ THE HALF-CONFIGURED SHAPE. The Edges that were missed are the ones that go quiet, and they are
		// the ones nobody looks at, because the others are fine.
		add("the deployment says whether its control channel survives a region", false,
			"%d Edge(s) can follow leadership to another region and %d cannot (%s). The ones that cannot are "+
				"the ones that go silent when a region is lost, and nothing else about them will look wrong",
			len(nodes)-len(fixed), len(fixed), strings.Join(fixed, ", "))
	case len(disconnected) > 0:
		add("the deployment says whether its control channel survives a region", false,
			"every Edge has a control-plane list across %s, but %d is not currently pulling from any of them "+
				"(%s) — it is running on what it last applied",
			strings.Join(known, ", "), len(disconnected), strings.Join(disconnected, ", "))
	default:
		add("the deployment says whether its control channel survives a region", true,
			"every Edge probes %d region(s) for leadership (%s) and is pulling from the one that holds it",
			len(known), strings.Join(known, ", "))
	}
	return out
}
