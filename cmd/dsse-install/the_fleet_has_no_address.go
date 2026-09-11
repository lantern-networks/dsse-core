package main

// the_fleet_has_no_address.go — the questions that are about NODES, asked at addresses production has not got.
//
// ★★★ EVERY MOUTH OF A DEPLOYMENT IS 443, AND THE PLANES ARE SEPARATED BY NAME RATHER THAN BY NUMBER. That
// is deliberate: an administrator arrives through the same corporate proxy a device does, and a non-standard
// port is where they both stop. So the admin API's production form is 443 under a different host name, not a
// second port — and the port numbers a lab publishes so several components can share one machine are a
// substitution for that, never the shape itself.
//
// ★★★ AND THE FRONT DOOR THIS INSTALLER GENERATES PRESENTS FOUR NAMES, NONE OF WHICH NAMES A NODE. It routes
// admin. / authority. / console. by SNI and everything else to the Edge fleet; the admin name goes to
// WHICHEVER control plane holds leadership, which is the whole point of it (frontdoor.go). So there is no
// name, anywhere in a deployment built the way the canonical describes, that reaches control plane A rather
// than B, or Edge A rather than Edge B.
//
// ★★★ BUT HALF OF -verify IS ABOUT EXACTLY THAT. These are fleet questions, and each one exists because a
// deployment that answers them from ONE node looks complete and is not:
//
//	more than one control-plane process is running     (through a door, one and two look the same)
//	exactly one control plane is the leader
//	every Edge hands devices the same region map        (an Edge missed when a region was added is healthy)
//	every node runs the same build                      (a node on yesterday's build reads as a product defect)
//	the deployment inspects, under ONE authority        (a fleet where each Edge invented a root looks fine)
//	the canonical log survives a restart                (per node, on that node's disk)
//
// They are asked through -edge-admin and -control-plane-peers, which take per-node URLs. On the AWS lab those
// are 9443/9444 on the Edge machine and 9543/9544 on the control plane's — ports behind the door, published
// on the deployment's own private network. That is the same substitution a single-machine lab makes on a
// container network, moved onto a private network between machines, and it is NOT what production presents.
//
// ★★ SO A GREEN -verify SAYS LESS THAN IT LOOKS LIKE IT SAYS. It says the fleet is consistent when reached at
// addresses the deployment does not offer. Nothing is wrong with the deployment and nothing is wrong with the
// answers; what is missing is that the reader is not told which addresses the answers came from.
//
// ★ WHAT THIS FILE DOES NOT DO is invent a per-node name. Whether a deployment should present one — 443 under
// something like <node>.admin.<host>, routed by SNI to that node and to no other — is an architecture
// decision, and inventing it here would put a fifth and sixth name into every certificate on the strength of
// a check wanting somewhere to point. It is written down instead, and reported at the moment it matters.

import (
	"fmt"
	"net/url"
	"strings"
)

// verifyTheFleetWasAskedWhereProductionAnswers reports which addresses the per-node questions were asked at.
func verifyTheFleetWasAskedWhereProductionAnswers(edgeAdmins []string, cpPeers string) []verifyResult {
	const name = "the fleet was asked where production answers"

	perNode := []string{}
	perNode = append(perNode, edgeAdmins...)
	for _, p := range strings.Split(cpPeers, ",") {
		if p = strings.TrimSpace(p); p != "" {
			perNode = append(perNode, p)
		}
	}
	if len(perNode) == 0 {
		return nil
	}
	offDoor := []string{}
	for _, raw := range perNode {
		u, err := url.Parse(strings.TrimRight(strings.TrimSpace(raw), "/"))
		if err != nil {
			continue
		}
		port := u.Port()
		if port == "" && u.Scheme == "https" {
			port = "443"
		}
		if port != "443" {
			offDoor = append(offDoor, raw)
		}
	}
	if len(offDoor) == 0 {
		return []verifyResult{{ok: true, name: name, note: fmt.Sprintf(
			"all %d per-node address(es) are on 443, which is where this deployment presents everything", len(perNode))}}
	}
	return []verifyResult{{name: name, note: fmt.Sprintf(
		"%d of %d per-node address(es) are NOT on 443: %s. Every mouth of this deployment is 443 and the "+
			"planes are separated by NAME, and the front door presents four names, none of which names an "+
			"individual node — so the fleet questions above (is more than one control plane running, does "+
			"every Edge hand devices the same region map, does every node run the same build) were answered "+
			"at addresses this deployment does not offer to anyone. The answers are true of the nodes; they "+
			"are not evidence that a fleet can be asked these questions as deployed. Naming an individual "+
			"node on 443 is an architecture decision this check deliberately does not make",
		len(offDoor), len(perNode), strings.Join(offDoor, ", "))}}
}
