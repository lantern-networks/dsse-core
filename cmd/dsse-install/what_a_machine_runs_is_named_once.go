package main

import "strings"

// ★★★ THE SERVICES A MACHINE RUNS ARE NAMED IN ONE PLACE (2026-09-02, after the operator asked "you removed a
// lot of services — are you sure there is no effect? shouldn't you check that it runs?").
//
// Retiring the second Edge and the second control plane on a machine broke four places that had each written
// the pair out as literals, and every one of them failed differently:
//
//   - the printed install order restarted `dsse-control-plane-b dsse-edge-b`, which is an error rather than a
//     partial success, so the operator following the procedure stops with the break-glass credential armed;
//   - the per-node admin doors rendered a haproxy backend whose name resolves to nothing;
//   - -verify asked every region for an edge-b.admin door and a control-plane-b.admin door that no longer
//     exist — a deployment reported as broken because the CHECK was stale;
//   - and the test guarding the restart demanded a service the deployment no longer defines, while a NEW
//     Edge would have slipped past it unnamed.
//
// A list written down in four places is four chances to describe a deployment that no longer exists. These
// are the names, and composeDefinesExactlyTheseNodes_test ties them to what the compose file actually
// renders, so adding an Edge back is one edit and the rest follows.
var (
	// edgeNodeNames are the Edges a machine that holds "edges" runs.
	edgeNodeNames = []string{"edge-a"}
	// controlPlaneNodeNames are the control planes a machine that holds a control plane runs. There is one:
	// a second beside it, behind a local haproxy, is not redundancy — it dies with the machine, and the
	// operator retired that shape.
	controlPlaneNodeNames = []string{"control-plane-a"}
)

// composeServicesFor turns node names into the compose service names that run them.
func composeServicesFor(nodes []string) []string {
	out := make([]string, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, "dsse-"+n)
	}
	return out
}

func composeServiceList(nodes ...[]string) string {
	var all []string
	for _, n := range nodes {
		all = append(all, composeServicesFor(n)...)
	}
	return strings.Join(all, " ")
}
