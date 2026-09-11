package main

import (
	"fmt"
	"net/http"
	"strings"
)

// verify_connectors_reach_the_edges.go — an Edge can only route to a connector it knows about.
//
// ★★★ AN EDGE KNOWS ONLY THE CONNECTORS THAT REGISTERED WITH IT (2026-08-25, measured while walking one flow
// from a device to a destination fronted by a connector in another region). A connector registers with ONE
// Edge; the others never hear of it. The connector-aware dialer resolves a destination by asking which
// connector fronts it, against the NODE-LOCAL registry — so an Edge that has not heard of the connector cannot
// resolve the destination, dials it directly, and fails. The mesh is consulted only AFTER that resolution, so
// it is never reached at all: a deployment can have a live mesh, a live connector, an authored and routable
// binding, and still carry nothing.
//
// The authority holds the whole set (its registry is the deployment's database). This check compares each
// Edge's answer against it and NAMES what is missing, because "the private app is unreachable" is otherwise
// indistinguishable from a network fault, a policy denial, or a dead connector.

// verifyConnectorsReachTheEdges compares each Edge's connector set against the authority's.
func verifyConnectorsReachTheEdges(client *http.Client, cpAdmin string, edgeAdmins []string, token string) []verifyResult {
	out := []verifyResult{}
	add := func(ok bool, format string, args ...any) {
		out = append(out, verifyResult{name: "the Edges can route to the deployment's connectors", ok: ok,
			note: fmt.Sprintf(format, args...)})
	}
	// ★ ONCE PER ORGANIZATION — connectors belong to customer organizations and this check holds the
	// deployment administrator's token. See the_deployments_connectors_are_not_the_operators.go.
	organizations := organizationsOfTheDeployment(client, cpAdmin, token)
	ask := func(base string) ([]string, error) {
		ids, answered := connectorsForEveryOrganization(client, base, token, organizations)
		if !answered {
			return nil, fmt.Errorf("%s did not answer", base)
		}
		return ids, nil
	}

	authority, err := ask(cpAdmin)
	if err != nil {
		add(false, "the authority could not be asked which connectors this deployment has: %v", err)
		return out
	}
	if len(authority) == 0 {
		// ★★★ SAME CORRECTION AS THE REGISTRY CHECK BESIDE THIS ONE (2026-08-26). A deployment nobody has
		// added a connector to has no private access to lose, and reporting that as a failure means no fresh
		// install can ever be all-green — so the operator following the printed procedure is told to fix
		// something that is not wrong. The dangerous case is the authority holding connectors the Edges
		// cannot see, and that is measured below, unchanged.
		add(true, "no connector has been added to this deployment yet, so there is no private access for the "+
			"Edges to be missing. This becomes a real measurement the moment one is registered")
		return out
	}

	for _, edge := range edgeAdmins {
		edge = strings.TrimRight(strings.TrimSpace(edge), "/")
		if edge == "" {
			continue
		}
		known, err := ask(edge)
		if err != nil {
			add(false, "%v — an Edge that cannot be asked cannot be shown to reach anything", err)
			return out
		}
		have := map[string]bool{}
		for _, id := range known {
			have[id] = true
		}
		missing := []string{}
		for _, id := range authority {
			if !have[id] {
				missing = append(missing, id)
			}
		}
		if len(missing) > 0 {
			add(false, "%s cannot see %d of the deployment's %d connector(s) (%s) — a destination fronted by "+
				"one of them is dialled DIRECTLY from this Edge and fails, and the mesh is never reached "+
				"because it is only consulted after the destination resolves to a connector",
				edge, len(missing), len(authority), strings.Join(missing, ", "))
			return out
		}
	}
	add(true, "all %d Edge(s) see every one of the deployment's %d connector(s)", len(edgeAdmins), len(authority))
	return out
}
