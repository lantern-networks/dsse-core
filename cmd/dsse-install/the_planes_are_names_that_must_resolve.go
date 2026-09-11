package main

import (
	"fmt"
	"net"
	"strings"
)

// the_planes_are_names_that_must_resolve.go — a deployment is reached by NAME, and the names have to exist.
//
// ★★★ FOUND BY BUILDING ONE AND TRYING TO USE IT (2026-08-26). The architecture separates the planes by name
// rather than by port — deliberately, because a corporate network that blocks a non-standard port blocks it
// for administrators too. So the front door routes on the SNI a client asked for, and a client that cannot
// RESOLVE that name never gets far enough to present it.
//
// Every plane's name is derived from the deployment's own: admin.<host>, agents.<host>, console.<host>,
// authority.<host>, recovery.<host>. Measured on a freshly minted deployment whose host was a real,
// resolvable machine name:
//
//	shinmac-mini.tail04460b.ts.net            -> 100.72.135.18
//	admin.shinmac-mini.tail04460b.ts.net      -> NO RESOLUTION
//	agents.shinmac-mini.tail04460b.ts.net     -> NO RESOLUTION
//	console.shinmac-mini.tail04460b.ts.net    -> NO RESOLUTION
//	authority.shinmac-mini.tail04460b.ts.net  -> NO RESOLUTION
//	recovery.shinmac-mini.tail04460b.ts.net   -> NO RESOLUTION
//
// The deployment was correct and unreachable. Nothing in the installer's output said that these DNS records
// are a prerequisite, so the operator discovers it as a connection failure with no name on it — or, worse,
// does not discover it, because a single-machine lab papers over it: *.localhost resolves by itself, and
// curl --resolve hides it from whoever is testing.
//
// ★ IT REPORTS AND DOES NOT REFUSE. The names may be created after the deployment is minted, and often are
// — the certificates are already issued for them, which is the point. What must not happen is somebody
// reaching the end of the procedure without being told.

// planeNamesToResolve are the names this deployment answers on, derived exactly as the environment file
// derives them.
func planeNamesToResolve(host string) []string {
	host = strings.TrimSpace(host)
	if host == "" {
		return nil
	}
	p := planeNamesFor(host)
	return []string{p.Admin, p.Agents, p.Console, p.Authority, p.Recovery}
}

// planeNameDoor says WHICH machine each name belongs on, for a deployment whose components are not all on
// one host.
//
// ★★★ "POINT EVERY ONE AT THIS DEPLOYMENT'S FRONT DOOR" IS ONE INSTRUCTION AND THERE ARE TWO DOORS
// (2026-08-27, measured on the AWS lab). With a machine per component, the doorway in front of the control
// plane and the doorway in front of the Edges are different machines, and the sentence above does not say
// which. Four of the five names were guessed right because their plane is obvious from the name. The fifth
// is not: recovery is the AGENT plane under another name — the renewal endpoint is served on the agent port
// — and it was put with admin and console, where it reached a front door that has no Edges behind it. See
// verify_the_way_back_reaches_the_agent_plane.go.
func planeNameDoor(host, name string) string {
	p := planeNamesFor(host)
	switch strings.ToLower(name) {
	case strings.ToLower(p.Agents), strings.ToLower(p.Recovery):
		return "the doorway in front of this region's EDGES"
	default:
		return "the doorway in front of the CONTROL PLANE"
	}
}

// unresolvedPlaneNames is which of them this machine cannot resolve right now.
func unresolvedPlaneNames(host string, lookup func(string) ([]net.IP, error)) []string {
	if lookup == nil {
		lookup = net.LookupIP
	}
	out := []string{}
	for _, n := range planeNamesToResolve(host) {
		if addrs, err := lookup(n); err != nil || len(addrs) == 0 {
			out = append(out, n)
		}
	}
	return out
}

// reportPlaneNameResolution says what has to exist before this deployment can be reached.
func reportPlaneNameResolution(host string) {
	missing := unresolvedPlaneNames(host, nil)
	if len(missing) == 0 {
		return
	}
	fmt.Printf("\n  ★★★ THESE NAMES DO NOT RESOLVE FROM THIS MACHINE, AND THIS DEPLOYMENT IS REACHED BY NAME:\n")
	for _, n := range missing {
		fmt.Printf("        %-40s %s\n", n, planeNameDoor(host, n))
	}
	fmt.Printf("  The planes are separated by NAME, not by port — one address, one port, and the front door\n")
	fmt.Printf("  routes on the name the client asked for. A client that cannot resolve one of these never\n")
	fmt.Printf("  reaches the plane behind it, and the failure carries no hint that DNS is what is missing.\n")
	fmt.Printf("  The certificates are already issued for them, so creating the records is all that is left:\n")
	fmt.Printf("  point each one at the doorway named beside it.\n")
	fmt.Printf("  ★★★ %s IS THE AGENT PLANE UNDER ANOTHER NAME. It is what an agent sends when the\n", planeNamesFor(host).Recovery)
	fmt.Printf("  certificate it holds has EXPIRED, and the renewal endpoint that answers it is served on the\n")
	fmt.Printf("  agent port — so it belongs with %s and not with the administrative names. Put it\n", planeNamesFor(host).Agents)
	fmt.Printf("  with them and the only devices that ever send it — the ones already locked out — arrive at a\n")
	fmt.Printf("  door with no Edge behind it, and no healthy device in the fleet ever touches it to say so.\n")
	fmt.Printf("  ★ On one machine, containers can be told instead: set DSSE_HOST_ALIAS_1..4 in\n")
	fmt.Printf("  deployment.env, e.g. DSSE_HOST_ALIAS_1=\"admin.%s:host-gateway\".\n", host)
}
