package main

import (
	"fmt"
	"net"
	"sort"
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

// ★★★ A PLAN'S CLIENTS USE THE REGION'S NAMES (2026-11-04, found by installing docs/plans/single-region.json
// from the published 0.4.0 images). The report above derives admin.<deployment>, agents.<deployment> … from the
// deployment's own name, while -order, -bootstrap-admin and the device profile use the region's names
// (admin.region-a.<deployment>, agents.region-a.<deployment> …). A reader who created the records the mint
// asked for still could not run the next printed command. The Console is the exception: it dials
// admin.<deployment> and <node>.admin.<deployment>, and its container is given those at the doorway on its own
// machine (consoleUpstreamNames), so they are not names a reader has to create. When the deployment comes from a plan, say the
// names its clients actually dial, who dials each, and the address that answers for it.
type planClientName struct {
	Name, Who, Address string
}

func planNamesClientsUse(p *Plan) []planClientName {
	if p == nil {
		return nil
	}
	// ★ FROM THE FUNCTIONS THAT GENERATE THE DOORS (2026-11-04). The first version listed
	// agents.<region>.<deployment> for every plan. A one-region three-node plan hands its devices
	// agents.<node>.<deployment>, and the multi-edge plans send browsers to Portal names; a reader who created
	// only the printed names could not enrol a device or finish a sign-in. The agent doors are now read from
	// RegionEndpoints() and the Portal names from BrowserPortalNames(), which are what the profiles carry.
	out := []planClientName{}
	seen := map[string]bool{}
	add := func(name, who, at string) {
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" || seen[name] {
			return
		}
		seen[name] = true
		out = append(out, planClientName{name, who, at})
	}
	regionDoor := func(r PlanRegion) string {
		for _, m := range r.Machines {
			if m.Holds.has("control-plane") && len(m.Addresses) > 0 {
				return strings.TrimSpace(m.Addresses[0])
			}
		}
		return ""
	}
	regionOf := map[string]PlanRegion{}
	for _, r := range p.Regions {
		for _, m := range r.Machines {
			regionOf[strings.ToLower(strings.TrimSpace(m.Name))] = r
		}
	}
	nodeAddress := func(m PlanMachine) string {
		if len(m.Addresses) > 0 {
			return strings.TrimSpace(m.Addresses[0])
		}
		return m.reachableAt()
	}
	for _, r := range p.Regions {
		planes := p.PlaneNamesFor(r.ID)
		door := regionDoor(r)
		add(planes["admin"], "this machine (-bootstrap-admin, -verify) and administrators' tools", door)
		add(planes["authority"], "the deployment's own machines", door)
		add(planes["console"], "the administrator's browser", door)
	}
	// The doors devices and connectors are given, exactly as the profile carries them.
	for _, entry := range strings.Split(p.RegionEndpoints(), ";") {
		region, url, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		host := strings.TrimPrefix(strings.TrimSpace(url), "https://")
		at := ""
		for _, r := range p.Regions {
			if !strings.EqualFold(strings.TrimSpace(r.ID), region) {
				continue
			}
			at = regionDoor(r)
			for _, m := range r.Machines {
				if strings.EqualFold(host, "agents."+strings.TrimSpace(m.Reachable)) {
					at = nodeAddress(m)
				}
			}
		}
		add(host, "devices and connectors (the transport in their profile)", at)
	}
	// The browser's sign-in pages, where the plan has them.
	for _, m := range p.machines() {
		r := regionOf[strings.ToLower(strings.TrimSpace(m.Name))]
		if m.Portal != "" {
			at := regionDoor(r)
			if m.Holds.has("control-plane") {
				at = nodeAddress(m)
			}
			add(m.Portal, "the user's browser during sign-in (the step-up portal)", at)
		}
		if p.dedicatedMultiEdge() && m.Holds.has("edges") {
			add(p.edgePortalName(m), "the user's browser during sign-in (the step-up portal)", regionDoor(r))
		}
	}
	shared := nodeAddress(p.sharedEntryMachine())
	if len(p.Regions) > 0 {
		add(planeNamesFor(p.Deployment).Recovery, "devices whose certificate has expired (an agent-plane name)", shared)
		// ★ AND THE DEPLOYMENT-WIDE AGENT NAME (2026-11-04, found by following this report on a fresh single-machine
		// install). -verify's way-back check states where recovery must point by resolving agents.<deployment>; a
		// reader who created only the region names saw that check fail with "does not resolve".
		add(planeNamesFor(p.Deployment).Agents, "-verify (the agent-plane name the way-back check compares recovery with)", shared)
		// ★ AND THE DEPLOYMENT-WIDE CONSOLE NAME (0.4.1 final acceptance A, 2026-11-09). Every deployment's
		// ADMIN_CONSOLE_ORIGIN is https://console.<deployment>, and the Console's own links are built on it — the
		// invitation an administrator is sent, and where a sign-in returns. The multi-region plans listed it through
		// their client-hosts rendering; the single-region plan did not, so the invited administrator's link went to
		// a name nobody had been told to create, and the walk added it to hosts by hand.
		add(planeNamesFor(p.Deployment).Console, "the administrator's browser (the links the Console sends: invitations, sign-in returns)", shared)
	}
	for _, m := range p.machines() {
		if n := strings.TrimSpace(m.Reachable); n != "" {
			add(n, "the deployment's own machines", m.reachableAt())
		}
	}
	// ★ THE ADDRESSES OF THE PLANS THAT HAVE A CLIENT-HOSTS RENDERING ARE ITS ADDRESSES (2026-11-04).
	// With shared_entry_machine moved to another machine, this report kept putting the shared names
	// on the founding control plane while -client-hosts, and the check that validates it, put them on the chosen
	// entry. The multi-edge and one-region three-node plans now take every name and its owner from the same
	// functions RenderClientHosts uses. Where the plan declares a shared region entry, whose address it does not
	// carry, the report names the entry instead of an address.
	rendered := p.clientHostsAddresses()
	renderedNames := make([]string, 0, len(rendered))
	for name := range rendered {
		renderedNames = append(renderedNames, name)
	}
	sort.Strings(renderedNames)
	for _, name := range renderedNames {
		at := rendered[name]
		if !seen[name] {
			add(name, whoDialsName(p, name), at)
			continue
		}
		for i := range out {
			if out[i].Name == name {
				out[i].Address = at
			}
		}
	}
	return out
}

// sharedRegionEntryAddress stands for the address of a declared shared region entry, which the plan does not
// carry: the operator gives it to -client-hosts as -entry-ip.
const sharedRegionEntryAddress = "<region entry>"

// clientHostsAddresses is the name -> address map RenderClientHosts would write for this plan with the plan's own
// addresses — or, for a one-region three-node plan with a declared shared entry, with that entry — and nil for
// plans that have no client-hosts rendering.
func (p *Plan) clientHostsAddresses() map[string]string {
	addressOf := func(m PlanMachine) string {
		if len(m.Addresses) > 0 {
			return strings.TrimSpace(m.Addresses[0])
		}
		return m.reachableAt()
	}
	shared := addressOf(p.sharedEntryMachine())
	out := map[string]string{}
	switch {
	case p.dedicatedMultiEdge():
		for name, owner := range p.threeRegionClientNameOwners() {
			at := shared
			if owner != "" {
				if _, m, ok := p.find(owner); ok {
					at = addressOf(m)
				}
			}
			out[strings.ToLower(name)] = at
		}
	case p.oneRegionThreeNodes():
		names, err := p.ClientHostNames(nil)
		if err != nil {
			return nil
		}
		// ★ A SHARED REGION ENTRY PUTS EVERY NAME ON IT (2026-11-04). With regions[0].entry
		// declared, RenderClientHosts(entryIP, nil) writes every name on the entry the operator names with
		// -entry-ip, which the plan does not carry. Listing the per-Node addresses here sent devices past the only
		// address a shared-entry layout exposes.
		if p.Regions[0].Entry != nil {
			for _, name := range names {
				out[strings.ToLower(name)] = sharedRegionEntryAddress
			}
			return out
		}
		own := map[string]string{}
		for _, m := range p.Regions[0].Machines {
			at := addressOf(m)
			own[strings.ToLower(m.Reachable)] = at
			own[strings.ToLower(m.Portal)] = at
			own["agents."+strings.ToLower(strings.TrimSpace(m.Reachable))] = at
			for _, target := range p.nodeAdminTargets() {
				if target.Machine == m.Name {
					own[strings.ToLower(target.Label+".admin."+p.Deployment)] = at
				}
			}
		}
		for _, name := range names {
			name = strings.ToLower(name)
			at := shared
			if o := own[name]; o != "" {
				at = o
			}
			out[name] = at
		}
	default:
		return nil
	}
	return out
}

// whoDialsName says who uses a name the client-hosts rendering adds beyond the region planes.
func whoDialsName(p *Plan, name string) string {
	for _, portal := range p.BrowserPortalNames() {
		if strings.EqualFold(portal, name) {
			return "the user's browser during sign-in (the step-up portal)"
		}
	}
	switch {
	case strings.EqualFold(name, p.Deployment):
		return "the deployment's shared entry"
	case strings.HasPrefix(name, "agents."):
		return "devices and connectors"
	case strings.HasPrefix(name, "recovery."):
		return "devices whose certificate has expired (an agent-plane name)"
	case strings.HasPrefix(name, "console."):
		return "the administrator's browser"
	case strings.HasPrefix(name, "authority."):
		return "the deployment's own machines"
	case strings.HasPrefix(name, "admin.") || strings.Contains(name, ".admin."):
		return "administrators' tools and -verify"
	}
	return "the deployment's own machines"
}

func reportPlanNameResolution(p *Plan) {
	names := planNamesClientsUse(p)
	if len(names) == 0 {
		return
	}
	fmt.Printf("\n  ★★★ THIS DEPLOYMENT IS REACHED BY NAME. Make these resolve where each is used:\n")
	for _, n := range names {
		fmt.Printf("        %-44s -> %-15s %s\n", n.Name, n.Address, n.Who)
	}
	fmt.Printf("  The addresses are the plan's. Behind NAT, use the address each client actually reaches.\n")
	for _, n := range names {
		if n.Address == sharedRegionEntryAddress {
			fmt.Printf("  ★ %s is this plan's shared region entry: every name above goes on its address. Give that\n", sharedRegionEntryAddress)
			fmt.Printf("  address to dsse-install -client-hosts -entry-ip to write the hosts block.\n")
			break
		}
	}
	if len(p.machines()) == 1 {
		fmt.Printf("  ★ ON ONE MACHINE the containers are already told: DSSE_HOST_ALIAS_1..4 in deployment.env point the\n")
		fmt.Printf("  names they use at %s. This machine's own resolver, the administrator's computer and the devices\n", names[0].Address)
		fmt.Printf("  still need DNS records or hosts entries.\n")
	}
	fmt.Printf("  ★ A Windows hosts file reads at most nine names on one line; put longer lists on several lines.\n")
}
