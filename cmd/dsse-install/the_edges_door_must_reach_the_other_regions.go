package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ★★★ AN EDGE'S DOOR TO THE AUTHORITY KNEW ONLY ITS OWN REGION (2026-08-27, measured the first time leadership
// landed elsewhere).
//
// The Edges reach a control plane through a door on their own compose network, and its backend named the two
// control planes on that network and nothing else. So when the leader was in another region, the Edges HERE had
// no route to the authority at all — the walk stopped with "the door the Edges use never routed to a leader",
// and the deployment looked, from that region, exactly like one whose control plane had died.
//
// The canonical says an Edge probes every control plane and takes configuration from whichever region holds
// leadership. The flag-based path does that; this door did not. A deployment with two mechanisms where only one
// crosses a region has a failover that works in a diagram.
//
// ★ THE HEALTH CHECK IS STILL WHAT ROUTES. Adding peers changes nothing about how the door decides: every
// server is checked with GET /leader, exactly one answers 200, and that is where the traffic goes. What changes
// is the size of the set it is allowed to find the leader in.

// controlPlanePeersFile is where a region records the other regions' control planes. Written into
// deployment.env by the operator (or by the walk) as host:port entries.
const controlPlanePeersKey = "DSSE_CP_PEERS"

// databasePeersKey names the deployment's database members that are NOT on this machine.
//
// ★★★ THE DATABASE'S DOOR KNEW ONLY ITS OWN MEMBERS, AND A JOINING REGION HAS NO PRIMARY (2026-08-27,
// measured by installing one). The door routes to whichever member answers 200 to GET /primary. In the region
// that founds the deployment one of them does. In a region that JOINS, both are replicas by definition — the
// deployment has ONE primary and it is somewhere else — so the door has no healthy backend at all, and that
// region's control planes cannot reach the deployment's database:
//
//	open CP-state blob store: ping cp-state blob db: dial tcp 10.117.1.6:5432: connect: connection refused
//
// which reads as a database that is down and is a door that is looking in one region.
//
// This is the same defect the AGENT plane's door had and had fixed: a door that fronts something the
// deployment holds ONCE has to be able to reach it wherever it currently is.
//
// Each entry is host:port:apiport — the address to send traffic to, and the port to ask "are you the primary"
// on, because a member reached across machines publishes both and they are not adjacent by convention.
const databasePeersKey = "DSSE_PG_PEERS"

// controlPlanePeers reads the other regions' control planes from this deployment's environment.
//
// ★ THE DOOR IS A STATIC FILE, so this is read when the file is GENERATED — which means adding a region and
// then repairing is what teaches the existing regions about it. That is stated in the file itself, because a
// door that silently predates a region is the failure this exists to fix, one release later.
func databasePeers(dir string) []string { return peersNamedIn(dir, databasePeersKey) }

func controlPlanePeers(dir string) []string { return peersNamedIn(dir, controlPlanePeersKey) }

func peersNamedIn(dir, controlPlanePeersKey string) []string {
	body, err := os.ReadFile(filepath.Join(dir, "deployment.env"))
	if err != nil {
		return nil
	}
	raw := ""
	for _, line := range strings.Split(string(body), "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, controlPlanePeersKey+"=") {
			raw = strings.Trim(strings.TrimPrefix(t, controlPlanePeersKey+"="), "'\"")
		}
	}
	seen := map[string]bool{}
	var out []string
	for _, part := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ';' || r == ' ' }) {
		part = strings.TrimSpace(part)
		// Tolerate a URL: an operator copying an address from the printed output should not have to strip it.
		part = strings.TrimPrefix(strings.TrimPrefix(part, "https://"), "http://")
		part = strings.TrimSuffix(part, "/")
		if part == "" || seen[part] {
			continue
		}
		seen[part] = true
		out = append(out, part)
	}
	sort.Strings(out)
	return out
}

// peerControlPlaneServers renders the haproxy server lines for the other regions' control planes.
func peerControlPlaneServers(peers []string) string {
	if len(peers) == 0 {
		return "    # (no other region is configured: this deployment holds its authority in one region)\n"
	}
	var b strings.Builder
	for i, p := range peers {
		// ★★★ NO resolvers ON THESE, FOR THE REASON THE DATABASE DOOR CARRIES (2026-08-27). With a resolvers
		// section haproxy will not hand the SAME address to two servers in one backend — it holds the second at
		// "No IP for server" indefinitely. Another region's two control planes are on ONE machine, sharing a
		// name and differing only by port, which is exactly that case: the second peer never comes up, and if
		// leadership is on it this door has no route to the authority at all.
		// ★ name@address: TLS verifies the NAME and the connection goes to the ADDRESS. These lines carry no
		// resolvers, so a bare name is resolved once at start-up inside a container — see the note on
		// PlanMachine.ReachableAddress for what that cost.
		if name, address, found := strings.Cut(strings.TrimPrefix(strings.TrimPrefix(p, "https://"), "http://"), "@"); found {
			fmt.Fprintf(&b, "    server cp-peer-%d %s check check-ssl check-sni %s sni str(%s) verify none\n",
				i+1, address, name, name)
			continue
		}
		fmt.Fprintf(&b, "    server cp-peer-%d %s check check-ssl verify none\n", i+1, p)
	}
	return b.String()
}

// ★★★ AND THE EDGES THEMSELVES ARE ON OTHER MACHINES (2026-08-27, measured the first time this deployment was
// stood up with one component per host).
//
// The region doorway routes agents.<host> to the Edge fleet, and its backend named dsse-edge-a and dsse-edge-b
// — compose service names, which resolve only on the network that defines them. On one host that is every
// service; on the deployment this product is actually sold as, the Edges are separate machines and those names
// reach nothing.
//
// ★ THE DEFAULT IS STILL THE COMPOSE NAMES, because the one-host reference deployment is a real thing that
// must keep working. Naming real hosts is what a per-component install does, and it is an answer the operator
// gives rather than something derived — only they know what the Edges are called.
const edgeBackendsKey = "DSSE_EDGE_BACKENDS"

// The ports an Edge that sits BEHIND a region's front door publishes on its own machine. They are not 443:
// 443 belongs to the doorway, and this machine has none.
const (
	planEdgeBehindDoorAgentPort = 8443
	planEdgeBehindDoorAdminPort = 9443
)

// edgeFleetBackends reads where this region's Edges actually are.
func edgeFleetBackends(dir string) []string { return envList(dir, edgeBackendsKey) }

// envList reads a comma/space separated list from deployment.env, tolerating a URL where a host:port belongs.
func envList(dir, key string) []string {
	body, err := os.ReadFile(filepath.Join(dir, "deployment.env"))
	if err != nil {
		return nil
	}
	raw := ""
	for _, line := range strings.Split(string(body), "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, key+"=") {
			raw = strings.Trim(strings.TrimPrefix(t, key+"="), "'\"")
		}
	}
	seen := map[string]bool{}
	var out []string
	for _, part := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ';' || r == ' ' }) {
		part = strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(part), "https://"), "http://"), "/")
		if part == "" || seen[part] {
			continue
		}
		seen[part] = true
		out = append(out, part)
	}
	sort.Strings(out)
	return out
}

// edgeFleetServers renders the haproxy server lines for this region's Edges.
//
// ★ send-proxy IS KEPT. It is what preserves each device's address through the doorway, and an Edge only
// believes the header from the addresses in -trusted-front-doors — so moving the doorway to its own machine
// means that list has to name it. Dropping send-proxy here would make every device in the region arrive from
// one address, which is a device list saying every machine is in the same place.
//
// ★★★ AND resolve-prefer ipv4 IS THE OTHER HALF OF THAT SENTENCE (2026-08-31, measured on a fresh install
// that failed nine checks with one cause).
//
// -trusted-front-doors expresses trust as ADDRESSES. Once the container network carries IPv6, Docker's DNS
// answers AAAA, haproxy re-resolves the Edges to their v6 addresses, and the doorway's source address becomes
// one the Edge was never told to trust — so the Edge drops every connection the instant it arrives. haproxy
// logs SD, the door presents no certificate to anybody, and every check that needs a device fails at once
// with "EOF". Nothing anywhere names the cause.
//
// This was found and fixed on 2026-08-30 — in frontdoor.go, which renders the control-plane, console and
// database backends. THIS function renders the AGENT plane, in a different file, and was missed. The
// deployment came up with the fix applied to every door a device does not use. See
// TestEveryResolvedBackendPrefersIPv4, which now spans both generators for exactly that reason.
func edgeFleetServers(backends []string) string {
	if len(backends) == 0 {
		// ★ ONE EDGE ON THIS MACHINE. A second Edge for this region lives on ANOTHER machine and is named in
		// DSSE_EDGE_BACKENDS, which is the branch below — that is what makes a region's Edges redundant.
		return "    server edge-a dsse-edge-a:8443 check check-ssl verify none port 9443 send-proxy resolvers containers init-addr last,libc,none resolve-prefer ipv4\n"
	}
	var b strings.Builder
	for i, e := range backends {
		// The health check is on the admin port while traffic goes to the agent one: health is a property of
		// the node, and asking the port that carries traffic would call a busy Edge unhealthy.
		host := e
		if h, _, ok := strings.Cut(e, ":"); ok {
			host = h
		}
		fmt.Fprintf(&b, "    server edge-%d %s check check-ssl verify none port 9443 send-proxy addr %s "+
			"resolvers containers init-addr last,libc,none resolve-prefer ipv4\n", i+1, e, host)
	}
	return b.String()
}

// databaseFrontDoorPeers renders the deployment's database members that are not on this machine, as backends
// of this region's database door.
//
// ★ EMPTY IS THE ORDINARY CASE for a deployment with one region, and the file says so rather than leaving a
// reader to wonder whether something is missing.
func databaseFrontDoorPeers(dir string) string {
	peers := databasePeers(dir)
	if len(peers) == 0 {
		return "    # (no other region is configured: this deployment holds its database in one region)\n"
	}
	out := "    # ★★★ AND THE MEMBERS IN THE OTHER REGIONS. The deployment has ONE primary; in a region that\n" +
		"    # JOINS, both local members are replicas by definition, and a door that knows only them has no\n" +
		"    # backend at all. See " + databasePeersKey + ".\n"
	for i, p := range peers {
		host, port, api := p, "5432", "8008"
		fields := strings.Split(p, ":")
		if len(fields) == 3 {
			host, port, api = fields[0], fields[1], fields[2]
		} else if len(fields) == 2 {
			host, port = fields[0], fields[1]
		}
		// ★★★ NO resolvers ON THESE, AND IT IS NOT AN OVERSIGHT (2026-08-27, measured). With a resolvers
		// section haproxy will not hand the SAME address to two servers in one backend — it holds the second
		// at "No IP for server" forever. Another region's two members are on ONE machine, so they share a
		// name and differ only by port, which is exactly that case: the second peer never came up and the
		// door reported no backend at all while the primary was sitting behind it.
		//
		// ★ Resolved once, by the system resolver, at start-up. These are other regions' addresses: stable by
		// construction, and a region that moves is a restart either way.
		out += fmt.Sprintf("    server pg-peer-%d %s:%s check port %s\n", i+1, host, port, api)
	}
	return out
}

// databaseAndAuthorityNote: see peerControlPlaneDataServers.
//
// ★★★ THE ADMIN PLANE'S DOOR LEARNED TO CROSS A REGION AND THE AUTHORITY'S DID NOT (2026-08-27, measured on a
// two-region deployment whose leader was in the other one). Both backends front the same nodes and both check
// GET /leader, so when leadership moves the LOCAL pair fails that check in both — the admin plane was given
// the other regions' control planes and this one was left with only its own. The Edges here could then READ
// nothing and WRITE nothing to the authority, and what it looked like was:
//
//	FAIL what this Edge records is reaching the authority — shipping to https://authority.<host>/audit-ingest
//	     has been failing since …
//	FAIL blocking a device stops it steering — … could not be blocked: 404
//	FAIL the verification device was removed — … 404. It is enrolled in this deployment …
//
// which is word for word the failure this whole plane exists to prevent, quoted in frontdoor.go's own note
// about why the authority has a name of its own: "a device enrolled through the second region was admitted
// there and unknown to the authority, so blocking it answered 404 and removing it stopped nothing".
//
// ★ THE ENTRIES CARRY BOTH PORTS. Traffic goes to the node's DATA surface and the health check asks its ADMIN
// one, exactly as the local pair does — and across machines those two are published separately, so neither
// can be derived from the other. host:dataport:adminport, like the database peers beside them.
const controlPlaneDataPeersKey = "DSSE_CP_DATA_PEERS"

func controlPlaneDataPeers(dir string) []string { return peersNamedIn(dir, controlPlaneDataPeersKey) }

func peerControlPlaneDataServers(dir string) string {
	// ★★★ AND THE ADDRESS IS THE OTHER REGION'S DOORWAY, NOT A NODE (2026-08-27, measured on a two-region
	// deployment whose leader was in the other one). The mechanism above wanted host:dataport:adminport — a
	// control plane's own published data port — and no deployment publishes one. compose.go says why, in the
	// comment beside the ports it does publish: "publishing one node's own port would hand somebody an
	// address that is right only until a failover". So the authority's door could not cross a region under
	// any supported configuration, and what it looked like on the Edges was
	//
	//	region cp_data_plane/<NOSRV>
	//	tenant_transport_material first fetch failed (Post "https://authority.<host>/tenant-edge-material": EOF)
	//	★ audit ship: FAILING — Post "https://authority.<host>/audit-ingest": EOF
	//
	// while the admin plane beside it was serving happily through the peer it did have.
	//
	// ★ THE OTHER REGION HAS A DOORWAY, ON 443, THAT ALREADY DOES THIS. It reads the same SNI and routes
	// authority.<host> to whichever of ITS control planes leads. The stream is passed through untouched, so
	// the name the client sent is the name that arrives — there is nothing to publish and no node to address.
	//
	// ★★ AND IT CANNOT LOOP BACK. The health check speaks TLS with this name and asks GET /leader: a region
	// that is not leading answers from its own cp_data_plane, which is NOSRV there for the same reason, so
	// the check fails and nothing is forwarded. Only the region that holds leadership is ever a backend.
	peers := controlPlaneDataPeers(dir)
	if len(peers) > 0 {
		// An operator who published per-node data ports anyway is not overruled.
		out := "    # ★★★ AND THE AUTHORITY IN THE OTHER REGIONS, by node, because " + controlPlaneDataPeersKey + "\n" +
			"    # was set. Without a way across, an Edge here cannot ship what it recorded or report an\n" +
			"    # enrolment whenever leadership is elsewhere.\n"
		for i, p := range peers {
			if name, address, found := strings.Cut(strings.TrimPrefix(strings.TrimPrefix(p, "https://"), "http://"), "@"); found {
				// The authority's own surface wants a client certificate, so the CHECK asks for the peer's
				// ADMIN name — the same question, answered without one.
				check := strings.Replace(name, "authority.", "admin.", 1)
				// ★★★ AND THE TRAFFIC CARRIES A NAME TOO, NOT ONLY THE CHECK (2026-08-31, measured on the
				// first three-region deployment). The check asked admin.<region> — the right question, since
				// leadership is answered there — and the forwarded request carried whatever name the client
				// had sent, which is a container alias no front door routes. It landed on the other region's
				// default backend, its Edge fleet, and came back 404: an Edge's enrolments stayed in its
				// outbox with the authority answering "no such route" about a route it serves.
				//
				// ★ THE CHECK'S NAME AND THE TRAFFIC'S NAME ARE DIFFERENT ON PURPOSE. Leadership is a
				// property of the node and is asked on the admin plane; what is being forwarded belongs to
				// the data plane. Two names, one node, and both have to be said.
				//
				// ★★★ AND THE `sni` BELOW DOES NOT TAKE EFFECT HERE (2026-09-01, measured with a control
				// experiment that changed nothing but the SNI). haproxy only rewrites SNI on a server it
				// speaks TLS to — a server line with `ssl` — and this one deliberately has none, because the
				// requests being forwarded carry a CLIENT CERTIFICATE and terminating their TLS would throw
				// it away. So the name that arrives at the far region is still whatever the client dialled.
				//
				// Measured: an Edge asking for its organizations' material through this door reached the far
				// region as "dsse-control-plane", landed on its Edge fleet, and was answered
				//
				//	remote error: tls: unknown certificate authority
				//
				// while the check beside it — which DOES speak TLS, and so does send admin.<region> — went on
				// reporting the peer healthy. Two of three regions signed every flow under the deployment's
				// one shared root for as long as that lasted.
				//
				// ★ SO THE FIX IS NOT IN THIS DOOR. A node that must reach the authority with a client
				// certificate dials the region's OWN address instead of forwarding through here — that is
				// what the data-peers list becomes on an Edge (-config-source-data-endpoints), and it names
				// authority.<region>, which the far doorway serves. The line below stays because the check is
				// real and because forwarding WITHOUT a client certificate does work; it is simply not the
				// path anything mTLS should take.
				out += fmt.Sprintf("    server cp-data-peer-%d %s check check-ssl check-sni %s sni str(%s) verify none\n",
					i+1, address, check, name)
				continue
			}
			host, data, admin := p, "8443", "9443"
			if f := strings.Split(p, ":"); len(f) == 3 {
				host, data, admin = f[0], f[1], f[2]
			} else if len(f) == 2 {
				host, data = f[0], f[1]
			}
			// No resolvers, for the reason the peers above carry: two servers, one name, different ports.
			out += fmt.Sprintf("    server cp-data-peer-%d %s:%s check check-ssl verify none port %s\n", i+1, host, data, admin)
		}
		return out
	}
	doors := peerRegionDoorways(dir)
	if len(doors) == 0 {
		return "    # (no other region is configured: this deployment holds its authority in one region)\n"
	}
	out := "    # ★★★ AND THE AUTHORITY IN THE OTHER REGIONS, reached through each one's own doorway on 443.\n" +
		"    # The stream carries the client's SNI, so that doorway routes it to whichever of ITS control\n" +
		"    # planes leads; a region that is not leading fails the check below and is never forwarded to.\n" +
		"    #\n" +
		"    # ★★★ AND THE CHECK ASKS FOR THE ADMIN NAME, NOT THIS ONE (measured). The authority's\n" +
		"    # surface requires a CLIENT CERTIFICATE — that is the whole point of it — so a health check\n" +
		"    # holding none never finishes the handshake, and the peer reads as\n" +
		"    #\n" +
		"    #\tServer cp_data_plane/cp-data-peer-1 is DOWN, reason: Layer4 timeout\n" +
		"    #\n" +
		"    # on a region that was answering perfectly: its own log showed every probe arriving and being\n" +
		"    # routed. Asking the same address for the ADMIN name reaches that region's admin plane through\n" +
		"    # the same doorway, and admin.<host> answers GET /leader without one. It is the same question —\n" +
		"    # this is the idiom the LOCAL pair already uses, traffic to the data surface and the check on the\n" +
		"    # admin one, and across a doorway the two are one address distinguished by name.\n"
	for i, d := range doors {
		out += fmt.Sprintf("    server cp-data-peer-%d %s check check-ssl check-sni %s verify none\n",
			i+1, d.address, d.check)
	}
	return out
}

// peerRegionDoorway is one other region's front door and the name its health check asks for there.
type peerRegionDoorway struct{ address, check string }

// peerRegionDoorways reads DSSE_REGION_ENDPOINTS — the deployment's regions and the address each answers on,
// the same list every Edge hands its devices — and returns the ones that are not this machine's region.
func peerRegionDoorways(dir string) []peerRegionDoorway {
	env := readDeploymentEnv(dir)
	here := strings.ToLower(strings.TrimSpace(env["DSSE_EDGE_REGION"]))
	authority := strings.TrimSpace(env["DSSE_AUTHORITY_ORIGIN"])
	authority = strings.TrimPrefix(strings.TrimPrefix(authority, "https://"), "http://")
	if i := strings.IndexAny(authority, ":/"); i >= 0 {
		authority = authority[:i]
	}
	if authority == "" {
		return nil
	}
	// The admin plane's name for this deployment, which is the authority's with the first label swapped —
	// both are planeNamesFor(host) on the same host, so this is that pair and not a guess.
	check := planeNamesFor(strings.TrimPrefix(authority, "authority.")).Admin
	out := []peerRegionDoorway{}
	for _, entry := range strings.Split(env["DSSE_REGION_ENDPOINTS"], ";") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		name, address, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(name), here) {
			continue
		}
		// ★★★ THE REGION ENDPOINT NAMES THE AGENT PLANE, AND THE AUTHORITY IS NOT ON IT (2026-08-28, measured
		// on the first deployment with a machine per component). DSSE_REGION_ENDPOINTS is the map DEVICES are
		// handed, so each entry is that region's agent plane — on the EDGE machine. The authority lives on the
		// CONTROL PLANE's machine, behind a different doorway, and pointing this at the endpoint sent every
		// cross-region write to a door that does not serve it:
		//
		//	server cp-data-peer-1 agents.region-b.dsse.lab:443 check-sni admin.dsse.lab
		//
		// On a region that was one machine the two doorways were the same and this was invisible. What is
		// wanted is the peer's AUTHORITY, which is named the way every plane is: <plane>.<region>.<host>.
		regionName := strings.ToLower(strings.TrimSpace(name))
		host := authority
		// ★★★ THE ENDPOINT MAY CARRY THE ADDRESS, AND THEN IT IS USED (2026-08-28). A doorway peer verifies a
		// NAME — that is what check-sni is for — but it still has to CONNECT somewhere, and these lines carry
		// no resolvers on purpose. Written name@address, the connection goes to the address and the check
		// still asks for the name, which is the same idiom -verify takes for a doorway pair.
		if regionName != "" && strings.HasPrefix(authority, "authority.") {
			host = "authority." + regionName + "." + strings.TrimPrefix(authority, "authority.")
		}
		// The endpoint's PORT is still believed: a rendering that publishes its doorway elsewhere says so
		// here, and assuming 443 would health-check a port nothing listens on.
		endpoint := strings.TrimSpace(address)
		endpoint = strings.TrimPrefix(strings.TrimPrefix(endpoint, "https://"), "http://")
		if i := strings.IndexByte(endpoint, '/'); i >= 0 {
			endpoint = endpoint[:i]
		}
		if _, port, err := net.SplitHostPort(endpoint); err == nil && port != "" {
			host += ":" + port
		}
		// ★ THE PORT IN THE ENDPOINT IS KEPT. This list is "the address each region answers on" — the same
		// value handed to every device — so a rendering that publishes its doorway somewhere other than 443
		// says so here, and assuming 443 would health-check a port nothing is listening on. Production folds
		// to 443 and that is what an entry without a port means.
		if host != "" {
			if !strings.Contains(host, ":") {
				host += ":443"
			}
			// The check asks for the peer's ADMIN plane, for the reason above the loop: the authority's
			// surface wants a client certificate and a health check holding none never finishes a handshake.
			peerCheck := check
			if regionName != "" && strings.HasPrefix(check, "admin.") {
				peerCheck = "admin." + regionName + "." + strings.TrimPrefix(check, "admin.")
			}
			out = append(out, peerRegionDoorway{address: host, check: peerCheck})
		}
	}
	return out
}

// readDeploymentEnv reads deployment.env as key -> value, unquoted. It is a sourced shell file of plain
// assignments; nothing here needs a shell, and running one to read a configuration file would be a way to
// execute whatever is in it.
func readDeploymentEnv(dir string) map[string]string {
	out := map[string]string{}
	body, err := os.ReadFile(filepath.Join(dir, "deployment.env"))
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(body), "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		key, value, ok := strings.Cut(t, "=")
		if !ok {
			continue
		}
		out[strings.TrimSpace(key)] = strings.Trim(strings.TrimSpace(value), "'\"")
	}
	return out
}

// endpointAddress reads the ADDRESS out of a region endpoint written name@address, and "" from one that is
// only a name. See peerRegionDoorways: the peer is verified by name and reached at an address, because the
// server lines here resolve nothing at run time.
func endpointAddress(endpoint string) string {
	endpoint = strings.TrimSpace(endpoint)
	endpoint = strings.TrimPrefix(strings.TrimPrefix(endpoint, "https://"), "http://")
	if i := strings.IndexByte(endpoint, '/'); i >= 0 {
		endpoint = endpoint[:i]
	}
	_, address, found := strings.Cut(endpoint, "@")
	if !found {
		return ""
	}
	return strings.TrimSpace(address)
}
