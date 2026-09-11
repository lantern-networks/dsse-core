package main

// plan_environment.go — the values each machine needs, derived from the plan rather than typed on it.
//
// ★★★ EVERY ENTRY HERE WAS ONCE SET BY HAND, AND EVERY ONE WAS A DEFECT WHEN IT WAS WRONG (2026-08-28, from
// standing up two real sites). The failures were silent in the way that matters: a machine that named another
// machine's address, a region that called itself by the name of the one it was packed from, two database
// members claiming one name, a region map whose two entries pointed at the same place. None of it was unknown
// when the deployment was decided. It is derived now.

import (
	"fmt"
	"sort"
	"strings"
)

// The ports a control-plane machine publishes its state and consensus on — the compose file's own defaults.
// Naming them here is what lets one region address another's.
const (
	planEtcdPortA = 12379
	planEtcdPortB = 12380
	planEtcdPortC = 12381
	// ★ WHERE MEMBERS GOSSIP. Clients use the ports above; members use this one, and until it was published
	// a member in another region could be told about this one and never reach it.
	planEtcdPeerPortA = 12390
	planPgPortA       = 15433
	planPgPortB       = 15434
	planPgAPIA        = 18008
	planPgAPIB        = 18009
)

// MachineEnvironment is what one machine's deployment.env must say that is NOT the same on every machine.
// Everything else in that file belongs to the deployment and is carried unchanged.
func (p *Plan) MachineEnvironment(machineName string) (map[string]string, error) {
	region, machine, ok := p.find(machineName)
	if !ok {
		return nil, fmt.Errorf("this plan has no machine called %q", machineName)
	}
	env := map[string]string{}

	// ★ WHICH REGION THIS IS. The name devices use to choose a region and the name every record carries.
	env["DSSE_EDGE_REGION"] = strings.ToLower(strings.TrimSpace(region.ID))

	// ★★★ AND WHICH MACHINE THIS IS (2026-09-03, after a fourth machine was added and could not be found on
	// any screen). Nothing in a generated deployment named the machine it was generated for. A node reports
	// itself to the control plane as its container's hostname — a hex id that changes every time the container
	// is recreated — so the fleet a Console can show is a list of hex ids in regions, and the answer to "which
	// machine is behind" is not derivable from anything on screen.
	//
	// The plan already holds both: the name the operator wrote and the name TLS verifies. This carries them
	// onto the machine so the machine can say them.
	env["DSSE_NODE_NAME"] = strings.TrimSpace(machine.Name)
	if r := strings.TrimSpace(machine.Reachable); r != "" {
		env["DSSE_NODE_ADDRESS"] = r
	} else if len(machine.Addresses) > 0 {
		env["DSSE_NODE_ADDRESS"] = strings.TrimSpace(machine.Addresses[0])
	}

	// ★ WHICH ADDRESS EACH FRONT DOOR BINDS. A pair is two ADDRESSES because both doors are on 443.
	//
	// ★★★ A MACHINE THAT RUNS ONLY EDGES BINDS NO DOORWAY (2026-09-02). It sits BEHIND the region's front
	// door, so it needs one address and publishes its Edge ports there for the doorway to reach.
	if !machine.Holds.has("control-plane") && machine.Holds.has("edges") {
		// ★ ONLY A MACHINE WITHOUT A DOOR PUBLISHES ITS EDGE, and the compose file it is packed with is the
		// one that decides that — see edgePortsFor. These are the ports it publishes on.
		env["DSSE_EDGE_AGENT_PORT"] = fmt.Sprintf("%d", planEdgeBehindDoorAgentPort)
		env["DSSE_EDGE_ADMIN_PORT"] = fmt.Sprintf("%d", planEdgeBehindDoorAdminPort)
		// ★★★ AND IT TRUSTS THE DOOR THAT FRONTS IT, BY ADDRESS (2026-09-02). -trusted-front-doors expresses
		// trust as addresses, and it is what makes the PROXY protocol header believable — without it this Edge
		// drops every connection the doorway sends, and every device in the region arrives from nowhere. The
		// doorway is on another machine now, so the list has to name that machine rather than a container.
		doors := []string{}
		for _, other := range region.Machines {
			if !other.Holds.has("control-plane") {
				continue
			}
			for _, a := range other.Addresses {
				if a = strings.TrimSpace(a); a != "" {
					doors = append(doors, a)
				}
			}
		}
		if len(doors) > 0 {
			sort.Strings(doors)
			env["DSSE_TRUSTED_FRONT_DOORS"] = strings.Join(doors, ",")
		}
	} else {
		env["DSSE_REGION_BIND_A"] = strings.TrimSpace(machine.Addresses[0]) + ":"
		env["DSSE_REGION_PORT"] = "443"
	}

	// ★★★ THE EDGES OF THIS REGION THAT ARE NOT ON THIS MACHINE (2026-09-02). This is the seam that made
	// "Edges scaled horizontally behind the region's front door" possible, and until today NOTHING WROTE IT:
	// edgeFleetBackends read DSSE_EDGE_BACKENDS from deployment.env and no code path ever put a value there,
	// so every doorway named its own containers and a region could only grow by adding whole doorways beside
	// each other.
	//
	// Derived from the plan, so an operator declares machines and the doors follow. The health check is on the
	// admin port and traffic on the agent one — see edgeFleetServers.
	if machine.Holds.has("control-plane") && machine.Holds.has("edges") {
		behind := []string{}
		for _, other := range region.Machines {
			if other.Name == machine.Name || other.Holds.has("control-plane") || !other.Holds.has("edges") {
				continue
			}
			if len(other.Addresses) == 0 {
				continue
			}
			behind = append(behind, fmt.Sprintf("%s:%d", strings.TrimSpace(other.Addresses[0]), planEdgeBehindDoorAgentPort))
		}
		if len(behind) > 0 {
			sort.Strings(behind)
			// The doorway's own Edge first, then the machines behind it: the list the door balances over.
			env[edgeBackendsKey] = strings.Join(append([]string{"dsse-edge-a:8443"}, behind...), ",")
		}
	}

	// ★ THE MAP OF EVERY REGION, IDENTICAL EVERYWHERE. An Edge holding a shorter one is healthy and hands its
	// devices a map missing the region it never heard about.
	env["DSSE_REGION_ENDPOINTS"] = p.RegionEndpoints()
	if pub := strings.TrimSpace(p.Publisher); pub != "" {
		env["DSSE_AGENT_PUBLISHER"] = pub
	}

	// ★★★ THE CONSENSUS STORE OF THE WHOLE DEPLOYMENT, which lives in the founding region and which every
	// other region must reach. Published on the founding control plane's own address; advertised by a NAME,
	// so one value is correct at home and abroad.
	spanning := p.stateBearingRegions()
	founding := p.foundingRegion().controlPlane()
	etcd := []string{}
	if len(spanning) > 1 {
		// ★★★ ONE MEMBER IN EACH STATE-BEARING REGION. Every one of them is a client endpoint, and Patroni is
		// told all of them: the cluster it asks for its member list will answer with these.
		for _, r := range spanning {
			etcd = append(etcd, fmt.Sprintf("'%s:%d'", r.controlPlane().reachableName(), planEtcdPortA))
		}
	} else {
		// ★ ONE REGION MEANS ONE MEMBER (2026-09-03) — see stateBearingServicesFor. Naming three here while
		// the compose file renders one is how Patroni ends up waiting for members that do not exist.
		etcd = append(etcd, fmt.Sprintf("'%s:%d'", founding.reachableName(), planEtcdPortA))
	}
	env["DSSE_ETCD_HOSTS"] = strings.Join(etcd, ",")

	if machine.Holds.has("control-plane") {
		local := strings.TrimSpace(machine.Addresses[0])
		reach := machine.reachableName()
		switch {
		case len(spanning) > 1 && region.HoldsState:
			// ★★★ THIS REGION'S ONE MEMBER OF THE DEPLOYMENT'S ONE STORE (2026-08-31).
			env["DSSE_ETCD_A_NAME"] = storeMemberName(region.ID)
			env["DSSE_ETCD_A_PUBLISH"] = fmt.Sprintf("%s:%d", local, planEtcdPortA)
			env["DSSE_ETCD_A_PEER_PUBLISH"] = fmt.Sprintf("%s:%d", local, planEtcdPeerPortA)
			env["DSSE_ETCD_A_ADVERTISE"] = fmt.Sprintf("https://%s:%d", reach, planEtcdPortA)
			env["DSSE_ETCD_A_PEER_ADVERTISE"] = fmt.Sprintf("https://%s:%d", reach, planEtcdPeerPortA)

			// ★★★ AND IT IS ENCRYPTED, BECAUSE OF WHERE IT NOW GOES (2026-08-31). A store with a member in
			// another region carries which database is primary across whatever is between them, which between
			// two cloud regions nobody has peered is the public network. The database beside it was fixed the
			// same way when its sslmode was disable.
			//
			// ★ PEER AND CLIENT ARE SEPARATE, AND BOTH ARE ASKED FOR A CERTIFICATE. Encrypting without
			// requiring one leaves a peer anybody can be; the material is issued from this deployment's own
			// store authority, which nothing outside these machines has.
			const caPath, certPath, keyPath = "/deployment/store-ca.pem", "/deployment/store-member.pem", "/deployment/store-member-key.pem"
			env["DSSE_ETCD_LISTEN_CLIENT_URLS"] = "https://0.0.0.0:2379"
			env["DSSE_ETCD_LISTEN_PEER_URLS"] = "https://0.0.0.0:2380"
			// ★★★ THE CLIENT CA IS WHAT DEMANDS A CLIENT CERTIFICATE — NOT THE FLAG NAMED FOR IT
			// (2026-08-31, measured: without a certificate the client endpoint refused the handshake while
			// ETCD_CLIENT_CERT_AUTH was already false). etcd turns on client-certificate verification when a
			// trusted CA is configured for the client endpoint; the flag does not turn that back off. So
			// leaving this empty is how the client endpoint is encrypted and server-authenticated without
			// asking the caller for one — and the PEER CA below is untouched, which is the traffic that
			// crosses a network.
			//
			// ★ The measurement is the only reason this is known. Setting the flag and reading it back said
			// "false" on a store that was refusing every certificate-less caller.
			env["DSSE_ETCD_TRUSTED_CA_FILE"] = ""
			env["DSSE_ETCD_CERT_FILE"] = certPath
			env["DSSE_ETCD_KEY_FILE"] = keyPath
			// ★★★ THE CLIENT ENDPOINT IS ENCRYPTED AND DOES NOT DEMAND A CERTIFICATE, AND THAT IS A GAP
			// (2026-08-31, measured on the first three-region lab: Patroni could not start).
			//
			// Every private key this deployment mounts is 0600, which works because every container that reads
			// one runs as root. The database image does not: Patroni runs as uid 101, so the member key it was
			// told to present was unreadable and the only symptom was
			// PermissionError(13) inside a urllib3 ProtocolError — a permission error wearing a network
			// error's clothes.
			//
			// What crosses a network here is PEER traffic, and that keeps mutual certificates. The client
			// endpoint is reached by Patroni on this same machine and by the operator's -verify; it is
			// encrypted and the server is authenticated, and it does not require a certificate from the
			// caller. So anything that can reach the published client port can talk to the store without one.
			// The security group holds that set down to this deployment's own machines and the operator's
			// address, and every one of those machines already holds a member key — but the operator's
			// network is in it too, and that is the part that is weaker than it should be.
			//
			// ★ THE RIGHT FIX IS PER-CONSUMER CLIENT MATERIAL OWNED BY THE UID THAT READS IT, which needs the
			// installer to know that uid or to run as root. Written down rather than guessed at: this is a
			// deliberate, stated gap and not an oversight.
			env["DSSE_ETCD_CLIENT_CERT_AUTH"] = "false"
			env["DSSE_ETCD_PEER_TRUSTED_CA_FILE"] = caPath
			env["DSSE_ETCD_PEER_CERT_FILE"] = certPath
			env["DSSE_ETCD_PEER_KEY_FILE"] = keyPath
			env["DSSE_ETCD_PEER_CLIENT_CERT_AUTH"] = "true"

			// ★ AND PATRONI REACHES IT THE SAME WAY. Its host list stays bare host:port — the protocol is its
			// own setting, so a deployment that "configured TLS" by writing https:// into the hosts would talk
			// plaintext and look configured.
			env["DSSE_ETCD_CLIENT_SCHEME"] = "https"
			env["DSSE_ETCD_CLIENT_CACERT"] = caPath
			// ★ AND PATRONI IS NOT TOLD TO PRESENT ONE. Pointing it at a key it cannot read is the failure
			// above; pointing it at nothing is the honest expression of the line above this.
			env["DSSE_ETCD_CLIENT_CERT"] = ""
			env["DSSE_ETCD_CLIENT_KEY"] = ""

			// ★★★ THE FOUNDING MEMBER STARTS A CLUSTER OF ONE, AND THE OTHERS JOIN IT (2026-08-31).
			//
			// A static three-member bootstrap needs all three machines at once, and the install order is
			// sequential — the founding region would stop being able to finish on its own, because its
			// control plane waits for a database whose Patroni waits for a quorum that needs machines nobody
			// has built yet.
			//
			// ★ AND EACH JOINER IS ADDED AS A LEARNER FIRST. `member add` changes the quorum the instant it
			// runs: adding a second voting member to a cluster of one makes the quorum two, so a joiner that
			// then fails to start takes the founding region's database read-only — with no way back, because
			// the store is what would have to agree to remove it. Learners do not count toward quorum, are
			// refused promotion by the server until they have caught up, and reject client traffic until they
			// are promoted. The install order carries `member add --learner` and `member promote` for exactly
			// this reason. See the design note beside this shape.
			members := []string{}
			for _, r := range spanning {
				cp := r.controlPlane()
				_ = cp
				members = append(members, storeMemberName(r.ID)+"="+p.storeMemberPeerURL(r))
				if strings.EqualFold(r.ID, region.ID) {
					break // a joining member names the cluster as it will be when it joins, and no further
				}
			}
			env["DSSE_ETCD_INITIAL_CLUSTER"] = strings.Join(members, ",")
			if region.Founding {
				env["DSSE_ETCD_INITIAL_CLUSTER_STATE"] = "new"
			} else {
				env["DSSE_ETCD_INITIAL_CLUSTER_STATE"] = "existing"
			}
		case region.Founding:
			// One member: the B and C addresses named nothing once the store stopped rendering them.
			env["DSSE_ETCD_A_PUBLISH"] = fmt.Sprintf("%s:%d", local, planEtcdPortA)
			env["DSSE_ETCD_A_ADVERTISE"] = fmt.Sprintf("http://%s:%d", reach, planEtcdPortA)
		}
		// ★★★ AND WHAT ITS DATABASE MEMBERS CALL THEMSELVES. The default is the compose service name, the
		// same in every region — so the second region's first member announces a name the deployment already
		// has, and Patroni refuses it outright. One cluster spans every region.
		env["DSSE_PG_A_NAME"] = "dsse-pg-" + env["DSSE_EDGE_REGION"] + "-a"
		env["DSSE_PG_B_NAME"] = "dsse-pg-" + env["DSSE_EDGE_REGION"] + "-b"
		env["DSSE_PG_A_MEMBER_PUBLISH"] = fmt.Sprintf("%s:%d", local, planPgPortA)
		env["DSSE_PG_B_MEMBER_PUBLISH"] = fmt.Sprintf("%s:%d", local, planPgPortB)
		env["DSSE_PG_A_API_PUBLISH"] = fmt.Sprintf("%s:%d", local, planPgAPIA)
		env["DSSE_PG_B_API_PUBLISH"] = fmt.Sprintf("%s:%d", local, planPgAPIB)
		env["DSSE_PG_A_ADVERTISE"] = fmt.Sprintf("%s:%d", reach, planPgPortA)
		env["DSSE_PG_B_ADVERTISE"] = fmt.Sprintf("%s:%d", reach, planPgPortB)
		env["DSSE_PG_A_API_ADVERTISE"] = fmt.Sprintf("%s:%d", reach, planPgAPIA)
		env["DSSE_PG_B_API_ADVERTISE"] = fmt.Sprintf("%s:%d", reach, planPgAPIB)
	}

	// ★★★ THE DATABASE MEMBERS IN THE OTHER REGIONS. The deployment has ONE primary and it can be in any
	// region; a door knowing only local members has no backend whenever the primary is elsewhere, and
	// everything that needs the database stops — measured, in the region that was still healthy.
	peers := []string{}
	for _, other := range p.Regions {
		if strings.EqualFold(other.ID, region.ID) {
			continue
		}
		cp := other.controlPlane()
		if cp.reachableName() == "" {
			continue
		}
		// ★ THE ADDRESS, NOT THE NAME. This door speaks plain TCP and verifies nothing, and its server lines
		// carry no resolvers — so a name here is resolved once, at start-up, inside a container. See
		// PlanMachine.ReachableAddress: given a name, the peer sat at ECONNRESET while that very name answered
		// 200 from inside the same container.
		// ★ ONE MEMBER PER MACHINE SINCE 2026-09-02 — the second beside the first was retired, so a region
		// contributes one address, not two.
		peers = append(peers, fmt.Sprintf("%s:%d:%d", cp.reachableAt(), planPgPortA, planPgAPIA))
	}
	sort.Strings(peers)
	env["DSSE_PG_PEERS"] = strings.Join(peers, ",")

	// ★★★ EVERY MEMBER OF THE DEPLOYMENT'S DATABASE, FOR THE CLIENT TO CHOOSE BETWEEN (2026-09-02). The proxy
	// that used to stand in front of the database on this machine is gone: it health-checked Patroni's REST
	// port and forwarded to whichever member led, which libpq does itself given the list and
	// target_session_attrs=read-write. Local member first — a control plane that can be served from its own
	// machine should be.
	hosts := []string{fmt.Sprintf("dsse-postgres-a:%d", 5432)}
	for _, other := range p.Regions {
		if strings.EqualFold(other.ID, region.ID) {
			continue
		}
		if cp := other.controlPlane(); cp.reachableAt() != "" {
			hosts = append(hosts, fmt.Sprintf("%s:%d", cp.reachableAt(), planPgPortA))
		}
	}
	env["DSSE_PG_HOSTS"] = strings.Join(hosts, ",")

	// ★★★ THE OTHER EDGE MACHINES OF THIS REGION (2026-09-02). A connector attaches to ONE Edge of its region
	// and every other node reaches its estate by relaying to that one, so a region that grows by adding Edge
	// machines needs each of them to know the others. Until today this was a container name — the second Edge
	// beside the first — which is the co-location that has been retired.
	if machine.Holds.has("edges") {
		siblings := []string{}
		for _, other := range region.Machines {
			if other.Name == machine.Name || !other.Holds.has("edges") || len(other.Addresses) == 0 {
				continue
			}
			siblings = append(siblings, siblingEdgeURL(other))
		}
		if len(siblings) > 0 {
			sort.Strings(siblings)
			env["DSSE_EDGE_SIBLINGS"] = strings.Join(siblings, ",")
		}
	}

	// ★★★ AND THE TWO DOORS THAT CROSS REGIONS, BY NAME AND AT AN ADDRESS (2026-08-28).
	//
	// DSSE_REGION_ENDPOINTS is what DEVICES are handed, so it names each region's agent plane and nothing
	// else — an address in it would be an address on every device. The doors need somewhere to CONNECT, and
	// their server lines resolve nothing at run time. Both come from the plan, so this is still one answer
	// rather than a second list to keep in step: written name@address, TLS verifies the name and the
	// connection goes to the address.
	admin, data := []string{}, []string{}
	for _, other := range p.Regions {
		if strings.EqualFold(other.ID, region.ID) {
			continue
		}
		id := strings.ToLower(strings.TrimSpace(other.ID))
		at := other.controlPlane().reachableAt()
		if at == "" {
			continue
		}
		admin = append(admin, fmt.Sprintf("https://%s@%s:443", p.PlaneNamesFor(id)["admin"], at))
		data = append(data, fmt.Sprintf("https://%s@%s:443", p.PlaneNamesFor(id)["authority"], at))
	}
	sort.Strings(admin)
	sort.Strings(data)
	env["DSSE_CP_PEERS"] = strings.Join(admin, ",")
	// ★★★ AND WHERE AN EDGE MAY ASK WHEN THE REGION IT ASKS DIES (2026-08-28, reported by -verify): "this
	// deployment spans more than one region and every Edge takes configuration from ONE control-plane
	// address. Losing the region that answers it leaves every Edge — in every region — serving what it last
	// applied, with nowhere to ask and nothing to show for it."
	//
	// The plan knows every region's control plane, so the list is derived rather than asked for.
	//
	// ★ AND IN THE SHAPE THE START SCRIPT READS: region=URL, semicolon-separated. A list of bare URLs is
	// accepted by the file and used by nothing — start-edge.sh keys it by region, and the Edge went on taking
	// configuration from one address while deployment.env said otherwise.
	endpoints := []string{}
	for _, r := range p.Regions {
		id := strings.ToLower(strings.TrimSpace(r.ID))
		endpoints = append(endpoints, id+"=https://"+p.PlaneNamesFor(id)["admin"])
	}
	sort.Strings(endpoints)
	env["DSSE_CP_ENDPOINTS"] = strings.Join(endpoints, ";")

	// ★★★ AND WHERE THE SAME REGIONS ARE WRITTEN TO (2026-08-31). The list above is where a node READS from.
	// What it WRITES — the history it recorded, an enrolment it completed, a connector that joined — goes to
	// the DATA plane, which is a different NAME of the same region. start-edge.sh has read this since
	// 2026-08-25 and turns it into -config-source-data-endpoints; nothing wrote it, so an Edge that had
	// followed leadership for reading still shipped to one fixed address.
	dataEndpoints := []string{}
	for _, r := range p.Regions {
		id := strings.ToLower(strings.TrimSpace(r.ID))
		dataEndpoints = append(dataEndpoints, id+"=https://"+p.PlaneNamesFor(id)["authority"])
	}
	sort.Strings(dataEndpoints)
	env["DSSE_CP_DATA_ENDPOINTS"] = strings.Join(dataEndpoints, ";")

	// ★ AND WHICH ONE THIS NODE PREFERS: its own region, so a deployment whose leader is at home does not
	// send every read across an ocean to discover that.
	// ★★★ AND THE MESH, WHEN THE PLAN SAYS THIS DEPLOYMENT HAS ONE (2026-09-01). start-edge.sh has read
	// DSSE_MESH_PEERS since 2026-08-25 and the printed order names the mesh as a step; nothing wrote it, so
	// the step could only be done by composing peer URLs by hand from names this plan already holds. Empty
	// stays the default and stays a decision — see Plan.Mesh — but a deployment that declared one gets the
	// addresses derived rather than typed, in both directions, because a mesh link is mutual and a hand-typed
	// half looks like a network fault.
	if peers := p.MeshPeersFor(region.ID); peers != "" {
		env["DSSE_MESH_PEERS"] = peers
	}
	env["DSSE_CP_HOME"] = strings.ToLower(strings.TrimSpace(region.ID))
	env["DSSE_CP_DATA_PEERS"] = strings.Join(data, ",")
	return env, nil
}

// PlanEnvironmentFor writes those values into a deployment.env, replacing what is there and appending what is
// not. A value the plan does not decide is left exactly as it was.
func PlanEnvironmentFor(env string, values map[string]string) string {
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	lines := strings.Split(env, "\n")
	for _, key := range keys {
		set := false
		for i, line := range lines {
			if k, _, ok := strings.Cut(strings.TrimSpace(line), "="); ok && k == key {
				lines[i] = key + "=" + shellQuoted(values[key])
				set = true
				break
			}
		}
		if !set {
			lines = append(lines, key+"="+shellQuoted(values[key]))
		}
	}
	return withTrailingNewline(strings.Join(lines, "\n"))
}

func (p *Plan) find(machineName string) (PlanRegion, PlanMachine, bool) {
	machineName = strings.ToLower(strings.TrimSpace(machineName))
	for _, r := range p.Regions {
		for _, m := range r.Machines {
			if strings.ToLower(strings.TrimSpace(m.Name)) == machineName {
				return r, m, true
			}
		}
	}
	return PlanRegion{}, PlanMachine{}, false
}

// shellQuoted wraps a value for a file that is SOURCED.
//
// ★★★ THE VALUE THAT ALREADY HAD QUOTES IN IT (2026-08-28, caught by reading a packed machine). etcd wants its
// hosts quoted individually — 'a:2379','b:2379' — and wrapping that in single quotes again produced
//
//	DSSE_ETCD_HOSTS=''cp-a.dsse.lab:12379','cp-a.dsse.lab:12380''
//
// which a shell reads as something else entirely. Nothing would have reported it: the file sources without
// error and the consensus store is simply somewhere else.
func shellQuoted(value string) string {
	if !strings.Contains(value, "'") {
		return "'" + value + "'"
	}
	if !strings.Contains(value, `"`) && !strings.Contains(value, "$") && !strings.Contains(value, "`") {
		return `"` + value + `"`
	}
	// Both kinds present: close, escape, reopen — the only form that survives either.
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}

// siblingEdgeURL is how one Edge of a region dials another.
//
// ★★★ IT WAS AN ADDRESS, AND NO EDGE'S CERTIFICATE CARRIES ONE (2026-09-03, measured on a region given a
// second Edge machine — the first time this link has been exercised anywhere).
//
//	mesh peer tokyo-east (wss://10.21.1.158:8443/mesh/ingress/tunnel) link down:
//	  tls: failed to verify certificate: x509: certificate is valid for 10.77.0.10, 127.0.0.1, ::1,
//	  not 10.21.1.158
//
// 10.77.0.10 is the Edge's address on its own compose network — the only IP in the leaf. Every machine's
// leaf is otherwise identical and carries NAMES, including this one: CertificateNames() puts each machine's
// Reachable into every leaf, precisely so a node can be verified when another node dials it.
//
// So the sibling link has never come up on any deployment: it dialled by an address the certificate could
// not vouch for, retried every two seconds, and the only symptom was a log line. The relay it exists for —
// a flow arriving at one Edge of a region for a connector whose tunnel another Edge holds — silently had no
// path, and the door's source hashing makes that pairing ordinary rather than rare.
//
// ★ A MACHINE WITH NO Reachable KEEPS THE ADDRESS. It cannot be verified by name because it has none, and a
// deployment that has always worked that way is not made worse by this.
func siblingEdgeURL(m PlanMachine) string {
	host := strings.TrimSpace(m.Reachable)
	if host == "" {
		host = strings.TrimSpace(m.Addresses[0])
	}
	return fmt.Sprintf("wss://%s:%d/mesh/ingress/tunnel", host, planEdgeBehindDoorAgentPort)
}
