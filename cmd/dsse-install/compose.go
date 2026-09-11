package main

import (
	"os"
	"path/filepath"
	"strings"
)

// compose.go — the same deployment, rendered for containers.
//
// ★★★ WHY THE INSTALLER WRITES THIS AND NOT A HUMAN (2026-08-23, measured by counting what was published).
// The published tree described how to stand DSSE up in three places, and the installer was named in none of
// them:
//
//	deploy/docker-compose.yml + deploy/README.md   a "one-command demo": two containers, ONE static token
//	                                              (`demo`) shared by both, no named administrator, no
//	                                              enrolment, no device CA, no database
//	a "getting started" page                      a single hand-started Edge, `go install`, an openssl
//	                                              self-signed certificate, -admin-token
//	dsse-install                                  the deployment the architecture describes
//
// Three descriptions of one procedure is the ordinary version of this problem. This was worse: the first two
// stand up a shape a DEPLOYMENT MAY NOT HAVE. A static token shared by the control plane and the Edge is a
// break-glass credential, which is meant to stop working the moment there is a real administrator; a
// deployment with no named administrator attributes every act to nobody; an Edge with no control-plane
// authority and no device CA is a deployment no device can join. A reader following either document does not
// get a smaller DSSE. They get a different one, and nothing tells them so.
//
// ★ A COMPOSE FILE MUST NOT BE A SECOND PROCEDURE. Every service below runs one of the START SCRIPTS. The
// flags live in exactly one place — start-control-plane.sh and start-edge.sh — and this file says only WHERE
// they run and what surrounds them. That is why the two cannot drift: there is nothing here to drift with.
// The eleven flags the walk found missing from a printed command were found because somebody ran it; a second
// hand-maintained rendering is where the twelfth would hide.

// composeServiceNames are the names this deployment answers on INSIDE a container network. They go into the
// certificates for the same reason the operator's own hostnames do — an Edge verifies the control plane
// against the deployment anchor, and a name that is not in the certificate is a deployment that cannot start
// no matter which rendering is used.
//
// ★★★ THE FRONT DOOR'S NAME IS ONE OF THEM, and leaving it out cost a walk (2026-08-24). Everything reaches
// the control plane THROUGH the front door now, so that is the name in the URL an Edge verifies against the
// deployment anchor — and the certificate did not carry it. The Edge stayed up, healthy, enforcing what it
// booted with, pulling nothing; the only thing that said so was -verify's "has applied NOTHING". Same lesson
// as the container names themselves, one layer further out: a name something is REACHED BY has to be in the
// certificate, and a front door is a name.
//
// ★ THEY ARE ADDED ALWAYS, not only when containers are used. A certificate minted for a host install and
// then deployed in containers would otherwise have to be re-minted — and re-minting orphans every anchor
// already distributed. The names cost nothing: this deployment's own CA naming this deployment's own nodes.
var composeServiceNames = []string{"dsse-control-plane", "dsse-control-plane-a",
	// dsse-edge is the region's front door — the name devices ask for, and therefore the name that must be in
	// the transport certificate the EDGES present, because the front door terminates nothing.
	//
	// ★★ THE FLEET'S OWN NAMES ARE HERE TOO, AND LEAVING THEM OUT COSTS AN OUTAGE THAT LOOKS LIKE HEALTH. A
	// name missing from this list has twice produced an Edge that stayed up, answered its health check, and
	// applied nothing at all — caught only by a check that asked what it had applied. The front door reaches
	// each node BY NAME to health-check it, and a node reached by a name it cannot prove is a node the front
	// door quietly removes from rotation.
	"dsse-edge", "dsse-edge-a"}

// composeFrontDoorAddresses are the fixed addresses the region's front doors hold, and composeRegionAddress is
// the one the region answers on, delivered by the layer below this file.
//
// ★★★ THEY ARE FIXED BECAUSE TWO OTHER THINGS ARE TOLD ABOUT THEM. Every Edge is told which addresses may
// state a device's original address (-trusted-front-doors), and the deployment's own certificate has to carry
// the region address or a device reaching it cannot verify what answers. Neither can be "whatever the network
// hands out today".
//
// ★ THERE WAS A composeFrontDoorB = "10.77.0.6" HERE UNTIL 2026-09-05. A region's doorway was a pair until
// 2026-09-02; the second door went, and its address stayed — in this file as an unused constant, and in the
// -trusted-front-doors default as an address every Edge was told to believe a source-address claim from.
const (
	composeFrontDoorA    = "10.77.0.5"
	composeRegionAddress = "10.77.0.10"
)

// writeComposeFile renders the deployment for containers. It is written next to the scripts it runs.
// writeComposeFile renders the deployment for containers.
//
// ★★★ A REGION EITHER HOLDS THE DEPLOYMENT'S STATE OR IT DOES NOT, AND THE SECOND SHAPE IS THE ONE THE
// ARCHITECTURE ASKS FOR MOST OF THE TIME. "Edges may live in more regions than state does; a region without
// state fails its control-plane channel over to a region that has it." A region that stands up its own etcd
// cluster and its own Postgres is not a second region — it is a second DEPLOYMENT: two leaders, each holding
// a lock on its own database, and one-time decisions that are per region rather than per deployment. The
// identity claim's uniqueness — "has this identity already enrolled" answered once for the whole fleet —
// breaks exactly at that boundary.
//
// So the state-bearing services are a block, and a joining region is rendered without them.
// ★ THE FOUNDING MACHINE'S SHAPE. Historically always state-bearing WITH Edges, which is the one-host
// reference. A machine that runs only the Control Plane component says so with -control-plane-only, and this
// is where that answer arrives.
var foundingShape = machineShape{holds: regionShapeStateBearing, edges: true}

func writeComposeFile(dir string) error { return writeComposeFileFor(dir, foundingShape) }

// regionHolding is what a region holds. Three values rather than a bool, because the third — a region with a
// warm control plane and no state — is neither of the other two and had no way to be expressed.
type regionHolding int

const (
	// regionShapeStateBearing: the consensus store, the database, the control-plane pair and everything the
	// control plane owns.
	regionShapeStateBearing regionHolding = iota
	// regionShapeEdgesOnly: Edges and a front door. Takes configuration from wherever leadership is.
	regionShapeEdgesOnly
	// regionShapeStateBearingJoin: everything a state-bearing region has, JOINING the deployment rather than
	// founding it. Its Postgres members come up as replicas of the existing primary, its control planes
	// contend for the same advisory lock, and it keeps its own hot store, archive and Console — which the
	// operator's definition of a Control Plane requires and which is what stops a region's history being
	// written across an ocean.
	//
	// ★ IT RUNS NO CONSENSUS STORE OF ITS OWN. There is one per deployment with a member per region; a second
	// cluster would be a second opinion about which database is primary.
	regionShapeStateBearingJoin
	// regionShapeStandbyCP: Edges, a front door, and a warm control plane that JOINS the deployment's
	// database. Leadership can move here while that database is reachable. See composeStandbyControlPlane
	// for why that is one third of a state-bearing region and not a substitute for one.
	regionShapeStandbyCP
)

func (s regionHolding) holdsAControlPlane() bool {
	return s == regionShapeStateBearing || s == regionShapeStateBearingJoin || s == regionShapeStandbyCP
}

// holdsState reports whether this region keeps a database it could be promoted on. ★ THE DIFFERENCE THAT
// MATTERS: a warm control plane with no database of its own is not somewhere leadership can move TO when the
// region holding the state is gone — there is nothing there to promote.
func (s regionHolding) holdsState() bool {
	return s == regionShapeStateBearing || s == regionShapeStateBearingJoin
}

// machineShape is what ONE machine stands up: what its REGION holds, and whether this machine is the one
// running the Edges.
//
// ★★★ THESE ARE TWO QUESTIONS AND THEY WERE ONE VALUE (2026-08-27, found by trying to put a second region's
// control plane on its own machine). "Control-plane-only" was a fifth REGION shape, so it could only ever
// describe the founding one. Asking for it in a JOINING region gave that region its own consensus store — a
// second opinion about which database is primary, which is the one thing a joining region must not have.
// Asking for the joining shape instead gave the control plane's machine a fleet of Edges beside the
// authority. There was no way at all to say "this machine holds the Control Plane component of a region that
// joins", so a second region could not be installed one component per machine.
//
// A region kind and a machine's role are independent, so they are two fields. Every combination an operator
// can ask for is then expressible, and none of them is an enum value nobody thought to add.
type machineShape struct {
	// behindDoorway marks a machine that runs Edges and NO control plane: it sits behind the region's front
	// door rather than being one. Edges are the highest-load component and are scaled horizontally BEHIND the
	// region's front door; until 2026-09-02 that role could not be expressed at all.
	behindDoorway bool

	// holds is what the REGION this machine belongs to holds.
	holds regionHolding
	// edges is whether THIS MACHINE runs the Edge processes. A machine that does not still renders the
	// region's doorway: every machine that serves a plane needs a door to it.
	edges bool
	// storeSpansRegions says this deployment keeps state in more than one region, so the consensus store has
	// ONE member here and its others elsewhere — rather than the whole cluster on this host.
	//
	// ★ IT IS A PROPERTY OF THE DEPLOYMENT, ASKED OF THE MACHINE. A machine cannot work it out alone: it is
	// whether anyone ELSE holds state, which only the plan knows.
	storeSpansRegions bool
}

func (m machineShape) runsEdges() bool          { return m.edges }
func (m machineShape) holdsAControlPlane() bool { return m.holds.holdsAControlPlane() }

// writeComposeFileFor renders this region. stateBearingRegion=false leaves out the database, the consensus
// store and the control planes: those belong to the deployment, not to each region.
func writeComposeFileFor(dir string, shape machineShape) error {
	return composeFileFor(dir, shape, false)
}

// rewriteComposeFileFor renders the compose file whether or not one is already there.
//
// ★★★ THE REPAIR SAID IT HAD REWRITTEN THIS FILE AND HAD NOT (2026-08-26, found while giving an existing
// deployment a log cap it could not otherwise receive). The guard below is right for INSTALL — re-running it
// on a directory it made must not clobber an operator's edits — and it is wrong for repair, which exists
// precisely so a deployment generated by an older installer can take a correction. It applied to both, so
// "rewrote this deployment's generated files: docker-compose.yml" was printed over a file left untouched.
// The launch scripts and the front-door configs beside it were rewritten unconditionally the whole time, so
// this was also the one file in that list behaving differently from the others.
func rewriteComposeFileFor(dir string, shape machineShape) error {
	return composeFileFor(dir, shape, true)
}

func composeFileFor(dir string, shape machineShape, rewrite bool) error {
	path := filepath.Join(dir, "docker-compose.yml")
	if _, err := os.Stat(path); err == nil && !rewrite {
		stateBearingRegion := shape.holds == regionShapeStateBearing
		// ★★★ A CARRIED FILE IS ANOTHER REGION'S, NOT AN EDIT OF THIS ONE (2026-08-25, found by rendering a
		// second region and getting the first one's services). "Leave it alone, an operator has edited it" is
		// right when this command is re-run on a directory it made — and wrong for a region prepared from a
		// carried copy, where the file it finds describes a DIFFERENT region. Honouring it there produced a
		// joining region that stood up its own database and its own control planes: exactly the second
		// deployment this block exists to prevent, arrived at by refusing to write.
		if stateBearingRegion {
			return nil // this command made this file; leave whatever is there
		}
	}
	return composeFileTo(dir, path, shape)
}

// composeFileTo renders this region's compose to an explicit path.
func composeFileTo(dir, path string, shape machineShape) error {
	stateBearingRegion := shape.holds == regionShapeStateBearing
	_ = stateBearingRegion
	stateBearing, cpOwned := stateBearingServicesFor(shape.storeSpansRegions), composeControlPlaneOwnedWith(adminUpstreamFor(dir, shape), consoleEdgeUpstreamFor(dir, shape))
	if !shape.edges && shape.holds == regionShapeStateBearing {
		// ★ THE SAME CONTROL PLANE, WITHOUT THE EDGES. It founds the deployment exactly as before — consensus
		// store, database, control planes, hot store, archive, Console — and the Edge block is left out
		// elsewhere in this function. Nothing about the authority changes because its Edges moved house.
		stateBearing, cpOwned = stateBearingServicesFor(shape.storeSpansRegions), composeControlPlaneOwnedWith(adminUpstreamFor(dir, shape), consoleEdgeUpstreamFor(dir, shape))
	} else if shape.holds == regionShapeStateBearingJoin {
		// ★★★ THE SAME REGION, JOINING RATHER THAN FOUNDING (2026-08-27). It renders its own database, its own
		// control planes, and its own hot store, archive and Console — everything the operator's definition of
		// a Control Plane contains. What it leaves out is the consensus store (one per deployment, a member
		// per region) and the database initialisation (the database exists; running it again would wait on a
		// local front door with no primary behind it).
		//
		// ★ AND ITS HISTORY STAYS HERE. The shape this replaces wrote to the deployment's hot store and
		// archive ACROSS REGIONS whenever it held leadership — which, once regions are geographically apart,
		// means a region's log writes crossing an ocean. One-sided history that converges through the cold
		// archive is the operator's decision (2026-08-27) and it is the cheaper truth.
		stateBearing, cpOwned = joiningStateBearingServicesFor(shape.storeSpansRegions), composeControlPlaneOwnedWith(adminUpstreamFor(dir, shape), consoleEdgeUpstreamFor(dir, shape))
	} else if !stateBearingRegion {
		// ★ THE HOT STORE, THE ARCHIVE AND THE CONSOLE GO WITH THE CONTROL PLANE, because they are what it
		// OWNS — a region with no control plane has nothing to own them. Its Edges ship what they record to
		// the deployment's control plane, which is where the history is kept and where it is read from.
		//
		// ★ AND A STANDBY OWNS NONE OF THEM EITHER. It writes to the deployment's hot store and archive
		// across regions when it holds leadership; standing up a second pair here would be a second place
		// the history lives, which is the same mistake as a second database wearing different clothes.
		stateBearing, cpOwned = composeJoiningRegionNote, ""
		if shape.holds == regionShapeStandbyCP {
			stateBearing = composeStandbyControlPlane
		}
	}
	// ★★★ THE DOORWAY WAITS FOR THE EDGES ONLY WHEN THEY ARE IN THIS FILE. Naming a service compose does not
	// define makes the whole project invalid; naming one that IS defined but belongs on another machine starts
	// it here, which is the co-location this whole exercise exists to end.
	// ★★★ ONE EDGE PROCESS PER MACHINE (2026-09-02, the operator's decision). Edge is the highest-load
	// component of this product, and two of them in one compose file share a CPU, a kernel and a failure
	// domain — so "this region has two Edges" was a sentence about processes, not about redundancy. A region
	// is made redundant by ANOTHER MACHINE running an Edge behind the same doorway (DSSE_EDGE_BACKENDS), not
	// by a second container beside the first.
	doorwayDepends := "\n      dsse-edge-a: { condition: service_started }"
	// ★ AND IT WAITS FOR NOTHING WHEN THERE IS NOTHING HERE TO WAIT FOR. A control-plane machine defines no
	// Edge at all, so naming one makes the whole project invalid — the doorway is here for the planes this
	// machine serves, not for Edges it does not run.
	if len(edgeFleetBackends(dir)) > 0 || !shape.runsEdges() {
		doorwayDepends = " {}"
	}

	// ★ AND THE VOLUMES GO WITH THEM. Declaring storage for a database this region does not run says the
	// region holds state, in the one file somebody reads to find out what it holds.
	stateVolumes := "  pg-a:\n  clickhouse-data:\n  archive-data:\n  cp-a-state:\n  store-a-state:\n"
	if shape.holds == regionShapeStandbyCP {
		// The standby's own state directory, and nothing else. It starts empty, which is what makes it warm
		// rather than a second, emptier deployment — see the note on the state-bearing pair.
		stateVolumes = "  cp-a-state:\n"
	}
	// ★ AN EDGE WAITS FOR A CONTROL PLANE THAT IS IN THIS FILE, AND ONLY THEN. In a region that holds no
	// state the control plane is in another region entirely: naming it here does not order anything, it makes
	// the file invalid — "depends on undefined service". The Edge still refuses to start without a control
	// plane to reach; that check is in the Edge, where it belongs, and it does not need a local one to exist.
	// ★ THE EDGE WAITS FOR THE CONTROL PLANE ITSELF (2026-09-02), not for the proxy that used to stand in
	// front of it on this machine.
	edgeDependsOnCP := "\n      dsse-control-plane-a: { condition: service_started }"
	if !shape.holdsAControlPlane() {
		stateVolumes, edgeDependsOnCP = "", " {}"
	}
	// ★★★ THE EDGE PROCESSES AND THEIR DOORWAY, WHICH A CONTROL-PLANE MACHINE DOES NOT RUN (2026-08-27). Until
	// this was separable, every shape that held a control plane also defined the Edges — so the control
	// plane's machine offered their admin ports, and anything that started the doorway started Edge processes
	// beside the authority. One component per machine cannot be expressed without being able to leave this out.
	// ★ THE DOORWAY IS ALWAYS HERE; the Edge processes are not. Every machine that serves a plane needs a door
	// to it, and only the machines that run Edges define them.
	// ★★★ AN EDGE ON ITS OWN MACHINE CANNOT REACH A CONTAINER NAME (2026-08-27, measured by installing one).
	// The default was https://dsse-control-plane:9443 — the compose service in front of the control-plane
	// pair, which exists on the CONTROL PLANE's machine and on no other. On one host that is exactly right and
	// it is what every reader saw. On the shape that exists SO THAT a machine can run only Edges, it names
	// something that machine cannot resolve, and deployment.env writes no value to override it: the Edges come
	// up pointed at nothing, having been installed exactly as generated.
	//
	// ★ THE ANSWER IS THE NAMES THIS DEPLOYMENT ALREADY HAS. admin.<host> and authority.<host> are in the
	// certificate, are routed by the region doorway, and are on 443 like every other mouth. authority.<host>
	// was even written into deployment.env as DSSE_AUTHORITY_ORIGIN, for exactly this, and nothing read it.
	// ★ THE CALLERS NAME THE CONTROL PLANE ITSELF (2026-09-02), because the proxy that used to stand in front of
	// it on this machine is gone — see the note where it was defined.
	adminDefault, dataDefault := "https://dsse-control-plane-a:9443", "https://dsse-control-plane-a:8443"
	if !shape.holdsAControlPlane() {
		planes := planeNamesFor(deploymentHostFor(dir))
		adminDefault, dataDefault = "https://"+planes.Admin, "https://"+planes.Authority
	}
	// ★ A MACHINE BEHIND THE DOOR RENDERS NO DOOR. Its Edge publishes its own ports and the region's doorway,
	// on another machine, names it in DSSE_EDGE_BACKENDS.
	edgeBlock := strings.Replace(composeEdgeFleetWith(edgeDependsOnCP, adminDefault, dataDefault),
		edgePortsPlaceholder, edgePortsFor(shape), 1)
	if !shape.behindDoorway {
		edgeBlock = composeRegionDoorwayWith(edgeDependsOnCP) + "\n" + edgeBlock
	}
	edgeVolumes := "  edge-a-state:\n"
	if !shape.runsEdges() {
		edgeBlock = composeRegionDoorwayWith(edgeDependsOnCP) +
			"\n  # (this machine runs the Control Plane component; its Edges are on their own machines)"
		edgeVolumes = ""
	}

	body := `# This deployment, rendered for containers. Generated by dsse-install.
#
#   docker compose --env-file deployment.env up -d
#
# ★ --env-file IS NOT OPTIONAL. The secrets this deployment refuses to start without are in deployment.env,
# and compose does not read a file by that name on its own. Without it the database password below is empty
# and the control plane comes up against a database it cannot open.
#
# ★★ NOTHING HERE REPEATS A FLAG. Each service runs one of the start scripts beside this file, so the
# deployment is described ONCE. Change how a node starts by changing the script; this file only says where.
#
# ★★★ THE ORDER IS THE SAME ORDER, AND IT IS ENFORCED. The control plane holds the authority and the
# database; an Edge holds neither and refuses to start without a control plane to reach. depends_on says so
# here for the same reason the scripts do.
# ★★★ THE PROJECT AND THE NETWORK CARRY THE REGION, AND WITHOUT THAT A SECOND REGION DELETES THE FIRST
# (found by reading what -region generates). A deployment spans regions, and each one is rendered
# from the SAME carried directory — so both would have named the same compose project. On one host, bringing
# the second one up does not stand up a second region: compose sees the project it already knows and RECONCILES
# it, which means tearing down containers the first region is still serving from. On separate hosts, which is
# where regions actually live, it is invisible — so this is the kind of defect that only ever appears the first
# time somebody tries it, on the day they are trying to do something else.
#
# The addresses have the same shape of problem for a smaller reason: two regions on one host would put two
# bridges on 10.77.0.0/16 and the front doors on the same fixed addresses.
name: ${DSSE_PROJECT:-dsse}

services:
` + stateBearing + `
` + cpOwned + `
  # ★ EVERY EDGE RUNS THIS SAME SERVICE. To add one, copy this block, give it another name and other published
  # ports, and change nothing else — a fleet is identical nodes with different addresses. The state volume is
  # per-node because it holds what that node OBSERVED, never what it was told; the answers all come from the
  # control plane.
  # ★★★ A REGION PRESENTS ONE ADDRESS TO DEVICES AND HAS MANY EDGES BEHIND IT (invariants 9 and 10). This is
  # that address. Devices reach it; nothing reaches an Edge directly.
  #
  # ★★★ AND IT IS LAYER 4, WHICH IS NOT A PERFORMANCE CHOICE. A device's identity IS its client certificate,
  # verified at the handshake against the enrolled inventory. Terminating TLS here would hand every Edge a
  # connection with no client certificate on it, and every decision about who a device is would become "the
  # front door said so". So TCP passes through, and TLS terminates where the identity is checked.
` + edgeBlock + `
volumes:
` + stateVolumes + edgeVolumes + `

# ★★★ A DEFINED SUBNET, BECAUSE ONE ADDRESS IN IT IS PROMISED TO THE EDGES. The front door's address is
# named in every Edge's -trusted-front-doors, so it has to be an address this file decides rather than one
# the container runtime hands out on the day. ip_range keeps the runtime's own allocations away from the
# addresses this file assigns by hand.
# ★★★ AND IT CARRIES IPv6, BECAUSE AN EDGE THAT CANNOT DIAL v6 CANNOT REACH AN IPv6-ONLY ORIGIN
# (measured: an IPv6-only name came back 502 with "connect: cannot assign requested address" —
# no v6 source address to bind — and a dual-stack name worked only because the Edge silently dropped to v4.
# A device sees 200 either way, so the device is not where this can be measured.)
#
# The subnet is a ULA and reaches the world by NAT66, which the daemon does when ip6tables is on. That is a
# HOST setting, not this file's: see the note beside the compose file about /etc/docker/daemon.json.
networks:
  default:
    driver: bridge
    enable_ipv6: true
    ipam:
      config:
        - subnet: ${DSSE_SUBNET:-10.77.0.0/16}
          ip_range: ${DSSE_SUBNET_RANGE:-10.77.1.0/24}
        - subnet: ${DSSE_SUBNET_V6:-fd00:d55e:77::/64}

# ★★★ THEN CHECK IT, THEN CLOSE IT — the same two steps as a host install, because it is the same deployment:
#
#   dsse-install -verify -dir . -control-plane https://admin.<host>:${DSSE_REGION_PORT:-18443} \
#     -control-plane-peers https://<region>-control-plane-a.admin.<host>@<the door's address> \
#     -edge-admin https://<region>-edge-a.admin.<host>@<the door's address> \
#     -edge https://agents.<host>:${DSSE_REGION_PORT:-18443}
#
# ★★★ THOSE ARE NAMES, NOT PORTS. Per-node access is by NAME through the region's one door, which routes it
# by SNI, and @<address> is how that name is dialled where DNS does not answer it. The control plane
# publishes no port of its own, and a machine holds one Edge — so a port list here would be addresses that
# answer nothing, and a deployment that reads as broken to whoever dialled them.
#
# ★ -control-plane-peers IS NOT OPTIONAL HERE. Through the front door one control plane and three look the
# same, so the check counts what it is given: omit it and a redundant authority reports as a single point of
# failure. Name one entry per MACHINE that holds a control plane — which is one per machine, and one per
# region.
#   dsse-install -bootstrap-admin -dir . -control-plane https://admin.<host>:${DSSE_REGION_PORT:-18443} -admin-email <address> 2>&1 | tee credentials.txt
#   docker compose --env-file deployment.env up -d --force-recreate dsse-control-plane-a dsse-edge-a
#
# ★ THE EDGES RESTART TOO. Closing the break-glass credential changes what the FLEET presents; an Edge still
# holding the old one is answered 401 on every pull and goes on serving what it booted with, so nothing can
# enrol — measured, three checks red on a deployment that had been all-green a minute earlier.
# ★ AND CAPTURE THE OUTPUT: the password, second factor, recovery codes and API token are shown once and
# stored nowhere, and this same command closes the only other way in.
#
# ★ THE NAMES ARE NOT DECORATION. Every plane is behind ONE port and told apart by the name in the
# ClientHello, so reaching the control plane by the host's bare name lands on the agent plane instead. Those
# names have to resolve to this host.
#   docker compose --env-file deployment.env restart dsse-control-plane dsse-edge
#
# The restart is what disarms the break-glass credential: the script reads the marker -bootstrap-admin wrote,
# and from then on arms nothing. Until that restart the deployment still has an owner credential attributed
# to a synthetic principal.
`
	// ★ EVERY SERVICE'S LOG IS BOUNDED, CENTRALLY. See a_deployment_may_not_fill_its_own_disk.go — an
	// uncapped log took this whole deployment down, and a per-service list is a list somebody adds to
	// without remembering.
	body = strings.ReplaceAll(body, "__DOORWAY_DEPENDS__", doorwayDepends)
	// ★ EVERY MEMBER OF THE DEPLOYMENT'S DATABASE, so libpq can find the primary itself. See
	// the_client_finds_the_primary.go for the door this replaces.
	body = strings.ReplaceAll(body, databaseHostsPlaceholder, databaseHostList(dir))
	return os.WriteFile(path, []byte(boundEveryServicesLog(body)), 0o644)
}

// composeBodyFor renders a machine's compose WITHOUT writing it.
//
// ★★★ A CARRY HAS TO KNOW WHAT THE RECEIVING MACHINE WILL RUN, AND ONLY THE COMPOSE KNOWS (2026-08-27). Each
// component is its own hardware and its own operating system, so nothing may be handed to a machine because
// another machine needs it. What a machine needs is exactly what ITS services mount and name — which is a
// property of the file that defines those services, and of nothing else. Rendering it in memory is what lets
// the carry answer that question for a machine other than the one the installer is standing on.
func composeBodyFor(dir string, shape machineShape) (string, error) {
	tmp, err := os.MkdirTemp("", "dsse-compose-shape")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tmp)
	// ★ RENDERED AGAINST THE REAL DIRECTORY, because the shape reads it — edgeFleetBackends looks at what the
	// operator configured there, and a render against an empty directory would answer a different question.
	// Only the OUTPUT goes somewhere temporary.
	path := filepath.Join(tmp, "docker-compose.yml")
	if err := composeFileTo(dir, path, shape); err != nil {
		return "", err
	}
	b, err := os.ReadFile(path)
	return string(b), err
}

// composeFileName is what report() names, kept beside the file so the two cannot drift.
func composeFileName() string { return "docker-compose.yml" }

// composeStateBearingServices is the four blocks below, in the order a region that holds state needs them.
//
// ★★★ SPLIT INTO PARTS ON 2026-08-27, so a JOINING region can hold state too. A second region that keeps a
// Postgres replica runs the same database and the same control planes — what it must NOT run is a second
// consensus store (there is one per deployment, with a member per region) and a second database
// initialisation (the database already exists; running it again against a local replica waits forever on a
// front door with no primary behind it). Before the split the only joining shape was one that holds no state
// at all, which is not a region anybody can fail over to.
// ★ WHAT A CONTROL PLANE WAITS FOR, which is not the same in the two shapes. A region that INITIALISES the
// database waits for that to finish; a region that joins an existing cluster has nothing to initialise, and
// compose refuses a file naming a service it does not define — "depends on undefined service" — so the
// dependency travels with the block that provides it.
const (
	cpDependsPlaceholder = "__CP_DEPENDS_ON_DB_INIT__"
	// ★★★ AND THE PAIR IS RETRIED, for the same reason dsse-postgres-init is. This process FATALS when its
	// database cannot be opened — deliberately: a control plane answering from a store it could not read
	// would be worse. But "starts once, fails, stays dead" turns a database that is thirty seconds late into
	// a region with no control plane until a person notices. Ordering says when to start; this says what to
	// do when the order was not enough.
	//
	// ★★ IT RIDES ON THE PLACEHOLDER SO BOTH HALVES GET IT (2026-08-29, an hour after the first version).
	// composeControlPlanePair is ONE string containing dsse-control-plane-a AND -b; the first attempt wrote
	// the line into the -a block by hand, so -a was retried and -b was not. On the live build that read as a
	// region whose control plane recovered and whose standby stayed dead — a pair that is half-fixed, which is
	// worse than neither, because it looks like it works. The placeholder is replaced in both, so a policy
	// attached to it cannot be given to one and forgotten on the other.
	cpRetries              = "\n    restart: unless-stopped"
	cpWaitsForDatabaseInit = "\n      dsse-postgres-init: { condition: service_completed_successfully }" + cpRetries
	// ★★★ A JOINING REGION'S CONTROL PLANES WAITED FOR NOTHING AND DIED ON THEIR OWN DATABASE (2026-08-29,
	// measured on a two-region build):
	//
	//   open CP-state blob store: ping cp-state blob db: dial tcp: lookup postgres on 127.0.0.11:53: no such host
	//
	// The founding shape waits for dsse-postgres-init, which by definition means the database is answering.
	// The joining shape correctly does not run that init — and in dropping it, dropped its ONLY ordering
	// dependency, so both control planes started before the database's front door existed, failed to resolve
	// it, and exited. Compose reported success; `docker ps` showed a control-plane machine whose control
	// planes are simply absent, which is what the fleet view also shows for a region that is switched off.
	//
	// It is a RACE, which is why it survived a build the day before: that time the door happened to win.
	// ★ AND THE CONTROL PLANE WAITS FOR THE DATABASE MEMBER ON THIS MACHINE. The door it used to wait for is
	// gone; the client is given every member and picks the writable one.
	cpWaitsForTheDatabaseDoor = "\n      postgres: { condition: service_started }" + cpRetries
	cpWaitsForNothing         = " {}" + cpRetries
)

func stateBearingServices() string { return stateBearingServicesFor(false) }

// stateBearingServicesFor renders the founding region. spansRegions says this deployment keeps state in more
// than one region, which is what decides whether the store here is the whole cluster or one member of it.
func stateBearingServicesFor(spansRegions bool) string {
	// ★★★ ONE MEMBER, ON ONE MACHINE TOO (2026-09-03, the operator's decision on seeing what a one-machine
	// deployment actually runs: "one machine, and three of them? that is wrong — it has to be one").
	//
	// Three members here used to be the answer for a deployment that IS one host, reasoning that it survives a
	// container restart while losing the host loses everything either way. Both halves are true and the trade
	// is still bad:
	//
	//   - what it protects against is ONE etcd process dying while the machine lives, which is not what
	//     happens. What happened on this lab was every container being recreated together, and three members
	//     died exactly as one would have;
	//   - it costs three processes, three data directories and three pairs of published ports on the SMALLEST
	//     shape this product ships, which is most of what an operator sees when they look at the machine;
	//   - and it reads as redundancy. Someone looking at the ports counts three and concludes the store can
	//     lose one. The store can lose one PROCESS; the deployment cannot lose the one place it is in.
	//
	// A single member costs the seconds it takes to restart, during which nothing can be elected — and on a
	// one-machine deployment there is nothing to elect it to.
	body := composeConsensusStoreOneMember + "\n" +
		composeDatabaseWith("\n    depends_on: [dsse-store-a]") + "\n" + composeDatabaseDoor + "\n" +
		composeDatabaseInit + "\n" +
		strings.ReplaceAll(composeControlPlanePair, cpDependsPlaceholder, cpWaitsForDatabaseInit)
	return withOneMemberStoreDefaults(body)
}

// ★★★ A ONE-MEMBER STORE'S DEFAULTS NAME ONE MEMBER (2026-09-02, caught by the gate that asks whether
// anything in this file dials a name the file does not define).
//
// The store block and the database block both carry three-member defaults — dsse-store-a, -b and -c — and a
// deployment whose state spans regions renders only the first. In the field the plan sets
// DSSE_ETCD_INITIAL_CLUSTER and DSSE_ETCD_HOSTS, so the defaults never showed; a deployment that lost those
// two variables would have had etcd and Patroni waiting on two members that do not exist, which reads as a
// slow start rather than as a broken file.
func withOneMemberStoreDefaults(body string) string {
	return strings.NewReplacer(
		"dsse-store-a=http://dsse-store-a:2380,dsse-store-b=http://dsse-store-b:2380,dsse-store-c=http://dsse-store-c:2380",
		"dsse-store-a=http://dsse-store-a:2380",
		"'dsse-store-a:2379','dsse-store-b:2379','dsse-store-c:2379'",
		"'dsse-store-a:2379'",
	).Replace(body)
}

// composeJoiningStateBearingServices is what a region that JOINS the deployment's database renders: the same
// database and control planes, without the consensus store and without re-initialising a database that exists.
//
// ★ ITS MEMBERS COME UP AS REPLICAS BY THEMSELVES. Patroni sees a cluster that already has a primary and
// makes them followers — there is nothing to configure for that, and nothing that decides it locally.
func joiningStateBearingServices() string { return joiningStateBearingServicesFor(false) }

// joiningStateBearingServicesFor renders a region that JOINS the deployment's database. spansRegions says the
// consensus store has a member in each state-bearing region — including this one.
//
// ★★★ IT HELD NO MEMBER AT ALL, WHICH IS WHY THE STORE WAS A SINGLE POINT OF FAILURE (2026-08-31). The
// comment beside it has always said "one per deployment, a member per region", and what it rendered was none:
// a joining region was a CLIENT of the founding region's store. That is coherent and it is not redundant —
// the founding region's loss takes the deployment's authority with it, however many regions exist.
func joiningStateBearingServicesFor(spansRegions bool) string {
	if spansRegions {
		// ★ AND IT WAITS FOR ITS OWN MEMBER, not for the cluster. The member joins a cluster that already
		// exists (ETCD_INITIAL_CLUSTER_STATE=existing), so what has to be up here is the one process here.
		return withOneMemberStoreDefaults(composeConsensusStoreOneMember + "\n" +
			composeDatabaseWith("\n    depends_on: [dsse-store-a]") + "\n" + composeDatabaseDoor + "\n" +
			strings.ReplaceAll(composeControlPlanePair, cpDependsPlaceholder, cpWaitsForTheDatabaseDoor))
	}
	// ★ NO STORE DEPENDENCY: this region runs no consensus store, and naming one it does not define makes
	// the whole project invalid.
	return composeDatabaseWith("") + "\n" + composeDatabaseDoor + "\n" +
		strings.ReplaceAll(composeControlPlanePair, cpDependsPlaceholder, cpWaitsForTheDatabaseDoor)
}

// composeConsensusStoreOneMember is the first member ALONE: the whole store up to the second member, which is
// where the two that merge its anchor begin.
//
// ★★★ WHY ONE, AND WHEN (2026-08-31). Three members on one host is right for a deployment that IS one host —
// it survives a container restart, and losing the host loses everything either way. It is wrong the moment
// the deployment keeps state in more than one region: three votes in one place and one in each of the others
// means losing that place loses the quorum, so the deployment with more machines tolerates fewer failures.
// The canonical footprint is a member per state-bearing region, which is what this renders.
//
// ★ DERIVED RATHER THAN COPIED. A second literal would drift from the first, and the settings above it — the
// encryption, the advertise URLs, the published ports, the reasons for each — are the ones that took the
// longest to get right.
var composeConsensusStoreOneMember = func() string {
	const secondMember = "\n  dsse-store-b:"
	i := strings.Index(composeConsensusStore, secondMember)
	if i < 0 {
		// Not reachable while the store renders three members, and a test holds that. Returning the whole
		// store is the safe answer if it ever is: a cluster with too many members in one place is a worse
		// deployment, and a compose file naming a service it does not define is not a deployment at all.
		return composeConsensusStore
	}
	return composeConsensusStore[:i] + "\n"
}()

const composeConsensusStore = `  # ★★★ THE CONNECTION TO IT IS ENCRYPTED, AND IT HAS TO BE SAID. With sslmode=disable the authority's
  # entire durable state — every one-time decision, every identity claim, the enrolled inventory — crosses the
  # network in the clear, and nothing says so. What catches it is not a warning: a real Postgres image refuses
  # an unencrypted connection by default and the control plane does not start.
  #
  # ★ sslmode=require ENCRYPTS AND DOES NOT AUTHENTICATE. It stops a passive reader on the network and does
  # not stop an active one that can answer as the database. Verifying the database's certificate against this
  # deployment's own anchor is the next step and needs the cluster to present one this deployment issued.
  # ★★★ THE DEPLOYMENT'S DATABASE, AND WHY IT IS SIX CONTAINERS. A control plane OWNS its Postgres, so an
  # authority that is not a single point of failure means a DATABASE that is not one — two control-plane
  # processes in front of one database are one control plane with two front ends, and the leadership advisory
  # lock lives in that same database, so losing it loses leadership as well as the state.
  #
  # ★★★ AND PROMOTION HAS TO BE AUTOMATIC OR IT IS NOT FAILOVER. A replica somebody promotes by hand is a
  # backup: it survives the DATA and not the OUTAGE. So the cluster manages itself — it detects the primary is
  # gone, decides, and promotes, and the front door follows that decision rather than making it.
  #
  # ★ THE THREE STORE NODES ARE WHAT THE DECISION COSTS. The promotion decision needs a quorum, or two nodes
  # each convinced they are the primary write two divergent histories. Three tolerate losing one. One would be
  # worse than none: a cluster that loses its store demotes the primary to read-only rather than risk that
  # split, so a single store node is a single point of failure for the whole database, not only for failover.
  #
  # ★ IT BELONGS TO THE CONTROL PLANE, and is not a service beside it. Nothing else in this deployment may
  # connect to it — an Edge holds no database, which is what lets a fleet grow and shrink without a migration.
  dsse-store-a: &dsse-store
    image: ${DSSE_ETCD_IMAGE:-quay.io/coreos/etcd:v3.5.15}
    # ★ A REGION THAT REBOOTS MUST COME BACK. Without a policy Docker starts nothing when the daemon does, and
    # "on-failure" declines a container that was stopped cleanly — which is every container on a planned
    # restart. A node brought back then serves its door with its Edge and nothing behind it, and the fleet
    # view reads that Edge and calls the region current.
    restart: unless-stopped
    environment: &dsse-store-env
      # ★★★ WHO THE MEMBERS ARE IS THE DEPLOYMENT'S ANSWER, NOT THIS FILE'S. These were three
      # container aliases, which is exactly right on one host and unreachable from anywhere else — so the
      # store could never have a member in another region, which is what the comment above it has always
      # said it should have. The default keeps the one-host reference byte for byte.
      #
      # ★ AND THE STATE MATTERS AS MUCH AS THE LIST. A static three-member bootstrap needs all three machines
      # at once, and the documented install order is sequential — the founding region would stop being able
      # to finish on its own. So a joining member is added to a running cluster and comes up with
      # ETCD_INITIAL_CLUSTER_STATE=existing, which means redundancy arrives when the THIRD member joins and
      # not before. Anything reporting on this deployment has to say that rather than call two members green.
      ETCD_INITIAL_CLUSTER: ${DSSE_ETCD_INITIAL_CLUSTER:-dsse-store-a=http://dsse-store-a:2380,dsse-store-b=http://dsse-store-b:2380,dsse-store-c=http://dsse-store-c:2380}
      ETCD_INITIAL_CLUSTER_STATE: ${DSSE_ETCD_INITIAL_CLUSTER_STATE:-new}
      ETCD_INITIAL_CLUSTER_TOKEN: dsse-database
      ETCD_LISTEN_PEER_URLS: ${DSSE_ETCD_LISTEN_PEER_URLS:-http://0.0.0.0:2380}
      ETCD_LISTEN_CLIENT_URLS: ${DSSE_ETCD_LISTEN_CLIENT_URLS:-http://0.0.0.0:2379}
      # ★★★ TLS, AND WHY IT IS EMPTY BY DEFAULT. etcd reads an empty file setting as "no TLS",
      # which is the right answer for a deployment on one host: these members talk over a container network
      # that never leaves the machine, and a certificate there protects nothing while being one more thing to
      # rotate. The moment the store has a member in another region they talk across whatever is between the
      # two, and what crosses is which database is primary — so the plan fills these in exactly when it fills
      # in members elsewhere. See the_store_has_its_own_authority.go.
      #
      # ★ PEER AND CLIENT ARE SEPARATE SETTINGS AND BOTH MATTER. Peer is members to each other; client is
      # Patroni to the store. Securing one and leaving the other is a door locked on one side.
      ETCD_TRUSTED_CA_FILE: ${DSSE_ETCD_TRUSTED_CA_FILE:-}
      ETCD_CERT_FILE: ${DSSE_ETCD_CERT_FILE:-}
      ETCD_KEY_FILE: ${DSSE_ETCD_KEY_FILE:-}
      ETCD_CLIENT_CERT_AUTH: ${DSSE_ETCD_CLIENT_CERT_AUTH:-false}
      ETCD_PEER_TRUSTED_CA_FILE: ${DSSE_ETCD_PEER_TRUSTED_CA_FILE:-}
      ETCD_PEER_CERT_FILE: ${DSSE_ETCD_PEER_CERT_FILE:-}
      ETCD_PEER_KEY_FILE: ${DSSE_ETCD_PEER_KEY_FILE:-}
      # ★ A PEER THAT IS NOT ASKED FOR A CERTIFICATE IS A PEER ANYBODY CAN BE. With peer TLS on, this is what
      # makes the certificate mean something rather than merely encrypt.
      ETCD_PEER_CLIENT_CERT_AUTH: ${DSSE_ETCD_PEER_CLIENT_CERT_AUTH:-false}
      # ★ THE MEMBER'S NAME, WHICH IS THE CLUSTER'S AND NOT THIS HOST'S. Two regions each rendering this
      # file would otherwise both call themselves dsse-store-a, and a cluster cannot hold one name twice.
      ETCD_NAME: ${DSSE_ETCD_A_NAME:-dsse-store-a}
      # Where the volume above is mounted. etcd's default is ${ETCD_NAME}.etcd in the working directory, which
      # is inside the container: naming it puts the data on the volume and not in the container's own layer.
      ETCD_DATA_DIR: /data
      ETCD_INITIAL_ADVERTISE_PEER_URLS: ${DSSE_ETCD_A_PEER_ADVERTISE:-http://dsse-store-a:2380}
      # ★★★ WHAT A CLIENT IN ANOTHER REGION IS TOLD TO COME BACK TO (measured by joining one).
      # A client reaches the store on the address its operator configured, and then asks the CLUSTER for its
      # members and uses what it is told from then on. What it was told is this line — a container name on
      # THIS machine's compose network — so a joining region's Patroni connected once, refreshed its machine
      # list, and reported
      #
      #	etcd.EtcdConnectionFailed: No more machines in the cluster
      #
      # naming nothing the operator had configured. On one host the container name is exactly right, which is
      # why it survived; across machines it is an address only this machine has.
      ETCD_ADVERTISE_CLIENT_URLS: ${DSSE_ETCD_A_ADVERTISE:-http://dsse-store-a:2379}
    # ★★★ REACHABLE FROM ANOTHER REGION, OR A SECOND REGION CANNOT HOLD STATE. A region that
    # keeps a Postgres replica runs a Patroni member, and a Patroni member that cannot reach this consensus
    # store cannot be told it may be promoted — so it is not a replica anybody can fail over TO. Until this
    # port existed, nothing outside this compose network could reach the store at all, which is why the only
    # shape a joining region had was one that holds no state.
    #
    # ★ THE DEFAULT BINDS TO LOOPBACK, like the database beside it. Widening it is an explicit act, and it
    # should be an address only the deployment's other regions can dial: this store decides which database
    # becomes primary, so reaching it is reaching the deployment's authority.
    # ★ THE MEMBER'S OWN MATERIAL. The same three paths on every machine, with this machine's bytes in them:
    # packing substitutes them, so no machine carries another member's key. Absent on a one-host deployment,
    # where the settings above are empty and nothing reads them.
` + composeAuthorityAliases + `    volumes:
      # ★★★ THE CONSENSUS STORE NEEDS SOMEWHERE DURABLE TO KEEP ITS DATA. Without it, recreating the
      # containers brings the cluster back as ONE member while the others refuse to start with
      # "member count is unequal", and they stay that way.
      #
      # Every other stateful service here has a named volume — pg-a, clickhouse-data, archive-data,
      # cp-a-state, edge-a-state. This one had three read-only certificates and nothing else, so etcd's data
      # directory lived inside the container. Recreating it — which this installer's own procedures ask for,
      # to close the break-glass credential, to pick up a new build, to add a machine — DESTROYED the
      # deployment's consensus state. The founding member then re-bootstrapped as a fresh single-member
      # cluster and every other member was locked out of a cluster that no longer knew them.
      #
      # This is the store that decides which database is primary. Losing it is losing the deployment's
      # authority, and it was one docker compose up -d --force-recreate away, on every deployment.
      - "store-a-state:/data"
      - "./store-ca.pem:/deployment/store-ca.pem:ro"
      - "./store-member.pem:/deployment/store-member.pem:ro"
      - "./store-member-key.pem:/deployment/store-member-key.pem:ro"
    # ★★★ AND THE PEER PORT, WHICH WAS NEVER PUBLISHED. Only 2379 was, so a member in another
    # region could be TOLD about this one and could never reach it: peers gossip on 2380. The client port
    # being reachable and the peer port not is the shape where a cluster looks configured and cannot form.
    ports:
      - "${DSSE_ETCD_A_PUBLISH:-127.0.0.1:12379}:2379"
      - "${DSSE_ETCD_A_PEER_PUBLISH:-127.0.0.1:12390}:2380"
  dsse-store-b:
    <<: *dsse-store
    environment:
      <<: *dsse-store-env
      ETCD_NAME: dsse-store-b
      ETCD_INITIAL_ADVERTISE_PEER_URLS: ${DSSE_ETCD_B_PEER_ADVERTISE:-http://dsse-store-b:2380}
      ETCD_ADVERTISE_CLIENT_URLS: ${DSSE_ETCD_B_ADVERTISE:-http://dsse-store-b:2379}
    # ★ ITS OWN PUBLISHED PORT, because the anchor above carries one. Merging <<: *dsse-store without saying
    # this would give all three members the SAME host port and none of them would start — the second binds
    # what the first holds. A member that inherits an address is not a member, it is a collision.
    ports:
      - "${DSSE_ETCD_B_PUBLISH:-127.0.0.1:12380}:2379"
      - "${DSSE_ETCD_B_PEER_PUBLISH:-127.0.0.1:12391}:2380"
  dsse-store-c:
    <<: *dsse-store
    environment:
      <<: *dsse-store-env
      ETCD_NAME: dsse-store-c
      ETCD_INITIAL_ADVERTISE_PEER_URLS: ${DSSE_ETCD_C_PEER_ADVERTISE:-http://dsse-store-c:2380}
      ETCD_ADVERTISE_CLIENT_URLS: ${DSSE_ETCD_C_ADVERTISE:-http://dsse-store-c:2379}
    # ★ ITS OWN PUBLISHED PORT, because the anchor above carries one. Merging <<: *dsse-store without saying
    # this would give all three members the SAME host port and none of them would start — the second binds
    # what the first holds. A member that inherits an address is not a member, it is a collision.
    ports:
      - "${DSSE_ETCD_C_PUBLISH:-127.0.0.1:12381}:2379"
      - "${DSSE_ETCD_C_PEER_PUBLISH:-127.0.0.1:12392}:2380"
`

// composeDatabaseWith renders the database pair. storeDependency is what its members wait for, which is
// nothing at all in a region that does not run the consensus store.
//
// ★★★ A JOINING REGION'S DATABASE WAITED FOR A STORE IN ANOTHER REGION (2026-08-27, found by carrying a
// second region's control-plane machine and reading the file). There is ONE consensus store per deployment
// with a member per region, so a joining region defines none — and this line named all three anyway. Compose
// refuses a project that names an undefined service, so the shape that exists FOR a second region rendered a
// file that could not start at all.
//
// ★ THE GUARD EXISTED AND WAS BLIND TO THE FORM. assertNoDanglingDependsOn read the mapping form,
// "name: { condition: … }", and this is the list form. Both are compose; only one was checked. That is the
// second time in one day a check missed a defect because a generated file uses both list forms.
//
// ★ AND WAITING FOR IT WAS NEVER THE MECHANISM ANYWAY. The members find the store through DSSE_ETCD_HOSTS,
// which a joining region MUST set to the deployment's; depends_on only orders start-up on one machine.
func composeDatabaseWith(storeDependency string) string {
	return `  dsse-postgres-a: &dsse-postgres
    image: ${DSSE_POSTGRES_IMAGE:-ghcr.io/zalando/spilo-16:3.2-p2}` + storeDependency + `
    environment: &dsse-postgres-env
      SCOPE: dsse
      # ★★★ AND ITS NAME IN THE CLUSTER, WHICH TWO REGIONS WOULD OTHERWISE SHARE. Every region is
      # rendered from the same file, so both would call their members dsse-postgres-a and dsse-postgres-b —
      # and a Patroni cluster identifies members BY NAME. Two members with one name is not redundancy; it is
      # two machines each believing the other's state is its own. The default is the service name, which is
      # right for the region that founds the cluster and wrong for every region that joins it.
      #
      # ★★ AND IT HAD TO MOVE, BECAUSE PATRONI_NAME WAS IGNORED (measured: every member in a
      # running cluster was named after its container id, and a restart therefore left the old name behind as
      # a member in an unknown state). The image writes Patroni's configuration itself; what it merges over
      # its own answer is SPILO_CONFIGURATION, below.
      PATRONI_NAME: ${DSSE_PG_A_NAME:-dsse-postgres-a}
      PGVERSION: "16"
      # ★★★ WHERE THE CONSENSUS IS, WHICH IS NOT ALWAYS HERE. A region that joins the deployment
      # runs Patroni members against the deployment's ONE consensus store, whose members live one per region —
      # so this has to be answerable from outside. The default names the local three, which is right for the
      # first region and wrong for every other one.
      ETCD3_HOSTS: "${DSSE_ETCD_HOSTS:-'dsse-store-a:2379','dsse-store-b:2379','dsse-store-c:2379'}"
      # ★★★ SPILO PASSES ANY ETCD3_* STRAIGHT INTO PATRONI'S etcd3 SECTION (verified against
      # configure_spilo.py), which is why these are named this way and not PATRONI_ETCD3_* — the
      # image builds Patroni's configuration itself and PATRONI_* loses here, as PATRONI_NAME did.
      #
      # ★ THE PROTOCOL IS ITS OWN SETTING. Patroni's host list is bare host:port; putting a scheme in it is
      # not how it is read, so a deployment that "configured TLS" by writing https:// into the hosts would
      # talk plaintext and look configured.
      ETCD3_PROTOCOL: ${DSSE_ETCD_CLIENT_SCHEME:-http}
      ETCD3_CACERT: ${DSSE_ETCD_CLIENT_CACERT:-}
      ETCD3_CERT: ${DSSE_ETCD_CLIENT_CERT:-}
      ETCD3_KEY: ${DSSE_ETCD_CLIENT_KEY:-}
      PGPASSWORD_SUPERUSER: ${PG_SUPERUSER_PASSWORD:?PG_SUPERUSER_PASSWORD is in deployment.env — pass --env-file deployment.env}
      PGPASSWORD_ADMIN: ${PG_SUPERUSER_PASSWORD}
      PGPASSWORD_STANDBY: ${PG_SUPERUSER_PASSWORD}
      # ★★★ WHAT THE OTHER MEMBERS ARE TOLD TO COME BACK TO (the same defect the consensus store
      # had, one layer down). A Patroni member writes its own address into the cluster, and every other member
      # — including one in ANOTHER REGION — uses what it finds there: to call this node's API, and to stream
      # from it when it is the primary. Left to itself it writes the address of this machine's compose
      # network, which exists on this machine and nowhere else, so a replica in another region has a leader it
      # can see in the cluster state and cannot reach.
      #
      # ★ THE DEFAULT IS THIS SERVICE'S OWN NAME, which is what the container network answers to and what a
      # one-host deployment has always effectively used. Set it to an address the OTHER regions can dial, and
      # publish the ports below to match, when the deployment spans machines.
      # ★ THROUGH SPILO_CONFIGURATION, BECAUSE PATRONI_* LOSES HERE (measured). The image builds
      # Patroni's configuration file itself and writes connect_address from the container's own IP, so
      # PATRONI_POSTGRESQL_CONNECT_ADDRESS arrived in the environment, was visible in the process env, and
      # appeared nowhere in /home/postgres/postgres.yml. What the image merges over its own answer is this.
      SPILO_CONFIGURATION: '{name: "${DSSE_PG_A_NAME:-dsse-postgres-a}", postgresql: {connect_address: "${DSSE_PG_A_ADVERTISE:-dsse-postgres-a:5432}"}, restapi: {connect_address: "${DSSE_PG_A_API_ADVERTISE:-dsse-postgres-a:8008}"}}'
    # ★★★ AND REACHABLE, WHICH IS A SEPARATE ACT FROM BEING ADVERTISED. A member that announces an address
    # nothing listens on is the same outage with a better error message. Loopback by default, like every other
    # published port here: widening it should reach the deployment's other regions and nothing else, because a
    # database published by accident is the thing in this file worth the most to somebody else.
    ports:
      - "${DSSE_PG_A_MEMBER_PUBLISH:-127.0.0.1:15433}:5432"
      - "${DSSE_PG_A_API_PUBLISH:-127.0.0.1:18008}:8008"
` + composeAuthorityAliases + `    volumes:
      - "pg-a:/home/postgres/pgdata"
      # ★ WHAT PATRONI VERIFIES THE STORE AGAINST, and the identity it presents when the store asks for one.
      - "./store-ca.pem:/deployment/store-ca.pem:ro"
      - "./store-member.pem:/deployment/store-member.pem:ro"
      - "./store-member-key.pem:/deployment/store-member-key.pem:ro"
  # ★★★ ONE DATABASE MEMBER PER MACHINE. A Patroni pair sharing a host survives a process crash and not the
  # host, and this deployment replicates ACROSS machines — the database door below already names the members
  # in the other regions — so the member that matters is the one on the next machine, not one beside this.
`
}

// ★★★ AND IT REACHES THE DATABASE BY THE DATABASE'S OWN NAME (2026-09-02). Every psql below said `-h postgres`
// — the local haproxy that fronted a PAIR of Postgres members on one machine and forwarded to whichever was
// primary. The operator retired that pair ("neither Postgres nor the control plane needs a haproxy in this
// shape"), and this block kept dialling the door that used to be there. It has `restart: on-failure`, so it
// would not have failed loudly once: it would have retried forever, and a deployment whose role and database
// were never created is a deployment whose control plane cannot start.
//
// There is one member per region now, and it is the primary, so the name is the member's.
const composeDatabaseDoor = `  # ★★★ THIS DOOR IS HOW A CLIENT REACHES THE PRIMARY, AND IT IS NOT THE LOCAL PROXY IT RESEMBLES.
  #
  # A machine running TWO Postgres members behind a proxy of its own would not need one — that pair is not
  # this shape. This door health-checks Patroni's GET /primary across every member of the deployment, in
  # every region, and forwards to the one that answers 200. The deployment has ONE cluster spanning its
  # regions, so a region's own member is a replica most of the time, and without this every client is pointed
  # at a follower:
  #
  #	ERROR:  cannot execute GRANT ROLE in a read-only transaction         (the database initialiser)
  #	open CP-state blob store: ping cp-state blob db: ... no such host    (the control plane, on the DSN
  #	                                                                     that replaced it)
  #
  # ★ AND THE CLIENT CANNOT DO IT INSTEAD. libpq finds the primary itself when it is given every member and
  # target_session_attrs=read-write — psql does, and dsse-postgres-init uses it — but this product's Go
  # clients are lib/pq, which supports ONE host and reads a comma-separated list as a single hostname to
  # resolve. So the door stays, and the reason it stays is written here.
  postgres:
    image: ${DSSE_HAPROXY_IMAGE:-haproxy:2.9-alpine}
    # ★ A REGION THAT REBOOTS MUST COME BACK. Without a policy Docker starts nothing when the daemon does, and
    # "on-failure" declines a container that was stopped cleanly — which is every container on a planned
    # restart. A node brought back then serves its door with its Edge and nothing behind it, and the fleet
    # view reads that Edge and calls the region current.
    restart: unless-stopped
    # ★★★ THE FRONT DOOR COULD NOT START ON AN ORDINARY HOST (measured the first time this
    # deployment ran with one component per machine):
    #
    #   [ALERT] (1) : [haproxy.main] Cannot raise FD limit to 131109, limit is 32768.
    #
    # haproxy reserves file descriptors for maxconn across every proxy in the file, and asks the kernel for
    # them at start-up. A default Linux host allows far fewer, so it exits — and the region's doorway is the
    # one service whose absence looks like the whole deployment being down.
    ulimits:
      nofile: { soft: 200000, hard: 200000 }
    depends_on: [dsse-postgres-a]
    volumes:
      - "./haproxy-postgres.cfg:/usr/local/etc/haproxy/haproxy.cfg:ro"
    # ★★★ NOT PUBLISHED UNLESS THE DEPLOYMENT NEEDS IT TO BE. The default binds to loopback, which reaches
    # exactly one machine: the one already running the database. Widening it is an explicit act —
    # DSSE_PG_PUBLISH='10.0.0.7:15432' — because a database published by accident is the one thing in this
    # file that is worth the most to somebody else.
    #
    # ★ compose does NOT re-parse an interpolated value as YAML, so this cannot be "a list or nothing": the
    # slot has to be a port, and the safe choice is a port nobody outside this host can dial.
    ports: ["${DSSE_PG_PUBLISH:-127.0.0.1:15432}:5432"]
`

const composeDatabaseInit = `  # ★ THE DEPLOYMENT'S OWN ROLE AND DATABASE, created once against whichever node is primary. Idempotent and
  # restarted until it succeeds, because the cluster is still electing when compose first starts it — and an
  # init that runs once, fails, and is never retried is how a deployment comes up with no database to use.
  dsse-postgres-init:
    image: ${DSSE_PSQL_IMAGE:-postgres:16-alpine}
    depends_on: [dsse-postgres-a]
    restart: on-failure
    environment:
      PGPASSWORD: ${PG_SUPERUSER_PASSWORD}
    entrypoint: ["sh", "-c"]
    command:
      - |
        set -e
        psql "postgres://postgres@${DSSE_PG_HOSTS:-__PG_HOSTS__}/postgres?target_session_attrs=read-write" -c "DO \$\$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='dsse') THEN CREATE ROLE dsse LOGIN PASSWORD '${PG_PASSWORD}'; END IF; END \$\$;"
        psql "postgres://postgres@${DSSE_PG_HOSTS:-__PG_HOSTS__}/postgres?target_session_attrs=read-write" -tAc "SELECT 1 FROM pg_database WHERE datname='dsse'" | grep -q 1 || psql "postgres://postgres@${DSSE_PG_HOSTS:-__PG_HOSTS__}/postgres?target_session_attrs=read-write" -c "CREATE DATABASE dsse OWNER dsse"
        # ★ SO THE DEPLOYMENT CAN SEE WHETHER ITS OWN STATE IS REDUNDANT. pg_stat_replication is visible to
        # every role but its COLUMNS are null without this, so the control plane would read a cluster with a
        # streaming replica as having none — reporting a redundant authority as not redundant.
        psql "postgres://postgres@${DSSE_PG_HOSTS:-__PG_HOSTS__}/postgres?target_session_attrs=read-write" -c "GRANT pg_read_all_stats TO dsse"
        echo "the deployment's database and role exist"
`

const composeControlPlanePair = `  dsse-control-plane-a:
    image: ${DSSE_IMAGE:?set DSSE_IMAGE to the DSSE image this deployment runs}
    # ★★★ NAMED HERE ONLY WHEN IT EXISTS. A joining region runs no database initialisation — the
    # database it joins already has its role and schema — and compose refuses a file that names a service it
    # does not define: "depends on undefined service". So the dependency travels with the block that provides
    # it, rather than being written once and being wrong in one of the two shapes.
    depends_on:__CP_DEPENDS_ON_DB_INIT__
    environment:
      DSSE_EDGE_BINARY: ${DSSE_BINARY:-/usr/local/bin/dsse-edge}
      # ★ THE CLIENT FINDS THE PRIMARY. DSSE_PG_HOSTS lists every member of the deployment's cluster and
      # target_session_attrs=read-write picks the one that can be written to — no proxy in between.
      DSSE_POSTGRES_DSN: postgres://dsse:${PG_PASSWORD}@${DSSE_PG_HOST:-postgres:5432}/dsse?sslmode=require
      DSSE_MIGRATION_DIR: ${DSSE_MIGRATION_DIR:-/app/migrations}
      DSSE_CP_STATE_DIR: /var/lib/dsse
      # Which machine this is. Screens that report a per-node answer name the node that produced it, so a
      # reader can go and ask that node; without this a control plane cannot say who it is.
      DSSE_NODE_NAME: ${DSSE_NODE_NAME:-}
      DSSE_NODE_ADDRESS: ${DSSE_NODE_ADDRESS:-}
      DSSE_EDGE_REGION: ${DSSE_EDGE_REGION:-}
      DSSE_CLICKHOUSE_ENDPOINT: ${DSSE_CLICKHOUSE_ENDPOINT:-http://dsse-clickhouse:8123}
      CLICKHOUSE_PASSWORD: ${CLICKHOUSE_PASSWORD:?set CLICKHOUSE_PASSWORD}
      DSSE_ARCHIVE_ENDPOINT: ${DSSE_ARCHIVE_ENDPOINT:-dsse-archive:9000}
      DSSE_ARCHIVE_BUCKET: ${DSSE_ARCHIVE_BUCKET:-dsse-audit-archive}
      MINIO_ROOT_USER: ${MINIO_ROOT_USER:-dsse-archive}
      MINIO_ROOT_PASSWORD: ${MINIO_ROOT_PASSWORD:?set MINIO_ROOT_PASSWORD}
    volumes:
      # ★★★ WHAT THIS NODE READS, AND NOTHING ELSE. See the note on the Edge above: the whole-directory mount
      # this replaces handed the deployment's root CA key to every service that had one.
      - "./start-control-plane.sh:/deployment/start-control-plane.sh:ro"
      - "./deployment.env:/deployment/deployment.env:ro"
      - "./policy.json:/deployment/policy.json:ro"
      - "./policy-egress.json:/deployment/policy-egress.json:ro"
      - "./policy-bundle.json:/deployment/policy-bundle.json:ro"
      - "./schemas:/deployment/schemas:ro"
      - "./deployment-anchor.pem:/deployment/deployment-anchor.pem:ro"
      # ★ The interception root, CERTIFICATE ONLY — see the same mount on the single control plane below.
      - "./lantern_dsse_interception_root_ca.pem:/deployment/lantern_dsse_interception_root_ca.pem:ro"
      - "./management-ca.crt:/deployment/management-ca.crt:ro"
      - "./management.crt:/deployment/management.crt:ro"
      - "./management.key:/deployment/management.key:ro"
      - "./device-ca-registry.json:/deployment/device-ca-registry.json"
      - "./audit-ingest-authority.json:/deployment/audit-ingest-authority.json"
      - "./agent-policy-signing.key:/deployment/agent-policy-signing.key:ro"
      - "./agent-update-signing.pub:/deployment/agent-update-signing.pub:ro"
      - "./runtime:/deployment/runtime"
      - "cp-a-state:/var/lib/dsse"
    # ★★★ ITS OWN ADMIN PORT IS NOT PUBLISHED, AND THE NODE IS STILL ASKABLE (measured: this was
    # listening on 0.0.0.0:19543 beside a door on 10.22.1.200:443).
    #
    # It was published because some questions are about a NODE and cannot be asked through a front door that
    # serves whichever node it likes — whether the authority is redundant, whether two control planes hold the
    # SAME authority. That is still true, and it is no longer the reason for a second way in: the region's
    # door carries a PER-NODE admin name (<region>-control-plane-a.admin.<host>) and routes it by SNI to that
    # one node. -verify asks exactly those names, through 443, and the peer doors in every other region reach
    # this region on 443 too. Nothing was dialling this port.
    #
    # ★ AND A MACHINE THAT RUNS A CONTROL PLANE ALWAYS RENDERS A DOORWAY — behindDoorway is Edges with no
    # control plane — so this is unconditional, unlike the Edge's ports, which a machine behind the door
    # still needs.
    expose: ["9443"]
    # ★ NOT PUBLISHED DIRECTLY. Everything reaches the control plane through the front door, which routes to
    # whichever node is the leader; publishing one node's own port would hand somebody an address that is
    # right only until a failover. The published ports are on the front door, and THEY are the one thing a
    # host gets a say in — another process may already hold 8443, which is not a reason to edit a generated
    # file.
    # ★★★ entrypoint, NOT command (found by running it). A DSSE image's entrypoint IS the binary,
    # so a command: is appended to it as an ARGUMENT: the script never runs, the binary starts with its own
    # defaults, and what comes out is "REFUSING TO START: this Edge has no control plane" — from the control
    # plane. A message that cannot be true, produced by a start script that was never executed.
    entrypoint: ["/deployment/start-control-plane.sh"]
  # ★★★ ONE CONTROL PLANE PER MACHINE, AND NO WARM STANDBY BESIDE IT. A second process from the same image
  # and the same configuration, on the SAME MACHINE, survives a process crash and nothing else: the machine
  # that dies takes the leader, the standby and the door in front of them together.
  #
  # The deployment answers the failure that matters one layer up. Every region holds a control plane and the
  # authority is ONE across them, elected through the consensus store — so losing a machine is losing one
  # candidate, not the authority. A standby beside the leader answers a question already answered, at the
  # cost of a process, a state volume and a backend on every machine.

  # ★★★ AND NO SEPARATE DOOR IN FRONT OF THEM. The region's 443 door already routes admin, authority and
  # Console by name, and already health-checks GET /leader across every region — so a second proxy behind it
  # would be the same question asked twice, on the same machine.
`

// composeJoiningRegionNote stands where the state-bearing services would be, in a region that holds none.
//
// ★ IT IS A NOTE AND NOT AN ABSENCE. A file that simply omits them reads as a rendering someone truncated;
// the reason a region has no database is a decision, and the deployment says which decision it was.
const composeJoiningRegionNote = `  # ★★★ THIS REGION HOLDS NO STATE, AND THAT IS THE SHAPE, NOT A REDUCTION. The deployment has ONE authority:
  # every control plane contends for the SAME advisory lock, and that lock can only be taken on the Postgres
  # primary — so the leader and the primary move together, inseparably, and there is exactly one of each for
  # the whole deployment however many regions it spans.
  #
  # A region that stood up its own consensus store and its own database would not be a second region. It would
  # be a second DEPLOYMENT: two leaders, each holding a lock on its own database, and one-time decisions taken
  # per region rather than per deployment — so "has this identity already enrolled" would have two answers, and
  # the identity claim's uniqueness would break exactly at the region boundary. A device moving between them
  # would meet an issuer it has never heard of.
  #
  # So there is no etcd here, no Postgres, no control plane. This region's Edges take their configuration from
  # the deployment's control plane, wherever leadership currently is, and carry traffic for the devices nearest
  # to them. Edges may live in more regions than state does; that is the point.
  #
  # ★ ADDING STATE HERE IS A DIFFERENT ACT. A state-bearing region carries three things together — a quorum
  # member of the deployment's consensus store, a REPLICA of its database, and a warm standby control plane —
  # and all three join what already exists rather than creating their own. That is not a flag on this file.

`

// composeControlPlaneOwnedWith renders what the control plane OWNS — its hot store, its archive and the
// Console. adminUpstream is where the Console reaches the deployment's authority.
func composeControlPlaneOwnedWith(adminUpstream, edgeUpstream string) string {
	return `  # ★★★ THE HOT STORE. The control plane owns three durable components — Postgres for shared state, this for
  # what the deployment decided, and an archive for keeping it — and a generated deployment had only the
  # first. So the path a record takes from the node that made it to the authority did not exist in anything
  # this installer produced: an Edge wrote records to its own disk and nothing carried them anywhere, and the
  # Console's every report read an empty store. A deployment that decides and cannot say what it decided is
  # not the product.
  #
  # ★ ITS SCHEMA IS MOUNTED FROM THIS DIRECTORY, and the installer wrote it there. ClickHouse applies whatever
  # is in /docker-entrypoint-initdb.d on FIRST boot only — so a schema change is a migration and not an edit,
  # and the deployment says so by shipping the files rather than by hiding them in an image.
  dsse-clickhouse:
    image: ${DSSE_CLICKHOUSE_IMAGE:-clickhouse/clickhouse-server:24-alpine}
    # ★ A REGION THAT REBOOTS MUST COME BACK. Without a policy Docker starts nothing when the daemon does, and
    # "on-failure" declines a container that was stopped cleanly — which is every container on a planned
    # restart. A node brought back then serves its door with its Edge and nothing behind it, and the fleet
    # view reads that Edge and calls the region current.
    restart: unless-stopped
    # ★ LOOPBACK BY DEFAULT, for the same reason the database is. A warm control plane in another
    # region writes what the deployment decided HERE while it holds leadership, so this has to be
    # reachable from there — and from nowhere else until somebody says so.
    ports: ["${DSSE_CLICKHOUSE_PUBLISH:-127.0.0.1:18123}:8123"]
    environment:
      CLICKHOUSE_DB: dsse
      CLICKHOUSE_USER: dsse
      CLICKHOUSE_PASSWORD: ${CLICKHOUSE_PASSWORD:?set CLICKHOUSE_PASSWORD - the hot store holds every record this deployment produces}
      CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT: "1"
    volumes:
      - "clickhouse-data:/var/lib/clickhouse"
      - "./clickhouse-init:/docker-entrypoint-initdb.d:ro"
    ulimits:
      nofile: { soft: 262144, hard: 262144 }

  # ★★★ THE COLD ARCHIVE. Long-term retention is not the same question as "what happened last week": a hot
  # store answers a screen and an archive answers an auditor, and one of them has to survive a retention
  # policy the other cannot. Object storage the deployment runs itself, because the list of things outside a
  # deployment is short — an identity provider and a customer's own interception root — and a
  # hyperscaler is not on it.
  dsse-archive:
    image: ${DSSE_MINIO_IMAGE:-minio/minio:latest}
    # ★ A REGION THAT REBOOTS MUST COME BACK. Without a policy Docker starts nothing when the daemon does, and
    # "on-failure" declines a container that was stopped cleanly — which is every container on a planned
    # restart. A node brought back then serves its door with its Edge and nothing behind it, and the fleet
    # view reads that Edge and calls the region current.
    restart: unless-stopped
    command: server /data --console-address ":9001"
    # ★ AND THE ARCHIVE, likewise: a standby elsewhere keeps the same history, in the same place.
    ports: ["${DSSE_ARCHIVE_PUBLISH:-127.0.0.1:19000}:9000"]
    environment:
      MINIO_ROOT_USER: ${MINIO_ROOT_USER:-dsse-archive}
      MINIO_ROOT_PASSWORD: ${MINIO_ROOT_PASSWORD:?set MINIO_ROOT_PASSWORD - the cold archive cannot be reached without it}
      # ★ THE IMAGE BAKES IN MINIO_ROOT_USER_FILE, a Docker-secrets pattern. With no such file present it
      # silently falls back to minioadmin:minioadmin — a deployment whose archive has the default password and
      # says nothing. Overriding the phantom *_FILE variables to empty is what makes the credentials above the
      # ones that are used.
      MINIO_ROOT_USER_FILE: ""
      MINIO_ROOT_PASSWORD_FILE: ""
      MINIO_ACCESS_KEY_FILE: ""
      MINIO_SECRET_KEY_FILE: ""
    volumes: ["archive-data:/data"]

  # ★★★ WHERE THE HISTORY CONVERGES. Three layers, three treatments: the
  # database replicates with automatic promotion, the HOT store is deliberately not replicated — that is the
  # one-sided window, and it is cheaper than writing a region's logs across an ocean — and the cold archive is
  # where both regions end up holding the same record.
  #
  # ★★ ASYNCHRONOUS AND AUTOMATIC. Asynchronous is fine here; automatic is what matters, and bucket
  # replication is both by nature. A replication an operator runs periodically is not an answer.
  #
  # ★ VERSIONING FIRST, OR THE RULE CANNOT EXIST. MinIO refuses to configure replication on a bucket without
  # it, and the refusal is easy to miss in a start-up log — so it is turned on here whether or not a peer is
  # ever configured, and the deployment does not depend on somebody remembering the order.
  dsse-archive-init:
    image: ${DSSE_MC_IMAGE:-minio/mc:latest}
    depends_on: [dsse-archive]
    restart: on-failure
    entrypoint: ["sh", "-c"]
    environment:
      MINIO_ROOT_USER: ${MINIO_ROOT_USER:-dsse-archive}
      MINIO_ROOT_PASSWORD: ${MINIO_ROOT_PASSWORD:?set MINIO_ROOT_PASSWORD}
      DSSE_ARCHIVE_BUCKET: ${DSSE_ARCHIVE_BUCKET:-dsse-audit-archive}
      # ★ THE OTHER REGION'S ARCHIVE, when there is one. Empty means this deployment has one region holding
      # state and there is nowhere to converge to — which is a fact about the deployment, not a failure, so
      # it is said and not treated as an error.
      DSSE_ARCHIVE_PEER_ENDPOINT: ${DSSE_ARCHIVE_PEER_ENDPOINT:-}
      DSSE_ARCHIVE_PEER_USER: ${DSSE_ARCHIVE_PEER_USER:-}
      DSSE_ARCHIVE_PEER_PASSWORD: ${DSSE_ARCHIVE_PEER_PASSWORD:-}
    command:
      - |
        set -e
        until mc alias set local http://dsse-archive:9000 "$$MINIO_ROOT_USER" "$$MINIO_ROOT_PASSWORD" >/dev/null 2>&1; do
          sleep 2
        done
        mc mb --ignore-existing "local/$$DSSE_ARCHIVE_BUCKET"
        mc version enable "local/$$DSSE_ARCHIVE_BUCKET"
        if [ -z "$$DSSE_ARCHIVE_PEER_ENDPOINT" ]; then
          echo "cold archive: no peer configured, so this region's record converges nowhere."
          echo "  That is correct for a deployment with one state-bearing region. Set DSSE_ARCHIVE_PEER_ENDPOINT"
          echo "  (and _USER/_PASSWORD) on both regions to make the two archives converge, asynchronously and"
          echo "  without anybody running anything."
          exit 0
        fi
        mc alias set peer "$$DSSE_ARCHIVE_PEER_ENDPOINT" "$${DSSE_ARCHIVE_PEER_USER:-$$MINIO_ROOT_USER}" "$${DSSE_ARCHIVE_PEER_PASSWORD:-$$MINIO_ROOT_PASSWORD}"
        mc mb --ignore-existing "peer/$$DSSE_ARCHIVE_BUCKET"
        mc version enable "peer/$$DSSE_ARCHIVE_BUCKET"
        # ★ IDEMPOTENT. This runs on every start; a rule that already exists must not become a second rule.
        if mc replicate ls "local/$$DSSE_ARCHIVE_BUCKET" 2>/dev/null | grep -q "$$DSSE_ARCHIVE_PEER_ENDPOINT"; then
          echo "cold archive: replication to $$DSSE_ARCHIVE_PEER_ENDPOINT is already configured"
        else
          mc replicate add "local/$$DSSE_ARCHIVE_BUCKET" \
            --remote-bucket "$$DSSE_ARCHIVE_PEER_ENDPOINT/$$DSSE_ARCHIVE_BUCKET" \
            --priority 1
          echo "cold archive: replicating to $$DSSE_ARCHIVE_PEER_ENDPOINT — asynchronous, and nobody has to run it"
        fi

  # ★★★ THE FOURTH STEP OF THE INSTALL ORDER, AND IT WAS NOT HERE. The order is Postgres, the
  # anchor, the control plane, the CONSOLE, then the Edges — and everything this installer generated skipped
  # straight from the control plane to the Edges. A deployment with no Console is one nobody can administer
  # except with curl, which is not a deployment anybody hands over.
  #
  # ★★★ ITS ADMIN UPSTREAM IS THE CONTROL PLANE, NOT AN EDGE. Observation is "the Edge REPORTS", never "the
  # Console asks an Edge": a read served from an Edge answers differently depending on which node the front
  # door picked, and that does not reproduce. The reference deployment points this at an Edge and the
  # architecture records it as a known defect.
  #
  # Measured before choosing, on 121 routes the Console actually calls, asked of both nodes with one
  # administrator session:
  #
  #   81  both answer                     the great majority is already answerable from the control plane
  #    9  ONLY the control plane answers  including /admin/admins — the administrator list itself — the
  #                                       audit-outbox health, the fleet's config status, and the three
  #                                       per-organization PKI authorities. A Console pointed at an Edge
  #                                       cannot see any of them today.
  #    1  ONLY an Edge answers            /admin/interception-intermediate, and the control plane REFUSES it
  #                                       with the reason: it holds the authorities but serves no traffic, so
  #                                       it cannot say what an organization's traffic is inspected under.
  #                                       That is an Edge's observation and the refusal names where to ask.
  #
  # ★ THE FIRST PASS COUNTED FOUR LOSSES AND THREE OF THEM WERE THE PROBE. Two routes needed 8 and 9 seconds
  # and my timeout was 8, so "no answer" was recorded as "the control plane cannot"; one was a lab ClickHouse
  # running out of memory. A timeout is not an answer, and neither is somebody else's resource limit.
  dsse-console:
    # Built from deploy/Dockerfile.console in this same tree — the Console is part of it.
    image: ${DSSE_CONSOLE_IMAGE:?set DSSE_CONSOLE_IMAGE to the Admin Console image this deployment runs}
    # ★ A REGION THAT REBOOTS MUST COME BACK. Without a policy Docker starts nothing when the daemon does, and
    # "on-failure" declines a container that was stopped cleanly — which is every container on a planned
    # restart. A node brought back then serves its door with its Edge and nothing behind it, and the fleet
    # view reads that Edge and calls the region current.
    restart: unless-stopped
    # ★★★ THE CONTROL PLANE ITSELF, NOT THE DOOR THAT USED TO FRONT IT. This named
    # dsse-control-plane — the local haproxy over a PAIR of control planes on one machine — and retiring the
    # pair took the item away and left the key, so the generated file had depends_on: with nothing under
    # it. Compose refuses the whole file for that: "services.dsse-console.depends_on must be a array". A
    # deployment that cannot be parsed cannot be started, stopped, or rolled, and the message names the
    # Console rather than the change that caused it.
    depends_on:
      dsse-control-plane-a: { condition: service_started }
    environment:
      LISTEN: "0.0.0.0:8443"
      # ★★★ THE FIRST SCREEN AN ADMINISTRATOR SEES MUST NOT BE A CERTIFICATE WARNING (the
      # operator: "the certificate error every time you enter the Admin Console — shouldn't that be solved
      # first, and be in the published install procedure?").
      #
      # The Console is served with this deployment's own management certificate, so every browser refuses it
      # until something is done. Two moments, two answers, and the procedure needs both:
      #
      #   - Day zero, before any certificate exists: the administrator MUST reach this screen to do anything
      #     at all, so the answer cannot be "obtain a certificate first". It is to VERIFY rather than accept:
      #     the installer prints the fingerprint of what this deployment will present, and the administrator
      #     compares it in the browser. That is a different act from clicking through a warning, and it is
      #     the only one available before the deployment has a name anybody else vouches for.
      #   - After that: the operator's own certificate for the Console's name, the same way the step-up
      #     portal takes one. Drop the pair into <dir>/console/ and it is served instead. Nothing about the
      #     deployment's internal PKI changes — this is the outward-facing page, and its certificate is the
      #     operator's, exactly as they decided for the portal.
      #
      # A deployment with no pair keeps the management certificate, which is right for a lab and is a visible
      # warning rather than a trust decision made quietly on the operator's behalf.
      TLS_CERT: ${DSSE_CONSOLE_TLS_CERT:-/deployment/management.crt}
      TLS_KEY: ${DSSE_CONSOLE_TLS_KEY:-/deployment/management.key}
      # ★★★ THE DEPLOYMENT'S ADMIN PLANE, NOT THIS MACHINE'S CONTROL PLANES (measured the first
      # time leadership landed in another region). This named the LOCAL pair's door, which health-checks
      # GET /leader and therefore has no backend at all when the leader is elsewhere. The Console then could
      # not reach the authority, and what an administrator saw was
      #
      #	Invalid credentials.
      #
      # for a password that was correct — measured against the leader directly, which answered 200. That is
      # the worst wrong answer this screen can give: it sends someone to reset a credential that is fine.
      #
      # The region doorway already routes admin.<host> to whichever control plane holds leadership, including
      # in another region (see haproxy-edge.cfg). Going out through it is one hop further and always finds the
      # authority. The Edges' door learned this; the Console's own upstream had not.
      # The enforcement Edge, which is a different node from the authority even when it is the same machine.
      # The Console asks each plane the questions that plane can answer; pointing both at one collapses them.
      ADMIN_API_UPSTREAM: ${DSSE_ADMIN_API_UPSTREAM:-` + edgeUpstream + `}
      CONTROL_API_UPSTREAM: ${DSSE_CONTROL_API_UPSTREAM:-` + adminUpstream + `}
      AUTH_API_UPSTREAM: ${DSSE_AUTH_API_UPSTREAM:-` + adminUpstream + `}
      ADMIN_SESSION_VALIDATE_CA: /deployment/deployment-anchor.pem
    volumes:
      # ★★★ THE CONSOLE READS THREE FILES, and it was given the whole deployment directory to serve a web
      # interface — read-only, which does nothing about the fact that the deployment's root CA private key was
      # inside it. Read-only is not "cannot reach"; it is "cannot edit".
      - "./management.crt:/deployment/management.crt:ro"
      - "./management.key:/deployment/management.key:ro"
      - "./deployment-anchor.pem:/deployment/deployment-anchor.pem:ro"
      # ★ WHERE THE OPERATOR PUTS THE CONSOLE'S OWN CERTIFICATE. A directory rather than two files, because a
      # bind mount of a file that does not exist creates a directory in its place. Usually empty.
      - "./console:/deployment/console:ro"
    expose: ["8443"]
`
}

// composeAuthorityAliases lets a node RESOLVE the names this deployment answers on.
//
// ★★★ IT WAS ON THE EDGE ALONE, AND THE EDGE IS NOT THE ONLY SERVICE THAT DIALS BY NAME (2026-09-04, found
// by standing the published tree up on one host with no DNS for it). Three services in this file resolve a
// deployment name:
//
//	dsse-edge-a      DSSE_CP_ENDPOINTS — the control planes it pulls from
//	dsse-postgres-a  ETCD3_HOSTS       — Patroni's view of the consensus store
//	dsse-store-a     its own advertised peer URL
//
// Only the first had these slots, so on a host where the deployment's own name does not resolve, Patroni
// never started:
//
//	WARNING: failed to resolve host node-tokyo.example.lab: [Errno -2] Name or service not known
//	ERROR: Failed to get list of machines from http://node-tokyo.example.lab:12379/v3beta
//	INFO: waiting on etcd
//
// and the database init behind it restarted for ever while `docker compose up` waited on it. On a deployment
// whose DNS answers — which is every one this lab has built — nothing was wrong. It is exactly the case a
// receiver meets first.
//
// ★★★ THE NAME IS THE ROUTE, AND A CONTAINER DOES NOT SHARE THE HOST'S NAMES (2026-08-25, measured twice).
//
// Every plane of this deployment answers on 443 and is told apart by NAME, so a node that has to reach
// another region reaches it as a name — the address alone routes to the agent plane, and an IP is refused by
// the peer's certificate, which covers names. On separate hosts, which is where regions actually live, DNS
// answers that. On ONE host — which is how anybody first tries a second region, and how this deployment's own
// multi-region walk is done — the names resolve inside the container to 127.0.0.1 and every cross-region path fails.
//
// Measured the first time as a joining region that could not reach the authority (silently stopped pulling
// configuration), and the second time as a mesh link refused by name:
//
//	x509: certificate is valid for ... agents.localhost, admin.localhost ... not host.docker.internal
//
// ★ FOUR SLOTS, BECAUSE THIS DEPLOYMENT HAS FOUR NAMES A NODE MIGHT NEED — the agent plane, the authority's
// admin and data surfaces, and the way back. The first attempt shipped two and was one short the moment the
// mesh was configured.
//
// ★ AND THE DEFAULTS SHADOW NOTHING. Each unset slot maps a name nothing uses to a loopback nothing serves,
// so a deployment whose DNS already answers is untouched — which matters, because a hosts entry silently
// beats DNS and this file would otherwise break the case it is trying to help.
//
//	DSSE_HOST_ALIAS_1='agents.example.test:host-gateway'
const composeAuthorityAliases = `    # Names this node must resolve that its own DNS may not answer — on one host, point them at the gateway.
    # Where DNS already answers, leave these alone: a hosts entry beats DNS, including when DNS was right.
    extra_hosts:
      - "${DSSE_HOST_ALIAS_1:-host-alias-1-unset.invalid:127.0.0.1}"
      - "${DSSE_HOST_ALIAS_2:-host-alias-2-unset.invalid:127.0.0.1}"
      - "${DSSE_HOST_ALIAS_3:-host-alias-3-unset.invalid:127.0.0.1}"
      - "${DSSE_HOST_ALIAS_4:-host-alias-4-unset.invalid:127.0.0.1}"
`

// composeStandbyControlPlane is the third shape a region can take: it holds no state of its own, and it does
// hold a WARM STANDBY control plane.
//
// ★★★ WHY A THIRD SHAPE EXISTS (2026-08-25, measured). the multi-region install order's control-plane failover step is control-plane failover, and the check
// for it fails on a two-region deployment where every Edge takes configuration from ONE address — because
// there is only one place leadership can be. The control planes were rendered inside the state-bearing block,
// so a joining region could not have one, and the step could not be completed with what this installer
// produced.
//
// ★ IT IS NOT A SECOND DEPLOYMENT, AND THE DIFFERENCE IS THE DATABASE. The joining-region note beside this
// explains what a region standing up its own consensus store and its own database would be: two leaders, two
// answers to "has this identity already enrolled". This standby stands up NEITHER. It joins the deployment's
// existing database over the network and contends for the SAME advisory lock — so the deployment still has
// exactly one leader, and this region is simply another place that leader can be.
//
// ★★ WHICH MEANS DSSE_POSTGRES_DSN IS REQUIRED AND HAS NO DEFAULT. A standby that fell back to a local
// "postgres" host would find nothing, or worse, find something — and the second is how a deployment becomes
// two. The := form refuses to render rather than guess.
//
// ★ ONE STANDBY, NOT TWO. In the state-bearing region the pair is what makes the authority survive losing a
// process; here the point is surviving losing a REGION, and the deployment already has a pair where its state
// is. A second standby in this region would add a node that can only ever be third.
//
// ★★★ AND IT IS STILL ONLY ONE THIRD OF A STATE-BEARING REGION. The architecture names three things that
// travel together — a quorum member of the consensus store, a REPLICA of the database, and this. With only
// this, leadership can move here while the database is reachable; it cannot move here when the region holding
// the database is GONE, because there would be nothing to promote. The deployment says which of the two it
// has, and this file does not pretend otherwise.
const composeStandbyControlPlane = `  # ★ A WARM CONTROL PLANE, AND NO STATE. See composeStandbyControlPlane for why this is not a second
  # deployment: it joins the deployment's database rather than standing up one, and contends for the same
  # advisory lock, so there is still exactly one leader for the whole deployment.
  dsse-control-plane-a:
    image: ${DSSE_IMAGE:?set DSSE_IMAGE to the DSSE image this deployment runs}
    environment:
      DSSE_EDGE_BINARY: ${DSSE_BINARY:-/usr/local/bin/dsse-edge}
      # ★★ NO DEFAULT ON PURPOSE. This must name the DEPLOYMENT's database, across regions. A fallback to a
      # local host would either fail confusingly or, if something answered, make this region a second
      # deployment.
      DSSE_POSTGRES_DSN: ${DSSE_POSTGRES_DSN:?set DSSE_POSTGRES_DSN to the deployment's database, reachable from this region}
      DSSE_MIGRATION_DIR: ${DSSE_MIGRATION_DIR:-/app/migrations}
      DSSE_CP_STATE_DIR: /var/lib/dsse
      # Which machine this is. Screens that report a per-node answer name the node that produced it, so a
      # reader can go and ask that node; without this a control plane cannot say who it is.
      DSSE_NODE_NAME: ${DSSE_NODE_NAME:-}
      DSSE_NODE_ADDRESS: ${DSSE_NODE_ADDRESS:-}
      DSSE_EDGE_REGION: ${DSSE_EDGE_REGION:-}
      # The deployment's hot store and archive, which live with the state. This node writes to them across
      # regions when it holds leadership.
      DSSE_CLICKHOUSE_ENDPOINT: ${DSSE_CLICKHOUSE_ENDPOINT:?set DSSE_CLICKHOUSE_ENDPOINT to the deployment's hot store}
      CLICKHOUSE_PASSWORD: ${CLICKHOUSE_PASSWORD:?set CLICKHOUSE_PASSWORD}
      DSSE_ARCHIVE_ENDPOINT: ${DSSE_ARCHIVE_ENDPOINT:?set DSSE_ARCHIVE_ENDPOINT to the deployment's archive}
      DSSE_ARCHIVE_BUCKET: ${DSSE_ARCHIVE_BUCKET:-dsse-audit-archive}
      MINIO_ROOT_USER: ${MINIO_ROOT_USER:-dsse-archive}
      MINIO_ROOT_PASSWORD: ${MINIO_ROOT_PASSWORD:?set MINIO_ROOT_PASSWORD}
    volumes:
      # ★★★ WHAT THIS NODE READS, AND NOTHING ELSE. See the note on the Edge above: the whole-directory mount
      # this replaces handed the deployment's root CA key to every service that had one.
      - "./start-control-plane.sh:/deployment/start-control-plane.sh:ro"
      - "./deployment.env:/deployment/deployment.env:ro"
      - "./policy.json:/deployment/policy.json:ro"
      - "./policy-egress.json:/deployment/policy-egress.json:ro"
      - "./policy-bundle.json:/deployment/policy-bundle.json:ro"
      - "./schemas:/deployment/schemas:ro"
      - "./deployment-anchor.pem:/deployment/deployment-anchor.pem:ro"
      # ★★★ THE INTERCEPTION ROOT, CERTIFICATE ONLY, SO A PROFILE ISSUED HERE CAN NAME IT (found
      # by walking a Mac onto a deployment built from the published tree). A control plane holds no
      # interception key and signs nothing — that stays with the Edges, deliberately — but it is the node the
      # Console asks for a device's configuration, and a profile that cannot name the root its devices will be
      # inspected under leaves every command-line tool on those devices unable to verify anything, with
      # nothing able to say why. The key is NOT mounted here and must not be.
      - "./lantern_dsse_interception_root_ca.pem:/deployment/lantern_dsse_interception_root_ca.pem:ro"
      - "./management-ca.crt:/deployment/management-ca.crt:ro"
      - "./management.crt:/deployment/management.crt:ro"
      - "./management.key:/deployment/management.key:ro"
      - "./device-ca-registry.json:/deployment/device-ca-registry.json"
      - "./audit-ingest-authority.json:/deployment/audit-ingest-authority.json"
      - "./agent-policy-signing.key:/deployment/agent-policy-signing.key:ro"
      - "./agent-update-signing.pub:/deployment/agent-update-signing.pub:ro"
      - "./runtime:/deployment/runtime"
      - "cp-a-state:/var/lib/dsse"
    extra_hosts:
      - "${DSSE_HOST_ALIAS_1:-host-alias-1-unset.invalid:127.0.0.1}"
      - "${DSSE_HOST_ALIAS_2:-host-alias-2-unset.invalid:127.0.0.1}"
      - "${DSSE_HOST_ALIAS_3:-host-alias-3-unset.invalid:127.0.0.1}"
      - "${DSSE_HOST_ALIAS_4:-host-alias-4-unset.invalid:127.0.0.1}"
    # ★ BOTH DOORS ARE PUBLISHED HERE, and only the admin one is in the state-bearing region. There the data
    # door is reached through the region's front door by name; a standby region has no front door for the
    # authority's names, and when leadership moves HERE every other region has to be able to WRITE to it —
    # what it recorded, who enrolled, which connector joined. Measured as an outbox that grew and delivered
    # nothing while leadership was in this region.
    ports:
      - "${DSSE_CP_A_ADMIN_PORT:-19543}:9443"
      - "${DSSE_CP_A_DATA_PORT:-19545}:8443"
    entrypoint: ["/deployment/start-control-plane.sh"]

  # The same internal door the state-bearing region has, so this region's Edges reach "the control plane" by
  # the same name. Here it fronts one node; the health check is the same, and it is the check that decides.
  # ★★★ AND NO SEPARATE CONTROL-PLANE DOOR. Two proxies in a row on one machine, both asking GET /leader:
  # the region's 443 door already names the control plane directly AND the doors of the other regions, so it
  # is the thing that finds the leader across the deployment. A second one would repeat that, one hop later,
  # over a single backend.
`

// composeEdgeFleet is the Edge processes and the region doorway in front of them. Separable because a
// machine that runs the Control Plane component must not define them at all.
// composeRegionDoorway is the pair of front doors that present this machine's planes on 443.
//
// ★★★ IT IS NOT PART OF THE EDGE (2026-08-27, found by removing the Edges from a control-plane machine and
// watching 443 disappear with them). The doorway routes by the NAME in the ClientHello — admin, authority and
// console to the control plane, agents to the Edges — so it belongs with whatever planes the machine it runs
// on actually serves. Bundling it with the Edge processes meant a machine could offer the authority and have
// no door to it.
func composeRegionDoorwayWith(edgeDependsOnCP string) string {
	_ = edgeDependsOnCP
	return `  dsse-edge:
    # ★★★ AN EDGE THAT REFUSES TO JOIN NEVER TRIED AGAIN (measured: a roll that happened while one
    # region's door was unreachable left BOTH of that region's Edges exited, and both of another region's, and
    # they stayed exited after the door came back). The fleet guard is right to refuse a node that cannot keep
    # the names the deployment has already promised — but the reason it cannot is usually transient, and the
    # containers were generated with no restart policy at all, so "temporarily unable" and "permanently
    # broken" had the same outcome. The control planes had this line; the Edges did not.
    restart: unless-stopped
    image: ${DSSE_HAPROXY_IMAGE:-haproxy:2.9-alpine}
    # ★★★ THE FRONT DOOR COULD NOT START ON AN ORDINARY HOST (measured the first time this
    # deployment ran with one component per machine):
    #
    #   [ALERT] (1) : [haproxy.main] Cannot raise FD limit to 131109, limit is 32768.
    #
    # haproxy reserves file descriptors for maxconn across every proxy in the file, and asks the kernel for
    # them at start-up. A default Linux host allows far fewer, so it exits — and the region's doorway is the
    # one service whose absence looks like the whole deployment being down.
    #
    # ★ IT NEVER APPEARED ON THE DEVELOPMENT MACHINE. Docker Desktop and colima hand containers a very large
    # descriptor limit, so the same file started there every time. The limit is declared here rather than left
    # to whatever the host happens to allow, because "it works on the machine it was written on" is exactly
    # what a one-host lab certifies.
    ulimits:
      nofile: { soft: 200000, hard: 200000 }
    depends_on:__DOORWAY_DEPENDS__
    volumes: ["./haproxy-edge.cfg:/usr/local/etc/haproxy/haproxy.cfg:ro"]
    # ★★★ A FIXED ADDRESS, BECAUSE THE EDGES ARE TOLD TO BELIEVE IT AND NOTHING ELSE. This container states
    # each device's original address in a PROXY protocol header, and an Edge that believed such a header from
    # anyone would let any peer choose its own source address — and with it every decision keyed on the
    # address. -trusted-front-doors names THIS address, so it cannot be whatever the network hands out today.
    networks:
      default:
        ipv4_address: ${DSSE_FRONT_DOOR_A:-10.77.0.5}
    # ★★★ THE ONE PUBLISHED MOUTH, AND IT IS 443 INSIDE. Every plane this deployment presents is behind this
    # port, separated by the name in the ClientHello. On the host it is mapped somewhere else only because a
    # laptop already has things on 443; on a real host it is 443:443, which is the whole point — a device, a
    # connector and an administrator all arrive through some enterprise's proxy, and a non-standard port is
    # where they stop.
    #
    # ★★★ AND A PAIR IS TWO ADDRESSES, SO EACH DOOR CAN BIND ONE (measured on the first deployment
    # where every component had its own machine). Both doors want 443, and a host has one 443 per address —
    # so on one machine the pair could only ever be 18443 and 18444, which is the substitution this whole
    # arrangement exists to end. DSSE_REGION_BIND_A/B name the host address each door listens on, so both can
    # be 443. Empty by default, which is every interface and exactly what a one-host rendering had.
    ports: ["${DSSE_REGION_BIND_A:-}${DSSE_REGION_PORT:-18443}:443"]
  # ★★★ ONE DOOR PER REGION. A second haproxy beside this one — the same image and the same configuration
  # file, bound to a second address, both on 443 — lets a region survive losing a door. It does; but a device
  # whose door stops answering already FAILS OVER TO ANOTHER REGION, which is measured and takes about thirty
  # seconds.
  #
  # A second door shortens one failure and costs every machine a second address, a second process, and a rule
  # that a doorway is a pair — which is the rule that makes "an Edge node behind the region's door"
  # impossible to declare. One door, and the region's failure is a region failure.

  # ★★★ WHAT DELIVERS THE REGION'S ONE ADDRESS IS NOT IN THIS FILE, AND SAYING SO IS THE POINT. A region
  # presents ONE agent-facing address (invariant 9) and the pair above is what stands behind it — but a
  # container rendering on one host cannot deliver that address itself: a host port is published by exactly
  # one container, so whichever front door published it would be the single point again.
  #
  # The address is delivered one layer down, by whichever of these the deployment sits on:
  #
  #   - the platform's own layer-4 load balancer (an NLB and its equivalents), which is redundant by
  #     construction and is what a cloud deployment uses;
  #   - a virtual address on the front-door hosts themselves, moved by VRRP.
  #
  # ★ AND THE SECOND ONE WAS TRIED HERE AND DOES NOT RUN ON THIS DESK. keepalived was generated
  # into this file, and on Docker Desktop VRRP never leaves BACKUP: the protocol-112 sockets do not open on a
  # container bridge, on the native architecture as well as the emulated one. Shipping it would have been a
  # mechanism the operator generating this file cannot check — so it is named as the host's job instead of
  # being written as though this rendering performed it.
  #
  # What this deployment DOES carry so that address works the day it exists: 10.77.0.10 is in the certificate
  # the Edges present. A deployment that discovers this later repairs it by re-minting, which orphans every
  # anchor already distributed.
  #
  # ★★★ THE EDGES ARE A FLEET: the same image, the same script, the same configuration pulled from the same
  # control plane. They differ in their address and their state directory and in nothing else. Two is the
  # smallest number that makes that true rather than aspirational — with one node, "the front door routes to
  # a healthy Edge" is a sentence nothing tests.
  #
  # ★ NEITHER PUBLISHES THE AGENT PORT. An address a device can reach directly is an address the deployment
  # can never withdraw, and a device holding one is a device that survives its node being drained.
  #
  # ★★ BUT BOTH PUBLISH THEIR ADMIN PORT, AND PUBLISHING ONLY ONE HID A NODE (found by killing
  # it). Per-node observation is answered PER NODE — that is what the admin surface is for, and it is why
  # -verify takes a comma-separated list of Edges: whether every node hands devices the same region map is a
  # property of the fleet and cannot be asked of one member. With one node published, stopping THAT node ended
  # the walk with "the Edge answers -> connection refused" while the agent plane was serving perfectly well
  # through the other one. The check measured the wrong door and called the deployment down.`
}

// composeEdgeFleetWith is the Edge processes themselves.
// composeEdgeFleetWith renders the Edges. authorityDefaults is where an Edge here reaches the deployment's
// control plane when the operator has not said — the admin surface and the data surface, in that order.
const edgePortsPlaceholder = "__EDGE_PORTS__"

// edgePortsFor is what an Edge publishes on its machine's own addresses.
//
// ★★★ EVERY MACHINE THAT RUNS EDGES PUBLISHES THEM, INCLUDING THE ONE HOLDING THE DOOR (2026-09-03, measured
// by adding a second Edge to a running region).
//
// This used to publish nothing on a doorway machine, reasoning that "the door's address is the region's one
// destination, and a port beside it is a way in that carries no device address in a PROXY header". The second
// half is true and applies EQUALLY to the machines behind the door, which have always published — so it was
// never the rule it read as. What it actually produced was a machine whose Edge no other machine could reach:
//
//	mesh peer tokyo-east (wss://10.21.1.158:8443/mesh/ingress/tunnel) link down:
//	  dial tcp 10.21.1.158:8443: connect: connection refused        (every two seconds, for ever)
//
// A region's Edges hold a link to each OTHER — that is how a flow arriving at one reaches a connector whose
// tunnel is held by another, which happens routinely because the door pins a device to one Edge by source
// hash and a connector to another. The sibling address is <the machine's address>:<agent port>, generated for
// every Edge; on the doorway machine that address answered nothing, so half of a two-Edge region's private
// access had no path, and the only sign of it was a line in a log nobody reads.
//
// ★ THE DOOR REMAINS THE ONLY ADVERTISED WAY IN. Nothing points a device at this port: it is not in DNS, not
// in any profile, and not in the region map. What governs who may reach it is the same firewall that already
// has to let the door reach the Edges behind it.
func edgePortsFor(shape machineShape) string {
	if !shape.behindDoorway && !shape.edges {
		return ""
	}
	return "    ports: [\"${DSSE_EDGE_AGENT_PORT:-8443}:8443\", \"${DSSE_EDGE_ADMIN_PORT:-19443}:9443\"]\n"
}

func composeEdgeFleetWith(edgeDependsOnCP string, adminDefault, dataDefault string) string {
	return `  dsse-edge-a:
    # ★★★ AN EDGE THAT REFUSES TO JOIN NEVER TRIED AGAIN (measured: a roll that happened while one
    # region's door was unreachable left BOTH of that region's Edges exited, and both of another region's, and
    # they stayed exited after the door came back). The fleet guard is right to refuse a node that cannot keep
    # the names the deployment has already promised — but the reason it cannot is usually transient, and the
    # containers were generated with no restart policy at all, so "temporarily unable" and "permanently
    # broken" had the same outcome. The control planes had this line; the Edges did not.
    restart: unless-stopped
    image: ${DSSE_IMAGE:?set DSSE_IMAGE to the DSSE image this deployment runs}
    depends_on:` + edgeDependsOnCP + `
    environment:
      DSSE_EDGE_BINARY: ${DSSE_BINARY:-/usr/local/bin/dsse-edge}
      # ★★★ THE DEPLOYMENT'S CONTROL PLANE, WHICH IS NOT ALWAYS IN THIS REGION. Where state lives, this
      # resolves to the local front door; in a region that holds none it names the deployment's, across
      # regions. An Edge takes configuration from whichever node currently holds leadership, and there is one
      # of those for the whole deployment.
      DSSE_CONTROL_PLANE: ${DSSE_CONTROL_PLANE:-` + adminDefault + `}
      # The DATA surface, not the admin one: shipping records is a node talking to the authority, not an
      # administrator acting on it.
      DSSE_CONTROL_PLANE_DATA: ${DSSE_CONTROL_PLANE_DATA:-` + dataDefault + `}
      # ★★★ AND WHERE LEADERSHIP CAN BE, WHICH THE PLAN ALREADY WORKS OUT (measured on the first
      # three-region deployment). start-edge.sh has read these already and turns them into
      # -config-source-endpoints, which makes the Edge probe each region's GET /leader and pull from whichever
      # answers — and the compose file never passed them in, so every Edge used the single URL above.
      #
      # ★ THAT URL IS THIS REGION'S OWN DOOR, and in a region that JOINS, its control planes are warm
      # standbys. The door had nothing to route to, and what the Edge could not deliver it kept: the exact
      # symptom start-edge.sh names beside these variables — "enrolment_report_outbox: delivered=0
      # still_pending=2 (growing)" and "the authority counts the connector -> registered on an Edge, and the
      # control plane does not name it". Both were failing checks on the deployment this was found on.
      #
      # ★ AND THE DOOR COULD NOT HAVE FIXED IT. Every region answers /leader through its own front door, which
      # forwards to whoever leads — so a health check there cannot tell a region that LEADS from one that
      # merely knows where the leader is. The Edge asking each region BY NAME can.
      DSSE_CP_ENDPOINTS: ${DSSE_CP_ENDPOINTS:-}
      DSSE_CP_DATA_ENDPOINTS: ${DSSE_CP_DATA_ENDPOINTS:-}
      DSSE_CP_HOME: ${DSSE_CP_HOME:-${DSSE_EDGE_REGION:-}}
      # ★★★ WHICH MACHINE THIS IS. A node reports itself to the control plane as its container's
      # hostname, so the fleet an operator can be shown is a list of hex ids grouped by region — and "which
      # machine is behind?" is not answerable from anything on screen. The plan holds the name the operator
      # wrote; this is how it reaches the process that reports it.
      DSSE_NODE_NAME: ${DSSE_NODE_NAME:-}
      DSSE_NODE_ADDRESS: ${DSSE_NODE_ADDRESS:-}
      # ★★★ THE OTHER EDGE OF THIS REGION, BY NAME (measured on a site with a connector pair).
      #
      # A connector must hold a tunnel on EVERY Edge node of its region, because a flow can arrive on any of
      # them — and it cannot. The region's agent door balances by SOURCE ADDRESS with a consistent hash, deliberately,
      # so a device's live sockets stay on one node; a connector dials from ONE address and therefore lands on
      # the same node for ever. Its own search says "on only 1 of the 2 Edge node(s)" and has nowhere to go.
      # Measured: half the flows to a private asset were served and half were refused, decided by which node
      # the device's source address hashed to.
      #
      # So an Edge that cannot serve a connector itself relays to the one that can — the same peer-Edge link
      # this deployment already uses across regions, applied to a sibling here, where the nodes ARE
      # individually addressable. They are named to each other in the door's own backend already.
      # ★★★ THE OTHER EDGE MACHINES OF THIS REGION, BY ADDRESS — never by container name. A region grows by
      # adding MACHINES that run an Edge, so a sibling is on another host and a container name reaches
      # nothing.
      #
      # It matters because a connector attaches to ONE Edge of its region — the door balances by source
      # address with a consistent hash, so it lands on the same node every time — and every other node reaches
      # what is behind it by relaying to the one that holds it. Without this, adding a node adds capacity for
      # public traffic and a hole for private access: flows that land on the new node cannot reach any
      # connector. Empty is correct for a region of one machine.
      DSSE_EDGE_SIBLINGS: ${DSSE_EDGE_SIBLINGS:-}
      DSSE_EDGE_STATE_DIR: /var/lib/dsse
      DSSE_RECOVERY_SNI: ${DSSE_RECOVERY_SNI:-}
      # ★★★ ONE DOOR, SO ONE ADDRESS. This list is what makes a PROXY protocol header believable, so an
      # address no door holds is trust handed to whoever turns up on it. Name the doors that exist, and no
      # more.
      DSSE_TRUSTED_FRONT_DOORS: ${DSSE_TRUSTED_FRONT_DOORS:-10.77.0.5}
` + composeAuthorityAliases + `    volumes:
      # ★★★ WHAT THIS NODE READS, AND NOTHING ELSE. This was a mount of ./ onto /deployment — the whole
      # directory, every private key the deployment has, handed to both Edges, both control planes and the
      # Console. Five of those keys are read by nothing at runtime; they now live in authority/ and are
      # mounted by no service at all. The rest is enumerated because enumerating it is the point: this list
      # IS the material an Edge installer will have to produce on a machine of its own.
      - "./start-edge.sh:/deployment/start-edge.sh:ro"
      - "./deployment.env:/deployment/deployment.env:ro"
      - "./policy.json:/deployment/policy.json:ro"
      - "./policy-egress.json:/deployment/policy-egress.json:ro"
      - "./policy-bundle.json:/deployment/policy-bundle.json:ro"
      - "./schemas:/deployment/schemas:ro"
      - "./deployment-anchor.pem:/deployment/deployment-anchor.pem:ro"
      # ★★★ THE INTERCEPTION ROOT, CERTIFICATE ONLY, SO A PROFILE ISSUED HERE CAN NAME IT (found
      # by walking a Mac onto a deployment built from the published tree). A control plane holds no
      # interception key and signs nothing — that stays with the Edges, deliberately — but it is the node the
      # Console asks for a device's configuration, and a profile that cannot name the root its devices will be
      # inspected under leaves every command-line tool on those devices unable to verify anything, with
      # nothing able to say why. The key is NOT mounted here and must not be.
      - "./lantern_dsse_interception_root_ca.pem:/deployment/lantern_dsse_interception_root_ca.pem:ro"
      - "./transport-ca.crt:/deployment/transport-ca.crt:ro"
      - "./management-ca.crt:/deployment/management-ca.crt:ro"
      - "./transport.crt:/deployment/transport.crt:ro"
      - "./transport.key:/deployment/transport.key:ro"
      - "./edge-identity.crt:/deployment/edge-identity.crt:ro"
      - "./edge-identity.key:/deployment/edge-identity.key:ro"
      # ★ THE TWO AN EDGE LEGITIMATELY HOLDS. It signs device certificates at /enroll and signs the agent
      # policy, and per-Edge signing is deliberate — a single shared signer would make the
      # HSM a single point of failure. These are the fleet-wide halves, and Phase 1 replaces the files with
      # an HSM the node holds.
      - "./device-ca.crt:/deployment/device-ca.crt:ro"
      - "./device-ca.key:/deployment/device-ca.key:ro"
      - "./agent-policy-signing.key:/deployment/agent-policy-signing.key:ro"
      - "./agent-update-signing.pub:/deployment/agent-update-signing.pub:ro"
      - "./lantern_dsse_interception_root_ca.pem:/deployment/lantern_dsse_interception_root_ca.pem:ro"
      # ★ AND ITS PRIVATE HALF, which the Edge finds as a sibling of the path above rather than by a flag. It
      # signs interception leaves with it. That an Edge holds the deployment's interception ROOT — rather than
      # a per-tenant intermediate, as the PKI document says and deploy/reference does — is a real gap, and
      # mounting it keeps the gap honest instead of producing a fleet that mints its own roots.
      - "./lantern_dsse_interception_root_ca.key.pem:/deployment/lantern_dsse_interception_root_ca.key.pem:ro"
      # ★ WRITTEN AFTER START-UP, so a directory rather than files: a bind mount of a file that does not exist
      # yet creates a directory in its place, and the host can then never write the file.
      - "./runtime:/deployment/runtime"
      # ★ WHERE AN OPERATOR PUTS THE STEP-UP PORTAL'S CERTIFICATE. A browser is sent to that page and has
      # no reason to trust what this deployment mints; the identity provider beyond it is the customer's own
      # (Okta, Entra ID) and publicly trusted. A DIRECTORY rather than two files, because a bind mount of a
      # file that does not exist creates a directory in its place. Usually empty.
      - "./clientless:/deployment/clientless:ro"
      - "edge-a-state:/var/lib/dsse"
      # ★★★ THE ORGANIZATION'S INTERCEPTION ROOTS BELONG TO THE NODE, NOT TO A PROCESS (measured).
      # Per-process state gave a region one root PER EDGE PROCESS: osaka-edge-a signed Sakura Foods under
      # 0a8fc598… while the door's trust bundle announced d5e54171…, minted by osaka-edge-b. A device is told
      # one fingerprint and any Edge may serve it, so it works or fails depending on which process the door
      # picked. Making the roots durable fixed "lost on restart" and left this untouched — durable and
      # divergent is the same outage with a longer memory.
      - "./interception-roots:/var/lib/dsse/interception-roots"
    # ★★★ AND THE AGENT PORT, WHEN THE DOORWAY IS ON ANOTHER MACHINE (measured). On one host the
    # doorway reached this Edge over the compose network, so 8443 never had to leave the container — and the
    # first per-component deployment had a doorway whose health check passed on the admin port and whose
    # traffic was refused on the agent one. "UP, Layer7 check passed" beside "Connection refused" is the
    # shape of a port that exists for the checker and not for the caller.
    #
    # ★ EACH EDGE GETS ITS OWN, because two on one host cannot share it — the same reason the admin ports
    # differ. compose does not expand a conditional, so the port is always published and the value is what
    # decides whether it collides.
    # ★★★ A REGION HAS ONE DESTINATION AND IT IS THE DOOR. For both connectors and agents the destination
    # address is one per region, and that is the haproxy. A machine that also listens on 0.0.0.0:8443 and
    # 0.0.0.0:19443 offers the Edge's agent plane AND its admin plane on the same address, past the door.
    #
    # That is not a smaller door: the door is what carries each device's own address through in the PROXY
    # header, and an Edge only believes that header from the addresses it was told to trust. A connection
    # arriving on 8443 directly can claim to be from anywhere, and the region's device list is built from
    # exactly that claim.
    #
    # So an Edge that shares a machine with the door is reachable on the container network only. An Edge on a
    # machine of its OWN publishes these ports: that machine has no door, and the door that fronts it is on
    # another host and has to reach it.
    #
    # ★★ AND THE CHOICE IS MADE HERE, IN GO, NOT BY A VARIABLE (caught by asking compose to parse
    # what this renders). The first attempt made the whole value a variable, set on machines behind a
    # door and empty on machines that are one. Compose interpolates AFTER it parses, so that is a scalar
    # string where a list belongs, and every shape that runs an Edge was refused outright:
    #
    #	services.dsse-edge-a.ports must be a list
    #
    # The comment three paragraphs up already said "compose does not expand a conditional". It is right: the
    # conditional belongs to the generator, which knows the machine's shape.
__EDGE_PORTS__    expose: ["8443", "9443"]
    entrypoint: ["/deployment/start-edge.sh"]`
}

// shapeFromFlags is the one place the flags an operator gives become a machine's shape. Both the installer
// and the carry read it, so "what this machine runs" and "what this machine may hold" cannot disagree.
func shapeFromFlags(controlPlaneOnly bool, region string, holdsState, standbyCP, storeSpansRegions bool) machineShape {
	// ★★★ -control-plane-only IS A MACHINE'S ROLE, NOT A REGION KIND. It composes with whatever the region
	// holds, so a JOINING region's control plane can be on its own machine — which had no expression at all
	// while this was a fifth region shape.
	holds := regionShapeEdgesOnly
	switch {
	case region == "":
		holds = foundingShape.holds
	// ★ HOLDING STATE SUBSUMES THE WARM STANDBY. A region with a database of its own runs control planes too —
	// the standby flag describes one third of it, and asking for both is asking for the whole thing.
	case holdsState:
		holds = regionShapeStateBearingJoin
	case standbyCP:
		holds = regionShapeStandbyCP
	}
	// ★ A CONTROL-PLANE MACHINE IN A REGION THAT WOULD OTHERWISE HOLD NOTHING holds the deployment's state:
	// asking for the Control Plane component is asking for what a Control Plane is.
	if controlPlaneOnly && holds == regionShapeEdgesOnly {
		holds = regionShapeStateBearingJoin
		if region == "" {
			holds = regionShapeStateBearing
		}
	}
	return machineShape{holds: holds, edges: !controlPlaneOnly, storeSpansRegions: storeSpansRegions}
}

// deploymentHostFor is the name this deployment answers on, as the deployment itself recorded it.
//
// ★ READ FROM THE DEPLOYMENT, NOT FROM A FLAG. A region is prepared from a CARRIED copy, where the operator
// gives no -host at all: the deployment already knows its own name, and asking again is how a second answer
// gets into a deployment that must have one.
func deploymentHostFor(dir string) string {
	env, err := readEnvFile(filepath.Join(dir, "deployment.env"))
	if err != nil {
		return ""
	}
	if h := strings.TrimSpace(env["EDGE_HOST"]); h != "" {
		return h
	}
	// The agent plane's name is the host with a prefix; planeNamesFor strips it back off.
	return strings.TrimSpace(env["DSSE_AGENT_PLANE_NAME"])
}

// consoleEdgeUpstreamFor is where this machine's Console reaches the ENFORCEMENT EDGE.
//
// ★★★ THE CONSOLE HAS TWO PLANES AND THIS DEPLOYMENT GAVE IT ONE (2026-09-05, measured through the Console's
// own origin on a running deployment). cmd/dsse-console is explicit about the split — ADMIN_API_UPSTREAM is
// the "enforcement Edge", CONTROL_API_UPSTREAM the "control-plane durable data", AUTH_API_UPSTREAM the auth
// authority — and this file set all three to the admin plane, which routes to the control plane. So both of
// the Console's planes answered as the same node, and every question that only an Edge can answer was put to
// the node that cannot. Asking the Console's own origin for the same resource on both planes:
//
//	default   measured_on: singapore/node-singapore (control plane)   2 certificates
//	/control  measured_on: singapore/node-singapore (control plane)   2 certificates
//
// while the Edge's own admin door on the SAME machine answered with seven, and with a live trust refusal from
// a device that the Console had no way to show. Also measured empty or refused through the collapsed plane:
// connectors (the installer's own verification connector), sites, the transport trust anchors (503 on the
// control plane), the interception intermediate (409), the bypass hosts.
//
// The name already exists — the region doorway publishes <region>-edge-a.admin.<host> and routes it to this
// node's Edge admin surface (perNodeAdminTargets), the node certificate carries *.admin.<host>, and it
// resolves inside the Console's container. Nothing needed building; it needed asking.
//
// The auth surface is unaffected: cmd/dsse-console registers login/activate/admins/session/logout/oidc and
// /auth/ against AUTH_API_UPSTREAM as more-specific patterns, so moving the admin plane does not move sign-in
// — which is the failure the note on adminUpstreamFor exists to prevent.
func consoleEdgeUpstreamFor(dir string, shape machineShape) string {
	if p := planeNamesFor(deploymentHostFor(dir)); p.Split && strings.TrimSpace(p.BareHost) != "" {
		for _, n := range perNodeAdminTargets(dir) {
			// The edges come first out of perNodeAdminTargets, but ordering is not the contract — the compose
			// service name is.
			if strings.Contains(n.host, "edge") {
				return "https://" + n.node + ".admin." + strings.TrimSpace(p.BareHost)
			}
		}
	}
	// A deployment that answers on an address rather than on names reaches the Edge beside it directly, the
	// same way adminUpstreamFor falls back to the control plane beside it.
	return "https://dsse-edge-a:9443"
}

// adminUpstreamFor is where this machine's Console reaches the deployment's authority.
//
// ★ THE LOCAL PAIR WHEN THERE IS NOTHING ELSE. A deployment that answers on an address rather than on names
// has no admin plane to route through, and the compose service beside it is both correct and shorter.
func adminUpstreamFor(dir string, shape machineShape) string {
	if p := planeNamesFor(deploymentHostFor(dir)); p.Split && strings.TrimSpace(p.Admin) != "" {
		return "https://" + p.Admin
	}
	return "https://dsse-control-plane-a:9443"
}
