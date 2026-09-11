package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// region.go — installing the SECOND region of one deployment.
//
// ★★★ THE INSTALL ORDER SPLITS INTO THREE, AND ONLY THE MIDDLE ONE REPEATS (2026-08-23, walked).
//
//	once for the whole deployment   the anchor and the three tiers of authority beneath it
//	once per region                 the database, the control planes, the front door, the Edges, the Console
//	after every region exists       the region entry list, the data-plane mesh, revocation propagation,
//	                                control-plane failover
//
// The dangerous one is the first. An operator standing up region B naturally runs the same command that stood
// up region A — and that MINTS A SECOND DEPLOYMENT. Two anchors, two device-identity authorities, two of
// everything, and nothing says so: both regions come up healthy and serve traffic. What fails is a device
// that moves between them, which sees a certificate from an issuer it has never heard of, at the moment it is
// furthest from help.
//
// So -region refuses to mint. A second region is the SAME deployment's material, carried to another place:
//
//	region A:  dsse-install -dir /etc/dsse -host <names>
//	           ... copy /etc/dsse to region B's host, as privately as it was created ...
//	region B:  dsse-install -dir /etc/dsse -region region-b
//
// ★ WHY CARRYING AND NOT FETCHING. There is nothing to fetch from yet — this runs before region B has a
// control plane, and the material includes private keys, which no deployment should hand out over a channel
// it has not yet established. The copy is the operator's, once, and its correctness is checkable: the anchor
// fingerprint printed here is the one region A printed.

// placeholderHost is the host part of the two addresses only the operator can supply. It is a single constant
// so that "is this still a placeholder" is decided by the same string that wrote it.
const placeholderHost = "REPLACE-WITH-THE-DEPLOYMENTS-CONTROL-PLANE-HOST"

// regionInstall prepares an EXISTING deployment's material for one more region. It mints nothing.
func regionInstall(dir, region string, shape machineShape) error {
	dir = strings.TrimSpace(dir)
	region = strings.ToLower(strings.TrimSpace(region))
	if dir == "" {
		return fmt.Errorf("-dir is required: name the directory holding this deployment's authorities, carried " +
			"here from the region that created them")
	}
	if region == "" {
		return fmt.Errorf("-region is required and names this region, e.g. region-b")
	}

	minted, err := alreadyMinted(dir)
	if err != nil {
		return err
	}
	if !minted {
		// ★★★ THIS IS THE INVARIANT-11 MISTAKE, CAUGHT AT THE ONE MOMENT IT IS STILL CHEAP.
		return fmt.Errorf("%s holds no authorities, so installing a region here would MINT A SECOND "+
			"DEPLOYMENT.\n\n"+
			"  A deployment has ONE anchor and one set of authorities beneath it, however many regions it "+
			"spans.\n"+
			"  Minting again would give this region its own, and both regions would come up healthy — the\n"+
			"  failure appears later, on a device that MOVES between them and is served a certificate from an\n"+
			"  issuer it has never heard of.\n\n"+
			"  Carry the deployment from the region that created it:  dsse-install -dir <that region> -carry\n"+
			"  <file.tar.gz>  — then untar it here and point -dir at it. That command packs what a receiving\n"+
			"  machine needs and structurally leaves out authority/, the root CA private key and the three\n"+
			"  beside it: no running process reads them, so a machine that is not minting never holds them.\n"+
			"  The file still carries private keys; move it as privately as the directory it came from.\n\n"+
			"  If this really is a NEW deployment that happens to be in another place, install it without\n"+
			"  -region", dir)
	}

	// ★★★ AND THE CARRY HAS TO INCLUDE THE SIGNING AUTHORITY, NOT ONLY THE CERTIFICATE ONES (2026-08-25).
	//
	// The anchor check above catches an operator who ran the minting command twice. It does NOT catch a
	// directory that was carried CORRECTLY but is missing one file, because the Edge's agent-policy loader is
	// load-or-generate: an absent key means "mint one and persist it", so this region would come up healthy,
	// signing steer policy with an authority no device has pinned and REJECTING every config bundle the
	// deployment's control plane serves — measured, at ten-second intervals, on a two-region deployment where
	// both regions reported healthy. Refusing here costs one copy; the alternative is found from the device
	// side, later.
	if _, err := os.Stat(filepath.Join(dir, agentPolicySigningKeyFile)); err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("stat %s: %w", filepath.Join(dir, agentPolicySigningKeyFile), err)
		}
		return fmt.Errorf("%s holds the deployment's certificate authorities but not %s, so this region "+
			"would MINT ITS OWN SIGNING AUTHORITY.\n\n"+
			"  That key signs the steer policy a device applies and the config bundle an Edge accepts, and a\n"+
			"  deployment has exactly one of it. A region that mints its own comes up HEALTHY: it just quietly\n"+
			"  refuses every bundle the control plane serves, and hands its devices policy signed by an\n"+
			"  authority none of them has pinned.\n\n"+
			"  Carry %s from the region that created it, as privately as the private keys beside it, and run\n"+
			"  this again. Its public half is in agent-policy-signing.pub, which is safe to compare out loud",
			dir, agentPolicySigningKeyFile, agentPolicySigningKeyFile)
	}

	// ★★★ AND IT MUST NOT BE POINTED AT THE REGION THAT HOLDS THE STATE (2026-08-25, done by accident).
	//
	// -region rewrites the compose file as a JOINING region, which is a region with no database, no consensus
	// store and no control planes — that is the whole point of it. Run against the directory of the region
	// that HOLDS those, it silently removes them from the file that stands them up. Nothing fails at the
	// moment it happens, because the containers are already running; it fails the next time somebody brings
	// the deployment up, when the deployment's authority and its database are simply not in the file any more.
	//
	// The check is not "is this region-a" — a deployment can put its state anywhere. It is "does the compose
	// file here already stand up this deployment's state", which is a fact about the directory rather than a
	// name, and it is exactly what would be destroyed.
	// ★ THE TEST IS NOT "does this compose stand up state" ON ITS OWN. A carried copy always does — that is
	// what carrying means, and turning it into a joining region is this command's whole job. What separates
	// the accident from the intent is the NAME: preparing region-b from a copy that still calls itself
	// region-a is the carry; running -region region-a on the directory that already is region-a is the
	// origin, and there the rewrite removes the deployment's own database from the file that starts it.
	if bearing, berr := composeStandsUpTheState(dir); berr == nil && bearing && sameRegionAsRecorded(dir, region) {
		return fmt.Errorf("%s already IS %q, and it stands up this deployment's STATE — its database, its "+
			"consensus store and its control planes are in the compose file here.\n\n"+
			"  Preparing it as a joining region would REMOVE them from that file. Nothing would fail today,\n"+
			"  because they are already running; it would fail the next time this deployment is brought up.\n\n"+
			"  -region prepares ANOTHER place to run Edges from a COPY of this directory, and the region it\n"+
			"  names is that other place. To rename this one, set DSSE_EDGE_REGION in deployment.env",
			dir, region)
	}

	// Everything a region needs beyond the shared material: which region this is, and where the deployment's
	// regions answer. Both are per-region facts, so they live in deployment.env rather than in the scripts.
	if err := setRegionEnvironment(dir, region, shape.holds == regionShapeStandbyCP,
		shape.holds == regionShapeStateBearingJoin); err != nil {
		return err
	}
	// ★★★ A JOINING REGION HOLDS NO STATE. See writeComposeFileFor: a region that stands up its own consensus
	// store and its own database is a second DEPLOYMENT, with a second leader and one-time decisions taken
	// twice. Adding state to a region is a separate act, and it joins what exists rather than creating its own.
	//
	// ★ -with-standby-control-plane IS THAT ACT, PARTLY. It adds a control plane that JOINS the deployment's
	// database — no database of its own, no consensus store — so the deployment still has exactly one leader
	// and this region becomes another place it can be. The other two thirds (a quorum member and a replica)
	// are what would let leadership move here when the region holding the state is GONE.
	if shape.holds == regionShapeStandbyCP {
		if err := writeStandbyFrontDoorConfig(dir); err != nil {
			return err
		}
	}
	// ★★★ AND THIS REGION'S OWN DOORWAY (2026-08-28, measured standing up a second site). Everything else
	// here is rendered for THIS region and the door was not: it arrived in the carry, generated for the region
	// it was packed FROM, naming that region's peers. So region-b's doorway forwarded cross-region traffic to
	// region-b — itself — and the plane names that route to whichever control plane leads had no way to reach
	// the one that did. The file is regenerated here, where DSSE_EDGE_REGION and DSSE_REGION_ENDPOINTS say
	// which region this is and who its peers are.
	if err := os.Remove(filepath.Join(dir, "haproxy-edge.cfg")); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := writeRegionFrontDoorConfig(dir, planeNamesFor(planeHostOf(dir))); err != nil {
		return err
	}
	// ★ AND THE DATABASE'S DOOR, for exactly the same reason: its peers are the OTHER regions' members, so a
	// copy generated for the region it was packed from names the wrong ones. Measured: region-b's door had
	// only its own members, reported "backend 'pg_primary' has no server available", and its control planes
	// could not open the deployment's state at all while the primary was in region-a.
	if err := os.Remove(filepath.Join(dir, "haproxy-postgres.cfg")); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := writeDatabaseFrontDoorConfig(dir); err != nil {
		return err
	}
	if err := writeComposeFileFor(dir, shape); err != nil {
		return err
	}
	if err := writeLaunchScripts(dir); err != nil {
		return err
	}
	reportRegion(dir, region, shape)
	return nil
}

// setRegionEnvironment records this region's id in deployment.env without disturbing the secrets already
// there, and makes sure the region entry list has a line even when it is still empty.
//
// ★ THE ENTRY LIST IS DELIBERATELY LEFT EMPTY HERE. It cannot be complete until every region exists — that
// is why the install order puts it in the third group — and a half-written list is worse than none: an Edge
// holding a shorter list is healthy and hands its devices a valid map that simply does not contain the
// regions it never heard about.
func setRegionEnvironment(dir, region string, standbyControlPlane, stateBearingJoin bool) error {
	path := filepath.Join(dir, "deployment.env")
	body, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w — a region needs the deployment's environment, carried with its keys",
			path, err)
	}
	lines := strings.Split(strings.TrimRight(string(body), "\n"), "\n")
	set := func(key, value string) {
		for i, line := range lines {
			if strings.HasPrefix(strings.TrimSpace(line), key+"=") {
				lines[i] = key + "=" + shellQuote(value)
				return
			}
		}
		lines = append(lines, key+"="+shellQuote(value))
	}
	// setIfUnset writes a value only when the file does not carry the key at all, or carries it empty. Unlike
	// setUnlessAnswered it holds no notion of a placeholder: it is for values where anything already written
	// is somebody's answer.
	setIfUnset := func(key, value string) {
		for _, line := range lines {
			t := strings.TrimSpace(line)
			if !strings.HasPrefix(t, key+"=") {
				continue
			}
			if strings.TrimSpace(strings.Trim(strings.TrimPrefix(t, key+"="), "'\"")) != "" {
				return
			}
		}
		set(key, value)
	}
	// ★★★ AND A VALUE SOMEBODY HAS ALREADY FILLED IN IS NOT REPLACED (2026-08-25, done to a running region).
	//
	// Two of the values below are deliberately written as placeholders for the operator to replace. Running
	// -region again — to rename the region, or after carrying a fresh copy of the deployment directory —
	// wrote the placeholder back over the real address. Nothing failed at that moment: the Edges keep serving
	// what they booted with. They simply stop pulling configuration and stop reporting, and the fleet view
	// shows them as silent, which is the same thing it shows for a machine that is switched off.
	//
	// So a placeholder is only ever written into an EMPTY or still-placeholder slot.
	setUnlessAnswered := func(key, placeholder string) {
		for _, line := range lines {
			t := strings.TrimSpace(line)
			if !strings.HasPrefix(t, key+"=") {
				continue
			}
			current := strings.Trim(strings.TrimPrefix(t, key+"="), "'\"")
			if strings.TrimSpace(current) != "" && !strings.Contains(current, placeholderHost) {
				return // the operator answered this; leave their answer alone
			}
		}
		set(key, placeholder)
	}
	set("DSSE_EDGE_REGION", region)
	// ★★★ AND THE NAMES THIS REGION'S CONTAINERS ANSWER TO. Every region is rendered from the SAME carried
	// directory, so without this both would name the same compose project — and on one host, bringing the
	// second one up does not stand up a second region: compose reconciles the project it already knows, which
	// means tearing down what the first region is still serving from. On separate hosts, which is where
	// regions actually live, it is invisible; so it is the defect that appears the first time somebody tries
	// it, on the day they are trying to do something else.
	set("DSSE_PROJECT", "dsse-"+region)
	// ★★★ WHERE THE DEPLOYMENT'S AUTHORITY ANSWERS. This region runs no control plane, so its Edges take
	// configuration across regions from whichever node currently holds leadership. Left as a placeholder the
	// operator must replace: guessing it would produce a region whose Edges point confidently at nothing, and
	// an Edge with no control plane refuses to start — which is the right direction, and a clearer failure
	// than a hostname somebody has to discover is wrong.
	setUnlessAnswered("DSSE_CONTROL_PLANE", "https://admin."+placeholderHost)
	// ★★★ THE AUTHORITY'S WRITE DOOR, ON 443 AND BY NAME. This region has no network in common with the one
	// that holds the state, so "dsse-control-plane:8443" reaches nothing here. What an Edge WRITES — the
	// history it recorded, an enrolment it completed, a connector that joined — goes to this name. Without
	// it a device enrolled in this region is admitted here and unknown to the authority: blocking it answers
	// 404, and removing it stops nothing.
	setUnlessAnswered("DSSE_CONTROL_PLANE_DATA", "https://authority."+placeholderHost)
	// ★★★ AND THE DATABASE, WHEN THIS REGION RUNS A WARM CONTROL PLANE (2026-08-26, found by carrying a
	// directory and running the printed command). The rendered compose requires DSSE_POSTGRES_DSN with `:?`,
	// deliberately — a standby that invented its own database would be a second deployment — and nothing
	// wrote it, so the very next command an operator runs stops with:
	//
	//	error while interpolating services.dsse-control-plane-a.environment.DSSE_POSTGRES_DSN:
	//	required variable DSSE_POSTGRES_DSN is missing a value
	//
	// A placeholder rather than a guess, for the same reason as the two above: this region has no network in
	// common with the one holding the state, so only the operator knows how the database is reached from
	// here. It is written so the file SHOWS what has to be answered, instead of the compose file being the
	// first place anybody learns it exists.
	if standbyControlPlane {
		setUnlessAnswered("DSSE_POSTGRES_DSN",
			"postgres://dsse:CHANGE-ME@"+placeholderHost+":5432/dsse?sslmode=disable")
	}
	// ★★★ A REGION THAT KEEPS STATE ANSWERS A DIFFERENT QUESTION (2026-08-27). It does NOT reach across to
	// another region's database — it runs members of the deployment's cluster here, which is the whole point,
	// and its own control planes talk to its own front door. What it cannot invent is where the CONSENSUS is:
	// the deployment has one store with a member per region, and Patroni here has to reach it to be told this
	// region's replica may be promoted.
	//
	// ★ WITHOUT IT, THE MEMBERS LOOK FOR A STORE ON THEIR OWN NETWORK AND FIND NOTHING — which reads as a
	// database that never finishes starting, and says nothing about consensus. A placeholder makes the
	// question visible in the file rather than in a symptom.
	if stateBearingJoin {
		// ★★★ AND ITS MEMBERS NEED NAMES NO OTHER REGION USES. Patroni identifies members BY NAME, and every
		// region is rendered from the same file — so without this both regions call their members
		// dsse-postgres-a and dsse-postgres-b. Two members with one name is not redundancy: it is two machines
		// each taking the other's state for its own. Derived from the region so nobody has to choose.
		set("DSSE_PG_A_NAME", region+"-postgres-a")
		set("DSSE_PG_B_NAME", region+"-postgres-b")
		setUnlessAnswered("DSSE_ETCD_HOSTS",
			"'"+placeholderHost+":12379','"+placeholderHost+":12380','"+placeholderHost+":12381'")
	}
	// The addresses have the same shape for a smaller reason: two bridges cannot share one subnet, and the
	// front doors cannot share one address. Derived from the region so the operator does not have to choose,
	// and overridable because a host may already be using this range.
	// ★★★ AND THE PUBLISHED PORTS, FOR THE SAME REASON AS THE SUBNET (2026-08-26, found by bringing a second
	// region up on one host):
	//
	//	Bind for 0.0.0.0:19543 failed: port is already allocated
	//
	// This command already concluded that two regions may share a host — it derives their subnets, their
	// front-door addresses and their compose project names precisely so they do not collide. The published
	// ports were the one thing left identical, so the second region got as far as CREATING its containers and
	// then failed on the first one that binds. In production each region is on its own host and the ports are
	// the same by design; on one host they cannot be, and the deployment that is easiest to try is the one
	// that collides.
	//
	// Derived from the region, so the operator does not choose, and overridable because a host may already be
	// using a range.
	//
	// ★★★ THE LIST IS EVERY PORT A MACHINE PUBLISHES, AND IT WENT STALE THE DAY ONE WAS ADDED (2026-09-05,
	// measured by rendering two regions into two directories on one host and reading what each publishes).
	// It named seven ports; three of them stopped being published on 2026-09-02 when the second control
	// plane, the second Edge and the control-plane door were retired, and two more were never published at
	// all. Meanwhile the AGENT port became published on every machine that runs Edges on 2026-09-03 — and
	// was not added here, because this list was written from the shape rather than from what binds. So both
	// regions rendered `8443:8443`, and the second one to start could not:
	//
	//	Bind for 0.0.0.0:8443 failed: port is already allocated
	//
	// which is the exact failure the note above records being fixed, returned by the same means.
	//
	// ★ THE AGENT PORT IS NOT OVERWRITTEN IF SOMETHING ALREADY ANSWERED IT. A plan gives a machine that sits
	// BEHIND a door 8443 deliberately, and the sibling and mesh addresses other machines are told are built
	// from that number — so a value already in the file is the deployment's answer and not this one's.
	if offset := regionPortOffset(region); offset > 0 {
		set("DSSE_REGION_PORT", fmt.Sprintf("%d", 18443+offset))
		set("DSSE_EDGE_ADMIN_PORT", fmt.Sprintf("%d", 19443+offset))
		setIfUnset("DSSE_EDGE_AGENT_PORT", fmt.Sprintf("%d", 8443+offset))
	}
	if octet := regionSubnetOctet(region); octet > 0 {
		set("DSSE_SUBNET", fmt.Sprintf("10.%d.0.0/16", octet))
		set("DSSE_SUBNET_RANGE", fmt.Sprintf("10.%d.1.0/24", octet))
		// ★★★ AND THE v6 SUBNET, WHICH WAS NOT MOVED AND COLLIDES ON ITS OWN. Everything above exists because
		// two regions may share a host; the v6 pool was left at one default for all of them, so the second
		// deployment or region on a host is refused before a single container starts:
		//
		//	failed to create network dsse_default: invalid pool request: Pool overlaps with other one on
		//	this address space
		//
		// which names no variable and reads as a broken compose file. A value that must be unique per
		// rendering is derived here with the others.
		set("DSSE_SUBNET_V6", fmt.Sprintf("fd00:d55e:%d::/64", octet))
		set("DSSE_FRONT_DOOR_A", fmt.Sprintf("10.%d.0.5", octet))
		// ★★★ ONE DOOR, SO ONE TRUSTED ADDRESS (2026-09-05). This named .6 as well, from when a region's
		// doorway was a PAIR. That door was retired on 2026-09-02 and nothing holds .6 now — and this list is
		// what makes a PROXY protocol header believable, so naming an address no door holds is telling every
		// Edge in the region to accept a device's claimed source address from a place the deployment does not
		// operate. Nothing was reachable through it; it was trust extended to nobody, which is the kind that
		// is never noticed until somebody is there.
		set("DSSE_TRUSTED_FRONT_DOORS", fmt.Sprintf("10.%d.0.5", octet))
	}
	for _, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "DSSE_REGION_ENDPOINTS=") {
			return os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600)
		}
	}
	lines = append(lines,
		"",
		"# The deployment's regions and the address each answers on. ★ KEEP THE QUOTES: this file is sourced,",
		"# and the ';' in this format is a command separator — an unquoted value makes every node exit 127.",
		"#   DSSE_REGION_ENDPOINTS='region-a=https://a.example;region-b=https://b.example'",
		"# ★ FILL THIS IN ONLY WHEN EVERY REGION EXISTS, AND GIVE EVERY EDGE THE SAME VALUE. An Edge holding a",
		"# shorter list is healthy and hands its devices a map missing the regions it never heard about, so a",
		"# device served by it never fails over there. Check it with: dsse-install -verify -edge-admin a,b,c",
		"DSSE_REGION_ENDPOINTS=''")
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600)
}

// reportRegion says what was prepared and what to do next.
//
// ★★★ IT USED TO DESCRIBE ONE SHAPE ON EVERY SHAPE (2026-08-27, caught by walking a second region's
// control-plane machine). The compose was rendered correctly — a state-bearing join, no consensus store, no
// Edges — and the text beside it said "THIS REGION HOLDS NO STATE" and told the operator to start "the region
// front door, Edge x N". So a machine that runs the authority and its database was handed the procedure for
// a machine that runs neither: an operator would look for Edges that are not there, and would never be told
// to bring up the database this region joins.
//
// A printed procedure that does not read the shape is a second description of the deployment, and it drifts
// the moment a shape is added — which is exactly what happened when one was.
func reportRegion(dir, region string, shape machineShape) {
	fmt.Printf("dsse-install: %s is prepared as region %q of an existing deployment.\n\n", dir, region)
	fmt.Printf("  ★ THE COMPOSE FILE WAS REPLACED. The one carried here describes the region it came from, and\n")
	fmt.Printf("  this region is a different shape — see below. Everything else in this directory is the\n")
	fmt.Printf("  deployment's and was left exactly as it arrived.\n\n")
	fmt.Printf("  ★ NOTHING WAS MINTED. This region uses the deployment's own anchor and authorities, which is\n")
	fmt.Printf("  what lets a device move between regions without meeting an issuer it has never heard of.\n\n")
	if shape.holds.holdsState() {
		fmt.Printf("  ★★★ THIS REGION HOLDS STATE, AND IT JOINS RATHER THAN FOUNDS. Its database members come up as\n")
		fmt.Printf("  REPLICAS of the deployment's existing primary, and its control planes contend for the SAME\n")
		fmt.Printf("  advisory lock as every other one — there is ONE leader for the whole deployment, and it is\n")
		fmt.Printf("  wherever the primary is. It runs NO consensus store of its own: there is one per deployment\n")
		fmt.Printf("  with a member per region, and a second cluster is a second opinion about which database is\n")
		fmt.Printf("  primary.\n\n")
		fmt.Printf("  ★★★ SO IT MUST BE TOLD WHERE THE DEPLOYMENT'S ARE, and both are placeholders until you do:\n")
		fmt.Printf("    DSSE_ETCD_HOSTS      the deployment's consensus store, reachable FROM HERE\n")
		fmt.Printf("    DSSE_CONTROL_PLANE   where the deployment's control plane answers\n")
		fmt.Printf("  ★ Reachable from here is an explicit act on the other side too: the store and the database\n")
		fmt.Printf("  publish on loopback by default, and widening them should reach this region and nothing else.\n\n")
		fmt.Printf("  ★★★ AND WIDENING THE PORT IS NOT ENOUGH FOR EITHER OF THEM (2026-08-27, measured by joining\n")
		fmt.Printf("  a region across machines). A client reaches the store on the address you configure here,\n")
		fmt.Printf("  then asks the CLUSTER for its members and uses what it is told from then on — and what it\n")
		fmt.Printf("  is told is each member's ADVERTISED address, which defaults to a container name on the\n")
		fmt.Printf("  founding machine. Patroni connects once, refreshes, and reports \"No more machines in the\n")
		fmt.Printf("  cluster\", naming nothing you configured. Set DSSE_ETCD_A_ADVERTISE / _B_ / _C_ on the\n")
		fmt.Printf("  machine that runs the store to addresses THIS region can dial.\n")
		fmt.Printf("  ★★★ AND THE DATABASE HAS THE SAME SHAPE. Its members advertise an address too, and one\n")
		fmt.Printf("  reached from another region has to be PUBLISHED as well as advertised. On every machine\n")
		fmt.Printf("  that runs the database, per member:\n")
		fmt.Printf("    DSSE_PG_A_MEMBER_PUBLISH / _API_PUBLISH    where this member listens for other regions\n")
		fmt.Printf("    DSSE_PG_A_ADVERTISE      / _API_ADVERTISE   what it writes into the cluster as its address\n")
		fmt.Printf("  and the same for _B_. Loopback by default: a database published by accident is the thing\n")
		fmt.Printf("  in this deployment worth the most to somebody else.\n\n")
		fmt.Printf("  ★★★ AND THIS REGION'S DATABASE DOOR MUST KNOW THE DEPLOYMENT'S OTHER MEMBERS. It routes to\n")
		fmt.Printf("  whichever member answers that it is the primary, and in a region that JOINS both local\n")
		fmt.Printf("  members are replicas by definition — so a door that knows only them has no backend at all,\n")
		fmt.Printf("  and this region's control planes report the deployment's database as refusing connections.\n")
		fmt.Printf("  Set %s to the other regions' members, as host:port:apiport.\n\n", databasePeersKey)
	} else {
		fmt.Printf("  ★★★ AND THIS REGION HOLDS NO STATE. The deployment has ONE authority: every control plane\n")
		fmt.Printf("  contends for the SAME advisory lock, and that lock can only be taken on the database's primary,\n")
		fmt.Printf("  so the leader and the primary move together and there is one of each for the whole deployment.\n")
		fmt.Printf("  A region with its own consensus store and its own database would be a second DEPLOYMENT: two\n")
		fmt.Printf("  leaders, and \"has this identity already enrolled\" answered twice.\n\n")
		fmt.Printf("  ★ ADDING STATE HERE IS A DIFFERENT ACT, and not a flag on this command. A state-bearing region\n")
		fmt.Printf("  carries three things together — a quorum member of the deployment's consensus store, a REPLICA\n")
		fmt.Printf("  of its database, and a warm standby control plane — and all three JOIN what already exists.\n\n")
	}
	fmt.Printf("  this machine needs, in order:\n")
	if shape.holds.holdsAControlPlane() {
		fmt.Printf("    1. the database               it joins the deployment's cluster as a replica\n")
		fmt.Printf("    2. the control plane pair     ./start-control-plane.sh — a warm standby of the deployment's\n")
		fmt.Printf("    3. the region front door      L4, and the doorway for the planes this machine serves\n")
	} else {
		fmt.Printf("    1. the region front door      L4, one address for the agents\n")
		fmt.Printf("    2. Edge x N                   ./start-edge.sh — every node runs the same script\n")
	}
	fmt.Printf("\n")
	if shape.runsEdges() {
		fmt.Printf("  ★ FIRST, SET DSSE_CONTROL_PLANE in deployment.env to where the deployment's control plane\n")
		fmt.Printf("  answers. It is a placeholder until you do, and an Edge with no control plane refuses to start —\n")
		fmt.Printf("  which is the right direction, and a clearer failure than a hostname nobody notices is wrong.\n\n")
	}
	fmt.Printf("  ★★ THEN, ONCE EVERY REGION EXISTS — and not before:\n")
	fmt.Printf("    set DSSE_REGION_ENDPOINTS in deployment.env to the SAME value in every region, restart the\n")
	// ★★★ AND THE CONTROL PLANES, WHICH THIS LINE USED TO LEAVE OUT (2026-08-26, measured on a two-region
	// deployment). The region map is what a CONNECTOR's enrolment token carries, and the token is minted by
	// the control plane — not by an Edge. Restarting only the Edges left the authority with no map, so every
	// connector it issued was given a single door and could not fail over: the exact defect
	// a_connector_is_given_every_door.go was written to close, reappearing because the minting is on the
	// other node. Restarting the control planes made the next token carry both regions.
	fmt.Printf("    Edges AND THE CONTROL PLANES, and check they agree:\n")
	fmt.Printf("    (the control plane mints connector enrolment tokens, and a control plane with no region\n")
	fmt.Printf("     map issues connectors that have ONE door and cannot fail over)\n")
	fmt.Printf("      dsse-install -verify -dir %s -edge-admin https://<edge-a>:9443[,one per Edge machine] ...\n", dir)
	fmt.Printf("\n  ★★★ WRITING IT ON ONE SIDE ONLY IS THE FAILURE THIS ORDER EXISTS TO PREVENT. An Edge that was\n")
	fmt.Printf("  missed stays healthy and hands its devices a shorter map — they simply never fail over to the\n")
	fmt.Printf("  region it does not know about, and nothing reports it. The check above is what finds it.\n")
	fmt.Printf("\n  ★ Connectors and device agents come LAST, after the region they belong to is serving.\n")
}

// regionSubnetOctet turns a region id into a stable second octet, so two regions rendered on one host do not
// share a bridge. 0 means "could not choose one" and the deployment keeps the default, which is right: a
// guessed address that collides is worse than the operator setting DSSE_SUBNET themselves.
//
// ★ IT IS DERIVED, NOT COUNTED. Nothing here knows how many regions the deployment has — each one is prepared
// on its own host from a carried directory — so the number has to come from the region's own name or from the
// operator.
func regionSubnetOctet(region string) int {
	region = strings.ToLower(strings.TrimSpace(region))
	if region == "" {
		return 0
	}
	var sum int
	for _, r := range region {
		sum = (sum*31 + int(r)) % 200
	}
	// 10.77.x is the single-region default; keep away from it, and from 10.0/10.1 which hosts commonly use.
	octet := 20 + (sum % 200)
	if octet == 77 {
		octet = 78
	}
	return octet
}

// composeStandsUpTheState reports whether the compose file in this directory carries the state-bearing block:
// the consensus store, the database and the control planes. It reads the FILE rather than a flag or a name,
// because the file is the thing -region would overwrite.
func composeStandsUpTheState(dir string) (bool, error) {
	body, err := os.ReadFile(filepath.Join(dir, "docker-compose.yml"))
	if err != nil {
		// No compose file at all is the ordinary case for a carried directory, and not an error here.
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	text := string(body)
	// ★ ALL THREE, NOT ANY. A joining region's file names the control plane in DSSE_CONTROL_PLANE and in the
	// note explaining why it has none, so a single-substring test matches the very file this is meant to
	// distinguish from. The service DEFINITIONS are what only a state-bearing file has.
	for _, service := range []string{"\n  dsse-store-a:", "\n  dsse-postgres-a:", "\n  dsse-control-plane-a:"} {
		if !strings.Contains(text, service) {
			return false, nil
		}
	}
	return true, nil
}

// sameRegionAsRecorded reports whether deployment.env already calls this directory the region being asked for.
// A directory that has never been named is not the same as one that was named something else, so an absent
// value answers false: the guard is for the operator who ran this on the origin, not for a fresh copy.
func sameRegionAsRecorded(dir, region string) bool {
	body, err := os.ReadFile(filepath.Join(dir, "deployment.env"))
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(body), "\n") {
		t := strings.TrimSpace(line)
		if !strings.HasPrefix(t, "DSSE_EDGE_REGION=") {
			continue
		}
		current := strings.Trim(strings.TrimPrefix(t, "DSSE_EDGE_REGION="), "'\"")
		return strings.EqualFold(strings.TrimSpace(current), region)
	}
	return false
}

// regionShapeFromCompose reads which of the three shapes a directory's compose file ALREADY stands up.
//
// ★★★ TWO SHAPES WERE ASSUMED AND THERE ARE THREE (2026-08-25, caught by diffing a rewrite before restarting
// anything). Regenerating a joining region's compose from a two-way guess replaced its warm control plane with
// an edges-only file — a region that would have come back without the control plane it had, on the next
// restart, for no reason the operator asked for. The shape is not a guess: the file says what it stands up.
//
// The second return is false when the file names none of the three, which is a directory this installer must
// not rewrite rather than one it should reshape.
// shapeOverride is set when the operator NAMES the shape on the command line. ★ AN EXPLICIT ANSWER OUTRANKS
// WHAT THE FILE SAYS (2026-08-27): the repair reads the compose to avoid reshaping a region nobody asked to
// reshape, which is right — and it made -control-plane-only inert on any directory that had already been
// minted, which is every directory anybody would run it on.
var shapeOverride *machineShape

func regionShapeFromCompose(dir string) (machineShape, bool) {
	if shapeOverride != nil {
		return *shapeOverride, true
	}
	body, err := os.ReadFile(filepath.Join(dir, "docker-compose.yml"))
	if err != nil {
		// ★★★ NO FILE IS NOT AN UNKNOWN SHAPE (2026-08-27, measured by deleting it to force a rewrite). The
		// repair reads this to avoid RESHAPING a region nobody asked to reshape — and answered "unknown" for a
		// directory with no compose at all, so it left the deployment with none. A directory that holds this
		// deployment's authorities and has no compose is the region that MINTED them: the shape that founds a
		// deployment, which is the only one it could be.
		if _, mintErr := os.Stat(filepath.Join(dir, "root.crt")); mintErr == nil {
			return machineShape{holds: regionShapeStateBearing, edges: true}, true
		}
		return machineShape{holds: regionShapeEdgesOnly, edges: true}, false
	}
	text := string(body)
	has := func(service string) bool { return strings.Contains(text, "\n  "+service+":") }
	// ★ AND WHETHER THIS MACHINE RUNS THE EDGES IS THE FILE'S ANSWER TOO. A machine holding the Control Plane
	// component defines no Edge, and a rewrite that assumed it did would put a fleet back beside the authority
	// on the next repair.
	edges := has("dsse-edge-a")
	// ★★★ AND THE FILE KNOWS WHETHER THE STORE SPANS REGIONS (2026-09-02, measured on a live three-region
	// deployment while checking a shape change actually runs).
	//
	// storeSpansRegions says "this deployment keeps state elsewhere too, so the store has ONE member here"
	// and its comment says only the plan knows that — true of a machine being packed for the first time, and
	// false of this one. A repair is reading a compose file that was ALREADY rendered from the plan, and that
	// file answers the question directly: a store with a second member here is the whole cluster on one host,
	// and a store without one is a member of a cluster that lives in more than one place.
	//
	// Guessing instead turned a joining region back into a founding one. On a deployment of three regions of
	// one machine each — every one of which has store-a, postgres-a and control-plane-a — the repair added
	// dsse-store-b and dsse-store-c to a machine that holds one vote, and the next `up -d` would have started
	// two more etcd members beside a cluster that had never heard of them. Nothing in the repair's output
	// mentioned the store: it printed the haproxy files it rewrote and "nothing changes until the deployment
	// is restarted".
	spans := has("dsse-store-a") && !has("dsse-store-b")
	// ★ A MACHINE BEHIND THE DOOR RENDERS NO DOOR. Same reading, same reason: the file says whether this
	// machine is the region's doorway, and a repair that assumed it was would put a second door in the region.
	behind := edges && !has("dsse-edge")
	switch {
	case has("dsse-store-a") && has("dsse-postgres-a") && has("dsse-control-plane-a"):
		return machineShape{holds: regionShapeStateBearing, edges: edges, storeSpansRegions: spans, behindDoorway: behind}, true
	case has("dsse-postgres-a") && has("dsse-control-plane-a"):
		// ★ A DATABASE BUT NO CONSENSUS STORE: this region keeps state and JOINS the deployment's cluster
		// rather than founding one. There is one consensus store per deployment, so its absence here is the
		// shape, not an omission — and its PRESENCE is what would make this a second deployment.
		return machineShape{holds: regionShapeStateBearingJoin, edges: edges, storeSpansRegions: spans, behindDoorway: behind}, true
	case has("dsse-control-plane-a"):
		// A control plane with no database of its own JOINS the deployment's. That is the standby shape.
		// ★ AND IT IS NOT SOMEWHERE LEADERSHIP CAN MOVE TO when the region holding the state is gone: there
		// is nothing here to promote. See regionShapeStateBearingJoin for the shape that is.
		return machineShape{holds: regionShapeStandbyCP, edges: edges, behindDoorway: behind}, true
	case has("dsse-edge-a"):
		return machineShape{holds: regionShapeEdgesOnly, edges: true, behindDoorway: behind}, true
	}
	return machineShape{holds: regionShapeEdgesOnly, edges: true}, false
}

// regionPortOffset moves a region's published ports clear of every other region's, on a host where more than
// one of them runs.
//
// ★ IT IS A MULTIPLE OF A THOUSAND so the numbers stay readable: region-a's 19543 becomes 20543, not 19551.
// An operator reading a port has to be able to tell which region it belongs to, and a small offset makes two
// regions' ports interleave into a list nobody can scan.
func regionPortOffset(region string) int {
	region = strings.ToLower(strings.TrimSpace(region))
	if region == "" || region == "region-a" {
		// The first region keeps the numbers the single-region deployment already uses, so nothing that was
		// written down for it stops being true.
		return 0
	}
	var sum int
	for _, r := range region {
		sum = (sum*31 + int(r)) % 40
	}
	return 1000 * (1 + sum%40)
}

// planeHostOf is the name this deployment's planes hang off, read from its own environment. The same
// derivation repairDerivedFiles uses: the agent plane's name if it has one, the deployment's name otherwise.
func planeHostOf(dir string) string {
	env := readDeploymentEnv(dir)
	if h := strings.TrimSpace(env["DSSE_AGENT_PLANE_NAME"]); h != "" {
		return h
	}
	return strings.TrimSpace(env["EDGE_HOST"])
}
