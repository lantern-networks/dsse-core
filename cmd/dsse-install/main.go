// Command dsse-install prepares a deployment: it mints the authorities a deployment needs and issues the
// certificates its own processes present, so that starting one requires nothing but a hostname.
//
// ★★★ WHY AN INSTALLER MINTS THESE, AND NOT EACH PROCESS FOR ITSELF (design decision 2026-08-22, and the
// reasoning is measured rather than aesthetic — see docs/strategy/installer_mints_the_ca.ja.md).
//
// A node with no certificate refuses to start unless it is in dev mode, where it self-signs. Promoting that
// to production would give every process its own anchor, and then:
//
//   - N self-signed certificates need N distribution paths. Every party — the Console, an Edge, a connector,
//     a device — has to be told about each one separately.
//   - The SECOND Edge presents something nobody was told about. That is precisely what the fleet guard
//     refuses (refuseToJoinFleetIfPromisesCannotBeKeptWithAnchors), and it refuses correctly.
//   - A device arrives holding ONLY its organization's anchor. Anything it reaches by address is served the
//     deployment-wide certificate — which, if that certificate differs per node, fails on some nodes and not
//     others. This deployment spent 2026-08-22 on exactly that failure with ONE such certificate.
//
// One anchor at the entrance means one thing to distribute. That is not a new shape: it is the shape the
// reference deployment already has. What changes is who creates it.
//
// ★ WHAT THIS DOES NOT CREATE. Per-organization authorities — transport, device identity, interception — are
// the CONTROL PLANE's, made when an organization is created, and an organization's interception ROOT is the
// organization's own and never held here at all. The installer touches the deployment side only.
package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/bundle"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/signedconfig"
)

func main() {
	dir := flag.String("dir", "", "directory the deployment's keys and certificates live in. Created if absent, "+
		"and NEVER a temporary path: an authority that does not outlive the installer leaves anchors devices "+
		"have adopted and nobody can issue for")
	host := flag.String("host", "", "the name or address this deployment answers on. Repeatable as a "+
		"comma-separated list; every entry lands in the certificates this deployment presents")
	orgName := flag.String("organization", "DSSE Deployment", "the O= this deployment's own certificates carry")
	years := flag.Int("years", 10, "how long the deployment's root is valid for")
	force := flag.Bool("force", false, "mint again even though this directory already holds authorities. "+
		"THIS ORPHANS EVERY ANCHOR ALREADY DISTRIBUTED — devices that adopted the old one can no longer verify "+
		"this deployment, and they cannot be repaired over the channel that just broke")
	// ★★★ THE CHECKING IS PART OF THE INSTALLER (2026-08-23). An installer that produces a deployment and
	// leaves somebody else to establish whether it works has done half the job — and the half it skipped is
	// the one that catches a control plane answering /healthz while nobody can authenticate to it.
	//
	// Every requirement this tool carries was found by walking the procedure by hand, once. A finding that is
	// only ever found by hand is found again by the next person, on their deployment, at their cost. -verify
	// runs those same checks and names which invariant failed rather than reporting that something is
	// unhealthy.
	// ★★★ THE QUESTION SOMEBODY ASKS BEFORE STOPPING SOMETHING, which is not the one -verify answers. See
	// who_depends.go: a deployment can be green on every inward check while stopping it takes a machine's
	// entire network with it, and the machines that cannot come back by themselves are nameable in advance.
	whoDepends := flag.Bool("who-depends", false,
		"instead of checking this deployment, ask what depends on it: how many machines trust it, how many of "+
			"those can come back by themselves if it changes or stops, and how many were relying on it in the "+
			"last hour. Ask this BEFORE tearing anything down. Requires -control-plane")
	verify := flag.Bool("verify", false,
		"check a deployment that is already running, instead of minting one. Asserts, in the order they can "+
			"fail: the control plane answers, it can be ADMINISTERED, the Edge answers, the Edge has APPLIED "+
			"configuration from the control plane, a device can enrol, and the same one-time token cannot be "+
			"used twice. Requires -control-plane and -edge")
	verifyNoWait := flag.Bool("verify-no-wait", false,
		"with -verify: check initial control-plane, Edge configuration and fleet readiness immediately, "+
			"without waiting for startup. All checks still run; request timeouts and waits after verification writes are unchanged")
	cpAdmin := flag.String("control-plane", "",
		"with -verify: the control plane's admin URL, e.g. https://cp.example:9443")
	// ★★★ THE DEPLOYMENT, DESCRIBED ONCE (2026-08-28). See plan.go: everything an operator had to set on each
	// machine by hand was decided before anything was installed, and every hand-set value that was wrong was
	// silent. -plan names the file that says it, and the machine flags below still describe ONE machine.
	planFile := flag.String("plan", "",
		"a JSON description of the whole deployment: its name, its regions, and each region's machines with "+
			"the addresses their front doors bind. Everything that differs between machines — which region "+
			"this is, which address each door binds, where the state and consensus answer from, what each "+
			"database member is called, which of the other regions' members this one must reach — is DERIVED "+
			"from it rather than typed onto each machine. Use with -dir to install, or with -carry to pack one "+
			"machine of it")
	planOrder := flag.Bool("order", false,
		"with -plan: print every step of standing this deployment up, in the only order that works, with what "+
			"must already be true before each and what goes wrong if it is done early. The order is derived "+
			"from the description like everything else — it was learned by doing it wrong and written in no file")
	planMachine := flag.String("machine", "",
		"with -plan and -carry: which machine of the plan to pack. Its shape, its region and every address it "+
			"is given come from the plan")
	edgeAdmin := flag.String("edge-admin", "",
		"with -verify: an Edge's admin URL, e.g. https://edge.example:9443. Comma-separated for a fleet — "+
			"whether every Edge hands devices the SAME region map is a property of the fleet and cannot be "+
			"asked of one node, and an Edge that was missed when a region was added is healthy and hands its "+
			"devices a shorter map")
	verifyAdminToken := flag.String("admin-token", "",
		"with -verify: a named API token to check the enrolment path with. Needed only AFTER "+
			"-bootstrap-admin has run, because the break-glass credential is refused from then on — which is "+
			"why the natural order is to verify while the deployment is still being installed, and close it last")
	cpPeers := flag.String("control-plane-peers", "",
		"with -verify: the individual control planes BEHIND the front door, comma-separated. Whether the "+
			"authority is redundant is a question about those nodes; through a front door one control plane "+
			"and two look identical, which is what a front door is for")
	consoleURL := flag.String("console", "",
		"with -verify: the Admin Console's URL, e.g. https://console.example:8088. Checked for whether it "+
			"answers and whether the node behind its ADMIN surface is the CONTROL PLANE — observation is the "+
			"Edge reporting, never the Console asking an Edge, because a read served from an Edge depends on "+
			"which node the front door picked")
	edgeTransport := flag.String("edge", "",
		"with -verify: the region's device-facing URL, e.g. https://edge.example:8443 — devices reach an Edge to enrol, so the enrolment check goes here rather than to the control plane. Comma-separated for the region's front doors: whether losing one takes the agent plane with it is a property of the PAIR and cannot be asked of one door")
	// ★★★ AND THE CIRCLE THE ARMING OPENED IS CLOSED HERE. A new deployment cannot be administered until the
	// break-glass credential is armed, and it must not stay armed — see bootstrap.go. This creates the first
	// named administrator, proves it can sign in, and writes the marker that stops the start script arming
	// anything from the next restart.
	bootstrapAdmin := flag.Bool("bootstrap-admin", false,
		"create this deployment's FIRST named administrator, while the break-glass credential is armed, and "+
			"close it. Requires -dir, -control-plane and -admin-email")
	adminEmail := flag.String("admin-email", "",
		"with -bootstrap-admin: the address of the deployment's first administrator")
	// ★★★ A REGION IS NOT A DEPLOYMENT (2026-08-23, walked). See region.go: this prepares an EXISTING
	// deployment's material for one more region, and refuses to mint, because an operator who stands up
	// region B by re-running the install command creates a second deployment and is told nothing.
	region := flag.String("region", "",
		"prepare an EXISTING deployment's directory as another REGION, e.g. region-b. Mints nothing: carry "+
			"the deployment directory from the region that created it and point -dir at the copy. A "+
			"deployment has one anchor however many regions it spans, and minting a second gives a device "+
			"that MOVES between regions an issuer it has never heard of")
	// ★★★ THE CARRY IS PART OF THE PRODUCT OR IT IS A tar COMMAND SOMEBODY REMEMBERS (2026-08-27, measured
	// on the AWS lab). See carry.go: "carry the deployment directory" put the root CA private key on the
	// Edge's machine, and it was deleted afterwards by hand.
	carryTo := flag.String("carry", "",
		"pack this deployment for a machine that did NOT mint it, and write it to the named .tar.gz. "+
			"Everything a receiving machine needs, and structurally NOT authority/ — the root CA private key "+
			"and the three beside it, which no running process reads and only this installer signs with. The "+
			"file still holds private keys; move it as privately as the directory it came from")
	addEdge := flag.String("add-edge", "",
		"with -plan and -dir, run on the machine that holds a region's door: teach that door about a machine "+
			"which holds only edges and has been added to the plan since this deployment was installed. The "+
			"region keeps ONE door and balances over the Edges behind it. Additive and derived — running it "+
			"twice says nothing changed — and it reloads rather than replaces the door, because recreating it "+
			"would drop every established connection in the region for the sake of adding capacity")
	addHost := flag.String("add-host", "",
		"teach a deployment that ALREADY EXISTS another name or address it answers on, e.g. a machine's "+
			"tailnet name. Re-issues the leaf certificates from the authorities already on disk and touches "+
			"neither — so every anchor already distributed keeps verifying. Additive: the names already in "+
			"the certificate are kept. Restart the nodes afterwards, or the new name is in a file and not on "+
			"the wire")
	regionStandbyCP := flag.Bool("with-standby-control-plane", false,
		"with -region: this region also runs a WARM CONTROL PLANE that joins the deployment's existing "+
			"database and contends for the same leader lock, so leadership can move here. It stands up no "+
			"database and no consensus store of its own — that would be a second deployment. Requires "+
			"DSSE_POSTGRES_DSN (and the hot store / archive endpoints) to name the deployment's, reachable "+
			"from this region. ★ This is ONE THIRD of a state-bearing region: leadership can move here while "+
			"that database is reachable, and cannot move here when the region holding it is gone")
	controlPlaneOnly := flag.Bool("control-plane-only", false,
		"render this machine as the Control Plane component and nothing else: the control planes, their "+
			"database, their consensus store, their hot store, their archive and their Console — with no Edge. "+
			"★ Use it when every component has its own machine, which is what this product is deployed as. "+
			"Without it a control-plane machine also DEFINES the Edges, offers their admin ports, and starts "+
			"Edge processes beside the authority the moment anything brings the doorway up.")
	storeSpansRegions := flag.Bool("store-spans-regions", false,
		"this deployment keeps state in MORE THAN ONE region, so the consensus store has ONE member on this "+
			"machine and its others in the other state-bearing regions. Without it a state-bearing region "+
			"renders the WHOLE store — three members on this host — which is right for a deployment that IS "+
			"one host and wrong the moment a second region holds state: three votes in one place and one in "+
			"each of the others means losing that place loses the quorum, so the deployment with MORE machines "+
			"tolerates FEWER failures. ★ The canonical footprint is a member per state-bearing region, and "+
			"surviving the loss of one costs three of them. ★ Redundancy arrives when the THIRD member joins "+
			"and not before: the members before it are a cluster that cannot lose one.")
	regionHoldsState := flag.Bool("holds-state", false,
		"with -region: this region KEEPS A DATABASE of the deployment's cluster, so leadership can move here "+
			"even when the region that had it is gone. It renders its own Postgres members (which come up as "+
			"replicas of the existing primary), its own control planes, and its own hot store, archive and "+
			"Console. It renders NO consensus store: there is one per deployment with a member per region, and "+
			"a second cluster is a second opinion about which database is primary. Requires DSSE_ETCD_HOSTS to "+
			"name the deployment's consensus store, reachable from here. ★ This is what the canonical calls a "+
			"state-bearing region, and it is the difference between a region leadership can move TO and one "+
			"where there is nothing to promote")
	adminPassword := flag.String("admin-password", "",
		"with -bootstrap-admin: their password. Generated and printed once when omitted, which is the "+
			"better of the two — a password on a command line is in the shell history and in every ps listing")
	flag.Parse()

	if strings.TrimSpace(*addEdge) != "" {
		if strings.TrimSpace(*planFile) == "" {
			fmt.Fprintln(os.Stderr, "dsse-install: -add-edge needs -plan: the machine's region and address are "+
				"derived from the plan rather than typed here")
			os.Exit(1)
		}
		if err := addAnEdgeToARunningRegion(*dir, *planFile, *addEdge); err != nil {
			fmt.Fprintf(os.Stderr, "dsse-install: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if strings.TrimSpace(*addHost) != "" {
		if err := addHostsToDeployment(*dir, *addHost); err != nil {
			fmt.Fprintf(os.Stderr, "dsse-install: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if *bootstrapAdmin {
		if err := runBootstrapAdmin(*dir, *cpAdmin, *adminEmail, *adminPassword); err != nil {
			fmt.Fprintf(os.Stderr, "dsse-install: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// ★ THE FOUNDING MACHINE CAN BE CONTROL-PLANE-ONLY TOO. It mints the authorities and runs the Control
	// Plane component; its Edges are on their own machines from the start.
	if *controlPlaneOnly {
		// ★ THE FOUNDING MACHINE CAN BE A CONTROL-PLANE MACHINE TOO: it mints the authorities and runs the
		// Control Plane component, and its Edges are on their own machines from the start.
		foundingShape = machineShape{holds: regionShapeStateBearing, edges: false}
		cpOnly := foundingShape
		shapeOverride = &cpOnly
	}
	// ★★★ THE CARRY IS FOR ONE MACHINE, AND THE SHAPE FLAGS SAY WHICH — read BEFORE -region acts, because
	// -carry describes a machine rather than installing one. The same flags that render a machine's compose
	// choose what that machine may hold, so there is no second vocabulary to keep in step with the first.
	// ★★★ ONE MACHINE OF A PLAN. The shape, the region and every address are read from the description rather
	// than repeated on the command line — which is where they were wrong, every time, on every machine.
	// ★★★ MAKING AN EXISTING DIRECTORY BE ONE OF THE PLAN'S MACHINES (2026-08-28). Every other machine gets
	// its values when it is packed; the one the deployment was MINTED on had no way to be given them again
	// after the plan changed — so it kept whatever it was installed with while every other machine moved on,
	// which is the fleet-half-on-yesterday's-answers shape.
	if *planFile != "" && *planMachine != "" && *carryTo == "" && !*planOrder {
		plan, perr := LoadPlan(*planFile)
		if perr != nil {
			fmt.Fprintf(os.Stderr, "dsse-install: %v\n", perr)
			os.Exit(1)
		}
		if err := applyPlanToThisMachine(plan, *dir, *planMachine); err != nil {
			fmt.Fprintf(os.Stderr, "dsse-install: %v\n", err)
			os.Exit(1)
		}
		return
	}
	if *planOrder && *planFile != "" {
		plan, perr := LoadPlan(*planFile)
		if perr != nil {
			fmt.Fprintf(os.Stderr, "dsse-install: %v\n", perr)
			os.Exit(1)
		}
		PrintInstallOrder(plan, *dir, *planFile)
		return
	}
	if *carryTo != "" && *planFile != "" {
		plan, perr := LoadPlan(*planFile)
		if perr != nil {
			fmt.Fprintf(os.Stderr, "dsse-install: %v\n", perr)
			os.Exit(1)
		}
		if err := carryPlanMachine(plan, *dir, *carryTo, *planMachine); err != nil {
			fmt.Fprintf(os.Stderr, "dsse-install: %v\n", err)
			os.Exit(1)
		}
		return
	}
	if *carryTo != "" {
		carried, withheld, err := carryDeploymentFor(*dir, *carryTo,
			shapeFromFlags(*controlPlaneOnly, *region, *regionHoldsState, *regionStandbyCP, *storeSpansRegions), *region, nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "dsse-install: %v\n", err)
			os.Exit(1)
		}
		reportCarry(*carryTo, *dir, carried, withheld)
		return
	}

	if *region != "" {
		shape := shapeFromFlags(*controlPlaneOnly, *region, *regionHoldsState, *regionStandbyCP, *storeSpansRegions)
		if err := regionInstall(*dir, *region, shape); err != nil {
			fmt.Fprintf(os.Stderr, "dsse-install: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if *whoDepends {
		if err := runWhoDepends(*dir, *cpAdmin, *verifyAdminToken); err != nil {
			fmt.Fprintf(os.Stderr, "dsse-install: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if *verify {
		if err := runVerify(*dir, *cpAdmin, *edgeAdmin, *edgeTransport, *verifyAdminToken, *consoleURL, *cpPeers, *verifyNoWait); err != nil {
			fmt.Fprintf(os.Stderr, "dsse-install: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// ★★★ INSTALLING FROM THE DESCRIPTION. The names this deployment answers on are every plane of every
	// region plus every machine the other regions reach by name — a list nobody should be assembling on a
	// command line, and one that was wrong every time it was. -host still works and is what an operator
	// installing one deployment by hand uses.
	hosts, orgFromPlan := *host, *orgName
	if *planFile != "" {
		installingFromAPlan = true
		plan, perr := LoadPlan(*planFile)
		if perr != nil {
			fmt.Fprintf(os.Stderr, "dsse-install: %v\n", perr)
			os.Exit(1)
		}
		hosts = strings.Join(plan.CertificateNames(), ",")
		if err := run(*dir, hosts, orgFromPlan, *years, *force); err != nil {
			fmt.Fprintf(os.Stderr, "dsse-install: %v\n", err)
			os.Exit(1)
		}
		if err := applyPlanToFoundingMachine(plan, *dir); err != nil {
			fmt.Fprintf(os.Stderr, "dsse-install: %v\n", err)
			os.Exit(1)
		}
		// Now that the plan's values are in the file — see reportRegionName for why this is here and not
		// inside the report above.
		reportRegionName(*dir)
		return
	}

	if err := run(*dir, hosts, orgFromPlan, *years, *force); err != nil {
		fmt.Fprintf(os.Stderr, "dsse-install: %v\n", err)
		os.Exit(1)
	}
}

// deploymentAuthorities is what a deployment holds. Named rather than a bag of files, because the set is the
// design: adding one later is a decision about what a device has to be told, not a detail.
type deploymentAuthorities struct {
	RootCert  *x509.Certificate
	RootKey   *ecdsa.PrivateKey
	AdminCA   *x509.Certificate
	AdminKey  *ecdsa.PrivateKey
	TransCA   *x509.Certificate
	TransKey  *ecdsa.PrivateKey
	DeviceCA  *x509.Certificate
	DeviceKey *ecdsa.PrivateKey
	// InterceptCA is the THIRD TIER, and a deployment without it inspects nothing.
	//
	// ★★★ THE ARCHITECTURE NAMES THREE AND THIS INSTALLER MINTED TWO (2026-08-26, reported from real hardware
	// as letter 105 and confirmed by reading the generated directory). "One deployment = one anchor and three
	// tiers: transport / device-identity / interception." transport-ca and device-ca were here; nothing signed
	// the certificates an Edge presents to a browser, and the generated start script did not mention
	// interception at all. The organization checklist then said done 4/13, blocking [] — on a deployment where
	// nothing has ever been inspected.
	InterceptCA  *x509.Certificate
	InterceptKey *rsa.PrivateKey
}

// installingFromAPlan is set by the plan branch so report() leaves the region's name to it. A package
// variable rather than a parameter because report() is reached through run() and several callers, and
// threading a flag through all of them to decide one printed line is worse than saying it once here.
var installingFromAPlan bool

func run(dir, hosts, orgName string, years int, force bool) error {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return fmt.Errorf("-dir is required: name the directory this deployment's authorities live in, and " +
			"make it one that outlives this command")
	}
	names, ips, err := parseHosts(hosts)
	if err != nil {
		return err
	}

	// ★ IDEMPOTENT BY DEFAULT. A second run must not quietly replace an authority: devices adopt anchors, and
	// an anchor replaced without the announce/measure/retire sequence strands every one of them.
	existing, err := alreadyMinted(dir)
	if err != nil {
		return err
	}
	// ★★★ -host IS FOR MINTING, AND A REPAIR WAS DEMANDING IT ANYWAY (2026-08-27, found walking the paid lane).
	// This check sat above the idempotency branch, so refreshing an existing deployment's derived files failed
	// with "a deployment's certificates have to name where it answers" — about certificates that were minted
	// months ago and are not touched. Worse than the inconvenience: the value is IGNORED on that path (the
	// repair reads EDGE_HOST from deployment.env, which is the deployment's own record of it), so the flag was
	// required, unused, and teaching an operator that restating it mattered. Getting it wrong is exactly how a
	// deployment ends up with the wrong EDGE_HOST.
	if len(names)+len(ips) == 0 && !existing {
		return fmt.Errorf("-host is required: a deployment's certificates have to name where it answers, and " +
			"a device that reaches a name the certificate does not carry cannot tell that from an outage")
	}
	if existing && !force {
		fmt.Printf("dsse-install: %s already holds this deployment's authorities — nothing to do.\n", dir)
		fmt.Printf("  Replacing them is a rotation, not an install: it orphans every anchor already\n")
		fmt.Printf("  distributed. Use the rotation acts on a running deployment, which announce the new\n")
		fmt.Printf("  authority, measure adoption and retire the old one. -force skips all of that.\n")
		// ★★ "NOTHING TO DO" WAS NOT QUITE TRUE (2026-08-25). Files that are DERIVED from an authority — not
		// the authority itself — are not a rotation to write, and a deployment that has been running since
		// before one of them existed will never get it any other way. agent-policy-signing.pub is the case
		// that showed this: the public half an agent package is built with, absent from a live deployment,
		// obtainable only by grepping an Edge's start-up log. Repair is idempotent and touches no secret.
		if err := repairDerivedFiles(dir); err != nil {
			return err
		}
		return nil
	}
	// ★★★ 0755, AND THE SECRETS ARE IN A SUBDIRECTORY THAT IS NOT (2026-09-02, measured on the founding
	// machine of a live deployment).
	//
	// This was 0700, and the installer runs as root, so the founding region's directory came out root:root
	// 0700. The very next printed step is a docker compose command that has to run from inside it, and the
	// operator who ran step 1 could not even cd there:
	//
	//	bash: line 1: cd: /opt/dsse/tokyo-east: Permission denied
	//
	// A joining region's directory is made by tar and comes out traversable, so this was true of exactly one
	// machine in the fleet — the first one, on every deployment. What actually needs protecting is the
	// minting material, and moveAuthorityMaterialIntoPlace already puts it in <dir>/authority, which is
	// created 0700 in its own right. Everything else here is configuration an operator has to read.
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}

	now := time.Now().UTC()
	auth, err := mint(orgName, now, years)
	if err != nil {
		return err
	}
	if err := writeAuthorities(dir, auth); err != nil {
		return err
	}
	// ★★★ THE STORE'S OWN AUTHORITY, MINTED HERE BECAUSE NOTHING LATER CAN (2026-08-31). Once the consensus
	// store has a member in each state-bearing region its members talk across whatever is between those
	// regions, and what crosses is which database is primary. The control plane cannot issue these: it starts
	// after Postgres, which starts after the store. See the_store_has_its_own_authority.go.
	storeCA, serr := mintStoreAuthority(orgName, now, years)
	if serr != nil {
		return serr
	}
	if serr := writeStoreAuthority(dir, storeCA); serr != nil {
		return serr
	}
	// ★ AND A MEMBER CERTIFICATE STRAIGHT AWAY. The compose file mounts three paths whatever the deployment
	// looks like, and a mount of a path that does not exist becomes an empty directory rather than an error.
	// A plan-driven install replaces this with the one naming its region.
	if cert, key, merr := storeMemberMaterialFor(dir, nil, now, storeMemberYears); merr != nil {
		return merr
	} else if cert != nil {
		if werr := os.WriteFile(filepath.Join(dir, storeMemberFile), cert, 0o644); werr != nil {
			return werr
		}
		if werr := os.WriteFile(filepath.Join(dir, storeMemberKeyFile), key, 0o600); werr != nil {
			return werr
		}
	}
	if err := issueServerCertificates(dir, auth, names, ips, now); err != nil {
		return err
	}
	if err := writeSchemasAndPolicy(dir); err != nil {
		return err
	}
	// One of this deployment's authorities, minted with the rest. See writeAgentPolicySigningKey: left to the
	// Edge's load-or-generate, it is created after the directory has already been carried elsewhere, and each
	// place ends up with a different one.
	if err := writeAgentPolicySigningKey(dir); err != nil {
		return err
	}
	// ★★★ AND THE KEY THAT AUTHORISES RUNNING CODE, without which no endpoint can be installed against this
	// deployment at all. See writeAgentUpdateSigningKey: the pin is carried, the private half is not.
	if err := writeAgentUpdateSigningKey(dir); err != nil {
		return err
	}
	if err := writeEnvironment(dir, names, ips); err != nil {
		return err
	}
	// The commands that actually start this deployment. Written as files rather than printed, because the
	// printed version was followed exactly and refused to start eleven times — see launch.go.
	if err := writeDatabaseFrontDoorConfig(dir); err != nil {
		return err
	}
	planeHost := ""
	if len(names) > 0 {
		planeHost = names[0]
	} else if len(ips) > 0 {
		planeHost = ips[0].String()
	}
	planes := planeNamesFor(planeHost)
	if err := writeRegionFrontDoorConfig(dir, planes); err != nil {
		return err
	}
	if err := writeFrontDoorConfig(dir); err != nil {
		return err
	}
	if err := writeComposeFile(dir); err != nil {
		return err
	}
	if err := writeLaunchScripts(dir); err != nil {
		return err
	}
	report(dir, auth, names, ips)
	return nil
}

// reportRegionName says what this region is called, reading the file rather than naming a default.
//
// ★★★ IT SAID "region-a" OVER A DEPLOYMENT WHOSE PLAN CALLED IT "tokyo" (2026-08-29, found by building one).
// The line was unconditional and told the operator to change DSSE_EDGE_REGION if the region should be called
// something else — an instruction to repair a correct file. Following it renames the region out from under
// every record and every device that has chosen it, and renaming later moves neither.
//
// ★★ AND IT IS PRINTED AFTER THE PLAN HAS BEEN APPLIED, WHICH IS WHY IT IS A FUNCTION (2026-08-29, the second
// version of this fix). Reading the file was right and reading it inside report() was too early: the founding
// install mints, reports, and only THEN writes the plan's values into deployment.env. So the corrected line
// read the correct source at the one moment it still held the default, and printed "region-a" again.
func reportRegionName(dir string) {
	region := strings.TrimSpace(readDeploymentEnv(dir)["DSSE_EDGE_REGION"])
	if region == "" {
		region = "region-a"
	}
	fmt.Printf("\n  ★ THIS REGION IS CALLED %q — it is the name devices use to choose this region, and the name\n", region)
	fmt.Printf("  every record from it carries; renaming it later moves neither. To call it something else, set\n")
	fmt.Printf("  DSSE_EDGE_REGION in deployment.env before the first start (a plan names it, and that name wins).\n")
}

func parseHosts(hosts string) (names []string, ips []net.IP, err error) {
	for _, raw := range strings.Split(hosts, ",") {
		h := strings.TrimSpace(raw)
		if h == "" {
			continue
		}
		if ip := net.ParseIP(h); ip != nil {
			ips = append(ips, ip)
			continue
		}
		names = append(names, strings.ToLower(h))
	}
	return names, ips, nil
}

// alreadyMinted asks whether this directory is already a deployment. It looks for the ROOT, because that is
// the one thing every other file here is derived from.
func alreadyMinted(dir string) (bool, error) {
	_, err := os.Stat(filepath.Join(dir, "root.crt"))
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func newKey() (*ecdsa.PrivateKey, error) { return ecdsa.GenerateKey(elliptic.P256(), rand.Reader) }

// mint creates the deployment's authorities. The shape mirrors the reference deployment exactly — a root with
// two CAs under it, plus a device CA — so that an installed deployment and the reference one are the same
// thing, and a document written about one is true of the other.
func mint(orgName string, now time.Time, years int) (*deploymentAuthorities, error) {
	a := &deploymentAuthorities{}
	var err error
	if a.RootKey, err = newKey(); err != nil {
		return nil, err
	}
	// pathlen is not constrained on the root: an issuing CA sits under it, and a per-node tier may sit under
	// that. This deployment has already been bitten by a pathlen:0 that made a legitimate chain invalid.
	a.RootCert, err = selfSigned(pkix.Name{Organization: []string{orgName}, CommonName: orgName + " Root CA"},
		a.RootKey, now, now.AddDate(years, 0, 0))
	if err != nil {
		return nil, err
	}
	for _, sub := range []struct {
		cn   string
		cert **x509.Certificate
		key  **ecdsa.PrivateKey
	}{
		{orgName + " Management CA", &a.AdminCA, &a.AdminKey},
		{orgName + " Transport CA", &a.TransCA, &a.TransKey},
		{orgName + " Device CA", &a.DeviceCA, &a.DeviceKey},
	} {
		k, err := newKey()
		if err != nil {
			return nil, err
		}
		c, err := issueCA(pkix.Name{Organization: []string{orgName}, CommonName: sub.cn}, k,
			a.RootCert, a.RootKey, now, now.AddDate(years, 0, 0))
		if err != nil {
			return nil, err
		}
		*sub.cert, *sub.key = c, k
	}
	// ★★★ THE INTERCEPTION TIER IS RSA, AND ITS SIBLINGS ARE NOT (2026-08-26, found by the Edge refusing to
	// start: "lab TLS persistent root key is not RSA"). Every other authority here is P-256 because its only
	// consumers are this deployment's own code. This one's consumer is a BROWSER — the engine that signs site
	// certificates under it holds an RSA key throughout, and RSA is what every OS trust store and every TLS
	// stack handles without argument. A tier whose key type its own engine cannot load is not a tier.
	//
	// ★ THE SAME SHAPE OTHERWISE, INCLUDING THE ROOM UNDERNEATH: signed by this deployment's root, pathlen:1
	// so a per-node short-lived issuing CA can sit below it. A pathlen:0 here would make that chain invalid,
	// and this deployment has been bitten by exactly that before.
	ik, err := newInterceptionKey()
	if err != nil {
		return nil, err
	}
	ic, err := issueCARSA(pkix.Name{Organization: []string{orgName}, CommonName: orgName + " Interception CA"},
		ik, a.RootCert, a.RootKey, now, now.AddDate(years, 0, 0))
	if err != nil {
		return nil, err
	}
	a.InterceptCA, a.InterceptKey = ic, ik
	return a, nil
}

// newInterceptionKey mints the key the interception tier signs with. 2048 is what the engine generates for
// itself, so a deployment-minted authority and an Edge-minted one are the same kind of thing.
func newInterceptionKey() (*rsa.PrivateKey, error) { return rsa.GenerateKey(rand.Reader, 2048) }

func selfSigned(subject pkix.Name, key *ecdsa.PrivateKey, notBefore, notAfter time.Time) (*x509.Certificate, error) {
	tmpl := &x509.Certificate{
		SerialNumber: serial(), Subject: subject, NotBefore: notBefore.Add(-time.Hour), NotAfter: notAfter,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

func issueCA(subject pkix.Name, key *ecdsa.PrivateKey, parent *x509.Certificate,
	parentKey *ecdsa.PrivateKey, notBefore, notAfter time.Time) (*x509.Certificate, error) {
	tmpl := &x509.Certificate{
		SerialNumber: serial(), Subject: subject, NotBefore: notBefore.Add(-time.Hour), NotAfter: notAfter,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, BasicConstraintsValid: true, IsCA: true,
		// One tier below, because the control plane mints a short-lived per-node certificate under this one.
		MaxPathLen: 1, MaxPathLenZero: false,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// issueCARSA is issueCA for a subject whose key is RSA — the interception tier. Kept separate rather than
// made generic so the ordinary path stays exactly what it was, and the one tier that differs says why.
func issueCARSA(subject pkix.Name, key *rsa.PrivateKey, parent *x509.Certificate,
	parentKey *ecdsa.PrivateKey, notBefore, notAfter time.Time) (*x509.Certificate, error) {
	tmpl := &x509.Certificate{
		SerialNumber: serial(), Subject: subject, NotBefore: notBefore.Add(-time.Hour), NotAfter: notAfter,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, BasicConstraintsValid: true, IsCA: true,
		MaxPathLen: 1, MaxPathLenZero: false,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

func serial() *big.Int {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return new(big.Int).SetBytes(b)
}

// writeAuthorities puts the deployment's own material on disk, with the permissions the design promises.
//
// ★ THE PERMISSIONS ARE PART OF THE ANSWER, NOT A DETAIL. The default key store is a directory, not an HSM —
// that is a deliberate choice so a deployment can be stood up without one — and a default that is honest
// about being a file has to actually be a file only its owner can read.
func writeAuthorities(dir string, a *deploymentAuthorities) error {
	// ★ THE LAYOUT FIRST. Minting material goes where nothing running can reach it — see
	// the_authority_is_not_a_runtime_possession.go for what that fixed.
	if err := ensureAuthorityLayout(dir); err != nil {
		return fmt.Errorf("create the deployment's directories: %w", err)
	}
	for _, item := range []struct {
		name string
		pem  []byte
		mode os.FileMode
	}{
		{"root.crt", certPEM(a.RootCert), 0o644},
		{"root.key", keyPEM(a.RootKey), 0o600},
		{"management-ca.crt", certPEM(a.AdminCA), 0o644},
		{"management-ca.key", keyPEM(a.AdminKey), 0o600},
		{"transport-ca.crt", certPEM(a.TransCA), 0o644},
		{"transport-ca.key", keyPEM(a.TransKey), 0o600},
		{"device-ca.crt", certPEM(a.DeviceCA), 0o644},
		{"device-ca.key", keyPEM(a.DeviceKey), 0o600},
		// ★ THE NAMES THE EDGE ALREADY LOOKS FOR. The interception engine reuses persistent root material at
		// <path>.pem with a sibling <path>.key.pem rather than minting its own, so writing the deployment's
		// third tier under those names is what makes every Edge in the fleet sign under ONE authority instead
		// of each inventing a root nobody else has heard of.
		{interceptionRootCertFile, certPEM(a.InterceptCA), 0o644},
		{interceptionRootKeyFile, interceptionKeyPEM(a.InterceptKey), 0o600},
	} {
		if item.pem == nil {
			return fmt.Errorf("%s could not be encoded", item.name)
		}
		// ★ THE FIVE THAT NOTHING RUNNING READS GO SOMEWHERE NOTHING RUNNING IS GIVEN. Deciding it here, by
		// the file's own name, rather than at each of the places that later hand a directory to a container:
		// a rule applied where the file is created cannot be forgotten by the next thing that mounts something.
		path := filepath.Join(dir, item.name)
		if isAuthorityFile(item.name) {
			path = authorityPath(dir, item.name)
		}
		if err := os.WriteFile(path, item.pem, item.mode); err != nil {
			return fmt.Errorf("write %s: %w", item.name, err)
		}
	}
	// ★★★ AND THE DEVICE CA IS REGISTERED AS AN AUTHORITY, NOT ONLY WRITTEN AS A FILE (2026-08-24, found by
	// walking the deployment as a device). Two different things had to be true and only one was: /enroll SIGNS
	// with this CA, and an Edge ADMITS a device by chaining its certificate to a REGISTERED one. The generated
	// deployment registered none — so it minted identities its own Edges would not look at. A device enrolled,
	// appeared on every screen as enrolled, and was answered 401 by the steer tunnel: the deployment could not
	// carry one byte of anybody's traffic, and nothing said so.
	//
	// ★ IT BELONGS TO AN ORGANIZATION, WHICH IS WHY THE FILE NAMES ONE. Device identity is per-organization —
	// a customer that brings its own device CA replaces this entry through /admin/tenant-cas, and the
	// architecture's goal is that every organization runs on its own PKI. This is the default organization's
	// authority, written so a fresh deployment works, not a deployment-wide one that would make every
	// organization share an issuer.
	//
	// ★ THE CERTIFICATE IS INSIDE THE FILE, NOT A PATH TO IT. The registry accepts either, and a path is the
	// wrong one here: this deployment directory is generated on one machine and mounted somewhere else — at
	// /deployment in the container rendering — so a path written at install time names a file that is not
	// there when it is read. A registry that resolves to nothing refuses every device, which is the same
	// outcome as having no registry and is harder to see.
	registry, err := json.MarshalIndent(map[string]any{
		"tenants": []map[string]string{{
			"tenant_id": "tenant_default",
			"ca_pem":    string(certPEM(a.DeviceCA)),
		}},
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("encode the device-CA registry: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "device-ca-registry.json"), append(registry, '\n'), 0o644); err != nil {
		return fmt.Errorf("write device-ca-registry.json: %w", err)
	}
	// Which organizations this deployment's Edges may ship records for.
	//
	// ★★★ IT NAMED ONE ORGANIZATION, AND THIS DEPLOYMENT'S EDGES SHARE ONE IDENTITY (2026-08-28, measured by
	// putting a second organization on the lab). The reasoning written here was that naming "*" "would make
	// the client certificate the receiver checks pointless" — but every Edge this installer generates ships as
	// CN=dsse-edge-fleet, so that certificate proves WHICH DEPLOYMENT is shipping and cannot distinguish one
	// organization from another. Against a hostile Edge of this deployment the per-organization value bought
	// nothing; against a legitimate second organization it was a wall:
	//
	//	shipping to https://admin…/audit-ingest has been failing (audit ingest returned HTTP 403)
	//
	// and nothing anywhere said an organization had to be added to a file. It was invisible for longer than
	// that: until the flow's organization was bound to the device's certificate, every record was stamped
	// tenant_default and the map was accidentally true.
	//
	// ★ SO IT SAYS WHAT IT MEANS. The receiver still requires a verified certificate and still refuses anybody
	// who is not this deployment's Edge; what it stops claiming is a per-organization restriction it cannot
	// enforce. A deployment whose Edges hold PER-ORGANIZATION identities is the arrangement where naming them
	// is real, and there this file lists each identity with the organizations it serves.
	authority, err := json.MarshalIndent(map[string][]string{"dsse-edge-fleet": {"*"}}, "", "  ")
	if err != nil {
		return fmt.Errorf("encode the audit-ingest authority map: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "audit-ingest-authority.json"), append(authority, '\n'), 0o644); err != nil {
		return fmt.Errorf("write audit-ingest-authority.json: %w", err)
	}
	// The anchor a device is told to trust: the root alone. Written separately from root.crt so that the file
	// an operator distributes has a name that says what it is for.
	return os.WriteFile(filepath.Join(dir, "deployment-anchor.pem"), certPEM(a.RootCert), 0o644)
}

// issueServerCertificates issues what this deployment's own processes present.
//
// ★ TWO, NOT ONE, AND THEY COME FROM DIFFERENT CAs. The management certificate is what the Console, the
// connectors and the control plane check to know they reached the real node. The transport certificate is the
// DEFAULT leaf a device meets when it arrives without an organization name — and per-organization
// certificates are minted later, by the control plane, under each organization's own authority. Serving both
// from one CA would make an organization's devices verify the management plane too, which is more trust than
// the job needs.
func issueServerCertificates(dir string, a *deploymentAuthorities, names []string, ips []net.IP,
	now time.Time) error {
	for _, item := range []struct {
		file   string
		cn     string
		parent *x509.Certificate
		key    *ecdsa.PrivateKey
		// fixedCN keeps this certificate's common name out of the host override below. A name that identifies
		// a NODE must not become whatever address the deployment answers on: it is a key somebody writes in a
		// configuration file, and a key that changes with the hostname is a configuration file that stops
		// matching the day the deployment is reached by another name.
		fixedCN bool
	}{
		{"management", "management", a.AdminCA, a.AdminKey, false},
		{"transport", "transport", a.TransCA, a.TransKey, false},
		// ★★★ WHAT AN EDGE IS, TO THE AUTHORITY. An Edge ships everything it records to the control plane, and
		// the control plane refuses a shipment it cannot attribute to a node — correctly, because the shared
		// bearer alone would let anything holding it write any organization's history. So an Edge needs an
		// identity of its own, and the tree is explicit that it comes from the OPERATOR's authority and not
		// from an organization's: "an Edge's identity is not a tenant's".
		//
		// ★ ONE IDENTITY FOR THE FLEET, deliberately, because a fleet is identical nodes: they already share
		// the transport certificate in this rendering, and per-node shipping identities would be per-node
		// configuration for a question ("may this node ship") whose answer is the same for all of them.
		{"edge-identity", "dsse-edge-fleet", a.AdminCA, a.AdminKey, true},
	} {
		leafKey, err := newKey()
		if err != nil {
			return err
		}
		cn := item.cn
		if len(names) > 0 && !item.fixedCN {
			cn = names[0]
		}
		// ★★★ THE NAMES A CONTAINER DEPLOYMENT ANSWERS ON ARE ALSO NAMES (2026-08-23). An Edge verifies the
		// control plane against the deployment anchor, so whichever name it reaches it by has to be in this
		// certificate. In a container rendering that name is the service's, and the operator never said it —
		// they said the address the deployment answers on from outside. Both are true at once, and leaving
		// the inside ones out would mean a deployment that starts one way and not the other, repaired only
		// by re-minting — which orphans every anchor already distributed.
		san := append(append([]string{}, names...), composeServiceNames...)
		// ★★★ AND THE PER-PLANE NAMES, because that is what a client actually asks for. Every mouth of this
		// deployment is 443 and the planes are separated by NAME — so "agents.<host>" is the name a device
		// puts in its ClientHello and checks against what answers. Leaving them out means a deployment whose
		// front door routes correctly and whose certificate is refused by every client, repaired only by
		// re-minting, which orphans every anchor already distributed.
		if p := planeNamesFor(cnHostFor(names, ips)); p.Split {
			// ★ THE RECOVERY NAME IS IN HERE FOR THE SAME REASON THE OTHERS ARE, and it is the one that
			// matters when everything else has already gone wrong: an agent whose certificate expired reaches
			// this name, and if the certificate it meets does not carry it, the way back does not exist.
			san = append(san, p.Agents, p.Admin, p.Console, p.Recovery, p.Authority)
		}
		// ★★ AND THE ADDRESS EVERY NODE IS REACHED ON FROM ITS OWN MACHINE. Same reasoning as the compose
		// service names above: it is a name the node ANSWERS to from inside, the operator never says it
		// because it is not what the deployment answers on from outside, and leaving it out produces a
		// deployment that works one way and not the other.
		//
		// Measured 2026-08-27 while checking a node from the machine it runs on: the only address that
		// reached its own process was 127.0.0.1, and the certificate refused it —
		//
		//	x509: certificate is valid for 10.77.0.10, not 127.0.0.1
		//
		// which is repaired only by re-minting, orphaning every anchor already distributed, or by -add-host.
		//
		// ★★★ THIS IS A CONVENIENCE AND NOT AN ANSWER TO THE REAL QUESTION. Every mouth of a deployment is
		// 443 and the planes are separated by NAME: an administrator arrives through the same corporate proxy
		// a device does, and a non-standard port is where they both stop, so the admin surface in production
		// is 443 under a different host name rather than a different port. Reaching a node on its loopback is
		// what an operator standing on a machine does; it is not how this deployment presents anything.
		// What has no answer yet is naming an INDIVIDUAL node at all: see the_fleet_has_no_address.go.
		//
		// ★ IT GOES IN THE SAN AND NOWHERE ELSE. Not into names, so it is not the CN and no plane name is
		// derived from it: "agents.localhost" resolves to whoever asks, which is the defect this installer
		// already warns about at the end of an install.
		san = append(san, "localhost")
		// ★★★ AND ONE NAME PER NODE, AS A WILDCARD (2026-08-28, decided by the operator: "443"). The comment
		// above says what had no answer yet — naming an individual node at all. It has one now:
		// <node>.admin.<host>, routed by SNI to that node and no other, on 443 like everything else.
		//
		// ★ A WILDCARD RATHER THAN A LIST, because Edges are AUTOSCALED. That is the whole reason their
		// material is short-lived, and naming each node in the certificate would mean re-issuing the
		// deployment's own identity every time the fleet grew. One name survives a fleet that changes size.
		//
		// ★★★ FROM THE DEPLOYMENT'S OWN NAME, AND FROM NOTHING ELSE (2026-08-28, measured on the lab minutes
		// after the first version of this). Derived from every host in the list it produced
		// *.admin.cp-a.dsse.lab, *.admin.edge-a.dsse.lab — names nothing routes — and, once the wildcard was
		// itself in the list, *.admin.*.admin.dsse.lab. That last one is not a DNS name, and ONE malformed SAN
		// makes the WHOLE certificate unusable: macOS answered
		//
		//	SSL certificate problem: unsupported or invalid name syntax
		//
		// for every name in it, including the four plane names that had been working all morning. A bad entry
		// here does not cost you that entry; it costs you the deployment.
		// ★ AND A DEPLOYMENT THAT ANSWERS ON AN ADDRESS HAS NO NAME TO HANG THIS OFF. names is empty there —
		// the addresses are in ips — and indexing it crashed the installer outright, which the test for that
		// shape caught before it reached anyone. A node wildcard needs a name; an address deployment has none
		// and simply does not get one.
		if len(names) > 0 {
			if primary := strings.TrimSpace(names[0]); primary != "" &&
				net.ParseIP(primary) == nil && !strings.Contains(primary, "*") {
				san = append(san, "*.admin."+primary)
			}
		}
		// ★★★ AND THE REGION'S OWN ADDRESS IS ONE A DEVICE REACHES. It is held by whichever front door is alive,
		// so it belongs to no container and would appear in no list of service names — and a device that reaches
		// the region by it and cannot verify what answers has a deployment that works until the moment it fails
		// over. Repairing that afterwards means re-minting, which orphans every anchor already distributed.
		certIPs := append(append([]net.IP{}, ips...), net.ParseIP(composeRegionAddress),
			net.ParseIP("127.0.0.1"), net.ParseIP("::1"))
		tmpl := &x509.Certificate{
			SerialNumber: serial(),
			Subject:      pkix.Name{Organization: item.parent.Subject.Organization, CommonName: cn},
			NotBefore:    now.Add(-time.Hour), NotAfter: now.AddDate(1, 0, 0),
			KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			DNSNames:    san, IPAddresses: certIPs,
			BasicConstraintsValid: true,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, item.parent, &leafKey.PublicKey, item.key)
		if err != nil {
			return fmt.Errorf("issue the %s certificate: %w", item.file, err)
		}
		leaf, err := x509.ParseCertificate(der)
		if err != nil {
			return err
		}
		// The chain, not the leaf alone: a party that holds only the deployment anchor has to be able to
		// build a path, and a leaf served without its issuer is a chain nobody can complete.
		chain := append(certPEM(leaf), certPEM(item.parent)...)
		if err := os.WriteFile(filepath.Join(dir, item.file+".crt"), chain, 0o644); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, item.file+".key"), keyPEM(leafKey), 0o600); err != nil {
			return err
		}
	}
	return writeBundle(dir)
}

// startingBundleID, shippedPolicyIDs and policyFileForID keep one fact in one place: what this installer
// ships as a deployment's starting policy set. They are derived from the documents above rather than typed
// out again, because a second list is how the bundle comes to disagree with the files beside it — the exact
// failure writeBundle now checks for.
var startingBundleID = mustBundleField(startingBundle, "id")

var shippedPolicyIDs = func() []string {
	ids := []string{}
	for _, body := range shippedPolicies {
		ids = append(ids, mustBundleField(body, "id"))
	}
	return ids
}()

func policyFileForID(id string) string {
	for name, body := range shippedPolicies {
		if mustBundleField(body, "id") == id {
			return name
		}
	}
	return "(unknown)"
}

// mustBundleField reads one top-level string from a document this file defines as a constant. A failure here
// is a malformed constant in this source file, which no deployment should ever get far enough to meet.
func mustBundleField(document, field string) string {
	var m map[string]any
	if err := json.Unmarshal([]byte(document), &m); err != nil {
		panic(fmt.Sprintf("a document in this installer is not valid JSON: %v", err))
	}
	value, _ := m[field].(string)
	if value == "" {
		panic(fmt.Sprintf("a document in this installer has no %q", field))
	}
	return value
}

// shippedPolicies is the one list of what a deployment starts with: file name to document.
var shippedPolicies = map[string]string{
	"policy.json":        startingPolicy,
	"policy-egress.json": startingEgressPolicy,
}

// shippedPolicyFiles is shippedPolicies in a stable order, so a deployment directory is written the same way
// every time and two installs of the same version produce identical trees.
func shippedPolicyFiles() []struct{ name, body string } {
	names := make([]string, 0, len(shippedPolicies))
	for name := range shippedPolicies {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]struct{ name, body string }, 0, len(names))
	for _, name := range names {
		out = append(out, struct{ name, body string }{name, shippedPolicies[name]})
	}
	return out
}

// writeBundle writes the bundle with a checksum this deployment's own loader will accept.
//
// ★★★ COMPUTED, NOT WRITTEN DOWN (2026-08-22, measured). A bundle carries a checksum over its own canonical
// form, and the Edge refuses one that does not match:
//
//	load policy bundle: policy bundle checksum mismatch: got sha256:unsigned-local-bundle expected sha256:efff…
//
// A constant in this file would be right for exactly one version of the starting bundle and wrong the moment
// anything in it changed — including the tenant id, which an installer will eventually take as an argument.
//
// ★ AND IT USES THE LOADER'S OWN FUNCTION. bundle.CanonicalChecksum is what the Edge checks against; a second
// implementation here would agree today and drift the first time the canonical form is touched, and the
// symptom would be a deployment that refuses its own bundle.
func writeBundle(dir string) error {
	path := filepath.Join(dir, "policy-bundle.json")
	// ★★★ AN EXISTING BUNDLE IS KEPT ONLY WHILE IT STILL NAMES EVERY POLICY THIS INSTALLER SHIPS
	// (2026-09-04, found on a lab whose Edge had been crash-looping for an hour).
	//
	// This used to return unconditionally when the file existed. Then a release added a second shipped policy
	// — the egress floor — and an EXISTING deployment could not adopt it: the file was written, mounted and
	// passed to -policy, and the bundle went on naming one policy, so the deployment carried a rule nothing
	// enforced. The only way out was to edit policy_ids by hand, and the bundle carries a checksum and a
	// signature over its own canonical form, so that produced:
	//
	//	load policy bundle: policy bundle checksum mismatch: got sha256:6b28d29… expected sha256:4539e01…
	//
	// — for ever, on every restart. A hand-edit is not a mistake an operator can be told not to make when the
	// product leaves them no other route.
	//
	// ★ AND IT ONLY REWRITES ITS OWN. If the id is no longer this installer's starting bundle, somebody
	// authored it, and overwriting an authored policy set is worse than any of the above. Say so and stop.
	if existing, err := os.ReadFile(path); err == nil {
		var b model.PolicyBundle
		if err := json.Unmarshal(existing, &b); err != nil {
			return fmt.Errorf("this deployment's policy-bundle.json is not valid JSON, so it cannot be checked or replaced: %w", err)
		}
		if b.ID != startingBundleID {
			for _, want := range shippedPolicyIDs {
				if !slices.Contains(b.PolicyIDs, want) {
					return fmt.Errorf("this deployment's bundle %q does not name %q, which this installer ships as %s. "+
						"The bundle was authored elsewhere, so this installer will not overwrite it: add the policy to it "+
						"and re-sign, or the rule will be carried and enforced by nothing", b.ID, want, policyFileForID(want))
				}
			}
			return nil
		}
		// ★★★ THE PREDICATE IS THE LOADER'S, NOT A LIST COMPARISON (2026-09-04, second attempt — the first
		// one checked membership and left the broken deployment exactly as it found it).
		//
		// The bundle that had been hand-edited NAMED both policies. What was wrong with it was the checksum,
		// because the edit changed the document and not the sum over it. "Does it list what we ship" answers
		// a question nobody was asking; "would the Edge start with this" is the actual condition, and
		// bundle.Validate is the function the Edge uses to decide it.
		reason := ""
		for _, want := range shippedPolicyIDs {
			if !slices.Contains(b.PolicyIDs, want) {
				reason = fmt.Sprintf("it does not name %s", want)
				break
			}
		}
		if reason == "" {
			if err := bundle.Validate(b, time.Now()); err != nil {
				reason = fmt.Sprintf("the Edge would refuse it: %v", err)
			}
		}
		if reason == "" {
			return nil
		}
		fmt.Printf("  policy bundle: rewriting %s — %s\n", filepath.Base(path), reason)
	}
	var b model.PolicyBundle
	if err := json.Unmarshal([]byte(startingBundle), &b); err != nil {
		return fmt.Errorf("the starting bundle in this installer is not valid: %w", err)
	}
	// ★★★ AND IT IS SIGNED, NOT MOCK-SIGNED (2026-08-22). The loader accepts a specific mock signature for
	// local development, and shipping that from an installer is how a development affordance becomes the
	// production default by inertia — the failure this repository keeps recording. The deployment already
	// holds its own authorities; a bundle-signing key is one more, and signing with it costs nothing.
	signPub, signPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	// ★ THE KEY ID IS THE PUBLIC KEY. The loader requires the ed25519-public: prefix and reads the key out of
	// the id itself, so a bundle carries what verifies it and no key registry has to be distributed alongside.
	keyID := signedconfig.SigningKeyIDPrefix + base64.RawURLEncoding.EncodeToString(signPub)
	b.SigningKeyID = keyID
	b.Signature = ""
	// The checksum covers the bundle WITHOUT its checksum and signature (see bundle.CanonicalChecksum), so it
	// is computed after the signing key id is in place and before the signature is.
	sum, err := bundle.CanonicalChecksum(b)
	if err != nil {
		return err
	}
	b.Checksum = sum
	payload, err := bundle.SignaturePayload(b)
	if err != nil {
		return err
	}
	sig := signedconfig.SignaturePrefix + base64.RawURLEncoding.EncodeToString(ed25519.Sign(signPriv, payload))
	if err := os.WriteFile(authorityPath(dir, "bundle-signing.key"), keyPEMEd25519(signPriv), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "bundle-signing.pub"),
		[]byte(keyID+"\n"), 0o644); err != nil {
		return err
	}

	// ★ THE TEXT WE WROTE, WITH ONE VALUE REPLACED — not the struct re-marshalled. Round-tripping through
	// model.PolicyBundle emitted fields the starting bundle deliberately does not carry, and the schema
	// rejected one of them ("field metadata type is invalid"). The bundle above is the thing that was checked
	// against the schema; re-encoding it makes a DIFFERENT document, and then this installer would be shipping
	// something nobody validated.
	out := startingBundle
	for _, sub := range []struct{ from, to string }{
		{`"checksum": "sha256:unsigned-local-bundle"`, `"checksum": "` + sum + `"`},
		{`"signature": "unsigned-local-bundle"`, `"signature": "` + sig + `"`},
		{`"signing_key_id": "unsigned-local-bundle"`, `"signing_key_id": "` + keyID + `"`},
	} {
		if !strings.Contains(out, sub.from) {
			return fmt.Errorf("the starting bundle no longer carries %q, which this installer replaces", sub.from)
		}
		out = strings.Replace(out, sub.from, sub.to, 1)
	}
	return os.WriteFile(path, []byte(out), 0o644)
}

// writeEnvironment emits the values a deployment is configured with, as an env file.
//
// ★★★ WHY A FILE OF VALUES AND NOT A LIST OF FLAGS (2026-08-22, measured). The Edge takes THREE HUNDRED AND
// THIRTY-EIGHT flags and reads no configuration file. Printing the ones a deployment needs is fine for one
// process; a deployment is several, and the reference deployment already answers this — its compose file
// reads a handful of names from an env file and encodes everything else itself.
//
// So the installer's job is not to restate 338 flags. It is to mint the authorities and produce the small set
// of VALUES the deployment cannot invent for itself: the secrets it refuses to start without, and where it
// answers. That keeps one description of how a deployment is wired instead of two that drift.
//
// ★ SECRETS ARE GENERATED HERE RATHER THAN LEFT AS PLACEHOLDERS. Each one is refused if it is short, and two
// of them are refused if they are equal — measured. A file of TODOs is a file an operator fills in with the
// shortest thing that passes, which is how a development default becomes production.
func writeEnvironment(dir string, names []string, ips []net.IP) error {
	// ★★★ THE FIRST -host IS THE DEPLOYMENT'S NAME, AND EVERY PLANE IS DERIVED FROM IT. admin.<host>,
	// agents.<host>, console.<host>, authority.<host> — the names a device dials, the name another region's
	// Edges take configuration from, and the names the front door routes by.
	//
	// ★ SO "localhost" FIRST BUILDS A DEPLOYMENT THAT CANNOT SPAN REGIONS (2026-08-26, found by building
	// one). Every plane became admin.localhost / agents.localhost, which resolve to the asking machine — so
	// the second region's Edges, on another host or merely another container network, dial themselves. It is
	// invisible in a single-region lab, which is exactly where somebody would choose it, and it is not
	// repairable later without re-issuing every certificate the deployment presents.
	//
	// Said rather than refused: a genuinely single-machine deployment is a legitimate thing to build, and an
	// installer that refuses it would be wrong. What it must not do is let somebody build a two-region
	// deployment on a name that cannot leave the machine without ever being told.
	host := "localhost"
	if len(names) > 0 {
		host = names[0]
	} else if len(ips) > 0 {
		host = ips[0].String()
	}
	path := filepath.Join(dir, "deployment.env")
	if keepWhatIsThere(path) {
		return nil
	}
	var b strings.Builder
	b.WriteString("# Generated by dsse-install. These are the values a deployment cannot invent for itself:\n")
	b.WriteString("# the secrets it refuses to start without, and where it answers. Everything else is in the\n")
	b.WriteString("# deployment description that reads this file.\n")
	b.WriteString("#\n")
	b.WriteString("# Keep this file as private as the keys beside it: it IS credentials.\n\n")
	b.WriteString("# ★ EVERY VALUE IS QUOTED. This file is SOURCED by the start scripts, so a value carrying a\n")
	b.WriteString("# shell metacharacter is executed rather than assigned. Measured: a region entry list, which\n")
	b.WriteString("# contains ';' by its own format, made every node of a deployment exit 127 at once with a\n")
	b.WriteString("# message naming this file and a line number — nothing about quoting. Keep the quotes when\n")
	b.WriteString("# you edit, and add them to anything you add.\n\n")
	// ★★★ THE FIRST REGION HAS A NAME TOO (2026-08-25, found by rendering a second one). Only -region named a
	// region, so the region a deployment STARTS as was unnamed — and an unnamed region cannot appear in the
	// entry list devices use to choose where to go, which means nothing can ever fail over TO it. It is also
	// the region every record from this deployment came from, and a record that cannot say which region it is
	// from is a record no residency question can be asked of.
	//
	// region-a is a default, not a decision: it is written here so an operator can change it before the first
	// start, and the report says so.
	b.WriteString("DSSE_EDGE_REGION=" + shellQuote("region-a") + "\n")
	// ★★★ WHICH ORGANIZATION OPERATES THIS DEPLOYMENT. Written rather than left to the launch script's
	// default, because it decides who can be answered about the deployment AS A WHOLE — and a value that
	// only exists as a shell default is one nobody can see, change, or check. It is the seed tenant: the
	// break-glass credential is stamped with it, and every customer organization is created BESIDE it.
	b.WriteString("DSSE_OPERATOR_TENANT=" + shellQuote("tenant_default") + "\n")
	b.WriteString("EDGE_HOST=" + shellQuote(host) + "\n")
	// ★ THE CONSOLE'S ORIGIN IS A NAME ON 443, not a port. Every plane this deployment presents is behind one
	// port and separated by name; an origin naming a second port would be the one thing an enterprise proxy
	// stops, and it is also what the browser checks against the certificate.
	b.WriteString("ADMIN_CONSOLE_ORIGIN=" + shellQuote("https://"+planeNamesFor(host).Console) + "\n")
	// The name an agent sends when the certificate it holds has expired. Announced in the trust bundle so
	// devices adopt it while they are healthy — a way back is only a way back if it was distributed BEFORE it
	// was needed.
	b.WriteString("DSSE_RECOVERY_SNI=" + shellQuote(planeNamesFor(host).Recovery) + "\n")
	// ★ THE NAME A CONNECTOR AND A DEVICE BOTH REACH THIS DEPLOYMENT BY. Written out so the connector
	// enrolment command is self-contained AND correct — it used to name the Edge's own port inside the
	// container network, which is reachable from the Edge and from nowhere a connector runs.
	b.WriteString("DSSE_AGENT_PLANE_NAME=" + shellQuote(planeNamesFor(host).Agents) + "\n")
	// Where a node writes to the authority. Inside one region the service name is enough and this is unused;
	// a region that holds no state has no such network and reaches it here.
	b.WriteString("DSSE_AUTHORITY_ORIGIN=" + shellQuote("https://"+planeNamesFor(host).Authority) + "\n")
	// ★★★ WHO MAY BUILD SOFTWARE THAT INSTALLS ITSELF ON THIS DEPLOYMENT'S DEVICES (2026-08-27, found by
	// building the real signed, notarised macOS package and running its own preinstall against the
	// configuration this deployment publishes). Empty until an operator fills it in, and empty is not a
	// default that works: the endpoint installer refuses a configuration that names no publisher, because a
	// device holding none installs, as root, whatever a signed manifest points at.
	b.WriteString("\n# The signing identity that builds the agent packages your devices install — an Apple\n")
	b.WriteString("# Team ID on macOS, its counterpart on Windows. ★ UNTIL THIS IS SET, NO ENDPOINT CAN BE\n")
	b.WriteString("# INSTALLED against this deployment: its published configuration names no publisher, and\n")
	b.WriteString("# the endpoint installer refuses that rather than installing whatever a manifest points at.\n")
	b.WriteString("# Read it from the agent build you distribute:  codesign -dv <app> 2>&1 | grep TeamIdentifier\n")
	b.WriteString("DSSE_AGENT_PUBLISHER=''\n")
	// ★★★ AND THE MAP OF THE DEPLOYMENT'S REGIONS, WHICH THE FOUNDING REGION NEVER HAD (2026-08-28, found
	// standing up two real sites). The instruction this program prints at the end of an install says "set
	// DSSE_REGION_ENDPOINTS to the same value in every region's deployment.env" — and only a region created
	// with -region had the line. In the region that FOUNDED the deployment the variable did not exist, so the
	// operator was told to set something their own configuration does not mention, in the file the product
	// wrote for them. Same shape as DSSE_AGENT_PUBLISHER above and the same fix: give it a place, empty, with
	// what empty costs written beside it.
	b.WriteString("\n# The deployment's regions and the address each answers on. ★ KEEP THE QUOTES: this file\n")
	b.WriteString("# is sourced, and the ';' in this format is a command separator — an unquoted value makes\n")
	b.WriteString("# every node exit 127.\n")
	b.WriteString("#   DSSE_REGION_ENDPOINTS='region-a=https://a.example;region-b=https://b.example'\n")
	b.WriteString("# ★ FILL THIS IN ONLY WHEN EVERY REGION EXISTS, AND GIVE EVERY EDGE THE SAME VALUE. An Edge\n")
	b.WriteString("# holding a shorter list is healthy and hands its devices a map missing the regions it never\n")
	b.WriteString("# heard about, so a device served by it never fails over there.\n")
	b.WriteString("DSSE_REGION_ENDPOINTS=''\n\n")
	for _, k := range []string{"ADMIN_TOKEN", "CONNECTOR_SECRET", "WORKLOAD_SECRET", "AUDIT_INGEST_TOKEN",
		// DSSE_VRRP_PASSWORD authenticates the two front doors' announcements to each other. Without it, any
		// process on the deployment's network could announce a higher priority and take the region's address,
		// which is a way to become the region rather than to attack it.
		// STEPUP_BINDING_SECRET signs the device AND the organization into the step-up start URL every Edge
		// hands a held flow. It has to be the SAME on every Edge: the URL names the deployment's agent plane,
		// the region's door hands that connection to whichever Edge it likes, and an Edge that cannot verify
		// what another Edge signed reads it as "no device identity" — minting an organization-wide grant in
		// place of a device-bound one, with nothing said anywhere.
		"STEPUP_BINDING_SECRET",
		"EDGE_CP_TOKEN", "PG_PASSWORD", "PG_SUPERUSER_PASSWORD", "DSSE_VRRP_PASSWORD",
		"CLICKHOUSE_PASSWORD", "MINIO_ROOT_PASSWORD"} {
		b.WriteString(k + "=" + shellQuote(randomSecret()) + "\n")
	}
	// Where the control plane's own durable components answer. Named here rather than repeated in the start
	// scripts, and overridable, because a host install puts them somewhere else than a container rendering.
	b.WriteString("\nDSSE_CLICKHOUSE_ENDPOINT=" + shellQuote("http://dsse-clickhouse:8123") + "\n")
	b.WriteString("DSSE_ARCHIVE_ENDPOINT=" + shellQuote("dsse-archive:9000") + "\n")
	b.WriteString("DSSE_ARCHIVE_BUCKET=" + shellQuote("dsse-audit-archive") + "\n")
	b.WriteString("MINIO_ROOT_USER=" + shellQuote("dsse-archive") + "\n")
	// ★★★ WHICH IMAGES THIS DEPLOYMENT RUNS, BECAUSE WITHOUT THEM IT DOES NOT START AT ALL (2026-08-26,
	// found by generating a deployment and running the command its own compose file prints at the top):
	//
	//	error while interpolating services.dsse-control-plane-b.image:
	//	required variable DSSE_IMAGE is missing a value
	//
	// The compose file requires DSSE_IMAGE and DSSE_CONSOLE_IMAGE with `:?`, deliberately — a deployment that
	// silently ran `latest` would be a fleet nobody chose. But nothing wrote them, so every generated
	// deployment stopped on its first command, and the lab only worked because a human had added them by hand
	// once and the file was carried forward. An installer whose output cannot be started by the instructions
	// printed in that same output has not installed anything.
	//
	// ★ THEY ARE WRITTEN AS DEFAULTS AND MEANT TO BE EDITED. The tag names the product build this deployment
	// is to run; an operator pointing at a registry replaces the value here rather than editing the compose,
	// which is why the compose refers to the variable in the first place.
	b.WriteString("\n# The images this deployment runs. Change these to the build you intend to run — a\n")
	b.WriteString("# deployment that picks its own version is a fleet nobody chose.\n")
	b.WriteString("DSSE_IMAGE=" + shellQuote("dsse:release") + "\n")
	b.WriteString("DSSE_CONSOLE_IMAGE=" + shellQuote("dsse-console:release") + "\n")
	// ★★★ THE PORTS, WRITTEN ONCE, BECAUSE TWO PLACES WERE READING DIFFERENT ANSWERS (2026-08-26, found by
	// installing a connector). The compose file defaults the region doorway to 18443; the start scripts read
	// deployment.env, where nothing said so, so they derived the agent plane as https://agents.<host> — port
	// 443. A connector enrolled from its token and was then refused its identity:
	//
	//	Post "https://agents.localhost/enroll": dial tcp 127.0.0.1:443: connection refused
	//
	// The compose file's own header states the rule this breaks: nothing here repeats a flag, the deployment
	// is described ONCE. A default that lives in the compose file and nowhere else is a value the scripts
	// beside it cannot see.
	//
	// ★ IN PRODUCTION EVERY PLANE IS ON 443 and these become 443; they are here so that a rendering which
	// publishes elsewhere says so in the one file everything reads.
	b.WriteString("\n# Where this rendering publishes each plane. In production every one of these is 443 —\n")
	b.WriteString("# the planes are told apart by NAME, not by port. They are here because the compose file\n")
	b.WriteString("# and the start scripts must read the same answer.\n")
	// ★★★ AND WHICH ADDRESS EACH DOOR LISTENS ON, so a pair can both be 443 (2026-08-28). A host has one 443
	// per ADDRESS; the doorway is a pair; so on one machine the two doors could only ever be different ports,
	// which is the substitution a deployment with a machine per component exists to end. Empty is every
	// interface, which is what a one-host rendering had and still gets.
	b.WriteString("# ★ Which host ADDRESS the region's door binds, with a trailing colon, e.g. '10.20.1.5:'.\n")
	b.WriteString("# ★★ THIS IS PER MACHINE — the only value in this file that differs between the copies of\n")
	b.WriteString("# it. Everything else is the deployment's and is the same everywhere.\n")
	b.WriteString("# Empty = every interface, which is why the ports below are moved in a one-host rendering.\n")
	b.WriteString("DSSE_REGION_BIND_A=''\n")
	// ★★★ EVERY PORT HERE IS ONE SOMETHING BINDS (2026-09-05, measured by rendering a deployment and asking
	// the compose file what it publishes). This wrote seven, and four of them were reachable nowhere: the
	// second door, the second Edge's admin port and both control-plane ports stopped being published on
	// 2026-09-02, and the control plane's own ports were never published at all — per-node access is by NAME
	// through the region's door. An operator reading this file was being handed four ports to dial, and the
	// generated compose file's own header told them to hand three of those to -verify.
	//
	// ★ AND THE ONE THAT WAS MISSING IS THE ONE THAT COLLIDES. The agent port became published on every
	// machine that runs Edges on 2026-09-03; it was not written here, so it could not be moved, and two
	// regions on one host both bound 8443. A port that is published is a port this file names.
	// ★ THE AGENT PORT IS NAMED HERE AND NOT SET HERE. Every machine that runs Edges publishes it, so it has
	// to be movable when two regions share a host — but a plan gives a machine that sits BEHIND a door its
	// own value, and the sibling and mesh addresses other machines are told are built from that number. So it
	// is written as a comment: -region fills in a real line only when this region moved it, and a value
	// somebody else already wrote is never overwritten.
	b.WriteString("# DSSE_EDGE_AGENT_PORT — every machine running Edges publishes it; 8443 unless set.\n")
	for _, p := range [][2]string{
		{"DSSE_REGION_PORT", "18443"},
		{"DSSE_EDGE_ADMIN_PORT", "19443"},
	} {
		b.WriteString(p[0] + "=" + shellQuote(p[1]) + "\n")
	}
	return os.WriteFile(path, []byte(b.String()), 0o600)
}

//go:embed schemas/*.json
var embeddedSchemas embed.FS

// ★★★ THE HOT STORE'S SCHEMA SHIPS WITH THE THING THAT MATERIALIZES A DEPLOYMENT. The published tree carried
// the ClickHouse client and no schema at all — the same defect the Postgres migrations already record one
// layer down: a deployment would start a hot store the product could not write to, on a table nobody could
// have supplied. It is embedded HERE rather than kept at the tree root because ClickHouse applies it itself on
// first boot, so the installer is what has to put it somewhere ClickHouse can read.
//
//go:embed clickhouse/*.sql
var embeddedClickHouseSchema embed.FS

// startingPolicy is what a deployment enforces before anybody has authored anything.
//
// ★ DEFAULT-DENY WITH ONE RULE, NOT AN EMPTY FILE. An Edge with no policy is not a neutral state: it is a
// deployment that decides nothing, and what a reader concludes from "it let everything through on day one" is
// that the product does not enforce. One explicit allow, which an operator then narrows, says what shape a
// rule has and leaves the deny as the thing underneath it.
const startingPolicy = `{
  "id": "pol_starting_allow_https",
  "tenant_id": "tenant_default",
  "name": "Allow HTTPS — the rule to narrow first",
  "priority": 100,
  "conditions": {
    "actor_type": "human",
    "service_family": "https"
  },
  "action": {
    "decision": "allow"
  },
  "status": "active"
}
`

// startingEgressPolicy is the floor underneath it: any human flow to a PUBLIC address is allowed.
//
// ★★★ WITHOUT IT, INSTALLING THE AGENT STOPS THE MACHINE (2026-09-04, measured on a Mac steered by a
// deployment this installer had just minted). The agent steers ALL TCP; the only policy above allows the
// https service family; everything else met the default deny. On the device that is not a policy message, it
// is the network going away:
//
//	example.com:80        connected, then OSError [Errno 50] Network is down
//	github.com:22         connected, then Network is down
//	smtp.gmail.com:587    connected, then Network is down
//
// So a freshly installed device could browse and do nothing else — no ssh, no smtp, no plain http, and
// therefore no code signing, no package manager that speaks anything but https, no captive portal. "Install
// this and the machine stops" is the worst thing a security product can do, and it is what this did.
//
// ★ EGRESS ONLY, AND LAST. destination_address_scope=public means the internet: a private or link-local
// destination does not match, so this grants nothing east-west and nothing toward an internal asset — those
// stay with the connector routes an administrator binds. Priority 1000 puts it after every rule an operator
// will ever write (lower number is evaluated first), so it is the floor and never the ceiling.
const startingEgressPolicy = `{
  "id": "pol_starting_allow_egress",
  "tenant_id": "tenant_default",
  "name": "Allow outbound internet — the floor, narrow above it",
  "priority": 1000,
  "conditions": {
    "actor_type": "human",
    "destination_address_scope": "public"
  },
  "action": {
    "decision": "allow"
  },
  "status": "active"
}
`

// startingBundle names the policies this deployment enforces.
//
// ★ IT EXISTS BECAUSE THE EDGE DEMANDS ONE, and its default points inside a source checkout. A deployment
// that does not ship a bundle dies on a path an operator never chose:
//
//	validate policy bundle ../samples/phase1/policy_bundle_standard.json: no such file or directory
const startingBundle = `{
  "id": "pb_starting_001",
  "tenant_id": "tenant_default",
  "version": "1",
  "policy_schema_version": "2026.05.22",
  "checksum": "sha256:unsigned-local-bundle",
  "signature": "unsigned-local-bundle",
  "signing_key_id": "unsigned-local-bundle",
  "target_scope": {
    "target_type": "local_edge",
    "edge_region_id": "local",
    "edge_cluster_id": "local-edge-001",
    "device_group_id": null,
    "connector_group_id": null
  },
  "policy_ids": ["pol_starting_allow_https", "pol_starting_allow_egress"],
  "compiled_policy_ref": "policy.json",
  "bundle_type": "standard",
  "created_at": "2026-01-01T00:00:00Z",
  "expires_at": "2036-01-01T00:00:00Z",
  "status": "active"
}
`

// writeSchemasAndPolicy makes the deployment directory self-contained.
//
// ★★★ THE EDGE COULD NOT START OUTSIDE THE REPOSITORY (2026-08-22, measured by trying). -schema-dir defaults
// to "../schemas", a path that exists only in a source checkout, and its help says "schema JSON directory"
// with no hint that the default is repo-relative. A deployment that follows any document not mentioning that
// flag dies with
//
//	validate schema: ... read schema: open ../schemas/policy.schema.json: no such file or directory
//
// which reads as a missing file rather than as a flag nobody was told to pass. The schemas are small and they
// belong with the deployment they validate, so the installer writes them next to everything else and prints
// -schema-dir pointing at them. Nothing then depends on where the binary was built.
func writeSchemasAndPolicy(dir string) error {
	schemaDir := filepath.Join(dir, "schemas")
	if err := os.MkdirAll(schemaDir, 0o755); err != nil {
		return err
	}
	entries, err := embeddedSchemas.ReadDir("schemas")
	if err != nil {
		return fmt.Errorf("read the embedded schemas: %w", err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		b, err := embeddedSchemas.ReadFile("schemas/" + e.Name())
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(schemaDir, e.Name()), b, 0o644); err != nil {
			return err
		}
	}
	// The hot store's tables, written where the container rendering mounts them and where a host install can
	// point clickhouse-client at them.
	chDir := filepath.Join(dir, "clickhouse-init")
	if err := os.MkdirAll(chDir, 0o755); err != nil {
		return err
	}
	if err := os.Chmod(chDir, 0o755); err != nil {
		return err
	}
	chEntries, err := embeddedClickHouseSchema.ReadDir("clickhouse")
	if err != nil {
		return fmt.Errorf("read the embedded hot-store schema: %w", err)
	}
	for _, e := range chEntries {
		if e.IsDir() {
			continue
		}
		b, rerr := embeddedClickHouseSchema.ReadFile("clickhouse/" + e.Name())
		if rerr != nil {
			return rerr
		}
		if werr := writeContainerReadableFile(filepath.Join(chDir, e.Name()), b); werr != nil {
			return werr
		}
	}
	for _, item := range shippedPolicyFiles() {
		path := filepath.Join(dir, item.name)
		if _, err := os.Stat(path); err == nil {
			continue // an operator has edited it; never overwrite what somebody authored
		}
		if err := os.WriteFile(path, []byte(item.body), 0o644); err != nil {
			return err
		}
	}
	return nil
}

// report prints what was made and the fingerprint of the one thing that has to be distributed.
//
// ★★★ THE FINGERPRINT IS THE POINT (2026-08-22, learned the same day). A root was handed to another machine
// by a path nobody could vouch for — the file named in the letter had never been pushed — and it was safe to
// install anyway, because three independent sources named the same fingerprint and the device itself said
// which one it was missing. An installer that prints the anchor's fingerprint makes every later "is this the
// right file" answerable without trusting the file's journey.
func report(dir string, a *deploymentAuthorities, names []string, ips []net.IP) {
	where := make([]string, 0, len(names)+len(ips))
	where = append(where, names...)
	for _, ip := range ips {
		where = append(where, ip.String())
	}
	fmt.Printf("dsse-install: this deployment's authorities are in %s\n\n", dir)
	fmt.Printf("  answers on          %s\n", strings.Join(where, ", "))
	fmt.Printf("  anchor to distribute deployment-anchor.pem\n")
	fmt.Printf("  anchor fingerprint  %s\n", fingerprint(a.RootCert))
	fmt.Printf("                      ★ check this against the anchor wherever it arrives. The file's journey\n")
	fmt.Printf("                        does not have to be trusted if the fingerprint is compared.\n\n")
	fmt.Printf("  keys are files in this directory, readable only by its owner. That is the default so a\n")
	fmt.Printf("  deployment can be stood up without an HSM; every one of them also has an HSM path.\n\n")
	fmt.Printf("  start it with the scripts beside the keys — %s.\n", launchScriptNames())
	fmt.Printf("  In containers, %s runs those same scripts:\n", composeFileName())
	fmt.Printf("    docker compose --env-file deployment.env up -d\n")
	fmt.Printf("  ★ ONE DESCRIPTION, TWO RENDERINGS. The compose file repeats no flag — each service runs a\n")
	fmt.Printf("  script above — so a host install and a container install cannot say different things.\n")
	fmt.Printf("  They read %s, so the secrets are not in your shell history\n", filepath.Join(dir, "deployment.env"))
	fmt.Printf("  or in a ps listing. Each needs DSSE_EDGE_BINARY; the control plane also needs a database\n")
	fmt.Printf("  (DSSE_POSTGRES_DSN, DSSE_MIGRATION_DIR) and each Edge needs DSSE_CONTROL_PLANE.\n")
	fmt.Printf("\n  ★ THE CONTROL PLANE FIRST. An Edge refuses to start without one, so the order is enforced\n")
	fmt.Printf("  rather than recommended — and an Edge holds no database of its own.\n")
	fmt.Printf("\n  then check it:\n")
	fmt.Printf("    dsse-install -verify -dir %s \\\n", dir)
	fmt.Printf("      -control-plane https://admin.<host>:443 \\\n")
	// ★★★ EVERY CONTROL PLANE, BY NAME (2026-08-26, found by following this very instruction). Through the
	// front door one control plane and two look identical — that is what a front door is for — so whether the
	// authority is redundant is a question about the NODES, and the check can only count what it is given.
	// Without this flag it counted one and reported the deployment as a single point of failure, on a
	// deployment that had more than one. An operator following the printed procedure was told to fix
	// something that was not wrong, and had nothing to do about it.
	//
	// ★★★ ONE ENTRY PER MACHINE, AND THIS PRINTED TWO OF EACH UNTIL 2026-09-05. It named <cp-b> and
	// <edge-b> — the second control plane and second Edge that used to sit on every machine, retired
	// 2026-09-02. A machine holds one of each now and a region grows by adding MACHINES, so the list is as
	// long as the deployment has machines: give it one entry per node, or the check counts what it was
	// handed and reports the rest as absent.
	fmt.Printf("      -control-plane-peers https://<cp-a>:9443[,https://<another machine's cp>:9443 ...] \\\n")
	fmt.Printf("      -edge-admin https://<edge-a>:9443[,...] -edge https://agents.<host>:443\n")
	fmt.Printf("\n  ★ RUN THE CHECK. It asserts what this deployment is supposed to be — that the control plane\n")
	fmt.Printf("  holds the authority, that the Edge is APPLYING it rather than merely reaching it, and that a\n")
	fmt.Printf("  device can enrol exactly once. An Edge whose pull is refused stays healthy on every screen\n")
	fmt.Printf("  while enforcing what it booted with; that is the failure this catches and nothing else does.\n")
	fmt.Printf("\n  then close it:\n")
	fmt.Printf("    dsse-install -bootstrap-admin -dir %s \\\n", dir)
	fmt.Printf("      -control-plane https://admin.<host>:443 -admin-email <address>\n")
	// ★★★ AND THE EDGES, WHICH THIS LINE USED TO LEAVE OUT (2026-08-26, measured by following it). Closing
	// the break-glass credential changes what the FLEET presents too: every Edge is still holding the
	// credential that just stopped working, so it is answered 401 on every pull and goes on serving what it
	// booted with. Restarting only the control plane left a deployment where no device and no connector could
	// enrol — 403 "invalid or missing eligibility token" — on a deployment that had been all-green a minute
	// earlier. Restarting the Edges as well made it green again.
	fmt.Printf("    # then restart the control plane AND this region's Edges — closing the break-glass\n")
	fmt.Printf("    # credential changes the credential the fleet presents, and an Edge still holding the old\n")
	fmt.Printf("    # one is answered 401 on every pull while staying healthy on every screen\n")
	fmt.Printf("\n  ★★ THE ORDER IS: START, CHECK, THEN CLOSE. A new deployment has no named principals and no\n")
	fmt.Printf("  API tokens, so nothing can authenticate — not an administrator, not an Edge pulling config.\n")
	fmt.Printf("  start-control-plane.sh therefore arms a break-glass credential that authorises as owner and\n")
	fmt.Printf("  attributes every act to nobody. -bootstrap-admin creates a real administrator, mints the\n")
	fmt.Printf("  fleet's own read-scoped credential, and writes a marker; from the next restart the script\n")
	fmt.Printf("  arms nothing. Check BEFORE that, while the break-glass credential is the only one there is —\n")
	fmt.Printf("  which is also when somebody is looking.\n")
	// ★★★ SAID AT THE END, WHERE THE OPERATOR IS STILL READING. A deployment named after a name that
	// resolves to the asking machine cannot span regions, and nothing later in the procedure says so — the
	// second region simply dials itself.
	deploymentHost := "localhost"
	if len(names) > 0 {
		deploymentHost = strings.TrimSpace(names[0])
	}
	// Four DNS records are a prerequisite nothing here used to mention. See the_planes_are_names_that_must_resolve.go.
	reportPlaneNameResolution(deploymentHost)
	if strings.EqualFold(deploymentHost, "localhost") ||
		strings.HasSuffix(strings.ToLower(deploymentHost), ".localhost") {
		fmt.Printf("\n  ★★★ THIS DEPLOYMENT IS CALLED %q, AND EVERY PLANE IS DERIVED FROM IT: admin.%s,\n",
			deploymentHost, deploymentHost)
		fmt.Printf("  agents.%s, console.%s. Those names resolve to whoever asks, so a SECOND REGION's\n",
			deploymentHost, deploymentHost)
		fmt.Printf("  Edges would dial themselves rather than this deployment. That is fine for one machine and\n")
		fmt.Printf("  cannot be repaired later without re-issuing every certificate this deployment presents.\n")
		fmt.Printf("  If this deployment will ever have a second region, mint it again with a name that\n")
		fmt.Printf("  resolves from elsewhere FIRST:  -host <the-name-others-use>,localhost\n")
	}
	// The region's name is printed by the CALLER, after a plan has had its say — see reportRegionName.
	if !installingFromAPlan {
		reportRegionName(dir)
	}
	fmt.Printf("\n  ★★★ EVERY OTHER MACHINE IS CARRIED FROM HERE — never this command run again. A deployment has ONE\n")
	fmt.Printf("  anchor however many machines and regions it spans, and minting a second gives a device that\n")
	fmt.Printf("  MOVES between them an issuer it has never heard of. Pack each machine what IT runs:\n\n")
	fmt.Printf("    dsse-install -dir %s -carry <file.tar.gz> -control-plane-only\n", dir)
	fmt.Printf("    dsse-install -dir %s -carry <file.tar.gz> -region <region-id>\n", dir)
	fmt.Printf("    dsse-install -dir %s -carry <file.tar.gz> -region <region-id> -holds-state -control-plane-only\n\n", dir)
	fmt.Printf("  ★ EACH ONE HOLDS ONLY WHAT THAT MACHINE'S SERVICES MOUNT AND NAME, and never authority/ — the\n")
	fmt.Printf("  minting material stays HERE, on this machine, which is the only one that issues. Untar on the\n")
	fmt.Printf("  receiving machine and start it; a machine that runs Edges also needs -region run on the copy.\n")
	fmt.Printf("  Then, ONLY once every region exists, set DSSE_REGION_ENDPOINTS to the same value in every\n")
	fmt.Printf("  region's deployment.env, restart the Edges, and check they agree:\n")
	fmt.Printf("    dsse-install -verify -dir %s -edge-admin https://<edge-a>:9443[,one per Edge machine] ...\n", dir)
}

func certPEM(c *x509.Certificate) []byte {
	if c == nil {
		return nil
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}

func keyPEM(k *ecdsa.PrivateKey) []byte {
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		return nil
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

// interceptionKeyPEM encodes the interception tier's key. PKCS#1, which is what the engine's own persistence
// writes and its loader tries first — the point of this tier is that an Edge picks it up instead of minting
// one, so it has to be written in the shape that Edge reads.
func interceptionKeyPEM(k *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
}

// randomSecret makes one of the secrets an Edge demands in a production configuration.
//
// ★ PRINTED RATHER THAN WRITTEN TO A FILE, and generated rather than suggested. An Edge refuses to start with
// a short secret, with a workload-attestation secret equal to the connector one, and with the development
// default it ships for local use — all measured by trying. An installer that printed placeholders would hand
// an operator three things to invent at the moment they least want to think about it, and the shortest path
// from there is the very default being refused.
// randomSecret mints a value this deployment will carry for its life.
//
// ★★★ AND IT MUST NEVER BEGIN WITH "-" (2026-09-02, measured: a deployment that stood up correctly and whose
// hot store was dead). base64url's alphabet includes "-", so roughly one generated secret in thirty-two starts
// with one — and a value starting with "-" stops being a value the moment anything passes it as an argument:
//
//	Code: 552. DB::Exception: Unrecognized option '-H9ekhsO1gSO_nlvY5d7hWMa34wGmG5x'. (UNRECOGNIZED_ARGUMENTS)
//
// The hot store exited 1 at boot, every Edge's audit shipping backed up behind it, and -verify reported a
// degraded store with 75 ingest failures. Nothing in that chain names a password, and nothing in it is wrong
// except the first character of a random string. A deployment that fails one build in thirty-two, somewhere
// else entirely, is worse than one that fails every time.
//
// The fix is at the mint, not at each use: quoting every call site is a rule someone has to keep, and the
// first place it is forgotten is a place nobody looks. A leading "-" is simply not minted.
func randomSecret() string {
	for {
		b := make([]byte, 24)
		if _, err := rand.Read(b); err != nil {
			return "GENERATE-A-LONG-RANDOM-SECRET-AND-PUT-IT-HERE"
		}
		if secret := base64.RawURLEncoding.EncodeToString(b); !strings.HasPrefix(secret, "-") {
			return secret
		}
	}
}

func keyPEMEd25519(k ed25519.PrivateKey) []byte {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func fingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:])
}

// shellQuote makes a value safe to SOURCE, because deployment.env is read with '.' rather than parsed.
//
// ★★★ A REGION ENTRY LIST BROUGHT A WHOLE DEPLOYMENT DOWN (2026-08-23, measured while installing a second region). Its
// format is "region=URL;region=URL", and ';' is a command separator: the shell assigned the first entry and
// then tried to RUN the second. Every node exited 127 within a second of each other, and the message was
//
//	/deployment/deployment.env: 23: region-b=https://localhost:28445: not found
//
// which points at a file and a line and says nothing about quoting. This is the good direction — a deployment
// that refuses to start beats one that starts holding half a region map — but it is a failure the tool
// writing the file can simply not produce.
func shellQuote(v string) string {
	return "'" + strings.ReplaceAll(v, "'", `'"'"'`) + "'"
}

// cnHostFor is the one name (or address) this deployment is reached by from outside.
func cnHostFor(names []string, ips []net.IP) string {
	if len(names) > 0 {
		return names[0]
	}
	if len(ips) > 0 {
		return ips[0].String()
	}
	return ""
}

// agentPolicySigningKeyFile is the deployment's agent-policy signing key: the Ed25519 seed whose public half
// every device pins, and which signs both the steer policy an agent applies and the config bundle an Edge
// accepts.
//
// ★★★ WHY THE INSTALLER MINTS IT AND NOT THE EDGE (2026-08-25, measured on a two-region deployment).
//
// The Edge's loader is load-or-generate: an absent file means "make one and persist it". Inside ONE region
// that is invisible, because the control plane and the Edges share this directory, so whichever boots first
// mints the key and the rest load it. Across regions it is a deployment split in half. Region B was carried
// from region A and came up healthy, announcing
//
//	agent-policy signing ENABLED — key_id=edge-agent-policy-3350acbc94987678
//
// against a deployment whose bundles are signed by edge-agent-policy-33f9b9153e082e57 — so every ten seconds
// its Edge logged "config bundle signature verification failed (rejecting tampered/untrusted config)" and
// applied NOTHING from the control plane, while both regions reported healthy. A device enrolled there would
// have been served steer policy signed by an authority no device has ever pinned.
//
// The repository already knew this failure: agentpolicy.LoadSigner exists precisely because "a freshly
// generated key is one no device has ever pinned or adopted, so the Edge would come up reporting healthy
// while signing policy the entire fleet rejects". What was missing is that nothing put the key in the set an
// operator CARRIES — it was not created until a node booted, so a directory copied before that carried a hole,
// and the hole filled itself differently in each place.
//
// A deployment has one anchor and one set of authorities beneath it (invariant 11). This is one of them, so it
// is minted here, once, with everything else — and then carrying the directory carries it.
const agentPolicySigningKeyFile = "agent-policy-signing.key"

// The public half, which is what an agent package is BUILT with (-Pin) — not a secret, and not optional.
const agentPolicySigningPublicFile = "agent-policy-signing.pub"

// writeAgentPolicySigningKey mints the seed if this directory has none, and never touches one that exists:
// replacing it would orphan every device that has pinned the public half.
func writeAgentPolicySigningKey(dir string) error {
	path := filepath.Join(dir, agentPolicySigningKeyFile)
	if _, err := os.Stat(path); err == nil {
		// ★★ THE KEY IS KEPT, BUT THE PUBLIC HALF IS STILL OWED (measured 2026-08-25 on a deployment whose key
		// an Edge had generated before this installer minted them). Returning here left a deployment with no
		// agent-policy-signing.pub for its whole life — and the public half is not a convenience: it is the
		// value an agent package is built with (-Pin), so without it nobody can produce an agent that trusts
		// this deployment, and the only way to read it was to grep an Edge's start-up log.
		return writeAgentPolicySigningPublicHalf(dir, path)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("stat %s: %w", path, err)
	}
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return err
	}
	// The on-disk form is the Edge's: 32 bytes as hex, and nothing else. Written by the same rule the Edge
	// reads by, so a key this installer mints and a key an Edge minted are the same file.
	if err := os.WriteFile(path, []byte(hex.EncodeToString(seed)), 0o600); err != nil {
		return err
	}
	// ★ AND ITS PUBLIC HALF, SO THE CARRY IS CHECKABLE. The private seed must never be compared out loud, and
	// "did the copy arrive intact" is a question an operator has to be able to answer in another region without
	// handling the secret. This is the value the Edge prints as public_key= at start-up.
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	return os.WriteFile(filepath.Join(dir, agentPolicySigningPublicFile),
		[]byte(hex.EncodeToString(pub)+"\n"), 0o644)
}

// agentUpdateSigningKeyFile is the key that authorises RUNNING CODE on every device of this deployment, and
// it is the one authority here that is minted OUTSIDE the deployment directory on purpose.
//
// ★★★ A DEPLOYMENT THIS PROGRAM PRODUCED COULD NOT INSTALL AN AGENT (2026-08-27, measured by building the
// real signed, notarised macOS package and running its own preinstall against the configuration this
// deployment publishes):
//
//	REFUSING TO INSTALL: the agent configuration has no usable update_signing_keys, so this Mac could
//	never be updated.
//
// That gate is right, and it exists because the fleet once shipped exactly that — a security agent nobody
// could patch. The control plane publishes update_signing_keys from -agent-update-pin and this installer
// named none, so the two halves of the product refused each other: the deployment came up healthy, every
// screen was green, and no endpoint could ever join it.
//
// ★ THE PIN IS WHAT A DEPLOYMENT NEEDS, AND A PIN IS PUBLIC. Releases can be published by handing the control
// plane an envelope signed somewhere else, and there is deliberately NO on-disk fallback for the signing key:
// it belongs in a token, because an Edge holding it would mean one compromised node can authorise running
// code on every device. So the public half is minted here and carried; the private half is written into
// authority/, which -carry structurally never sends to any node, and is material to move into a token.
const agentUpdateSigningKeyFile = "agent-update-signing.key"

// The public half — the pin. Not a secret, and the value that makes a published configuration installable.
const agentUpdateSigningPublicFile = "agent-update-signing.pub"

// writeAgentUpdateSigningKey mints the pair if this deployment has none, and never replaces one: the public
// half is pinned by every device installed from this deployment, and replacing it orphans all of them.
func writeAgentUpdateSigningKey(dir string) error {
	priv := filepath.Join(dir, authorityDirName, agentUpdateSigningKeyFile)
	pub := filepath.Join(dir, agentUpdateSigningPublicFile)
	if _, err := os.Stat(priv); err == nil {
		if _, perr := os.Stat(pub); perr == nil {
			return nil
		}
		// The public half is owed even when the private one is already here — without it the control plane
		// pins nothing, and that is the whole failure above.
		seedHex, rerr := os.ReadFile(priv)
		if rerr != nil {
			return rerr
		}
		seed, derr := hex.DecodeString(strings.TrimSpace(string(seedHex)))
		if derr != nil || len(seed) != ed25519.SeedSize {
			return fmt.Errorf("%s is not a 32-byte hex seed", priv)
		}
		return writeUpdatePinFile(pub, seed)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("stat %s: %w", priv, err)
	}
	if err := os.MkdirAll(filepath.Dir(priv), 0o700); err != nil {
		return err
	}
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return err
	}
	if err := os.WriteFile(priv, []byte(hex.EncodeToString(seed)), 0o600); err != nil {
		return err
	}
	return writeUpdatePinFile(pub, seed)
}

func writeUpdatePinFile(path string, seed []byte) error {
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	return os.WriteFile(path, []byte(hex.EncodeToString(pub)+"\n"), 0o644)
}

// appendAgentPublisherIfAbsent gives every answer only an OPERATOR can supply a place in a deployment.env
// written before that answer existed, with what leaving it empty costs written beside it.
//
// ★★★ THESE ARE THE VALUES THE PRODUCT'S OWN INSTRUCTIONS NAME AND OLDER FILES DO NOT CONTAIN. deployment.env
// is never regenerated — it holds this deployment's secrets — so a value a new version requires is one the
// operator meets as a -verify failure, or as a closing instruction, naming a line their own configuration does
// not have. Appending costs nothing: an empty assignment in a sourced file is what absent already meant.
func appendAgentPublisherIfAbsent(dir string) error {
	path := filepath.Join(dir, "deployment.env")
	body, err := os.ReadFile(path)
	if err != nil {
		return nil // no environment here; the install path writes one
	}
	existing := string(body)
	for _, answer := range []struct{ key, block, note string }{
		{
			key: "DSSE_AGENT_PUBLISHER",
			block: "\n# The signing identity that builds the agent packages your devices install — an Apple\n" +
				"# Team ID on macOS, its counterpart on Windows. ★ UNTIL THIS IS SET, NO ENDPOINT CAN BE\n" +
				"# INSTALLED against this deployment: its published configuration names no publisher, and\n" +
				"# the endpoint installer refuses that rather than installing whatever a manifest points at.\n" +
				"# Read it from the agent build you distribute:  codesign -dv <app> 2>&1 | grep TeamIdentifier\n" +
				"DSSE_AGENT_PUBLISHER=''\n",
			note: "empty means no endpoint can be installed against this deployment",
		},
		{
			key: "DSSE_REGION_BIND_A",
			block: "\n# \u2605 Which host ADDRESS the region's door binds, with a trailing colon, e.g. '10.20.1.5:'.\n" +
				"# This is per MACHINE: it is the only value in this file that differs between the copies of it.\n" +
				"# Empty = every interface, which is why the ports are moved in a one-host rendering.\n" +
				"DSSE_REGION_BIND_A=''\n",
			note: "empty means the door is on every interface, so two regions on one host cannot both be 443",
		},
		{
			key: "DSSE_ETCD_A_PUBLISH",
			block: "\n# ★★★ WHERE THIS REGION'S STATE AND CONSENSUS ANSWER FROM, for a deployment with more than\n" +
				"# one region. They default to LOOPBACK, which is right for one host and means a second region\n" +
				"# can reach neither — and -holds-state says it 'requires DSSE_ETCD_HOSTS to name the\n" +
				"# deployment's consensus store, reachable from here', which nothing published makes true.\n" +
				"# PUBLISH is the address on THIS machine; ADVERTISE is the name the deployment tells others to\n" +
				"# use, so a name that resolves privately at home and publicly abroad is correct in both.\n" +
				"# ★ THESE CARRY THE DEPLOYMENT'S STATE. Between sites they cross whatever is between them:\n" +
				"# put them on a private interconnect, or restrict them at the firewall to the other region's\n" +
				"# addresses. Leave them empty and this deployment simply has one region.\n" +
				"DSSE_ETCD_A_PUBLISH=''\nDSSE_ETCD_A_ADVERTISE=''\n" +
				"DSSE_ETCD_B_PUBLISH=''\nDSSE_ETCD_B_ADVERTISE=''\n" +
				"DSSE_ETCD_C_PUBLISH=''\nDSSE_ETCD_C_ADVERTISE=''\n" +
				"DSSE_PG_A_MEMBER_PUBLISH=''\nDSSE_PG_A_ADVERTISE=''\n" +
				"DSSE_PG_A_API_PUBLISH=''\nDSSE_PG_A_API_ADVERTISE=''\n" +
				"DSSE_PG_B_MEMBER_PUBLISH=''\nDSSE_PG_B_ADVERTISE=''\n" +
				"DSSE_PG_B_API_PUBLISH=''\nDSSE_PG_B_API_ADVERTISE=''\n" +

				"# What a JOINING region is given: this deployment's consensus store.\n" +
				"# ★★★ DSSE_POSTGRES_DSN IS DELIBERATELY NOT HERE (after writing it empty broke a\n" +
				"# working deployment). start-control-plane.sh REQUIRES it and the compose supplies a default;\n" +
				"# writing it empty overrides nothing and trips the required check, so every control plane\n" +
				"# exited 2 with 'set DSSE_POSTGRES_DSN to a database this control plane owns' — on a\n" +
				"# deployment that had been running. Giving an answer a place must never turn a working\n" +
				"# default into an empty required value. A joining region is told this one by -region.\n" +
				"DSSE_ETCD_HOSTS=''\n",
			note: "empty means the consensus store and the database answer on loopback, so no second region can join",
		},
		{
			// ★ ITS OWN ENTRY, NOT PART OF THE BLOCK ABOVE. Each entry here is keyed on ONE variable, so a
			// value added to an existing block never reaches a deployment that already has that block's first
			// line — which is how this one was written, appended, and did not appear.
			key: "DSSE_PG_A_NAME",
			block: "\n# ★★★ WHAT EACH DATABASE MEMBER CALLS ITSELF. The default is its compose service name, which\n" +
				"# is the SAME in every region — so the second region's first member announces a name the\n" +
				"# deployment already has, and Patroni refuses it outright:\n" +
				"#   CRITICAL: Can't start; there is already a node named 'dsse-postgres-a' running\n" +
				"# One cluster spans every region, so the names in it must be unique. ★ PER MACHINE.\n" +
				"DSSE_PG_A_NAME=''\nDSSE_PG_B_NAME=''\n",
			note: "empty means both regions call their members the same thing, and the second one cannot start",
		},
		{
			key: "DSSE_PG_PEERS",
			block: "\n# ★★★ THE DATABASE MEMBERS IN THE OTHER REGIONS, as host:member-port:api-port. The deployment has\n" +
				"# ONE primary and it can be in any region — so a door that knows only the members on this\n" +
				"# machine has no backend at all whenever the primary is elsewhere, and everything that needs\n" +
				"# the database stops. Measured: the leader moved to the second region and the FIRST region's\n" +
				"# database init looped on 'server closed the connection unexpectedly', which took its control\n" +
				"# planes with it — they wait for it.\n" +
				"# ★ The ports are the ones that region PUBLISHES its members on, so they cannot be derived\n" +
				"# from anything here. Empty means this deployment keeps its database in one region.\n" +
				"DSSE_PG_PEERS=''\n",
			note: "empty means this region's database door cannot find a primary in another region",
		},
		{
			key: "DSSE_REGION_ENDPOINTS",
			block: "\n# The deployment's regions and the address each answers on. \u2605 KEEP THE QUOTES: this file\n" +
				"# is sourced, and the ';' in this format is a command separator \u2014 an unquoted value makes\n" +
				"# every node exit 127.\n" +
				"#   DSSE_REGION_ENDPOINTS='region-a=https://a.example;region-b=https://b.example'\n" +
				"# \u2605 FILL THIS IN ONLY WHEN EVERY REGION EXISTS, AND GIVE EVERY EDGE THE SAME VALUE. An Edge\n" +
				"# holding a shorter list is healthy and hands its devices a map missing the regions it never\n" +
				"# heard about, so a device served by it never fails over there.\n" +
				"DSSE_REGION_ENDPOINTS=''\n",
			note: "empty means devices served here never fail over to another region",
		},
	} {
		if strings.Contains(existing, answer.key) {
			continue
		}
		f, ferr := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
		if ferr != nil {
			return ferr
		}
		_, werr := f.WriteString(answer.block)
		cerr := f.Close()
		if werr != nil {
			return werr
		}
		if cerr != nil {
			return cerr
		}
		existing += answer.block
		fmt.Printf("  added %s to deployment.env — %s.\n", answer.key, answer.note)
	}
	return nil
}

// deploymentFileExists answers whether one file is in the deployment directory.
func deploymentFileExists(dir, name string) bool {
	_, err := os.Stat(filepath.Join(dir, name))
	return err == nil
}

// repairDerivedFiles writes what can be DERIVED from authorities already on disk. Every act here must be safe
// to repeat on a running deployment and must never replace an authority — those are rotations, and a rotation
// that happens as a side effect of re-running an installer is how a fleet gets orphaned.
func repairDerivedFiles(dir string) error {
	// ★★★ THIS IS THE ONE PATH THAT MAY OVERWRITE A GENERATED FILE. Every writer below opens with "leave it
	// alone, an operator has edited it", which is right on an install and is exactly wrong here: this
	// function exists to bring a running deployment up to the current installer, and on 2026-08-31 it
	// therefore rewrote nothing at all while printing the names of the files it had skipped. See
	// a_repair_that_reports_what_it_did.go.
	regeneratingDerivedFiles = true
	derivedFileOutcomes = nil
	defer func() { regeneratingDerivedFiles = false }()
	key := filepath.Join(dir, agentPolicySigningKeyFile)
	if _, err := os.Stat(key); err != nil {
		return nil // no key here; the carry check elsewhere is what refuses that
	}
	if _, err := os.Stat(filepath.Join(dir, agentPolicySigningPublicFile)); err != nil {
		if err := writeAgentPolicySigningPublicHalf(dir, key); err != nil {
			return err
		}
		fmt.Printf("  wrote %s — the public half of the agent-policy signing key, which is the value an agent\n",
			agentPolicySigningPublicFile)
		fmt.Printf("  package is built with. It is not a secret, and this deployment did not have it on disk.\n")
	}

	// ★★★ AND THE SCRIPTS THAT START IT (2026-08-25). A deployment generated by an older installer could never
	// receive a correction to its own launch: this act returned "nothing to do", and the launch scripts, the
	// compose file and the front-door configuration stayed frozen at whatever the installer knew on the day the
	// authorities were minted. Measured on a two-region deployment whose control planes held their connector
	// registry in per-process MEMORY and therefore disagreed with each other, 8 against 1 — a fix existed and
	// there was no way for that deployment to take it.
	//
	// Every file below is DERIVED: it is generated from the deployment's own values and holds no secret (the
	// secrets stay in deployment.env, which is read at start-up and is never touched here). Rewriting them
	// changes nothing until the operator restarts, which is theirs to choose.
	// ★★★ AND THE TIER THAT WAS NEVER MINTED. See the_third_tier.go — adding one orphans nothing, because
	// nothing has ever been issued under it, and without it this deployment's Edges inspect nothing.
	if _, err := mintTheInterceptionTierIfMissing(dir, time.Now(), defaultDeploymentYears); err != nil {
		return err
	}
	// ★★★ AND THE KEY THE REWRITTEN SCRIPTS ABOVE NOW READ (2026-08-27, measured on a copy of a running lab).
	// The rewrite is the whole point of this function, and it made the launch script read
	// agent-update-signing.pub and the compose file mount it — on a deployment where nothing had minted one.
	// The control plane would have started, found nothing, pinned an empty list, and published a configuration
	// every endpoint installer refuses; and the operator was told "no secret or authority was touched", which
	// was true and read as reassurance.
	//
	// ★ MINTING WHAT IS ABSENT IS NOT A ROTATION, the same rule as the tier above: a key that does not exist
	// has been pinned by nobody, so there is nothing to orphan. writeAgentUpdateSigningKey never replaces one
	// that is here.
	// ★★ AND THE ANSWER ONLY AN OPERATOR CAN GIVE GETS A PLACE TO BE WRITTEN. deployment.env is never
	// regenerated — it holds this deployment's secrets — so a value a new version requires would never appear
	// in the file of a deployment that already exists, and the operator would meet it as a -verify failure
	// naming a variable their own configuration does not mention. Appending the block costs nothing: an empty
	// assignment in a sourced file is what absent already meant, and now it explains itself.
	if err := appendAgentPublisherIfAbsent(dir); err != nil {
		return err
	}
	hadPin := deploymentFileExists(dir, agentUpdateSigningPublicFile)
	if err := writeAgentUpdateSigningKey(dir); err != nil {
		return err
	}
	if !hadPin && deploymentFileExists(dir, agentUpdateSigningPublicFile) {
		fmt.Printf("  wrote %s — the key that authorises RUNNING CODE on this deployment's devices. Without it\n",
			agentUpdateSigningPublicFile)
		fmt.Printf("  the configuration this deployment publishes is one the endpoint installer refuses, so no\n")
		fmt.Printf("  device could be installed against it. The private half is in %s/ and belongs in a token.\n",
			authorityDirName)
	}
	// ★★★ AND THE KEYS THAT WERE BEING HANDED TO EVERY CONTAINER (2026-08-27). A deployment minted before the
	// authority directory existed keeps its root CA key at the top of the directory that five services mount.
	// Repair is the only path by which such a deployment stops doing that, and it has to say so: a private key
	// changing place is a thing an operator must be able to find again.
	if moved, err := moveAuthorityMaterialIntoPlace(dir); err != nil {
		return fmt.Errorf("move the minting material out of reach: %w", err)
	} else if len(moved) > 0 {
		fmt.Printf("  moved %d piece(s) of minting material into %s/ — nothing running is handed them any\n",
			len(moved), authorityDirName)
		fmt.Printf("  more: %s\n", strings.Join(moved, ", "))
		fmt.Printf("  ★ they are the deployment's own authority. Back them up from there, not from where they were.\n")
	}
	if err := rewriteGeneratedFiles(dir); err != nil {
		return err
	}
	// ★ THE ADMIN CONSOLE'S OWN CERTIFICATE, when the operator has put one there. See
	// the_console_is_the_first_screen_an_administrator_sees.go — the pair being present IS the intent, so the
	// installer does the bookkeeping rather than leaving an operator to remember a variable.
	if said := adoptConsoleCertificate(dir); said != "" {
		fmt.Printf("  %s\n", said)
	}
	if said := adoptStepUpPortalCertificate(dir); said != "" {
		fmt.Printf("  %s\n", said)
	}
	// ★★★ AND THE DIRECTORY IS ONE AN OPERATOR CAN ENTER (2026-09-02). New deployments are created 0755
	// (see the note beside MkdirAll); this is the same correction for one that already exists, because the
	// machine where it is wrong is the machine where the next printed step has to be run from — and that
	// step is `cd <dir> && docker compose`. The minting material is in <dir>/authority, 0700 in its own
	// right, and is not touched.
	if info, err := os.Stat(dir); err == nil && info.Mode().Perm()&0o055 != 0o055 {
		if err := os.Chmod(dir, info.Mode().Perm()|0o055); err == nil {
			fmt.Printf("  %s was %#o — an operator could not cd into the directory the next step runs in.\n",
				dir, info.Mode().Perm())
			fmt.Printf("  It is now %#o. The minting material stays in %s/, which is 0700 in its own right.\n",
				info.Mode().Perm()|0o055, authorityDirName)
		}
	}
	return nil
}

// rewriteGeneratedFiles regenerates the derived operational files of an existing deployment. Authorities,
// certificates, deployment.env and anything holding a secret are untouched.
func rewriteGeneratedFiles(dir string) error {
	env, err := readEnvFile(filepath.Join(dir, "deployment.env"))
	if err != nil {
		// No environment to derive from: this directory holds authorities and nothing else, which is a
		// carry in progress rather than a deployment to repair.
		return nil
	}
	planeHost := strings.TrimSpace(env["DSSE_AGENT_PLANE_NAME"])
	if planeHost == "" {
		planeHost = strings.TrimSpace(env["EDGE_HOST"])
	}
	// The shape is READ from what this directory already stands up, never assumed — see regionShapeFromCompose
	// for the rewrite that replaced a joining region's warm control plane because the guess had two answers
	// and the world has three. When the file names no shape this installer recognises, its compose is LEFT
	// ALONE: the launch scripts are the correction that matters, and reshaping a deployment nobody asked to
	// reshape is how a repair becomes an outage.
	shape, shapeKnown := regionShapeFromCompose(dir)
	composeBefore := ""
	acts := []struct {
		name string
		run  func() error
	}{
		{"the launch scripts", func() error { return writeLaunchScripts(dir) }},
		{"haproxy.cfg (the region's front door)", func() error { return writeRegionFrontDoorConfig(dir, planeNamesFor(planeHost)) }},
		{"haproxy-edge.cfg", func() error { return writeFrontDoorConfig(dir) }},
		{"haproxy-postgres.cfg", func() error { return writeDatabaseFrontDoorConfig(dir) }},
	}
	if shapeKnown {
		acts = append(acts, struct {
			name string
			run  func() error
		}{"docker-compose.yml", func() error {
			// Read before rewriting, so the report below is about THIS repair.
			before, _ := os.ReadFile(filepath.Join(dir, "docker-compose.yml"))
			if err := rewriteComposeFileFor(dir, shape); err != nil {
				return err
			}
			composeBefore = string(before)
			return nil
		}})
	}
	for _, a := range acts {
		if err := a.run(); err != nil {
			return fmt.Errorf("rewrite %s: %w", a.name, err)
		}
	}
	// ★ WHAT HAPPENED, NOT WHAT WAS ATTEMPTED. Printing the act list as though it were the outcome is the
	// defect this replaces: the list is the same whether a file was rewritten or silently kept.
	fmt.Printf("  this deployment's generated files, against the current installer:\n")
	reportDerivedFiles()
	if composeBefore != "" {
		reportComposeServiceChange(dir, composeBefore)
	}
	if !shapeKnown {
		fmt.Printf("    (docker-compose.yml was LEFT ALONE — this file names no shape this installer recognises)\n")
	}
	fmt.Printf("  No secret or authority was touched.\n")
	return nil
}

// writeAgentPolicySigningPublicHalf derives the public half from a seed already on disk. Derived rather than
// remembered: the two cannot disagree, and a .pub that no longer matches its key is worse than a missing one —
// an agent built against it silently refuses everything this deployment signs.
func writeAgentPolicySigningPublicHalf(dir, keyPath string) error {
	raw, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", keyPath, err)
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(seed) != ed25519.SeedSize {
		// Not fatal to the install: an ECDSA/PKCS#8 key is a shape this deployment may legitimately hold (the
		// HSM lane), and refusing here would make a supported deployment uninstallable. Say what was not
		// written so the operator does not go looking for a file that will never appear.
		fmt.Printf("note: %s is not a 32-byte hex seed, so its public half was not derived — read it from the "+
			"Edge's start-up line (public_key=)\n", filepath.Base(keyPath))
		return nil
	}
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	return os.WriteFile(filepath.Join(dir, agentPolicySigningPublicFile),
		[]byte(hex.EncodeToString(pub)+"\n"), 0o644)
}

// The deployment's interception tier on disk. The names are the ones the Edge's interception engine reads
// when it is pointed at this directory: it reuses material that is already there and mints its own only when
// there is none. See edgeplane.NetworkExtensionLabTLSRootCertFilename.
const (
	interceptionRootCertFile = "lantern_dsse_interception_root_ca.pem"
	interceptionRootKeyFile  = "lantern_dsse_interception_root_ca.key.pem"
)
