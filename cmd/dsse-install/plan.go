package main

// plan.go — a deployment described once, so every machine is derived rather than typed.
//
// ★★★ WHY THIS EXISTS (2026-08-28, written after standing up a two-site deployment by hand). Every value an
// operator had to set on each machine turned out to be a defect this installer should have prevented, and the
// list was long: which address each front door binds, where the consensus store and the database answer from,
// what each database member calls itself, which regions exist and what each is called, which of the other
// regions' planes this region's doors must reach. Each was set by hand, on four machines, and each mistake was
// silent — a machine that named another machine's address, a region that called itself by the name of the one
// it was packed from, two database members claiming one name, a region map whose two entries pointed at the
// same place.
//
// None of it was unknown. All of it is decided BEFORE anything is installed: it is the description of the
// deployment. So it is written down once, and everything below is derived.
//
// ★★ WHAT A PLAN IS NOT. It is not a second vocabulary for the flags. -control-plane-only and -region already
// describe ONE MACHINE, and they still do; a plan describes the DEPLOYMENT and produces those machines. The
// flags remain how a single machine is rendered, which is what an operator adding one to an existing
// deployment does.

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"sort"
	"strings"
)

// Plan is the whole deployment, as decided before it exists.
type Plan struct {
	// DeploymentCRLOrigins are independent, unauthenticated HTTP origins that
	// publish this deployment's signed CRLs. The issuer host must serve each
	// origin before endpoint enrollment; omitted origins retain legacy material
	// and fail the online-revocation release gate.
	DeploymentCRLOrigins []string `json:"deployment_crl_origins,omitempty"`
	// Profile selects a topology whose placement cannot be inferred from the number of regions.
	// An absent profile retains the meaning of existing plans.
	Profile            string `json:"profile,omitempty"`
	SharedEntryMachine string `json:"shared_entry_machine,omitempty"`
	// Deployment is the name everything hangs off: the planes, the per-region names, the node wildcard.
	Deployment string `json:"deployment"`
	// Names are any other names this deployment answers on. The first entry of the certificate is Deployment.
	Names []string `json:"names,omitempty"`
	// Publisher is the signing identity that builds the agent packages this deployment's devices install.
	// Without it the configuration this deployment publishes is one the endpoint installer refuses.
	Publisher string `json:"agent_publisher,omitempty"`
	// Images are operator inputs; omission retains the documented local build tags.
	ServiceImage string `json:"service_image,omitempty"`
	ConsoleImage string `json:"console_image,omitempty"`
	// DataLayer selects one reviewed cohort for offline candidate installs.
	// Omission retains the generated defaults until the public images are released.
	DataLayer *PlanDataLayer `json:"data_layer,omitempty"`
	Archive   *PlanArchive   `json:"archive,omitempty"`
	// ImageRevision identifies the reviewed source used for both first-party images.
	// Setup preflight requires it; generating an offline plan does not start services.
	ImageRevision string `json:"image_revision,omitempty"`
	// Mesh is whether the Edges of this deployment relay flows to each other's regions. A pointer, because
	// the three states are different: absent means "this deployment did not say", true and false mean it did.
	//
	// ★★★ ABSENT ON A MULTI-REGION DEPLOYMENT MEANS YES, AND THAT IS THE FIX (2026-09-01, the operator's
	// decision: "a three-region build with the mesh missing is a hole; fixing it is required").
	//
	// The flag existed, the start script read DSSE_MESH_PEERS, the printed order named the mesh as a step
	// after every region exists, and -verify said a connector in another region is unreachable without it —
	// while NOTHING WROTE A SINGLE PEER. So every multi-region deployment this installer has ever built came
	// up without one, and the shape it came up in reads as deliberate: "fail-closed, which is the default".
	//
	// It was not a posture, it was an omission wearing one. A deployment given three regions was given them
	// so that a device in one can reach an asset in another; refusing that by default, in silence, is not
	// residency — it is the second region not working, described in the vocabulary of a decision nobody made.
	//
	// ★ AND TURNING IT OFF IS STILL AVAILABLE, because there is a real posture here: a deployment whose
	// regions must NOT relay to each other keeps residency by construction, and a flow that needs a missing
	// link is refused BY NAME rather than finding another way out. That is now `"mesh": false` — said, once,
	// by whoever means it. The difference is which one you have to write down.
	//
	// A single-region deployment has nobody to relay to and gets no peers either way.
	Mesh    *bool        `json:"mesh,omitempty"`
	Regions []PlanRegion `json:"regions"`
}

// PlanDataLayer keeps the database image and its actual PostgreSQL major together.
// All three immutable images must be supplied, so carried nodes cannot silently
// mix the candidate database with the old init helper or consensus store.
type PlanDataLayer struct {
	EtcdImage          string `json:"etcd_image"`
	PostgresImage      string `json:"postgres_image"`
	PostgresToolsImage string `json:"postgres_tools_image"`
	PostgresMajor      int    `json:"postgres_major"`
}

func immutableImageRef(ref string) bool {
	if strings.TrimSpace(ref) != ref || strings.ContainsAny(ref, " \t\r\n") {
		return false
	}
	name, digest, ok := strings.Cut(ref, "@sha256:")
	if !ok || name == "" || len(digest) != 64 || strings.Contains(name, "@") {
		return false
	}
	_, err := hex.DecodeString(digest)
	return err == nil
}

// PlanArchive names storage operated outside DSSE. It contains no secret: static
// credentials are entered once in the private deployment.env before carrying CPs.
type PlanArchive struct {
	Endpoint   string `json:"endpoint"` // TLS endpoint, host:port
	Bucket     string `json:"bucket"`
	Region     string `json:"region,omitempty"`
	AuthMode   string `json:"auth_mode"`   // static or iam
	WebhookURL string `json:"webhook_url"` // HTTPS receiver; signing secret stays in deployment.env
}

// HasMesh is whether this deployment relays between its regions: what it said, or — when it said nothing —
// yes for more than one region and no for one. See the note on Plan.Mesh for why the absent case is yes.
func (p *Plan) HasMesh() bool {
	if len(p.Regions) < 2 {
		return false
	}
	if p.Mesh == nil {
		return true
	}
	return *p.Mesh
}

// MeshPeersFor is what one region dials to reach the others: "region=wss://<its doorway>/mesh/ingress/tunnel",
// semicolon-separated, in the shape start-edge.sh reads. Empty when the plan declares no mesh, or when this is
// the only region — a deployment with one region has nobody to relay to, and an empty value there says that
// rather than pointing a region at itself.
//
// The doorway is the AGENT-facing name, because that is the door a sibling Edge dials; the peer's certificate
// is pinned to this deployment's own anchor and this Edge proves itself with the fleet identity it already
// holds, so nothing here needs material the plan does not have.
func (p *Plan) MeshPeersFor(region string) string {
	if !p.HasMesh() {
		return ""
	}
	region = strings.ToLower(strings.TrimSpace(region))
	peers := []string{}
	for _, r := range p.Regions {
		id := strings.ToLower(strings.TrimSpace(r.ID))
		if id == "" || id == region {
			continue
		}
		peers = append(peers, id+"=wss://"+p.PlaneNamesFor(id)["agents"]+"/mesh/ingress/tunnel")
	}
	sort.Strings(peers)
	return strings.Join(peers, ";")
}

// PlanRegion is one site.
type PlanRegion struct {
	ID string `json:"id"`
	// Entry is an optional legacy external TCP entry. Without it, the three Node doors are
	// independent agent endpoints; the installer does not provision a load balancer.
	Entry *PlanEntry `json:"entry,omitempty"`
	// Founding marks the region whose machine MINTS the deployment. Exactly one, and it is where the
	// consensus store lives; every other region joins it.
	Founding bool `json:"founding,omitempty"`
	// HoldsState is whether this region keeps a copy of the deployment's database, so leadership can move
	// here. A region without it has nothing to promote.
	HoldsState bool          `json:"holds_state,omitempty"`
	Machines   []PlanMachine `json:"machines"`
}

type PlanEntry struct {
	Mode              string   `json:"mode"`
	Targets           []string `json:"targets"`
	PreservesClientIP bool     `json:"preserves_client_ip"`
}

// PlanMachine is one host, and what it runs.
type PlanMachine struct {
	Name string `json:"name"`
	// Portal is the public, node-specific TLS name for OIDC start and callback.
	// Unlike the shared region entry, it must reach this Node's own Edge.
	// Dedicated multi-edge profiles instead derive one common Portal per Region;
	// an explicit value in that profile must equal the derived shared name.
	Portal string `json:"portal,omitempty"`
	// FailureDomain identifies an independently failing place, not a DSSE Region.
	FailureDomain string `json:"failure_domain,omitempty"`
	// Holds is what this machine runs: "control-plane", "edges", or both.
	//
	// ★★★ ONE MACHINE MAY HOLD BOTH, AND THE SMALLEST REDUNDANT DEPLOYMENT REQUIRES IT (2026-08-31). This was
	// a single string, and the canonical architecture's smallest shape that survives a failure is three
	// state-bearing regions — because a quorum needs three voting places, not three machines. One machine per
	// region, each holding the control plane and the Edges, is three machines and survives the loss of any
	// one; four machines in two regions survives nothing at the authority layer, because two voting places
	// cannot keep a quorum. So the shape with fewer machines is the one with redundancy, and it could not be
	// declared.
	//
	// ★ IT IS NOT A NEW SHAPE. The renderer has always had it — machineShape{holds: stateBearing, edges:true}
	// is the one-host reference. What was missing was the vocabulary to ask for it.
	//
	// A bare string is still accepted, so plans written before this keep working and keep their meaning.
	Holds heldComponents `json:"holds"`
	// Addresses are the host addresses its front door binds, in order. A Node
	// needs at least one address; one TCP doorway carries the planes by SNI.
	Addresses []string `json:"addresses"`
	// Reachable is the name the OTHER regions reach this machine by, and it is what TLS verifies.
	Reachable string `json:"reachable,omitempty"`
	// ReachableAddress is where that name is, from another region.
	//
	// ★★★ A NAME IS NOT ENOUGH FOR A CHECK THAT DOES NOT VERIFY ONE (2026-08-28, measured). The database door
	// speaks plain TCP to the other regions' members and its server lines carry no resolvers — deliberately,
	// because with a resolvers section haproxy will not hand one address to two servers in a backend. So the
	// name is resolved once, at start-up, inside a container, by whatever that machine's resolver is, and
	// that is a step this plan does not control:
	//
	//	Server pg_primary/pg-peer-1 is DOWN, reason: Socket error, ECONNRESET, check duration: 0ms
	//
	// while the very same name, asked from inside that container, answered "HTTP/1.0 200 OK". Given the
	// address instead, the peer came up and the one that really was not listening said "Connection refused" —
	// an honest answer where there had been a confusing one.
	//
	// So the address is prior information too. The doorway's peers still verify the NAME, and reach it here.
	ReachableAddress string `json:"reachable_address,omitempty"`
}

// LoadPlan reads a plan and refuses one that cannot describe a working deployment.
func LoadPlan(path string) (*Plan, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p Plan
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &p, nil
}

// Validate refuses what cannot work, naming what to fix. Every rule here is a failure this deployment has
// actually had.
func (p *Plan) Validate() error {
	if d := p.DataLayer; d != nil {
		if d.PostgresMajor != 18 {
			return fmt.Errorf("data_layer postgres_major must be 18 for this release candidate")
		}
		for _, image := range [][2]string{
			{"etcd_image", d.EtcdImage}, {"postgres_image", d.PostgresImage},
			{"postgres_tools_image", d.PostgresToolsImage},
		} {
			if !immutableImageRef(image[1]) {
				return fmt.Errorf("data_layer %s must be an immutable image@sha256: reference", image[0])
			}
		}
	}
	if a := p.Archive; a != nil {
		if strings.TrimSpace(a.Endpoint) == "" || strings.TrimSpace(a.Bucket) == "" {
			return fmt.Errorf("archive requires an external endpoint and bucket")
		}
		if strings.Contains(a.Endpoint, "://") {
			return fmt.Errorf("archive endpoint must be a host:port, with TLS implicit")
		}
		if _, _, err := net.SplitHostPort(a.Endpoint); err != nil {
			return fmt.Errorf("archive endpoint must be a host:port: %w", err)
		}
		if a.AuthMode != "static" && a.AuthMode != "iam" {
			return fmt.Errorf("archive auth_mode must be static or iam")
		}
		webhook, err := url.Parse(a.WebhookURL)
		if err != nil || webhook.Scheme != "https" || webhook.Hostname() == "" || webhook.User != nil || webhook.Fragment != "" || webhook.RawQuery != "" {
			return fmt.Errorf("archive webhook_url must be an HTTPS URL without credentials, query, or fragment")
		}
	}
	if p.Profile != "" && p.Profile != "one-region-three-nodes" && p.Profile != "three-regions-multi-edge" && !p.oneRegionMultiEdge() {
		return fmt.Errorf("unknown deployment profile %q", p.Profile)
	}
	if strings.TrimSpace(p.Deployment) == "" {
		return fmt.Errorf("the plan names no deployment — it is what every plane name and every per-region name hangs off")
	}
	if net.ParseIP(strings.TrimSpace(p.Deployment)) != nil {
		return fmt.Errorf("the deployment is named by an ADDRESS (%q). The planes are separated by NAME, and "+
			"a deployment addressed by number has no name to hang admin./agents./authority. off", p.Deployment)
	}
	if len(p.Regions) == 0 {
		return fmt.Errorf("the plan names no regions")
	}
	if p.SharedEntryMachine != "" {
		_, entry, found := p.find(p.SharedEntryMachine)
		if !declaredNodeMapProfile(p.Profile) || !found || !entry.Holds.has("control-plane") {
			return fmt.Errorf("shared_entry_machine must name a declared CP/L4 entrance")
		}
	}
	founding, seenRegion, seenMachine, seenAddress := 0, map[string]bool{}, map[string]bool{}, map[string]string{}
	for _, r := range p.Regions {
		id := strings.ToLower(strings.TrimSpace(r.ID))
		if !p.oneRegionThreeNodes() && r.Entry != nil {
			return fmt.Errorf("region %q declares an entry but no supported topology profile uses it", id)
		}
		if id == "" {
			return fmt.Errorf("a region has no id — it is the name devices use to CHOOSE a region and the name every record from it carries")
		}
		if seenRegion[id] {
			return fmt.Errorf("two regions are called %q; a device handed a map with two entries of one name cannot fail over between them", id)
		}
		seenRegion[id] = true
		if r.Founding {
			founding++
		}
		holds := map[string]int{}
		for _, m := range r.Machines {
			name := strings.ToLower(strings.TrimSpace(m.Name))
			if name == "" {
				return fmt.Errorf("region %q has a machine with no name", id)
			}
			if seenMachine[name] {
				return fmt.Errorf("two machines are called %q", name)
			}
			seenMachine[name] = true
			if len(m.Holds) == 0 {
				return fmt.Errorf("machine %q holds nothing; say what it runs — \"control-plane\", \"edges\", or both", name)
			}
			seenComponent := map[string]bool{}
			for _, c := range m.Holds {
				c = strings.ToLower(strings.TrimSpace(c))
				switch c {
				case "control-plane", "edges":
				default:
					return fmt.Errorf("machine %q holds %q; a machine runs \"control-plane\", \"edges\", or both", name, c)
				}
				if seenComponent[c] {
					return fmt.Errorf("machine %q names %q twice", name, c)
				}
				seenComponent[c] = true
				holds[c]++
			}
			// ★★★ A MACHINE THAT RUNS ONLY EDGES CARRIES NO DOORWAY (2026-09-02, the operator's decision).
			// Edges are the highest-load component and are scaled horizontally BEHIND the region's front
			// door — two of them in one place share a CPU, a kernel and a failure domain.
			//
			// Until today every machine holding "edges" was also a doorway, so the role this sentence
			// describes — a bare Edge node behind somebody else's load balancer — did not exist, and a region
			// could only be widened by adding whole doorways beside each other. Such a machine needs ONE
			// address: the doorway that fronts it reaches it there, and it publishes no 443 of its own.
			if !m.Holds.has("control-plane") && m.Holds.has("edges") {
				if len(m.Addresses) < 1 {
					return fmt.Errorf("machine %q names no address; the doorway that fronts it has to reach it "+
						"somewhere", name)
				}
			} else if len(m.Addresses) < 1 {
				// ★★★ ONE DOOR, ONE ADDRESS (2026-09-02). This used to demand TWO, because a doorway was a
				// pair and both doors were on 443. The pair is gone: a region whose door stops answering is a
				// region a device fails over out of, which is the answer this product already has and which
				// is measured at about thirty seconds. The old rule is what made "an Edge node behind the
				// region's door" impossible to declare, since every machine holding Edges had to be a door.
				return fmt.Errorf("machine %q names no address; its door has to bind somewhere", name)
			}
			for _, a := range m.Addresses {
				a = strings.TrimSpace(a)
				if a == "" {
					return fmt.Errorf("machine %q has an empty address", name)
				}
				if other, taken := seenAddress[a]; taken {
					return fmt.Errorf("%s is given to both %q and %q; a front door that shares an address with "+
						"another cannot also be on 443", a, other, name)
				}
				seenAddress[a] = name
			}
		}
		if holds["control-plane"] == 0 {
			return fmt.Errorf("region %q has no control-plane machine", id)
		}
		if holds["edges"] == 0 {
			return fmt.Errorf("region %q has no machine running Edges, so no device can reach it", id)
		}
	}
	// ★★★ MORE THAN ONE REGION MEANS EVERY MACHINE MUST BE REACHABLE FROM THE OTHERS, by a name AND at an
	// address. Without the name nothing verifies; without the address the resolution happens inside a
	// container at start-up and is not this plan's to decide.
	if len(p.Regions) > 1 {
		for _, r := range p.Regions {
			for _, m := range r.Machines {
				if strings.TrimSpace(m.Reachable) == "" {
					return fmt.Errorf("machine %q names no \"reachable\": with more than one region the other "+
						"regions address it by name, and TLS verifies that name", m.Name)
				}
				if strings.TrimSpace(m.ReachableAddress) == "" {
					return fmt.Errorf("machine %q names no \"reachable_address\": the doors that cross regions "+
						"resolve nothing at run time, so where %q is has to be decided here rather than "+
						"inside a container at start-up", m.Name, m.Reachable)
				}
			}
		}
	}
	if founding != 1 {
		return fmt.Errorf("%d regions are marked founding; exactly one mints the deployment, and every other "+
			"joins it — a second one mints a second anchor, and a device that MOVES between them meets an "+
			"issuer it has never heard of", founding)
	}
	if p.oneRegionThreeNodes() {
		if len(p.Regions) != 1 || len(p.Regions[0].Machines) != 3 {
			return fmt.Errorf("profile one-region-three-nodes requires exactly one DSSE region with three machines")
		}
		if !validPlanDNSName(p.Deployment) || !validPlanDNSLabel(p.Regions[0].ID) {
			return fmt.Errorf("profile one-region-three-nodes requires DNS-safe deployment and region names")
		}
		domains := map[string]bool{}
		portals := map[string]bool{}
		peerNames := map[string]bool{}
		adminNames := map[string]bool{}
		for _, target := range p.nodeAdminTargets() {
			name := target.Label + ".admin." + strings.ToLower(strings.TrimSpace(p.Deployment))
			if adminNames[name] {
				return fmt.Errorf("two machines generate the same admin name %q", name)
			}
			adminNames[name] = true
		}
		for _, alias := range p.Names {
			if adminNames[strings.ToLower(strings.TrimSpace(alias))] {
				return fmt.Errorf("deployment alias shadows an owned admin name")
			}
		}
		nodeAddressOwners := map[string]string{}
		for _, m := range p.Regions[0].Machines {
			if adminNames[strings.ToLower(strings.TrimSpace(m.Reachable))] {
				return fmt.Errorf("machine %q reachable name shadows an owned admin name", m.Name)
			}
			peer := strings.ToLower(strings.TrimSpace(m.Reachable))
			if peerNames[peer] {
				return fmt.Errorf("two machines share reachable name %q", peer)
			}
			peerNames[peer] = true
		}
		entry := p.Regions[0].Entry
		targets := map[string]bool{}
		if entry != nil {
			if entry.Mode != "tcp-pass-through" || !entry.PreservesClientIP || len(entry.Targets) != 3 {
				return fmt.Errorf("profile one-region-three-nodes entry must be TCP pass-through with three targets and preserved client IP")
			}
			for _, target := range entry.Targets {
				target = strings.ToLower(strings.TrimSpace(target))
				if targets[target] {
					return fmt.Errorf("entry target %q is duplicated", target)
				}
				targets[target] = true
			}
		}
		for _, m := range p.Regions[0].Machines {
			portal := strings.ToLower(strings.TrimSpace(m.Portal))
			if adminNames[portal] {
				return fmt.Errorf("machine %q portal shadows an owned admin name", m.Name)
			}
			for _, component := range []string{"edge-a", "control-plane-a"} {
				label := nodeAdminLabel(p.Regions[0].ID, m.Name, component)
				if !validPlanDNSLabel(label) || !validPlanDNSName(label+".admin."+p.Deployment) {
					return fmt.Errorf("machine %q generates an invalid admin name %q; shorten the region or machine name", m.Name, label)
				}
			}
			if !validPlanDNSName(portal) || portals[portal] {
				return fmt.Errorf("machine %q needs a distinct DNS-safe portal name for its own Edge", m.Name)
			}
			if peerNames[portal] {
				return fmt.Errorf("machine %q portal name must differ from every peer-reachable name", m.Name)
			}
			portals[portal] = true
			for _, plane := range p.PlaneNamesFor(p.Regions[0].ID) {
				if strings.EqualFold(portal, plane) {
					return fmt.Errorf("machine %q portal name cannot equal a shared region plane", m.Name)
				}
			}
			if !validPlanDNSLabel(m.Name) || !validPlanDNSName(m.Reachable) {
				return fmt.Errorf("machine %q needs DNS-safe name and reachable TLS name", m.Name)
			}
			if entry != nil && !targets[strings.ToLower(strings.TrimSpace(m.Name))] {
				return fmt.Errorf("entry omits machine %q", m.Name)
			}
			if !m.Holds.has("control-plane") || !m.Holds.has("edges") {
				return fmt.Errorf("machine %q must hold both control-plane and edges in profile one-region-three-nodes", m.Name)
			}
			if len(m.Addresses) == 0 || net.ParseIP(strings.TrimSpace(m.Addresses[0])).To4() == nil ||
				net.ParseIP(strings.TrimSpace(m.ReachableAddress)).To4() == nil {
				return fmt.Errorf("machine %q needs IPv4 local and reachable peer addresses; IPv6-only peer wiring is not yet supported", m.Name)
			}
			local, reachable := strings.TrimSpace(m.Addresses[0]), strings.TrimSpace(m.ReachableAddress)
			for _, address := range []string{local, reachable} {
				if owner := nodeAddressOwners[address]; owner != "" && owner != m.Name {
					return fmt.Errorf("machine %q must have distinct local and peer-reachable Node addresses", m.Name)
				}
				nodeAddressOwners[address] = m.Name
			}
			d := strings.ToLower(strings.TrimSpace(m.FailureDomain))
			if d == "" || domains[d] {
				return fmt.Errorf("machine %q needs a distinct failure_domain", m.Name)
			}
			domains[d] = true
		}
	}
	if p.oneRegionMultiEdge() {
		if err := p.validateOneRegionMultiEdge(); err != nil {
			return err
		}
	}
	if p.threeRegionsMultiEdge() {
		if err := p.validateThreeRegionNames(); err != nil {
			return err
		}
		if len(p.Regions) != 3 {
			return fmt.Errorf("profile three-regions-multi-edge requires exactly three DSSE regions")
		}
		for _, r := range p.Regions {
			if !r.HoldsState {
				return fmt.Errorf("region %q must hold a consensus vote and database member on its control-plane node", r.ID)
			}
			controlPlanes, edges := 0, 0
			domains := map[string]bool{}
			for _, m := range r.Machines {
				domain := strings.ToLower(strings.TrimSpace(m.FailureDomain))
				if domain == "" || domains[domain] {
					return fmt.Errorf("machine %q needs a distinct failure_domain within region %q", m.Name, r.ID)
				}
				domains[domain] = true
				switch {
				case m.Holds.has("control-plane") && !m.Holds.has("edges"):
					controlPlanes++
				case m.Holds.has("edges") && !m.Holds.has("control-plane"):
					edges++
				default:
					return fmt.Errorf("machine %q must be either the dedicated control-plane/L4 door or a dedicated Edge", m.Name)
				}
			}
			if controlPlanes != 1 || edges < 2 {
				return fmt.Errorf("region %q needs exactly one control-plane/L4 door and at least two dedicated Edge nodes; got %d and %d", r.ID, controlPlanes, edges)
			}
		}
	}
	return nil
}

func (p *Plan) oneRegionThreeNodes() bool   { return p.Profile == "one-region-three-nodes" }
func (p *Plan) threeRegionsMultiEdge() bool { return p.Profile == "three-regions-multi-edge" }

func validPlanDNSName(name string) bool {
	if name == "" || len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if !validPlanDNSLabel(label) {
			return false
		}
	}
	return true
}

func validPlanDNSLabel(label string) bool {
	if len(label) == 0 || len(label) > 63 {
		return false
	}
	for i, c := range label {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
			continue
		}
		if c == '-' && i > 0 && i < len(label)-1 {
			continue
		}
		return false
	}
	return true
}

func storeMemberNameForMachine(m PlanMachine) string {
	return "dsse-store-" + strings.ToLower(strings.TrimSpace(m.Name))
}

func storeMemberPeerURLForMachine(m PlanMachine) string {
	return fmt.Sprintf("https://%s:%d", m.reachableName(), planEtcdPeerPortA)
}

// ---- what the plan means -----------------------------------------------------

// PlaneNamesFor is the five plane names of one region: the same five the deployment presents, under a name
// that says WHICH region. Both are needed and they are not interchangeable — agents.<deployment> is answered
// by every site with its own doorway, which is what makes a client reach the region it is in, and is exactly
// why it cannot name the other one.
func (p *Plan) PlaneNamesFor(region string) map[string]string {
	region = strings.ToLower(strings.TrimSpace(region))
	out := map[string]string{}
	for _, plane := range []string{"agents", "recovery", "admin", "authority", "console"} {
		out[plane] = plane + "." + region + "." + p.Deployment
	}
	return out
}

// CertificateNames is every name the deployment transport leaf must carry.
// A three-Region browser Portal uses a separate Region-scoped leaf instead.
func (p *Plan) CertificateNames() []string {
	names := []string{p.Deployment}
	if declaredNodeMapProfile(p.Profile) {
		for _, target := range p.nodeAdminTargets() {
			names = append(names, target.Label+".admin."+p.Deployment)
		}
	}
	names = append(names, p.Names...)
	for _, r := range p.Regions {
		for _, n := range p.PlaneNamesFor(r.ID) {
			names = append(names, n)
		}
	}
	for _, m := range p.machines() {
		if m.Reachable != "" {
			names = append(names, m.Reachable)
			if p.oneRegionThreeNodes() {
				names = append(names, "agents."+strings.ToLower(strings.TrimSpace(m.Reachable)))
			}
		}
		// The 3-Region profile serves each browser Portal through a separate,
		// Region-scoped leaf. Its transport fallback must not authenticate a
		// Portal name, including one owned by a different Region.
		if m.Portal != "" && p.Profile != "three-regions-multi-edge" {
			names = append(names, m.Portal)
		}
		if p.dedicatedMultiEdge() && p.Profile != "three-regions-multi-edge" && m.Holds.has("edges") {
			names = append(names, p.edgePortalName(m))
		}
	}
	return dedupeSorted(names, p.Deployment)
}

// BrowserPortalNames are served with a separate browser certificate. A management
// leaf must not also cover these names: an HTTP/2 browser may otherwise reuse an
// existing Console TLS connection for a Portal request on the same entry IP.
func (p *Plan) BrowserPortalNames() []string {
	names := []string{}
	for _, m := range p.machines() {
		if m.Portal != "" {
			names = append(names, m.Portal)
		}
		if p.dedicatedMultiEdge() && m.Holds.has("edges") {
			names = append(names, p.edgePortalName(m))
		}
	}
	if len(names) == 0 {
		return nil
	}
	return dedupeSorted(names, names[0])
}

// RegionEndpoints is the same signed-catalog source on every Edge. In the 1x3 profile each
// Node has its own DNS name (agents.<node-reachable-name>) and public address supplied by
// the operator's DNS/hosts; the TLS name is on the deployment certificate. All three doors
// route that SNI to the same Edge fleet. Older one-door-per-region plans are unchanged.
func (p *Plan) RegionEndpoints() string {
	entries := []string{}
	for _, r := range p.Regions {
		id := strings.ToLower(strings.TrimSpace(r.ID))
		if p.oneRegionThreeNodes() {
			for _, m := range r.Machines {
				entries = append(entries, id+"=https://agents."+strings.ToLower(strings.TrimSpace(m.Reachable)))
			}
		} else {
			entries = append(entries, id+"=https://"+p.PlaneNamesFor(id)["agents"])
		}
	}
	sort.Strings(entries)
	return strings.Join(entries, ";")
}

func (p *Plan) machines() []PlanMachine {
	out := []PlanMachine{}
	for _, r := range p.Regions {
		out = append(out, r.Machines...)
	}
	return out
}

func (p *Plan) foundingRegion() PlanRegion {
	for _, r := range p.Regions {
		if r.Founding {
			return r
		}
	}
	return PlanRegion{}
}

func (r PlanRegion) controlPlane() PlanMachine {
	for _, m := range r.Machines {
		if m.Holds.has("control-plane") {
			return m
		}
	}
	return PlanMachine{}
}

// reachableAt is the ADDRESS another region connects to. Falls back to the name, then to the machine's own
// first address — right for a deployment on one private network, and refused above for one that is not.
func (m PlanMachine) reachableAt() string {
	if a := strings.TrimSpace(m.ReachableAddress); a != "" {
		return a
	}
	return m.reachableName()
}

// reachableName is how the other regions address this machine. Falls back to its first address, which is
// right for a deployment on one private network and wrong across sites — so the plan says so rather than
// pretending either is always correct.
func (m PlanMachine) reachableName() string {
	if n := strings.TrimSpace(m.Reachable); n != "" {
		return n
	}
	if len(m.Addresses) > 0 {
		return strings.TrimSpace(m.Addresses[0])
	}
	return ""
}

func dedupeSorted(in []string, first string) []string {
	seen := map[string]bool{first: true}
	out := []string{first}
	rest := []string{}
	for _, n := range in {
		n = strings.TrimSpace(n)
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		rest = append(rest, n)
	}
	sort.Strings(rest)
	return append(out, rest...)
}

// heldComponents is what one machine runs. It accepts "edges" and ["control-plane", "edges"] alike, because a
// plan written when a machine was one component must keep meaning what it meant.
type heldComponents []string

func (h *heldComponents) UnmarshalJSON(b []byte) error {
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*h = heldComponents{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return fmt.Errorf("\"holds\" must be a component name or a list of them, e.g. \"edges\" or [\"control-plane\", \"edges\"]")
	}
	*h = many
	return nil
}

// MarshalJSON writes a single component back as the bare string it arrived as, so a plan this program reads
// and writes is the plan the operator wrote.
func (h heldComponents) MarshalJSON() ([]byte, error) {
	if len(h) == 1 {
		return json.Marshal(h[0])
	}
	return json.Marshal([]string(h))
}

// has reports whether this machine runs the named component.
func (h heldComponents) has(component string) bool {
	for _, c := range h {
		if strings.EqualFold(strings.TrimSpace(c), component) {
			return true
		}
	}
	return false
}

func (h heldComponents) String() string {
	out := make([]string, 0, len(h))
	for _, c := range h {
		out = append(out, strings.ToLower(strings.TrimSpace(c)))
	}
	return strings.Join(out, "+")
}

// stateBearingRegions is every region that keeps a copy of the deployment's database, in install order: the
// founding one first, because it is the one that mints and the one the others join.
//
// ★ IT IS ALSO THE ORDER MEMBERSHIP GROWS IN. The founding member starts a cluster of one; each later region
// is added to it. So "the cluster as this machine will find it" is this list up to and including itself.
func (p *Plan) stateBearingRegions() []PlanRegion {
	out := []PlanRegion{}
	for _, r := range p.Regions {
		// ★ THE FOUNDING REGION ALWAYS HOLDS STATE: it is where the database is minted, so holds_state is
		// not something it has to declare.
		if r.Founding {
			out = append(out, r)
		}
	}
	for _, r := range p.Regions {
		if !r.Founding && r.HoldsState {
			out = append(out, r)
		}
	}
	return out
}

// storeMemberName is what a region's consensus-store member calls itself in the cluster.
//
// ★ ONE DEFINITION, BECAUSE TWO PLACES NEED THE SAME ANSWER. The machine's environment writes it as the
// member's own name and the install order names it in `member add`; built separately they drift, and the
// symptom is a member added under a name no member answers to.
func storeMemberName(regionID string) string {
	return "dsse-store-" + strings.ToLower(strings.TrimSpace(regionID))
}

// storeMemberPeerURL is where that member's peers reach it. Peers gossip on their own port, which is not the
// one clients use.
func (p *Plan) storeMemberPeerURL(r PlanRegion) string {
	// ★ https, ALWAYS. This URL exists only in a deployment whose store spans regions, and there the peers
	// talk across whatever is between those regions.
	return fmt.Sprintf("https://%s:%d", r.controlPlane().reachableName(), planEtcdPeerPortA)
}
