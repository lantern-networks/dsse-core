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
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
)

// Plan is the whole deployment, as decided before it exists.
type Plan struct {
	// Deployment is the name everything hangs off: the planes, the per-region names, the node wildcard.
	Deployment string `json:"deployment"`
	// Names are any other names this deployment answers on. The first entry of the certificate is Deployment.
	Names []string `json:"names,omitempty"`
	// Publisher is the signing identity that builds the agent packages this deployment's devices install.
	// Without it the configuration this deployment publishes is one the endpoint installer refuses.
	Publisher string `json:"agent_publisher,omitempty"`
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
	// Founding marks the region whose machine MINTS the deployment. Exactly one, and it is where the
	// consensus store lives; every other region joins it.
	Founding bool `json:"founding,omitempty"`
	// HoldsState is whether this region keeps a copy of the deployment's database, so leadership can move
	// here. A region without it has nothing to promote.
	HoldsState bool          `json:"holds_state,omitempty"`
	Machines   []PlanMachine `json:"machines"`
}

// PlanMachine is one host, and what it runs.
type PlanMachine struct {
	Name string `json:"name"`
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
	// Addresses are the host addresses its front doors bind, in order. A doorway is a PAIR and every mouth is
	// 443, so two addresses are needed — a host has one 443 per address.
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
	founding, seenRegion, seenMachine, seenAddress := 0, map[string]bool{}, map[string]bool{}, map[string]string{}
	for _, r := range p.Regions {
		id := strings.ToLower(strings.TrimSpace(r.ID))
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
	return nil
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

// CertificateNames is every name this deployment's leaves must carry.
func (p *Plan) CertificateNames() []string {
	names := []string{p.Deployment}
	names = append(names, p.Names...)
	for _, r := range p.Regions {
		for _, n := range p.PlaneNamesFor(r.ID) {
			names = append(names, n)
		}
	}
	for _, m := range p.machines() {
		if m.Reachable != "" {
			names = append(names, m.Reachable)
		}
	}
	return dedupeSorted(names, p.Deployment)
}

// RegionEndpoints is the map every Edge in every region is handed, identically: one entry per region, each
// naming that region's AGENT plane, which is where a device goes.
func (p *Plan) RegionEndpoints() string {
	entries := []string{}
	for _, r := range p.Regions {
		id := strings.ToLower(strings.TrimSpace(r.ID))
		entries = append(entries, id+"=https://"+p.PlaneNamesFor(id)["agents"])
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
