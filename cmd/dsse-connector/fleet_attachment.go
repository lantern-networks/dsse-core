package main

// fleet_attachment.go — one connector, a tunnel on every Edge node behind the door.
//
// ★★★ THE OPERATOR'S RULE: "a connector must not be bound to a single Edge; like an agent it fails over
// between regions and connects to the Edge FLEET." Authentication reached the fleet first (any Edge will
// accept this connector's certificate); the DATA PATH did not, and that is where it shows.
//
// A region's Edges share one L4 front door. A single tunnel therefore lands on ONE node, and only that node
// can bridge a flow into the connector — every sibling answers "fronts this destination but has no live
// tunnel". Measured on the deployment the installer generates, two nodes per region:
//
//   - within the region: 10 probes, 5 served, 5 refused, alternating exactly with the door's leastconn
//   - across regions:    0 of 8 served — the mesh link is itself pinned to one node of the far fleet, and it
//                        was not the node holding the connector, so every relayed flow failed
//
// Nothing reported this. The connector logged one healthy tunnel, both Edges logged themselves healthy, and
// the private estate behind the connector was reachable half the time.
//
// So the connector keeps dialling the SAME door until it holds a tunnel on every node behind it. It never
// needs the fleet's size or its members' addresses: the Edge names the node on the handshake, and the door's
// own balancing hands out a different one each time a connection is already held. When landings stop being
// new, the connector stops growing; a slow re-probe picks up nodes added later.
//
// ★ THE DOOR IS STILL ONE ADDRESS. Nothing here reaches a node directly — that would be an inside address a
// customer's connector must never be given, and it would defeat the door's own health checking.

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	// connectorFleetMaxNodes is a runaway stop, never a target. A connector that somehow keeps seeing new node
	// names (a door that rotates identities, a fleet churning) must not open tunnels without bound.
	connectorFleetMaxNodes = 16
	// connectorFleetDuplicateGiveUp is how many consecutive landings on nodes this connector ALREADY holds
	// count as "the fleet is covered". One is too few: a door balancing by least-connections can hand out the
	// same node twice in a row while a third sits idle.
	connectorFleetDuplicateGiveUp = 4
	// connectorFleetShortRecheck is the cadence used while this connector is KNOWN to be short of its region's
	// fleet — measured against a denominator the deployment gave it, so "short" is a fact, not a guess.
	//
	// ★★★ BEING SHORT IS AN OUTAGE FOR PART OF THE FLEET, AND IT WAS SILENT (2026-08-26). A member of an HA
	// pair sat on one of its region's two Edge nodes for TWELVE MINUTES without a word: the search worker was
	// dialling and being refused, and every refusal is deliberately quiet because it is the normal answer while
	// walking a door. Quiet-per-refusal is right; quiet-per-outage is not — for anything arriving on the other
	// node, everything behind that connector was unreachable the whole time.
	connectorFleetShortRecheck = 30 * time.Second
	// connectorFleetRecheck is how often a single extra probe goes out to notice a node ADDED to the fleet
	// since coverage settled. Rare on purpose: this is a scale-out event, not a failure mode, and a probe that
	// lands on a held node costs a connect and a close.
	connectorFleetRecheck = 5 * time.Minute
	// connectorFleetDuplicateBackoff paces the retries while a connector is still spreading over the fleet.
	connectorFleetDuplicateBackoff = 2 * time.Second
)

// connectorFleetAttachments is which Edge nodes this connector holds a tunnel on right now. The zero value is
// not usable; see newConnectorFleetAttachments.
type connectorFleetAttachments struct {
	mu sync.Mutex
	// siblingsRelay is what the Edge said on the handshake: the other nodes of its region relay to whichever
	// one holds this connector. See coverage().
	siblingsRelay bool
	// held maps an Edge node to the REGION this connector reached it through.
	//
	// ★★★ A CONNECTOR LIVES IN ONE REGION AT A TIME, AND WITHOUT THE REGION HERE IT DID NOT (2026-08-26,
	// measured on a real failover). Its home region came back while the connector was working in the next one,
	// a worker dialled through the returning door, and the connector ended up holding tunnels in BOTH — which
	// its own coverage line reported as "all 3 of the region's 2". Two things then go wrong: the nodes
	// terminating those tunnels each tell the authority a different region, so "where is this connector"
	// flaps, and every Edge holding no tunnel of its own follows whichever answer it last saw. Counting
	// coverage against a fleet size that belongs to ONE region while the held set spans two is the arithmetic
	// that hid it.
	held map[string]attachmentOwner
	// seen is every node this connector has ever attached to, so a RECONNECT to a node it already knows does
	// not start another search. Only a genuinely new node means there may be more of the fleet to find.
	seen      map[string]bool
	fleetSize int
	workers   int
	onNewNode func(node string)
	// region is the region this connector currently belongs to — the door its primary worker is on. Coverage
	// is counted within it, and an attachment made through any other region is abandoned.
	region string
	// nextOwner numbers attachments so a worker can only ever release its OWN.
	//
	// ★★★ A DISPLACED WORKER USED TO DELETE THE CLAIM OF THE ONE THAT DISPLACED IT (2026-08-26). The map was
	// keyed by node alone, so when a sibling probe landed on a node this connector already held — the race the
	// declaration cannot close, because the declaration is a snapshot taken before the dial — the Edge replaced
	// the session, the displaced worker's deferred release ran, and it removed the LIVE attachment its
	// displacer had just made. The connector then believed it held one fewer node than it did.
	nextOwner int64
}

// attachmentOwner is who holds a node right now: which region it was reached through, and which worker.
type attachmentOwner struct {
	region  string
	id      int64
	abandon func()
}

func newConnectorFleetAttachments() *connectorFleetAttachments {
	return &connectorFleetAttachments{held: map[string]attachmentOwner{}, seen: map[string]bool{}}
}

// claim records that this connector now holds a tunnel on node, reporting whether the claim is NEW. A node
// that is already held is refused, so the caller drops the duplicate connection and dials again — that is how
// the door is walked.
//
// ★ AN UNNAMED NODE IS ALWAYS CLAIMABLE. An Edge too old to name itself on the handshake sends no node header.
// Refusing those would leave a connector with no tunnel at all against an older fleet, which is a far worse
// failure than holding two tunnels on one node, so an empty name never collides.
func (a *connectorFleetAttachments) claim(node, region string, abandon func()) (int64, bool) {
	node, region = strings.TrimSpace(node), strings.TrimSpace(region)
	if node == "" {
		return 0, true
	}
	a.mu.Lock()
	if _, taken := a.held[node]; taken {
		a.mu.Unlock()
		return 0, false
	}
	a.nextOwner++
	id := a.nextOwner
	a.held[node] = attachmentOwner{region: region, id: id, abandon: abandon}
	first := !a.seen[node]
	a.seen[node] = true
	notify := a.onNewNode
	a.mu.Unlock()
	if first && notify != nil {
		notify(node)
	}
	return id, true
}

// release gives up a node, but only if this worker is still the one holding it. See nextOwner.
func (a *connectorFleetAttachments) release(node string, id int64) {
	node = strings.TrimSpace(node)
	if node == "" {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if owner, ok := a.held[node]; ok && owner.id == id {
		delete(a.held, node)
	}
}

// stillHeldByAnother reports that this worker's tunnel to node was replaced by a SIBLING worker of the same
// connector — the Edge keeps one session per connector, so a probe that lands on a node already held ends the
// tunnel that was there.
//
// ★★★ THAT IS NOT EVIDENCE ABOUT THE REGION, AND IT CAUSED A FALSE FAILOVER (2026-08-26, measured). The
// primary's tunnel was displaced two seconds after it formed, "did not hold", and the connector failed over to
// the next region — then out of that one as well, cycling all the way round the door list in two seconds
// because of its own probe.
func (a *connectorFleetAttachments) stillHeldByAnother(node string, id int64) bool {
	node = strings.TrimSpace(node)
	if node == "" {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	owner, ok := a.held[node]
	return ok && owner.id != id
}

// belongsTo sets the region this connector currently lives in and lets go of every attachment made through a
// different one.
//
// ★★★ THE RETURNING HOME REGION IS THE CASE THAT NEEDS THIS. A connector that failed over is working in the
// second region when the first comes back; a worker dials the returning door and now the connector is in two
// places. Each node terminating a tunnel tells the authority a different region, so the deployment's answer to
// "where is this connector" flaps, and every Edge that holds no tunnel of its own follows whichever it saw
// last. Letting go is what makes the answer single.
func (a *connectorFleetAttachments) belongsTo(region string) []string {
	region = strings.TrimSpace(region)
	if region == "" {
		return nil
	}
	a.mu.Lock()
	if a.region == region {
		a.mu.Unlock()
		return nil
	}
	a.region = region
	letGo := []string{}
	cancels := []func(){}
	for node, owner := range a.held {
		if owner.region != "" && !strings.EqualFold(owner.region, region) {
			letGo = append(letGo, node)
			if owner.abandon != nil {
				cancels = append(cancels, owner.abandon)
			}
		}
	}
	a.mu.Unlock()
	for _, cancel := range cancels {
		cancel()
	}
	sort.Strings(letGo)
	return letGo
}

// letGoOfEverything ends every attachment this connector holds, so its workers re-dial. Used when the
// connector is deliberately moving back to the operator's first door: nothing else ends a tunnel that is
// working, which is exactly why a connector that failed over never went home.
func (a *connectorFleetAttachments) letGoOfEverything() []string {
	a.mu.Lock()
	letGo := make([]string, 0, len(a.held))
	cancels := make([]func(), 0, len(a.held))
	for node, owner := range a.held {
		letGo = append(letGo, node)
		if owner.abandon != nil {
			cancels = append(cancels, owner.abandon)
		}
	}
	a.mu.Unlock()
	for _, cancel := range cancels {
		cancel()
	}
	sort.Strings(letGo)
	return letGo
}

// noteSiblingsRelay records what the node said on the handshake: that the other Edge nodes of its region will
// relay to whichever one holds this connector. Sticky once true — a single node that cannot promise it does
// not unsay what another has said, and the connector is on only one node at a time anyway.
func (a *connectorFleetAttachments) noteSiblingsRelay(relay bool) {
	if !relay {
		return
	}
	a.mu.Lock()
	a.siblingsRelay = true
	a.mu.Unlock()
}

// noteFleetSize records the denominator the Edge advertised: how many nodes its region is known to have.
// Zero (or absent) means the deployment has not told this connector, and unknown must stay unknown.
func (a *connectorFleetAttachments) noteFleetSize(n int) {
	if n <= 0 {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.fleetSize = n
}

// coverage says how much of the fleet this connector is on, in the words the reader needs. It NEVER claims
// completeness from a number it was not given: an unknown denominator is said out loud, because "3 nodes" and
// "3 of 3 nodes" are different facts and only one of them means everything behind this connector is reachable
// from anywhere in the region.
func (a *connectorFleetAttachments) coverage() string {
	a.mu.Lock()
	held, size, relay := a.heldHereLocked(), a.fleetSize, a.siblingsRelay
	nodes := make([]string, 0, len(a.held))
	for node, owner := range a.held {
		if a.region == "" || owner.region == "" || strings.EqualFold(owner.region, a.region) {
			nodes = append(nodes, node)
		}
	}
	a.mu.Unlock()
	sort.Strings(nodes)
	switch {
	case size <= 0:
		return fmt.Sprintf("%d Edge node(s) %v — this deployment has not said how many its region has, so whether that is all of them is unknown", held, nodes)
	case held >= size:
		// ★ "THE DEPLOYMENT KNOWS OF", NOT "THERE ARE". The denominator is how many Edge nodes of this region
		// have REPORTED to the control plane recently — a floor, not a census. A node that has never reported
		// is not in it, and it still accepts flows for everything this connector fronts. Saying "all 2 of 2"
		// would promise a completeness nobody measured, which is the promise this whole line exists to stop
		// the deployment making.
		return fmt.Sprintf("all %d of the %d Edge node(s) the deployment knows of here %v", held, size, nodes)
	default:
		// ★★★ THE CONSEQUENCE IS THE DEPLOYMENT'S TO STATE, NOT THIS CONNECTOR'S (2026-09-02). A region's door
		// balances by source address with a consistent hash, so a connector dialling from one address lands on
		// the same node every time and CANNOT spread over its region — this line was printed every thirty
		// seconds, for ever, on a healthy deployment. And its second half stopped being true when the Edges
		// learned to relay to the sibling that holds a connector: the flow arrives on the other node and gets
		// there anyway. A warning that repeats a hole somebody has closed is how a log stops being read.
		//
		// The node says on the handshake whether its siblings relay. Absent means it cannot promise that, and
		// then the original sentence is right.
		if relay {
			return fmt.Sprintf("%d of the %d Edge node(s) the deployment knows of here %v, and the others relay to it — a flow arriving on one of them still reaches what is behind this connector", held, size, nodes)
		}
		return fmt.Sprintf("only %d of the %d Edge node(s) the deployment knows of here %v — a flow arriving on one of the others cannot reach anything behind this connector", held, size, nodes)
	}
}

// searchIsDone reports whether this connector should stop looking for more of the fleet.
//
// ★★★ A KNOWN DENOMINATOR OVERRULES THE HEURISTIC (2026-08-26, caught by the denominator on its first live
// run). "Four landings in a row on nodes I already hold" is a guess at completeness for a connector that has
// not been told how many nodes there are — and a door balancing by least-connections can hand out the same node
// four times while a sibling sits idle. It did: the search retired and said, in the same line, that it was on
// ONLY ONE OF TWO. A report that says it is not covered and a search that has stopped cannot both be right.
// Where the deployment has said how many nodes the region has, that number decides; the guess is used only
// where it is the sole thing available.
func (a *connectorFleetAttachments) searchIsDone(duplicates int) bool {
	a.mu.Lock()
	held, size := a.heldHereLocked(), a.fleetSize
	a.mu.Unlock()
	if size > 0 {
		return held >= size
	}
	return duplicates >= connectorFleetDuplicateGiveUp
}

// covered reports whether this connector is on every node its region is KNOWN to have. False when the
// deployment has not said, because an unmeasured fleet cannot be declared covered.
func (a *connectorFleetAttachments) covered() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.fleetSize > 0 && a.heldHereLocked() >= a.fleetSize
}

// heldHereLocked counts the attachments that belong to the region this connector is in. The fleet size the
// Edge advertises is ONE region's, so counting a held set that spans two against it is how "all 3 of the
// region's 2" got printed.
func (a *connectorFleetAttachments) heldHereLocked() int {
	n := 0
	for _, owner := range a.held {
		if a.region == "" || owner.region == "" || strings.EqualFold(owner.region, a.region) {
			n++
		}
	}
	return n
}

// knowsItsFleetSize reports whether a denominator has ever arrived. Without one there is nothing to be short
// OF, so the impatient cadence and the repeated warning both stay off.
func (a *connectorFleetAttachments) knowsItsFleetSize() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.fleetSize > 0
}

// nodes is the sorted set of Edge nodes currently held, for logging. Sorted so the line is stable.
func (a *connectorFleetAttachments) nodes() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]string, 0, len(a.held))
	for node := range a.held {
		out = append(out, node)
	}
	sort.Strings(out)
	return out
}

// addWorker reserves a worker slot, reporting false when the runaway stop is reached.
func (a *connectorFleetAttachments) addWorker() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.workers >= connectorFleetMaxNodes {
		return false
	}
	a.workers++
	return true
}

func (a *connectorFleetAttachments) dropWorker() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.workers > 0 {
		a.workers--
	}
}

// spreadConnectorOverTheFleet runs this connector's attachments: one primary worker that owns door selection,
// and additional workers dialled through the SAME door until every node behind it holds a tunnel.
//
// Growth is driven by success, not by a configured number: each worker that lands on a node nobody has yet
// starts one more worker to look for the next. The extra worker beyond the last node keeps meeting nodes
// already held and retires, so a fleet of N settles at N attachments plus the retiring probe. Nothing here
// knows N — the deployment never has to tell a customer's connector how many Edges it runs.
func spreadConnectorOverTheFleet(ctx context.Context, doors *connectorEndpoints, connectorID, connectorSecret, privateBaseURL string, tcpRoutes []connectorTCPRoute, tcpDialer connectorTCPConnectionDialer, tlsConfig *tls.Config) {
	attachments := newConnectorFleetAttachments()
	// A door change must reach the tunnels that are already held, or the decision is only a log line — see
	// connectorEndpoints.onMove.
	doors.SetOnMove(func() {
		if letGo := attachments.letGoOfEverything(); len(letGo) > 0 {
			log.Printf("connector let go of %v because its door changed", letGo)
		}
	})
	var start func(primary bool)
	start = func(primary bool) {
		if !attachments.addWorker() {
			return
		}
		go func() {
			if !primary {
				defer attachments.dropWorker()
			}
			connectTunnelLoop(ctx, doors, attachments, primary, connectorID, connectorSecret, privateBaseURL, tcpRoutes, tcpDialer, tlsConfig)
		}()
	}
	attachments.onNewNode = func(node string) {
		log.Printf("connector reached a new Edge node %s; looking for the next one behind the same door", node)
		start(false)
	}
	start(true)

	// ★ AND IT GOES HOME WHEN IT CAN. Nothing else ever ends a tunnel that is working, so without this a
	// connector that failed over stays in the second region for ever — see goes_home_when_it_can.go.
	go watchForHome(ctx, doors, attachments, connectorID, connectorSecret, tlsConfig)

	// ★ A FLEET GROWS AFTER A CONNECTOR HAS SETTLED. Scaling a region out adds a node that accepts flows for
	// everything this connector fronts and has no tunnel to it — the same half-reachable estate, arriving
	// silently later. One probe every few minutes finds it; if the fleet has not changed the probe meets a node
	// already held and retires, which costs a connect and a close.
	go func() {
		for {
			// Impatient while short of a fleet whose size is known; slow once covered, where the only thing
			// left to find is a node added later.
			wait := connectorFleetRecheck
			short := attachments.knowsItsFleetSize() && !attachments.covered()
			if short {
				wait = connectorFleetShortRecheck
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(wait):
			}
			if attachments.knowsItsFleetSize() && !attachments.covered() {
				// Say it every time, for as long as it is true. A connector that is short is an outage for
				// whatever arrives on the nodes it is missing, and the deployment has no other way to hear it.
				log.Printf("connector is still %s", attachments.coverage())
			}
			start(false)
		}
	}()
}
