package main

import (
	"log"
	"strings"
	"sync"
)

// region_failover.go — a connector reaches the FLEET, and a fleet has more than one door.
//
// ★★★ THE OPERATOR'S INSTRUCTION (2026-08-26): "a connector, like an agent, does region failover and connects
// to the Edge fleet, so it must not be bound to a single Edge." It had no failover at all: one --edge-url, used
// for registration, heartbeats, the tunnel and the route poll, and when that address stopped answering the
// connector retried it for ever. Everything behind that connector was unreachable for as long as one region
// was — in a deployment that exists in two precisely so that it need not be.
//
// The shape is the agent's, deliberately: an ORDERED list, tried from the top, in the same "region=URL" form
// the install profile and -region-endpoints-seed already carry. One vocabulary for "where this deployment
// answers", so an operator who has learned it once has learned it everywhere.
//
// ★ FAILING BACK MATTERS AS MUCH AS FAILING OVER. A connector that moves to the second region and stays there
// leaves every flow crossing the mesh for ever — correct, and slower and more fragile than it needs to be. So
// a connection that has held long enough to be called good resets the search to the top of the list, and the
// next reconnect starts from the operator's first choice again.

// connectorEndpoints is the ordered set of Edge doors this connector may use.
type connectorEndpoints struct {
	mu      sync.Mutex
	regions []string // parallel to urls; "" when the operator gave a bare URL
	urls    []string
	at      int

	// movedOnPurpose marks that this connector has just been sent somewhere BY ITSELF, so the tunnel it is
	// about to lose is one it chose to end. See advance().
	movedOnPurpose bool

	// onMove is what to do to the tunnels this connector is holding when the door changes.
	//
	// ★★★ DECIDING TO MOVE DID NOT MOVE ANYTHING (2026-09-02, measured twice in one window). With the door
	// decision driven by the heartbeat the connector concluded at +98s that the region was gone — and the new
	// tunnel appeared at +142s regardless, because the tunnel worker was still blocked on a socket to the dead
	// door and only re-dialled when the KERNEL gave up on it. The decision moved 43 seconds earlier and the
	// outage did not move at all, which is the shape of a fix that measures well and changes nothing.
	//
	// The failback path already knew this: it lets go of every attachment so the workers re-dial. Failover has
	// to do the same, and it is the same call.
	onMove func()
}

// SetOnMove registers what to do to held tunnels when this connector changes door. Set once, by the thing that
// owns the attachments.
func (e *connectorEndpoints) SetOnMove(f func()) {
	if e == nil {
		return
	}
	e.mu.Lock()
	e.onMove = f
	e.mu.Unlock()
}

// parseConnectorEndpoints reads "region=URL;region=URL" (or bare URLs, ';' or ',' separated), preserving order.
//
// Order is the decision — it is the order a connector tries — so nothing here sorts, de-duplicates by region,
// or reorders by any notion of proximity. What the operator wrote is what happens.
func parseConnectorEndpoints(raw string) *connectorEndpoints {
	out := &connectorEndpoints{}
	for _, field := range strings.FieldsFunc(raw, func(r rune) bool { return r == ';' || r == ',' || r == '\n' }) {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		region, url := "", field
		if i := strings.Index(field, "="); i > 0 {
			region, url = strings.TrimSpace(field[:i]), strings.TrimSpace(field[i+1:])
		}
		url = strings.TrimRight(url, "/")
		if url == "" {
			continue
		}
		out.regions = append(out.regions, region)
		out.urls = append(out.urls, url)
	}
	return out
}

// len reports how many doors this connector knows.
func (e *connectorEndpoints) count() int {
	if e == nil {
		return 0
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.urls)
}

// current is the door to use now.
func (e *connectorEndpoints) current() string {
	if e == nil {
		return ""
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.urls) == 0 {
		return ""
	}
	return e.urls[e.at%len(e.urls)]
}

// currentRegion names the region of the door in use, for a log line an operator can act on.
func (e *connectorEndpoints) currentRegion() string {
	if e == nil {
		return ""
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.regions) == 0 {
		return ""
	}
	return e.regions[e.at%len(e.regions)]
}

// advance moves to the next door and reports where it went. A single-door connector stays where it is: moving
// to the same address and announcing a failover would be a lie in the log.
func (e *connectorEndpoints) advance(because error) string {
	if e == nil {
		return ""
	}
	e.mu.Lock()
	if e.movedOnPurpose {
		e.movedOnPurpose = false
		at := e.at
		urls := append([]string(nil), e.urls...)
		regions := append([]string(nil), e.regions...)
		e.mu.Unlock()
		if at < len(urls) {
			log.Printf("connector: the tunnel this connector ended ITSELF is not counted against %s%s",
				urls[at], regionSuffix(regionAt(regions, at)))
			return urls[at]
		}
		return ""
	}
	e.mu.Unlock()

	e.mu.Lock()
	n := len(e.urls)
	if n <= 1 {
		e.mu.Unlock()
		return e.current()
	}
	from := e.urls[e.at%n]
	e.at = (e.at + 1) % n
	to, region := e.urls[e.at], e.regions[e.at]
	e.mu.Unlock()
	log.Printf("connector region failover: %s did not hold (%v) — trying %s%s. Everything behind this connector "+
		"is reachable again only once one of its doors answers", from, because, to, regionSuffix(region))
	e.mu.Lock()
	move := e.onMove
	e.mu.Unlock()
	if move != nil {
		move()
	}
	return to
}

// resetToPreferred returns to the operator's first choice. Called when a connection has held long enough to
// count as good, so a connector that failed over does not stay in the second region for ever.
func (e *connectorEndpoints) resetToPreferred() {
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.at != 0 && len(e.urls) > 0 {
		log.Printf("connector: returning to %s%s, the first door configured", e.urls[0], regionSuffix(regionAt(e.regions, 0)))
		e.at = 0
		// ★★★ AND THE TUNNEL THIS IS ABOUT TO END IS NOT EVIDENCE (2026-09-02, measured: the connector decided
		// to go home every three minutes and reconnected to the region it was leaving, for ever). Going home
		// tears the tunnel down; the tunnel-end handler then sees a connection that did not hold for a minute
		// — because it was just moved — and calls advance(), which puts it straight back. Decide, undo,
		// decide, undo: the log said "returning to osaka" and two seconds later "tunnel connected to
		// tokyo-east", three times, and nothing in either line is wrong on its own.
		//
		// The connector already knows this shape: a tunnel ended by its OWN probe is explicitly not counted
		// against the door. A tunnel ended by its own failback is the same fact.
		e.movedOnPurpose = true
	}
}

// atPreferred reports whether this connector is on the operator's first door.
func (e *connectorEndpoints) atPreferred() bool {
	if e == nil {
		return true
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.at == 0
}

// preferred is the operator's first door and its region — where this connector is meant to live.
func (e *connectorEndpoints) preferred() (string, string) {
	if e == nil {
		return "", ""
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.urls) == 0 {
		return "", ""
	}
	return e.urls[0], regionAt(e.regions, 0)
}

func regionAt(regions []string, i int) string {
	if i < len(regions) {
		return regions[i]
	}
	return ""
}

func regionSuffix(region string) string {
	if strings.TrimSpace(region) == "" {
		return ""
	}
	return " (" + region + ")"
}

// replace takes a new door list from the deployment, keeping this connector where it currently is when that
// door is still in the list. It reports whether anything changed.
//
// ★★★ THE DOORS ARE A DEPLOYMENT FACT AND THEY MOVE (2026-08-26). A connector's list used to be whatever its
// one-time token carried, so a region added to the deployment afterwards could never be failed over to — the
// list was frozen on the day somebody pressed "Add connector", and the only way to change it was to enrol the
// connector again.
//
// ★ STAYING PUT MATTERS AS MUCH AS UPDATING. A settled connector re-reads this list every poll; if a
// refreshed list moved it back to the first door each time, it would leave a healthy region on a timer for no
// reason. Position is preserved by NAME, not by index — the operator's order can change too.
func (e *connectorEndpoints) replace(next *connectorEndpoints) bool {
	if e == nil || next == nil || next.count() == 0 {
		return false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if sameConnectorDoorList(e.urls, e.regions, next.urls, next.regions) {
		return false
	}
	current := ""
	if len(e.urls) > 0 {
		current = e.urls[e.at%len(e.urls)]
	}
	e.urls, e.regions, e.at = next.urls, next.regions, 0
	for i, u := range e.urls {
		if u == current {
			e.at = i
			break
		}
	}
	return true
}

func sameConnectorDoorList(aURLs, aRegions, bURLs, bRegions []string) bool {
	if len(aURLs) != len(bURLs) || len(aRegions) != len(bRegions) {
		return false
	}
	for i := range aURLs {
		if aURLs[i] != bURLs[i] {
			return false
		}
	}
	for i := range aRegions {
		if aRegions[i] != bRegions[i] {
			return false
		}
	}
	return true
}

// describe renders the door list for a log line, in order, so a change says what it changed to.
func (e *connectorEndpoints) describe() string {
	if e == nil {
		return ""
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	parts := make([]string, 0, len(e.urls))
	for i, u := range e.urls {
		parts = append(parts, regionAt(e.regions, i)+"="+u)
	}
	return strings.Join(parts, ";")
}
