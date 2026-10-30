package main

import (
	"context"
	"fmt"
	"log"
	"net/url"
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
	// profileURL is used only for the authenticated profile GET while the
	// authoritative data-door list is empty. It must never enter urls.
	profileURL string
	dataCtx    context.Context
	cancelData context.CancelFunc

	revision uint64 // identifies the selection a reachability verdict actually measured

	// onMove is what to do to held tunnels when the DSSE Region changes. Switching
	// entrances inside the same named Region must preserve surviving Edge tunnels.
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

// SetOnMove registers what to do to held tunnels when this connector changes
// DSSE Region. Set once, by the thing that owns the attachments.
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

// validateConnectorDoorURLs checks every effective door, including failover doors.
// A pinned transport must never be allowed to fall back to plaintext merely
// because a later door came from a saved profile or a deployment update.
func validateConnectorDoorURLs(doors *connectorEndpoints, pinnedTLS bool) error {
	if doors == nil || doors.count() == 0 {
		return fmt.Errorf("no Edge doors configured")
	}
	for i, raw := range doors.urls {
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Hostname() == "" || parsed.User != nil || parsed.Fragment != "" {
			return fmt.Errorf("Edge door %d is not a valid base URL", i+1)
		}
		if pinnedTLS && parsed.Scheme != "https" {
			return fmt.Errorf("Edge door %d must use HTTPS with pinned transport TLS", i+1)
		}
		if parsed.Scheme != "https" && parsed.Scheme != "http" {
			return fmt.Errorf("Edge door %d has an unsupported URL scheme", i+1)
		}
	}
	return nil
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

func (e *connectorEndpoints) profileDoor() string {
	if e == nil {
		return ""
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.urls) > 0 {
		return e.urls[e.at%len(e.urls)]
	}
	return e.profileURL
}

// selectionForData ties a dial to the current authoritative door set. A
// withdrawal cancels in-flight dials as well as already-held attachments.
func (e *connectorEndpoints) selectionForData() (connectorDoorSelection, context.Context) {
	if e == nil {
		return connectorDoorSelection{}, nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.urls) == 0 {
		return connectorDoorSelection{revision: e.revision}, nil
	}
	if e.dataCtx == nil {
		e.dataCtx, e.cancelData = context.WithCancel(context.Background())
	}
	at := e.at % len(e.urls)
	return connectorDoorSelection{e.urls[at], e.regions[at], e.revision}, e.dataCtx
}

// withdraw closes all held data tunnels and leaves only the last verified
// profile GET address. Empty data doors are authoritative, not a failover to
// the old enrolment URL.
func (e *connectorEndpoints) withdraw(profileURL string) bool {
	if e == nil || strings.TrimSpace(profileURL) == "" {
		return false
	}
	e.mu.Lock()
	changed := len(e.urls) > 0
	e.profileURL = profileURL
	if changed {
		if e.cancelData != nil {
			e.cancelData()
		}
		e.dataCtx, e.cancelData = nil, nil
		e.urls, e.regions, e.at = nil, nil, 0
		e.revision++
	}
	move := e.onMove
	e.mu.Unlock()
	if changed && move != nil {
		move()
	}
	return changed
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

// A door change inside one named DSSE Region must not evict tunnels held on
// other healthy Edge nodes. Unnamed doors cannot establish this relationship.
func sameConnectorRegion(a, b string) bool {
	return a != "" && a == b
}

// advance moves to the next door and reports where it went. A single-door connector stays where it is: moving
// to the same address and announcing a failover would be a lie in the log.
type connectorDoorSelection struct {
	url, region string
	revision    uint64
}

func (e *connectorEndpoints) selection() connectorDoorSelection {
	if e == nil {
		return connectorDoorSelection{}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.urls) == 0 {
		return connectorDoorSelection{revision: e.revision}
	}
	at := e.at % len(e.urls)
	return connectorDoorSelection{e.urls[at], e.regions[at], e.revision}
}

func (e *connectorEndpoints) advance(because error) string {
	return e.advanceIfSelected(e.selection(), because)
}

// A late failure belongs to the selection tested, never to its replacement.
// This also rejects ABA (A -> B -> A) and removes the global self-close marker,
// which incorrectly suppressed a real heartbeat failure after failback.
func (e *connectorEndpoints) advanceIfSelected(expected connectorDoorSelection, because error) string {
	if e == nil {
		return ""
	}
	e.mu.Lock()
	n := len(e.urls)
	if n == 0 || e.revision != expected.revision || e.urls[e.at%n] != expected.url {
		e.mu.Unlock()
		return ""
	}
	if n == 1 {
		to := e.urls[0]
		e.mu.Unlock()
		return to
	}
	from, fromRegion := e.urls[e.at%n], e.regions[e.at%n]
	e.at = (e.at + 1) % n
	e.revision++
	to, region, move := e.urls[e.at], e.regions[e.at], e.onMove
	e.mu.Unlock()
	log.Printf("connector entry failover: %s%s unavailable (%v); trying %s%s", from, regionSuffix(fromRegion), because, to, regionSuffix(region))
	if move != nil && !sameConnectorRegion(fromRegion, region) {
		move()
	}
	return to
}

// resetToPreferred returns to the operator's first choice. Called when a connection has held long enough to
// count as good, so a connector that failed over does not stay in the second region for ever.
// resetToPreferred reports whether the move crossed a DSSE Region boundary.
// The decision and the index change happen under one lock so the caller can
// decide whether to retire old-region tunnels without a stale region snapshot.
func (e *connectorEndpoints) resetToPreferred() bool { return e.resetToPreferredIfSelected(nil) }

func (e *connectorEndpoints) resetToPreferredIfSelected(expected *connectorDoorSelection) bool {
	if e == nil {
		return false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if expected != nil && (len(e.urls) == 0 || e.revision != expected.revision || e.urls[e.at%len(e.urls)] != expected.url) {
		return false
	}
	if e.at != 0 && len(e.urls) > 0 {
		crossRegion := !sameConnectorRegion(e.regions[e.at%len(e.regions)], e.regions[0])
		log.Printf("connector: returning to %s%s, the first door configured", e.urls[0], regionSuffix(regionAt(e.regions, 0)))
		e.at = 0
		e.revision++
		return crossRegion
	}
	return false
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
	if sameConnectorDoorList(e.urls, e.regions, next.urls, next.regions) {
		e.mu.Unlock()
		return false
	}
	current := ""
	if len(e.urls) > 0 {
		current = e.urls[e.at%len(e.urls)]
	}
	e.urls, e.regions, e.at = next.urls, next.regions, 0
	e.profileURL = ""
	e.revision++
	stillAllowed := current == ""
	for i, u := range e.urls {
		if u == current {
			e.at = i
			stillAllowed = true
			break
		}
	}
	move := e.onMove
	if !stillAllowed && e.cancelData != nil {
		e.cancelData()
		e.dataCtx, e.cancelData = nil, nil
	}
	e.mu.Unlock()
	if !stillAllowed && move != nil {
		move()
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
