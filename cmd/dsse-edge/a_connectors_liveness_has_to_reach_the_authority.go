package main

import (
	"strings"
	"sync"
	"time"
)

// ★★★ A HEALTHY SITE READ "DOWN — 0 OF 2 CONNECTORS ONLINE" (2026-09-01, found on the Console, which is the
// only place it could be found).
//
// A connector registers, its Edge carries that registration to the control plane, and the authority names it.
// Then it heartbeats, every few seconds, for as long as it lives — and that never leaves the Edge node that
// received it. So the authority's copy stops at the moment of registration, the Console reads the authority,
// and every connector reads Offline a minute after it comes up, with a LAST HEARTBEAT frozen at the time it
// registered, while it is holding a live tunnel and serving flows.
//
//	Kaede HQ  Down  0 / 2 connectors online  osaka
//	  conn-45df9a8edc88  Offline  2026-09-01T02:01:32Z
//	  conn-c8e4d27798e1  Offline  2026-09-01T01:23:53Z
//
// ★ THE API SAID online=0 AND I READ PAST IT. A number is a number; the SCREEN put "Offline" beside a stale
// per-connector timestamp, which names the mechanism — the liveness is not travelling — and that is why the
// operator's instruction to check on the Console rather than the API was right. This is the connector's
// version of the split this deployment found this morning between the ledger (who is admitted) and presence
// (what they are doing): the authority holds the first and never learns the second.
//
// ★★ CARRIED, BUT NOT ON EVERY BEAT. A connector heartbeats far more often than an operator needs the
// authority to know, and the report is a POST that can queue. So it is carried when something CHANGED — a
// status, a region, a route set — and otherwise at a floor, which is what turns "still alive" into a fact the
// authority holds without turning it into traffic.

// connectorLivenessFloor is how often an unchanged connector is still carried upward. Short enough that a
// screen showing "last heartbeat" is not misleading, long enough that a fleet of connectors does not become
// the authority's load.
const connectorLivenessFloor = 30 * time.Second

// connectorLivenessCarrier decides whether this heartbeat is worth telling the authority about.
//
// restart-durability: ephemeral
// populated-by: assertion
//
// ★ LOSING IT IS NOT ONLY HARMLESS, IT IS THE SAFE DIRECTION. What this remembers is "I have told the
// authority about this connector recently". An empty map means every connector's NEXT heartbeat is carried
// immediately — so a restarted Edge re-asserts the whole site's liveness within one beat instead of waiting
// out a floor. The state is filled by the heartbeats themselves, which repeat for as long as a connector
// lives, so it re-converges with nobody doing anything.
//
// ★ AND NOTHING AN OPERATOR READS DEPENDS ON IT SURVIVING. The fact an operator reads — when this connector
// was last seen — lives at the control plane; this only decides how often that fact is refreshed. Holding it
// durably would make a restart carry LESS, which is the wrong direction for the defect this exists to fix.
type connectorLivenessCarrier struct {
	mu   sync.Mutex
	last map[string]connectorLivenessMark
}

type connectorLivenessMark struct {
	at     time.Time
	status string
	region string
}

func newConnectorLivenessCarrier() *connectorLivenessCarrier {
	return &connectorLivenessCarrier{last: map[string]connectorLivenessMark{}}
}

// shouldCarry reports whether to report this connector now, and records that it did. A change is always
// carried; an unchanged connector is carried at the floor.
func (c *connectorLivenessCarrier) shouldCarry(connectorID, status, region string, now time.Time) bool {
	if c == nil {
		return false
	}
	id := strings.TrimSpace(connectorID)
	if id == "" {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	prev, seen := c.last[id]
	changed := !seen || prev.status != status || prev.region != region
	if !changed && now.Sub(prev.at) < connectorLivenessFloor {
		return false
	}
	c.last[id] = connectorLivenessMark{at: now, status: status, region: region}
	return true
}
