package main

import (
	"log"
	"strings"

	frontdoor "github.com/lantern-networks/dsse-core/frontdoor"
)

// ★★★ THE CONSOLE BESIDE THE LEADER LEFT THROUGH ITS OWN DOOR, AND ONLY THROUGH IT (2026-11-08, acceptance C).
//
// In the profiles where every control-plane machine has a front door, the Console is served only beside the
// control-plane leader, and every door sends the browser to that Console. The Console then asks the
// deployment's names — admin.<host> for sign-in and the control plane, <node>.admin.<host> for the Edge — and
// those names resolve inside its container to the door on the same machine. Stopping that one door (the
// leader's entrance) therefore cost sign-in at EVERY door: the browser still reached the Console through the
// two doors that were up, and the Console answered HTTP 502 for every sign-in and every session check, because
// its own way out was the door that had been stopped. The data path was untouched; the administrator was locked
// out of a deployment with two working entrances.
//
// The other doors of a one-region profile route the same names to the same places — the leader for admin.<host>,
// the named node for <node>.admin.<host> — so the Console may leave through any of them. Across regions only
// admin.<host> is routed everywhere: another region's door sends this region's per-node Edge names to its own data
// plane, which refuses /admin/* (review C2R2), so sign-in and the control plane continue and those Edge screens do
// not. Only where it CONNECTS changes: the TLS server name, the Host and the certificate check stay those of the
// name in the URL. A door that routes a name somewhere else is answered by whatever it routes to, which is why the
// list holds this deployment's own doors and nothing else.
//
// The door on this machine stays first: it is one hop, and it is the one every other request has always used.
// When it refuses, new connections go to the other doors for a short while before this one is tried again, so a
// stopped door costs one short wait, not one per request. A connection already open is not moved.
const consoleDoorFallbacksEnv = "DSSE_CONSOLE_DOOR_FALLBACKS"

// doorDialer is the shared one (frontdoor.Dialer): the Edge on the same machine needed the same thing a walk
// later, for the same reason.
type doorDialer = frontdoor.Dialer

func newDoorDialer(raw string) (*doorDialer, error) {
	d, err := frontdoor.Parse(raw, consoleDoorFallbacksEnv)
	if d != nil {
		d.Who = "the Console"
	}
	return d, err
}

// consoleDoorDialer reads the setting once. An unreadable setting stops the Console: a list the operator wrote
// and the Console silently ignored would come back as the outage it exists to prevent.
func consoleDoorDialer(raw string) *doorDialer {
	d, err := newDoorDialer(raw)
	if err != nil {
		log.Fatal(err)
	}
	if d != nil {
		log.Printf("front door: when this machine's door does not answer, the Console leaves through %s", strings.Join(d.Fallbacks(), ", "))
	}
	return d
}
