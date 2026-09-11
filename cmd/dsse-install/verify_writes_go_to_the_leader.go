package main

import (
	"fmt"
	"net/http"
	"strings"
)

// verify_writes_go_to_the_leader.go — administration is authored by whoever holds leadership.
//
// ★★★ A BLOCK WRITTEN ON A STANDBY IS ACCEPTED AND NEVER REACHES THE FLEET (2026-08-26, measured). The
// deployment's roster is authored by the leader; a standby re-reads it every fifteen seconds and, being a
// reader, its own writes are what the NEXT reload overwrites — while the leader, correctly, never re-reads at
// all, because it is the author. So a device blocked on a standby answers 200, stays enabled everywhere the
// fleet can see, and goes on carrying traffic. For a security control, "accepted and ineffective" is the worst
// of the three possible outcomes.
//
// An operator using the Console never meets this: the Console talks to the front door, which health-checks
// GET /leader and routes there. Anything addressing a control plane DIRECTLY can meet it — including this
// walk, which is told a URL and believes it.
//
// So this walk finds the leader among the control planes it was given, and administers there. When the node it
// was pointed at is not the leader, it SAYS so rather than quietly using another: an operator who names a
// control plane is entitled to know that the deployment is answering from a different one.

// leaderAmong returns the first control plane that answers GET /leader with 200, and whether the preferred one
// was it.
func leaderAmong(client *http.Client, preferred string, others []string) (leader string, preferredLeads bool) {
	leads := func(u string) bool {
		u = strings.TrimRight(strings.TrimSpace(u), "/")
		if u == "" {
			return false
		}
		code, _, err := get(client, u+"/leader", "")
		return err == nil && code == 200
	}
	preferred = strings.TrimRight(strings.TrimSpace(preferred), "/")
	if leads(preferred) {
		return preferred, true
	}
	for _, u := range others {
		u = strings.TrimRight(strings.TrimSpace(u), "/")
		if u != "" && u != preferred && leads(u) {
			return u, false
		}
	}
	// Nobody answered as leader — a single control plane with no election answers 404 or 503 and is still the
	// only author there is. Keep what the operator named; the checks below then measure the deployment as it
	// actually is rather than refusing to run.
	return preferred, true
}

// verifyAdministrationReachesTheLeader reports where this walk will administer, and why.
func verifyAdministrationReachesTheLeader(preferred, leader string, preferredLeads bool) []verifyResult {
	if preferredLeads {
		return []verifyResult{{ok: true, name: "administration is authored where leadership is",
			note: fmt.Sprintf("%s holds leadership, so this walk administers there", preferred)}}
	}
	return []verifyResult{{ok: true, name: "administration is authored where leadership is",
		note: fmt.Sprintf("%s does NOT hold leadership; %s does, and this walk administers there. A write "+
			"accepted by a standby is not carried to the fleet — the Console reaches the leader through the "+
			"front door, but anything naming a control plane directly has to know this", preferred, leader)}}
}
