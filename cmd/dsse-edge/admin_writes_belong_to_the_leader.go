package main

import (
	"fmt"
	"net/http"
	"strings"
)

// admin_writes_belong_to_the_leader.go — an administrative write is authored where leadership is.
//
// ★★★ A BLOCK ACCEPTED BY A STANDBY IS A BLOCK THAT NEVER HAPPENS (2026-08-26, measured with its control on
// the two-region lab):
//
//	the same device, blocked on the STANDBY  -> 200, and still admitted two minutes later
//	the same device, blocked on the LEADER   -> 200, and refused fifteen seconds later
//
// The deployment's authored state is held by whoever holds leadership. A standby re-reads it on a timer, so
// its own writes are what the next re-read overwrites — and the leader, correctly, never re-reads at all,
// because it is the author. The write is therefore accepted, recorded, shown on the screen that made it, and
// discarded. For a security control that is the worst of the three possible outcomes: an administrator who
// blocks a machine has been told it is stopped, and it is not.
//
// ★ AN OPERATOR USING THE CONSOLE NEVER MEETS THIS. The Console talks to the front door, which health-checks
// GET /leader and routes there. What meets it is anything addressing a control plane DIRECTLY — a script, a
// check, an operator who noted a node's address, or a front door in a region that has lost leadership.
//
// So a node that is not the leader REFUSES the write and says where the leader is. Refusing is not a
// limitation to apologise for: it is the difference between a control that failed and a control that lied.

// adminWriteRefusedOnAStandby reports the refusal and returns true when the caller must stop.
//
// Reads only apply to WRITE permissions: a standby answering questions is exactly what a standby is for, and
// its answers are the authority's own state, one re-read behind at worst.
func adminWriteRefusedOnAStandby(w http.ResponseWriter, permission string) bool {
	if !adminPermissionWrites(permission) {
		return false
	}
	if cpLeaderElectorInstance == nil || cpLeaderElectorInstance.IsLeader() {
		// No election here means this node is the only author there is — a single control plane, which is the
		// ordinary shape of a small deployment and must keep working exactly as it did.
		return false
	}
	writeError(w, http.StatusConflict, fmt.Errorf(
		"this control plane does not hold leadership, and an administrative change written here would be "+
			"accepted and then discarded — the deployment's authored state belongs to the node that leads, and "+
			"this one re-reads it. Send this to the leader: the Console reaches it through the front door, and "+
			"GET /leader answers 200 only there"))
	return true
}

// adminPermissionWrites reports whether a permission names a change rather than a question.
//
// By the scope's own suffix, so a permission added tomorrow is covered the day it exists rather than the day
// somebody remembers to add it to a list here.
func adminPermissionWrites(permission string) bool {
	p := strings.ToLower(strings.TrimSpace(permission))
	for _, suffix := range []string{".write", ".admin", ".cancel", ".create"} {
		if strings.HasSuffix(p, suffix) {
			return true
		}
	}
	return false
}
