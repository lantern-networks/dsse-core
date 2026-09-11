package main

import (
	"fmt"
	"net/http"
)

// the_bundle_is_the_leaders_instruction.go — a control plane that does not lead must not hand the fleet a
// configuration bundle.
//
// ★★★ MEASURED ON A DEPLOYMENT STANDING ITSELF UP (2026-08-27). Two Edges of one region, polling in the same
// second, had applied DIFFERENT configurations:
//
//	edge-a  applied generation 13   last_poll 20:43:59
//	edge-b  applied generation  8   last_poll 20:43:59
//
// Asked directly, the two control planes explained it:
//
//	cp-a  leader=true   bundle generation 13
//	cp-b  leader=false  bundle generation  8      ← frozen, and served without complaint
//
// So edge-b was enforcing configuration nobody had authored for five generations, reporting itself healthy,
// and polling successfully the whole time. What that cost, in the same run: a Site created on the authority
// never reached it, so a connector enrolling through the region's front door was refused whenever the door
// picked edge-b; and a device an administrator BLOCKED went on steering through it — "an administrator who
// blocks a machine has been told it is stopped; it is carrying traffic with the certificate it already holds".
//
// ★★ THE PREMISE NEXT DOOR IS WRONG FOR THIS ONE DOCUMENT. admin_writes_belong_to_the_leader.go refuses
// writes on a standby and lets reads through, saying "a standby answering questions is exactly what a standby
// is for, and its answers are the authority's own state, one re-read behind at worst". That is true of a
// question. The bundle is not a question — it is the authority's INSTRUCTION to the fleet, and this node's
// copy of it is not one re-read behind: the generation is a sum over stores that only the leader writes, so a
// standby's number cannot advance at all. It is not stale, it is stopped.
//
// ★ REFUSING IS THE SAFE DIRECTION, and it is the behaviour the architecture already describes: an Edge that
// cannot reach the authority keeps enforcing what it last applied. That is a deployment holding still. Serving
// a frozen bundle is a deployment that has quietly split in two — half the fleet on the operator's rules and
// half on rules from before they wrote them, with every screen green.

// configBundleRefusedOnAStandby reports the refusal and returns true when the caller must stop.
func configBundleRefusedOnAStandby(w http.ResponseWriter) bool {
	if cpLeaderElectorInstance == nil || cpLeaderElectorInstance.IsLeader() {
		// No election here means this node is the only author there is — a single control plane, which is the
		// ordinary shape of a small deployment and must keep working exactly as it did.
		return false
	}
	writeError(w, http.StatusConflict, fmt.Errorf("%s", bundleRefusalMessage()))
	return true
}

// bundleRefusalMessage is the refusal, in one place, because the Edge's puller MATCHES ON IT: seeing
// "does not hold leadership" is how it knows to drop a connection pinned to a former leader rather than to
// keep asking the same wrong node. Two copies of this sentence would be two contracts.
func bundleRefusalMessage() string {
	return "this control plane does not hold leadership, so the configuration bundle it holds is not the " +
		"deployment's: the generation is a sum over stores only the leader writes, so this node's copy " +
		"cannot advance and an Edge that applied it would enforce what nobody authored while reporting " +
		"itself current. Pull from the leader — GET /leader answers 200 only there"
}
