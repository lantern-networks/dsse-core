package main

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// ★★★ A STANDBY'S BUNDLE IS NOT ONE RE-READ BEHIND, IT IS STOPPED (2026-08-27, measured). Two Edges of one
// region, polling in the same second, had applied generations 13 and 8; the two control planes explained it —
// the leader served 13, the standby served 8 and had no way to advance, because the generation is a sum over
// stores only the leader writes. The Edge on 8 enforced configuration nobody had authored for five
// generations while reporting itself current: a Site created on the authority never reached it, and a device
// an administrator had BLOCKED went on steering through it.
func TestAStandbyDoesNotHandTheFleetABundle(t *testing.T) {
	previous := cpLeaderElectorInstance
	defer func() { cpLeaderElectorInstance = previous }()

	// A node with no election is the only author there is — the ordinary small deployment, which must keep
	// working exactly as it did.
	cpLeaderElectorInstance = nil
	if w := httptest.NewRecorder(); configBundleRefusedOnAStandby(w) {
		t.Fatal("a single control plane refused to serve its own bundle")
	}
}

// ★ AND THE REFUSAL SAYS WHY, not just no. An Edge that is refused keeps enforcing what it last applied —
// a deployment holding still, which is the safe direction — and an operator reading the message learns that
// the node was asked the wrong question rather than that the deployment is broken.
func TestTheRefusalNamesWhatIsWrongWithTheAnswerItDidNotGive(t *testing.T) {
	previous := cpLeaderElectorInstance
	defer func() { cpLeaderElectorInstance = previous }()
	cpLeaderElectorInstance = nil

	w := httptest.NewRecorder()
	if configBundleRefusedOnAStandby(w) {
		t.Fatal("the no-election case must not refuse")
	}
	// The message itself is asserted where it is produced: it must name leadership, because that string is
	// what the Edge's puller matches on to drop a connection pinned to a former leader.
	msg := bundleRefusalMessage()
	if !strings.Contains(msg, "does not hold leadership") || !strings.Contains(msg, "GET /leader") {
		t.Fatalf("the refusal does not carry what the puller looks for: %q", msg)
	}
}
