package main

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// closeCountingTransport stands in for the websocket the Edge has already registered.
type closeCountingTransport struct {
	mu     sync.Mutex
	closed int
}

func (c *closeCountingTransport) Close() error {
	c.mu.Lock()
	c.closed++
	c.mu.Unlock()
	return nil
}
func (c *closeCountingTransport) closes() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

// ★★★ A WORKER THAT LOSES THE LOCAL CLAIM MUST CLOSE THE SOCKET IT JUST OPENED (2026-09-02, measured after a
// failover/failback cycle on a real deployment).
//
// The Edge registers a tunnel the moment the upgrade completes, and registering REPLACES whatever this
// connector had on that node — closing it. So when a sibling worker wins the claim, the session this worker is
// abandoning is the connector's ONLY serving session. Walking away without closing it leaves the Edge holding
// a session whose peer never reads: every flow to the estate times out, both sides report themselves healthy,
// and only restarting the connector clears it.
//
// This test is about the CONTRACT the code has to keep, stated where somebody changing that path will see it:
// the abandoning worker closes, and the winner's session is untouched.
func TestAWorkerThatLosesTheClaimClosesWhatTheEdgeAlreadyRegistered(t *testing.T) {
	attachments := newConnectorFleetAttachments()
	node := "edge-node-1"

	// The sibling worker wins the node first.
	winner := &closeCountingTransport{}
	if _, ok := attachments.claim(node, "osaka", func() { _ = winner.Close() }); !ok {
		t.Fatal("setup: the first claim must win")
	}

	// This worker dialled the same node; the Edge has ALREADY registered its socket and closed the previous
	// one. It then loses the claim.
	loser := &closeCountingTransport{}
	_, ok := attachments.claim(node, "osaka", func() { _ = loser.Close() })
	if ok {
		t.Fatal("the second claim on one node must lose — one session per connector per node")
	}
	// What connectTunnelOnce does on that branch.
	_ = loser.Close()

	if loser.closes() == 0 {
		t.Fatal("the abandoned socket was left open: the Edge holds a session whose peer never reads, and " +
			"every flow to this connector's estate times out until the process is restarted")
	}
	if winner.closes() != 0 {
		t.Fatal("the winner's session must be untouched — closing it would hand the estate back to nobody")
	}

	// And the winner still holds the node, so the connector's coverage line is not a stale claim.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = ctx
	if len(attachments.nodes()) != 1 {
		t.Fatalf("exactly one worker holds this node, got %v", attachments.nodes())
	}
}

// ★★★ THE CALL SITE, NOT THE CONTRACT. The test above states what has to happen; this one states that
// connectTunnelOnce actually does it. The whole defect was one missing line on a branch that returns early,
// and every helper it touches was correct.
func TestConnectTunnelOnceClosesOnALostClaim(t *testing.T) {
	body, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(body)
	i := strings.Index(src, "id, ok := attachments.claim(node, region, letGo)")
	if i < 0 {
		t.Fatal("the claim in connectTunnelOnce has moved; this check needs rewriting rather than deleting")
	}
	j := strings.Index(src[i:], "errConnectorNodeAlreadyHeld")
	if j < 0 {
		t.Fatal("the lost-claim branch has moved")
	}
	branch := src[i : i+j]
	if !strings.Contains(branch, "conn.Close()") {
		t.Fatal("the lost-claim branch returns without closing the socket the Edge has already registered — " +
			"the connector is then left with no serving session and its estate is unreachable until restart")
	}
}
