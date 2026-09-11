package main

import (
	"context"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/regionfailover"
)

// driverHarness wires a regionFailover with a controllable probe + action spies, so we can assert the loop's
// SIDE EFFECTS (endpoint swaps, fail-closed, deny) without Windows I/O. The engine's selection rules themselves
// are covered by regionfailover's own tests; here we verify the driver acts on the decisions correctly.
type driverHarness struct {
	health map[string]regionfailover.Health

	switches   []string // region ids switchTo was called with, in order
	switchErr  map[string]error
	failClosed int
	denied     int
	connected  []string // region ids connectedOK was called with
}

func newDriverHarness(seed []regionfailover.RegionEndpoint, home string, strikes int) (*regionFailover, *driverHarness) {
	h := &driverHarness{health: map[string]regionfailover.Health{}, switchErr: map[string]error{}}
	actions := regionFailoverActions{
		switchTo: func(ep regionfailover.RegionEndpoint) error {
			if err := h.switchErr[ep.Region]; err != nil {
				return err
			}
			h.switches = append(h.switches, ep.Region)
			return nil
		},
		failClosed:    func(string) { h.failClosed++ },
		surfaceDenied: func(string) { h.denied++ },
		connectedOK:   func(ep regionfailover.RegionEndpoint) { h.connected = append(h.connected, ep.Region) },
	}
	probeOne := func(ep regionfailover.RegionEndpoint) regionfailover.Health { return h.health[ep.Region] }
	rf := newRegionFailover(seed, home, probeOne, actions, regionFailoverOptions{unhealthyStrike: strikes})
	return rf, h
}

func up(rttMS int) regionfailover.Health {
	return regionfailover.Health{Reachable: true, Admitted: true, RTT: time.Duration(rttMS) * time.Millisecond}
}

var twoRegions = []regionfailover.RegionEndpoint{
	{Region: "jp-east", Endpoint: "https://edge-jp:18543"},
	{Region: "ap-southeast", Endpoint: "https://edge-sg:18543"},
}

func TestDriver_NearestHealthySelectedAndSwitchedOnce(t *testing.T) {
	rf, h := newDriverHarness(twoRegions, "jp-east", 3)
	h.health["jp-east"] = up(80)
	h.health["ap-southeast"] = up(20) // nearer than home
	rf.evaluateOnce(context.Background())
	if len(h.switches) != 1 || h.switches[0] != "ap-southeast" {
		t.Fatalf("expected one switch to the nearest region (ap-southeast); got %v", h.switches)
	}
	if len(h.connected) != 1 || h.connected[0] != "ap-southeast" {
		t.Fatalf("expected connectedOK(ap-southeast); got %v", h.connected)
	}
	// Re-evaluate with no change: sticky, no second switch.
	rf.evaluateOnce(context.Background())
	if len(h.switches) != 1 {
		t.Fatalf("a healthy current region must be sticky (no re-switch); got %v", h.switches)
	}
}

func TestDriver_InBoundaryFailover(t *testing.T) {
	rf, h := newDriverHarness(twoRegions, "jp-east", 1) // strikes=1: fail over immediately when current degrades
	h.health["jp-east"] = up(20)
	h.health["ap-southeast"] = up(80)
	rf.evaluateOnce(context.Background()) // lands on jp-east (nearer)
	if len(h.switches) != 1 || h.switches[0] != "jp-east" {
		t.Fatalf("setup: expected initial switch to jp-east; got %v", h.switches)
	}
	// jp-east goes down -> fail over to the other LISTED region, never anything else.
	h.health["jp-east"] = regionfailover.Health{Reachable: false}
	rf.evaluateOnce(context.Background())
	if len(h.switches) != 2 || h.switches[1] != "ap-southeast" {
		t.Fatalf("expected failover switch to ap-southeast; got %v", h.switches)
	}
	if h.failClosed != 0 {
		t.Fatalf("a healthy alternate exists; must not fail closed")
	}
}

func TestDriver_FailClosedWhenNoneHealthy_NeverBypasses(t *testing.T) {
	rf, h := newDriverHarness(twoRegions, "jp-east", 1)
	h.health["jp-east"] = regionfailover.Health{Reachable: false}
	h.health["ap-southeast"] = regionfailover.Health{Reachable: false}
	rf.evaluateOnce(context.Background())
	if h.failClosed != 1 {
		t.Fatalf("no healthy region -> exactly one failClosed; got %d", h.failClosed)
	}
	if len(h.switches) != 0 {
		t.Fatalf("fail-closed must NEVER switch/bypass to any endpoint; got %v", h.switches)
	}
	// Stays fail-closed without re-firing the action each round (idempotent).
	rf.evaluateOnce(context.Background())
	if h.failClosed != 1 {
		t.Fatalf("failClosed must be idempotent across rounds; got %d", h.failClosed)
	}
	// Recovery: a region returns -> connect + switch, deny cleared.
	h.health["ap-southeast"] = up(30)
	rf.evaluateOnce(context.Background())
	if len(h.switches) != 1 || h.switches[0] != "ap-southeast" {
		t.Fatalf("recovery must switch to the recovered region; got %v", h.switches)
	}
	if len(h.connected) == 0 || h.connected[len(h.connected)-1] != "ap-southeast" {
		t.Fatalf("recovery must announce connectedOK; got %v", h.connected)
	}
}

func TestDriver_AdmissionDeniedSurfacedNotHunted(t *testing.T) {
	rf, h := newDriverHarness(twoRegions, "jp-east", 1)
	// Both regions are UP but reject THIS device (revoked) -> deny, never failover.
	h.health["jp-east"] = regionfailover.Health{Reachable: true, Admitted: false}
	h.health["ap-southeast"] = regionfailover.Health{Reachable: true, Admitted: false}
	rf.evaluateOnce(context.Background())
	if h.denied != 1 {
		t.Fatalf("reachable-but-unadmitted -> exactly one surfaceDenied; got %d", h.denied)
	}
	if len(h.switches) != 0 || h.failClosed != 0 {
		t.Fatalf("admission deny must not switch or fail-closed; switches=%v failClosed=%d", h.switches, h.failClosed)
	}
}

func TestDriver_SwitchErrorDoesNotAdvanceState_RetriesNextRound(t *testing.T) {
	rf, h := newDriverHarness(twoRegions, "jp-east", 1)
	h.health["jp-east"] = up(20)
	h.health["ap-southeast"] = up(80)
	h.switchErr["jp-east"] = context.DeadlineExceeded // first switch attempt fails
	rf.evaluateOnce(context.Background())
	if len(h.switches) != 0 {
		t.Fatalf("a failed switch must not be recorded as applied; got %v", h.switches)
	}
	if len(h.connected) != 0 {
		t.Fatalf("connectedOK must not fire when the switch failed; got %v", h.connected)
	}
	// Clear the error: next round retries the same region and succeeds (state had not advanced).
	delete(h.switchErr, "jp-east")
	rf.evaluateOnce(context.Background())
	if len(h.switches) != 1 || h.switches[0] != "jp-east" {
		t.Fatalf("expected retry to switch to jp-east; got %v", h.switches)
	}
}

func TestDriver_UpdateListDropsOutOfBoundaryCurrent(t *testing.T) {
	rf, h := newDriverHarness(twoRegions, "jp-east", 1)
	h.health["jp-east"] = up(20)
	h.health["ap-southeast"] = up(80)
	rf.evaluateOnce(context.Background()) // on jp-east
	if rf.sel.Current() != "jp-east" {
		t.Fatalf("setup: expected current jp-east; got %q", rf.sel.Current())
	}
	// A residency-policy shrink: jp-east is no longer allowed. Update the engine + the driver's probe set.
	shrunk := []regionfailover.RegionEndpoint{{Region: "ap-southeast", Endpoint: "https://edge-sg:18543"}}
	rf.mu.Lock()
	rf.allowed = shrunk
	rf.mu.Unlock()
	rf.sel.UpdateList(shrunk, "ap-southeast")
	if rf.sel.Current() != "" {
		t.Fatalf("out-of-boundary current region must be dropped immediately; current=%q", rf.sel.Current())
	}
	rf.evaluateOnce(context.Background())
	if h.switches[len(h.switches)-1] != "ap-southeast" {
		t.Fatalf("after shrink, must re-select an in-boundary region; got %v", h.switches)
	}
}
