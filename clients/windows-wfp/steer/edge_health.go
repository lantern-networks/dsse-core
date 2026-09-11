package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// edgeHealth is a tiny circuit breaker shared by the DNS proxy and the TCP steerer in --fail-open mode. It
// distinguishes a control-plane OUTAGE (the Edge is unreachable at the transport layer) from a healthy Edge
// that returns a policy DENY — only the former trips fail-open. Without it, every flow and DNS query during a
// sustained Edge outage would pay the full Edge dial/timeout before falling back, turning an outage into a
// multi-second stall on every connection. Once `failThreshold` consecutive transport failures are seen the
// circuit OPENS for `cooldown`: callers skip the Edge entirely and take the fail-open path immediately. After
// the cooldown one probe is allowed (half-open); a success closes the circuit, another failure re-opens it.
//
// All methods are nil-safe so the fail-closed path (health == nil) needs no guards at the call sites.
type edgeHealth struct {
	mu            sync.Mutex
	consecFail    int
	openUntil     time.Time
	failThreshold int
	cooldown      time.Duration
}

func newEdgeHealth(failThreshold int, cooldown time.Duration) *edgeHealth {
	if failThreshold < 1 {
		failThreshold = 3
	}
	if cooldown <= 0 {
		cooldown = 10 * time.Second
	}
	return &edgeHealth{failThreshold: failThreshold, cooldown: cooldown}
}

// shouldTryEdge reports whether the caller should attempt the Edge. It returns false while the circuit is open
// (during the cooldown after a burst of failures), so the caller goes straight to the fail-open path.
func (h *edgeHealth) shouldTryEdge() bool {
	if h == nil {
		return true
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return !time.Now().Before(h.openUntil)
}

// recordSuccess marks the Edge reachable (any response from it, including a policy deny): reset the failure
// count and close the circuit.
func (h *edgeHealth) recordSuccess() {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.consecFail = 0
	h.openUntil = time.Time{}
}

// recordFailure counts a transport-level Edge failure and opens the circuit once the threshold is crossed.
// It returns true the moment it opens the circuit (so the caller can log the transition exactly once).
func (h *edgeHealth) recordFailure() (opened bool) {
	if h == nil {
		return false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.consecFail++
	if h.consecFail >= h.failThreshold {
		h.consecFail = 0
		h.openUntil = time.Now().Add(h.cooldown)
		return true
	}
	return false
}

// isOpen reports whether the circuit is currently open (fail-open engaged). Used by the active health monitor
// to decide whether to probe the Edge for recovery.
func (h *edgeHealth) isOpen() bool {
	if h == nil {
		return false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return time.Now().Before(h.openUntil)
}

// markRecovered closes the circuit (Edge reachable again) and reports whether it WAS open — so the active
// monitor logs the steer-all re-arm exactly once on the transition.
func (h *edgeHealth) markRecovered() (wasOpen bool) {
	if h == nil {
		return false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	wasOpen = time.Now().Before(h.openUntil)
	h.consecFail = 0
	h.openUntil = time.Time{}
	return wasOpen
}

// extendOpen pushes the open window forward by the cooldown IF the circuit is currently open. The active
// monitor calls this after a FAILED probe so a sustained outage keeps the circuit open (every flow stays
// direct/fast) instead of lazily expiring at the cooldown boundary and forcing real flows to re-probe the
// dead Edge. It never opens a closed circuit.
func (h *edgeHealth) extendOpen() {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.openUntil.IsZero() && time.Now().Before(h.openUntil) {
		h.openUntil = time.Now().Add(h.cooldown)
	}
}

// runEdgeHealthMonitor is the active recovery + escalation loop for --fail-open. While the circuit is OPEN (the
// Edge was found unreachable and flows are going direct/unmediated) — or while DISARMED — it probes the Edge
// every `interval`:
//   - probe succeeds: if disarmed, RE-ARM (onRearm); else CLOSE the circuit (markRecovered). Either way the box
//     returns to mediated steering automatically, without waiting for a user flow to gamble a probe.
//   - probe fails: keep the circuit open (extendOpen). If the outage has lasted >= disarmAfter and we are not
//     yet disarmed, ESCALATE to a full self-disarm (onDisarm) — restore DNS, stop the WFP redirect, unblock QUIC
//     — so the box uses its native network when an interface goes down and per-flow direct dials also fail (the
//     OS hasn't failed over yet). disarmAfter<=0 disables the escalation (per-flow fail-open only).
//
// It does nothing while the circuit is closed and not disarmed (healthy steer-all): zero overhead normally.
// onDisarm/onRearm may be nil (then only the circuit open/close behaviour applies). `disarmed` is the shared
// flag the disarm callbacks flip; the monitor reads it to keep probing while disarmed. Stops when `stop` closes.
func runEdgeHealthMonitor(stop <-chan struct{}, h *edgeHealth, probe func() bool, interval, disarmAfter time.Duration, disarmed *atomic.Bool, onDisarm, onRearm func()) {
	if h == nil || probe == nil {
		return
	}
	if interval <= 0 {
		interval = 5 * time.Second
	}
	isDisarmed := func() bool { return disarmed != nil && disarmed.Load() }
	t := time.NewTicker(interval)
	defer t.Stop()
	var openSince time.Time
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			if !h.isOpen() && !isDisarmed() {
				openSince = time.Time{}
				continue // healthy: nothing to recover
			}
			if probe() {
				if isDisarmed() {
					if onRearm != nil {
						onRearm()
					}
				} else if h.markRecovered() {
					fmt.Println("edge_recovered: connectivity restored — steer-all re-armed (fail-open disengaged)")
				}
				openSince = time.Time{}
				continue
			}
			// Probe failed — the Edge is (still) unreachable.
			if isDisarmed() {
				continue // already disarmed; just keep waiting for recovery
			}
			if openSince.IsZero() {
				openSince = time.Now()
			}
			if disarmAfter > 0 && onDisarm != nil && time.Since(openSince) >= disarmAfter {
				onDisarm()
			} else {
				h.extendOpen() // keep flows on the direct path, don't lazily expire
			}
		}
	}
}

// probeEdge reports whether the Edge is reachable for steering: it establishes the (T) pinned mTLS tunnel AND
// exchanges a real request over it, so a success means steering will actually work, not merely that a TCP port is
// open. For the legacy plaintext path it does a bare TCP dial to the edge host. Used by the active health monitor.
func probeEdge(tc transportConfig, edgeURL string) bool {
	if tc.enabled {
		c, err := tc.dial(4 * time.Second)
		if err != nil {
			return false
		}
		defer c.Close()
		// A bare dial+close is NOT enough: under TLS 1.3 the client handshake completes before the server
		// verifies the client cert, so a REJECTED device cert (e.g. a revoked/untrusted identity — the Edge
		// rejects it post-handshake with a "bad certificate" alert) still looks "connected". That false positive
		// makes the breaker flap "edge_recovered" while every real flow fails. Exchange an actual request
		// (CONNECT /steer-mux) and require a valid HTTP response: a rejected cert makes the write/read fail, so
		// this cleanly separates a bad device cert from a reachable Edge.
		_ = c.SetDeadline(time.Now().Add(4 * time.Second))
		if _, err := io.WriteString(c, "CONNECT /steer-mux HTTP/1.1\r\nHost: "+tc.host+"\r\n\r\n"); err != nil {
			return false
		}
		_, _, err = readCONNECTStatus(bufio.NewReader(c))
		return err == nil
	}
	host, err := edgeHostPort(edgeURL)
	if err != nil {
		return false
	}
	c, err := net.DialTimeout("tcp", host, 4*time.Second)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}
