package regionfailover

import (
	"testing"
	"time"
)

var (
	tok = RegionEndpoint{Region: "jp-tokyo", Endpoint: "https://tok:443"}
	osa = RegionEndpoint{Region: "jp-osaka", Endpoint: "https://osa:443"}
	ish = RegionEndpoint{Region: "jp-ishikari", Endpoint: "https://ish:443"}
)

func up(rttMS int) Health {
	return Health{Reachable: true, Admitted: true, RTT: time.Duration(rttMS) * time.Millisecond}
}
func down() Health        { return Health{Reachable: false} }
func deniedAdmit() Health { return Health{Reachable: true, Admitted: false, RTT: 5 * time.Millisecond} }

// probeFrom returns a Probe backed by a region->Health map; an absent region probes as down.
func probeFrom(m map[string]Health) Probe {
	return func(ep RegionEndpoint) Health {
		if h, ok := m[ep.Region]; ok {
			return h
		}
		return down()
	}
}

// nearest-healthy among allowed: with home=tokyo but osaka nearer, the agent lands on osaka, not home.
func TestNearestHealthyAmongAllowedNotHome(t *testing.T) {
	s := New([]RegionEndpoint{tok, osa, ish}, "jp-tokyo")
	d := s.Evaluate(probeFrom(map[string]Health{"jp-tokyo": up(50), "jp-osaka": up(10), "jp-ishikari": down()}))
	if d.State != StateConnected || d.Current.Region != "jp-osaka" {
		t.Fatalf("got state=%s current=%s, want connected jp-osaka (nearest, not the home anchor)", d.State, d.Current.Region)
	}
	if len(d.FailoverSet) != 1 || d.FailoverSet[0].Region != "jp-tokyo" {
		t.Fatalf("failover set = %v, want [jp-tokyo] (the other healthy region)", d.FailoverSet)
	}
}

// in-boundary failover: the current region dies, the agent reconnects to the next healthy ALLOWED region.
func TestInBoundaryFailover(t *testing.T) {
	s := New([]RegionEndpoint{tok, osa, ish}, "jp-tokyo")
	s.SetUnhealthyStrikes(1) // immediate failover for this test
	// Land on osaka (nearest).
	if d := s.Evaluate(probeFrom(map[string]Health{"jp-tokyo": up(50), "jp-osaka": up(10), "jp-ishikari": up(80)})); d.Current.Region != "jp-osaka" {
		t.Fatalf("setup: current=%s, want jp-osaka", d.Current.Region)
	}
	// Osaka dies -> fail over to the next healthy allowed region (tokyo, 50 < ishikari 80).
	d := s.Evaluate(probeFrom(map[string]Health{"jp-tokyo": up(50), "jp-osaka": down(), "jp-ishikari": up(80)}))
	if d.State != StateConnected || d.Current.Region != "jp-tokyo" {
		t.Fatalf("after osaka down: state=%s current=%s, want connected jp-tokyo", d.State, d.Current.Region)
	}
}

// fail closed when no in-boundary peer is healthy: deny, never reach outside the boundary.
func TestFailClosedWhenNoHealthyAllowed(t *testing.T) {
	s := New([]RegionEndpoint{tok, osa, ish}, "jp-tokyo")
	d := s.Evaluate(probeFrom(map[string]Health{"jp-tokyo": down(), "jp-osaka": down(), "jp-ishikari": down()}))
	if d.State != StateFailClosed {
		t.Fatalf("all regions down: state=%s, want fail_closed (deny, never cross the boundary)", d.State)
	}
	if d.Current.Region != "" {
		t.Fatalf("fail-closed must select NO region, got %s", d.Current.Region)
	}
}

// residency shrink: a list refresh that removes the current region drops it; re-select within the new set.
func TestResidencyShrinkDropsOutOfBoundaryCurrent(t *testing.T) {
	s := New([]RegionEndpoint{tok, osa, ish}, "jp-tokyo")
	s.SetUnhealthyStrikes(1)
	s.Evaluate(probeFrom(map[string]Health{"jp-osaka": up(10), "jp-tokyo": up(50)})) // current=osaka
	if s.Current() != "jp-osaka" {
		t.Fatalf("setup current=%s, want jp-osaka", s.Current())
	}
	// Residency policy shrinks to {tokyo, ishikari} — osaka is now out of boundary.
	s.UpdateList([]RegionEndpoint{tok, ish}, "jp-tokyo")
	if s.Current() != "" {
		t.Fatal("an out-of-boundary current region must be dropped on the list refresh")
	}
	// Even if osaka still probes healthy, it must NEVER be selected (not in the allowed list).
	d := s.Evaluate(probeFrom(map[string]Health{"jp-osaka": up(1), "jp-tokyo": up(50), "jp-ishikari": up(80)}))
	if d.Current.Region != "jp-tokyo" {
		t.Fatalf("after shrink: current=%s, want jp-tokyo (osaka excluded despite being healthy/nearest)", d.Current.Region)
	}
}

// An EMPTY home from a list refresh preserves the client's configured home anchor (server "no opinion"); a
// non-empty server home overrides it. home=osaka (NOT list[0]) so the tiebreak is distinguishable from list order.
func TestUpdateListEmptyHomePreservesConfiguredAnchor(t *testing.T) {
	s := New([]RegionEndpoint{tok, osa, ish}, "jp-osaka")
	// Refresh with an empty home (server didn't set home_region): the configured osaka anchor must survive.
	s.UpdateList([]RegionEndpoint{tok, osa, ish}, "")
	// Equal RTT => tie => home anchor wins. If the empty refresh had cleared home, list order would pick tokyo.
	d := s.Evaluate(probeFrom(map[string]Health{"jp-tokyo": up(10), "jp-osaka": up(10), "jp-ishikari": up(10)}))
	if d.Current.Region != "jp-osaka" {
		t.Fatalf("empty-home refresh: current=%s, want jp-osaka (configured anchor preserved, not cleared to list order)", d.Current.Region)
	}
	// A non-empty server home overrides the anchor.
	s2 := New([]RegionEndpoint{tok, osa, ish}, "jp-osaka")
	s2.UpdateList([]RegionEndpoint{tok, osa, ish}, "jp-ishikari")
	d2 := s2.Evaluate(probeFrom(map[string]Health{"jp-tokyo": up(10), "jp-osaka": up(10), "jp-ishikari": up(10)}))
	if d2.Current.Region != "jp-ishikari" {
		t.Fatalf("non-empty server home: current=%s, want jp-ishikari (server home overrides)", d2.Current.Region)
	}
}

// revocation is not evaded by failover: regions reachable but admission-denied => surface deny, don't hunt.
func TestAdmissionDeniedSurfacesDenyNotFailover(t *testing.T) {
	s := New([]RegionEndpoint{tok, osa, ish}, "jp-tokyo")
	d := s.Evaluate(probeFrom(map[string]Health{"jp-tokyo": deniedAdmit(), "jp-osaka": deniedAdmit(), "jp-ishikari": deniedAdmit()}))
	if d.State != StateDenied {
		t.Fatalf("all regions reachable-but-denied: state=%s, want denied (revoked device must not hunt for an admitting region)", d.State)
	}
	if d.Current.Region != "" {
		t.Fatalf("denied must select NO region, got %s", d.Current.Region)
	}
}

// Observability of the accepted-risk hysteresis window (WONT-FIX #14): an admission-deny on the
// ALREADY-CONNECTED current region is tolerated for unhealthyStrike-1 rounds. The engine keeps
// StateConnected (failover behavior UNCHANGED) but annotates the hold so the agent can surface the
// otherwise-silent, delayed revocation. See docs/2026-07-26_region_failover_hysteresis_accepted_risk.ja.md.
func TestHysteresisHoldAnnotatesAdmissionDenied(t *testing.T) {
	s := New([]RegionEndpoint{tok, osa, ish}, "jp-tokyo") // default unhealthyStrike = 3
	// Land on tokyo (only healthy).
	if d := s.Evaluate(probeFrom(map[string]Health{"jp-tokyo": up(50)})); d.Current.Region != "jp-tokyo" {
		t.Fatalf("setup: current=%s, want jp-tokyo", d.Current.Region)
	}
	// Tokyo (the current region) is now admission-DENIED (revoked), no other region healthy.
	// Strike 1 of 3: still StateConnected (behavior unchanged) but annotated as a held admission-deny.
	d := s.Evaluate(probeFrom(map[string]Health{"jp-tokyo": deniedAdmit()}))
	if d.State != StateConnected || d.Current.Region != "jp-tokyo" {
		t.Fatalf("hold: state=%s current=%s, want connected jp-tokyo (behavior unchanged during hysteresis)", d.State, d.Current.Region)
	}
	if !d.Held || !d.HeldAdmissionDenied {
		t.Fatalf("hold: Held=%v HeldAdmissionDenied=%v, want both true (revoked device held)", d.Held, d.HeldAdmissionDenied)
	}
	if d.HeldRoundsRemaining != 2 {
		t.Fatalf("hold: HeldRoundsRemaining=%d, want 2 (strike 1 of 3)", d.HeldRoundsRemaining)
	}
	// Strike 2 of 3: still held, one round left.
	d = s.Evaluate(probeFrom(map[string]Health{"jp-tokyo": deniedAdmit()}))
	if d.State != StateConnected || !d.Held || d.HeldRoundsRemaining != 1 {
		t.Fatalf("strike 2: state=%s held=%v remaining=%d, want connected/held/remaining=1", d.State, d.Held, d.HeldRoundsRemaining)
	}
	// Strike 3 reaches the threshold: the deny now takes effect (no healthy region, admission denied).
	d = s.Evaluate(probeFrom(map[string]Health{"jp-tokyo": deniedAdmit()}))
	if d.State != StateDenied {
		t.Fatalf("strike 3: state=%s, want denied (kill-switch takes effect at the threshold)", d.State)
	}
	if d.Held {
		t.Fatalf("a resolved deny must not be flagged as a hold: Held=%v", d.Held)
	}
}

// An UNREACHABLE hold is annotated but NOT flagged as an admission-deny (benign transient blip).
func TestHysteresisHoldUnreachableNotAdmissionDenied(t *testing.T) {
	s := New([]RegionEndpoint{tok, osa, ish}, "jp-tokyo")
	if d := s.Evaluate(probeFrom(map[string]Health{"jp-tokyo": up(50)})); d.Current.Region != "jp-tokyo" {
		t.Fatalf("setup: current=%s, want jp-tokyo", d.Current.Region)
	}
	d := s.Evaluate(probeFrom(map[string]Health{"jp-tokyo": down()}))
	if d.State != StateConnected || !d.Held {
		t.Fatalf("unreachable hold: state=%s held=%v, want connected/held", d.State, d.Held)
	}
	if d.HeldAdmissionDenied {
		t.Fatal("an unreachable hold must NOT be flagged as admission-denied")
	}
}

// A persistent admission-deny on the CURRENT region must NOT fail over to another region that still admits
// this (revoked) device — its revocation may simply not have propagated there yet. After the hysteresis window
// the engine surfaces StateDenied, never hunting for an admitting region (a kill-switch must not be evadable
// via cross-region revocation skew).
func TestCurrentRegionAdmissionDenyDeniesNotFailoverToAdmittingPeer(t *testing.T) {
	s := New([]RegionEndpoint{tok, osa, ish}, "jp-tokyo")
	s.SetUnhealthyStrikes(1)       // reach the threshold immediately
	s.SetDenyOnAdmissionDeny(true) // endpoint-agent semantics: !Admitted = revoked device
	// Land on tokyo.
	if d := s.Evaluate(probeFrom(map[string]Health{"jp-tokyo": up(50)})); d.Current.Region != "jp-tokyo" {
		t.Fatalf("setup: current=%s, want jp-tokyo", d.Current.Region)
	}
	// Tokyo (current) now DENIES this device (revoked here) while osaka still ADMITS it (revocation not yet
	// propagated to osaka). Must surface deny — NOT fail over to osaka.
	d := s.Evaluate(probeFrom(map[string]Health{"jp-tokyo": deniedAdmit(), "jp-osaka": up(10), "jp-ishikari": down()}))
	if d.State != StateDenied {
		t.Fatalf("current-region admission-deny with an admitting peer: state=%s current=%s, want denied (never hunt for a region that admits a revoked device)", d.State, d.Current.Region)
	}
	if d.Current.Region != "" {
		t.Fatalf("denied must select NO region, got %s (would have evaded revocation via osaka)", d.Current.Region)
	}
}

// Instant revoke (opt-in): a current-region admission-deny denies IMMEDIATELY on the first probe — no
// hysteresis hold — while a genuine UNREACHABLE still gets the full hysteresis tolerance.
func TestInstantRevokeOnAdmissionDenyDeniesAtStrikeOne(t *testing.T) {
	s := New([]RegionEndpoint{tok, osa, ish}, "jp-tokyo") // default unhealthyStrike = 3
	s.SetInstantRevokeOnAdmissionDeny(true)
	if d := s.Evaluate(probeFrom(map[string]Health{"jp-tokyo": up(50)})); d.Current.Region != "jp-tokyo" {
		t.Fatalf("setup: current=%s, want jp-tokyo", d.Current.Region)
	}
	// Admission-deny on the current region: deny NOW (strike 1), not held.
	d := s.Evaluate(probeFrom(map[string]Health{"jp-tokyo": deniedAdmit()}))
	if d.State != StateDenied {
		t.Fatalf("instant revoke: state=%s, want denied on the first admission-deny round (no hold)", d.State)
	}
	if d.Held {
		t.Fatalf("instant revoke must NOT hold: Held=%v", d.Held)
	}
}

// STICKY deny: once the current region admission-denies, the deny holds on EVERY subsequent round — the
// revoked device must never reconnect to a peer that still admits it (revocation-propagation skew). Covers
// both shipping configs (instant-revoke, and deny-on-admission-deny at the threshold). Recovery: when the
// region admits again, it reconnects.
func TestAdmissionDenyIsStickyNoReconnectToAdmittingPeer(t *testing.T) {
	for _, tc := range []struct {
		name      string
		configure func(*Selector)
	}{
		{"instant-revoke", func(s *Selector) { s.SetInstantRevokeOnAdmissionDeny(true) }},
		{"deny-at-threshold", func(s *Selector) { s.SetDenyOnAdmissionDeny(true); s.SetUnhealthyStrikes(1) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := New([]RegionEndpoint{tok, osa, ish}, "jp-tokyo")
			tc.configure(s)
			if d := s.Evaluate(probeFrom(map[string]Health{"jp-tokyo": up(50)})); d.Current.Region != "jp-tokyo" {
				t.Fatalf("setup: current=%s, want jp-tokyo", d.Current.Region)
			}
			// tokyo revokes; osaka still admits (skew). Deny must hold for MANY rounds — never ride to osaka.
			revoked := probeFrom(map[string]Health{"jp-tokyo": deniedAdmit(), "jp-osaka": up(10), "jp-ishikari": up(80)})
			for round := 1; round <= 5; round++ {
				d := s.Evaluate(revoked)
				if d.State != StateDenied {
					t.Fatalf("round %d: state=%s current=%s, want denied (must not reconnect to admitting peer osaka)", round, d.State, d.Current.Region)
				}
			}
			// Recovery: tokyo admits again -> reconnect (not stuck denied forever).
			d := s.Evaluate(probeFrom(map[string]Health{"jp-tokyo": up(50), "jp-osaka": up(10)}))
			if d.State != StateConnected || d.Current.Region != "jp-tokyo" {
				t.Fatalf("recovery: state=%s current=%s, want connected jp-tokyo (re-admitted device reconnects)", d.State, d.Current.Region)
			}
		})
	}
}

// Instant revoke is SPECIFIC to admission denials: a genuine UNREACHABLE current region still gets the
// hysteresis tolerance (a network flap must not deny a valid device on the first miss).
func TestInstantRevokeStillHoldsOnUnreachable(t *testing.T) {
	s := New([]RegionEndpoint{tok, osa}, "jp-tokyo")
	s.SetInstantRevokeOnAdmissionDeny(true)
	s.SetUnhealthyStrikes(3)
	if d := s.Evaluate(probeFrom(map[string]Health{"jp-tokyo": up(50)})); d.Current.Region != "jp-tokyo" {
		t.Fatalf("setup: current=%s, want jp-tokyo", d.Current.Region)
	}
	// Tokyo unreachable, osaka down: within hysteresis, hold tokyo (do NOT instant-deny an unreachable blip).
	d := s.Evaluate(probeFrom(map[string]Health{"jp-tokyo": down()}))
	if d.State != StateConnected || !d.Held || d.HeldAdmissionDenied {
		t.Fatalf("unreachable round 1: state=%s held=%v admDenied=%v, want connected/held/not-admission-denied", d.State, d.Held, d.HeldAdmissionDenied)
	}
}

// DEFAULT (deny-on-admission-deny OFF): the SAME engine drives the Edge CP-endpoint selector, where
// !Admitted means "not the CP leader" — a reachable-but-not-leader current region MUST fail over to the
// leader, never be denied. This guards the overloaded-Admitted semantics the CP selector depends on.
func TestCurrentRegionNotAdmittedFailsOverWhenDenyOptionOff(t *testing.T) {
	s := New([]RegionEndpoint{tok, osa, ish}, "jp-tokyo")
	s.SetUnhealthyStrikes(1) // deny option left OFF (default) — CP-endpoint-selector semantics
	if d := s.Evaluate(probeFrom(map[string]Health{"jp-tokyo": up(50)})); d.Current.Region != "jp-tokyo" {
		t.Fatalf("setup: current=%s, want jp-tokyo", d.Current.Region)
	}
	// tokyo is reachable-but-not-admitted (e.g. lost CP leadership); osaka is admitted (the new leader).
	d := s.Evaluate(probeFrom(map[string]Health{"jp-tokyo": deniedAdmit(), "jp-osaka": up(10), "jp-ishikari": down()}))
	if d.State != StateConnected || d.Current.Region != "jp-osaka" {
		t.Fatalf("deny-option OFF: state=%s current=%s, want connected jp-osaka (follow leadership / fail over)", d.State, d.Current.Region)
	}
}

// Contrast: a current region that goes UNREACHABLE (not admission-denied) still fails over normally — the
// deny-not-failover rule is specific to admission denials, health failover is unaffected.
func TestCurrentRegionUnreachableStillFailsOver(t *testing.T) {
	s := New([]RegionEndpoint{tok, osa, ish}, "jp-tokyo")
	s.SetUnhealthyStrikes(1)
	s.SetDenyOnAdmissionDeny(true)
	if d := s.Evaluate(probeFrom(map[string]Health{"jp-tokyo": up(50)})); d.Current.Region != "jp-tokyo" {
		t.Fatalf("setup: current=%s, want jp-tokyo", d.Current.Region)
	}
	d := s.Evaluate(probeFrom(map[string]Health{"jp-tokyo": down(), "jp-osaka": up(10), "jp-ishikari": down()}))
	if d.State != StateConnected || d.Current.Region != "jp-osaka" {
		t.Fatalf("current unreachable: state=%s current=%s, want connected jp-osaka (health failover unaffected)", d.State, d.Current.Region)
	}
}

// no flap: a healthy current region is kept even when another becomes nearer (stickiness).
func TestStickinessNoFlapOnSmallRTTDelta(t *testing.T) {
	s := New([]RegionEndpoint{tok, osa, ish}, "jp-tokyo")
	// Land on tokyo (only healthy initially).
	s.Evaluate(probeFrom(map[string]Health{"jp-tokyo": up(50)}))
	if s.Current() != "jp-tokyo" {
		t.Fatalf("setup current=%s, want jp-tokyo", s.Current())
	}
	// Now osaka is healthy AND nearer — but tokyo is still healthy, so we must NOT flap.
	d := s.Evaluate(probeFrom(map[string]Health{"jp-tokyo": up(50), "jp-osaka": up(10)}))
	if d.Current.Region != "jp-tokyo" {
		t.Fatalf("flapped to %s; a healthy current region must stick despite a nearer alternative", d.Current.Region)
	}
}

// Hysteresis: a degraded current region is tolerated for N-1 rounds (stays CONNECTED), failing over on the Nth.
func TestHysteresisToleratesTransientThenFailsOver(t *testing.T) {
	s := New([]RegionEndpoint{tok, osa}, "jp-tokyo")
	s.SetUnhealthyStrikes(3)
	s.Evaluate(probeFrom(map[string]Health{"jp-tokyo": up(50)})) // current=tokyo
	downTok := probeFrom(map[string]Health{"jp-tokyo": down(), "jp-osaka": up(10)})
	for round := 1; round <= 2; round++ {
		d := s.Evaluate(downTok)
		if d.State != StateConnected || d.Current.Region != "jp-tokyo" {
			t.Fatalf("round %d: state=%s current=%s, want still connected jp-tokyo (within hysteresis)", round, d.State, d.Current.Region)
		}
	}
	d := s.Evaluate(downTok) // 3rd strike -> failover
	if d.State != StateConnected || d.Current.Region != "jp-osaka" {
		t.Fatalf("3rd strike: state=%s current=%s, want failover to jp-osaka", d.State, d.Current.Region)
	}
}

// Recovery: after fail-closed, the agent returns to CONNECTED when an allowed region recovers.
func TestRecoversFromFailClosed(t *testing.T) {
	s := New([]RegionEndpoint{tok, osa}, "jp-tokyo")
	if d := s.Evaluate(probeFrom(map[string]Health{})); d.State != StateFailClosed {
		t.Fatalf("want fail_closed, got %s", d.State)
	}
	d := s.Evaluate(probeFrom(map[string]Health{"jp-osaka": up(10)}))
	if d.State != StateConnected || d.Current.Region != "jp-osaka" {
		t.Fatalf("recovery: state=%s current=%s, want connected jp-osaka", d.State, d.Current.Region)
	}
}
