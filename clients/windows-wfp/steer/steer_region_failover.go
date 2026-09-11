// steer_region_failover.go — the PORTABLE driver that wires the platform-agnostic regionfailover engine to the
// steering agent's I/O (docs/multi_region_client_region_failover_design.md; handoff:
// docs/handoff_windows_wfp_region_failover.md). No OS build tag so the loop is unit-tested without Windows; the
// real probe + endpoint swap are injected (Windows supplies them in steer_region_failover_windows.go, tests stub
// them). This file owns the CONTROL LOOP and LIST REFRESH around the engine — never the selection rule, stickiness,
// hysteresis, or the fail-closed/residency invariants (those live in the engine, by design).
package main

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/lantern-networks/dsse-core/agentpolicy"
	"github.com/lantern-networks/dsse-core/regionfailover"
)

// regionFailoverActions are the platform side-effects the control loop drives. They are injected so the loop is
// unit-testable without Windows I/O, and are always invoked from the single control-loop goroutine (never
// concurrently with each other).
type regionFailoverActions struct {
	// switchTo makes the live (T) transport steer through ep (resolve it out of band + repoint EVERY consumer:
	// per-flow CONNECT dial, DNS-over-tunnel proxy, health probe). Called only when the selected region CHANGES.
	// An error means the new endpoint could not be made live; the loop logs and retries next round — it must NOT
	// bypass. While a switch is failing, the (now-degraded) prior endpoint's dials fail = deny, which is correct.
	switchTo func(ep regionfailover.RegionEndpoint) error
	// failClosed is invoked when NO healthy allowed region remains: steered egress is denied. With region failover
	// the agent runs fail-CLOSED (no --fail-open bypass), so deny is structural (dials to the unreachable region
	// fail); this hook is for logging/metrics and any explicit deny hardening. NEVER bypasses. Idempotent.
	failClosed func(reason string)
	// surfaceDenied is invoked when allowed regions are reachable but admission DENIED this device
	// (revoked/not-enrolled). Same deny as failClosed but a distinct, user-visible cause; the agent does NOT hunt
	// other regions (the engine already refuses to). Idempotent.
	surfaceDenied func(reason string)
	// connectedOK is invoked when the agent is (re)connected to a healthy region — announce/clear a prior deny.
	connectedOK func(ep regionfailover.RegionEndpoint)
}

// regionFailoverOptions configures the driver's I/O cadence and the signed list source.
type regionFailoverOptions struct {
	client  *http.Client // wired to the (T) mTLS transport (transportHTTPClient)
	baseURL string       // Edge base for GET /steer/region-endpoints (default: https://<transport-host>)
	pinHex  string       // pinned agent-policy Ed25519 key (same key/signer as steer-exclusions)
	// policyKeys (optional) returns the full set of signing keys this device accepts (pin plus any adopted from
	// a signed trust bundle), so a signing-key rotation does not strand a device on a stale region list.
	// nil => the pin alone, i.e. the behaviour before any set was published.
	policyKeys func() []string
	// regionPriority is the operator's install-time preference (region -> rank, lower preferred), applied by
	// LOOKUP onto every list this driver hands the engine — the seed AND each refreshed signed list. It is
	// applied HERE, in the two places a list enters, rather than at the call site, so a future third source
	// cannot quietly arrive unranked. nil = unconfigured. Production supplies it from the SIGNED install
	// profile (installprofile.InstallProfile.RegionPriority); the rule itself lives in regionfailover.
	regionPriority map[string]int
	// publishFleetServerName, when set, receives the transport name the signed list states this organization
	// presents at EVERY region — the fact that replaces the agent's old rule of falling silent about its
	// organization under failover. nil = the caller does not consume it (tests, and any build predating it).
	publishFleetServerName func(string)
	listRefresh            time.Duration // slow cadence to re-fetch the signed list (also triggered on network change)
	healthTick             time.Duration // cadence to re-probe + re-evaluate selection
	unhealthyStrike        int           // hysteresis: tolerate a degraded current region N rounds before failover
	probeParallel          int           // max concurrent endpoint probes per round (bounded; default 4)
	logf                   func(string, ...any)
}

// regionFailover is the live driver: the engine selector + the current allowed list + the injected probe/actions.
type regionFailover struct {
	sel      *regionfailover.Selector
	probeOne regionfailover.Probe // single-endpoint health probe (real on Windows; stub in tests)
	actions  regionFailoverActions
	opts     regionFailoverOptions

	mu      sync.Mutex // guards allowed (refresh goroutine vs. control loop read)
	allowed []regionfailover.RegionEndpoint

	lastState  regionfailover.State
	lastRegion string
	haveState  bool
	heldLogKey string // dedup: (region|kind) of the last-logged hold; a change (region OR benign->admission-deny) re-logs
}

func newRegionFailover(seed []regionfailover.RegionEndpoint, home string, probeOne regionfailover.Probe, actions regionFailoverActions, opts regionFailoverOptions) *regionFailover {
	if opts.logf == nil {
		opts.logf = func(string, ...any) {}
	}
	if opts.healthTick <= 0 {
		opts.healthTick = 5 * time.Second
	}
	if opts.listRefresh <= 0 {
		opts.listRefresh = 5 * time.Minute
	}
	if opts.probeParallel < 1 {
		opts.probeParallel = 4
	}
	// Rank the SEED too, not just the refreshed signed list. The seed is what the device steers by until the
	// first list fetch succeeds — and it is what it KEEPS if the Edge is unreachable, which can be indefinitely.
	// Ranking only the refreshed list would leave exactly the case this feature exists for (a lab where both
	// regions are the same machine, so RTT is jitter) decided by jitter for the whole bootstrap window.
	seed = regionfailover.ApplyPriority(seed, opts.regionPriority)
	sel := regionfailover.New(seed, home)
	if opts.unhealthyStrike > 0 {
		sel.SetUnhealthyStrikes(opts.unhealthyStrike)
	}
	// Endpoint agent: a persistent admission-deny on the current region is a device revocation — deny, don't
	// fail over to a region that may still admit the revoked device (kill-switch must not ride revocation skew).
	sel.SetDenyOnAdmissionDeny(true)
	// Instant revoke: a device revocation is not a transient blip — deny at the first probe instead of holding
	// through hysteresis, so the client recognizes the deny in ~one probe interval, not unhealthyStrike-1 rounds.
	// (The Edge blocks independently in ~2s regardless; this is client-side recognition speed.) UNREACHABLE
	// still gets hysteresis tolerance.
	sel.SetInstantRevokeOnAdmissionDeny(true)
	return &regionFailover{sel: sel, probeOne: probeOne, actions: actions, opts: opts, allowed: append([]regionfailover.RegionEndpoint(nil), seed...)}
}

// run drives the loop until ctx is cancelled. It refreshes the authoritative signed list once up front (falling
// back to the seed on failure), evaluates immediately, then re-evaluates on every health tick and on each
// failureEvent (a transport failure the data path reports), and refreshes the list on the slow cadence and
// whenever netChange fires. failureEvent / netChange may be nil.
func (r *regionFailover) run(ctx context.Context, failureEvent <-chan struct{}, netChange <-chan struct{}) {
	r.refreshList(ctx) // authoritative list if the Edge is reachable; otherwise keep the seed
	r.evaluateOnce(ctx)

	health := time.NewTicker(r.opts.healthTick)
	defer health.Stop()
	list := time.NewTicker(r.opts.listRefresh)
	defer list.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-health.C:
			r.evaluateOnce(ctx)
		case <-failureEvent:
			// A live transport failure — re-evaluate now rather than waiting for the next tick (fast failover).
			r.evaluateOnce(ctx)
		case <-list.C:
			r.refreshList(ctx)
		case <-netChange:
			// A network switch can change both proximity AND (via a residency-policy push) the allowed set.
			r.refreshList(ctx)
			r.evaluateOnce(ctx)
		}
	}
}

// refreshList fetches + verifies the signed allowed-region list and hands it to the engine. On ANY error it KEEPS
// the current list (fail-safe: never widen or drop the residency boundary on a bad/again-unreachable fetch).
func (r *regionFailover) refreshList(ctx context.Context) {
	if r.opts.client == nil || r.opts.baseURL == "" || r.opts.pinHex == "" {
		return // no authoritative source configured: run on the seed list only
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	keys := []string{r.opts.pinHex}
	if r.opts.policyKeys != nil {
		if published := r.opts.policyKeys(); len(published) > 0 {
			keys = published
		}
	}
	p, err := agentpolicy.FetchVerifiedRegionEndpointsWithKeys(cctx, r.opts.client, r.opts.baseURL, keys)
	if err != nil {
		r.opts.logf("region_failover: list refresh failed; keeping current allowed set: %v", err)
		return
	}
	next := regionfailover.ApplyPriority(toEngineEndpoints(p.AllowedRegionEndpoints), r.opts.regionPriority)
	if len(next) == 0 {
		r.opts.logf("region_failover: signed list is empty; keeping current allowed set (refusing an empty residency boundary)")
		return
	}
	r.mu.Lock()
	r.allowed = next
	r.mu.Unlock()
	r.sel.UpdateList(next, p.HomeRegion) // drops a now-out-of-boundary current region for us
	// ★ The fleet-wide name, if this list states one. Publishing it is what lets a FAILED-OVER device go on
	// presenting its organization instead of the region's own host name — see activeServerName, where the
	// absence of a name deliberately keeps the older, narrower rule. Published on every refresh, including
	// when it is empty: a deployment that stops stating a name means "the shared certificate", and a device
	// that kept the old one would keep asking for a certificate nobody serves.
	if r.opts.publishFleetServerName != nil {
		r.opts.publishFleetServerName(p.TransportServerName)
		if strings.TrimSpace(p.TransportServerName) != "" {
			r.opts.logf("region_failover: the signed list states this organization presents %q at every region, "+
				"so failing over no longer changes which name is sent", p.TransportServerName)
		}
	}
	r.opts.logf("region_failover: allowed regions refreshed: %d region(s), home=%q", len(next), p.HomeRegion)
}

// evaluateOnce probes the allowed regions (in parallel, bounded) and acts on the engine's decision.
func (r *regionFailover) evaluateOnce(ctx context.Context) {
	results := r.probeAll(ctx)
	dec := r.sel.Evaluate(func(ep regionfailover.RegionEndpoint) regionfailover.Health {
		// The engine iterates its own (identical) allowed set; we serve the pre-measured result. A missing entry
		// (should not happen) reads as the zero Health = unreachable, which is the safe (fail-closed) default.
		return results[ep.Region]
	})
	r.act(dec)
}

// probeAll measures every currently-allowed endpoint concurrently, bounded by probeParallel, and returns a
// region->Health map. Pre-measuring in parallel keeps the engine's per-endpoint Probe interface while honouring
// "probe the 2-3 regions in parallel, do not stampede".
func (r *regionFailover) probeAll(ctx context.Context) map[string]regionfailover.Health {
	r.mu.Lock()
	eps := append([]regionfailover.RegionEndpoint(nil), r.allowed...)
	r.mu.Unlock()

	results := make(map[string]regionfailover.Health, len(eps))
	var mu sync.Mutex
	sem := make(chan struct{}, r.opts.probeParallel)
	var wg sync.WaitGroup
	for _, ep := range eps {
		select {
		case <-ctx.Done():
			return results
		default:
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(ep regionfailover.RegionEndpoint) {
			defer wg.Done()
			defer func() { <-sem }()
			h := r.probeOne(ep)
			mu.Lock()
			results[ep.Region] = h
			mu.Unlock()
		}(ep)
	}
	wg.Wait()
	return results
}

// act applies the decision via the injected actions, transitioning the live transport only on a real change.
func (r *regionFailover) act(dec regionfailover.Decision) {
	switch dec.State {
	case regionfailover.StateConnected:
		// Observability for the accepted-risk hysteresis window (does NOT change failover behavior): when the
		// current region is DEGRADED but tolerated under hysteresis, the hold is otherwise silent. Log it once
		// per entry into the hold — loudly when it is an admission-deny (a revoked/not-enrolled device kept
		// steering through this region until the kill-switch takes effect). The Edge still denies this device
		// independently per connection. See docs/2026-07-26_region_failover_hysteresis_accepted_risk.ja.md.
		if dec.Held {
			// Dedup on (region|kind): log once per entry, but ALWAYS re-log when the region changes or a benign
			// unreachable hold ESCALATES to an admission-deny (revocation) — a single bool would swallow that.
			kind := "unreach"
			if dec.HeldAdmissionDenied {
				kind = "denied"
			}
			key := dec.Current.Region + "|" + kind
			if key != r.heldLogKey {
				if dec.HeldAdmissionDenied {
					secs := int(r.opts.healthTick.Seconds()) * dec.HeldRoundsRemaining
					r.opts.logf("region_failover: HOLDING admission-denied region %q under hysteresis (revoked/not-enrolled) "+
						"— failover suppressed for stability; client-side deny takes effect in <=%d more round(s) (~%ds). "+
						"The Edge still denies this device independently per connection.",
						dec.Current.Region, dec.HeldRoundsRemaining, secs)
				} else {
					r.opts.logf("region_failover: holding degraded (unreachable) region %q under hysteresis "+
						"— tolerating a transient blip; failover in <=%d more round(s).",
						dec.Current.Region, dec.HeldRoundsRemaining)
				}
				r.heldLogKey = key
			}
		} else {
			r.heldLogKey = "" // healthy again -> allow the next distinct hold to log
		}
		regionChanged := !r.haveState || dec.Current.Region != r.lastRegion
		if regionChanged {
			if err := r.actions.switchTo(dec.Current); err != nil {
				// Could not make the new endpoint live. Do NOT bypass; keep state so we retry next round. Dials to
				// the prior (degraded) endpoint fail = deny in the meantime, which is the safe posture.
				r.opts.logf("region_failover: switch to region %q (%s) failed; will retry: %v", dec.Current.Region, dec.Current.Endpoint, err)
				return
			}
			r.opts.logf("region_failover: steering through region %q (%s) — %s", dec.Current.Region, dec.Current.Endpoint, dec.Reason)
		}
		if r.lastState != regionfailover.StateConnected || regionChanged {
			r.actions.connectedOK(dec.Current)
		}
		r.lastState, r.lastRegion, r.haveState = regionfailover.StateConnected, dec.Current.Region, true
	case regionfailover.StateFailClosed:
		if !r.haveState || r.lastState != regionfailover.StateFailClosed {
			r.opts.logf("region_failover: FAIL-CLOSED — %s", dec.Reason)
			r.actions.failClosed(dec.Reason)
		}
		r.lastState, r.lastRegion, r.haveState = regionfailover.StateFailClosed, "", true
	case regionfailover.StateDenied:
		if !r.haveState || r.lastState != regionfailover.StateDenied {
			r.opts.logf("region_failover: DENIED — %s", dec.Reason)
			r.actions.surfaceDenied(dec.Reason)
		}
		r.lastState, r.lastRegion, r.haveState = regionfailover.StateDenied, "", true
	}
}

// toEngineEndpoints maps the signed-payload endpoints onto the engine's type (preserving server order, which is
// home-anchored). The engine re-normalizes (lowercase/dedupe), so this is a pure shape conversion.
func toEngineEndpoints(in []agentpolicy.RegionEndpoint) []regionfailover.RegionEndpoint {
	out := make([]regionfailover.RegionEndpoint, 0, len(in))
	for _, e := range in {
		out = append(out, regionfailover.RegionEndpoint{Region: e.Region, Endpoint: e.Endpoint})
	}
	return out
}
