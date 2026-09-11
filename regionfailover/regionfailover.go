// Package regionfailover is the platform-agnostic ENGINE for client-side region selection and in-boundary
// failover (docs/multi_region_client_region_failover_design.md). The endpoint agents (macOS Network Extension /
// Windows WFP) drive it with REAL health probes (TCP + (T) mTLS handshake, resolved out of band) and act on its
// Decision (which region's transport to steer through / whether to fail closed). The selection rule, hysteresis,
// stickiness, and the fail-closed-never-cross-boundary invariant live here so they are unit-testable independent
// of any platform I/O.
//
// Residency is enforced by CONSTRUCTION: the engine only ever considers the endpoints it was given, and that list
// is the server's residency-filtered allowed-region list (GET /steer/region-endpoints). It can never select an
// out-of-boundary region because it is never handed one.
//
// Canonical home: the shared OSS module (github.com/lantern-networks/dsse-core/regionfailover) — NOT the
// proprietary dsse module — so BOTH consumers can import the SAME engine: the OSS Windows WFP steering agent
// (same module) and the proprietary Edge (via the dsse->dsse-core replace, like agentpolicy/decision). Go forbids
// a cross-module import of a dsse/internal/ package from dsse-core, which is why this lives here. The macOS NE has
// a hand-kept Swift port (DsseRegionFailover.swift) whose behavior must stay byte-for-byte identical to this.
package regionfailover

import (
	"math"
	"sort"
	"strings"
	"time"
)

// RegionEndpoint is one allowed region's transport endpoint (from the signed allowed_region_endpoints list).
type RegionEndpoint struct {
	Region   string
	Endpoint string
	// Priority is the OPERATOR'S preference: lower is preferred, and it outranks measured latency.
	//
	// ★ Why preference beats measurement (2026-08-10). Selection used to be nearest-RTT-first with the home
	// anchor only as an exact-tie break. On integer milliseconds that made "home" almost unreachable — and in
	// the reference lab, where both regions are the same machine, the region a device landed on was decided by
	// jitter. Widening the tie into a tolerance band was the wrong repair: tens of milliseconds is not noise to
	// an application, it is several TLS round trips and every serialized request after them. So the operator's
	// ordering is authoritative, and RTT chooses only WITHIN one priority tier — which is exactly where "pick
	// the nearest PoP" belongs, among endpoints the operator called equally preferred.
	//
	// 0 = unspecified, ranked LAST so an explicitly-preferred region always wins over one nobody ranked. When
	// nothing is specified every region is unspecified, they tie, and RTT decides as before — so an older
	// control plane that does not send priorities keeps its current behaviour.
	Priority int
}

// effectiveRegionPriority maps "unspecified" to the end of the order. Shared by both ranking paths so the
// unspecified case cannot be answered two ways.
func effectiveRegionPriority(p int) int {
	if p <= 0 {
		return math.MaxInt32
	}
	return p
}

// Health is the result of probing one region endpoint.
type Health struct {
	// Reachable: the (T) transport answered (TCP + mTLS handshake completed). False = region down / unreachable.
	Reachable bool
	// Admitted: this device was admitted (NOT a revoked / not-enrolled handshake rejection). When Reachable but
	// !Admitted, the region is UP but is denying THIS device — that is a deny to surface, never a reason to fail
	// over hunting for a region that admits a revoked device (failover is for health, not admission).
	Admitted bool
	// RTT is the measured round-trip (proximity) when Reachable; ignored otherwise.
	RTT time.Duration
}

func (h Health) healthy() bool { return h.Reachable && h.Admitted }

// Probe measures one endpoint's health. Injected by the agent (real = out-of-band resolve + TCP + mTLS); stubbed
// in tests. It must be bounded (the agent applies the connect timeout).
type Probe func(ep RegionEndpoint) Health

// State is the engine's output state.
type State int

const (
	// StateConnected: a healthy allowed region is selected (Decision.Current).
	StateConnected State = iota
	// StateFailClosed: NO healthy allowed region remains -> the agent DENIES egress (never crosses the boundary).
	StateFailClosed
	// StateDenied: allowed regions are reachable but admission DENIED this device (revoked / not-enrolled). The
	// agent surfaces deny; it does NOT fail over (failover is for region health, never to evade a kill-switch).
	StateDenied
)

func (s State) String() string {
	switch s {
	case StateConnected:
		return "connected"
	case StateFailClosed:
		return "fail_closed"
	case StateDenied:
		return "denied"
	default:
		return "unknown"
	}
}

// Decision is the engine's verdict for one evaluation round.
type Decision struct {
	State State
	// Current is the region to steer through (valid only when State == StateConnected).
	Current RegionEndpoint
	// FailoverSet is the ordered set of healthy ALTERNATE regions (nearest first), the standby targets.
	FailoverSet []RegionEndpoint
	// Reason is a short non-secret explanation (for agent logs).
	Reason string

	// The Held* fields are OBSERVABILITY ONLY — they annotate the decision and NEVER change selection
	// (State/Current/FailoverSet are identical with or without them). They exist so the agent can surface
	// the otherwise-silent hysteresis window in which a DEGRADED current region is still being steered
	// through (StateConnected). This matters for revocation: when the degradation is an admission-deny, the
	// device keeps steering through the current region for HeldRoundsRemaining more rounds before the deny
	// takes effect — an accepted risk (stability over instant revoke) that should still be observable.
	// See docs/2026-07-26_region_failover_hysteresis_accepted_risk.ja.md.
	//
	// Held is true when the current region failed its probe this round but is tolerated under hysteresis.
	Held bool
	// HeldAdmissionDenied distinguishes a revoked/not-enrolled hold (Reachable && !Admitted — the
	// kill-switch is being delayed) from a benign unreachable hold. Only meaningful when Held.
	HeldAdmissionDenied bool
	// HeldRoundsRemaining is how many more rounds the degraded region is tolerated before failover/deny
	// (unhealthyStrike - currentStrikes). Only meaningful when Held.
	HeldRoundsRemaining int
}

const defaultUnhealthyStrikes = 3

// Selector holds the allowed-region list + sticky current selection + hysteresis state. Not safe for concurrent
// use; the agent calls Evaluate from a single control loop.
type Selector struct {
	allowed []RegionEndpoint
	home    string
	// current is the sticky current region id ("" = none selected yet).
	//
	// ★ STICKY MEANS NO FAIL-BACK WHILE RUNNING, AND THAT IS THE DESIGN (2026-08-10). A healthy current region
	// is kept even after a higher-priority one recovers. Restarting the agent is the fail-back event: a fresh
	// Selector has no current, so its first Evaluate ranks by priority and the device homes on its best region.
	//
	// The alternative — returning as soon as the better region answers — moves the WHOLE FLEET at once, because
	// every device probes on the same interval and sees the recovery in the same round. The region least able
	// to absorb a reconnect storm is the one that has just come back, and if it buckles every device fails over
	// again in lockstep. Avoiding that by hand needs a stability hold-down plus a per-device stagger plus a
	// back-off on repeated returns: three mechanisms, each with its own failure mode.
	//
	// Restarts already provide the stagger, for free and better than any hash would: reboots, updates,
	// sleep/wake and logins are spread across a fleet by the real world. And the asymmetry that makes this
	// safe is that failing OVER is urgent (the current region is broken, the user is blocked) while failing
	// BACK is not (the current region works, nobody is waiting) — so the slow path costs nothing.
	//
	// The residual gap is named rather than hidden: a machine that never restarts stays on a lower-priority
	// region indefinitely. An agent update restarts it, which is the operator's lever.
	//
	// ★ THE PROPERTY THIS RESTS ON: nothing persists the chosen region across a restart. If a future change
	// remembers it — an obvious-looking optimisation — fail-back disappears silently and the fleet drifts to
	// whichever regions happened to be up during past blips, with everything reporting healthy. See
	// TestRestartIsTheFailBackEvent.
	current         string // sticky current region id ("" = none selected yet)
	currentStrikes  int    // consecutive unhealthy rounds for the current region (hysteresis)
	unhealthyStrike int    // threshold before failing over off a degraded current region

	// denyOnAdmissionDeny opts a consumer into treating a PERSISTENT current-region admission-deny
	// (Reachable && !Admitted surviving hysteresis) as a deny (StateDenied), NOT a reason to fail over.
	// This is correct ONLY where !Admitted means "this device is revoked/not-enrolled" — i.e. the endpoint
	// region-failover agents (macOS NE / Windows WFP), where a revoked device must not be moved to a region
	// that has not yet received the revocation. It is OFF by default because the SAME engine also drives the
	// Edge's CP-endpoint failover, where Admitted is OVERLOADED to mean "this region hosts the CP leader":
	// there a reachable-but-not-leader region (!Admitted) MUST be failed over (follow leadership), never denied.
	denyOnAdmissionDeny bool

	// instantRevokeOnAdmissionDeny STRENGTHENS denyOnAdmissionDeny: when set, a current-region admission-deny
	// (Reachable && !Admitted) returns StateDenied IMMEDIATELY on the first round — the hysteresis is bypassed
	// because a revocation is not a transient blip to absorb. A genuine UNREACHABLE (!Reachable) still gets the
	// full hysteresis tolerance (a network flap must not deny a valid device). Same per-consumer constraint as
	// denyOnAdmissionDeny: ON only where !Admitted means "revoked" (endpoint agents), OFF for the CP-endpoint
	// selector. Trade-off (why it is opt-in): a transient edge-admission hiccup denies the device for one round
	// until it recovers — the stability cost the hysteresis was there to avoid.
	instantRevokeOnAdmissionDeny bool
}

// SetDenyOnAdmissionDeny opts this selector into denying (not failing over) when the current region
// persistently admission-denies this device. Endpoint region-failover agents enable it (a revoked device
// must not ride cross-region revocation skew to an admitting region). Consumers where !Admitted does NOT
// mean "revoked" — notably the Edge CP-endpoint selector, where it means "not the leader" — must leave it OFF.
func (s *Selector) SetDenyOnAdmissionDeny(v bool) { s.denyOnAdmissionDeny = v }

// SetInstantRevokeOnAdmissionDeny opts this selector into denying a current-region admission-deny IMMEDIATELY
// (no hysteresis hold). Endpoint agents enable it so a revoked device's client recognizes the deny at the
// first probe instead of after unhealthyStrike-1 rounds. UNREACHABLE still gets hysteresis. Same per-consumer
// constraint as SetDenyOnAdmissionDeny (CP-endpoint selector leaves it OFF).
func (s *Selector) SetInstantRevokeOnAdmissionDeny(v bool) { s.instantRevokeOnAdmissionDeny = v }

// New builds a Selector over the residency-filtered, home-anchored allowed list (allowed[0] is the home anchor
// when home != ""). home is the tiebreak/preferred region id.
func New(allowed []RegionEndpoint, home string) *Selector {
	return &Selector{allowed: normalize(allowed), home: strings.ToLower(strings.TrimSpace(home)), unhealthyStrike: defaultUnhealthyStrikes}
}

// SetUnhealthyStrikes tunes how many consecutive unhealthy rounds the current region tolerates before failover
// (hysteresis / flap avoidance). <1 is treated as 1.
func (s *Selector) SetUnhealthyStrikes(n int) {
	if n < 1 {
		n = 1
	}
	s.unhealthyStrike = n
}

// UpdateList replaces the allowed-region list (a residency-policy change / list refresh). If the current region is
// no longer in the allowed set, it is DROPPED immediately — an out-of-boundary region can never remain current
// (flap avoidance + residency). Re-selection happens on the next Evaluate.
func (s *Selector) UpdateList(allowed []RegionEndpoint, home string) {
	s.allowed = normalize(allowed)
	// An EMPTY home from a list refresh means "the server has no opinion" — preserve the client's configured
	// home anchor (--region-home / the bootstrap seed home) instead of clearing it. A NON-EMPTY server home
	// overrides (the control plane is authoritative for the home anchor when it expresses one). Without this, a
	// signed list whose home_region is unset would erase the device's configured anchor and let the nearest-by
	// -list-order tiebreak decide. Parity: DsseRegionFailover.swift mirrors this exactly.
	if h := strings.ToLower(strings.TrimSpace(home)); h != "" {
		s.home = h
	}
	if s.current != "" && !s.inAllowed(s.current) {
		s.current = ""
		s.currentStrikes = 0
	}
}

// Current returns the sticky current region id ("" when none).
func (s *Selector) Current() string { return s.current }

// Evaluate probes the allowed regions and returns the decision for this round, updating sticky/hysteresis state.
//
// Rules (selection, hysteresis, residency):
//   - Stickiness: a HEALTHY current region is kept even if another is nearer (no flap on small RTT deltas).
//   - Hysteresis: a degraded current region is tolerated for unhealthyStrike rounds before failover.
//   - Selection: when (re)selecting, pick the nearest healthy region; ties -> home anchor -> list order.
//   - Fail-closed: no healthy allowed region -> StateFailClosed (deny) — NEVER an out-of-boundary region.
//   - Denied: no healthy but a reachable-yet-unadmitted region exists -> StateDenied (surface deny, don't hunt).
func (s *Selector) Evaluate(probe Probe) Decision {
	results := make(map[string]Health, len(s.allowed))
	var healthy []RegionEndpoint
	anyDeniedAdmission := false
	for _, ep := range s.allowed {
		h := probe(ep)
		results[ep.Region] = h
		if h.healthy() {
			healthy = append(healthy, ep)
		} else if h.Reachable && !h.Admitted {
			anyDeniedAdmission = true
		}
	}
	// Rank healthy: nearest RTT, then home anchor, then original list order.
	rankHealthy(healthy, results, s.home, s.allowed)

	// Stickiness + hysteresis on the current region.
	if s.current != "" {
		cur := results[s.current]
		if cur.healthy() {
			s.currentStrikes = 0
			return s.connected(s.current, healthy, "current region healthy (sticky)")
		}
		// Instant revoke (opt-in): a current-region ADMISSION-deny (Reachable && !Admitted) is a revocation, not
		// a transient blip — deny NOW without holding through hysteresis. A genuine UNREACHABLE still gets the
		// hysteresis tolerance below (a network flap must not deny a valid device). Same per-consumer opt-in as
		// denyOnAdmissionDeny (OFF for the CP-endpoint selector, where !Admitted means "not the leader").
		if s.instantRevokeOnAdmissionDeny && cur.Reachable && !cur.Admitted {
			// STICKY deny: keep s.current pinned (do NOT clear it) so the next Evaluate re-enters this block and
			// re-denies as long as the current region denies this device — never falling through to re-select a
			// peer that still admits a revoked device during revocation-propagation skew. Recovery is automatic:
			// if the region admits again the healthy branch above reconnects; if it goes UNREACHABLE the hysteresis
			// below fails over (health failover). Pin strikes at the threshold so it re-denies without re-holding.
			s.currentStrikes = s.unhealthyStrike
			return Decision{State: StateDenied, Reason: "current region admission-denied (revoked/not-enrolled) — instant revoke (hysteresis bypassed for a revocation)"}
		}
		s.currentStrikes++
		if s.currentStrikes < s.unhealthyStrike {
			// Tolerate a transient blip: stay CONNECTED to the current region, do not flap. The Decision is
			// unchanged (same State/Current/FailoverSet); we ONLY annotate the hold for observability so the
			// agent can surface this otherwise-silent window (esp. an admission-denied hold = delayed revoke).
			d := s.connected(s.current, healthy, "current degraded but within hysteresis")
			d.Held = true
			d.HeldAdmissionDenied = cur.Reachable && !cur.Admitted
			d.HeldRoundsRemaining = s.unhealthyStrike - s.currentStrikes
			return d
		}
		// Threshold reached. For a device region-failover agent (denyOnAdmissionDeny), if the current region has
		// been ADMISSION-DENYING this device throughout the hysteresis window (Reachable && !Admitted, not merely
		// unreachable), that is a PERSISTENT deny — a revocation/de-enrollment, not a transient blip the
		// hysteresis exists to absorb. Surface the deny and do NOT fail over: failover is for region HEALTH,
		// never a reason to hunt for a region that still admits a revoked device (its revocation may simply not
		// have propagated there yet — a kill-switch must not be evadable by riding cross-region revocation skew).
		// Matches Health.Admitted's contract and the "Denied" rule above. Only an UNREACHABLE current region
		// falls through to health failover below. Gated to opt-in because the CP-endpoint selector reuses this
		// engine with Admitted meaning "is the leader", where !Admitted must fail over (follow leadership).
		if s.denyOnAdmissionDeny && cur.Reachable && !cur.Admitted {
			// STICKY deny (see the instant-revoke branch above): keep s.current pinned so the deny holds each round
			// and never falls through to re-select an admitting peer. Pin strikes at the threshold so it re-denies
			// immediately without re-entering the hysteresis hold.
			s.currentStrikes = s.unhealthyStrike
			return Decision{State: StateDenied, Reason: "current region persistently denies admission (revoked/not-enrolled) — surfacing deny, not failing over to a region that may not yet have the revocation"}
		}
		// Otherwise the current region is unreachable: fail over off it (health failover) below.
	}

	if len(healthy) > 0 {
		best := healthy[0]
		s.current = best.Region
		s.currentStrikes = 0
		return s.connected(best.Region, healthy, "selected nearest healthy allowed region")
	}

	// No healthy allowed region: fail closed (or surface deny). Never cross the boundary.
	s.current = ""
	s.currentStrikes = 0
	if anyDeniedAdmission {
		return Decision{State: StateDenied, Reason: "allowed region(s) reachable but admission denied this device (revoked/not-enrolled) — surfacing deny, not failing over"}
	}
	return Decision{State: StateFailClosed, Reason: "no healthy region within the residency boundary — denying egress (never crossing the boundary)"}
}

// connected builds a StateConnected decision: Current = the chosen region, FailoverSet = the OTHER healthy regions
// in ranked order.
func (s *Selector) connected(currentRegion string, rankedHealthy []RegionEndpoint, reason string) Decision {
	var current RegionEndpoint
	var failover []RegionEndpoint
	for _, ep := range rankedHealthy {
		if ep.Region == currentRegion {
			current = ep
			continue
		}
		failover = append(failover, ep)
	}
	if current.Region == "" {
		// The current region is degraded-within-hysteresis (not in the healthy set this round); still report it.
		current = s.endpointFor(currentRegion)
	}
	return Decision{State: StateConnected, Current: current, FailoverSet: failover, Reason: reason}
}

func (s *Selector) endpointFor(region string) RegionEndpoint {
	for _, ep := range s.allowed {
		if ep.Region == region {
			return ep
		}
	}
	return RegionEndpoint{Region: region}
}

func (s *Selector) inAllowed(region string) bool {
	for _, ep := range s.allowed {
		if ep.Region == region {
			return true
		}
	}
	return false
}

// rankHealthy sorts healthy endpoints by operator PRIORITY, then nearest RTT, then home anchor, then original
// list order — stable so the outcome is deterministic. Priority first: see RegionEndpoint.Priority.
func rankHealthy(healthy []RegionEndpoint, results map[string]Health, home string, order []RegionEndpoint) {
	pos := make(map[string]int, len(order))
	for i, ep := range order {
		pos[ep.Region] = i
	}
	sort.SliceStable(healthy, func(i, j int) bool {
		if pi, pj := effectiveRegionPriority(healthy[i].Priority), effectiveRegionPriority(healthy[j].Priority); pi != pj {
			return pi < pj
		}
		ri, rj := results[healthy[i].Region].RTT, results[healthy[j].Region].RTT
		if ri != rj {
			return ri < rj
		}
		// Equal/unknown RTT -> home anchor wins, else original list order.
		if healthy[i].Region == home {
			return true
		}
		if healthy[j].Region == home {
			return false
		}
		return pos[healthy[i].Region] < pos[healthy[j].Region]
	})
}

func normalize(allowed []RegionEndpoint) []RegionEndpoint {
	out := make([]RegionEndpoint, 0, len(allowed))
	seen := map[string]bool{}
	for _, ep := range allowed {
		region := strings.ToLower(strings.TrimSpace(ep.Region))
		endpoint := strings.TrimSpace(ep.Endpoint)
		if region == "" || endpoint == "" || seen[region] {
			continue
		}
		seen[region] = true
		// Priority is CARRIED. It was dropped here when normalize only copied the two fields it knew about,
		// which made the field settable, readable and completely inert — the ranking never saw it. A struct
		// copy would have been immune; enumerating fields is what let a new one go missing silently.
		out = append(out, RegionEndpoint{Region: region, Endpoint: endpoint, Priority: ep.Priority})
	}
	return out
}
