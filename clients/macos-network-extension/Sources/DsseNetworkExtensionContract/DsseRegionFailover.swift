import Foundation

// DsseRegionFailover is the macOS Network Extension's client-side region selection + failover engine. The Edge
// hands the agent a list of transport endpoints (its allowed regions, already residency-filtered server-side);
// this engine measures each one's health and picks the nearest healthy region to steer through, failing over to
// another listed region when the current one degrades, and DENYING egress (fail-closed) when none are reachable.
//
// Residency is enforced by construction: the engine only ever considers the endpoints it was given, so it can
// never select a region the agent was not handed. It is the Swift counterpart of the Go `regionfailover` engine
// the Windows agent uses; the selection rule, stickiness, hysteresis, and fail-closed invariant are identical so
// both platforms behave the same.

public struct DsseRegionEndpoint: Equatable, Sendable {
    public let region: String
    public let endpoint: String
    /// The OPERATOR'S preference: lower is preferred, and it outranks measured latency.
    ///
    /// ★ Why preference beats measurement (2026-08-10). Selection used to be nearest-RTT-first with `home` only
    /// as an exact-tie break. On integer milliseconds that made the home anchor almost unreachable — and in the
    /// reference lab, where both regions are the same machine, the region a device landed on was decided by
    /// jitter. Widening the tie into a tolerance band was the wrong repair: tens of milliseconds is not noise to
    /// an application, it is several TLS round trips and every serialized request after them. So the operator's
    /// ordering is authoritative and RTT chooses only WITHIN one priority tier — which is where "pick the
    /// nearest PoP" belongs, among endpoints the operator called equally preferred.
    ///
    /// 0 = unspecified, ranked LAST. When nothing is specified everything ties and RTT decides as before, so an
    /// older Edge that does not send priorities keeps its current behaviour.
    public let priority: Int
    public init(region: String, endpoint: String, priority: Int = 0) {
        self.region = region
        self.endpoint = endpoint
        self.priority = priority
    }
}

/// Maps "unspecified" to the end of the order. Kept in one place so the unspecified case cannot be answered two
/// different ways; mirrors effectiveRegionPriority in the Go engine.
@inline(__always)
func dsseEffectiveRegionPriority(_ p: Int) -> Int { p <= 0 ? Int.max : p }

/// The result of probing one region endpoint (the agent supplies a real probe: out-of-band resolve + TCP + (T)
/// mTLS handshake; tests stub it).
public struct DsseRegionHealth: Sendable {
    /// The (T) transport answered (TCP + mTLS handshake completed). False = region down / unreachable.
    public let reachable: Bool
    /// This device was admitted (NOT a revoked / not-enrolled handshake rejection). Reachable-but-not-admitted is
    /// a DENY to surface, never a reason to fail over hunting for a region that admits a revoked device.
    public let admitted: Bool
    /// Measured round-trip in milliseconds (proximity) when reachable; ignored otherwise.
    public let rttMillis: Int
    public init(reachable: Bool, admitted: Bool, rttMillis: Int) {
        self.reachable = reachable
        self.admitted = admitted
        self.rttMillis = rttMillis
    }
    var healthy: Bool { reachable && admitted }
}

public enum DsseRegionState: String, Sendable {
    /// A healthy allowed region is selected (see DsseRegionDecision.current).
    case connected
    /// No healthy allowed region remains -> the agent DENIES egress (never reaches outside the boundary).
    case failClosed
    /// Allowed regions are reachable but admission DENIED this device (revoked / not-enrolled). Surface the deny;
    /// do NOT fail over (failover is for region health, never to evade a kill-switch).
    case denied
}

public struct DsseRegionDecision: Sendable {
    public let state: DsseRegionState
    /// The region to steer through (non-nil only when state == .connected).
    public let current: DsseRegionEndpoint?
    /// The ordered standby set of healthy ALTERNATE regions (nearest first).
    public let failoverSet: [DsseRegionEndpoint]
    public let reason: String

    // The held* fields are OBSERVABILITY ONLY — they annotate the decision and NEVER change selection
    // (state/current/failoverSet are identical with or without them). They surface the otherwise-silent
    // hysteresis window in which a DEGRADED current region is still steered through (.connected). For a
    // revocation (admission-deny), the device keeps steering through the current region for
    // heldRoundsRemaining more rounds before the deny takes effect — an accepted risk (stability over
    // instant revoke) that should still be observable. Byte-identical to the Go regionfailover engine;
    // see docs/2026-07-26_region_failover_hysteresis_accepted_risk.ja.md. Keep the two in lockstep.
    public let held: Bool
    public let heldAdmissionDenied: Bool
    public let heldRoundsRemaining: Int

    public init(state: DsseRegionState, current: DsseRegionEndpoint?, failoverSet: [DsseRegionEndpoint],
                reason: String, held: Bool = false, heldAdmissionDenied: Bool = false, heldRoundsRemaining: Int = 0) {
        self.state = state
        self.current = current
        self.failoverSet = failoverSet
        self.reason = reason
        self.held = held
        self.heldAdmissionDenied = heldAdmissionDenied
        self.heldRoundsRemaining = heldRoundsRemaining
    }
}

/// DsseRegionSelector is not thread-safe; the agent drives it from a single control loop.
public final class DsseRegionSelector {
    private var allowed: [DsseRegionEndpoint]
    // ★ `current` is sticky: NO FAIL-BACK WHILE RUNNING, by design (2026-08-10). A healthy current region is
    // kept even after a higher-priority one recovers, and RESTARTING the agent is the fail-back event — a fresh
    // selector has no current, so its first evaluate ranks by priority and the device homes on its best region.
    //
    // Returning as soon as the better region answers would move the WHOLE FLEET in one probe round, aiming a
    // reconnect storm at the region least able to absorb it: the one that just came back. Restarts spread that
    // for free (reboots, updates, sleep/wake), and the asymmetry makes the slow path free — failing OVER is
    // urgent because the user is blocked, failing BACK is not because the current region works.
    //
    // ★ It rests on NOTHING persisting the chosen region across a restart. Remembering it is an obvious-looking
    // optimisation whose cost is that the fleet never comes home, silently, with everything reporting healthy.
    // Mirrors the Go engine; see regionfailover/failback_test.go.
    private var home: String
    private var current: String = ""   // sticky current region id ("" = none selected yet)
    private var currentStrikes: Int = 0
    private var unhealthyStrikes: Int = 3
    // Opt-in: treat a PERSISTENT current-region admission-deny (reachable && !admitted surviving hysteresis) as
    // a deny, not a reason to fail over. Correct ONLY where !admitted means "this device is revoked" (the NE
    // endpoint agent enables it). OFF by default; byte-parity with the Go engine's denyOnAdmissionDeny (which
    // the Edge CP-endpoint selector must leave off, since there !Admitted means "not the CP leader" -> fail over).
    private var denyOnAdmissionDeny: Bool = false
    // Opt-in: deny a current-region admission-deny IMMEDIATELY (bypass the hysteresis hold). UNREACHABLE still
    // gets hysteresis. The NE endpoint agent enables it; byte-parity with the Go engine's instantRevokeOnAdmissionDeny.
    private var instantRevokeOnAdmissionDeny: Bool = false

    /// allowed is the residency-filtered, home-anchored list; home is the tiebreak/preferred region id.
    public init(allowed: [DsseRegionEndpoint], home: String) {
        self.allowed = DsseRegionSelector.normalize(allowed)
        self.home = home.lowercased().trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// How many consecutive unhealthy rounds the current region tolerates before failover (hysteresis). < 1 -> 1.
    public func setUnhealthyStrikes(_ n: Int) { unhealthyStrikes = max(1, n) }

    /// Opt into denying (not failing over) when the current region persistently admission-denies this device.
    /// The NE endpoint agent enables it (a revoked device must not ride cross-region revocation skew). Parity
    /// with the Go engine's SetDenyOnAdmissionDeny.
    public func setDenyOnAdmissionDeny(_ v: Bool) { denyOnAdmissionDeny = v }

    /// Opt into denying a current-region admission-deny IMMEDIATELY (no hysteresis hold). UNREACHABLE still
    /// gets hysteresis. Parity with the Go engine's SetInstantRevokeOnAdmissionDeny.
    public func setInstantRevokeOnAdmissionDeny(_ v: Bool) { instantRevokeOnAdmissionDeny = v }

    public var currentRegion: String { current }

    /// Replace the allowed list (a residency-policy change / list refresh). If the current region is no longer in
    /// the allowed set, it is DROPPED immediately — an out-of-boundary region can never remain current.
    public func updateList(allowed: [DsseRegionEndpoint], home: String) {
        self.allowed = DsseRegionSelector.normalize(allowed)
        // An EMPTY home from a list refresh means "the server has no opinion" — preserve the client's configured
        // home anchor instead of clearing it; a NON-EMPTY server home overrides. Byte-identical to the Go engine
        // (regionfailover.UpdateList); see that file for the rationale. Keep these two in lockstep.
        let refreshedHome = home.lowercased().trimmingCharacters(in: .whitespacesAndNewlines)
        if !refreshedHome.isEmpty {
            self.home = refreshedHome
        }
        if !current.isEmpty && !inAllowed(current) {
            current = ""
            currentStrikes = 0
        }
    }

    /// Probe the allowed regions and return the decision for this round, updating sticky/hysteresis state.
    public func evaluate(probe: (DsseRegionEndpoint) -> DsseRegionHealth) -> DsseRegionDecision {
        var results: [String: DsseRegionHealth] = [:]
        var healthy: [DsseRegionEndpoint] = []
        var anyDeniedAdmission = false
        for ep in allowed {
            let h = probe(ep)
            results[ep.region] = h
            if h.healthy {
                healthy.append(ep)
            } else if h.reachable && !h.admitted {
                anyDeniedAdmission = true
            }
        }
        rankHealthy(&healthy, results)

        // Stickiness + hysteresis on the current region.
        if !current.isEmpty {
            let cur = results[current]
            if cur?.healthy == true {
                currentStrikes = 0
                return connected(current, ranked: healthy, reason: "current region healthy (sticky)")
            }
            // Instant revoke (opt-in): a current-region ADMISSION-deny (reachable && !admitted) is a revocation,
            // not a transient blip — deny NOW without holding through hysteresis. A genuine UNREACHABLE still
            // gets the hysteresis tolerance below. Same per-consumer opt-in as denyOnAdmissionDeny. Byte-parity
            // with the Go engine.
            if instantRevokeOnAdmissionDeny, cur?.reachable == true, cur?.admitted == false {
                // STICKY deny: keep `current` pinned so the next evaluate re-denies rather than re-selecting a peer
                // that still admits a revoked device (byte-parity with the Go engine). Recovery is automatic
                // (healthy branch above) and an UNREACHABLE current still fails over via hysteresis below.
                currentStrikes = unhealthyStrikes
                return DsseRegionDecision(state: .denied, current: nil, failoverSet: [],
                    reason: "current region admission-denied (revoked/not-enrolled) — instant revoke (hysteresis bypassed for a revocation)")
            }
            currentStrikes += 1
            if currentStrikes < unhealthyStrikes {
                // Tolerate a transient blip: stay connected to the current region, do not flap. The decision is
                // unchanged (same state/current/failoverSet); we ONLY annotate the hold for observability so the
                // agent can surface this otherwise-silent window (esp. an admission-denied hold = delayed revoke).
                return connected(current, ranked: healthy, reason: "current degraded but within hysteresis",
                                 held: true,
                                 heldAdmissionDenied: (cur?.reachable == true && cur?.admitted == false),
                                 heldRoundsRemaining: unhealthyStrikes - currentStrikes)
            }
            // Threshold reached. If the current region has been ADMISSION-DENYING this device throughout the
            // hysteresis window (reachable && !admitted, not merely unreachable), that is a PERSISTENT deny —
            // a revocation, not a transient blip. Surface the deny; do NOT fail over to a region that may still
            // admit a revoked device whose revocation has not propagated there yet (a kill-switch must not be
            // evadable via cross-region revocation skew). Byte-parity with the Go engine; matches
            // DsseRegionHealth.admitted's contract. Only an unreachable current region fails over below.
            if denyOnAdmissionDeny, cur?.reachable == true, cur?.admitted == false {
                // STICKY deny (see instant-revoke branch): keep `current` pinned so the deny holds each round and
                // never re-selects an admitting peer. Byte-parity with the Go engine.
                currentStrikes = unhealthyStrikes
                return DsseRegionDecision(state: .denied, current: nil, failoverSet: [],
                    reason: "current region persistently denies admission (revoked/not-enrolled) — surfacing deny, not failing over to a region that may not yet have the revocation")
            }
            // Otherwise the current region is unreachable: fail over off it (health failover) below.
        }

        if let best = healthy.first {
            current = best.region
            currentStrikes = 0
            return connected(best.region, ranked: healthy, reason: "selected nearest healthy allowed region")
        }

        // No healthy allowed region: fail closed (or surface deny). Never cross the boundary.
        current = ""
        currentStrikes = 0
        if anyDeniedAdmission {
            return DsseRegionDecision(state: .denied, current: nil, failoverSet: [],
                reason: "allowed region(s) reachable but admission denied this device — surfacing deny, not failing over")
        }
        return DsseRegionDecision(state: .failClosed, current: nil, failoverSet: [],
            reason: "no healthy region within the residency boundary — denying egress")
    }

    private func connected(_ currentRegion: String, ranked: [DsseRegionEndpoint], reason: String,
                           held: Bool = false, heldAdmissionDenied: Bool = false, heldRoundsRemaining: Int = 0) -> DsseRegionDecision {
        var current: DsseRegionEndpoint?
        var failover: [DsseRegionEndpoint] = []
        for ep in ranked {
            if ep.region == currentRegion { current = ep } else { failover.append(ep) }
        }
        if current == nil { current = endpointFor(currentRegion) } // degraded-within-hysteresis: still report it
        return DsseRegionDecision(state: .connected, current: current, failoverSet: failover, reason: reason,
                                  held: held, heldAdmissionDenied: heldAdmissionDenied, heldRoundsRemaining: heldRoundsRemaining)
    }

    private func endpointFor(_ region: String) -> DsseRegionEndpoint {
        allowed.first(where: { $0.region == region }) ?? DsseRegionEndpoint(region: region, endpoint: "")
    }

    private func inAllowed(_ region: String) -> Bool { allowed.contains(where: { $0.region == region }) }

    /// Rank healthy endpoints by operator PRIORITY, then nearest RTT, then the home anchor, then original list
    /// order (stable/deterministic). Priority first: see DsseRegionEndpoint.priority.
    private func rankHealthy(_ healthy: inout [DsseRegionEndpoint], _ results: [String: DsseRegionHealth]) {
        var pos: [String: Int] = [:]
        for (i, ep) in allowed.enumerated() { pos[ep.region] = i }
        healthy.sort { a, b in
            let pa = dsseEffectiveRegionPriority(a.priority)
            let pb = dsseEffectiveRegionPriority(b.priority)
            if pa != pb { return pa < pb }
            let ra = results[a.region]?.rttMillis ?? Int.max
            let rb = results[b.region]?.rttMillis ?? Int.max
            if ra != rb { return ra < rb }
            if a.region == home { return true }
            if b.region == home { return false }
            return (pos[a.region] ?? Int.max) < (pos[b.region] ?? Int.max)
        }
    }

    private static func normalize(_ allowed: [DsseRegionEndpoint]) -> [DsseRegionEndpoint] {
        var out: [DsseRegionEndpoint] = []
        var seen = Set<String>()
        for ep in allowed {
            let region = ep.region.lowercased().trimmingCharacters(in: .whitespacesAndNewlines)
            let endpoint = ep.endpoint.trimmingCharacters(in: .whitespacesAndNewlines)
            if region.isEmpty || endpoint.isEmpty || seen.contains(region) { continue }
            seen.insert(region)
            // priority is CARRIED — the Go engine dropped it here first and the field went completely inert
            // (settable, readable, never ranked on). Enumerating fields is what lets a new one go missing.
            out.append(DsseRegionEndpoint(region: region, endpoint: endpoint, priority: ep.priority))
        }
        return out
    }
}
