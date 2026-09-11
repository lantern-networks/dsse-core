import Foundation

/// When a device acquires its client identity, relative to the start of the provider.
///
/// ★★★ THE DEFECT THIS EXISTS TO END (2026-08-29, measured on a real Mac). `startProxy` armed every
/// identity-dependent subsystem — the runtime-copy transport, certificate renewal, the agent-policy poller,
/// the device heartbeat and region failover — and THEN ran the enrolment gate. On a device installed the
/// documented way (profile + package + token) the identity does not exist yet at that point, so all five
/// resolved "no (T) transport" and latched off. Enrolment succeeded 0.4 seconds later and re-armed nothing.
///
/// What that cost, from this Mac's own log (18:15:19 boot):
///   * `runtime copy` fell back to a plain URLSession, whose App Transport Security refuses the deployment's
///     private CA — 959 × `edge_round_trip_failed … NSURLErrorDomain code=-1200`. Every steered flow died and
///     the machine lost all TCP for half an hour, under a fail-closed posture that was working as designed.
///   * `device_heartbeat=disabled — the Edge will see this device as dark even while it steers`
///   * `agent_policy_poller=disabled reason=no_transport`
///   * `region_failover=disabled (no pin or no (T) transport)`
///
/// Every one of those lines was TRUE when it was written and FALSE half a second later. The rule below is the
/// one that was missing: an identity that arrives during startup must re-arm what was decided without it.
public enum DsseStartupIdentityArrival: Equatable, Sendable {
    /// The device already held a usable identity when the provider started (restart of an enrolled device).
    case alreadyPresent
    /// The device enrolled during this start and holds an identity it did not have a moment ago.
    case arrivedDuringStartup
    /// Registration failed on a previously managed device. Capture traffic and deny it until repaired.
    case enforcementBlocked
}

public enum DsseStartupArming {
    public static func afterEnrolmentFailure(wasEnrolledBefore: Bool) -> DsseStartupIdentityArrival? {
        wasEnrolledBefore ? .enforcementBlocked : nil
    }

    /// Whether the subsystems armed before the enrolment gate must be armed again.
    ///
    /// Deliberately not "arm twice, it is harmless": arming is what starts timers and picks the transport every
    /// steered flow rides, so the caller needs to say WHICH of the two states it is in, and be seen to.
    public static func mustRearmIdentityDependentSubsystems(after arrival: DsseStartupIdentityArrival) -> Bool {
        arrival == .arrivedDuringStartup
    }
}
