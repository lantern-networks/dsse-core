import Foundation

/// Whether the Edge this agent is talking to signs intercepted traffic under the certificate authority this
/// agent was INSTALLED with.
///
/// The agent configuration now carries `trusted_ca_bundle`, written by the Edge from the anchor actually in
/// force at install time. That pin is the point: an endpoint's trust is decided by the artifact it was
/// installed from rather than by whatever happens to be in the machine's trust store, so an agent built for
/// one organization cannot be talked onto another's authorities.
///
/// The reason it must be checked and not merely recorded: the dangerous case is not an unknown root — a root
/// the machine does not hold makes every HTTPS site fail immediately, which is loud. It is a root the machine
/// DOES hold for some other reason (an older deployment, another organization's MDM, an attacker who managed
/// an install). Then interception under the wrong authority succeeds, the browser is satisfied, the operator
/// sees traffic, and nothing looks wrong until somebody reads a certificate.
///
/// Three careful distinctions, each of which is a different mistake if collapsed:
///
///   - NO PIN is not a mismatch. Every configuration already in the field predates this field, and treating
///     its absence as a failure would strand the entire installed base. It behaves exactly as before.
///   - The EDGE NAMING NOTHING is not a mismatch either. It is unknown, and this module refuses to turn
///     silence into a verdict — the same care `DsseInterceptionRootTrust` already takes when it reports what
///     it found.
///   - An OVERLAP is a match. A certificate authority is replaced by announcing old and new together while
///     devices move across, so "the announced set contains my pin" is the question, never "the announced set
///     equals my pin". Demanding equality would make every rotation an outage, which is the surest way to
///     have the check disabled.
public enum DsseInterceptionRootPinDecision: Equatable, Sendable {
    /// This agent was installed without a pinned interception root. Behave exactly as before.
    case noPin
    /// The Edge named no interception root at all. Unknown, not wrong.
    case edgeNamedNoRoot
    /// The Edge signs under the authority this agent was installed with (possibly among others, mid-rotation).
    case satisfied
    /// The Edge signs under something else entirely.
    case mismatch(pinned: String, announced: [String])
}

extension DsseInterceptionRootPinDecision {
    /// A stable, SPACE-FREE token for the log line, and for whoever greps it.
    ///
    /// ★ THE DEFAULT DESCRIPTION BROKE ITS OWN VERIFICATION (2026-08-16). Logging the enum directly printed
    /// `decision=mismatch(pinned: "…", announced: ["…"])` — with spaces inside the value. The live check
    /// written to prove this control matched `decision=[^ ]*`, missed every mismatch line, and reported the
    /// PREVIOUS phase's verdict as the current one: the control worked and the evidence said nothing had
    /// happened. An operator's grep fails exactly the same way.
    ///
    /// The details still travel — as their own fields, where a space cannot hide them.
    public var logToken: String {
        switch self {
        case .noPin: return "no_pin"
        case .edgeNamedNoRoot: return "edge_named_no_root"
        case .satisfied: return "satisfied"
        case .mismatch: return "mismatch"
        }
    }
}

public enum DsseInterceptionRootPin {

    /// Decides from facts the caller has already gathered, so this stays testable without a trust store, a
    /// filesystem or an Edge.
    ///
    /// - Parameters:
    ///   - pinned: the interception-root fingerprint carried in this agent's install configuration
    ///     (`trusted_ca_bundle.interception_root_sha256`). Empty or absent means the agent was installed
    ///     before the field existed.
    ///   - announced: the interception roots the Edge says it signs under, from the signed agent policy or
    ///     the signed trust bundle. A LIST, because an overlap is the normal state of a replacement.
    public static func decide(pinned: String?, announced: [String]) -> DsseInterceptionRootPinDecision {
        let pin = (pinned ?? "").trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !pin.isEmpty else { return .noPin }
        let named = announced
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() }
            .filter { !$0.isEmpty }
        guard !named.isEmpty else { return .edgeNamedNoRoot }
        if named.contains(pin) { return .satisfied }
        return .mismatch(pinned: pin, announced: named)
    }

    /// What an operator reads when the agent stands aside. It has to name both sides and say what to do:
    /// "pin mismatch" alone sends someone hunting for a cause that is really a re-installation or a rotation
    /// that did not reach this machine.
    public static func mismatchOperatorMessage(pinned: String, announced: [String]) -> String {
        "this device was installed pinned to interception root \(pinned), and the Edge says it signs under " +
        "\(announced.joined(separator: ", ")) — traffic is NOT being steered or inspected. Either this agent " +
        "belongs to a different organization than the Edge it is pointed at, or an authority was replaced " +
        "without this machine receiving the new configuration. Re-install with this organization's " +
        "configuration (the Edge serves it at /admin/tenant-install-bundle/{tenant}), or have the Edge " +
        "announce the previous authority alongside the new one until this device has moved."
    }
}
