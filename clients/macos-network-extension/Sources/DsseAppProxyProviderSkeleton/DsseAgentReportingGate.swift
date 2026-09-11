import Foundation

// What an agent is allowed to do with the two capabilities that used to be one decision: REPORT what it is
// actually doing, and APPLY a policy the server signed.
//
// They were conflated. Reporting was gated on the agent-policy pin, so a device with no pin sent nothing —
// and from the Edge, a device that reports nothing is indistinguishable from a device that does not exist.
// On 2026-08-05 a Mac had been steering for weeks while the "observed on devices" view listed only the
// Windows box. Nothing was broken in the Console; this gate had quietly removed the Mac from the picture.
//
// The Windows agent had already separated them, and its reasoning is the one adopted here: a device carrying
// only local exclusions is precisely the unmanaged case an operator most needs to see, so the report is gated
// on the (T) transport — which the Edge needs to know WHICH device is speaking — and not on the pin.
//
// Splitting them into a value makes the rule checkable. The previous version of this rule lived inside a
// multi-clause `guard` in a private method, where a test could only reach it by standing up a whole provider;
// so nothing tested it, and its regression was found by reading a Console page rather than by a failing build.
public struct DsseAgentReportingGate: Equatable {
    /// The device can send reverse telemetry (effective exclusion set, posture, adopted trust serial).
    public let mayReport: Bool
    /// The device can fetch, verify and apply server-signed policy. Requires a pin: an unverified policy must
    /// never reach enforcement.
    public let mayApplySignedPolicy: Bool
    /// Set only when mayReport is false — the single reason, for a log line an operator can act on.
    public let blockedReason: String

    /// decide evaluates the two capabilities independently.
    ///
    /// - hasTransport: the (T) mTLS transport resolved. Without it the device cannot identify itself, so it
    ///   genuinely cannot report — this is the only state in which silence is correct.
    /// - pin: the configured agent-policy signing key. Empty is a normal, supported state.
    public static func decide(hasTransport: Bool, pin: String) -> DsseAgentReportingGate {
        let trimmed = pin.trimmingCharacters(in: .whitespacesAndNewlines)
        guard hasTransport else {
            return DsseAgentReportingGate(
                mayReport: false, mayApplySignedPolicy: false,
                blockedReason: "no_transport")
        }
        return DsseAgentReportingGate(
            mayReport: true, mayApplySignedPolicy: !trimmed.isEmpty, blockedReason: "")
    }
}
