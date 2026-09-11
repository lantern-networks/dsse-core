import XCTest
@testable import DsseAppProxyProviderSkeleton

// A device with no agent-policy pin must still REPORT, and must still refuse to APPLY.
//
// Both halves matter and they pull in opposite directions, which is why this is pinned by a test rather than
// left to a comment. Reporting used to be gated on the pin, so an unpinned device sent nothing and the Edge
// could not tell it apart from a device that does not exist: on 2026-08-05 a Mac had been steering for weeks
// while the "observed on devices" view listed only the Windows box. Windows had already made the opposite
// call — its report loop is gated on the (T) transport and explicitly NOT on the pin, because a device
// carrying only local exclusions is the unmanaged case an operator most needs to see.
//
// Opening the report must not open enforcement with it. Reporting is observation; applying a policy is
// enforcement, and an unverified policy must never reach it.
//
// The first version of this file tested the poller's initialiser instead of the gate, and so passed both
// before and after the fix — it asserted something that was never broken. The rule now lives in
// DsseAgentReportingGate precisely so a test can reach the decision the provider actually makes.
final class DsseUnpinnedReportingTests: XCTestCase {

    // The regression itself: transport present, no pin. Reporting must be ON.
    func testUnpinnedDeviceWithTransportStillReports() {
        let gate = DsseAgentReportingGate.decide(hasTransport: true, pin: "")
        XCTAssertTrue(gate.mayReport,
            "an unpinned device must still report — otherwise the Edge cannot distinguish it from a device that does not exist")
        XCTAssertFalse(gate.mayApplySignedPolicy,
            "without a pin there is nothing to verify a signed policy against, so it must not be applied")
    }

    // Whitespace is not a pin. Trimming happens before the emptiness test, so a blank-looking value must not
    // unlock enforcement.
    func testWhitespacePinDoesNotUnlockEnforcement() {
        let gate = DsseAgentReportingGate.decide(hasTransport: true, pin: "  \n\t ")
        XCTAssertTrue(gate.mayReport)
        XCTAssertFalse(gate.mayApplySignedPolicy, "a whitespace pin must be treated as absent")
    }

    // A pinned device does both.
    func testPinnedDeviceReportsAndApplies() {
        let gate = DsseAgentReportingGate.decide(hasTransport: true, pin: String(repeating: "a", count: 64))
        XCTAssertTrue(gate.mayReport)
        XCTAssertTrue(gate.mayApplySignedPolicy)
    }

    // The one state where silence is correct: with no (T) transport the device cannot identify itself, so it
    // cannot report even in principle. It must say so rather than look like a device with nothing to say.
    func testNoTransportBlocksBothAndNamesTheReason() {
        let gate = DsseAgentReportingGate.decide(hasTransport: false, pin: String(repeating: "a", count: 64))
        XCTAssertFalse(gate.mayReport)
        XCTAssertFalse(gate.mayApplySignedPolicy)
        XCTAssertEqual(gate.blockedReason, "no_transport",
            "the blocked reason is what an operator reads in the log; it must name which of the two states this is")
    }

    // The other half of "must not apply": the verifier itself refuses an empty or malformed pin, so even if a
    // caller ignored the gate, no envelope could verify.
    func testEmptyOrMalformedPinCannotVerifyAnyPolicy() {
        let envelope = Data("""
        {"type":"dsse.agent_policy.v1","payload_b64":"eyJhIjoxfQ==","signature_b64":"AAAA"}
        """.utf8)
        for pin in ["", "   \n", "not-a-key"] {
            XCTAssertNil(
                DsseSignedAgentPolicy.verifiedServerExclusions(
                    envelopeData: envelope, pinnedPublicKeyHex: pin, alsoAccept: []),
                "pin \(pin.debugDescription) must verify nothing — reporting without a pin must not become applying without a pin")
        }
    }
}
