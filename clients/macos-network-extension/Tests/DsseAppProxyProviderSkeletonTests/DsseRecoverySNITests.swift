import XCTest
@testable import DsseAppProxyProviderSkeleton

/// ★★ THE AGENT PLANE IS BEING FOLDED ONTO ONE PORT, AND THIS PLATFORM CAN CARRY HALF OF IT TODAY.
///
/// The Edge announces a recovery SNI so the expired-certificate renewal path can share the transport port. An
/// agent must reach an Edge on ONE port; this deployment publishes three, and on a real deployment all three
/// would be 443 on one address and collide.
///
/// What this asserts is the decision, not a wish: where the device WOULD dial when a name is announced, and
/// that it falls back to exactly what it did before when none is. The request itself still goes out on the
/// separate port, because URLSession sends the URL's host as the TLS server name and offers no way to send
/// another — that constraint is logged at the moment it applies rather than left for somebody to discover as
/// an announcement the fleet appears to ignore.
final class DsseRecoverySNITests: XCTestCase {
    // Built from JSON, the way the sibling test does: the contract is a decoded document, and constructing it
    // any other way would test a constructor this code never uses.
    private func contract(recovery: String?, transport: String?) -> DsseTransportContract {
        let json = """
        {
          "transport_tls_url": \(transport.map { "\"\($0)\"" } ?? "null"),
          "renewal_recovery_endpoint": \(recovery.map { "\"\($0)\"" } ?? "null")
        }
        """
        return try! JSONDecoder().decode(DsseTransportContract.self, from: Data(json.utf8))
    }

    func testABundleThatNamesNoRecoverySNIDialsExactlyWhatItDidBefore() throws {
        let dir = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        let dial = DsseCertificateRenewalScheduler.resolvedRecoveryDial(
            contract: contract(recovery: "10.0.0.5:18545", transport: "https://10.0.0.5:18543"),
            configDirectory: dir)
        XCTAssertEqual(dial?.endpoint, "10.0.0.5:18545")
        XCTAssertNil(dial?.serverName, "a device that was told no name must not invent one — it would ask an "
            + "Edge for a path it does not serve, at the moment it is already locked out")
    }

    func testWithNoRecoveryEndpointAndNoNameThereIsNowhereToRecover() throws {
        let dir = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        XCTAssertNil(DsseCertificateRenewalScheduler.resolvedRecoveryDial(
            contract: contract(recovery: nil, transport: "https://10.0.0.5:18543"), configDirectory: dir),
            "no endpoint and no name is a device that cannot recover, and saying so is what lets an operator "
            + "re-enrol it rather than wait for a recovery that was never possible")
    }
}

// ★ AND THE DEVICE MUST SAY WHICH RECOVERY NAME IT HOLDS (the fold's last steps, 2026-08-19).
//
// The Edge closes the dedicated recovery port only when every enrolled device has SAID it holds the name.
// Windows shipped the field first and this agent did not send it, so half the fleet was permanently silent —
// and silence keeps the port open forever, which is safe but never finishes. Omitted when empty, because a
// device that holds nothing must not claim to hold "".
final class DsseRecoverySNIReportTests: XCTestCase {
    func testTheReportCarriesTheNameOnlyWhenTheDeviceHoldsOne() throws {
        var body: [String: Any] = [:]
        DsseAgentPolicyPoller.attachRecoverySNI(&body, held: "Recovery.DSSE.Invalid")
        XCTAssertEqual(body["renewal_recovery_sni_sent"] as? String, "recovery.dsse.invalid",
                       "the name is reported lower-cased, as the Edge compares it")

        var none: [String: Any] = [:]
        DsseAgentPolicyPoller.attachRecoverySNI(&none, held: "  ")
        XCTAssertNil(none["renewal_recovery_sni_sent"],
                     "a device holding no name must be SILENT, not claim to hold an empty one — the Edge reads " +
                     "silence as not-yet and an empty claim would be a claim")
    }
}


// ★★★ AND WHERE THIS DEVICE WOULD ACTUALLY DIAL (2026-08-20, reported from win-dev-1).
//
// The Edge closed the dedicated recovery port on the evidence that both agents REPORT the recovery name.
// One of them reported it and would still have dialled the closed port, because holding a name and resolving
// a destination were two different pieces of code there. So the report now carries the resolved target, and
// the gate reads that instead — a name is a string, a target is a behaviour.
final class DsseRecoveryTargetReportTests: XCTestCase {
    func testTheReportCarriesWhereRecoveryWouldActuallyDial() throws {
        var body: [String: Any] = [:]
        DsseAgentPolicyPoller.attachRecoverySNI(&body, held: "recovery.dsse.invalid",
                                                resolvedTarget: "203.0.113.10:18543|Recovery.DSSE.Invalid")
        XCTAssertEqual(body["renewal_recovery_target"] as? String, "203.0.113.10:18543|recovery.dsse.invalid")

        var nameOnly: [String: Any] = [:]
        DsseAgentPolicyPoller.attachRecoverySNI(&nameOnly, held: "recovery.dsse.invalid", resolvedTarget: "  ")
        XCTAssertEqual(nameOnly["renewal_recovery_sni_sent"] as? String, "recovery.dsse.invalid")
        XCTAssertNil(nameOnly["renewal_recovery_target"],
                     "a device that cannot say where it resolves must stay SILENT on that question rather " +
                     "than let the name stand in for it — that substitution is the defect being fixed")
    }
}
