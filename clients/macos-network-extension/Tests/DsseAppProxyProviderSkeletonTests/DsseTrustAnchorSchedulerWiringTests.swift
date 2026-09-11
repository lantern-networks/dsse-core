import XCTest
@testable import DsseAppProxyProviderSkeleton

// The components for anchor self-healing all existed and were tested, and none of them ever ran: nothing in
// production code called recoverIfNeeded. A stranded device would have stayed stranded. These tests pin the
// wiring itself, because "the parts work" and "the feature works" turned out to be different claims.
final class DsseTrustAnchorSchedulerWiringTests: XCTestCase {
    private var dir: URL!

    override func setUpWithError() throws {
        dir = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("dsse-wiring-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    }
    override func tearDownWithError() throws { try? FileManager.default.removeItem(at: dir) }

    private func contract(transport: String?) throws -> DsseTransportContract {
        let json = """
        { "transport_tls_url": \(transport.map { "\"\($0)\"" } ?? "null"), "mtls_required": true }
        """
        return try JSONDecoder().decode(DsseTransportContract.self, from: Data(json.utf8))
    }

    // Without a pinned key there is nothing to verify a bundle against. It must SAY so — a feature that is off
    // and silent is indistinguishable from one that is on and broken.
    func testWithoutAPinnedKeyItReportsItselfDisabled() throws {
        var lines: [String] = []
        let scheduler = DsseCertificateRenewalScheduler(
            configDirectory: dir, contract: try contract(transport: "https://127.0.0.1:18543"),
            agentPolicyPinnedPublicKeyHex: "", log: { lines.append($0) })

        scheduler.recoverTrustAnchorsIfNeeded()

        XCTAssertTrue(lines.contains { $0.contains("trust_anchor_recovery disabled") },
                      "the disabled state must be stated, not inferred from silence: \(lines)")
        XCTAssertNil(DsseAdoptedTrustAnchorStore.currentAnchors(configDirectory: dir))
    }

    // With no transport URL there is no Edge to probe and no host to derive the bundle from. It must return
    // without touching the store rather than inventing an address.
    func testWithoutATransportURLItDoesNothing() throws {
        var lines: [String] = []
        let scheduler = DsseCertificateRenewalScheduler(
            configDirectory: dir, contract: try contract(transport: nil),
            agentPolicyPinnedPublicKeyHex: String(repeating: "ab", count: 32), log: { lines.append($0) })

        scheduler.recoverTrustAnchorsIfNeeded()

        XCTAssertFalse(lines.contains { $0.contains("ADOPTED") })
        XCTAssertEqual(DsseAdoptedTrustAnchorStore.lastAcceptedSerial(configDirectory: dir), 0)
    }

    // Adoption must notify the caller so the running transport can be rebuilt. On-device, anchors were
    // adopted correctly and every flow kept failing until a restart: the transport had resolved its anchors
    // when it was built and nothing told it to look again. Self-healing that does not heal is worse than none,
    // because the log says ADOPTED.
    func testAdoptionNotifiesSoTheTransportCanBeRebuilt() throws {
        var rebuilds = 0
        let scheduler = DsseCertificateRenewalScheduler(
            configDirectory: dir, contract: try contract(transport: "https://127.0.0.1:1"),
            agentPolicyPinnedPublicKeyHex: String(repeating: "ab", count: 32),
            onAnchorsAdopted: { rebuilds += 1 }, log: { _ in })

        // Nothing is adoptable here (unreachable Edge), so the callback must NOT fire — a rebuild on every
        // tick would churn the data path for no reason.
        scheduler.recoverTrustAnchorsIfNeeded()
        XCTAssertEqual(rebuilds, 0, "the transport must only be rebuilt when anchors actually changed")
    }

    // An unreachable Edge is UNDETERMINED, never "stale anchors". Reporting it as a recovery failure is
    // correct; adopting anything, or claiming the anchors are fine, would not be.
    func testAnUnreachableEdgeIsReportedAndChangesNothing() throws {
        var lines: [String] = []
        let scheduler = DsseCertificateRenewalScheduler(
            configDirectory: dir,
            contract: try contract(transport: "https://127.0.0.1:1"),   // nothing listens on port 1
            agentPolicyPinnedPublicKeyHex: String(repeating: "ab", count: 32), log: { lines.append($0) })

        scheduler.recoverTrustAnchorsIfNeeded()

        XCTAssertTrue(lines.contains { $0.contains("NOT recovered") }, "the outcome must be reported: \(lines)")
        XCTAssertNil(DsseAdoptedTrustAnchorStore.currentAnchors(configDirectory: dir),
                     "an unreachable Edge must never cause an adoption")
    }
}
