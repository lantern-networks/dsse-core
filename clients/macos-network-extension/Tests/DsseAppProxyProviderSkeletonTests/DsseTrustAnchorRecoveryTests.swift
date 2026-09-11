import XCTest
@testable import DsseAppProxyProviderSkeleton

// The decision logic around self-healing. The dangerous mistakes here are not cryptographic — they are deciding
// to act on the wrong signal, or refusing to act when a device is genuinely stranded.
final class DsseTrustAnchorRecoveryTests: XCTestCase {
    private var dir: URL!
    private let liveBundle = Data("""
{\"type\":\"dsse_agent_steer_policy.v1\",\"version\":\"1\",\"signing_key_id\":\"edge-agent-policy-1685d085f8d5d59a\",\"created_at\":\"2026-07-29T20:50:28Z\",\"payload_sha256\":\"4931487e1ecf2932e114bab8f3dfe9043430b90a8c03ec9dfdb589fb59d00aee\",\"payload_b64\":\"eyJzY2hlbWFfdmVyc2lvbiI6ImRzc2UudHJ1c3QtYnVuZGxlLnYxIiwidGVuYW50X2lkIjoidGVuYW50X3RyYWNrX2FfdWMwM2FfbGFiIiwic2VyaWFsIjoxLCJpc3N1ZWRfYXQiOiIyMDI2LTA3LTI5VDIwOjUwOjI4WiIsInRyYW5zcG9ydF9jYV9wZW0iOiItLS0tLUJFR0lOIENFUlRJRklDQVRFLS0tLS1cbk1JSUJ2VENDQVdPZ0F3SUJBZ0lVWGM5T1NLOXp6UWdzcVhDQ2JQKy95T1VkUExvd0NnWUlLb1pJemowRUF3SXdcbklURWZNQjBHQTFVRUF3d1daRzl0WlhOMGFXTXRjM05sTFhSeVlXNXpjRzl5ZERBZUZ3MHlOakEzTVRjd016UTRcbk5UQmFGdzB5TnpBNE1UZ3dNelE0TlRCYU1DRXhIekFkQmdOVkJBTU1GbVJ2YldWemRHbGpMWE56WlMxMGNtRnVcbmMzQnZjblF3V1RBVEJnY3Foa2pPUFFJQkJnZ3Foa2pPUFFNQkJ3TkNBQVExNnVLKzJsV1VmQjNDbkZ4U0VvdElcbktvYUdkV1FmR21SanRIR21OT2tVMEROaDc3UWVKYTVISFdvWitDcWZ4YUlJSVJ3cUJneHI4UE5YejkzanBUK3Zcbm8za3dkekFQQmdOVkhSTUJBZjhFQlRBREFRSC9NQTRHQTFVZER3RUIvd1FFQXdJQ2hEQVRCZ05WSFNVRUREQUtcbkJnZ3JCZ0VGQlFjREFUQWdCZ05WSFJFRUdUQVhod1RBcUFFL2h3Ui9BQUFCZ2dsc2IyTmhiR2h2YzNRd0hRWURcblZSME9CQllFRkxVRG5pYkdyQ2pvdzNkYTkyQUsyR1hnQ3JxVU1Bb0dDQ3FHU000OUJBTUNBMGdBTUVVQ0lRREtcbldsOXlpenR5M0VGOGJ0anBOTkh3U1RoVmhJQjNKYllubTlsTk5vck16Z0lnWE5BbHBTT0VCVzJIYk9QdGhwWWlcblZ1V0EyNVVhOHE1Z1hMQll6SUplcWhVPVxuLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLVxuLS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tXG5NSUlCZXpDQ0FTS2dBd0lCQWdJUkFJTGhJRk13eTloaEZqZlBXdElkdmtnd0NnWUlLb1pJemowRUF3SXdIREVhXG5NQmdHQTFVRUF4TVJSRk5UUlNCVWNtRnVjM0J2Y25RZ1EwRXdIaGNOTWpZd056STVNVEExTXpJM1doY05Nell3XG5Oekk1TVRFMU16STNXakFjTVJvd0dBWURWUVFERXhGRVUxTkZJRlJ5WVc1emNHOXlkQ0JEUVRCWk1CTUdCeXFHXG5TTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCRlRSZERnYTZBSDAvZWFtTHFYQStzUHRXbXZPKy9XRWNZS3RHZ01VXG5UbUZFVkt3S05BQitQNUF3QkdEN0pUUk0zRDc3eGtmVGwvVVVGTGRhNXRRZUhwaWpSVEJETUE0R0ExVWREd0VCXG4vd1FFQXdJQmhqQVNCZ05WSFJNQkFmOEVDREFHQVFIL0FnRUJNQjBHQTFVZERnUVdCQlE0MXBiSnNUYXRtLzJhXG4rUzNkM0Z6dGFmVEJ4ekFLQmdncWhrak9QUVFEQWdOSEFEQkVBaUJCYjFiZ2FURDdaVkdYK1FocHhqdDdvMkdjXG54dHlYbHZPMitKSUYvTnlmVmdJZ2ZxNk9ZVlB3L29UYUhtYk5UZ2N1QzRRTlM4RllhaHh0S3ZMbTV3bFlHN3M9XG4tLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tXG4iLCJyZW5ld2FsX3JlY292ZXJ5X2VuZHBvaW50IjoiMTkyLjE2OC4xLjYzOjE4NTQ1In0=\",\"signature\":\"ed25519:DcmQ1IpecRJRjBFePCHxwpmOgNwpRXbI3PaRPeU2dufVF9aX-lu7KC4nKBn2c7oTTLNLMchcFhr_vVaWqNeRCA\"}
""".utf8)
    private let pinnedKey = "b408c812edcb3d4cafc72b6619c917aae7ddeb79f5cc63f2dc46e9204d7a5e57"

    override func setUpWithError() throws {
        dir = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("dsse-recover-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    }
    override func tearDownWithError() throws { try? FileManager.default.removeItem(at: dir) }

    // An unreachable Edge must NOT be read as stale anchors. Otherwise every device that loses signal starts
    // re-fetching trust material, and a network outage turns into fleet-wide trust churn.
    func testUnreachableEdgeIsNotTreatedAsAnAnchorFailure() {
        // Port 1 on localhost: nothing listens, so this fails to CONNECT rather than failing to verify.
        let outcome = DsseTrustAnchorRecovery.recoverIfNeeded(
            host: "127.0.0.1", port: 1, bundleURL: URL(string: "https://127.0.0.1:1/bootstrap/trust-bundle")!,
            configDirectory: dir, pinnedPublicKeyHex: pinnedKey,
            currentAnchors: DsseSignedTrustBundle.parseAnchors(readLiveAnchors()),
            fetchBundle: { _ in XCTFail("a bundle must not be fetched when the Edge was merely unreachable"); return nil })
        guard case .unrecovered(let reason) = outcome else {
            return XCTFail("expected unrecovered, got \(outcome)")
        }
        XCTAssertTrue(reason.contains("unreachable"), "the reason must name the real cause: \(reason)")
    }

    // With no anchors at all a device is definitively stranded, so it must look — this is the returning-from-a
    // -long-shutdown case, and refusing to act would leave it needing a human.
    func testAStrandedDeviceAdoptsAVerifiedBundle() throws {
        let outcome = DsseTrustAnchorRecovery.recoverIfNeeded(
            host: "127.0.0.1", port: 1, bundleURL: URL(string: "https://example.invalid/b")!,
            configDirectory: dir, pinnedPublicKeyHex: pinnedKey,
            currentAnchors: [],
            fetchBundle: { _ in self.liveBundle })
        guard case .adopted(let serial, let anchors) = outcome else {
            return XCTFail("expected adoption, got \(outcome)")
        }
        XCTAssertGreaterThan(serial, 0)
        XCTAssertEqual(anchors, 2)
        XCTAssertEqual(DsseAdoptedTrustAnchorStore.lastAcceptedSerial(configDirectory: dir), serial,
                       "the serial must be recorded, or the next replay would be accepted")
    }

    // A replay must not be adopted even though it is genuinely signed — the serial is the only thing that
    // distinguishes it, and this is the path an attacker who can serve anything would take.
    func testAReplayedBundleIsRefusedAndLeavesTheDeviceUnchanged() throws {
        _ = DsseTrustAnchorRecovery.recoverIfNeeded(
            host: "127.0.0.1", port: 1, bundleURL: URL(string: "https://example.invalid/b")!,
            configDirectory: dir, pinnedPublicKeyHex: pinnedKey, currentAnchors: [],
            fetchBundle: { _ in self.liveBundle })
        let accepted = DsseAdoptedTrustAnchorStore.lastAcceptedSerial(configDirectory: dir)

        let outcome = DsseTrustAnchorRecovery.recoverIfNeeded(
            host: "127.0.0.1", port: 1, bundleURL: URL(string: "https://example.invalid/b")!,
            configDirectory: dir, pinnedPublicKeyHex: pinnedKey, currentAnchors: [],
            fetchBundle: { _ in self.liveBundle })
        guard case .unrecovered = outcome else {
            return XCTFail("a replay of the accepted serial was adopted: \(outcome)")
        }
        XCTAssertEqual(DsseAdoptedTrustAnchorStore.lastAcceptedSerial(configDirectory: dir), accepted)
    }

    // A bundle signed by a key this device did not pin must change nothing at all.
    func testAnUnpinnedSignerChangesNothing() {
        var wrong = Array(pinnedKey); wrong[0] = wrong[0] == "a" ? "b" : "a"
        let outcome = DsseTrustAnchorRecovery.recoverIfNeeded(
            host: "127.0.0.1", port: 1, bundleURL: URL(string: "https://example.invalid/b")!,
            configDirectory: dir, pinnedPublicKeyHex: String(wrong), currentAnchors: [],
            fetchBundle: { _ in self.liveBundle })
        guard case .unrecovered = outcome else { return XCTFail("expected refusal, got \(outcome)") }
        XCTAssertNil(DsseAdoptedTrustAnchorStore.currentAnchors(configDirectory: dir))
    }

    private func readLiveAnchors() -> String { DsseTestAnchors.twoCABundlePEM }
}
