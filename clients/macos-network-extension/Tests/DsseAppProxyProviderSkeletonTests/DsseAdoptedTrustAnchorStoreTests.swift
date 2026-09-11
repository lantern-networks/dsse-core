import XCTest
@testable import DsseAppProxyProviderSkeleton

// What a device writes down after adopting a signed trust bundle, and why each rule is there. The store is the
// only reason replay protection survives a restart: the comparison is against the highest bundle ever accepted,
// so forgetting that number makes an old bundle acceptable again and lets a withdrawn CA back in.
final class DsseAdoptedTrustAnchorStoreTests: XCTestCase {
    private var dir: URL!

    override func setUpWithError() throws {
        dir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("dsse-anchors-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: dir)
    }

    private func bundle(serial: Int64, anchors: String) -> DsseVerifiedTrustBundle {
        DsseVerifiedTrustBundle(anchorsPEM: anchors, interceptionRootSHA256: [], renewalRecoveryEndpoint: ":18545", serial: serial, tenantID: "t")
    }

    // Two CA certificates in the shape a mid-rotation bundle has (previous + next). Embedded rather than read
    // from disk: a test in the public OSS package must not depend on one machine's checkout.
    private func liveAnchorsPEM() throws -> String { DsseTestAnchors.twoCABundlePEM }

    func testAdoptingWritesAnchorsAndRemembersTheSerial() throws {
        let pem = try liveAnchorsPEM()
        XCTAssertEqual(DsseAdoptedTrustAnchorStore.lastAcceptedSerial(configDirectory: dir), 0,
                       "a device that has never adopted must report 0, not something that looks like an adoption")
        XCTAssertNil(DsseAdoptedTrustAnchorStore.currentAnchors(configDirectory: dir))

        let adopted = try DsseAdoptedTrustAnchorStore.install(bundle(serial: 5, anchors: pem), configDirectory: dir)
        XCTAssertEqual(adopted.serial, 5)
        XCTAssertEqual(adopted.fingerprints.count, 2)
        XCTAssertEqual(DsseAdoptedTrustAnchorStore.lastAcceptedSerial(configDirectory: dir), 5,
                       "the serial must survive; it is the whole basis of replay protection across a restart")
        let anchors = try XCTUnwrap(DsseAdoptedTrustAnchorStore.currentAnchors(configDirectory: dir))
        XCTAssertEqual(anchors.count, 2)
    }

    func testRefusesASerialThatDoesNotAdvance() throws {
        let pem = try liveAnchorsPEM()
        _ = try DsseAdoptedTrustAnchorStore.install(bundle(serial: 9, anchors: pem), configDirectory: dir)
        XCTAssertThrowsError(try DsseAdoptedTrustAnchorStore.install(bundle(serial: 9, anchors: pem), configDirectory: dir),
                             "re-adopting the same serial is a replay")
        XCTAssertThrowsError(try DsseAdoptedTrustAnchorStore.install(bundle(serial: 4, anchors: pem), configDirectory: dir),
                             "an older bundle must never be adopted — that is how a withdrawn CA comes back")
        XCTAssertEqual(DsseAdoptedTrustAnchorStore.lastAcceptedSerial(configDirectory: dir), 9,
                       "a refused adoption must not disturb what the device already holds")
    }

    func testRefusesAnUnusableAnchorSet() throws {
        XCTAssertThrowsError(try DsseAdoptedTrustAnchorStore.install(bundle(serial: 1, anchors: ""), configDirectory: dir),
                             "installing nothing would leave the device with no anchors at all")
        XCTAssertEqual(DsseAdoptedTrustAnchorStore.lastAcceptedSerial(configDirectory: dir), 0)
        XCTAssertNil(DsseAdoptedTrustAnchorStore.currentAnchors(configDirectory: dir))
    }

    // A pointer naming anchors that are not there must read as "nothing adopted", so the device falls back to
    // its provisioned anchors — the state it was already working in — instead of failing closed forever.
    func testAMissingAnchorFileReadsAsNothingAdopted() throws {
        let pem = try liveAnchorsPEM()
        _ = try DsseAdoptedTrustAnchorStore.install(bundle(serial: 2, anchors: pem), configDirectory: dir)
        try FileManager.default.removeItem(at: dir.appendingPathComponent(DsseAdoptedTrustAnchorStore.anchorsFileName))
        XCTAssertNil(DsseAdoptedTrustAnchorStore.currentAnchors(configDirectory: dir),
                     "nil means 'fall back'; an empty array would mean 'trust nothing' and strand the device")
        XCTAssertEqual(DsseAdoptedTrustAnchorStore.lastAcceptedSerial(configDirectory: dir), 2,
                       "the serial must still hold, or losing the anchor file would also lose replay protection")
    }

    // A crash during a RE-adoption writes the new anchors file (first) but not the new pointer (second), leaving
    // the NEW anchors beside the OLD pointer/serial. Because the adopted set REPLACES the provisioned one,
    // serving new anchors under the old serial would roll the replay guard back and let a withdrawn CA at an
    // intermediate serial be re-adopted. currentAnchors must instead read the torn pair as "nothing adopted" and
    // fall back to the provisioned anchors — the state the anchors-first/pointer-second order intends.
    func testATornAnchorPointerPairReadsAsNothingAdopted() throws {
        let pem = try liveAnchorsPEM()
        _ = try DsseAdoptedTrustAnchorStore.install(bundle(serial: 7, anchors: pem), configDirectory: dir)
        // The anchors file now holds a DIFFERENT set (only the first CA) than the pointer's two fingerprints —
        // exactly the state a crash between the two writes leaves behind on a re-adoption.
        let firstBlockEnd = pem.range(of: "-----END CERTIFICATE-----")!.upperBound
        let onlyFirstCA = String(pem[..<firstBlockEnd]) + "\n"
        try onlyFirstCA.write(to: dir.appendingPathComponent(DsseAdoptedTrustAnchorStore.anchorsFileName),
                              atomically: true, encoding: .utf8)

        XCTAssertNil(DsseAdoptedTrustAnchorStore.currentAnchors(configDirectory: dir),
                     "a torn anchors/pointer pair must read as 'fall back', not be served under the stale serial")
        XCTAssertEqual(DsseAdoptedTrustAnchorStore.lastAcceptedSerial(configDirectory: dir), 7,
                       "the serial still holds; only the mismatched anchor set is refused")

        // And the consistent pair still reads back — the check must not reject a correctly-written adoption.
        _ = try DsseAdoptedTrustAnchorStore.install(bundle(serial: 8, anchors: pem), configDirectory: dir)
        XCTAssertEqual(try XCTUnwrap(DsseAdoptedTrustAnchorStore.currentAnchors(configDirectory: dir)).count, 2)
    }
}
