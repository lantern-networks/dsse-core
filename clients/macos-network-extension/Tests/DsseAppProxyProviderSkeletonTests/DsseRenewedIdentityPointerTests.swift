import XCTest
@testable import DsseAppProxyProviderSkeleton

// The pointer file is the renewal machinery's single commit point, and since the N-1 fallback it also names
// the previous generation. Two properties keep upgrades and rollbacks safe: a pointer written BEFORE the
// previous_* fields existed must keep decoding (as "no previous" — the pre-N-1 behaviour), and a pointer
// carrying them must round-trip exactly.
final class DsseRenewedIdentityPointerTests: XCTestCase {

    private func tempDir() throws -> URL {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("dsse-pointer-tests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    func testPreN1PointerFileStillDecodesAsNoPrevious() throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        // A verbatim pre-N-1 pointer file, as written by the shipped store.
        let legacy = """
        {
          "certificate_sha256" : "56617adf780576626d171737c765744227630b5f31a6930464ea873730700bed",
          "common_name" : "mac-dev-1",
          "installed_at" : "2026-08-02T01:34:44Z",
          "not_after" : "2026-10-01T01:34:44Z",
          "private_key_tag" : "dsse-device-key-20260802"
        }
        """
        try Data(legacy.utf8).write(to: dir.appendingPathComponent(DsseRenewedIdentityStore.pointerFileName))
        let pointer = DsseRenewedIdentityStore.readPointer(configDirectory: dir)
        XCTAssertNotNil(pointer, "a pre-N-1 pointer must keep decoding after the upgrade")
        XCTAssertEqual(pointer?.commonName, "mac-dev-1")
        XCTAssertNil(pointer?.previousCertificateSHA256, "absent fields read as no previous generation")
        XCTAssertNil(pointer?.previousPrivateKeyTag)
    }

    func testPointerWithPreviousGenerationRoundTrips() throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let written = DsseDeviceIdentityPointer(
            certificateSHA256: "aa".padding(toLength: 64, withPad: "a", startingAt: 0),
            privateKeyTag: "tag-current",
            commonName: "mac-dev-1",
            notAfter: Date(timeIntervalSince1970: 1_790_000_000),
            installedAt: Date(timeIntervalSince1970: 1_780_000_000),
            previousCertificateSHA256: "bb".padding(toLength: 64, withPad: "b", startingAt: 0),
            previousPrivateKeyTag: "tag-previous")
        try DsseRenewedIdentityStore.writePointer(written, configDirectory: dir)
        let read = DsseRenewedIdentityStore.readPointer(configDirectory: dir)
        XCTAssertEqual(read, written, "the commit-point file must round-trip the previous generation exactly")
    }

    func testPreviousIdentityWithoutPreviousFieldsIsQuietlyAbsent() throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        try DsseRenewedIdentityStore.writePointer(DsseDeviceIdentityPointer(
            certificateSHA256: "cc".padding(toLength: 64, withPad: "c", startingAt: 0),
            privateKeyTag: "tag", commonName: "mac-dev-1",
            notAfter: Date(), installedAt: Date()), configDirectory: dir)
        // No previous generation recorded: nil, and no keychain lookups attempted (nothing to look up).
        XCTAssertNil(DsseRenewedIdentityStore.previousIdentity(configDirectory: dir))
    }
}
