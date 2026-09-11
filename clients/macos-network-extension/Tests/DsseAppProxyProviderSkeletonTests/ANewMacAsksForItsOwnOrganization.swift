import XCTest
@testable import DsseAppProxyProviderSkeleton

// ★★★ A DEVICE THAT HAS ADOPTED NOTHING ASKED FOR NOBODY'S BUNDLE AND WAS GIVEN THE NODE'S (2026-08-29,
// measured on Windows by the session that walked hikari.lab, and true on this platform identically).
//
// advertisedTransportServerName is the name an ADOPTED bundle advertised — empty on a device that has never
// adopted one, which is every device on its first boot. The Edge answers a nameless request with its own
// organization, as it must, so a brand-new device of one organization adopts the DEPLOYMENT's interception
// root, logs "ADOPTED", and counts as provisioned with the wrong authority while every screen reads green.
//
// The name is in the signed install profile the device already holds and already verifies with the same pin.
// This asserts the fallback the fix rests on: the profile states it, and it survives verification.
final class ANewMacAsksForItsOwnOrganizationTests: XCTestCase {
    func testTheProfileStatesTheNameAFreshDeviceMustAskFor() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("dsse-ask-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        // A device on first boot: nothing adopted.
        XCTAssertTrue(DsseAdoptedTrustAnchorStore.advertisedTransportServerName(configDirectory: dir).isEmpty,
                      "a fresh device already advertises a name — this test is not measuring a fresh device")

        // Where the profile is looked for is the conventional place beside the configuration, so the
        // scheduler and the installer cannot disagree about it.
        let path = DsseInstallProfileApplication.profilePath(configured: nil, configDirectory: dir)
        XCTAssertEqual(URL(fileURLWithPath: path).lastPathComponent,
                       DsseInstallProfileApplication.defaultFileName)

        // ★ AND AN UNVERIFIABLE PROFILE YIELDS NOTHING. The fallback must not be a way to point a device at
        // an organization by dropping a file next to its configuration.
        try Data("not a profile".utf8).write(to: URL(fileURLWithPath: path))
        XCTAssertNil(DsseSignedInstallProfile.verifiedProfile(signedPath: path, pinnedPublicKeyHex: String(repeating: "ab", count: 32)),
                     "an unverifiable profile was accepted as the source of the name to ask for")
    }
}
