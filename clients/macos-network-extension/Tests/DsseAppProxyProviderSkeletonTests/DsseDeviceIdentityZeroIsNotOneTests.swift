import XCTest
@testable import DsseAppProxyProviderSkeleton

/// A device that holds a pointer and NO identity must not be reported as healthy.
///
/// ★★★ THE LINE THAT MISLED A DIAGNOSIS (2026-08-29). On a real Mac whose private key had gone with the
/// system extension, this report printed "exactly one identity in force, no leftovers" — and it was read, by
/// a person and by an agent, as proof the device could prove its name. It could not: enrolment came back 403
/// "already enrolled", renewal needs possession of a key that no longer exists, and nothing steered.
final class DsseDeviceIdentityZeroIsNotOneTests: XCTestCase {
    private func facts(_ cn: String, _ sha: String) -> DsseIdentityFacts {
        DsseIdentityFacts(certificateSHA256: sha, subjectCommonName: cn,
                          issuerCommonName: "Momiji Logistics Device Identity CA",
                          notAfter: Date(timeIntervalSinceNow: 86_400 * 30))
    }

    func testNoIdentityIsNeverReportedAsOneInForce() {
        let out = DsseDeviceIdentityOrphans.lines(all: [facts("SomeoneElse-mac", "ff")],
                                                  deviceCommonName: "ShinnoMac-mini",
                                                  inForceFingerprint: "aa", now: Date())
        XCTAssertTrue(out.contains { $0.contains("NO IDENTITY") },
                      "a device with no identity of its own must say so: \(out)")
        XCTAssertFalse(out.contains { $0.contains("no leftovers") },
                       "the clean bill of health must not be issued to a device that holds nothing: \(out)")
    }

    func testOneIdentityAndNoLeftoversSaysHowManyItCounted() {
        let out = DsseDeviceIdentityOrphans.lines(all: [facts("ShinnoMac-mini", "aa")],
                                                  deviceCommonName: "ShinnoMac-mini",
                                                  inForceFingerprint: "aa", now: Date())
        XCTAssertEqual(out.count, 1)
        XCTAssertTrue(out[0].contains("identities=1"), out[0])
        XCTAssertTrue(out[0].contains("no leftovers"), out[0])
    }

    func testAPointerNamingSomethingTheKeychainDoesNotHoldIsCalledOut() {
        let out = DsseDeviceIdentityOrphans.lines(all: [facts("ShinnoMac-mini", "bb")],
                                                  deviceCommonName: "ShinnoMac-mini",
                                                  inForceFingerprint: "aa", now: Date())
        XCTAssertTrue(out.contains { $0.contains("POINTER STALE") }, "\(out)")
    }

    func testASecondStillValidIdentityIsStillReported() {
        let out = DsseDeviceIdentityOrphans.lines(all: [facts("ShinnoMac-mini", "aa"),
                                                        facts("ShinnoMac-mini", "bb")],
                                                  deviceCommonName: "ShinnoMac-mini",
                                                  inForceFingerprint: "aa", now: Date())
        XCTAssertTrue(out.contains { $0.contains("still-valid duplicate credential") }, "\(out)")
    }
}
