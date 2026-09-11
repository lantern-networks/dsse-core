import XCTest
@testable import DsseAppProxyProviderSkeleton

// These test the DECISION — findOrphans over facts — not the keychain enumeration, which needs a real System
// keychain and is exercised on-device. The decision is where the mistakes live: scoping to the wrong subject,
// or flagging the identity actually in force.
final class DsseDeviceIdentityOrphansTests: XCTestCase {

    private let now = Date(timeIntervalSinceReferenceDate: 800_000_000) // fixed reference point

    private func facts(_ fp: String, cn: String, issuer: String = "DSSE Device CA",
                       notAfter: Date?) -> DsseIdentityFacts {
        DsseIdentityFacts(certificateSHA256: fp, subjectCommonName: cn, issuerCommonName: issuer, notAfter: notAfter)
    }

    // The identity the pointer names is never an orphan, even though it is one of several for the device.
    func testInForceIdentityIsNeverAnOrphan() {
        let all = [
            facts("aaa", cn: "mac-dev-1", notAfter: now.addingTimeInterval(86_400)),   // in force
            facts("bbb", cn: "mac-dev-1", notAfter: now.addingTimeInterval(10 * 365 * 86_400)), // 10y leftover
        ]
        let orphans = DsseDeviceIdentityOrphans.findOrphans(all: all, deviceCommonName: "mac-dev-1",
                                                            inForceFingerprint: "aaa", now: now)
        XCTAssertEqual(orphans.map { $0.facts.certificateSHA256 }, ["bbb"])
    }

    // An identity for a DIFFERENT subject is somebody else's item in a shared keychain — never flagged.
    func testOtherSubjectsAreNotOurOrphans() {
        let all = [
            facts("aaa", cn: "mac-dev-1", notAfter: now.addingTimeInterval(86_400)),
            facts("zzz", cn: "some-other-device", notAfter: now.addingTimeInterval(-86_400)),
            facts("yyy", cn: "Apple Development: SOMEBODY", notAfter: now.addingTimeInterval(86_400)),
        ]
        let orphans = DsseDeviceIdentityOrphans.findOrphans(all: all, deviceCommonName: "mac-dev-1",
                                                            inForceFingerprint: "aaa", now: now)
        XCTAssertTrue(orphans.isEmpty)
    }

    // The exact accumulation found on the device: an expired one, a 10-year one, and a fail-open test cert.
    func testFindsTheRealAccumulationAndClassifiesExpiry() {
        let all = [
            facts("live", cn: "mac-dev-1", notAfter: now.addingTimeInterval(30 * 86_400)),           // in force
            facts("old", cn: "mac-dev-1", notAfter: now.addingTimeInterval(-5 * 86_400)),            // expired
            facts("tenyr", cn: "mac-dev-1", notAfter: now.addingTimeInterval(10 * 365 * 86_400)),    // 10y
            facts("failopen", cn: "mac-dev-1", issuer: "Wrong CA (fail-open test)",
                  notAfter: now.addingTimeInterval(10 * 365 * 86_400)),                               // test cert
        ]
        let orphans = DsseDeviceIdentityOrphans.findOrphans(all: all, deviceCommonName: "mac-dev-1",
                                                            inForceFingerprint: "live", now: now)
        XCTAssertEqual(Set(orphans.map { $0.facts.certificateSHA256 }), ["old", "tenyr", "failopen"])
        let byFp = Dictionary(uniqueKeysWithValues: orphans.map { ($0.facts.certificateSHA256, $0.expired) })
        XCTAssertEqual(byFp["old"], true)
        XCTAssertEqual(byFp["tenyr"], false)  // still-valid → the dangerous kind
        XCTAssertEqual(byFp["failopen"], false)
    }

    // With no pointer (bootstrap-only device), nothing is in force to exclude; but there is also no device name
    // to scope to, so the reporting path skips. findOrphans itself, given a name and nil in-force, treats every
    // matching identity as an orphan — which is correct: none of them is committed.
    func testNilInForceMakesEveryMatchAnOrphan() {
        let all = [
            facts("aaa", cn: "mac-dev-1", notAfter: now.addingTimeInterval(86_400)),
            facts("bbb", cn: "mac-dev-1", notAfter: now.addingTimeInterval(86_400)),
        ]
        let orphans = DsseDeviceIdentityOrphans.findOrphans(all: all, deviceCommonName: "mac-dev-1",
                                                            inForceFingerprint: nil, now: now)
        XCTAssertEqual(orphans.count, 2)
    }

    // A missing notAfter must not be treated as expired — unknown is not the same as past.
    func testUnknownExpiryIsNotExpired() {
        let all = [facts("aaa", cn: "mac-dev-1", notAfter: nil)]
        let orphans = DsseDeviceIdentityOrphans.findOrphans(all: all, deviceCommonName: "mac-dev-1",
                                                            inForceFingerprint: nil, now: now)
        XCTAssertEqual(orphans.count, 1)
        XCTAssertFalse(orphans[0].expired)
    }
}
