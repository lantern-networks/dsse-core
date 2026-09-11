import XCTest
@testable import DsseNetworkExtensionContract

// The rule that was missing on 2026-08-10: prove the identity, THEN take the traffic.
//
// The provider enabled the transparent proxy while holding a certificate whose private key it was not allowed
// to use, captured every flow, and dropped them all — leaving the device neither protected nor usable, with
// `status=connected` reported throughout.
final class DsseStartupIdentityGateTests: XCTestCase {
    func testAUsableIdentityProceeds() {
        XCTAssertEqual(DsseStartupIdentityGate.decide(identityPresent: true, identityUsable: true), .proceed)
    }

    func testNoIdentityIsNotTheSameFaultAsAnUnusableOne() {
        XCTAssertEqual(DsseStartupIdentityGate.decide(identityPresent: false, identityUsable: false), .noIdentity)
        XCTAssertEqual(DsseStartupIdentityGate.decide(identityPresent: true, identityUsable: false), .identityUnusable)
    }

    // ★ The case the product got wrong. A certificate that is present but unusable must NOT be treated as
    // "proceed" — that is the state in which the provider took traffic it could not carry.
    func testPresentButUnusableNeverProceeds() {
        XCTAssertNotEqual(DsseStartupIdentityGate.decide(identityPresent: true, identityUsable: false), .proceed)
    }

    // The operator message has to name the remedy, because "not enrolled" and "cannot use what you enrolled
    // with" send someone to different places.
    func testTheMessageNamesTheRealRemedy() {
        let m = DsseStartupIdentityGate.unusableIdentityOperatorMessage
        XCTAssertTrue(m.contains("Re-provision"), m)
        XCTAssertTrue(m.contains("NOT steering"), m)
        XCTAssertTrue(m.lowercased().contains("bundle id") || m.lowercased().contains("re-signed"), m)
    }
}
