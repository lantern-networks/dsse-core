import XCTest
@testable import DsseAppProxyProviderSkeleton

/// ★★★ MEASURED ON A REAL MAC, 2026-08-30. The same machine was handed the four artefacts of a NEW deployment
/// — signed profile, verifying key, one-time token, package — and went on steering with the certificate the
/// PREVIOUS deployment (destroyed the night before) had issued it:
///
///	enrolment_gate decision=proceed has_identity=true has_token=true enrolled_before=true
///	device_identity renewed_identity=in_use sha256=a295a9c4…
///	curl https://example.com -> 000
///
/// A credential the deployment cannot accept, an administrator's unused approval sitting beside it, and
/// nothing connecting the two. That is the "move a device to another deployment" lane, and it is every rebuild
/// of a lab — which is the lane this product is trying to make short.
final class AnIdentityFromAnotherDeploymentTests: XCTestCase {
    func testAnIdentityThatDoesNotWorkHereSpendsTheApprovalItWasGiven() {
        XCTAssertEqual(
            DsseEnrolmentGate.decide(hasIdentity: true, hasEnrolmentToken: true,
                                     wasEnrolledBefore: true, identityWorksHere: false),
            .enrolFirst,
            "a device holding another deployment's certificate, with an unspent approval for THIS one, went on "
            + "steering with the credential that cannot work")
    }

    func testAWorkingIdentityIsLeftAlone() {
        XCTAssertEqual(
            DsseEnrolmentGate.decide(hasIdentity: true, hasEnrolmentToken: true,
                                     wasEnrolledBefore: true, identityWorksHere: true),
            .proceed,
            "a device whose certificate works was made to enrol again, spending an approval for nothing")
    }

    /// nil is "could not be asked" — no transport contract to handshake against — and must never be read as a
    /// failure. Reading it as one would re-enrol every device on a deployment that does not use (T) at all.
    func testNotAskedIsNotTheSameAsNo() {
        XCTAssertEqual(
            DsseEnrolmentGate.decide(hasIdentity: true, hasEnrolmentToken: true,
                                     wasEnrolledBefore: true, identityWorksHere: nil),
            .proceed)
    }

    /// And with no approval to spend, the gate does not change its mind: whether a device with a broken
    /// credential should stand aside is a posture decision, not this gate's to make.
    func testWithoutAnApprovalNothingChanges() {
        XCTAssertEqual(
            DsseEnrolmentGate.decide(hasIdentity: true, hasEnrolmentToken: false,
                                     wasEnrolledBefore: true, identityWorksHere: false),
            .proceed)
    }

    /// The call site must actually ask. A rule nothing consults is a comment.
    func testStartupAsksTheHandshakeBeforeDeciding() throws {
        let source = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Sources/DsseAppProxyProviderSkeleton/DsseAppProxyProvider.swift")
        let text = try String(contentsOf: source, encoding: .utf8)
        XCTAssertTrue(text.contains("identityWorksHere: identityWorksHere"),
                      "the enrolment gate is still deciding without being told whether the identity works here")
        XCTAssertTrue(text.contains("identity_works_here="),
                      "nothing in the log says which of the two states this device is in")
    }
}
