import XCTest
@testable import DsseAppProxyProviderSkeleton

// ★★★ AN ADOPTED DISTRIBUTION MUST NOT SUPERSEDE THE PROVISIONED ONE WHILE THERE IS NO RELATIONSHIP YET
// (2026-08-29; the Windows session reached the same rule from the other direction and states it more
// generally: supersession is conditional on coverage).
//
// "Adopted beats provisioned" is right for a rotation and wrong for a STRANGER. A device carrying a previous
// deployment's anchors — a re-provisioned machine, a reused lab box — pinned its enrolment dial against an
// authority with nothing to do with the deployment it was joining. Every attempt failed with a bare TLS
// error while the log said the anchors had been adopted.
//
// Enrolment is the one dial with no relationship to preserve: the device is presenting a one-time token an
// operator handed it with the profile, and the profile's anchors ARE that operator's statement.
//
// Everywhere else the live set still governs alone, because withdrawing the shared anchor from an
// organization's bundle is the whole point of that mechanism and a union would quietly undo it.
final class EnrolmentTrustsWhatTheOperatorHandedOverTests: XCTestCase {
    func testTheEnrolmentDialIsTheOnlyOneThatUnions() {
        // The bootstrap session opts in.
        let source = try! String(contentsOfFile: "Sources/DsseAppProxyProviderSkeleton/DsseDeviceEnrolment.swift",
                                 encoding: .utf8)
        XCTAssertTrue(source.contains("trustProvisionedAlongsideAdopted: true"),
                      "the enrolment bootstrap no longer trusts the anchors the operator handed over, so a "
                      + "device carrying a previous deployment's anchors can never enrol into a new one")

        // And nothing else does. A union on the steady-state transport would undo the shared-anchor
        // withdrawal, which is the mechanism roadmap D exists for.
        let security = try! String(contentsOfFile: "Sources/DsseAppProxyProviderSkeleton/DsseTransportSecurity.swift",
                                   encoding: .utf8)
        XCTAssertTrue(security.contains("trustProvisionedAlongsideAdopted: Bool = false"),
                      "the union is no longer opt-in — every pinned session would widen what it accepts")
        let optIns = security.components(separatedBy: "trustProvisionedAlongsideAdopted: true").count - 1
        XCTAssertEqual(optIns, 0, "a second caller opted into the union inside the transport layer")
    }

    // ★★★ THE DIAL THAT CREATES AN IDENTITY MUST NOT PRESENT ONE (2026-08-29, measured on a Mac carrying
    // identities from previous deployments). makeBootstrapSession says so in its own comment and passes nil —
    // and the delegate looked the LIVE identity up and presented it anyway. The device offered a certificate
    // from an authority the Edge has never heard of, the Edge sent a fatal alert, and enrolment failed with
    // -9802: a TLS error naming nothing.
    func testTheEnrolmentDialPresentsNoIdentity() {
        let source = try! String(contentsOfFile: "Sources/DsseAppProxyProviderSkeleton/DsseDeviceEnrolment.swift",
                                 encoding: .utf8)
        XCTAssertTrue(source.contains("withoutClientIdentity: true"),
                      "the enrolment bootstrap presents whatever identity this device happens to hold — "
                      + "including one from a deployment it is no longer part of")

        let security = try! String(contentsOfFile: "Sources/DsseAppProxyProviderSkeleton/DsseTransportSecurity.swift",
                                   encoding: .utf8)
        XCTAssertTrue(security.contains("withoutClientIdentity: Bool = false"),
                      "suppressing the identity is no longer opt-in — every session would stop presenting one, "
                      + "and the Edge would lose sight of every device")
        XCTAssertEqual(security.components(separatedBy: "withoutClientIdentity: true").count - 1, 0,
                       "a second caller opted out of presenting an identity inside the transport layer")
    }
}
