import XCTest
@testable import DsseAppProxyProviderSkeleton

/// ★★★ THE LAST GATE BEFORE A DEVICE ADOPTS AN IDENTITY WAS ON THE TRANSPORT THIS PRODUCT ABANDONED
/// (2026-08-30, measured).
///
///	enrolment probe host=jcui…hikari.lab:443/healthz result=REFUSED status=0
///	  reason=A TLS error caused the secure connection to fail.        (-1200, the ATS refusal)
///
/// DsseSingleRequestOverNW exists because "App Transport Security refuses a deployment's private CA before the
/// pinning delegate runs". Every other request the agent makes was moved to it. The probe was not — so it
/// could not succeed against any deployment with a private CA.
///
/// It went unnoticed because it almost never ran. resolve() fails closed when there is no client identity, and
/// transportHandshakeSucceeds returns true without dialling when there is no security to probe with — so on a
/// device enrolling for the FIRST time, which is every device this lane exists for, the probe is skipped. The
/// first time it truly ran was on a machine moved between deployments, and it refused a correct certificate.
final class TheLastGateWasOnTheAbandonedTransportTests: XCTestCase {
    func testTheProbeUsesTheTransportEveryOtherRequestUses() throws {
        let source = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Sources/DsseAppProxyProviderSkeleton/DsseAppProxyProvider.swift")
        let text = try String(contentsOf: source, encoding: .utf8)
        guard let i = text.range(of: "static func transportHandshakeSucceeds") else {
            return XCTFail("the probe is gone")
        }
        let body = text[i.upperBound...].prefix(3_000)
        XCTAssertTrue(body.contains("DsseSingleRequestOverNW.request"),
                      "the probe is back on URLSession, whose App Transport Security refuses a deployment's "
                      + "private CA before the pinning delegate runs — so it refuses every correct certificate")
        XCTAssertFalse(body.contains("makePinnedURLSession"),
                       "the probe still builds a URLSession")
        XCTAssertTrue(body.contains("identityOverride: candidate"),
                      "the probe does not send the certificate it claims to be testing")
    }

    /// ★ And the skip is still there, deliberately: a deployment that does not use (T) at all has nothing to
    /// probe against, and refusing on that basis would block every enrolment on it. Worth an assertion because
    /// the skip is also what hid this for months.
    func testADeploymentWithNoTransportStillEnrols() throws {
        let source = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Sources/DsseAppProxyProviderSkeleton/DsseAppProxyProvider.swift")
        let text = try String(contentsOf: source, encoding: .utf8)
        guard let i = text.range(of: "static func transportHandshakeSucceeds") else {
            return XCTFail("the probe is gone")
        }
        XCTAssertTrue(text[i.upperBound...].prefix(300).contains("guard let security else { return true }"),
                      "a deployment with no (T) transport can no longer enrol at all")
    }
}
