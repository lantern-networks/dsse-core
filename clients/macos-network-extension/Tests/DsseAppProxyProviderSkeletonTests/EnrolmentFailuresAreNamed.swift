import XCTest
@testable import DsseAppProxyProviderSkeleton

// ★★★ A CODE ON ITS OWN NAMES NOTHING, AND THE CODES ARE NOT THE DECLARATION ORDER (2026-08-29).
//
// A real enrolment failure logged `domain=…DsseDeviceEnrolmentError code=1`. Read as the second case of the
// enum that is `unpinnedTransport`, and the configuration on the device plainly HAD both pins — so the reading
// was wrong and a round trip was spent on it. Swift numbers cases that carry payloads before those that do
// not: code 1 is requestFailed, and unpinnedTransport is 5.
//
// This is the ordering, asserted, so nobody reads the declaration order off the source again. It is also why
// the log now carries the NAME and the reason text rather than a number.
final class EnrolmentFailuresAreNamedTests: XCTestCase {
    func testTheCodesAreNotTheDeclarationOrder() {
        XCTAssertEqual((DsseDeviceEnrolmentError.notConfigured("x") as NSError).code, 0)
        XCTAssertEqual((DsseDeviceEnrolmentError.requestFailed("x") as NSError).code, 1)
        XCTAssertEqual((DsseDeviceEnrolmentError.serverRefused(status: 1, message: "x") as NSError).code, 2)
        XCTAssertEqual((DsseDeviceEnrolmentError.responseUnusable("x") as NSError).code, 3)
        XCTAssertEqual((DsseDeviceEnrolmentError.caPinMismatch(expected: "a", got: "b") as NSError).code, 4)
        // The one that reads as "second" in the source and is last here.
        XCTAssertEqual((DsseDeviceEnrolmentError.unpinnedTransport as NSError).code, 5)
    }

    func testEveryEnrolmentFailureSaysWhichOneItIs() {
        let cases: [DsseDeviceEnrolmentError] = [
            .notConfigured("no url"),
            .unpinnedTransport,
            .requestFailed("could not connect"),
            .serverRefused(status: 403, message: "token spent"),
            .responseUnusable("no certificate"),
            .caPinMismatch(expected: "aa", got: "bb"),
        ]
        for e in cases {
            let line = providerNonsecretErrorDetail(e)
            XCTAssertTrue(line.contains("enrolment_error="),
                          "a failure logged only as a number: \(line)")
        }
        // The safe reason category travels; free-form network and response strings do not.
        XCTAssertTrue(providerNonsecretErrorDetail(DsseDeviceEnrolmentError.requestFailed("could not connect"))
            .contains("network_reason=connection_failed"))
        XCTAssertTrue(providerNonsecretErrorDetail(DsseDeviceEnrolmentError.serverRefused(status: 403, message: "token spent"))
            .contains("403"))
    }

    func testServerRefusalCannotCopyUntrustedResponseIntoPublicRuntimeLog() {
        let marker = "private_fixture_secret_marker"
        let enrolment = providerNonsecretErrorDetail(
            DsseDeviceEnrolmentError.serverRefused(status: 403, message: marker))
        XCTAssertTrue(enrolment.contains("enrolment_error=server_refused status=403"))
        XCTAssertFalse(enrolment.contains(marker))
        let renewal = providerNonsecretErrorDetail(
            DsseCertificateRenewalError.serverRefused(status: 403, message: marker))
        XCTAssertFalse(renewal.contains(marker))
        XCTAssertFalse(providerNonsecretErrorDetail(DsseSingleRequestError.transport("refused " + marker))
            .contains(marker))
        XCTAssertFalse(providerNonsecretErrorDetail(DsseRuntimeCopyTunnelError.connectionFailed("closed " + marker))
            .contains(marker))
        XCTAssertFalse(providerNonsecretErrorDetail(DsseRenewedIdentityStoreError.pointerWriteFailed(marker))
            .contains(marker))
    }
}
