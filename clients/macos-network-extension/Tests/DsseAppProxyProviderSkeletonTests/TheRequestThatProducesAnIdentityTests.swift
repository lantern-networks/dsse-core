import XCTest
@testable import DsseAppProxyProviderSkeleton

/// ★★★ MEASURED ON A REAL MAC, 2026-08-30. A device moving to a new deployment could never enrol, because the
/// credential that makes it NEED a new identity is the credential it presented while asking for one:
///
///	(the Edge) door=agent-plane TLS handshake error: x509: certificate signed by unknown authority
///	(the Mac)  enrolment_error=request_failed … transport: receive: -9831: unknown Cert Authority
///
/// The enrolment dial already passed `clientIdentity: nil` with a comment saying exactly why. One line down,
/// every connection resolves the device's LIVE identity when the caller expresses no preference — correct
/// everywhere else, and fatal here. nil could not express this: nil already means "no preference", and
/// withholding is a decision.
final class TheRequestThatProducesAnIdentityTests: XCTestCase {
    /// The call site, because this is a property of one dial and there is no way to observe a ClientHello from
    /// a unit test. A rule the enrolment does not ask for is a comment.
    func testTheEnrolmentDialWithholdsTheIdentity() throws {
        let source = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Sources/DsseAppProxyProviderSkeleton/DsseDeviceEnrolment.swift")
        let text = try String(contentsOf: source, encoding: .utf8)
        XCTAssertTrue(text.contains("presentClientIdentity: false"),
                      "the enrolment dial presents whatever certificate this device happens to hold — including "
                      + "one from a deployment it is no longer part of, which the Edge refuses at the handshake "
                      + "before the request can be read")
    }

    /// And the withholding must be a WORD, not the absence of one: a caller that says nothing keeps the live
    /// identity, which is what every other connection needs.
    func testSayingNothingStillPresentsTheIdentity() throws {
        let source = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Sources/DsseAppProxyProviderSkeleton/DsseTransportSecurity.swift")
        let text = try String(contentsOf: source, encoding: .utf8)
        XCTAssertTrue(text.contains("presentClientIdentity: Bool = true"),
                      "withholding became the default, so every other connection stopped identifying itself")
        XCTAssertTrue(text.contains("client_identity WITHHELD"),
                      "nothing in the log distinguishes a deliberate anonymous dial from a device that lost its key")
    }
}
