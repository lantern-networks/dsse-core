import XCTest
@testable import DsseAppProxyProviderSkeleton

/// ★★★ A PROBE THAT DOES NOT SEND WHAT IT CLAIMS TO BE TESTING (2026-08-30, measured on a real Mac).
///
/// The hazard is written out in this codebase already, above makeTunnelParameters: "reading the identity live
/// … makes the probe test the certificate ALREADY IN USE and report success about a candidate it never sent."
/// It was closed on the NW path with identityOverride. The URLSession delegate — which is what the enrolment
/// and renewal probe actually uses — went on reading it live.
///
/// That produced the other direction of the same defect. A Mac moved to a new deployment enrolled, the Edge
/// issued a certificate, and the probe dialled with the certificate the device was still holding — one from
/// the deployment destroyed the night before. The Edge refused THAT, and the new identity was rolled back:
///
///	enrolment certificate_renewal probe REJECTED the new identity — it was removed and the existing
///	  certificate remains in force; renewal will be retried
///
/// on every start, spending an administrator's one-time approval each time.
final class TheProbeMustSendWhatItTestsTests: XCTestCase {
    func testTheDelegateCanBeToldWhichIdentityToPresent() throws {
        let source = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Sources/DsseAppProxyProviderSkeleton/DsseTransportSecurity.swift")
        let text = try String(contentsOf: source, encoding: .utf8)
        XCTAssertTrue(text.contains("identityOverride ?? DsseLiveClientIdentity.current()"),
                      "the pinned URLSession still takes the live identity even when a caller named one, so a "
                      + "probe reports on a certificate it never sent")
        XCTAssertTrue(text.contains("identityOverride: SecIdentity? = nil"),
                      "naming an identity is not optional-by-default, so every existing caller changed behaviour")
    }

    /// And the probe must actually name it. A parameter nothing passes is a comment.
    func testTheProbeNamesTheCandidate() throws {
        let source = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Sources/DsseAppProxyProviderSkeleton/DsseAppProxyProvider.swift")
        let text = try String(contentsOf: source, encoding: .utf8)
        XCTAssertTrue(text.contains("identityOverride: candidate"),
                      "transportHandshakeSucceeds still lets the connection choose, so it proves nothing about "
                      + "the certificate it was given")
    }
}
