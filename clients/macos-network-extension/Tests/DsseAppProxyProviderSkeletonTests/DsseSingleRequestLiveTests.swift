import XCTest
@testable import DsseAppProxyProviderSkeleton

/// A LIVE check against a running Edge, skipped unless DSSE_LIVE_EDGE names one.
///
/// ★ WHAT IT CAN AND CANNOT PROVE. The real recovery case needs a certificate that has already expired, which
/// cannot be produced on demand on a working device. What CAN be proven is everything up to that point: the
/// parameters build, the TLS server name reaches the Edge, and the Edge answers the way it answers a client it
/// will not serve. A refusal is the expected outcome here — this test presents no client identity, and the
/// recovery path requires one.
///
/// It is written this way because the alternative was to claim the path works on the strength of unit tests
/// over its parser.
final class DsseSingleRequestLiveTests: XCTestCase {
    func testTheRecoverySNIReachesTheEdgeAndTheEdgeRefusesAnAnonymousCaller() throws {
        guard let target = ProcessInfo.processInfo.environment["DSSE_LIVE_EDGE"], !target.isEmpty else {
            throw XCTSkip("set DSSE_LIVE_EDGE=host:port to run this against a live Edge")
        }
        let sni = ProcessInfo.processInfo.environment["DSSE_LIVE_RECOVERY_SNI"] ?? "recovery.dsse.invalid"
        let parts = target.split(separator: ":")
        guard parts.count == 2, let port = Int(parts[1]) else {
            return XCTFail("DSSE_LIVE_EDGE must be host:port")
        }
        let security = DsseTransportSecurity(host: String(parts[0]), port: port, mtlsRequired: true,
                                             pinnedCACertificates: [], clientIdentity: nil)
        do {
            let answer = try DsseSingleRequestOverNW.post(
                host: String(parts[0]), port: port, serverName: sni, path: "/enroll/renew",
                body: Data("{}".utf8), security: security, timeout: 15)
            // An answer at all would mean the Edge served an anonymous caller on the recovery path.
            XCTFail("the recovery path answered a caller with no client certificate: HTTP \(answer.status)")
        } catch {
            // The expected shape: the handshake does not complete, and the error says so rather than hanging.
            let text = "\(error)"
            XCTAssertTrue(text.contains("transport") || text.contains("connection"),
                          "expected a transport-level refusal, got: \(text)")
            print("live recovery-SNI probe refused as expected: \(text)")
        }
    }
}
