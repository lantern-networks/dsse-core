import XCTest
import CryptoKit
@testable import DsseAppProxyProviderSkeleton

final class DsseRegionEndpointPollerTests: XCTestCase {
    private func signedList(_ key: Curve25519.Signing.PrivateKey) throws -> Data {
        let payload = try JSONSerialization.data(withJSONObject: [
            "schema_version": "dsse.region-endpoints.v1",
            "tenant_id": "tenant_test", "home_region": "east",
            "allowed_region_endpoints": [["region": "east", "endpoint": "https://east.example:443"]]
        ], options: [.sortedKeys])
        let signature = try key.signature(for: payload).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        return try JSONSerialization.data(withJSONObject: [
            "type": "dsse_agent_steer_policy.v1", "version": "1",
            "payload_sha256": SHA256.hash(data: payload).map { String(format: "%02x", $0) }.joined(),
            "payload_b64": payload.base64EncodedString(), "signature": "ed25519:" + signature
        ])
    }

    func testProductionPollFollowsSelectedRegionAndReadsCurrentTenantName() throws {
        let key = Curve25519.Signing.PrivateKey()
        let body = try signedList(key)
        let security = DsseTransportSecurity(host: "192.0.2.10", port: 443,
            mtlsRequired: true, pinnedCACertificates: [], clientIdentity: nil)
        let poller = try XCTUnwrap(DsseRegionEndpointPoller(security: security,
            pinnedPublicKeyHex: key.publicKey.rawRepresentation.map { String(format: "%02x", $0) }.joined(),
            cachePath: nil))
        defer { DsseLiveTransportServerName.setProvider { "" } }
        DsseLiveTransportServerName.setProvider { "tenant.transport.invalid" }
        var calls = 0
        poller.requestOverNW = { route, name, path in
            calls += 1
            XCTAssertEqual(route.host, calls == 1 ? "192.0.2.10" : "192.0.2.20")
            XCTAssertEqual(route.port, calls == 1 ? 443 : 8443)
            XCTAssertTrue(route.mtlsRequired)
            XCTAssertEqual(name, calls == 1 ? "tenant.transport.invalid" : "rotated.transport.invalid")
            XCTAssertEqual(path, "/steer/region-endpoints")
            return .init(status: 200, body: body)
        }
        let first = expectation(description: "signed list over tenant SNI")
        poller.fetchVerifiedRegionEndpoints { list in
            XCTAssertEqual(list?.endpoints.first?.region, "east"); first.fulfill()
        }
        wait(for: [first], timeout: 1)
        XCTAssertTrue(poller.selectEndpoint(URL(string: "https://192.0.2.20:8443")!))
        XCTAssertFalse(poller.selectEndpoint(URL(string: "http://attacker.invalid")!))
        DsseLiveTransportServerName.setProvider { "rotated.transport.invalid" }
        let second = expectation(description: "list after region and SNI change")
        poller.fetchVerifiedRegionEndpoints { list in
            XCTAssertNotNil(list); second.fulfill()
        }
        wait(for: [second], timeout: 1)
        XCTAssertEqual(calls, 2)
        XCTAssertNil(poller.lastFailureReason)
    }

    func testNamedTransportFailureOrUntrustedSignatureCannotReplaceVerifiedCache() throws {
        let key = Curve25519.Signing.PrivateKey()
        let good = try signedList(key)
        let bad = try signedList(Curve25519.Signing.PrivateKey())
        let cache = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: cache) }
        let security = DsseTransportSecurity(host: "192.0.2.10", port: 443,
            mtlsRequired: true, pinnedCACertificates: [], clientIdentity: nil)
        let poller = try XCTUnwrap(DsseRegionEndpointPoller(security: security,
            pinnedPublicKeyHex: key.publicKey.rawRepresentation.map { String(format: "%02x", $0) }.joined(),
            cachePath: cache.path))
        for mode in 0...3 {
            poller.requestOverNW = { _, _, _ in
                if mode == 3 { throw URLError(.serverCertificateUntrusted) }
                return .init(status: mode == 2 ? 503 : 200, body: mode == 1 ? bad : good)
            }
            let done = expectation(description: "mode \(mode)")
            poller.fetchVerifiedRegionEndpoints { list in
                if mode == 0 { XCTAssertNotNil(list) } else { XCTAssertNil(list) }
                done.fulfill()
            }
            wait(for: [done], timeout: 1)
            XCTAssertEqual(try Data(contentsOf: cache), good)
            if mode > 0 { XCTAssertNotNil(poller.lastFailureReason) }
        }
    }
}
