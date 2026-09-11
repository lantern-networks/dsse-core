import XCTest
@testable import DsseAppProxyProviderSkeleton

final class DsseControlRequestTransportTests: XCTestCase {
    override func tearDown() {
        DsseLiveTransportServerName.setProvider { "" }
        super.tearDown()
    }

    func testControlRequestsKeepTenantSNIWithoutDNSAndFollowRegionChanges() {
        let security = DsseTransportSecurity(host: "192.0.2.10", port: 443,
            mtlsRequired: true, pinnedCACertificates: [], clientIdentity: nil)
        DsseLiveTransportServerName.setProvider { "tenant.invalid" }
        XCTAssertEqual(security.controlServerName, "tenant.invalid")
        let transport = DsseControlRequestTransport(security: security) { req, route, name in
            XCTAssertEqual(route.host, "192.0.2.20")
            XCTAssertEqual(route.port, 8443)
            XCTAssertTrue(route.mtlsRequired)
            XCTAssertEqual(name, "rotated.invalid")
            XCTAssertEqual(req.httpMethod, "POST")
            XCTAssertEqual(req.httpBody, Data("test".utf8))
            return .init(status: 202, body: Data())
        }
        transport.selectEndpoint(URL(string: "https://192.0.2.20:8443")!)
        transport.selectEndpoint(URL(string: "http://attacker.invalid")!)
        transport.selectEndpoint(URL(string: "https://user:password@attacker.invalid")!)
        DsseLiveTransportServerName.setProvider { "rotated.invalid" }
        var req = URLRequest(url: URL(string: "https://192.0.2.10/devices/mac/heartbeat")!)
        req.httpMethod = "POST"; req.httpBody = Data("test".utf8)
        let done = expectation(description: "POST to selected region")
        transport.send(req) { _, response, error in
            XCTAssertNil(error)
            XCTAssertEqual((response as? HTTPURLResponse)?.statusCode, 202)
            done.fulfill()
        }
        wait(for: [done], timeout: 2)
    }

    func testTLSFailureIsReturnedWithoutSuccessOrFallback() {
        let security = DsseTransportSecurity(host: "192.0.2.10", port: 443,
            mtlsRequired: true, pinnedCACertificates: [], clientIdentity: nil)
        let transport = DsseControlRequestTransport(security: security) { _, _, _ in
            throw DsseSingleRequestError.transport("test pin refusal")
        }
        let done = expectation(description: "TLS error")
        transport.send(URLRequest(url: URL(string: "https://192.0.2.10/heartbeat")!)) { data, response, error in
            XCTAssertNil(data); XCTAssertNil(response); XCTAssertNotNil(error)
            done.fulfill()
        }
        wait(for: [done], timeout: 2)
    }
    func testUpdateOutboxIsKeptOnNamedTLSFailureAndDrainedOnlyOnAcceptance() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let file = dir.appendingPathComponent("20260909T000000Z-report.json")
        let bytes = Data(#"{"status":"installed","at":"2026-09-09T00:00:00Z"}"#.utf8)
        try bytes.write(to: file)
        let security = DsseTransportSecurity(host: "192.0.2.10", port: 443,
            mtlsRequired: true, pinnedCACertificates: [], clientIdentity: nil)
        DsseLiveTransportServerName.setProvider { "tenant.invalid" }
        for code in [0, 503, 202] {
            let transport = DsseControlRequestTransport(security: security) { req, _, name in
                XCTAssertEqual(name, "tenant.invalid")
                XCTAssertEqual(req.httpMethod, "POST")
                if code == 0 { throw DsseSingleRequestError.transport("pin refusal") }
                return .init(status: code, body: Data())
            }
            let sender = DsseUpdateReportSender(session: .shared,
                url: URL(string: "https://192.0.2.10/devices/mac/update-report")!,
                deviceID: "mac", tenantID: "tenant_test", directory: dir, controlTransport: transport)
            let done = expectation(description: "report status \(code)")
            sender.drain { done.fulfill() }
            wait(for: [done], timeout: 2)
            if code == 202 { XCTAssertFalse(FileManager.default.fileExists(atPath: file.path)) }
            else { XCTAssertEqual(try Data(contentsOf: file), bytes) }
        }
    }

}
