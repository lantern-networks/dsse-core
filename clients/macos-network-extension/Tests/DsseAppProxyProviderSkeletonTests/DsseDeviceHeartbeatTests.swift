import XCTest
@testable import DsseAppProxyProviderSkeleton

// Stub URLProtocol so the heartbeat POST is exercised without a real Edge.
final class StubHeartbeatURLProtocol: URLProtocol {
    nonisolated(unsafe) static var statusCode: Int = 202
    nonisolated(unsafe) static var lastBody: Data?
    nonisolated(unsafe) static var requestCount = 0
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        Self.requestCount += 1
        // httpBody is nil for a URLSession upload; the body arrives on the stream.
        if let stream = request.httpBodyStream {
            stream.open()
            var data = Data(); var buf = [UInt8](repeating: 0, count: 4096)
            while stream.hasBytesAvailable {
                let n = stream.read(&buf, maxLength: buf.count)
                if n <= 0 { break }
                data.append(contentsOf: buf[0..<n])
            }
            stream.close()
            Self.lastBody = data
        } else {
            Self.lastBody = request.httpBody
        }
        let resp = HTTPURLResponse(url: request.url!, statusCode: Self.statusCode, httpVersion: nil, headerFields: nil)!
        client?.urlProtocol(self, didReceive: resp, cacheStoragePolicy: .notAllowed)
        client?.urlProtocolDidFinishLoading(self)
    }
    override func stopLoading() {}
}

final class DsseDeviceHeartbeatTests: XCTestCase {

    private func stubSession() -> URLSession {
        let cfg = URLSessionConfiguration.ephemeral
        cfg.protocolClasses = [StubHeartbeatURLProtocol.self]
        return URLSession(configuration: cfg)
    }

    // THE decision this file exists to pin. The Edge re-derives device trust from any posture block a
    // heartbeat carries, against a policy that by default also requires screen lock — which this platform's
    // collector cannot read. Attaching posture here would therefore drop a `managed` Mac to `noncompliant` the
    // moment liveness was switched on, which is precisely what happened to the Windows agent (its heartbeat
    // carries only enforcement_agent_healthy, and win-dev-1 has been noncompliant ever since). Liveness must
    // not re-decide trust with a signal set known to be incomplete.
    func testHeartbeatCarriesNoPostureSoItCannotSilentlyDowngradeTrust() {
        let body = DsseDeviceHeartbeat.body(deviceID: "mac-dev-1", tenantID: "t1",
                                            agentVersion: "0.1.0+2026", now: Date(timeIntervalSince1970: 0))
        XCTAssertNil(body["posture"],
            "a heartbeat must not carry posture: the Edge would re-derive trust from an incomplete signal set")
        XCTAssertNil(body["device_trust_level"],
            "the device must not claim a trust level either — trust is the Edge's to derive from evidence")
    }

    func testHeartbeatBodyCarriesWhatTheEdgeNeeds() {
        let body = DsseDeviceHeartbeat.body(deviceID: "mac-dev-1", tenantID: "t1",
                                            agentVersion: "0.1.0+2026", now: Date(timeIntervalSince1970: 0))
        XCTAssertEqual(body["id"] as? String, "mac-dev-1")
        XCTAssertEqual(body["tenant_id"] as? String, "t1")
        XCTAssertEqual(body["status"] as? String, "active")
        XCTAssertEqual(body["agent_version"] as? String, "0.1.0+2026")
        XCTAssertNotNil(body["timestamp"] as? String)
    }

    // An empty tenant is OMITTED, not sent blank: the Edge's store compares a present tenant_id against the
    // registered one, so a blank string is a claim about a tenant rather than the absence of a claim.
    func testEmptyTenantIsOmittedRatherThanClaimed() {
        let body = DsseDeviceHeartbeat.body(deviceID: "mac-dev-1", tenantID: "",
                                            agentVersion: "v", now: Date(timeIntervalSince1970: 0))
        XCTAssertNil(body["tenant_id"])
    }

    // agent_version must be the build this actually is. The Windows agent reports the literal "wfp-steer" — a
    // steering-backend name — so no one can read a fleet's version distribution; this is step 0 of the
    // auto-update design, and it must not regress into another hardcoded product string.
    func testAgentVersionIsTheBuildNotAProductName() {
        let bundle = StubInfoBundle(values: ["CFBundleShortVersionString": "0.1.0", "CFBundleVersion": "20260805164016"])
        XCTAssertEqual(DsseDeviceHeartbeat.agentVersion(bundle: bundle), "0.1.0+20260805164016")
        XCTAssertEqual(DsseDeviceHeartbeat.agentVersion(bundle: StubInfoBundle(values: ["CFBundleVersion": "42"])), "42")
        XCTAssertEqual(DsseDeviceHeartbeat.agentVersion(bundle: StubInfoBundle(values: [:])), "unknown",
                       "an unreadable version must say so, never be omitted or faked")
    }

    func testSenderPostsToTheDeviceHeartbeatPath() {
        StubHeartbeatURLProtocol.statusCode = 202
        StubHeartbeatURLProtocol.requestCount = 0
        StubHeartbeatURLProtocol.lastBody = nil
        let sender = DsseDeviceHeartbeatSender(
            session: stubSession(), url: URL(string: "https://edge.test/devices/mac-dev-1/heartbeat")!,
            deviceID: "mac-dev-1", tenantID: "", agentVersion: "0.1.0+2026")
        sender.start(interval: 3600)   // long interval: this asserts on the immediate first beat
        let deadline = Date().addingTimeInterval(5)
        while StubHeartbeatURLProtocol.lastBody == nil && Date() < deadline { usleep(20_000) }
        sender.stop()
        guard let body = StubHeartbeatURLProtocol.lastBody,
              let json = try? JSONSerialization.jsonObject(with: body) as? [String: Any] else {
            return XCTFail("the sender must beat immediately — a device that just started enforcing must not look dark for a whole interval")
        }
        XCTAssertEqual(json["id"] as? String, "mac-dev-1")
        XCTAssertNil(json["posture"], "the wire body must carry no posture either, not just the builder")
    }

    // A device with no (T) client identity cannot say WHICH device it is, so it must refuse to construct
    // rather than beat anonymously. The caller logs that refusal loudly.
    func testNoClientCertificateMeansNoIdentityAndSoNoSender() {
        XCTAssertNil(DsseDeviceHeartbeat.deviceIdentity(from: nil))
    }
}

// A Bundle whose Info dictionary is supplied by the test.
private final class StubInfoBundle: Bundle, @unchecked Sendable {
    private let values: [String: String]
    init(values: [String: String]) { self.values = values; super.init() }
    override func object(forInfoDictionaryKey key: String) -> Any? { values[key] }
}
