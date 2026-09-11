import XCTest
@testable import DsseAppProxyProviderSkeleton

// Stub URLProtocol so the poller's (T) fetch is exercised on the Mac without a real Edge.
final class StubAgentPolicyURLProtocol: URLProtocol {
    nonisolated(unsafe) static var responseData: Data?
    nonisolated(unsafe) static var statusCode: Int = 200
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        let resp = HTTPURLResponse(url: request.url!, statusCode: Self.statusCode, httpVersion: nil, headerFields: nil)!
        client?.urlProtocol(self, didReceive: resp, cacheStoragePolicy: .notAllowed)
        if let d = Self.responseData { client?.urlProtocol(self, didLoad: d) }
        client?.urlProtocolDidFinishLoading(self)
    }
    override func stopLoading() {}
}

final class DsseAgentPolicyPollerTests: XCTestCase {
    // The same Go-signed fixture the NE file verifier + the Go agentpolicy package use.
    private let pubKeyHex = "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664"
    private let envelopeJSON = """
    {"type":"dsse_agent_steer_policy.v1","version":"1","signing_key_id":"edge-agent-policy-65b60673d6ed884b","created_at":"2026-06-19T00:00:00Z","payload_sha256":"d36582e645945d1ff924a9e9b8ca298cbbe9a2891131fcf0c3b2fc040e17ff9c","payload_b64":"eyJkZXZpY2VfZ3JvdXAiOiIiLCJkZXZpY2VfaWRlbnRpdHkiOiJtYWMtZGV2LTEiLCJleGNsdWRlZF9hcHBfc2lnbmluZ19pZHMiOlsiY29tLmNvcnAudnBuY2xpZW50IiwiY29tLmV4YW1wbGUuZGV2dG9vbCJdLCJzY2hlbWFfdmVyc2lvbiI6ImRvbWVzdGljX3NzZV9hZ2VudF9zdGVlcl9wb2xpY3kudjEiLCJ0ZW5hbnRfaWQiOiJ0ZW5hbnRfdHJhY2tfYV91YzAzYV9sYWIifQ==","signature":"ed25519:rOnMYYF_h9O6iWoBsSq8y2qmZ3KleakbjkRbpooZMsPNi6tXW_WrBcQ64DoVy4rRJUiNpIIdQf2LKlA7ACjbDQ"}
    """

    private func stubSession() -> URLSession {
        let cfg = URLSessionConfiguration.ephemeral
        cfg.protocolClasses = [StubAgentPolicyURLProtocol.self]
        return URLSession(configuration: cfg)
    }

    private func fetchSync(_ poller: DsseAgentPolicyPoller) -> [String]? {
        let sem = DispatchSemaphore(value: 0)
        final class Box: @unchecked Sendable { var v: [String]? }
        let box = Box()
        poller.fetchVerifiedExclusions { result in box.v = result; sem.signal() }
        _ = sem.wait(timeout: .now() + 5)
        return box.v
    }

    // verify-from-bytes (the path the poller uses on the network response).
    func testVerifyFromEnvelopeData() {
        let data = envelopeJSON.data(using: .utf8)!
        XCTAssertEqual(DsseSignedAgentPolicy.verifiedServerExclusions(envelopeData: data, pinnedPublicKeyHex: pubKeyHex),
                       ["com.corp.vpnclient", "com.example.devtool"])
        XCTAssertNil(DsseSignedAgentPolicy.verifiedServerExclusions(
            envelopeData: data, pinnedPublicKeyHex: "00000000000000000000000000000000000000000000000000000000000000ff"))
    }

    func testPollerFetchVerifiesSignedPolicyOverTransport() {
        StubAgentPolicyURLProtocol.statusCode = 200
        StubAgentPolicyURLProtocol.responseData = envelopeJSON.data(using: .utf8)
        let poller = DsseAgentPolicyPoller(
            session: stubSession(), url: URL(string: "https://edge.test/steer/agent-policy")!, pinnedPublicKeyHex: pubKeyHex)
        XCTAssertEqual(fetchSync(poller), ["com.corp.vpnclient", "com.example.devtool"],
                       "the poller must fetch + verify the signed policy over the transport")
    }

    func testPollerRejectsWrongPin() {
        StubAgentPolicyURLProtocol.statusCode = 200
        StubAgentPolicyURLProtocol.responseData = envelopeJSON.data(using: .utf8)
        let poller = DsseAgentPolicyPoller(
            session: stubSession(), url: URL(string: "https://edge.test/steer/agent-policy")!,
            pinnedPublicKeyHex: "0000000000000000000000000000000000000000000000000000000000000000")
        XCTAssertNil(fetchSync(poller), "a policy signed by an untrusted key must not be applied")
    }

    func testPollerFailsafeOnHTTPError() {
        StubAgentPolicyURLProtocol.statusCode = 500
        StubAgentPolicyURLProtocol.responseData = Data("edge down".utf8)
        let poller = DsseAgentPolicyPoller(
            session: stubSession(), url: URL(string: "https://edge.test/steer/agent-policy")!, pinnedPublicKeyHex: pubKeyHex)
        XCTAssertNil(fetchSync(poller), "an Edge error must yield nil so the caller keeps the current set")
    }

    // A poll that verifies NOTHING must still deliver a tick. The caller reports on every tick, so this is
    // what keeps a device visible to the Edge when its policy stops verifying — a wrong pin, an Edge error, a
    // signing-key switch. Before this, onUpdate fired only on success: mac-dev-1 kept steering while it
    // vanished from "observed on devices", because the only report it ever sent was the one at start-up
    // (2026-08-05). Silence has to be reserved for a device that is genuinely gone.
    func testFailedPollStillDeliversATickSoTheDeviceKeepsReporting() {
        StubAgentPolicyURLProtocol.statusCode = 500
        StubAgentPolicyURLProtocol.responseData = Data("edge down".utf8)
        let poller = DsseAgentPolicyPoller(
            session: stubSession(), url: URL(string: "https://edge.test/steer/agent-policy")!, pinnedPublicKeyHex: pubKeyHex)
        final class Box: @unchecked Sendable { var ticks = 0; var last: [String]??  = nil }
        let box = Box()
        let sem = DispatchSemaphore(value: 0)
        poller.start(interval: 3600) { result in   // long interval: this asserts on the immediate first poll
            box.ticks += 1; box.last = .some(result); sem.signal()
        }
        XCTAssertEqual(sem.wait(timeout: .now() + 5), .success,
                       "a failed poll must still call onUpdate — otherwise the caller never reports again")
        poller.stop()
        XCTAssertEqual(box.ticks, 1)
        XCTAssertEqual(box.last, .some(nil), "the tick must carry nil, so the caller keeps its current set and reports it")
    }

    // The success path still delivers the verified set through the same (now optional) callback.
    func testVerifiedPollDeliversTheSet() {
        StubAgentPolicyURLProtocol.statusCode = 200
        StubAgentPolicyURLProtocol.responseData = envelopeJSON.data(using: .utf8)
        let poller = DsseAgentPolicyPoller(
            session: stubSession(), url: URL(string: "https://edge.test/steer/agent-policy")!, pinnedPublicKeyHex: pubKeyHex)
        final class Box: @unchecked Sendable { var last: [String]? }
        let box = Box()
        let sem = DispatchSemaphore(value: 0)
        poller.start(interval: 3600) { result in box.last = result; sem.signal() }
        XCTAssertEqual(sem.wait(timeout: .now() + 5), .success)
        poller.stop()
        XCTAssertEqual(box.last, ["com.corp.vpnclient", "com.example.devtool"])
    }
}

// The 2026-08-03 incident, as tests. The Edge moved its policy-signing key into the HSM and this device's pin
// was still the retired one, so every fetch failed verification — for four days, with no region list and no
// admin exclusions, and NOT ONE LINE anywhere saying so. Returning nil was correct (fail-safe: keep the last
// known-good state); saying nothing about it was not. These assert the failure is CLASSIFIED, which is the
// difference between "the device is quiet" and "the device is quietly broken".
final class DsseAgentPolicyPollerFailureReportingTests: XCTestCase {
    private let pubKeyHex = "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664"
    private let envelopeJSON = """
    {"type":"dsse_agent_steer_policy.v1","version":"1","signing_key_id":"edge-agent-policy-65b60673d6ed884b","created_at":"2026-06-19T00:00:00Z","payload_sha256":"d36582e645945d1ff924a9e9b8ca298cbbe9a2891131fcf0c3b2fc040e17ff9c","payload_b64":"eyJkZXZpY2VfZ3JvdXAiOiIiLCJkZXZpY2VfaWRlbnRpdHkiOiJtYWMtZGV2LTEiLCJleGNsdWRlZF9hcHBfc2lnbmluZ19pZHMiOlsiY29tLmNvcnAudnBuY2xpZW50IiwiY29tLmV4YW1wbGUuZGV2dG9vbCJdLCJzY2hlbWFfdmVyc2lvbiI6ImRvbWVzdGljX3NzZV9hZ2VudF9zdGVlcl9wb2xpY3kudjEiLCJ0ZW5hbnRfaWQiOiJ0ZW5hbnRfdHJhY2tfYV91YzAzYV9sYWIifQ==","signature":"ed25519:rOnMYYF_h9O6iWoBsSq8y2qmZ3KleakbjkRbpooZMsPNi6tXW_WrBcQ64DoVy4rRJUiNpIIdQf2LKlA7ACjbDQ"}
    """

    private func stubSession() -> URLSession {
        let cfg = URLSessionConfiguration.ephemeral
        cfg.protocolClasses = [StubAgentPolicyURLProtocol.self]
        return URLSession(configuration: cfg)
    }

    private func fetchSync(_ poller: DsseAgentPolicyPoller) {
        let sem = DispatchSemaphore(value: 0)
        poller.fetchVerifiedExclusions { _ in sem.signal() }
        _ = sem.wait(timeout: .now() + 5)
    }

    // THE case that hid for four days.
    func testAPinMismatchIsReportedAndNamesTheKey() {
        StubAgentPolicyURLProtocol.statusCode = 200
        StubAgentPolicyURLProtocol.responseData = envelopeJSON.data(using: .utf8)
        let wrongPin = "00000000000000000000000000000000000000000000000000000000000000ff"
        let poller = DsseAgentPolicyPoller(
            session: stubSession(), url: URL(string: "https://edge.test/steer/agent-policy")!, pinnedPublicKeyHex: wrongPin)
        fetchSync(poller)
        guard let reason = poller.lastFailureReason else {
            return XCTFail("a signature that does not verify must be reported, not swallowed — this is the defect that hid for four days")
        }
        XCTAssertTrue(reason.contains("signature NOT verified"), "the reason must name verification, got: \(reason)")
        XCTAssertTrue(reason.contains(wrongPin.prefix(12)), "the reason must name the pin so the mismatch is diagnosable from one line, got: \(reason)")
    }

    func testATransportOrStatusFailureIsReportedDistinctly() {
        StubAgentPolicyURLProtocol.statusCode = 503
        StubAgentPolicyURLProtocol.responseData = Data("nope".utf8)
        let poller = DsseAgentPolicyPoller(
            session: stubSession(), url: URL(string: "https://edge.test/steer/agent-policy")!, pinnedPublicKeyHex: pubKeyHex)
        fetchSync(poller)
        XCTAssertEqual(poller.lastFailureReason, "HTTP 503",
                       "a server error must not be reported as a signature problem — they need different fixes")
    }

    // Recovery must clear the state, or the next operator reads a stale reason and chases a fixed problem.
    func testRecoveryClearsTheFailure() {
        StubAgentPolicyURLProtocol.statusCode = 503
        StubAgentPolicyURLProtocol.responseData = Data("nope".utf8)
        let poller = DsseAgentPolicyPoller(
            session: stubSession(), url: URL(string: "https://edge.test/steer/agent-policy")!, pinnedPublicKeyHex: pubKeyHex)
        fetchSync(poller)
        XCTAssertNotNil(poller.lastFailureReason)

        StubAgentPolicyURLProtocol.statusCode = 200
        StubAgentPolicyURLProtocol.responseData = envelopeJSON.data(using: .utf8)
        fetchSync(poller)
        XCTAssertNil(poller.lastFailureReason, "a successful fetch must clear the reported failure")
    }
}
