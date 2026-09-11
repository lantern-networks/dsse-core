import XCTest
@testable import DsseAppProxyProviderSkeleton

// Probes a RUNNING Edge, so it is inherently deployment-specific and takes its inputs from the environment.
// It SKIPS when they are absent rather than failing: this lives in the public OSS package, where nobody else
// has this lab, and a test that fails everywhere but one machine is worse than no test at all. It previously
// hard-coded one developer's checkout path and lab IP, which also put a personal name into the public package.
//
//   DSSE_LAB_TRANSPORT_CA    PEM of the anchors published for the Edge under test
//   DSSE_LAB_TRANSPORT_HOST  host of the (T) transport listener
//   DSSE_LAB_TRANSPORT_PORT  port of the (T) transport listener
//   DSSE_LAB_UNRELATED_CA    (optional) PEM of a CA that did NOT sign this Edge
final class DsseTrustAnchorRecoveryLiveTests: XCTestCase {
    private func env(_ key: String) -> String? {
        guard let v = ProcessInfo.processInfo.environment[key]?
            .trimmingCharacters(in: .whitespacesAndNewlines), !v.isEmpty else { return nil }
        return v
    }

    private func labTarget() throws -> (host: String, port: Int) {
        guard let host = env("DSSE_LAB_TRANSPORT_HOST"),
              let portText = env("DSSE_LAB_TRANSPORT_PORT"), let port = Int(portText) else {
            throw XCTSkip("set DSSE_LAB_TRANSPORT_HOST and DSSE_LAB_TRANSPORT_PORT to run the live probe")
        }
        return (host, port)
    }

    private func pem(_ key: String) throws -> String {
        guard let path = env(key), let text = try? String(contentsOfFile: path, encoding: .utf8) else {
            throw XCTSkip("set \(key) to a readable PEM to run the live probe")
        }
        return text
    }

    // The TRANSPORT listener, not the data plane: they serve different certificates, so probing the wrong port
    // answers a question about the wrong listener. The live lab is what made that visible.
    func testPublishedAnchorsValidateTheRunningEdge() throws {
        let target = try labTarget()
        let anchors = DsseSignedTrustBundle.parseAnchors(try pem("DSSE_LAB_TRANSPORT_CA"))
        XCTAssertFalse(anchors.isEmpty, "the published bundle must contain at least one CA")
        XCTAssertEqual(
            DsseTrustAnchorRecovery.probeAnchorsValidateEdge(host: target.host, port: target.port, anchors: anchors),
            true,
            "the anchors published for this Edge must validate it, or a healthy device would self-heal for no reason")
    }

    // A real CA, but not this Edge's: the probe must say NO rather than shrug, or recovery would never trigger.
    func testAnUnrelatedAnchorDoesNotValidateTheEdge() throws {
        let target = try labTarget()
        let anchors = DsseSignedTrustBundle.parseAnchors(try pem("DSSE_LAB_UNRELATED_CA"))
        try XCTSkipIf(anchors.isEmpty, "DSSE_LAB_UNRELATED_CA contained no CA certificate")
        XCTAssertEqual(
            DsseTrustAnchorRecovery.probeAnchorsValidateEdge(host: target.host, port: target.port, anchors: anchors),
            false)
    }
}
