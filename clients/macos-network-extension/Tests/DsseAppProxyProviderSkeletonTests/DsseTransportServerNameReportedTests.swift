import XCTest
@testable import DsseAppProxyProviderSkeleton

/// ★★★ THIS AGENT NEVER SENT transport_server_name_sent (2026-08-22, measured on this lab).
///
/// Windows has shipped the field since 0.2.10. macOS had no parameter and no body key, so every Edge-side
/// measurement that turns on it — the enrolment fold, a transport-name rename, and the withdrawal of an
/// organization's shared anchor — read this device as SILENT for ever, and a rename could never be finished
/// in either direction.
///
/// The value must come from the route the request actually takes. A device dialling by address is served the
/// deployment-wide certificate however good the name it HOLDS, and reporting the held name would open the
/// withdrawal gate and lock the device out — which is exactly what happened.
final class DsseTransportServerNameReportedTests: XCTestCase {
    func testTheNameIsAttachedOnlyWhenTheDeviceActuallySendsOne() {
        var body: [String: Any] = [:]
        DsseAgentPolicyPoller.attachTransportServerName(&body, sent: "LAB.dsse.invalid")
        XCTAssertEqual(body["transport_server_name_sent"] as? String, "lab.dsse.invalid",
                       "normalised the way the Edge compares it, like every other reported name")

        var none: [String: Any] = [:]
        DsseAgentPolicyPoller.attachTransportServerName(&none, sent: "")
        XCTAssertNil(none["transport_server_name_sent"],
                     "an empty string is a CLAIM that this device sends no name; the Edge must read silence " +
                     "as 'did not say' and keep the shared anchor, so the key is omitted entirely")

        var blank: [String: Any] = [:]
        DsseAgentPolicyPoller.attachTransportServerName(&blank, sent: "   ")
        XCTAssertNil(blank["transport_server_name_sent"], "whitespace is silence too")
    }

    /// A poller built on an injected session has no per-organization transport, so it dials by address — and
    /// it must say so by reporting nothing, not by reporting a name it does not send.
    func testAPollerDiallingByAddressReportsNoName() throws {
        let url = try XCTUnwrap(URL(string: "https://203.0.113.10:18543/steer/agent-policy"))
        let poller = DsseAgentPolicyPoller(session: .shared, url: url, pinnedPublicKeyHex: "aa")
        XCTAssertEqual(poller.transportServerNameSent(), "",
                       "this poller sends the URL's host, not the organization's name — reporting the name " +
                       "would tell the Edge the fold is complete for a device that is still on the shared " +
                       "certificate")
    }
}
