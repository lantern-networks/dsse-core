import XCTest
@testable import DsseAppProxyProviderSkeleton

final class DsseRegionTCPProbeTests: XCTestCase {
    func testHostPortParsing() {
        XCTAssertNotNil(DsseRegionTCPProbe.hostPort("https://203.0.113.10:18543"))
        XCTAssertNotNil(DsseRegionTCPProbe.hostPort("https://203.0.113.10:18544"))
        XCTAssertNil(DsseRegionTCPProbe.hostPort("not a url"))
        XCTAssertNil(DsseRegionTCPProbe.hostPort("https://"))
    }

    // A closed port is not reachable (deterministic; no dependency on a running edge).
    func testClosedPortNotReachable() {
        let h = DsseRegionTCPProbe.probe(endpoint: "https://127.0.0.1:9", timeout: 1.0)
        XCTAssertFalse(h.reachable)
        XCTAssertFalse(h.admitted)
    }
}

// ★★★ A REGION THAT LISTENS AND REFUSES IS THE FAILURE THIS SELECTOR EXISTS FOR (2026-08-31).
//
// On 2026-08-30 both regions' Edges served no certificate for half an hour while 443 stayed open. The probe
// opened a TCP socket, called both regions healthy, and the device had nowhere to fail over to. These tests
// pin the two halves of that: a plain socket is not an admission, and — the part that is a kill switch if it
// is wrong — only a peer alert ABOUT THIS DEVICE'S CERTIFICATE counts as being denied.
extension DsseRegionTCPProbeTests {
    func testOnlyPeerAlertsAboutOurCertificateAreAdmissionDenials() {
        // Denials: the peer sent a fatal alert about the certificate we presented.
        for status: OSStatus in [-9825, -9832, -9833, -9834, -9835, -9836] {
            XCTAssertTrue(DsseRegionTCPProbe.isAdmissionDenial(status),
                          "\(status) is a peer alert about our certificate and must read as an admission denial")
            XCTAssertNotEqual(DsseRegionTCPProbe.denialName(status), "unknown",
                              "\(status) must be nameable to an operator")
        }
        // NOT denials. The caller arms instant-revoke on an admission deny, so anything read as a denial takes
        // this device dark at the first probe. A handshake that failed for any other reason is an unhealthy
        // region — which is recoverable, and which failover is for.
        for status: OSStatus in [
            -9802, // errSSLFatalAlert — the alert we send, not one about us
            -9806, // errSSLClosedAbort — the connection died mid-handshake
            -9807, // errSSLXCertChainInvalid — OUR trust evaluation of THEIR chain failed
            -9824, // a neighbouring status that is not an alert about our certificate: this is a list, not a range
            -9843, // errSSLHostNameMismatch — the region served a certificate for another name
            -1200, // a bare transport failure
            0,
        ] {
            XCTAssertFalse(DsseRegionTCPProbe.isAdmissionDenial(status),
                           "\(status) must NOT read as an admission denial — it would revoke this device")
        }
    }

    func testWithoutTransportParametersNothingIsAdmitted() {
        // Before a transport exists there is nothing to handshake with, and "not established" must not be
        // reported as a healthy, admitted region.
        let h = DsseRegionTCPProbe.probe(endpoint: "https://127.0.0.1:9", timeout: 1.0)
        XCTAssertFalse(h.admitted)
    }
}
