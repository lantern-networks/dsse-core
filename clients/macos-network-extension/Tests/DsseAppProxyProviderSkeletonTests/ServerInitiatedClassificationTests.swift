@testable import DsseAppProxyProviderSkeleton
import DsseNetworkExtensionContract
import NetworkExtension
import XCTest

//  (Mac S3): the pure server-initiated (inbound) classifier. NE-agnostic; reused by the Windows WFP
// and macOS Content Filter inbound enforcement paths (the NETransparentProxy inbound-rule path was removed).
final class ServerInitiatedClassificationTests: XCTestCase {

    func testClassifiesInboundServerFlow() {
        // A remote server (10.0.0.9) connects in to this device's RDP port.
        guard let c = classifyServerInitiatedInboundFlow(remoteHost: "10.0.0.9", localPort: 3389, deviceGroup: "workstations") else {
            return XCTFail("a real inbound flow must classify")
        }
        XCTAssertEqual(c.connectionInitiator, "server")  // triggers the Edge server-initiated branch
        XCTAssertEqual(c.sourceServer, "10.0.0.9")        // server identity = Legacy Exception / audit key
        XCTAssertEqual(c.deviceGroup, "workstations")
        XCTAssertEqual(c.serviceFamily, "rdp")            // derived from the LOCAL port
        XCTAssertEqual(c.networkProtocol, "tcp")
        XCTAssertEqual(c.destinationPort, 3389)
    }

    func testServiceFamilyMapping() {
        XCTAssertEqual(serverInitiatedServiceFamily(445), "smb")
        XCTAssertEqual(serverInitiatedServiceFamily(139), "smb")
        XCTAssertEqual(serverInitiatedServiceFamily(5985), "winrm")
        XCTAssertEqual(serverInitiatedServiceFamily(22), "ssh")
        XCTAssertEqual(serverInitiatedServiceFamily(135), "rpc")
        XCTAssertEqual(serverInitiatedServiceFamily(443), "https")
        XCTAssertEqual(serverInitiatedServiceFamily(9999), "tcp") // fallback
    }

    func testLoopbackInboundIsNotServerInitiated() {
        // Loopback is local traffic, not lateral movement — must NOT be governed as server-initiated.
        XCTAssertNil(classifyServerInitiatedInboundFlow(remoteHost: "127.0.0.1", localPort: 445, deviceGroup: "g"))
        XCTAssertNil(classifyServerInitiatedInboundFlow(remoteHost: "::1", localPort: 445, deviceGroup: "g"))
    }

    func testInvalidPortOrHostReturnsNil() {
        XCTAssertNil(classifyServerInitiatedInboundFlow(remoteHost: "10.0.0.9", localPort: 0, deviceGroup: "g"))
        XCTAssertNil(classifyServerInitiatedInboundFlow(remoteHost: "10.0.0.9", localPort: 70000, deviceGroup: "g"))
        XCTAssertNil(classifyServerInitiatedInboundFlow(remoteHost: "  ", localPort: 445, deviceGroup: "g"))
        XCTAssertNil(classifyServerInitiatedInboundFlow(remoteHost: "bad/host", localPort: 445, deviceGroup: "g"))
    }

    func testHostnameSourceServerNormalized() {
        guard let c = classifyServerInitiatedInboundFlow(remoteHost: "PatchSrv.Corp.Local.", localPort: 445, deviceGroup: "") else {
            return XCTFail("hostname inbound should classify")
        }
        XCTAssertEqual(c.sourceServer, "patchsrv.corp.local") // lowercased, trailing dot stripped
        XCTAssertEqual(c.deviceGroup, "")                      // empty device group = wildcard downstream
    }

    // NOTE: the provider's inbound-rule wiring (transparentProxyInboundAnyRemoteTCPRule / the
    // network_extension_server_initiated_inbound config gate) was removed — a NETransparentProxy is
    // outbound-only and an inbound rule bricks the proxy (networkSettingsInvalid, verified on-device
    // 2026-06-17). Inbound enforcement lives in Windows WFP / a macOS Content Filter, which reuse this
    // pure classifier.
}
