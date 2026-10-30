@testable import DsseAppProxyProviderSkeleton
import DsseNetworkExtensionContract
import Foundation
import XCTest

final class ExactHTTPSPassthroughTests: XCTestCase {
    func testOnlyOriginalIdPNameAtPinnedAddressAndHTTPSPortBypasses() {
        let rule = DsseExactHTTPSPassthroughEndpoint(
            hostname: "idp.example.test", addresses: ["203.0.113.10"])
        func decision(_ host: String, _ port: Int = 443, _ address: String? = "203.0.113.10",
                      _ transport: ProviderFlowTransport = .tcp) -> DsseTransparentPassthroughDecision {
            DsseAppProxyProvider.exactHTTPSPassthroughDecision(
                input: ProviderFlowAuthorityInput(transport: transport, remoteHost: host, remotePort: port),
                resolvedRemoteAddress: address, endpoints: [rule])
        }

        XCTAssertTrue(decision("idp.example.test").shouldPassThrough)
        for denied in [
            decision("sub.idp.example.test"),
            decision("idp.example.test", 80),
            decision("idp.example.test", 8443),
            decision("idp.example.test", 443, "203.0.113.11"),
            decision("idp.example.test", 443, nil),
            decision("203.0.113.10"),
            decision("idp.example.test", 443, "203.0.113.10", .udp),
        ] {
            XCTAssertFalse(denied.shouldPassThrough)
        }
    }

    func testOriginalHostnameAndDialedAddressRemainSeparateFacts() {
        let endpoint = DsseProviderFlowAuthorityObservation(
            input: ProviderFlowAuthorityInput(transport: .tcp, remoteHost: "203.0.113.10", remotePort: 443),
            endpointSourceGate: "remote_flow_endpoint_hostport", portSourceGate: "hostport_rawvalue_fallback")
        let named = DsseAppProxyProvider.authorityObservationPreferringFlowRemoteHostname(
            flowRemoteHostname: "idp.example.test", endpointObservation: endpoint)
        XCTAssertEqual(named.input.remoteHost, "idp.example.test")
        XCTAssertEqual(named.resolvedRemoteAddress, "203.0.113.10")
        let addressOnly = DsseAppProxyProvider.authorityObservationPreferringFlowRemoteHostname(
            flowRemoteHostname: nil, endpointObservation: endpoint)
        XCTAssertNil(addressOnly.resolvedRemoteAddress)
        XCTAssertEqual(addressOnly.input.remoteHost, "203.0.113.10")
    }

    func testConfigurationRejectsDNSDriftAndMalformedOrBroadEntries() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("dsse-exact-https-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("agent_config.json")
        func write(_ entries: [[String: Any]]) throws {
            let data = try JSONSerialization.data(withJSONObject: [
                "network_extension_exact_https_passthrough_endpoints": entries
            ])
            try data.write(to: path, options: .atomic)
        }

        let resolved = DsseAppProxyProvider.addressesFor(domains: ["localhost"])
        XCTAssertFalse(resolved.isEmpty)
        try write([["hostname": "localhost", "addresses": resolved.sorted()]])
        XCTAssertEqual(DsseAppProxyProvider.exactHTTPSPassthroughEndpoints(agentConfigPath: path.path),
                       [DsseExactHTTPSPassthroughEndpoint(hostname: "localhost", addresses: resolved)])

        try write([["hostname": "localhost", "addresses": ["203.0.113.10"]]])
        XCTAssertTrue(DsseAppProxyProvider.exactHTTPSPassthroughEndpoints(agentConfigPath: path.path).isEmpty)
        try write([["hostname": "*.localhost", "addresses": resolved.sorted()]])
        XCTAssertTrue(DsseAppProxyProvider.exactHTTPSPassthroughEndpoints(agentConfigPath: path.path).isEmpty)
        try write([["hostname": "localhost", "addresses": resolved.sorted()],
                   ["hostname": "localhost", "addresses": resolved.sorted()]])
        XCTAssertTrue(DsseAppProxyProvider.exactHTTPSPassthroughEndpoints(agentConfigPath: path.path).isEmpty)
    }

    func testIPv6NumericAddressIsCanonicalizedWithoutDNSLookup() {
        XCTAssertEqual(DsseAppProxyProvider.canonicalNumericAddress("[2001:DB8::10]"), "2001:db8::10")
        XCTAssertNil(DsseAppProxyProvider.canonicalNumericAddress("idp.example.test"))
        XCTAssertNil(DsseAppProxyProvider.canonicalNumericAddress("fe80::1%en0"))
    }

    func testExistingBroadDomainExclusionRemainsIndependentAndMustNotOverlap() {
        let exact = DsseExactHTTPSPassthroughEndpoint(
            hostname: "idp.example.test", addresses: ["203.0.113.10"])
        let otherPort = ProviderFlowAuthorityInput(
            transport: .tcp, remoteHost: "idp.example.test", remotePort: 8443)
        XCTAssertFalse(DsseAppProxyProvider.exactHTTPSPassthroughDecision(
            input: otherPort, resolvedRemoteAddress: "203.0.113.10", endpoints: [exact]
        ).shouldPassThrough)
        // Compatibility is intentional, but means an administrator must remove
        // the old entry when switching this IdP to the narrow rule.
        XCTAssertTrue(DsseAppProxyProvider.transparentPassthroughDomainDecision(
            input: otherPort, domains: ["idp.example.test"]
        ).shouldPassThrough)
    }
}
