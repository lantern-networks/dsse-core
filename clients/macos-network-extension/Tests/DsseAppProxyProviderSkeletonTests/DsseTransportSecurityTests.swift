import XCTest
@testable import DsseAppProxyProviderSkeleton

final class DsseTransportSecurityTests: XCTestCase {
    // The (T) transport contract decodes from the agent_config block the Edge publishes ().
    func testTransportContractDecodesFromAgentConfigBlock() throws {
        let json = """
        {
          "transport_tls_url": "https://203.0.113.10:18543",
          "mtls_required": true,
          "dns_over_tunnel_path": "/steer/dns-query",
          "dns_over_tunnel_supported": true,
          "pinned_ca_ref": "transport_ca.pem"
        }
        """.data(using: .utf8)!
        let contract = try JSONDecoder().decode(DsseTransportContract.self, from: json)
        XCTAssertTrue(contract.enabled)
        XCTAssertEqual(contract.transportTLSURL, "https://203.0.113.10:18543")
        XCTAssertEqual(contract.mtlsRequired, true)
        XCTAssertEqual(contract.dnsOverTunnelPath, "/steer/dns-query")
        XCTAssertEqual(contract.pinnedCARef, "transport_ca.pem")
    }

    func testTransportContractDisabledWhenURLEmpty() throws {
        let json = "{ \"transport_tls_url\": \"\" }".data(using: .utf8)!
        let contract = try JSONDecoder().decode(DsseTransportContract.self, from: json)
        XCTAssertFalse(contract.enabled)
    }

    func testHostPortRequiresHTTPSHostAndPort() {
        let ok = DsseTransportSecurityFactory.hostPort(fromTransportURL: "https://203.0.113.10:18543")
        XCTAssertEqual(ok?.host, "203.0.113.10")
        XCTAssertEqual(ok?.port, 18543)
        // http (not https) rejected.
        XCTAssertNil(DsseTransportSecurityFactory.hostPort(fromTransportURL: "http://203.0.113.10:18543"))
        // ★ CHANGED 2026-08-29: a missing port is 443, not a refusal. The profile names the door as
        // https://agents.<region>.<zone>, and refusing that string took the whole (T) transport off every
        // device installed the documented way — see ADoorWithoutAPortNumberTests.
        XCTAssertEqual(DsseTransportSecurityFactory.hostPort(fromTransportURL: "https://edge.example.com")?.port, 443)
        // garbage rejected.
        XCTAssertNil(DsseTransportSecurityFactory.hostPort(fromTransportURL: "not a url"))
    }

    // The LAB device-identity fields decode and resolve() loads the mTLS client identity from a p12 FILE
    // (no MDM/keychain). This is the path that lets a real Mac present a device cert to the mtls_required
    // shared Edge without keychain enrollment.
    func testTransportContractDecodesP12IdentityFields() throws {
        let json = """
        {
          "transport_tls_url": "https://203.0.113.10:18543",
          "mtls_required": true,
          "pinned_ca_ref": "transport_ca.pem",
          "client_identity_p12_ref": "mac-device.p12",
          "client_identity_p12_pass_ref": "mac-device.p12.pass"
        }
        """.data(using: .utf8)!
        let contract = try JSONDecoder().decode(DsseTransportContract.self, from: json)
        XCTAssertEqual(contract.clientIdentityP12Ref, "mac-device.p12")
        XCTAssertEqual(contract.clientIdentityP12PassRef, "mac-device.p12.pass")
    }

    // When the contract references a p12 device-identity FILE, the resolver takes the p12 branch (not the
    // keychain/MDM path) and is FAIL-CLOSED: a missing/unreadable p12 yields a nil clientIdentity so an
    // mtls_required Edge rejects the handshake rather than silently connecting without a client cert. The
    // actual SecPKCS12Import success is covered by the on-device probe (DsseTransportProbe), since
    // SecPKCS12Import is unreliable under the xctest sandbox/keychain context.
    func testResolveP12IdentityIsFailClosedWhenFileMissing() throws {
        let dir = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("dsse-p12-missing-\(getpid())")
        try? FileManager.default.removeItem(at: dir)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        let json = """
        { "transport_tls_url": "https://203.0.113.10:18543", "mtls_required": true,
          "client_identity_p12_ref": "does-not-exist.p12", "client_identity_p12_pass_ref": "nope.pass" }
        """.data(using: .utf8)!
        let contract = try JSONDecoder().decode(DsseTransportContract.self, from: json)
        // Force a keychain label that cannot exist, so if the resolver wrongly fell through to the keychain
        // path it would still be nil — the assertion below is meaningful only because the p12 branch is taken.
        let sec = DsseTransportSecurityResolver.resolve(contract: contract, configDirectory: dir,
                                                               keychainLabel: "DSSE-test-no-such-identity-\(getpid())")
        XCTAssertNotNil(sec, "resolver should still materialize transport security (host/port/pin) when enabled")
        XCTAssertEqual(sec?.host, "203.0.113.10")
        XCTAssertEqual(sec?.port, 18543)
        XCTAssertTrue(sec?.mtlsRequired ?? false)
        XCTAssertNil(sec?.clientIdentity, "missing p12 file must fail closed to a nil identity")
    }

    func testCertificateFromPEMParsesAndRejectsGarbage() {
        let pem = """
        -----BEGIN CERTIFICATE-----
        MIIBfDCCASGgAwIBAgIULZ9abwUQ5ibO7eZMiaNXYSEfALowCgYIKoZIzj0EAwIw
        EzERMA8GA1UEAwwIcGluLXRlc3QwHhcNMjYwNjE3MDAzNzQwWhcNMjYwNzE3MDAz
        NzQwWjATMREwDwYDVQQDDAhwaW4tdGVzdDBZMBMGByqGSM49AgEGCCqGSM49AwEH
        A0IABOVX6owoq3Hu+lyVRhKOT6G2akNDmGtH7xLytS7HAE/drd6DZqC/GTEO4GHh
        1TfD9SGoWze9KDedW/WnBqKlX+CjUzBRMB0GA1UdDgQWBBTZV4v8AMNOwqsHNq+u
        N5TFJLSR5DAfBgNVHSMEGDAWgBTZV4v8AMNOwqsHNq+uN5TFJLSR5DAPBgNVHRMB
        Af8EBTADAQH/MAoGCCqGSM49BAMCA0kAMEYCIQC4UByGI+MunkOOZXwj56ByfbuN
        0tDSdCL3t/dzgF6BzAIhAIn6huYu4em/KY51O8KyZOsWp4OzvOtjiaMqFAEN5+/u
        -----END CERTIFICATE-----
        """
        XCTAssertNotNil(DsseTransportSecurityFactory.certificate(fromPEM: pem), "valid PEM should parse to a SecCertificate")
        XCTAssertNil(DsseTransportSecurityFactory.certificate(fromPEM: "no cert here"), "garbage should not parse")
    }

    // Slice 1 (G3): notAfter reading is nil-safe. A security with no client identity reports no expiry (so the
    // provider logs "unavailable" rather than crashing), and the static helper is nil-safe on a nil identity.
    // The REAL extraction from a device cert is verified on-device (the startProxy client_identity_not_after
    // log line), because SecPKCS12Import is unreliable under the xctest sandbox — same reason the p12 tests
    // above only cover the fail-closed path.
    func testClientIdentityNotAfterIsNilWhenNoIdentity() {
        let sec = DsseTransportSecurity(host: "edge", port: 18543, mtlsRequired: true,
                                        pinnedCACertificate: nil, clientIdentity: nil)
        XCTAssertNil(sec.clientIdentityNotAfter, "no identity -> no expiry")
        XCTAssertNil(DsseTransportSecurityFactory.notAfter(ofClientIdentity: nil), "nil identity -> nil notAfter")
    }
}
