import XCTest
import Security
@testable import DsseAppProxyProviderSkeleton

// Tests for the device-identity lookup, run against the REAL keychain.
//
// These exist because the previous implementation asked the keychain to filter by kSecAttrLabel and trusted
// the answer. The keychain ignores that filter for identity queries and returns everything, so the lookup was
// returning an arbitrary identity — on a developer machine, an Apple Development signing identity. A stubbed
// keychain would have agreed with the old code, which is precisely why these run against the real one.
final class DsseClientIdentityLookupTests: XCTestCase {

    // THE regression. Before the fix this returned a real identity — somebody else's — because the keychain
    // ignored the label and the code took the first row it got.
    func testALabelThatMatchesNothingReturnsNil() {
        let nobody = "dsse-no-such-identity-\(UUID().uuidString)"
        XCTAssertNil(DsseTransportSecurityFactory.clientIdentity(label: nobody),
                     "a label matching nothing must yield nil so the caller fails closed — returning an " +
                     "arbitrary identity means presenting somebody else's certificate to the Edge")
    }

    func testEmptyAndBlankLabelsReturnNil() {
        for label in ["", "   ", "\t\n"] {
            XCTAssertNil(DsseTransportSecurityFactory.clientIdentity(label: label),
                         "a blank label (\(label.debugDescription)) must not match anything")
        }
    }

    // Whatever comes back must actually carry the name that was asked for. This is the property the old
    // implementation silently lacked.
    func testAnyReturnedIdentityCarriesTheRequestedName() throws {
        // Ask for something that plausibly exists on a development machine. If nothing matches, there is
        // nothing to assert and the test above already covers the no-match case.
        var result: CFTypeRef?
        guard SecItemCopyMatching([
            kSecClass as String: kSecClassIdentity,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnAttributes as String: true,
        ] as CFDictionary, &result) == errSecSuccess,
            let rows = result as? [[String: Any]],
            let anyLabel = rows.compactMap({ $0[kSecAttrLabel as String] as? String }).first else {
            throw XCTSkip("no identities on this machine to select between")
        }

        guard let found = DsseTransportSecurityFactory.clientIdentity(label: anyLabel) else {
            // Every candidate under this name may be expired, which the lookup correctly discards.
            return
        }
        var certificate: SecCertificate?
        XCTAssertEqual(SecIdentityCopyCertificate(found, &certificate), errSecSuccess)
        let cert = try XCTUnwrap(certificate)
        var cn: CFString?
        SecCertificateCopyCommonName(cert, &cn)
        XCTAssertEqual(cn as String?, anyLabel,
                       "the lookup returned an identity for a DIFFERENT name than the one requested")
    }

    // An expired certificate resolves fine and then fails on the wire — which is exactly how the 2026-07-17
    // outage presented. The lookup must not hand one back.
    func testAnyReturnedIdentityIsUnexpired() throws {
        var result: CFTypeRef?
        guard SecItemCopyMatching([
            kSecClass as String: kSecClassIdentity,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnAttributes as String: true,
        ] as CFDictionary, &result) == errSecSuccess,
            let rows = result as? [[String: Any]] else {
            throw XCTSkip("no identities on this machine")
        }
        let labels = Set(rows.compactMap { $0[kSecAttrLabel as String] as? String })
        for label in labels {
            guard let found = DsseTransportSecurityFactory.clientIdentity(label: label) else { continue }
            var certificate: SecCertificate?
            guard SecIdentityCopyCertificate(found, &certificate) == errSecSuccess,
                  let cert = certificate,
                  let notAfter = DsseCertificateRenewal.notAfter(of: cert) else { continue }
            XCTAssertGreaterThan(notAfter, Date(),
                                 "the lookup returned an EXPIRED identity for \(label) — it would resolve " +
                                 "cleanly and then fail the mTLS handshake on the wire")
        }
    }

    // When one device name has several certificates — the normal state right after a re-issue — selection must
    // converge on the newest rather than depend on keychain ordering.
    func testSelectionIsDeterministicAcrossRepeatedLookups() throws {
        var result: CFTypeRef?
        guard SecItemCopyMatching([
            kSecClass as String: kSecClassIdentity,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnAttributes as String: true,
        ] as CFDictionary, &result) == errSecSuccess,
            let rows = result as? [[String: Any]] else {
            throw XCTSkip("no identities on this machine")
        }
        var counts: [String: Int] = [:]
        for row in rows {
            if let label = row[kSecAttrLabel as String] as? String { counts[label, default: 0] += 1 }
        }
        guard let (duplicated, _) = counts.first(where: { $0.value > 1 }) else {
            throw XCTSkip("no duplicated identity name on this machine to disambiguate")
        }

        var seen = Set<Data>()
        for _ in 0..<5 {
            guard let found = DsseTransportSecurityFactory.clientIdentity(label: duplicated) else { continue }
            var certificate: SecCertificate?
            if SecIdentityCopyCertificate(found, &certificate) == errSecSuccess, let cert = certificate {
                seen.insert(SecCertificateCopyData(cert) as Data)
            }
        }
        XCTAssertLessThanOrEqual(seen.count, 1,
                                 "repeated lookups for \(duplicated) returned DIFFERENT certificates — " +
                                 "selection depends on keychain ordering, so which identity a device presents " +
                                 "would vary between runs")
    }

    // The contract's device-name field must be honoured, because the fixed product-string label matches
    // nothing: macOS files a certificate under its subject common name, not under a name we choose.
    func testContractCarriesTheDeviceNameAndStaysBackwardCompatible() throws {
        let json = """
        {
            "transport_tls_url": "https://edge.example.com:18543",
            "mtls_required": true,
            "client_identity_common_name": "mac-dev-1"
        }
        """
        let contract = try JSONDecoder().decode(DsseTransportContract.self, from: Data(json.utf8))
        XCTAssertEqual(contract.clientIdentityCommonName, "mac-dev-1")

        // Absent stays absent — an existing agent_config.json without the field must still decode.
        let legacy = """
        {"transport_tls_url": "https://edge.example.com:18543", "mtls_required": true}
        """
        let old = try JSONDecoder().decode(DsseTransportContract.self, from: Data(legacy.utf8))
        XCTAssertNil(old.clientIdentityCommonName)
    }
}

// The recovery endpoint the scheduler falls back to when this device's certificate has already expired.
extension DsseClientIdentityLookupTests {

    func testContractCarriesTheRenewalRecoveryEndpoint() throws {
        let json = """
        {
            "transport_tls_url": "https://edge.example.com:18543",
            "mtls_required": true,
            "renewal_recovery_endpoint": "edge.example.com:18545"
        }
        """
        let contract = try JSONDecoder().decode(DsseTransportContract.self, from: Data(json.utf8))
        XCTAssertEqual(contract.renewalRecoveryEndpoint, "edge.example.com:18545")

        // Absent stays absent: an agent_config.json written before this field existed must still decode, and a
        // device with no recovery endpoint simply cannot self-recover — it must not fail to start.
        let legacy = """
        {"transport_tls_url": "https://edge.example.com:18543", "mtls_required": true}
        """
        XCTAssertNil(try JSONDecoder().decode(DsseTransportContract.self, from: Data(legacy.utf8))
            .renewalRecoveryEndpoint)
    }

    // The endpoint is parsed as host:port. A malformed value must yield nil rather than a half-built target,
    // so the scheduler reports "no recovery endpoint" instead of dialling something nonsensical.
    func testRecoveryEndpointParsing() {
        XCTAssertNotNil(DsseTransportSecurityFactory.hostPort(fromTransportURL: "https://edge.example.com:18545"))
        // ★ CHANGED 2026-08-29: no port now means 443, because that is what the deployment's own profile
        // writes since the agent plane was folded onto one port. Refusing it left every profile-installed
        // device with no (T) transport at all — see ADoorWithoutAPortNumberTests.
        XCTAssertEqual(DsseTransportSecurityFactory.hostPort(fromTransportURL: "https://edge.example.com")?.port, 443,
                       "a door named without a port is the ordinary case now and must resolve to 443")
        XCTAssertNil(DsseTransportSecurityFactory.hostPort(fromTransportURL: "https://:18545"),
                     "a value with no host must not resolve to a target")
    }
}
