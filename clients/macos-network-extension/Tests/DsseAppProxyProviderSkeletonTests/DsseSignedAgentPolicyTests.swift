import XCTest
import CryptoKit
@testable import DsseAppProxyProviderSkeleton

// Cross-language verification: this envelope + public key were produced by the GO Edge signer
// (agent_policy_signing.go). The Swift NE must verify a Go-signed policy, or the feature does not work
// end-to-end. The fixture is deterministic (fixed seed) so it is stable.
final class DsseSignedAgentPolicyTests: XCTestCase {
    // Go-produced fixture (seed 0102..20):
    private let pubKeyHex = "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664"
    private let envelopeJSON = """
    {"type":"dsse_agent_steer_policy.v1","version":"1","signing_key_id":"edge-agent-policy-65b60673d6ed884b","created_at":"2026-06-19T00:00:00Z","payload_sha256":"d36582e645945d1ff924a9e9b8ca298cbbe9a2891131fcf0c3b2fc040e17ff9c","payload_b64":"eyJkZXZpY2VfZ3JvdXAiOiIiLCJkZXZpY2VfaWRlbnRpdHkiOiJtYWMtZGV2LTEiLCJleGNsdWRlZF9hcHBfc2lnbmluZ19pZHMiOlsiY29tLmNvcnAudnBuY2xpZW50IiwiY29tLmV4YW1wbGUuZGV2dG9vbCJdLCJzY2hlbWFfdmVyc2lvbiI6ImRvbWVzdGljX3NzZV9hZ2VudF9zdGVlcl9wb2xpY3kudjEiLCJ0ZW5hbnRfaWQiOiJ0ZW5hbnRfdHJhY2tfYV91YzAzYV9sYWIifQ==","signature":"ed25519:rOnMYYF_h9O6iWoBsSq8y2qmZ3KleakbjkRbpooZMsPNi6tXW_WrBcQ64DoVy4rRJUiNpIIdQf2LKlA7ACjbDQ"}
    """

    private func writeTemp(_ contents: String) -> String {
        let path = NSTemporaryDirectory() + "signed_policy_\(UUID().uuidString).json"
        try? contents.write(toFile: path, atomically: true, encoding: .utf8)
        return path
    }

    func testGoSignedPolicyVerifiesInSwift() {
        let path = writeTemp(envelopeJSON)
        defer { try? FileManager.default.removeItem(atPath: path) }
        let result = DsseSignedAgentPolicy.verifiedServerExclusions(
            signedPath: path, pinnedPublicKeyHex: pubKeyHex, expectedDeviceIdentity: "mac-dev-1",
            expectedTenantID: "tenant_track_a_uc03a_lab")
        XCTAssertEqual(result, ["com.corp.vpnclient", "com.example.devtool"],
                       "the Go-signed server exclusion set must verify and parse in the NE")
    }

    func testDeviceScopedPolicyIsNotAcceptedWithoutADeviceOwner() {
        let envelope = Data(envelopeJSON.utf8)
        XCTAssertNil(DsseSignedAgentPolicy.verifiedServerExclusions(
            envelopeData: envelope, pinnedPublicKeyHex: pubKeyHex),
            "a valid signature for mac-dev-1 alone cannot authorize an unidentified device")
    }

    func testSameDeviceNameCannotApplySignedPolicyWithoutTenantBinding() {
        // A deployment key signs policies for many tenants. The same certificate CN can be presented
        // under a different tenant authority after a legitimate reprovisioning, while this old policy
        // remains cached. Device-name binding alone must not apply the old tenant's exclusions.
        XCTAssertNil(DsseSignedAgentPolicy.verifiedServerExclusions(
            envelopeData: Data(envelopeJSON.utf8), pinnedPublicKeyHex: pubKeyHex,
            expectedDeviceIdentity: "mac-dev-1"))
    }

    func testDeviceScopedPolicyRejectsAnotherDeviceAndAcceptsExactOwner() {
        let envelope = Data(envelopeJSON.utf8)
        XCTAssertNil(DsseSignedAgentPolicy.verifiedServerExclusions(
            envelopeData: envelope, pinnedPublicKeyHex: pubKeyHex,
            expectedDeviceIdentity: "mac-dev-2"))
        XCTAssertEqual(DsseSignedAgentPolicy.verifiedServerExclusions(
            envelopeData: envelope, pinnedPublicKeyHex: pubKeyHex,
            expectedDeviceIdentity: "mac-dev-1", expectedTenantID: "tenant_track_a_uc03a_lab"),
            ["com.corp.vpnclient", "com.example.devtool"])
        XCTAssertEqual(DsseSignedAgentPolicy.verifiedServerExclusions(
            envelopeData: envelope, pinnedPublicKeyHex: pubKeyHex,
            expectedDeviceIdentity: "MAC-DEV-1", expectedTenantID: "tenant_track_a_uc03a_lab"),
            ["com.corp.vpnclient", "com.example.devtool"],
            "the Edge canonicalizes certificate CNs by trimming and lowercasing")
    }

    func testEveryPolicyFieldRequiresTheCertificateDeviceIdentity() throws {
        let key = Curve25519.Signing.PrivateKey()
        let root = String(repeating: "a", count: 64)
        let payload = try JSONSerialization.data(withJSONObject: [
            "device_identity": "mac-dev-1",
            "tenant_id": "Tenant-Exact",
            "excluded_app_signing_ids": ["com.example.policy"],
            "interception_root_sha256": [root],
            "renew_certificates_issued_before": "2026-10-23T00:00:00Z",
        ])
        let signature = try key.signature(for: payload).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        let envelope = try JSONSerialization.data(withJSONObject: [
            "type": DsseSignedAgentPolicy.envelopeType,
            "signing_key_id": "test",
            "payload_sha256": SHA256.hash(data: payload).map { String(format: "%02x", $0) }.joined(),
            "payload_b64": payload.base64EncodedString(),
            "signature": "ed25519:" + signature,
        ])
        let pin = key.publicKey.rawRepresentation.map { String(format: "%02x", $0) }.joined()
        XCTAssertEqual(DsseSignedAgentPolicy.verifiedServerExclusions(
            envelopeData: envelope, pinnedPublicKeyHex: pin,
            expectedDeviceIdentity: "mac-dev-1", expectedTenantID: "Tenant-Exact"), ["com.example.policy"])
        XCTAssertEqual(DsseSignedAgentPolicy.verifiedInterceptionRoots(
            envelopeData: envelope, pinnedPublicKeyHex: pin,
            expectedDeviceIdentity: "mac-dev-1", expectedTenantID: "Tenant-Exact"), [root])
        XCTAssertEqual(DsseSignedAgentPolicy.verifiedDeploymentTenant(
            envelopeData: envelope, pinnedPublicKeyHex: pin,
            expectedDeviceIdentity: "mac-dev-1"), "Tenant-Exact")
        XCTAssertNotNil(DsseSignedAgentPolicy.verifiedRenewCertificatesIssuedBefore(
            envelopeData: envelope, pinnedPublicKeyHex: pin,
            expectedDeviceIdentity: "mac-dev-1", expectedTenantID: "Tenant-Exact"))
        XCTAssertNil(DsseSignedAgentPolicy.verifiedServerExclusions(
            envelopeData: envelope, pinnedPublicKeyHex: pin,
            expectedDeviceIdentity: "mac-dev-1", expectedTenantID: "tenant-other"),
            "a valid deployment signature and the same CN cannot transfer enforcement between tenants")
        XCTAssertEqual(DsseSignedAgentPolicy.verifiedInterceptionRoots(
            envelopeData: envelope, pinnedPublicKeyHex: pin,
            expectedDeviceIdentity: "mac-dev-1", expectedTenantID: "tenant-other"), [])
        XCTAssertNil(DsseSignedAgentPolicy.verifiedRenewCertificatesIssuedBefore(
            envelopeData: envelope, pinnedPublicKeyHex: pin,
            expectedDeviceIdentity: "mac-dev-1", expectedTenantID: "tenant-other"))
        XCTAssertEqual(DsseSignedAgentPolicy.verifiedDeploymentTenant(
            envelopeData: envelope, pinnedPublicKeyHex: pin,
            expectedDeviceIdentity: "mac-dev-1"), "Tenant-Exact",
            "startup must still read the signed old tenant for mismatch diagnosis, without applying it")
        XCTAssertNil(DsseSignedAgentPolicy.verifiedServerExclusions(
            envelopeData: envelope, pinnedPublicKeyHex: pin,
            expectedDeviceIdentity: "mac-dev-2"))
        XCTAssertEqual(DsseSignedAgentPolicy.verifiedInterceptionRoots(
            envelopeData: envelope, pinnedPublicKeyHex: pin,
            expectedDeviceIdentity: "mac-dev-2"), [])
        XCTAssertNil(DsseSignedAgentPolicy.verifiedDeploymentTenant(
            envelopeData: envelope, pinnedPublicKeyHex: pin,
            expectedDeviceIdentity: "mac-dev-2"))
        XCTAssertNil(DsseSignedAgentPolicy.verifiedRenewCertificatesIssuedBefore(
            envelopeData: envelope, pinnedPublicKeyHex: pin,
            expectedDeviceIdentity: "mac-dev-2"))
    }

    func testWrongPinnedKeyRejected() {
        let path = writeTemp(envelopeJSON)
        defer { try? FileManager.default.removeItem(atPath: path) }
        let wrongKey = "0000000000000000000000000000000000000000000000000000000000000000"
        XCTAssertNil(DsseSignedAgentPolicy.verifiedServerExclusions(signedPath: path, pinnedPublicKeyHex: wrongKey),
                     "a policy signed by an untrusted key must be rejected")
    }

    func testTamperedPayloadRejected() {
        // Swap payload_b64 for a different (attacker) payload while keeping the original signature.
        let tampered = envelopeJSON.replacingOccurrences(
            of: "\"payload_b64\":\"eyJkZXZ",
            with: "\"payload_b64\":\"eyJleGNsdWRlZF9hcHBfc2lnbmluZ19pZHMiOlsiY29tLmF0dGFja2VyIl19\",\"_x\":\"eyJkZXZ")
        let path = writeTemp(tampered)
        defer { try? FileManager.default.removeItem(atPath: path) }
        XCTAssertNil(DsseSignedAgentPolicy.verifiedServerExclusions(signedPath: path, pinnedPublicKeyHex: pubKeyHex),
                     "an edited payload must fail signature/checksum verification (the user cannot tamper)")
    }

    func testMissingFileReturnsNil() {
        XCTAssertNil(DsseSignedAgentPolicy.verifiedServerExclusions(signedPath: "/nonexistent/x.json", pinnedPublicKeyHex: pubKeyHex))
    }

    // Regression (live finding 2026-06-19): a verified server policy must ADD to — never REPLACE — the local
    // self-exclusion list. The local list carries loop-prevention INFRASTRUCTURE exclusions (e.g. a co-located
    // edge egress process). Replacing it dropped that infra exclusion, the edge egress self-looped back into
    // the NE, and EVERY flow returned 502. The merge must keep the local infra set and add the signed app set.
    func testSignedPolicyIsAdditiveToLocalInfraSelfExclusion() {
        let signedPath = writeTemp(envelopeJSON)
        defer { try? FileManager.default.removeItem(atPath: signedPath) }
        let configJSON = """
        {
          "network_extension_self_exclusion_default_signing_identifiers_enabled": false,
          "network_extension_self_exclusion_source_app_signing_identifiers": ["limactl-loop-egress", "a.out"],
          "network_extension_agent_policy_signed_path": "\(signedPath)",
          "network_extension_agent_policy_signing_public_key": "\(pubKeyHex)"
        }
        """
        let configPath = writeTemp(configJSON)
        defer { try? FileManager.default.removeItem(atPath: configPath) }

        let policy = DsseAppProxyProvider.selfExclusionPolicy(
            agentConfigPath: configPath,
            serverExclusionsOverride: ["com.corp.vpnclient", "com.example.devtool"])
        XCTAssertTrue(policy.excludes(sourceAppSigningIdentifier: "limactl-loop-egress"),
                      "the local loop-prevention infra exclusion must survive a signed server policy")
        XCTAssertTrue(policy.excludes(sourceAppSigningIdentifier: "a.out"),
                      "the local loop-prevention infra exclusion must survive a signed server policy")
        XCTAssertTrue(policy.excludes(sourceAppSigningIdentifier: "com.corp.vpnclient"),
                      "the server-issued admin app exclusion must be applied additively")
        XCTAssertTrue(policy.excludes(sourceAppSigningIdentifier: "com.example.devtool"),
                      "the server-issued admin app exclusion must be applied additively")
    }

    // Without a signed policy the local list is the sole source (unchanged pre-feature behavior).
    func testNoSignedPolicyUsesLocalListOnly() {
        let configJSON = """
        {
          "network_extension_self_exclusion_default_signing_identifiers_enabled": false,
          "network_extension_self_exclusion_source_app_signing_identifiers": ["limactl-loop-egress"]
        }
        """
        let configPath = writeTemp(configJSON)
        defer { try? FileManager.default.removeItem(atPath: configPath) }
        let policy = DsseAppProxyProvider.selfExclusionPolicy(agentConfigPath: configPath)
        XCTAssertTrue(policy.excludes(sourceAppSigningIdentifier: "limactl-loop-egress"))
        XCTAssertFalse(policy.excludes(sourceAppSigningIdentifier: "com.corp.vpnclient"),
                       "with no signed policy, server-only entries must not appear")
    }
}
