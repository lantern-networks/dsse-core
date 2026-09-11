import XCTest
import CryptoKit
@testable import DsseAppProxyProviderSkeleton

// Cross-language proof: this envelope was produced by the Go Edge and is verified here by the Swift client.
// A signature scheme that round-trips only within one language is worth nothing to a device — the whole point
// is that the Edge signs and the endpoint verifies.
//
// The fixture is a REAL bundle served by the running lab Edge at GET /bootstrap/trust-bundle, fetched WITHOUT
// validating the server certificate — which is the situation the document exists for.
final class DsseSignedTrustBundleTests: XCTestCase {
    private let liveEnvelope = Data("""
{\"type\":\"dsse_agent_steer_policy.v1\",\"version\":\"1\",\"signing_key_id\":\"edge-agent-policy-1685d085f8d5d59a\",\"created_at\":\"2026-07-29T20:50:28Z\",\"payload_sha256\":\"4931487e1ecf2932e114bab8f3dfe9043430b90a8c03ec9dfdb589fb59d00aee\",\"payload_b64\":\"eyJzY2hlbWFfdmVyc2lvbiI6ImRzc2UudHJ1c3QtYnVuZGxlLnYxIiwidGVuYW50X2lkIjoidGVuYW50X3RyYWNrX2FfdWMwM2FfbGFiIiwic2VyaWFsIjoxLCJpc3N1ZWRfYXQiOiIyMDI2LTA3LTI5VDIwOjUwOjI4WiIsInRyYW5zcG9ydF9jYV9wZW0iOiItLS0tLUJFR0lOIENFUlRJRklDQVRFLS0tLS1cbk1JSUJ2VENDQVdPZ0F3SUJBZ0lVWGM5T1NLOXp6UWdzcVhDQ2JQKy95T1VkUExvd0NnWUlLb1pJemowRUF3SXdcbklURWZNQjBHQTFVRUF3d1daRzl0WlhOMGFXTXRjM05sTFhSeVlXNXpjRzl5ZERBZUZ3MHlOakEzTVRjd016UTRcbk5UQmFGdzB5TnpBNE1UZ3dNelE0TlRCYU1DRXhIekFkQmdOVkJBTU1GbVJ2YldWemRHbGpMWE56WlMxMGNtRnVcbmMzQnZjblF3V1RBVEJnY3Foa2pPUFFJQkJnZ3Foa2pPUFFNQkJ3TkNBQVExNnVLKzJsV1VmQjNDbkZ4U0VvdElcbktvYUdkV1FmR21SanRIR21OT2tVMEROaDc3UWVKYTVISFdvWitDcWZ4YUlJSVJ3cUJneHI4UE5YejkzanBUK3Zcbm8za3dkekFQQmdOVkhSTUJBZjhFQlRBREFRSC9NQTRHQTFVZER3RUIvd1FFQXdJQ2hEQVRCZ05WSFNVRUREQUtcbkJnZ3JCZ0VGQlFjREFUQWdCZ05WSFJFRUdUQVhod1RBcUFFL2h3Ui9BQUFCZ2dsc2IyTmhiR2h2YzNRd0hRWURcblZSME9CQllFRkxVRG5pYkdyQ2pvdzNkYTkyQUsyR1hnQ3JxVU1Bb0dDQ3FHU000OUJBTUNBMGdBTUVVQ0lRREtcbldsOXlpenR5M0VGOGJ0anBOTkh3U1RoVmhJQjNKYllubTlsTk5vck16Z0lnWE5BbHBTT0VCVzJIYk9QdGhwWWlcblZ1V0EyNVVhOHE1Z1hMQll6SUplcWhVPVxuLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLVxuLS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tXG5NSUlCZXpDQ0FTS2dBd0lCQWdJUkFJTGhJRk13eTloaEZqZlBXdElkdmtnd0NnWUlLb1pJemowRUF3SXdIREVhXG5NQmdHQTFVRUF4TVJSRk5UUlNCVWNtRnVjM0J2Y25RZ1EwRXdIaGNOTWpZd056STVNVEExTXpJM1doY05Nell3XG5Oekk1TVRFMU16STNXakFjTVJvd0dBWURWUVFERXhGRVUxTkZJRlJ5WVc1emNHOXlkQ0JEUVRCWk1CTUdCeXFHXG5TTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCRlRSZERnYTZBSDAvZWFtTHFYQStzUHRXbXZPKy9XRWNZS3RHZ01VXG5UbUZFVkt3S05BQitQNUF3QkdEN0pUUk0zRDc3eGtmVGwvVVVGTGRhNXRRZUhwaWpSVEJETUE0R0ExVWREd0VCXG4vd1FFQXdJQmhqQVNCZ05WSFJNQkFmOEVDREFHQVFIL0FnRUJNQjBHQTFVZERnUVdCQlE0MXBiSnNUYXRtLzJhXG4rUzNkM0Z6dGFmVEJ4ekFLQmdncWhrak9QUVFEQWdOSEFEQkVBaUJCYjFiZ2FURDdaVkdYK1FocHhqdDdvMkdjXG54dHlYbHZPMitKSUYvTnlmVmdJZ2ZxNk9ZVlB3L29UYUhtYk5UZ2N1QzRRTlM4RllhaHh0S3ZMbTV3bFlHN3M9XG4tLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tXG4iLCJyZW5ld2FsX3JlY292ZXJ5X2VuZHBvaW50IjoiMTkyLjE2OC4xLjYzOjE4NTQ1In0=\",\"signature\":\"ed25519:DcmQ1IpecRJRjBFePCHxwpmOgNwpRXbI3PaRPeU2dufVF9aX-lu7KC4nKBn2c7oTTLNLMchcFhr_vVaWqNeRCA\"}
""".utf8)
    private let pinnedKey = "b408c812edcb3d4cafc72b6619c917aae7ddeb79f5cc63f2dc46e9204d7a5e57"

    func testVerifiesABundleSignedByTheEdge() throws {
        let got = DsseSignedTrustBundle.verified(envelopeData: liveEnvelope, pinnedPublicKeyHex: pinnedKey, lastAcceptedSerial: 0)
        let bundle = try XCTUnwrap(got, "a bundle signed by the Edge must verify in the client, or the scheme is useless")
        XCTAssertGreaterThan(bundle.serial, 0)
        let anchors = DsseSignedTrustBundle.parseAnchors(bundle.anchorsPEM)
        XCTAssertEqual(anchors.count, 2, "the lab publishes the old anchor plus the new CA — an overlap is the normal mid-rotation state")
    }

    func testRefusesAReplayOfAnAlreadyAcceptedSerial() throws {
        let first = try XCTUnwrap(DsseSignedTrustBundle.verified(envelopeData: liveEnvelope, pinnedPublicKeyHex: pinnedKey, lastAcceptedSerial: 0))
        XCTAssertNil(
            DsseSignedTrustBundle.verified(envelopeData: liveEnvelope, pinnedPublicKeyHex: pinnedKey, lastAcceptedSerial: first.serial),
            "re-serving the accepted serial is a replay; only a strict advance is safe, or a withdrawn CA could be restored")
        XCTAssertNil(
            DsseSignedTrustBundle.verified(envelopeData: liveEnvelope, pinnedPublicKeyHex: pinnedKey, lastAcceptedSerial: first.serial + 100),
            "a bundle older than what this device holds must be refused")
    }

    func testFailsClosedOnAnUnpinnedKeyOrTamperedPayload() throws {
        var wrong = Array(pinnedKey)
        wrong[0] = wrong[0] == "a" ? "b" : "a"
        XCTAssertNil(DsseSignedTrustBundle.verified(envelopeData: liveEnvelope, pinnedPublicKeyHex: String(wrong), lastAcceptedSerial: 0),
                     "a key this device did not pin must never verify a bundle")
        XCTAssertNil(DsseSignedTrustBundle.verified(envelopeData: liveEnvelope, pinnedPublicKeyHex: "", lastAcceptedSerial: 0),
                     "an empty pin must not be treated as 'accept anything'")

        var text = try XCTUnwrap(String(data: liveEnvelope, encoding: .utf8))
        text = text.replacingOccurrences(of: "\"payload_b64\":\"e", with: "\"payload_b64\":\"f")
        XCTAssertNil(DsseSignedTrustBundle.verified(envelopeData: Data(text.utf8), pinnedPublicKeyHex: pinnedKey, lastAcceptedSerial: 0),
                     "a tampered payload must be refused")
    }

    // The CA PEM the live fixture carries — a real lab CA, reused so a hand-signed bundle parses its anchors.
    private func liveTransportCAPEM() throws -> String {
        let env = try XCTUnwrap(try JSONSerialization.jsonObject(with: liveEnvelope) as? [String: Any])
        let b64 = try XCTUnwrap(env["payload_b64"] as? String)
        let payload = try XCTUnwrap(Data(base64Encoded: b64))
        let body = try XCTUnwrap(try JSONSerialization.jsonObject(with: payload) as? [String: Any])
        return try XCTUnwrap(body["transport_ca_pem"] as? String)
    }

    private func signedBundle(_ key: Curve25519.Signing.PrivateKey, serial: Int64,
                              policyKeys: [String], caPEM: String) throws -> Data {
        let payloadObj: [String: Any] = [
            "schema_version": "dsse.trust-bundle.v1",
            "tenant_id": "tenant_example",
            "serial": serial,
            "transport_ca_pem": caPEM,
            "renewal_recovery_endpoint": "203.0.113.10:18545",
            "agent_policy_public_keys": policyKeys,
        ]
        let payload = try JSONSerialization.data(withJSONObject: payloadObj, options: [.sortedKeys])
        let sha = SHA256.hash(data: payload).map { String(format: "%02x", $0) }.joined()
        let sig = try key.signature(for: payload)
        let sigB64URL = Data(sig).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        let envelope: [String: Any] = [
            "type": "dsse_agent_steer_policy.v1",
            "version": "1",
            "signing_key_id": "test",
            "created_at": "2026-08-03T00:00:00Z",
            "payload_sha256": sha,
            "payload_b64": payload.base64EncodedString(),
            "signature": "ed25519:" + sigB64URL,
        ]
        return try JSONSerialization.data(withJSONObject: envelope)
    }

    // The bug this pins: an HSM-held ECDSA next-key (130-hex, "04"-prefixed) was silently dropped by an
    // Ed25519-only length filter, so a device adopting the bundle reported only the OLD key and the
    // config-signing-key switch could never be shown safe. Both shapes must survive; malformed ones must not.
    func testAdoptsBothEd25519AndECDSAPolicyKeysAndDropsMalformed() throws {
        let key = Curve25519.Signing.PrivateKey()
        let pin = key.publicKey.rawRepresentation.map { String(format: "%02x", $0) }.joined()
        let ed = "b408c812edcb3d4cafc72b6619c917aae7ddeb79f5cc63f2dc46e9204d7a5e57"                 // 64 hex
        let ecdsa = "045dfd4ea0551351709095846afc1e241b74ad4ab5fa91ed02905b6d2722cbd0" +
                    "0e65571248acb788ece8d8801a8e5a643be2758096baa7babd79f4e5c4527e3315"          // 130 hex, "04"
        let notPoint = "05" + String(repeating: "a", count: 128)                                   // 130 hex, wrong prefix
        let tooShort = "04abcd"
        let notHex = String(repeating: "z", count: 64)
        let data = try signedBundle(key, serial: 42,
                                    policyKeys: [ed, ecdsa, notPoint, tooShort, notHex],
                                    caPEM: try liveTransportCAPEM())
        let bundle = try XCTUnwrap(DsseSignedTrustBundle.verified(
            envelopeData: data, pinnedPublicKeyHex: pin, lastAcceptedSerial: 0))
        XCTAssertEqual(bundle.agentPolicyPublicKeys, [ed, ecdsa],
                       "both the Ed25519 pin and the ECDSA next-key must survive; the three malformed entries must not")
    }

    private func ecdsaSignedBundle(_ key: P256.Signing.PrivateKey, serial: Int64, caPEM: String) throws -> Data {
        let payloadObj: [String: Any] = [
            "schema_version": "dsse.trust-bundle.v1",
            "tenant_id": "tenant_example",
            "serial": serial,
            "transport_ca_pem": caPEM,
            "renewal_recovery_endpoint": "203.0.113.10:18545",
        ]
        let payload = try JSONSerialization.data(withJSONObject: payloadObj, options: [.sortedKeys])
        let sha = SHA256.hash(data: payload).map { String(format: "%02x", $0) }.joined()
        // P256 signs SHA-256(payload) internally, matching the Edge (which signs sha256(payload) explicitly).
        let sig = try key.signature(for: payload)
        let sigB64URL = sig.derRepresentation.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        let envelope: [String: Any] = [
            "type": "dsse_agent_steer_policy.v1", "version": "1", "signing_key_id": "test-ecdsa",
            "created_at": "2026-08-03T00:00:00Z", "payload_sha256": sha,
            "payload_b64": payload.base64EncodedString(),
            "signature": "ecdsa-p256-sha256:" + sigB64URL,
        ]
        return try JSONSerialization.data(withJSONObject: envelope)
    }

    // The switch-blocker Agent A found: after the agent-policy key moves into the token, the trust bundle is
    // signed ECDSA-P256 by a key the Mac holds only in its ADOPTED set (alsoAccept), not as its Ed25519 pin.
    // The verifier must follow both the algorithm change and the key change, or every Mac freezes its adoption
    // and last-resort recovery path at the moment of the switch.
    func testVerifiesAnECDSABundleSignedByAnAdoptedKeyButNotByThePinAlone() throws {
        let hsmKey = P256.Signing.PrivateKey()
        let hsmHex = hsmKey.publicKey.x963Representation.map { String(format: "%02x", $0) }.joined() // 130 hex, "04"
        let ed = "b408c812edcb3d4cafc72b6619c917aae7ddeb79f5cc63f2dc46e9204d7a5e57"                    // the pin
        let data = try ecdsaSignedBundle(hsmKey, serial: 99, caPEM: try liveTransportCAPEM())

        // Pin alone (Ed25519) must NOT verify an ECDSA-signed bundle — the pre-switch state.
        XCTAssertNil(DsseSignedTrustBundle.verified(envelopeData: data, pinnedPublicKeyHex: ed, lastAcceptedSerial: 0),
                     "an ECDSA bundle must not verify against only the Ed25519 pin")
        // With the ECDSA key adopted (as it is before the switch is flipped), it must verify.
        let bundle = try XCTUnwrap(DsseSignedTrustBundle.verified(
            envelopeData: data, pinnedPublicKeyHex: ed, lastAcceptedSerial: 0, alsoAccept: [hsmHex]),
            "an ECDSA bundle signed by an adopted key must verify — this is what unfreezes the switch on macOS")
        XCTAssertEqual(bundle.serial, 99)
    }

    func testAnchorParsingRejectsNonCACertificates() {
        XCTAssertTrue(DsseSignedTrustBundle.parseAnchors("").isEmpty)
        XCTAssertTrue(DsseSignedTrustBundle.parseAnchors("-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----").isEmpty,
                      "unparseable input must yield no anchors rather than a partial set")
    }
}
