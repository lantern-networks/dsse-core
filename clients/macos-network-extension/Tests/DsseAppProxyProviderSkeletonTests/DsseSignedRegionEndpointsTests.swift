import XCTest
import CryptoKit
@testable import DsseAppProxyProviderSkeleton

// Cross-language verification: this envelope + public key were produced by the GO Edge signer (agentpolicy,
// seed 0x01..0x20) over a region-endpoint payload. The Swift NE must verify a Go-signed region list, or
// client-side geo-steering does not work end to end. The fixture is deterministic (fixed seed) so it is stable.
final class DsseSignedRegionEndpointsTests: XCTestCase {
    // Go-produced fixture (seed 0102..20):
    let pubKeyHex = "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664"
    let envelopeJSON = """
    {"type":"dsse_agent_steer_policy.v1","version":"1","signing_key_id":"edge-agent-policy-65b60673d6ed884b","created_at":"2026-06-19T00:00:00Z","payload_sha256":"d4c8b97e704c4117dcc8ab067e2165349975c02ffac5504a2389e221911f0dd9","payload_b64":"eyJhbGxvd2VkX3JlZ2lvbl9lbmRwb2ludHMiOlt7ImVuZHBvaW50IjoiaHR0cHM6Ly90b2suZWRnZS5leGFtcGxlOjQ0MyIsInJlZ2lvbiI6ImpwLXRva3lvIn0seyJlbmRwb2ludCI6Imh0dHBzOi8vb3NhLmVkZ2UuZXhhbXBsZTo0NDMiLCJyZWdpb24iOiJqcC1vc2FrYSJ9XSwiZGV2aWNlX2lkZW50aXR5IjoibWFjLWRldi0xIiwiaG9tZV9yZWdpb24iOiJqcC10b2t5byIsInNjaGVtYV92ZXJzaW9uIjoiZHNzZS5yZWdpb24tZW5kcG9pbnRzLnYxIiwidGVuYW50X2lkIjoidGVuYW50X2xhYl8wMDEifQ==","signature":"ed25519:942aHs0IvP3marcxT3j_G8brlgrxucx0Efu5G5hp1dxO-2BOC30w42ZVfEk_bOuoZ-wEZ110ZprvoFZ6-pfJAw"}
    """

    // A Go-signed region list verifies in the NE and yields the residency-filtered, home-anchored endpoints.
    func testGoSignedRegionListVerifies() {
        let v = DsseSignedRegionEndpoints.verifiedRegionEndpoints(
            envelopeData: Data(envelopeJSON.utf8), pinnedPublicKeyHex: pubKeyHex)
        XCTAssertNotNil(v, "the Go-signed region-endpoint list must verify and parse in the NE")
        XCTAssertEqual(v?.endpoints.map { $0.region }, ["jp-tokyo", "jp-osaka"])
        XCTAssertEqual(v?.endpoints.first?.endpoint, "https://tok.edge.example:443")
        XCTAssertEqual(v?.homeRegion, "jp-tokyo")
    }

    // A list signed by an untrusted key must be rejected (fail-closed against an attacker key).
    func testUntrustedKeyRejected() {
        let wrong = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
        XCTAssertNil(DsseSignedRegionEndpoints.verifiedRegionEndpoints(
            envelopeData: Data(envelopeJSON.utf8), pinnedPublicKeyHex: wrong))
    }

    // An edited payload must fail signature/checksum verification (the user cannot tamper to widen the region set).
    func testTamperedPayloadRejected() {
        let tampered = envelopeJSON.replacingOccurrences(
            of: "\"payload_b64\":\"eyJhbGxv",
            with: "\"payload_b64\":\"eyJhbGxvd2VkX3JlZ2lvbl9lbmRwb2ludHMiOlt7ImVuZHBvaW50IjoiaHR0cHM6Ly9hdHRhY2tlcjo0NDMiLCJyZWdpb24iOiJ1cy1pYWQifV19\",\"_x\":\"eyJhbGxv")
        XCTAssertNil(DsseSignedRegionEndpoints.verifiedRegionEndpoints(
            envelopeData: Data(tampered.utf8), pinnedPublicKeyHex: pubKeyHex),
            "an edited payload must fail verification")
    }

    // The bug this pins: verifiedRegionEndpoints was Ed25519-ONLY (pub.count == 32 / Curve25519), so once the
    // fleet moved to the ECDSA HSM signing key — and the device pinned it (B) — the Edge's region list could not
    // verify at all, and region failover ran on a stale set. It must verify an ECDSA-P256 list, both when that
    // key is the device's pin (post-re-pin) and when it is only in the adopted set (mid-rotation), while still
    // rejecting an unrelated key.
    func testVerifiesAnECDSASignedRegionList() throws {
        let hsm = P256.Signing.PrivateKey()
        let hsmHex = hsm.publicKey.x963Representation.map { String(format: "%02x", $0) }.joined() // 130 hex, "04"
        let env = try ecdsaSignedRegionEnvelope(hsm)

        // (1) ECDSA key as the PIN (the post-B state) verifies + parses.
        let v = DsseSignedRegionEndpoints.verifiedRegionEndpoints(envelopeData: env, pinnedPublicKeyHex: hsmHex)
        XCTAssertEqual(v?.endpoints.map { $0.region }, ["jp-tokyo", "jp-osaka"],
                       "an ECDSA-signed region list must verify when the ECDSA key is pinned (post-re-pin)")

        // (2) ECDSA key only in the ADOPTED set (mid-rotation, pin still Ed25519) verifies.
        XCTAssertNotNil(DsseSignedRegionEndpoints.verifiedRegionEndpoints(
            envelopeData: env, pinnedPublicKeyHex: pubKeyHex, alsoAccept: [hsmHex]),
            "an ECDSA-signed region list must verify against an adopted ECDSA key")

        // (3) An unrelated Ed25519 pin alone must NOT verify the ECDSA list — the key set is not a free pass.
        XCTAssertNil(DsseSignedRegionEndpoints.verifiedRegionEndpoints(envelopeData: env, pinnedPublicKeyHex: pubKeyHex),
                     "an ECDSA-signed list must not verify against only an unrelated Ed25519 pin")
    }

    // Builds a region-endpoint envelope signed ECDSA-P256, the same shape the Go Edge produces: P256 signs
    // SHA-256(payload) internally and the signature carries the "ecdsa-p256-sha256:" prefix over a base64url DER.
    private func ecdsaSignedRegionEnvelope(_ key: P256.Signing.PrivateKey) throws -> Data {
        let payloadObj: [String: Any] = [
            "schema_version": "dsse.region-endpoints.v1",
            "tenant_id": "tenant_lab_001",
            "home_region": "jp-tokyo",
            "allowed_region_endpoints": [
                ["region": "jp-tokyo", "endpoint": "https://tok.edge.example:443"],
                ["region": "jp-osaka", "endpoint": "https://osa.edge.example:443"],
            ],
        ]
        let payload = try JSONSerialization.data(withJSONObject: payloadObj, options: [.sortedKeys])
        let payloadSHA256 = SHA256.hash(data: payload).map { String(format: "%02x", $0) }.joined()
        let sig = try key.signature(for: payload)
        let sigB64URL = sig.derRepresentation.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        let env: [String: Any] = [
            "type": "dsse_agent_steer_policy.v1",
            "version": "1",
            "payload_sha256": payloadSHA256,
            "payload_b64": payload.base64EncodedString(),
            "signature": "ecdsa-p256-sha256:" + sigB64URL,
        ]
        return try JSONSerialization.data(withJSONObject: env)
    }
}
