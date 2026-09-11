import CryptoKit
import Foundation
import XCTest
@testable import DsseAppProxyProviderSkeleton

// The config-signing key cannot enter a PKCS#11 token as Ed25519, so hardware custody for it requires ECDSA.
// Before the Edge can ever sign ECDSA, this verifier must already accept it — additively, so the switch is
// only "start signing ECDSA". These mirror the Go package's ECDSA verify tests, keeping the two byte-compatible
// (P-256, SHA-256, ASN.1/DER signature, uncompressed-point public key = X9.63).
final class DsseSignedAgentPolicyECDSATests: XCTestCase {

    private func envelope(signedBy key: P256.Signing.PrivateKey, excluding ids: [String]) throws -> Data {
        let payload = try JSONSerialization.data(withJSONObject: ["excluded_app_signing_ids": ids])
        let digest = SHA256.hash(data: payload)
        let sig = try key.signature(for: digest)
        let env: [String: Any] = [
            "type": "dsse_agent_steer_policy.v1",
            "version": "1",
            "signing_key_id": "test-ecdsa",
            "created_at": "2026-08-03T00:00:00Z",
            "payload_sha256": digest.map { String(format: "%02x", $0) }.joined(),
            "payload_b64": payload.base64EncodedString(),
            "signature": "ecdsa-p256-sha256:" + sig.derRepresentation.base64EncodedString()
                .replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_")
                .replacingOccurrences(of: "=", with: ""),
        ]
        return try JSONSerialization.data(withJSONObject: env)
    }

    private func pubHex(_ key: P256.Signing.PrivateKey) -> String {
        key.publicKey.x963Representation.map { String(format: "%02x", $0) }.joined()
    }

    func testECDSASignedPolicyIsAcceptedByTheProvisionedPinOrAnAdoptedKey() throws {
        let provisioned = P256.Signing.PrivateKey()
        let next = P256.Signing.PrivateKey()
        let stranger = P256.Signing.PrivateKey()

        // Signed by the provisioned ECDSA pin: accepted.
        let byPin = try envelope(signedBy: provisioned, excluding: ["com.example.a"])
        XCTAssertEqual(DsseSignedAgentPolicy.verifiedServerExclusions(
            envelopeData: byPin, pinnedPublicKeyHex: pubHex(provisioned)), ["com.example.a"])

        // Signed by an ECDSA next-key: refused until adopted, accepted once it is in alsoAccept — the overlap.
        let byNext = try envelope(signedBy: next, excluding: ["com.example.b"])
        XCTAssertNil(DsseSignedAgentPolicy.verifiedServerExclusions(
            envelopeData: byNext, pinnedPublicKeyHex: pubHex(provisioned)))
        XCTAssertEqual(DsseSignedAgentPolicy.verifiedServerExclusions(
            envelopeData: byNext, pinnedPublicKeyHex: pubHex(provisioned), alsoAccept: [pubHex(next)]),
            ["com.example.b"])

        // A stranger's ECDSA key is refused however long the accepted list.
        let byStranger = try envelope(signedBy: stranger, excluding: ["com.example.c"])
        XCTAssertNil(DsseSignedAgentPolicy.verifiedServerExclusions(
            envelopeData: byStranger, pinnedPublicKeyHex: pubHex(provisioned),
            alsoAccept: [pubHex(next), pubHex(provisioned)]))
    }

    func testEd25519PinDoesNotVerifyAnECDSASignatureAndViceVersa() throws {
        let ec = P256.Signing.PrivateKey()
        let ecEnv = try envelope(signedBy: ec, excluding: ["x"])
        // An Ed25519-shaped pin against an ECDSA signature: refused (shape/algorithm mismatch, not a crash).
        let edPinHex = Data(repeating: 0, count: 32).map { String(format: "%02x", $0) }.joined()
        XCTAssertNil(DsseSignedAgentPolicy.verifiedServerExclusions(
            envelopeData: ecEnv, pinnedPublicKeyHex: edPinHex))
    }
}
