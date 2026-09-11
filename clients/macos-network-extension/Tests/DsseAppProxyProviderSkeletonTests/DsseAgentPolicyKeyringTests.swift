import CryptoKit
import Foundation
import XCTest
@testable import DsseAppProxyProviderSkeleton

// The policy-signing key is the one piece of material that could never be rotated: every agent pinned exactly
// one key, so changing it would leave the fleet rejecting everything signed by the new one — frozen on its
// last applied policy with no way to be told anything. That is also why the key could not move into a
// hardware token. Accepting a SET, distributed the same way transport CAs are, is what makes the ordinary
// overlap possible.
final class DsseAgentPolicyKeyringTests: XCTestCase {

    private func envelope(signedBy key: Curve25519.Signing.PrivateKey, excluding ids: [String]) throws -> Data {
        let payload = try JSONSerialization.data(withJSONObject: ["excluded_app_signing_ids": ids])
        let digest = SHA256.hash(data: payload).map { String(format: "%02x", $0) }.joined()
        let sig = try key.signature(for: payload)
        let env: [String: Any] = [
            "type": "dsse_agent_steer_policy.v1",
            "version": "1",
            "signing_key_id": "test",
            "created_at": "2026-08-03T00:00:00Z",
            "payload_sha256": digest,
            "payload_b64": payload.base64EncodedString(),
            "signature": "ed25519:" + sig.base64EncodedString()
                .replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_")
                .replacingOccurrences(of: "=", with: ""),
        ]
        return try JSONSerialization.data(withJSONObject: env)
    }

    private func hex(_ key: Curve25519.Signing.PrivateKey) -> String {
        key.publicKey.rawRepresentation.map { String(format: "%02x", $0) }.joined()
    }

    func testPolicySignedByAnAdoptedKeyIsAcceptedAndAStrangerIsNot() throws {
        let provisioned = Curve25519.Signing.PrivateKey()
        let next = Curve25519.Signing.PrivateKey()
        let stranger = Curve25519.Signing.PrivateKey()

        // Signed by the provisioned pin: accepted with or without a keyring, exactly as before.
        let byPin = try envelope(signedBy: provisioned, excluding: ["com.example.a"])
        XCTAssertEqual(DsseSignedAgentPolicy.verifiedServerExclusions(
            envelopeData: byPin, pinnedPublicKeyHex: hex(provisioned)), ["com.example.a"])

        // Signed by the NEXT key: refused until this device has adopted it, accepted once it has. That gap is
        // the whole overlap — publish, wait for adoption, then start signing.
        let byNext = try envelope(signedBy: next, excluding: ["com.example.b"])
        XCTAssertNil(DsseSignedAgentPolicy.verifiedServerExclusions(
            envelopeData: byNext, pinnedPublicKeyHex: hex(provisioned)),
            "a key this device has not adopted must not be accepted")
        XCTAssertEqual(DsseSignedAgentPolicy.verifiedServerExclusions(
            envelopeData: byNext, pinnedPublicKeyHex: hex(provisioned), alsoAccept: [hex(next)]),
            ["com.example.b"])

        // And an unrelated key is refused however long the accepted list is.
        let byStranger = try envelope(signedBy: stranger, excluding: ["com.example.c"])
        XCTAssertNil(DsseSignedAgentPolicy.verifiedServerExclusions(
            envelopeData: byStranger, pinnedPublicKeyHex: hex(provisioned),
            alsoAccept: [hex(next), hex(provisioned)]),
            "acceptance must be a set membership test, not a weakened check")
    }

    func testMalformedAcceptedKeysAreIgnoredRatherThanTrusted() throws {
        let provisioned = Curve25519.Signing.PrivateKey()
        let data = try envelope(signedBy: provisioned, excluding: ["com.example.a"])
        // Junk in the accepted list must neither crash nor widen what is accepted.
        XCTAssertEqual(DsseSignedAgentPolicy.verifiedServerExclusions(
            envelopeData: data, pinnedPublicKeyHex: hex(provisioned),
            alsoAccept: ["", "zz", String(repeating: "q", count: 64)]), ["com.example.a"])
    }
}
