import Foundation
import CryptoKit
import DsseNetworkExtensionContract

// Server-issued, signed region-endpoint list — the input to the client-side region selector. The Edge signs the
// device's residency-filtered allowed-region endpoints (Ed25519, over the raw payload bytes, the SAME envelope
// scheme as the signed steer policy); the NE VERIFIES against the pinned key before using the list, so the user
// cannot edit which regions the agent may connect to (and thus cannot widen past the residency boundary).
//
// Cross-language (Go signs, Swift verifies): the signature covers the base64-decoded payload bytes.

private struct DsseSignedRegionEnvelope: Decodable {
    let type: String
    let payloadSHA256: String
    let payloadB64: String
    let signature: String
    enum CodingKeys: String, CodingKey {
        case type
        case payloadSHA256 = "payload_sha256"
        case payloadB64 = "payload_b64"
        case signature = "signature"
    }
}

private struct DsseRegionEndpointPayload: Decodable {
    struct Entry: Decodable { let region: String; let endpoint: String }
    let schemaVersion: String?
    let homeRegion: String?
    let allowedRegionEndpoints: [Entry]?
    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case homeRegion = "home_region"
        case allowedRegionEndpoints = "allowed_region_endpoints"
    }
}

public struct DsseVerifiedRegionEndpoints: Sendable, Equatable {
    public let endpoints: [DsseRegionEndpoint]
    public let homeRegion: String
}

public enum DsseSignedRegionEndpoints {
    // The signing envelope type is the generic agent-policy signing envelope (the Edge reuses one signer); the
    // PAYLOAD schema_version distinguishes a region-endpoint doc from a steer-exclusion doc.
    static let signingEnvelopeType = "dsse_agent_steer_policy.v1"
    static let payloadSchemaVersion = "dsse.region-endpoints.v1"
    private static let signaturePrefix = "ed25519:"
    private static let ecdsaSignaturePrefix = "ecdsa-p256-sha256:"

    /// verifiedRegionEndpoints returns the server-issued allowed-region endpoints ONLY when the envelope verifies
    /// against pinnedPublicKeyHex AND its payload is a region-endpoint doc. Any failure (bad checksum/signature/
    /// type/schema/parse) returns nil — fail-closed; the caller keeps its previous list.
    public static func verifiedRegionEndpoints(envelopeData: Data, pinnedPublicKeyHex: String,
                                               alsoAccept: [String] = []) -> DsseVerifiedRegionEndpoints? {
        // Accept the provisioned pin PLUS any key the Edge advertised in a bundle this device adopted — the same
        // rotatable key-set the steer-exclusion and trust-bundle paths use. A single Ed25519-only pin is what
        // silently broke this path: this verifier only knew Ed25519 (pub.count == 32 / Curve25519), so once the
        // Edge signed region endpoints with the ECDSA HSM key and the device pinned it, EVERY list failed to
        // verify and region failover ran on a stale set (the 2c breakage the exclusion/trust-bundle verifiers were
        // migrated for but this one was missed). Both shapes are handled: 64-hex Ed25519, or 130-hex uncompressed
        // ECDSA-P256 (0x04||X||Y). Algorithm is chosen by the signature prefix; a candidate is tried only if its
        // shape matches.
        var candidates: [String] = []
        var seen = Set<String>()
        for raw in [pinnedPublicKeyHex] + alsoAccept {
            let k = raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            if (k.count == 64 || (k.count == 130 && k.hasPrefix("04"))), !seen.contains(k) {
                seen.insert(k)
                candidates.append(k)
            }
        }
        guard !candidates.isEmpty,
              let env = try? JSONDecoder().decode(DsseSignedRegionEnvelope.self, from: envelopeData),
              env.type == signingEnvelopeType,
              let payload = Data(base64Encoded: env.payloadB64) else {
            return nil
        }
        let digestHex = SHA256.hash(data: payload).map { String(format: "%02x", $0) }.joined()
        guard digestHex == env.payloadSHA256.lowercased() else { return nil }

        let sigVerified: Bool
        if env.signature.hasPrefix(ecdsaSignaturePrefix) {
            guard let sig = base64URLToData(String(env.signature.dropFirst(ecdsaSignaturePrefix.count))),
                  let ecdsaSig = try? P256.Signing.ECDSASignature(derRepresentation: sig) else {
                return nil
            }
            let digest = SHA256.hash(data: payload)
            sigVerified = candidates.contains { hex in
                guard hex.count == 130, let pub = hexToData(hex),
                      let key = try? P256.Signing.PublicKey(x963Representation: pub) else { return false }
                return key.isValidSignature(ecdsaSig, for: digest)
            }
        } else if env.signature.hasPrefix(signaturePrefix) {
            guard let sig = base64URLToData(String(env.signature.dropFirst(signaturePrefix.count))) else {
                return nil
            }
            sigVerified = candidates.contains { hex in
                guard hex.count == 64, let pub = hexToData(hex), pub.count == 32,
                      let key = try? Curve25519.Signing.PublicKey(rawRepresentation: pub) else { return false }
                return key.isValidSignature(sig, for: payload)
            }
        } else {
            return nil
        }
        guard sigVerified else { return nil }

        guard let parsed = try? JSONDecoder().decode(DsseRegionEndpointPayload.self, from: payload),
              parsed.schemaVersion == payloadSchemaVersion else {
            return nil
        }
        let eps = (parsed.allowedRegionEndpoints ?? []).map { DsseRegionEndpoint(region: $0.region, endpoint: $0.endpoint) }
        return DsseVerifiedRegionEndpoints(endpoints: eps, homeRegion: parsed.homeRegion ?? "")
    }

    public static func verifiedRegionEndpoints(signedPath: String, pinnedPublicKeyHex: String,
                                               alsoAccept: [String] = []) -> DsseVerifiedRegionEndpoints? {
        let path = signedPath.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !path.isEmpty, let data = try? Data(contentsOf: URL(fileURLWithPath: path)) else { return nil }
        return verifiedRegionEndpoints(envelopeData: data, pinnedPublicKeyHex: pinnedPublicKeyHex, alsoAccept: alsoAccept)
    }

    private static func hexToData(_ hex: String) -> Data? {
        let chars = Array(hex)
        guard chars.count % 2 == 0 else { return nil }
        var out = Data(capacity: chars.count / 2)
        var i = 0
        while i < chars.count {
            guard let byte = UInt8(String(chars[i ... i + 1]), radix: 16) else { return nil }
            out.append(byte)
            i += 2
        }
        return out
    }

    private static func base64URLToData(_ s: String) -> Data? {
        var b = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while b.count % 4 != 0 { b += "=" }
        return Data(base64Encoded: b)
    }
}
