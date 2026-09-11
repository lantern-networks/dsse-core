import Foundation
import CryptoKit

// Server-issued, signed steer-exclusion policy.
//
// The Edge signs the device's resolved exclusion set (Ed25519, over the raw payload bytes) and the agent
// drops the signed envelope at a root-owned path. The NE VERIFIES the signature against the public key it
// pins (from the root-owned agent_config) and, on success, uses the server-issued list as AUTHORITATIVE —
// ignoring any locally-edited list. So the endpoint user cannot change which apps are excluded.
//
// Cross-language scheme (Go signs, Swift verifies): the signature covers the base64-decoded payload bytes,
// so neither side reproduces the other's JSON byte-for-byte.

struct DsseSignedAgentPolicyEnvelope: Decodable {
    let type: String
    let signingKeyID: String
    let payloadSHA256: String
    let payloadB64: String
    let signature: String

    enum CodingKeys: String, CodingKey {
        case type
        case signingKeyID = "signing_key_id"
        case payloadSHA256 = "payload_sha256"
        case payloadB64 = "payload_b64"
        case signature = "signature"
    }
}

private struct DsseSignedAgentPolicyPayload: Decodable {
    let excludedAppSigningIdentifiers: [String]?
    let deviceIdentity: String?
    // "Any certificate issued before this is stale." Absent in the ordinary case, and an agent that never sees
    // it behaves exactly as it did before.
    let renewCertificatesIssuedBefore: String?
    /// Which interception roots to look for in this machine's trust store. A question, not a change to what
    /// the device trusts, which is why it arrives here rather than on the serial-gated trust bundle.
    let interceptionRootSHA256: [String]?
    /// Which organization the DEPLOYMENT resolves this device to — the answer computed from the certificate
    /// the device presented, not from anything the device claims. It has always been in this document; nothing
    /// read it.
    let tenantID: String?

    enum CodingKeys: String, CodingKey {
        case tenantID = "tenant_id"
        case excludedAppSigningIdentifiers = "excluded_app_signing_ids"
        case deviceIdentity = "device_identity"
        case renewCertificatesIssuedBefore = "renew_certificates_issued_before"
        case interceptionRootSHA256 = "interception_root_sha256"
    }
}

public enum DsseSignedAgentPolicy {
    static let envelopeType = "dsse_agent_steer_policy.v1"
    // ★ The update manifest rides the SAME envelope and the SAME crypto, deliberately: one signature scheme on
    // this device, not two. What must NOT be shared is the TYPE — see verifiedPayload's expectedType.
    static let updateManifestEnvelopeType = "dsse_agent_update_manifest.v1"
    private static let signaturePrefix = "ed25519:"
    private static let ecdsaSignaturePrefix = "ecdsa-p256-sha256:"

    // verifiedServerExclusions returns the server-issued excluded signing identifiers ONLY when the file at
    // signedPath is a signed envelope that verifies against pinnedPublicKeyHex. Any failure (missing file,
    // bad checksum, bad signature, wrong type) returns nil — the caller then keeps the previous behavior.
    // Fail-closed against tampering: an edited payload or a forged signature does not pass.
    public static func verifiedServerExclusions(signedPath: String, pinnedPublicKeyHex: String,
                                               alsoAccept: [String] = []) -> [String]? {
        let path = signedPath.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !path.isEmpty, let data = try? Data(contentsOf: URL(fileURLWithPath: path)) else {
            return nil
        }
        return verifiedServerExclusions(envelopeData: data, pinnedPublicKeyHex: pinnedPublicKeyHex, alsoAccept: alsoAccept)
    }

    // verifiedServerExclusions(envelopeData:) is the same verification over IN-MEMORY envelope bytes — used
    // when the agent PULLS the signed policy itself over the (T) transport (the production mechanism: no
    // human/script provisions a file; the NE fetches + verifies + applies + caches on its own). Fail-closed:
    // any checksum/signature/type/parse failure returns nil and the caller keeps the previous set.
    public static func verifiedServerExclusions(envelopeData: Data, pinnedPublicKeyHex: String,
                                               alsoAccept: [String] = []) -> [String]? {
        guard let parsed = verifiedPayload(envelopeData: envelopeData, pinnedPublicKeyHex: pinnedPublicKeyHex, alsoAccept: alsoAccept) else {
            return nil
        }
        return parsed.excludedAppSigningIdentifiers ?? []
    }

    // verifiedPayload is the one place the envelope is checked: type, checksum, Ed25519 signature, then decode.
    // Two readers now need the payload, and two copies of a signature check is one copy too many — the second
    // is where the weaker version ends up.
    private static func verifiedPayload(envelopeData: Data, pinnedPublicKeyHex: String,
                                        alsoAccept: [String] = []) -> DsseSignedAgentPolicyPayload? {
        guard let raw = verifiedPayloadBytes(envelopeData: envelopeData, expectedType: envelopeType,
                                             pinnedPublicKeyHex: pinnedPublicKeyHex, alsoAccept: alsoAccept) else {
            return nil
        }
        return try? JSONDecoder().decode(DsseSignedAgentPolicyPayload.self, from: raw)
    }

    // verifiedPayloadBytes is the crypto, with the document KIND as a required argument.
    //
    // ★ expectedType has no default and that is the whole point. One key legitimately signs several documents
    // on this surface, and the signature check is pure crypto that does not look at the type — so a caller that
    // forgot to say which kind it wanted would accept a steer policy as an update manifest, which is a
    // substitution with a valid signature. Making it a parameter with a default would put that mistake one
    // omission away; making it required puts it where the compiler is.
    //
    // The update manifest reuses this rather than getting its own verifier for the reason the design gives:
    // two implementations of a signature check is one too many, and the second is where the weaker one ends up.
    static func verifiedPayloadBytes(envelopeData: Data, expectedType: String, pinnedPublicKeyHex: String,
                                     alsoAccept: [String] = []) -> Data? {
        // The provisioned pin FIRST, then any key the Edge advertised in a bundle this device adopted. Both
        // are trusted material: the pin arrived by MDM, and the advertised set was carried inside a document
        // signed by the key in force at the time. Accepting a set rather than exactly one key is what makes
        // this key rotatable — every agent pinning one key is why it could never be changed, and therefore
        // why it could never move into a hardware token either.
        // Accept either signing-key shape the verifier below handles: a 32-byte Ed25519 key (64 hex) or an
        // uncompressed-point ECDSA-P256 key (65 bytes = 130 hex, 0x04||X||Y). ECDSA exists because the
        // config-signing key cannot enter a PKCS#11 token as Ed25519 (no binding supports it), so hardware
        // custody for it requires ECDSA — and a device must already accept it before the Edge ever switches.
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
              let env = try? JSONDecoder().decode(DsseSignedAgentPolicyEnvelope.self, from: envelopeData),
              env.type == expectedType,
              let payload = Data(base64Encoded: env.payloadB64) else {
            return nil
        }
        // checksum
        let digestHex = SHA256.hash(data: payload).map { String(format: "%02x", $0) }.joined()
        guard digestHex == env.payloadSHA256.lowercased() else { return nil }

        // The algorithm is chosen by the signature prefix, and each candidate key is tried only if its shape
        // matches that algorithm. One accepted key is enough; none is a refusal.
        let verified: Bool
        if env.signature.hasPrefix(ecdsaSignaturePrefix) {
            guard let sig = base64URLToData(String(env.signature.dropFirst(ecdsaSignaturePrefix.count))),
                  let ecdsaSig = try? P256.Signing.ECDSASignature(derRepresentation: sig) else {
                return nil
            }
            let digest = SHA256.hash(data: payload)
            verified = candidates.contains { hex in
                guard hex.count == 130, let pub = hexToData(hex),
                      let key = try? P256.Signing.PublicKey(x963Representation: pub) else { return false }
                return key.isValidSignature(ecdsaSig, for: digest)
            }
        } else if env.signature.hasPrefix(signaturePrefix) {
            guard let sig = base64URLToData(String(env.signature.dropFirst(signaturePrefix.count))) else {
                return nil
            }
            verified = candidates.contains { hex in
                guard hex.count == 64, let pub = hexToData(hex), pub.count == 32,
                      let key = try? Curve25519.Signing.PublicKey(rawRepresentation: pub) else { return false }
                return key.isValidSignature(sig, for: payload)
            }
        } else {
            return nil
        }
        guard verified else { return nil }
        return payload
    }

    // verifiedRenewCertificatesIssuedBefore returns the operator's "renew anything older than this" cutoff, and
    // only from a policy that PASSES the same signature check as everything else here.
    //
    // It has to be signed. This value can make a fleet replace its credentials, so accepting it from an
    // unverified document would hand that to anyone who can answer on the network — which is precisely the
    // position a device is in before it trusts anything.
    //
    // nil for absent, unparseable, or unverified: all three mean "no instruction", and the agent then renews on
    // its ordinary two-thirds-of-life schedule. Failing towards the normal schedule is the safe direction —
    // the opposite reading would turn any garbled response into a fleet-wide renewal storm.
    /// verifiedInterceptionRoots is which roots the deployment says it signs intercepted traffic under, from
    /// the SIGNED policy only. An unverified answer here would let anyone on the network choose which
    /// certificates this agent goes looking for, and an agent that reports finding an attacker's root would
    /// be handing the Edge a reason to switch onto it.
    public static func verifiedInterceptionRoots(signedPath: String, pinnedPublicKeyHex: String,
                                                alsoAccept: [String] = []) -> [String] {
        let path = signedPath.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !path.isEmpty, let data = FileManager.default.contents(atPath: path) else { return [] }
        return verifiedInterceptionRoots(envelopeData: data, pinnedPublicKeyHex: pinnedPublicKeyHex, alsoAccept: alsoAccept)
    }

    public static func verifiedInterceptionRoots(envelopeData: Data, pinnedPublicKeyHex: String,
                                                alsoAccept: [String] = []) -> [String] {
        guard let payload = verifiedPayload(envelopeData: envelopeData, pinnedPublicKeyHex: pinnedPublicKeyHex, alsoAccept: alsoAccept) else {
            return []
        }
        return (payload.interceptionRootSHA256 ?? [])
            .map { $0.lowercased().replacingOccurrences(of: ":", with: "") }
            .filter { $0.count == 64 }
    }

    /// verifiedDeploymentTenant is the organization the deployment says this device belongs to.
    ///
    /// ★★★ THE ONLY PARTY THAT CAN ANSWER (2026-09-04). A device cannot tell which organization issued its own
    /// certificate: the issuing CA is not on disk and not in any keychain, and the profile carries only its
    /// SHA-256. So a Mac given a NEW organization's profile went on presenting the OLD organization's
    /// certificate — it completed the handshake, because it is the same deployment — and every flow was
    /// inspected under the deployment's CA while the organization's own authority sat loaded and unused.
    ///
    /// The deployment already computes the answer and has always put it in this document. Reading it needs no
    /// new endpoint and no new object on any channel: it rides the document the agent fetches every minute,
    /// and it is SIGNED, so it cannot be chosen by anyone on the network.
    ///
    /// nil for absent, unparseable or unverified — all three are "not answered", never "wrong".
    public static func verifiedDeploymentTenant(signedPath: String, pinnedPublicKeyHex: String,
                                                alsoAccept: [String] = []) -> String? {
        let path = signedPath.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !path.isEmpty, let data = FileManager.default.contents(atPath: path) else { return nil }
        return verifiedDeploymentTenant(envelopeData: data, pinnedPublicKeyHex: pinnedPublicKeyHex, alsoAccept: alsoAccept)
    }

    public static func verifiedDeploymentTenant(envelopeData: Data, pinnedPublicKeyHex: String,
                                                alsoAccept: [String] = []) -> String? {
        guard let payload = verifiedPayload(envelopeData: envelopeData, pinnedPublicKeyHex: pinnedPublicKeyHex, alsoAccept: alsoAccept),
              let tid = payload.tenantID?.trimmingCharacters(in: .whitespacesAndNewlines), !tid.isEmpty else {
            return nil
        }
        return tid
    }

    public static func verifiedRenewCertificatesIssuedBefore(envelopeData: Data, pinnedPublicKeyHex: String,
                                                            alsoAccept: [String] = []) -> Date? {
        guard let payload = verifiedPayload(envelopeData: envelopeData, pinnedPublicKeyHex: pinnedPublicKeyHex, alsoAccept: alsoAccept),
              let raw = payload.renewCertificatesIssuedBefore?.trimmingCharacters(in: .whitespacesAndNewlines),
              !raw.isEmpty else {
            return nil
        }
        let iso = ISO8601DateFormatter()
        iso.formatOptions = [.withInternetDateTime]
        return iso.date(from: raw)
    }

    public static func verifiedRenewCertificatesIssuedBefore(signedPath: String, pinnedPublicKeyHex: String,
                                                            alsoAccept: [String] = []) -> Date? {
        let path = signedPath.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !path.isEmpty, let data = try? Data(contentsOf: URL(fileURLWithPath: path)) else { return nil }
        return verifiedRenewCertificatesIssuedBefore(envelopeData: data, pinnedPublicKeyHex: pinnedPublicKeyHex, alsoAccept: alsoAccept)
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
