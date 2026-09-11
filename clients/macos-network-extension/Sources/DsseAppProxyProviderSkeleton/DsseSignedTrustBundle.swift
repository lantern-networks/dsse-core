import Foundation
import CryptoKit
import Security

// The one signed document this device may fetch over a channel it cannot authenticate.
//
// Everything else the Edge serves rides the (T) mTLS transport, which is right — but it means all of it is
// unreachable in the single situation where this device is in real trouble: its pinned transport CA no longer
// validates the Edge, so the tunnel cannot open, and the anchor that would fix that is distributed only over
// that tunnel. Cross-signing is what should keep that deadlock from forming; this is the way out when it forms
// anyway (an unplanned revocation, a shutdown longer than the rotation overlap, a rotation done without the
// cross-certificate).
//
// Fetching it does NOT require validating the server: authenticity comes from the SIGNATURE, checked against a
// key pinned in this device's own configuration. A bundle that fails any check is discarded whole — there is no
// partial adoption, because a half-applied anchor set is a locked-out device.
//
// It cannot grant anything. It names which CA verifies the EDGE and where to recover, and nothing that
// identifies this device, so a forged bundle cannot make one device impersonate another. Obtaining a
// certificate still goes through the recovery path, which checks the expired certificate, the enrolment ledger
// and revocation.

public struct DsseVerifiedTrustBundle: Sendable, Equatable {
    /// Every CA this device should accept the Edge under. A LIST: an overlap is the normal state mid-rotation.
    public let anchorsPEM: String
    /// The interception roots this deployment signs under. Fingerprints only: a device that accepted a root
    /// because a bundle carried it would be trusting exactly the wrong thing. They are here so the agent
    /// knows which certificates to LOOK for in its own trust store and can report what it found — without
    /// that, switching the interception root is blind.
    public let interceptionRootSHA256: [String]
    /// The policy-signing keys the Edge says a device should accept. Empty = it said nothing, and the device
    /// keeps using the key it was provisioned with.
    public let agentPolicyPublicKeys: [String]

    /// The name to send when dialling the Edge to renew a certificate that has ALREADY EXPIRED.
    ///
    /// ★ THE AGENT PLANE IS BEING FOLDED ONTO ONE PORT. That path is a separate listener today because it must
    /// accept an expired client certificate, and the main transport must never be relaxed that way. Selecting
    /// it by name on the SAME port removes the second address without touching the main configuration — an
    /// agent must reach an Edge on one port, and on a real deployment both would be 443 and collide.
    ///
    /// Empty means what it always meant: use the recovery ENDPOINT from the agent configuration. A device that
    /// never sees this field behaves exactly as before.
    public let renewalRecoverySNI: String

    /// The name this organization's devices should SEND as the TLS server name when they dial the Edge, and
    /// verify the presented certificate against. Empty = this organization is served the deployment's shared
    /// certificate, which is what every device did before this field existed.
    ///
    /// ★ ANNOUNCED, NEVER INVENTED. The Edge derives it from the certificate it actually serves this
    /// organization, so a device that makes one up would ask for a certificate nobody has. Empty means dial as
    /// before; it does not mean "guess".
    public let transportServerName: String

    public init(anchorsPEM: String, interceptionRootSHA256: [String],
                agentPolicyPublicKeys: [String] = [],
                renewalRecoveryEndpoint: String, serial: Int64, tenantID: String,
                transportServerName: String = "", renewalRecoverySNI: String = "") {
        self.anchorsPEM = anchorsPEM
        self.interceptionRootSHA256 = interceptionRootSHA256
        self.agentPolicyPublicKeys = agentPolicyPublicKeys
        self.renewalRecoveryEndpoint = renewalRecoveryEndpoint
        self.serial = serial
        self.tenantID = tenantID
        self.transportServerName = transportServerName
        self.renewalRecoverySNI = renewalRecoverySNI
    }
    /// May name only a port; the host is resolved from the transport this device already has.
    public let renewalRecoveryEndpoint: String
    /// Strictly increasing. Persist it and pass it back as `lastAcceptedSerial`, or replay protection is absent.
    public let serial: Int64
    public let tenantID: String
}

private struct DsseTrustBundleEnvelope: Decodable {
    let type: String
    let payloadSHA256: String
    let payloadB64: String
    let signature: String
    enum CodingKeys: String, CodingKey {
        case type
        case payloadSHA256 = "payload_sha256"
        case payloadB64 = "payload_b64"
        case signature
    }
}

private struct DsseTrustBundleBody: Decodable {
    let schemaVersion: String?
    let tenantID: String?
    let serial: Int64?
    let transportCAPEM: String?
    let renewalRecoveryEndpoint: String?
    let interceptionRootSHA256: [String]?
    let agentPolicyPublicKeys: [String]?
    let transportServerName: String?
    let renewalRecoverySNI: String?
    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case tenantID = "tenant_id"
        case serial
        case transportCAPEM = "transport_ca_pem"
        case renewalRecoveryEndpoint = "renewal_recovery_endpoint"
        case interceptionRootSHA256 = "interception_root_sha256"
        case agentPolicyPublicKeys = "agent_policy_public_keys"
        case transportServerName = "transport_server_name"
        case renewalRecoverySNI = "renewal_recovery_sni"
    }
}

public enum DsseSignedTrustBundle {
    // The envelope is the shared agent-policy signing envelope; the payload schema is what keeps this document
    // apart from the others signed by the same key. Without that check, a body signed for another purpose could
    // be served in a trust bundle's place.
    static let signingEnvelopeType = "dsse_agent_steer_policy.v1"
    static let payloadSchemaVersion = "dsse.trust-bundle.v1"
    private static let signaturePrefix = "ed25519:"
    private static let ecdsaSignaturePrefix = "ecdsa-p256-sha256:"

    /// verified returns the bundle ONLY when the signature, the schema, the serial and the anchors all pass.
    ///
    /// `lastAcceptedSerial` is the highest this device has ever accepted (0 if none). It is what stops a replay:
    /// whoever can serve an unauthenticated document can serve an OLD one, and an old bundle is how a withdrawn
    /// CA gets restored. A signature alone does not detect that — the old bundle was genuinely signed.
    public static func verified(envelopeData: Data, pinnedPublicKeyHex: String, lastAcceptedSerial: Int64,
                                alsoAccept: [String] = []) -> DsseVerifiedTrustBundle? {
        // The provisioned pin FIRST, then any policy-signing key this device adopted from a prior bundle. The
        // trust bundle is signed by the SAME key as agent policy, so when that key moves into a PKCS#11 token
        // the bundle is signed ECDSA-P256 — and a device can only keep reading bundles if it verifies with the
        // key it already adopted, exactly as the agent-policy verifier does. Without this, flipping the signer
        // freezes every Mac's adoption AND recovery path: it can neither follow the algorithm change nor the
        // key change this whole work stream is about. Accept a 32-byte Ed25519 key (64 hex) or an uncompressed
        // P-256 point (130 hex, 0x04||X||Y); an empty candidate set is a refusal, never "accept anything".
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
              let env = try? JSONDecoder().decode(DsseTrustBundleEnvelope.self, from: envelopeData),
              env.type == signingEnvelopeType,
              let payload = Data(base64Encoded: env.payloadB64) else {
            return nil
        }
        let digestHex = SHA256.hash(data: payload).map { String(format: "%02x", $0) }.joined()
        guard digestHex == env.payloadSHA256.lowercased() else { return nil }
        // The algorithm is chosen by the signature prefix, and each candidate key is tried only if its shape
        // matches that algorithm. One accepted key is enough; none is a refusal.
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
        guard let body = try? JSONDecoder().decode(DsseTrustBundleBody.self, from: payload),
              body.schemaVersion == payloadSchemaVersion,
              let serial = body.serial, serial > 0,
              serial > lastAcceptedSerial,
              let pem = body.transportCAPEM,
              !parseAnchors(pem).isEmpty else {
            return nil
        }
        return DsseVerifiedTrustBundle(
            anchorsPEM: pem,
            interceptionRootSHA256: (body.interceptionRootSHA256 ?? []).map {
                $0.lowercased().replacingOccurrences(of: ":", with: "")
            }.filter { $0.count == 64 },
            // Hex public keys the device is being told to accept signed policy from: a 32-byte Ed25519 key
            // (64 hex) or an uncompressed P-256 point (130 hex, "04" prefix). A malformed entry is dropped
            // rather than carried forward — and dropping the wrong shape here is not cosmetic: it is what
            // silently kept an HSM-held ECDSA next-key out of the accepted set during the config-signing-key
            // switch, so the fleet reported only the old key and the switch could never be shown safe.
            agentPolicyPublicKeys: (body.agentPolicyPublicKeys ?? []).map {
                $0.lowercased().trimmingCharacters(in: .whitespaces)
            }.filter { k in
                k.allSatisfy { $0.isHexDigit } && (k.count == 64 || (k.count == 130 && k.hasPrefix("04")))
            },
            renewalRecoveryEndpoint: (body.renewalRecoveryEndpoint ?? "").trimmingCharacters(in: .whitespacesAndNewlines),
            serial: serial,
            tenantID: body.tenantID ?? "",
            // Lower-cased because an SNI is compared case-insensitively and the Edge announces it that way;
            // a device that sent a differently-cased name would ask for a certificate that exists under
            // another spelling.
            transportServerName: (body.transportServerName ?? "")
                .trimmingCharacters(in: .whitespacesAndNewlines).lowercased(),
            renewalRecoverySNI: (body.renewalRecoverySNI ?? "")
                .trimmingCharacters(in: .whitespacesAndNewlines).lowercased())
    }

    /// parseAnchors returns the CA certificates in a PEM bundle. A certificate that is not a CA is dropped
    /// rather than tolerated: an anchor set is not a place for leaves, and accepting one would let a bundle pin
    /// this device to a single server certificate — the very shape the CA layer exists to get away from.
    public static func parseAnchors(_ pem: String) -> [SecCertificate] {
        var out: [SecCertificate] = []
        for der in derBlocks(inPEM: pem) {
            guard let cert = SecCertificateCreateWithData(nil, der as CFData) else { continue }
            if isCertificateAuthority(cert) {
                out.append(cert)
            }
        }
        return out
    }

    // isCertificateAuthority reads Basic Constraints. Security.framework exposes it through the values API; when
    // the field cannot be read at all the certificate is REFUSED rather than assumed to be a CA, because
    // guessing wrong here widens what this device will accept as an Edge.
    private static func isCertificateAuthority(_ cert: SecCertificate) -> Bool {
        guard let values = SecCertificateCopyValues(cert, [kSecOIDBasicConstraints] as CFArray, nil) as? [String: Any],
              let bc = values[kSecOIDBasicConstraints as String] as? [String: Any],
              let entries = bc["value"] as? [[String: Any]] else {
            return false
        }
        for entry in entries {
            guard let label = entry["label"] as? String else { continue }
            if label == "Certificate Authority" {
                if let v = entry["value"] as? String {
                    return v.lowercased() == "yes" || v.lowercased() == "true"
                }
                if let n = entry["value"] as? NSNumber {
                    return n.boolValue
                }
            }
        }
        return false
    }

    private static func derBlocks(inPEM pem: String) -> [Data] {
        var out: [Data] = []
        var base64 = ""
        var inside = false
        for line in pem.components(separatedBy: .newlines) {
            let t = line.trimmingCharacters(in: .whitespaces)
            if t.hasPrefix("-----BEGIN CERTIFICATE") {
                inside = true
                base64 = ""
                continue
            }
            if t.hasPrefix("-----END CERTIFICATE") {
                if inside, let der = Data(base64Encoded: base64) {
                    out.append(der)
                }
                inside = false
                continue
            }
            if inside { base64 += t }
        }
        return out
    }

    private static func hexToData(_ hex: String) -> Data? {
        let chars = Array(hex)
        guard chars.count % 2 == 0, !chars.isEmpty else { return nil }
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
