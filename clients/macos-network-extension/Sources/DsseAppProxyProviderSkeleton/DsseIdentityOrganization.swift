import CryptoKit
import Foundation
import Security

// Whether the identity this device holds belongs to the organization whose profile is in force.
//
// ★★★ AN IDENTITY FROM ANOTHER ORGANIZATION COMPLETES THE HANDSHAKE (2026-09-04, measured on a real Mac).
//
// The enrolment gate already refuses an identity from another DEPLOYMENT: it asks whether the certificate
// completes a (T) handshake, and one issued by a destroyed lab does not. Within ONE deployment that question
// has the wrong answer. A Mac holding a `tenant_default` certificate was handed the four artefacts of a NEW
// organization, and the old certificate handshook perfectly — same Edge, same transport CA — so the gate said
// proceed and the device never enrolled into the organization it had been given:
//
//	steer_mux_tenant_resolved device="ShinnoMac-mini" tenant="tenant_default"
//	  — this flow's organization was proved from the device's certificate
//	signing_counts_since_start {"deployment_root_no_own_authority": 40}
//
// Every flow was then inspected under the DEPLOYMENT's interception CA while the organization's own authority
// sat loaded and unused on the Edge. Both sides reported success. That is per-tenant PKI separation failing at
// the only place it is actually decided — which certificate the device presents.
//
// ★ WHY THE ISSUER AND NOT A RECORDED TENANT. The identity pointer records a hash, a name and a date, and
// nothing about an organization; stamping it would only cover identities written from now on, and every device
// in the world already holds an unstamped one. The issuer is a property of the certificate itself, so this
// answers for the identities that already exist — which are the ones that are wrong.
public enum DsseIdentityOrganization {
    /// Does `identity`'s certificate chain to the device CA that `pinnedSHA256` names?
    ///
    /// nil is "could not be asked" — no pin in the profile, or the issuing certificate is not on this device —
    /// and MUST NOT be read as "no". Refusing an identity because a question could not be asked would strand a
    /// device whose issuer simply is not in the keychain, which is a different fault with a different fix.
    public static func identityIssuedByPinnedDeviceCA(identity: SecIdentity, pinnedSHA256: String) -> Bool? {
        let pin = pinnedSHA256.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !pin.isEmpty else { return nil }
        var leaf: SecCertificate?
        guard SecIdentityCopyCertificate(identity, &leaf) == errSecSuccess, let leaf else { return nil }
        guard let issuerDN = SecCertificateCopyNormalizedIssuerSequence(leaf) as Data? else { return nil }
        guard let issuers = certificates(withNormalizedSubject: issuerDN), !issuers.isEmpty else { return nil }
        for issuer in issuers where sha256Hex(of: issuer) == pin {
            return true
        }
        return false
    }

    /// Every certificate on this device whose normalized subject equals `subject`. A CA can legitimately appear
    /// more than once — an overlaid rotation puts old and new side by side — so this returns all of them and
    /// the caller accepts a match against any.
    static func certificates(withNormalizedSubject subject: Data) -> [SecCertificate]? {
        let query: [String: Any] = [kSecClass as String: kSecClassCertificate,
                                    kSecAttrSubject as String: subject,
                                    kSecMatchLimit as String: kSecMatchLimitAll,
                                    kSecReturnRef as String: true]
        var out: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &out)
        guard status == errSecSuccess else { return nil }
        return out as? [SecCertificate]
    }

    static func sha256Hex(of certificate: SecCertificate) -> String {
        let der = SecCertificateCopyData(certificate) as Data
        return SHA256.hash(data: der).map { String(format: "%02x", $0) }.joined()
    }
}
