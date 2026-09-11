import CryptoKit
import Foundation
import Security

// DsseRenewedIdentityStore — where a renewed device identity is kept, and how it takes over from the old one.
//
// STORAGE DECISION (2026-07-28): the keychain holds the material; a small pointer FILE decides which material
// is in force.
//
// The bootstrap identity arrives either as an MDM-provisioned keychain item (production) or as a p12 file the
// transport contract points at (lab). Renewal writes to the keychain rather than back to a p12, because
// creating a PKCS#12 means exporting a private key to a file — the opposite direction from where device keys
// are going (Secure Enclave, non-exportable). So: p12 / MDM is how the FIRST identity arrives; the keychain is
// where every identity after that lives.
//
// WHY A POINTER FILE AND NOT KEYCHAIN LABELS. The obvious design is to label the live identity and look it up
// by name. Measured on macOS 15, that does not work, in two separate ways:
//
//   * kSecAttrLabel is IGNORED when querying kSecClassIdentity. A query using a label that cannot match
//     anything still returns every identity on the machine, so a label-keyed lookup silently returns an
//     ARBITRARY identity.
//   * kSecAttrLabel passed to SecItemAdd for a certificate is ignored too; the item appears under its subject
//     common name instead.
//
// Both were found by running the code against the real keychain rather than a stub, and either one alone would
// have produced a device that connects with the wrong certificate. (This also means the pre-existing
// DsseTransportSecurityFactory.clientIdentity(label:) does not filter by label — see
// docs/2026-07-28_macos_keychain_label_lookup_is_not_a_filter.ja.md.)
//
// So the source of truth is a file this code fully controls: it records the SHA-256 of the certificate whose
// identity is in force. Selection matches on that hash. The hash is not a secret, so persisting it is fine.
//
// REPLACEMENT IS PROVE-THEN-SWAP. The failure that matters is not "renewal did not happen" — that has weeks of
// retry budget — but "renewal happened and the device can no longer reach the Edge". The new key and
// certificate go into the keychain, the caller proves the resulting identity can complete a real mTLS
// handshake, and ONLY THEN is the pointer file updated. Writing one small file is the single commit point, so
// there is no window in which a half-finished renewal is in force. A probe failure deletes the new material
// and leaves the pointer, and therefore the working identity, exactly as it was.

public enum DsseRenewedIdentityStoreError: Error, Equatable {
    case keyStoreFailed(OSStatus)
    case certificateStoreFailed(OSStatus)
    case identityNotResolvable
    case probeRejectedNewIdentity(String)
    case pointerWriteFailed(String)
}

// The pointer file's contents. Non-secret by construction: a hash, a name, and a date — never key material.
public struct DsseDeviceIdentityPointer: Codable, Equatable, Sendable {
    public let certificateSHA256: String
    // The keychain tag of this identity's private key. Recorded so a LATER renewal can delete the material it
    // supersedes. Without it, each renewal would leave its predecessor's key and certificate in the keychain
    // forever — one dead pair every renewal period, for the life of the device.
    public let privateKeyTag: String
    public let commonName: String
    public let notAfter: Date
    public let installedAt: Date
    // The PREVIOUS renewed identity, kept for exactly one generation as the fallback. It was proven on the
    // wire for a whole renewal period and its issuer is a CURRENT CA — both things a years-old bootstrap
    // cannot claim, and the second one is what turned a CA retirement into an outage on 2026-08-02. Keeping
    // one generation means the fallback's freshness rides the ordinary renewal cadence instead of needing a
    // renewal cycle of its own; the generation before this one is deleted, so nothing accumulates.
    // Optional so pointer files written before these fields existed keep decoding (they read as "no
    // previous", which falls back to the bootstrap exactly as before).
    public let previousCertificateSHA256: String?
    public let previousPrivateKeyTag: String?
    // ★★★ WHICH ORGANIZATION THIS IDENTITY BELONGS TO (2026-09-04, measured on a real Mac). A device holding
    // one organization's certificate was given another organization's profile, and nothing on the device could
    // tell: the issuing CA is not on disk and not in any keychain, and the certificate completes the handshake
    // because it is the same deployment. So the device went on presenting the wrong organization's identity and
    // every flow was inspected under the deployment's CA instead of the organization's own authority.
    // Optional, and an unstamped pointer reads as "unknown" — never as "wrong". Every device in the world holds
    // an unstamped one today; refusing on absence would strand all of them.
    public let tenantID: String?

    public init(certificateSHA256: String, privateKeyTag: String, commonName: String,
                notAfter: Date, installedAt: Date,
                previousCertificateSHA256: String? = nil, previousPrivateKeyTag: String? = nil,
                tenantID: String? = nil) {
        self.certificateSHA256 = certificateSHA256
        self.privateKeyTag = privateKeyTag
        self.commonName = commonName
        self.notAfter = notAfter
        self.installedAt = installedAt
        self.previousCertificateSHA256 = previousCertificateSHA256
        self.previousPrivateKeyTag = previousPrivateKeyTag
        self.tenantID = tenantID
    }

    enum CodingKeys: String, CodingKey {
        case certificateSHA256 = "certificate_sha256"
        case privateKeyTag = "private_key_tag"
        case commonName = "common_name"
        case notAfter = "not_after"
        case installedAt = "installed_at"
        case previousCertificateSHA256 = "previous_certificate_sha256"
        case previousPrivateKeyTag = "previous_private_key_tag"
        case tenantID = "tenant_id"
    }
}

public enum DsseRenewedIdentityStore {

    // The pointer file's name inside the agent-config directory.
    public static let pointerFileName = "device_identity_pointer.json"

    // MARK: - Reading the identity in force

    // currentIdentity returns the identity the pointer file names, or nil when there is no pointer or the
    // material it names is gone. Nil means "fall back to the bootstrap identity" — NOT "use anything you can
    // find", which is what the label-based lookup was silently doing.
    // Returning nil here silently is how a renewal can fail to converge without anything looking wrong: the
    // agent falls back to the bootstrap identity, traffic keeps flowing, and the Edge goes on observing the
    // OLD certificate forever while the device asks to renew again on every poll. On 2026-08-02 that state
    // held for hours and read as healthy from every direction. Each way of ending up with no renewed
    // identity is now a distinct, named outcome — silence was the whole problem.
    public static func currentIdentity(configDirectory: URL) -> SecIdentity? {
        guard let pointer = readPointer(configDirectory: configDirectory) else {
            // Absent and corrupt call for opposite responses — "never renewed / moved aside" is normal,
            // a pointer that EXISTS but does not decode means the commit-point file itself is damaged and
            // renewal state has been lost. One label for both would make the second look like the first.
            let url = configDirectory.appendingPathComponent(pointerFileName)
            let reason = FileManager.default.fileExists(atPath: url.path)
                ? "pointer_exists_but_does_not_decode" : "no_pointer_file"
            dsseRuntimeLog("device_identity renewed_identity=absent reason=\(reason)")
            return nil
        }
        guard let found = identity(certificateSHA256: pointer.certificateSHA256) else {
            // The pointer names a certificate the keychain does not have. The renewal was recorded but its
            // identity is gone — which is NOT the same as never having renewed, and must not read the same.
            dsseRuntimeLog("device_identity renewed_identity=absent reason=pointer_names_a_certificate_not_in_the_keychain"
                + " sha256=\(pointer.certificateSHA256)")
            return nil
        }
        // Present is not the same as usable. install() proves a renewed identity with a real exchange before
        // putting it in force, and that proof does not survive: on 2026-08-01 a renewal that had passed its
        // probe stopped being usable by this process afterwards (the device-key ACL restriction,
        // docs/2026-07-29_macos_device_key_acl_restriction.ja.md), every tunnel failed, and the only way back
        // was moving this pointer aside by hand. An older certificate that works beats a newer one that does
        // not. docs/handoff_windows_agent.ja.md names this check as a precondition for live identity
        // resolution — it was added in a710362e and then silently lost in 39b23541, which restated the risk.
        guard canSign(with: found) else {
            dsseRuntimeLog("device_identity renewed_identity=absent reason=private_key_refuses_to_sign"
                + " sha256=\(pointer.certificateSHA256) — falling back to the bootstrap identity")
            return nil
        }
        dsseRuntimeLog("device_identity renewed_identity=in_use sha256=\(pointer.certificateSHA256)")
        return found
    }

    // previousIdentity returns the previous renewed generation — the identity the CURRENT one replaced,
    // kept for exactly this moment: the current one stopped working and the device needs something proven
    // rather than something old. Same named-outcome logging and the same canSign gate as currentIdentity;
    // callers try this before the bootstrap. Only called once the current identity has already failed, so
    // a log line here is rare and load-bearing, never chatter.
    public static func previousIdentity(configDirectory: URL) -> SecIdentity? {
        guard let pointer = readPointer(configDirectory: configDirectory),
              let sha = pointer.previousCertificateSHA256, !sha.isEmpty else {
            return nil // no previous generation recorded — pre-N-1 pointer or first renewal; not an event
        }
        guard let found = identity(certificateSHA256: sha) else {
            dsseRuntimeLog("device_identity previous_identity=absent reason=pointer_names_a_certificate_not_in_the_keychain sha256=\(sha)")
            return nil
        }
        guard canSign(with: found) else {
            dsseRuntimeLog("device_identity previous_identity=absent reason=private_key_refuses_to_sign sha256=\(sha)")
            return nil
        }
        dsseRuntimeLog("device_identity previous_identity=in_use sha256=\(sha) — the current renewed identity failed and the prior generation is carrying the device")
        return found
    }

    /// canSign asks the only question that matters about a private key an agent is about to depend on: will it
    /// sign. A key can be found, be linked to its certificate, and still refuse — which is indistinguishable
    /// from a healthy identity until a handshake fails.
    static func canSign(with identity: SecIdentity) -> Bool {
        var key: SecKey?
        guard SecIdentityCopyPrivateKey(identity, &key) == errSecSuccess, let key else { return false }
        let algorithm: SecKeyAlgorithm = .ecdsaSignatureMessageX962SHA256
        guard SecKeyIsAlgorithmSupported(key, .sign, algorithm) else {
            // A key of another type is not evidence of breakage; leave it to the handshake.
            return true
        }
        var error: Unmanaged<CFError>?
        let probe = Data("dsse-identity-usability-probe".utf8) as CFData
        let signature = SecKeyCreateSignature(key, algorithm, probe, &error)
        return signature != nil
    }

    public static func readPointer(configDirectory: URL) -> DsseDeviceIdentityPointer? {
        let url = configDirectory.appendingPathComponent(pointerFileName)
        guard let data = try? Data(contentsOf: url) else { return nil }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try? decoder.decode(DsseDeviceIdentityPointer.self, from: data)
    }

    // MARK: - Installing a renewal

    // install stores a renewed identity, proves it works, and only then puts it in force.
    //
    // probe receives the candidate identity and must return true only if a real mTLS exchange with the Edge
    // succeeded using it. It is injected so the caller decides what "works" means, and so this is testable
    // without pretending about the network.
    @discardableResult
    /// - Parameter tenantID: the organization this identity was issued for, taken from the profile the device
    ///   enrolled or renewed against. Stamped onto the pointer so the next start can tell whether the identity
    ///   in hand belongs to the organization the device has been GIVEN — a question nothing else on the device
    ///   can answer, because the issuing CA is neither on disk nor in any keychain. nil leaves it unstamped,
    ///   which reads as "unknown" and never as "wrong".
    public static func install(_ renewed: DsseRenewedIdentity,
                               configDirectory: URL,
                               probe: (SecIdentity) -> Bool,
                               log: ((String) -> Void)? = nil,
                               tenantID: String? = nil) throws -> SecIdentity {
        let fingerprint = sha256Hex(SecCertificateCopyData(renewed.certificate) as Data)
        // Read before anything changes, so the material this renewal replaces can be cleaned up afterwards.
        let superseded = readPointer(configDirectory: configDirectory)

        // The private key is already in the keychain — DsseCertificateRenewal generates it there, because a
        // key imported afterwards never gets linked to its certificate on macOS. So only the certificate is
        // added here, and the identity forms at that moment.
        let certAttributes: [String: Any] = [
            kSecClass as String: kSecClassCertificate,
            kSecValueRef as String: renewed.certificate,
        ]
        let certStatus = SecItemAdd(certAttributes as CFDictionary, nil)
        guard certStatus == errSecSuccess || certStatus == errSecDuplicateItem else {
            rollBack(renewed, fingerprint: fingerprint)
            throw DsseRenewedIdentityStoreError.certificateStoreFailed(certStatus)
        }

        // The keychain forms an identity only when the certificate's public key really matches a stored
        // private key. Failing here means the two do not belong together.
        guard let candidate = identity(certificateSHA256: fingerprint) else {
            rollBack(renewed, fingerprint: fingerprint)
            throw DsseRenewedIdentityStoreError.identityNotResolvable
        }

        // Prove it on the wire while it is still inert. Nothing selects this certificate until the pointer
        // names it, so a failure here costs nothing.
        guard probe(candidate) else {
            rollBack(renewed, fingerprint: fingerprint)
            log?("certificate_renewal probe REJECTED the new identity — it was removed and the existing " +
                 "certificate remains in force; renewal will be retried")
            throw DsseRenewedIdentityStoreError.probeRejectedNewIdentity(
                "the renewed identity could not complete an mTLS handshake with the Edge")
        }

        // The single commit point. The identity being superseded is NOT deleted — it becomes the previous
        // generation, this device's fallback: proven on the wire for a whole renewal period and issued by a
        // current CA, which is everything a years-old bootstrap is not. Re-installing the same certificate
        // keeps whatever previous generation already existed rather than pointing the fallback at itself.
        let keepAsPrevious = (superseded != nil && superseded!.certificateSHA256 != fingerprint)
        do {
            try writePointer(DsseDeviceIdentityPointer(
                certificateSHA256: fingerprint,
                privateKeyTag: renewed.privateKeyTag,
                commonName: renewed.commonName,
                notAfter: renewed.notAfter,
                installedAt: Date(),
                previousCertificateSHA256: keepAsPrevious ? superseded?.certificateSHA256 : superseded?.previousCertificateSHA256,
                previousPrivateKeyTag: keepAsPrevious ? superseded?.privateKeyTag : superseded?.previousPrivateKeyTag,
                tenantID: tenantID ?? superseded?.tenantID),
                             configDirectory: configDirectory)
        } catch {
            rollBack(renewed, fingerprint: fingerprint)
            throw DsseRenewedIdentityStoreError.pointerWriteFailed(error.localizedDescription)
        }

        // Only now that the new identity is committed and working: drop the generation BEFORE the one just
        // kept as fallback (N-2). Done AFTER the commit, never before — if this step fails the device still
        // has a working identity, whereas deleting first would risk a window with none. Exactly one previous
        // generation is retained, so nothing accumulates.
        if keepAsPrevious, let dropSHA = superseded?.previousCertificateSHA256, dropSHA != fingerprint {
            remove(certificateSHA256: dropSHA)
            if let dropTag = superseded?.previousPrivateKeyTag, !dropTag.isEmpty {
                DsseCertificateRenewal.deleteKey(tag: dropTag)
            }
            log?("certificate_renewal removed generation N-2 fingerprint=\(dropSHA.prefix(16)) — the identity it replaced stays as the fallback")
        }

        log?("certificate_renewal INSTALLED identity=\(renewed.commonName) " +
             "not_after=\(ISO8601DateFormatter().string(from: renewed.notAfter)) fingerprint=\(fingerprint.prefix(16))")
        return candidate
    }

    static func writePointer(_ pointer: DsseDeviceIdentityPointer, configDirectory: URL) throws {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data = try encoder.encode(pointer)
        let url = configDirectory.appendingPathComponent(pointerFileName)
        // Atomic: a torn pointer file would leave the device unable to decide which identity is current.
        try data.write(to: url, options: .atomic)
    }

    // MARK: - Keychain access, keyed by certificate rather than by label

    // identity(certificateSHA256:) finds the identity whose certificate has exactly this fingerprint.
    //
    // It enumerates and compares rather than asking the keychain to filter, because the keychain does not
    // filter identity queries by label at all. Comparing the certificate bytes is unambiguous.
    static func identity(certificateSHA256 fingerprint: String) -> SecIdentity? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassIdentity,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnRef as String: true,
        ]
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let identities = result as? [SecIdentity] else {
            return nil
        }
        for identity in identities {
            var certificate: SecCertificate?
            guard SecIdentityCopyCertificate(identity, &certificate) == errSecSuccess,
                  let certificate else { continue }
            if sha256Hex(SecCertificateCopyData(certificate) as Data) == fingerprint { return identity }
        }
        return nil
    }

    // rollBack undoes a failed installation completely: the certificate AND the private key that was
    // generated for it. Leaving the key would accumulate unusable key material on the device with every
    // retry — once every few weeks, forever.
    static func rollBack(_ renewed: DsseRenewedIdentity, fingerprint: String) {
        remove(certificate: renewed.certificate)
        if !renewed.privateKeyTag.isEmpty {
            DsseCertificateRenewal.deleteKey(tag: renewed.privateKeyTag)
        }
    }

    // remove deletes exactly the certificate with this fingerprint and the key tagged for it. Scoped this
    // tightly on purpose: a rollback that deleted by name or by label could take out the identity the device
    // is currently connecting with.
    // remove(certificate:) deletes a certificate we still hold a reference to. PREFER THIS.
    //
    // MEASURED LIMIT, stated plainly because it is not fixable from here: the LAST certificate a process adds
    // cannot be deleted by that same process. Delete-by-reference, delete-by-serial+issuer and
    // enumerate-then-delete were all tried; the item stays invisible to this process's keychain searches while
    // being plainly present to `security find-certificate`, and the NEXT process removes it without trouble.
    // Repeated runs confirm it does not accumulate — each run clears its predecessor's straggler and leaves
    // exactly one of its own.
    //
    // Why this is acceptable rather than a leak worth blocking on: the PRIVATE KEY is deleted reliably (that
    // path uses kSecAttrApplicationTag, which behaves), and a certificate without its key forms no identity
    // and cannot authenticate anything. What lingers is a public certificate — not secret, not usable, and
    // superseded at the next renewal. The security-critical half of the rollback is intact; the cosmetic half
    // is delayed.
    static func remove(certificate: SecCertificate) {
        if SecItemDelete([kSecClass as String: kSecClassCertificate,
                          kSecValueRef as String: certificate] as CFDictionary) == errSecSuccess {
            return
        }
        // Serial number and issuer are indexed certificate attributes, so this matches the stored item without
        // a full scan.
        guard let serial = SecCertificateCopySerialNumberData(certificate, nil) as Data?,
              let issuer = SecCertificateCopyNormalizedIssuerSequence(certificate) as Data? else { return }
        SecItemDelete([kSecClass as String: kSecClassCertificate,
                       kSecAttrSerialNumber as String: serial,
                       kSecAttrIssuer as String: issuer] as CFDictionary)
    }

    // remove(certificateSHA256:) is for material we only know by fingerprint — the identity a renewal
    // supersedes, recorded in a pointer file written by an earlier run. Those items are from a previous
    // process, so the enumeration does find them.
    static func remove(certificateSHA256 fingerprint: String) {
        guard let certificate = certificate(sha256: fingerprint) else { return }
        remove(certificate: certificate)
    }

    // certificate(sha256:) finds a stored certificate by its fingerprint, or nil when it is not there.
    static func certificate(sha256 fingerprint: String) -> SecCertificate? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassCertificate,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnRef as String: true,
        ]
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let certificates = result as? [SecCertificate] else {
            return nil
        }
        return certificates.first { sha256Hex(SecCertificateCopyData($0) as Data) == fingerprint }
    }

    static func sha256Hex(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}
