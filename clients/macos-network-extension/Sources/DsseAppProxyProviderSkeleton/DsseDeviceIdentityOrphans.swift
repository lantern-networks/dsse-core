import Foundation
import Security

// DsseDeviceIdentityOrphans — names the device identities that are on this machine but NOT in force.
//
// WHY THIS EXISTS. DsseRenewedIdentityStore cleans up exactly one thing: the identity its OWN pointer file says
// the current one replaced. That is correct for the steady state — one renewal supersedes one predecessor — but
// it is blind to three real accumulations, every one of which was found on a live device on 2026-07-29:
//
//   * identities created BEFORE the pointer file existed (the store began on 2026-07-28; anything older was
//     never recorded in a pointer, so nothing will ever reap it),
//   * hand-made or test identities for this device — e.g. a leftover "Wrong CA (fail-open test)" certificate,
//   * a renewal that was KILLED after the key and certificate were in the keychain but before the pointer was
//     committed. install() rolls those back on a probe failure or an error, but a hard crash or a killed
//     process leaves the pair behind, and the next renewal makes another.
//
// Each survivor is not cosmetic. On macOS the private key of such an identity can be usable by an unprivileged
// local caller (measured: six of seven mac-dev-1 keys signed with no prompt), and the Edge trusts the
// certificate until it expires — which for the ones found ran to 2030 and 2036. So a superseded identity is a
// second, still-valid, still-signable credential for the same device, sitting on disk for years.
//
// WHAT THIS DOES AND DOES NOT DO. It REPORTS. It does not delete. Deleting from the System keychain needs
// privilege this process does not have, and — more to the point — which identities are safe to remove, and
// whether the underlying key ACL should be tightened at all, is a decision for an operator, not something an
// agent should do silently at startup. This follows the same shape as the keychain-writability and
// Secure-Enclave probes: state the precondition out loud so it is visible BEFORE the day it matters. The
// accumulation found on 2026-07-29 was invisible until someone ran `security find-certificate` by hand; after
// this, it is one line in the log at every startup.

// DsseIdentityFacts is the minimum needed to judge an identity, extracted so the decision is testable without a
// keychain. Certificates are identified by the SHA-256 of their DER, the same key the pointer file uses.
public struct DsseIdentityFacts: Equatable, Sendable {
    public let certificateSHA256: String
    public let subjectCommonName: String
    public let issuerCommonName: String
    public let notAfter: Date?

    public init(certificateSHA256: String, subjectCommonName: String, issuerCommonName: String, notAfter: Date?) {
        self.certificateSHA256 = certificateSHA256
        self.subjectCommonName = subjectCommonName
        self.issuerCommonName = issuerCommonName
        self.notAfter = notAfter
    }
}

// DsseDeviceIdentityOrphan is one identity that is present for this device but is not the one in force.
public struct DsseDeviceIdentityOrphan: Equatable, Sendable {
    public let facts: DsseIdentityFacts
    // expired is stated separately because an expired orphan is clutter, while a still-valid one is a live
    // duplicate credential — a different severity even though both should go.
    public let expired: Bool
}

public enum DsseDeviceIdentityOrphans {

    // findOrphans is the whole decision, as a pure function over facts.
    //
    // deviceCommonName scopes it to THIS device: an identity for some other subject is not an orphan of ours,
    // it is simply somebody else's item in a shared keychain, and deleting or even flagging it would be wrong.
    // inForceFingerprint is the certificate the pointer names; it, and only it, is excluded. Matching on the
    // fingerprint rather than on "the newest" is deliberate — "newest" would wrongly spare a freshly minted
    // rogue certificate and wrongly flag the real one during the brief window a renewal is being proved.
    public static func findOrphans(all: [DsseIdentityFacts],
                                   deviceCommonName: String,
                                   inForceFingerprint: String?,
                                   now: Date) -> [DsseDeviceIdentityOrphan] {
        all.compactMap { facts in
            guard facts.subjectCommonName == deviceCommonName else { return nil }
            if let inForceFingerprint, facts.certificateSHA256 == inForceFingerprint { return nil }
            let expired = facts.notAfter.map { $0 <= now } ?? false
            return DsseDeviceIdentityOrphan(facts: facts, expired: expired)
        }
    }

    // MARK: - Keychain enumeration

    // enumerateDeviceIdentityFacts reads every identity in the search list and pulls out the facts findOrphans
    // needs. It enumerates rather than filtering in the query for the same reason the rest of this store does:
    // the keychain does not filter identity queries by subject or label, so filtering here would silently
    // return everything anyway.
    static func enumerateDeviceIdentityFacts() -> [DsseIdentityFacts] {
        let query: [String: Any] = [
            kSecClass as String: kSecClassIdentity,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnRef as String: true,
        ]
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let identities = result as? [SecIdentity] else {
            return []
        }
        return identities.compactMap { identity in
            var certificate: SecCertificate?
            guard SecIdentityCopyCertificate(identity, &certificate) == errSecSuccess,
                  let certificate else { return nil }
            return facts(of: certificate)
        }
    }

    // facts(of:) extracts the subject CN, issuer CN, notAfter and fingerprint from a certificate.
    static func facts(of certificate: SecCertificate) -> DsseIdentityFacts {
        let fingerprint = DsseRenewedIdentityStore.sha256Hex(SecCertificateCopyData(certificate) as Data)
        let subject = (SecCertificateCopySubjectSummary(certificate) as String?) ?? ""

        var issuer = ""
        var notAfter: Date?
        let wanted = [kSecOIDX509V1ValidityNotAfter, kSecOIDX509V1IssuerName] as CFArray
        if let values = SecCertificateCopyValues(certificate, wanted, nil) as? [String: Any] {
            if let na = values[kSecOIDX509V1ValidityNotAfter as String] as? [String: Any],
               let seconds = na[kSecPropertyKeyValue as String] as? Double {
                // CFAbsoluteTime: seconds since 2001-01-01 UTC.
                notAfter = Date(timeIntervalSinceReferenceDate: seconds)
            }
            if let iss = values[kSecOIDX509V1IssuerName as String] as? [String: Any],
               let parts = iss[kSecPropertyKeyValue as String] as? [[String: Any]] {
                // The issuer name is a list of RDNs; take the common name.
                for part in parts where (part[kSecPropertyKeyLabel as String] as? String) == "2.5.4.3" {
                    if let cn = part[kSecPropertyKeyValue as String] as? String { issuer = cn }
                }
            }
        }
        return DsseIdentityFacts(certificateSHA256: fingerprint, subjectCommonName: subject,
                                 issuerCommonName: issuer, notAfter: notAfter)
    }

    // MARK: - Reporting

    // reportOrphans logs the finding once at startup. Silent when there is nothing, EXCEPT it says so, so an
    // operator can tell "checked, clean" from "never checked" — the two look identical when success is silent,
    // and a check nobody can see the result of is a check nobody trusts.
    public static func reportOrphans(configDirectory: URL, log: ((String) -> Void)?) {
        guard let log else { return }
        let pointer = DsseRenewedIdentityStore.readPointer(configDirectory: configDirectory)
        // Scope to this device. Prefer the in-force identity's own subject; fall back to the pointer's recorded
        // common name. Without a device name there is nothing to scope to, so do not guess — say why.
        guard let deviceCN = deviceCommonName(pointer: pointer), !deviceCN.isEmpty else {
            log("device_identity_orphans SKIPPED — no in-force identity to scope the check to (bootstrap only)")
            return
        }
        let all = enumerateDeviceIdentityFacts()
        for line in lines(all: all, deviceCommonName: deviceCN,
                          inForceFingerprint: pointer?.certificateSHA256, now: Date()) {
            log(line)
        }
    }

    /// lines is the whole report as text, decided from facts alone so it can be tested without a keychain.
    /// The keychain read stays in reportOrphans; everything that can be got wrong is here.
    public static func lines(all: [DsseIdentityFacts], deviceCommonName deviceCN: String,
                            inForceFingerprint: String?, now: Date) -> [String] {
        var out: [String] = []

        // ★★★ ZERO IS NOT ONE, AND THIS CHECK USED TO SAY IT WAS (2026-08-29, measured on a real Mac). The
        // report is scoped off the POINTER FILE, not off an identity — so on a device whose private key had
        // gone (dsse-uninstall removes the extension, and the key lives in its keychain access group) it found
        // no leftovers and printed "exactly one identity in force, no leftovers". There were none. The
        // certificate and the pointer were still there, so the device read as enrolled to itself and to the
        // Edge, and enrolment came back 403 "already enrolled — renewal proves possession of the one being
        // replaced": possession of a key that no longer exists. A check that cannot tell one from none is
        // worse than no check, because it is the line an operator reads INSTEAD of looking.
        let mine = all.filter { $0.subjectCommonName == deviceCN }
        if mine.isEmpty {
            out.append("⚠ device_identity_orphans NO IDENTITY cn=\(deviceCN) — this device holds a pointer, " +
                "and possibly a certificate, for an identity whose private key is NOT in the keychain. It " +
                "cannot prove the name it claims: enrolment will be refused as already enrolled, and renewal " +
                "cannot prove possession. Free the name by removing the device in the Console, then enrol again")
            return out
        }
        if let inForce = inForceFingerprint, !inForce.isEmpty,
           !mine.contains(where: { $0.certificateSHA256 == inForce }) {
            out.append("⚠ device_identity_orphans POINTER STALE cn=\(deviceCN) in_force=\(inForce) — the " +
                "identity the pointer names is not in the keychain, and \(mine.count) other identity(ies) for " +
                "this device are. The device will present one the deployment did not record as current")
        }

        let orphans = findOrphans(all: all, deviceCommonName: deviceCN,
                                  inForceFingerprint: inForceFingerprint, now: now)
        if orphans.isEmpty {
            out.append("device_identity_orphans ok cn=\(deviceCN) identities=\(mine.count) — no leftovers")
            return out
        }
        let iso = ISO8601DateFormatter()
        for orphan in orphans {
            let f = orphan.facts
            let expiry = f.notAfter.map { iso.string(from: $0) } ?? "unknown"
            let severity = orphan.expired ? "EXPIRED clutter" : "★still-valid duplicate credential"
            out.append("⚠ device_identity_orphans \(severity) cn=\(deviceCN) issuer=\"\(f.issuerCommonName)\" " +
                "not_after=\(expiry) fingerprint=\(f.certificateSHA256.prefix(16)) — a second identity for " +
                "this device that the Edge still trusts and whose key may be signable by any local caller; it " +
                "is not the one in force. Remove it from the keychain, or tighten its key's ACL.")
        }
        return out
    }

    // deviceCommonName decides which subject the check is scoped to: the pointer's recorded common name if there
    // is a pointer, otherwise the subject of the in-force identity read straight from the keychain.
    static func deviceCommonName(pointer: DsseDeviceIdentityPointer?) -> String? {
        if let pointer, !pointer.commonName.isEmpty { return pointer.commonName }
        guard let pointer, let identity = DsseRenewedIdentityStore.identity(certificateSHA256: pointer.certificateSHA256) else {
            return nil
        }
        var certificate: SecCertificate?
        guard SecIdentityCopyCertificate(identity, &certificate) == errSecSuccess, let certificate else { return nil }
        return SecCertificateCopySubjectSummary(certificate) as String?
    }
}
