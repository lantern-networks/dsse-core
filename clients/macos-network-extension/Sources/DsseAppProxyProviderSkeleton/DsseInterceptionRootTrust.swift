import CryptoKit
import Foundation
import Security

/// Which interception roots this machine actually trusts.
///
/// Switching the interception root is the one certificate operation the Console cannot offer, and the
/// obstacle was never the button: nothing told the Edge which root a device trusts, so a switch would start
/// signing under a root some endpoints may not have. Every HTTPS request on those machines fails at once —
/// the same shape as the 2026-07-31 transport outage, with a wider blast radius, because interception
/// applies to every site rather than to one tunnel.
///
/// So the Edge names the roots it signs under and the agent LOOKS. This reports only what it found: an empty
/// answer means "found none", and the Edge is careful to read a device that says nothing as unknown rather
/// than as untrusting, because those two lead to opposite mistakes.
public enum DsseInterceptionRootTrust {

    /// present returns the subset of `wanted` that is in this machine's trust settings. Fingerprints in,
    /// fingerprints out — the certificates themselves are never sent anywhere.
    public static func present(wanted: [String]) -> [String] {
        // Say what was asked and what was found, every time. Shipped without this, the report simply never
        // appeared and there was no way to tell whether the Edge had named no roots, whether the policy had
        // not reached this device, or whether the trust store genuinely did not hold them — three causes,
        // one silence. That is the failure this whole signal exists to end, reproduced in the signal itself.
        guard !wanted.isEmpty else {
            dsseRuntimeLog("interception_root_trust wanted=0 (the deployment named no roots to look for)")
            return []
        }
        let want = Set(wanted.map { $0.lowercased() })
        var found = Set<String>()
        // Admin and system: where an MDM profile or a manual install puts a root that applies to everyone on
        // the machine. The user domain is deliberately included too — a root installed only for the logged-in
        // user still decides whether THAT user's browsing works.
        for domain in [SecTrustSettingsDomain.user, .admin, .system] {
            var certs: CFArray?
            guard SecTrustSettingsCopyCertificates(domain, &certs) == errSecSuccess,
                  let list = certs as? [SecCertificate] else { continue }
            for certificate in list {
                let der = SecCertificateCopyData(certificate) as Data
                let fp = SHA256.hash(data: der).map { String(format: "%02x", $0) }.joined()
                if want.contains(fp) { found.insert(fp) }
            }
        }
        let out = found.sorted()
        dsseRuntimeLog("interception_root_trust wanted=\(wanted.count) found=\(out.count) " +
                       "scanned_domains=user,admin,system")
        for fp in wanted where !found.contains(fp) {
            dsseRuntimeLog("interception_root_trust NOT_IN_TRUST_STORE sha256=\(fp)")
        }
        return out
    }
}
