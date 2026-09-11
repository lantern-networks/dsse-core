import Foundation

/// Which deployment a device is installed FOR — the one fact that decides whether material it adopted earlier
/// still belongs to it. Separated from DsseAdoptedTrustAnchorStore so the rule can be read (and tested)
/// without a keychain or a bundle.
enum DsseAdoptedTenantScope {
    /// The tenant named by the signed install profile in force, or nil when this device has no profile.
    ///
    /// nil is "cannot be asked", never "no tenant": a deployment that predates install profiles has nothing to
    /// compare against, and inventing an answer there would discard the anchors of a fleet that is working.
    static func tenantInForce(configDirectory: URL) -> String? {
        profileInForce(configDirectory: configDirectory)
            .map { $0.tenantID.trimmingCharacters(in: .whitespacesAndNewlines) }
            .flatMap { $0.isEmpty ? nil : $0 }
    }

    /// The transport server name this deployment tells its devices to send.
    ///
    /// ★★★ THE SECOND PIECE OF EVIDENCE, AND THE ONLY ONE THAT REACHES A DEVICE THAT ALREADY HAS THE PROBLEM
    /// (2026-08-29). Recording the tenant on the pointer only protects material adopted from now on — every
    /// pointer in the world today is unstamped, so a tenant-only check left the measured Mac carrying
    /// 44paeq….dsse.invalid exactly as before. The name is different: a pointer that names a transport server
    /// name is claiming which certificate this device should be shown, and the profile names the one this
    /// deployment actually serves. Two different names is not "cannot prove it is ours" — it is proof it is
    /// someone else's, on evidence already present on the disk.
    static func transportServerNameInForce(configDirectory: URL) -> String? {
        profileInForce(configDirectory: configDirectory)?
            .transportServerName?
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
            .nonEmpty
    }

    private static func profileInForce(configDirectory: URL) -> DsseInstallProfile? {
        let profilePath = configDirectory
            .appendingPathComponent(DsseInstallProfileApplication.defaultFileName).path
        return DsseSignedInstallProfile.verifiedProfile(
            signedPath: profilePath,
            pinnedPublicKeyHex: pinnedKeyHex(configDirectory: configDirectory))
    }

    /// The key the OPERATOR placed beside the configuration — never one the profile names about itself.
    private static func pinnedKeyHex(configDirectory: URL) -> String {
        let url = configDirectory.appendingPathComponent("profile_signing_key.txt")
        guard let raw = try? String(contentsOf: url, encoding: .utf8) else { return "" }
        return raw.trimmingCharacters(in: .whitespacesAndNewlines)
    }
}

private extension String {
    var nonEmpty: String? { isEmpty ? nil : self }
}
