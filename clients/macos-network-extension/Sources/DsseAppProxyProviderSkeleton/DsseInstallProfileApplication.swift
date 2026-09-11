import Foundation
import DsseNetworkExtensionContract

// Where the deployment's signed install profile actually reaches this Mac.
//
// ★★★ THE MODULE THAT VERIFIES THE PROFILE HAD NO CALLER (2026-08-28, found by walking the documented install
// lane on a two-region deployment). `DsseSignedInstallProfile` was added on 2026-08-27 to close the gap its own
// header names — Windows applies `dsse_install_profile.v1`, macOS read a hand-placed `agent_config.json` — and
// it verifies, type-checks and anti-rollbacks correctly. Nothing called it. An administrator could download the
// profile from the Console's "Device configuration" screen, place it on a Mac, and the Mac would go on dialling
// whatever the local file said, with no log line saying the profile was ignored, because nothing had opened it.
//
// A verifier with no call site is the failure mode this project has hit in Go and has now hit in Swift: the
// language does not object, the tests of the helper pass, and the screen that hands out the artefact keeps
// working. So this file is the caller, and every decision it makes is logged by name.
//
// ★★ IT NARROWS ONE THING AND WIDENS NOTHING BY ACCIDENT. The profile decides WHERE this device connects and
// HOW it behaves when it cannot. It never supplies credentials, never names an anchor to trust, and never
// removes an exclusion the local configuration installed for loop prevention — the list that keeps the session
// doing the installing alive. Everything it cannot decide is left exactly as agent_config.json had it.
//
// ★ FAIL-CLOSED, LIKE EVERY OTHER READER HERE: any failure leaves the device on what it already had.
public enum DsseInstallProfileApplication {
    /// The name the Console's download is expected to carry once it is placed. Named rather than guessed at
    /// each call site so the installer, the MDM payload and this reader cannot drift apart.
    public static let defaultFileName = "install_profile.json"

    /// The stamp of the newest profile this device has APPLIED. Anti-rollback needs to survive a restart, or
    /// the rule is only enforced for as long as the process that learned it stays up — and replacing a file on
    /// a machine you can reboot would be the way around it.
    static let appliedStampFileName = "applied_install_profile.json"

    /// The keys this reader needs out of agent_config.json: the pin that decides whether a profile is genuine,
    /// and (optionally) where the profile file is. Both live in the root-owned file for the reason its own
    /// comments give — a document cannot carry the key that proves it.
    private struct AgentConfigProfileKeys: Decodable {
        let pinnedPublicKey: String?
        let signedPath: String?

        enum CodingKeys: String, CodingKey {
            case pinnedPublicKey = "network_extension_agent_policy_signing_public_key"
            case signedPath = "network_extension_install_profile_signed_path"
        }
    }

    private struct AppliedStamp: Codable {
        let issuedAt: String
        enum CodingKeys: String, CodingKey { case issuedAt = "issued_at" }
    }

    /// inForce returns the profile this device should be governed by right now, or nil when there is none it
    /// may apply. Every nil is logged with which of the reasons it was.
    ///
    /// - Parameters:
    ///   - agentConfigPath: the root-owned configuration this device was installed with. nil means the caller
    ///     does not know it, which is not an error — it means no profile can be resolved, and it says so.
    ///   - configDirectory: where the profile and the applied stamp live.
    public static func inForce(agentConfigPath: String?, configDirectory: URL,
                               log: ((String) -> Void)? = nil) -> DsseInstallProfile? {
        guard let agentConfigPath = agentConfigPath?.trimmingCharacters(in: .whitespacesAndNewlines),
              !agentConfigPath.isEmpty,
              let configData = try? Data(contentsOf: URL(fileURLWithPath: agentConfigPath)) else {
            return nil
        }
        let keys = try? JSONDecoder().decode(AgentConfigProfileKeys.self, from: configData)
        let pin = keys?.pinnedPublicKey?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        let path = profilePath(configured: keys?.signedPath, configDirectory: configDirectory)
        guard FileManager.default.fileExists(atPath: path) else {
            // The ordinary state of a deployment that has not issued one. Silent on purpose: a line every
            // startup for a file nobody placed is noise that trains an operator to skip this subsystem.
            return nil
        }
        guard !pin.isEmpty else {
            // A profile IS present and cannot be judged. That is worth saying loudly: an operator who placed
            // the file has every reason to believe it took effect.
            log?("install_profile ignored=no_pin path=\(path) — the deployment's profile is on this Mac and " +
                 "agent_config.json names no network_extension_agent_policy_signing_public_key to verify it " +
                 "against, so it cannot be applied")
            return nil
        }
        guard let profile = DsseSignedInstallProfile.verifiedProfile(signedPath: path, pinnedPublicKeyHex: pin) else {
            log?("install_profile REFUSED path=\(path) — it does not verify against the pinned signing key, is " +
                 "not an install profile, or does not decode. The device keeps the configuration it had")
            return nil
        }
        let applied = readAppliedStamp(configDirectory: configDirectory)
        guard DsseSignedInstallProfile.accepts(applied: applied, candidate: profile.issuedAt) else {
            log?("install_profile REFUSED=rollback path=\(path) applied_issued_at=\(applied ?? "-") " +
                 "candidate_issued_at=\(profile.issuedAt ?? "-") — a profile older than the one in force is a " +
                 "downgrade, and stripping the stamp is the same downgrade")
            return nil
        }
        recordApplied(issuedAt: profile.issuedAt, configDirectory: configDirectory)
        log?("install_profile applied path=\(path) tenant=\(profile.tenantID) issued_at=\(profile.issuedAt ?? "-") " +
             "transport_url=\(profile.transportURL) endpoints=\(profile.transportEndpoints?.count ?? 0) " +
             "posture=\(profile.posture ?? "-") ack_failopen=\(profile.ackFailOpen.map(String.init) ?? "-")")
        return profile
    }

    /// profilePath resolves where the profile is: what agent_config.json names, relative to the configuration
    /// directory when it is not absolute, else the conventional name beside the configuration.
    static func profilePath(configured: String?, configDirectory: URL) -> String {
        let named = configured?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        if named.isEmpty {
            return configDirectory.appendingPathComponent(defaultFileName).path
        }
        if named.hasPrefix("/") { return named }
        return URL(fileURLWithPath: named, relativeTo: configDirectory).path
    }

    /// applyTransport puts the profile's door on top of the contract the local file holds — the address, and
    /// nothing else.
    ///
    /// ★★★ ONLY THE URL. The contract also carries how this device proves itself (the keychain selector, the
    /// P12 refs) and which anchor it pins the Edge against. Those are properties of THIS machine and of what it
    /// was installed with; a document that could rewrite them would be a document that can re-point a device at
    /// an authority of its author's choosing. The profile says where to go, not who to trust on arrival.
    public static func applyTransport(to contract: DsseTransportContract?, profile: DsseInstallProfile?)
        -> DsseTransportContract? {
        guard let profile else { return contract }
        let url = profile.transportURL.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !url.isEmpty else { return contract }
        guard let contract else {
            // A deployment that issued a profile to a machine whose local file names no transport at all. The
            // profile is the whole contract in that case, which is the direction this is moving in.
            return DsseTransportContract(transportTLSURL: url, mtlsRequired: true, dnsOverTunnelPath: nil,
                                         dnsOverTunnelSupported: nil, pinnedCARef: nil,
                                         clientIdentityP12Ref: nil, clientIdentityP12PassRef: nil,
                                         clientIdentityCommonName: nil, renewalRecoveryEndpoint: nil)
        }
        return contract.withTransportTLSURL(url)
    }

    /// regionSeed is the door list a device tries before any Edge has answered — the profile's own ordering.
    /// Once an Edge answers, its SIGNED region list governs and this is replaced; a local file can reorder
    /// what the deployment allowed but can never add to it.
    public static func regionSeed(profile: DsseInstallProfile?) -> [DsseRegionEndpoint] {
        guard let entries = profile?.transportEndpoints, !entries.isEmpty else { return [] }
        var seeded: [DsseRegionEndpoint] = []
        for (index, entry) in entries.enumerated() {
            // "region-a=https://…" — the format the deployment's own DSSE_REGION_ENDPOINTS uses.
            let parts = entry.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            guard parts.count == 2 else { continue }
            let region = parts[0].trimmingCharacters(in: .whitespacesAndNewlines)
            let endpoint = parts[1].trimmingCharacters(in: .whitespacesAndNewlines)
            guard !region.isEmpty, !endpoint.isEmpty else { continue }
            // Earlier in the list is preferred. The poller's ranking uses a HIGHER number as more preferred,
            // so the order is inverted here rather than at the call site.
            seeded.append(DsseRegionEndpoint(region: region, endpoint: endpoint, priority: entries.count - index))
        }
        return seeded
    }

    /// failOpenOverride is what the deployment says about carrying traffic when no Edge can be reached.
    ///
    /// ★★ FAIL-CLOSED IS ENFORCED, FAIL-OPEN IS ONLY EVER PERMITTED. A profile saying fail-closed DISARMS a
    /// local acknowledgement, because the deployment's posture must not be widenable by editing a file on the
    /// device. A profile saying fail-open does not arm anything on its own — it removes the deployment's
    /// objection, and the device still needs its own acknowledgement, which is the property that keeps
    /// "someone shipped a profile" from being enough to take a fleet out of enforcement.
    /// Returns nil when the profile says nothing and the local posture stands unchanged.
    public static func failOpenOverride(profile: DsseInstallProfile?) -> Bool? {
        guard let posture = profile?.posture?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased(),
              !posture.isEmpty else {
            return nil
        }
        switch posture {
        case "fail-closed", "failclosed", "closed":
            return false
        case "fail-open", "failopen", "open":
            return profile?.ackFailOpen == true ? nil : false
        default:
            return nil
        }
    }

    // MARK: - the applied stamp

    static func readAppliedStamp(configDirectory: URL) -> String? {
        let url = configDirectory.appendingPathComponent(appliedStampFileName)
        guard let data = try? Data(contentsOf: url),
              let stamp = try? JSONDecoder().decode(AppliedStamp.self, from: data) else {
            return nil
        }
        let trimmed = stamp.issuedAt.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }

    static func recordApplied(issuedAt: String?, configDirectory: URL) {
        guard let issuedAt = issuedAt?.trimmingCharacters(in: .whitespacesAndNewlines), !issuedAt.isEmpty else {
            // An unstamped profile is applied but records nothing: writing an empty stamp would make every
            // later profile look like a rollback.
            return
        }
        guard let data = try? JSONEncoder().encode(AppliedStamp(issuedAt: issuedAt)) else { return }
        try? data.write(to: configDirectory.appendingPathComponent(appliedStampFileName), options: .atomic)
    }
}
