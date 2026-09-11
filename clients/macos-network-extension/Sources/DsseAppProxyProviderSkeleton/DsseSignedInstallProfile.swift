import Foundation

// The deployment's SIGNED install seed, on macOS.
//
// ★★★ THE TWO PLATFORMS OF ONE DEPLOYMENT HAD DIFFERENT CONFIGURATION CONTRACTS (2026-08-27, measured while
// putting an agent on a Mac). Windows applies `dsse_install_profile.v1` — the CP/tenant-authored document the
// deployment SIGNS — and refuses one that is unsigned, wrong-key, wrong-type or older than what it already
// holds. macOS read a plain `agent_config.json` that a person placed with `sudo cp`: no signature, no issuer,
// no ordering. Its only protection was file ownership.
//
// That difference is not a platform limitation. This module already verifies three signed documents from the
// same issuer with the same crypto — the steer policy, the update manifest and the update plan — so what was
// missing is the TYPE, not the mechanism.
//
// ★★ WHAT agent_config.json IS FOR AFTER THIS, and why it does not simply disappear: it carries the PIN. A
// document cannot carry the key that proves it, so the root of trust has to arrive some other way — baked
// into the MSI on Windows, and here a root-owned file placed by MDM or by an operator. Everything the
// deployment decides moves into the signed profile; what stays behind is the one thing that cannot be signed.
//
// ★ FAIL-CLOSED, LIKE EVERY OTHER READER HERE. Any failure returns nil and the caller keeps what it had.
// A profile that does not verify must never be the reason a device widens its posture.

/// The fields of `dsse_install_profile.v1` this platform acts on. The document carries more — the Windows
/// backend, the WFP start mode — and a field this platform does not implement is ignored rather than
/// treated as an error: one document, and each platform applies the part it can.
public struct DsseInstallProfile: Decodable, Equatable {
    public let kind: String
    public let version: Int
    /// When the issuer signed it. The ordering key that makes an older profile refusable — and it is inside
    /// the payload, so it is covered by the signature rather than being a stamp an attacker can write.
    public let issuedAt: String?
    public let tenantID: String
    public let groupID: String?
    /// Where flows go.
    public let transportURL: String
    /// The other regions' doors, in the order this device should prefer them.
    public let transportEndpoints: [String]?
    /// The pinned CA FINGERPRINT — not a path. A path is a place something else can write; a fingerprint is
    /// the answer itself.
    public let transportAnchor: String?
    /// The names this organization's devices present. See Organization.
    public let organization: Organization?
    /// The name this device presents on the transport dial. The plane it is asking for, which is not the
    /// same question as the address it dials.
    public var transportServerName: String? { organization?.transportServerName }
    public var enrolmentServerName: String? { organization?.enrolmentServerName }
    public var renewalRecoveryServerName: String? { organization?.renewalRecoveryServerName }
    public let posture: String?
    public let ackFailOpen: Bool?
    /// The apps whose flows are not steered. Authoritative: a locally-edited list does not widen this.
    public let bypassApps: [String]?
    public let bypassDests: [String]?
    public let regionPriority: [String: Int]?
    public let enrolment: Enrolment?
    /// What the device must be TOLD about the deployment it is joining. See Deployment.
    public let deployment: Deployment?

    /// ★★★ THE NAMES LIVE UNDER `organization`, AND THIS FILE READ THEM AT THE TOP LEVEL (2026-08-28, found
    /// by asking why a Mac dials the shared name). The producer nests them — Go's InstallProfile.Organization,
    /// which is also where the Windows agent reads them from — so these three keys matched nothing this
    /// deployment has ever emitted, and would have gone on matching nothing however carefully they were
    /// filled in. The same "two platforms of one deployment, two contracts" this file's own header was written
    /// about, one level further down and inside the fix for it.
    ///
    /// The old spelling is NOT kept as a fallback: nothing produces it, so accepting it would only preserve a
    /// second shape for the next reader to guess between.
    public struct Organization: Decodable, Equatable {
        /// Stated for the operator reading the profile and cross-checked against the profile's own tenant; it
        /// is never sent in a ClientHello.
        public let tenantID: String?
        /// The name presented on the (T) transport dial. The Edge selects an organization's certificate by
        /// SNI — it must, the server's certificate goes out before the client's arrives — so a device with no
        /// name to send is served the deployment's shared one.
        public let transportServerName: String?
        /// The name presented when enrolling, which on a folded port SELECTS the enrolment route.
        public let enrolmentServerName: String?
        /// The selector for the expired-certificate recovery path. Empty on deployments that announce it in
        /// the trust bundle instead.
        public let renewalRecoveryServerName: String?

        enum CodingKeys: String, CodingKey {
            case tenantID = "tenant_id"
            case transportServerName = "transport_server_name"
            case enrolmentServerName = "enrolment_server_name"
            case renewalRecoveryServerName = "renewal_recovery_server_name"
        }
    }

    /// ★★★ EVERYTHING THE DEVICE COULD NOT LEARN FROM THE DEPLOYMENT BECAUSE IT HAS NOT JOINED IT YET
    /// (2026-08-29). A customer receives a package, this profile, and a one-time token — and until now that
    /// was not enough: the device also needed an agent_config.json holding the anchor, the organization's
    /// device-CA pin, its interception root and the update pins, and nothing in the product produced that
    /// file. The lab wrote it by hand with a script no customer receives.
    ///
    /// None of these is a secret. The one-time token is, which is why it is not here.
    public struct Deployment: Decodable, Equatable {
        /// The root every Edge is verified against. Not the system trust store: this authority is not a
        /// public CA and must not be reachable by anything that trusts one.
        public let anchorPEM: String?
        /// The authority that signs THIS organization's device identities, so a device that reaches the wrong
        /// enrol endpoint refuses the certificate it is handed rather than adopting it.
        public let deviceCAPinSHA256: String?
        /// The organization's own inspection root. Putting it where the operating system looks is an act only
        /// the operating system can perform; carrying it to the machine is not.
        public let interceptionRootPEM: String?
        /// The authority the step-up portal is served under, when this deployment's portal is on a certificate
        /// it issued itself rather than one the operator supplied.
        ///
        /// ★★★ THE WINDOW USED TO CARRY A LIST OF HOSTS INSTEAD (2026-09-03). Two of them, hard-coded in the
        /// shipped app — 203.0.113.10 and kc.dsse.lab, addresses of a lab that no longer exists — and for
        /// those hosts it accepted ANY certificate without verification. A private address that common, in a
        /// signed product, is a blanket bypass waiting for somebody to reuse the address.
        ///
        /// The deployment knows which authority serves its own portal; a device should not be guessing from
        /// hostnames. Empty means the portal is on something the system already trusts, which is the case
        /// whenever the operator supplied its certificate — and then there is nothing here to do.
        public let stepUpPortalAnchorPEM: String?
        /// The key this profile is signed under — stated so a device that has none yet can adopt it at
        /// install time, and so a device that has one can refuse a profile signed by a different authority.
        public let agentPolicySigningPublicKey: String?
        public let updateSigningKeys: [String]?
        public let updatePublisherTeamID: String?
        /// The identifiers this deployment has AUTHORED as never-steered. This product ships none built in, so
        /// this is the whole list — and an empty one is an answer, not a gap.
        public let steerExclusions: [String]?
        public let passthroughDomains: [String]?

        enum CodingKeys: String, CodingKey {
            case anchorPEM = "anchor_pem"
            case deviceCAPinSHA256 = "device_ca_pin_sha256"
            case interceptionRootPEM = "interception_root_pem"
            case stepUpPortalAnchorPEM = "step_up_portal_anchor_pem"
            case agentPolicySigningPublicKey = "agent_policy_signing_public_key"
            case updateSigningKeys = "update_signing_keys"
            case updatePublisherTeamID = "update_publisher_team_id"
            case steerExclusions = "steer_exclusions"
            case passthroughDomains = "passthrough_domains"
        }
    }

    public struct Enrolment: Decodable, Equatable {
        public let mode: String
        public let tokenRef: String?

        enum CodingKeys: String, CodingKey {
            case mode
            case tokenRef = "token_ref"
        }
    }

    enum CodingKeys: String, CodingKey {
        case kind
        case version
        case issuedAt = "issued_at"
        case tenantID = "tenant_id"
        case groupID = "group_id"
        case transportURL = "transport_url"
        case transportEndpoints = "transport_endpoints"
        case transportAnchor = "transport_anchor"
        case organization
        case posture
        case ackFailOpen = "ack_failopen"
        case bypassApps = "bypass_apps"
        case bypassDests = "bypass_dests"
        case regionPriority = "region_priority"
        case enrolment
        case deployment
    }
}

public enum DsseSignedInstallProfile {
    /// The document kind. It rides the same envelope and the same key as the steer policy; only the type
    /// separates them, which is why `verifiedPayloadBytes` takes the type as a required argument.
    public static let envelopeType = "dsse_install_profile.v1"

    /// verifiedProfile returns the profile ONLY when the file verifies against a key this device trusts and
    /// declares itself to be an install profile. Missing file, bad checksum, forged signature, wrong type or
    /// a payload that does not decode all return nil.
    /// ★★★ ONE KEY, AND NOT THE ADOPTED SET. Every other signed document here verifies against the pin PLUS
    /// keys this device adopted at runtime, so the signing key can rotate. The install profile must not: it is
    /// what establishes this agent's configuration, so a key learned from a store or a bundle deciding what
    /// the agent installs itself as would let a value the profile is supposed to authorise turn around and
    /// authorise the profile. The Go side says the same thing in the same words (installprofile.Load).
    public static func verifiedProfile(signedPath: String, pinnedPublicKeyHex: String) -> DsseInstallProfile? {
        let path = signedPath.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !path.isEmpty, let data = try? Data(contentsOf: URL(fileURLWithPath: path)) else {
            return nil
        }
        return verifiedProfile(envelopeData: data, pinnedPublicKeyHex: pinnedPublicKeyHex)
    }

    public static func verifiedProfile(envelopeData: Data, pinnedPublicKeyHex: String) -> DsseInstallProfile? {
        // ★ EITHER ENVELOPE TYPE, AND THE PAYLOAD KIND ALWAYS. Profiles issued before the envelope carried its
        // own type are signed with the steer-policy type and are told apart only by the kind below; refusing
        // them would strand deployed agents to fix a labelling problem. The kind is what actually prevents a
        // validly-signed document of another sort being applied as a profile.
        let raw = DsseSignedAgentPolicy.verifiedPayloadBytes(
                envelopeData: envelopeData, expectedType: envelopeType, pinnedPublicKeyHex: pinnedPublicKeyHex)
            ?? DsseSignedAgentPolicy.verifiedPayloadBytes(
                envelopeData: envelopeData, expectedType: DsseSignedAgentPolicy.envelopeType,
                pinnedPublicKeyHex: pinnedPublicKeyHex)
        guard let raw, let profile = try? JSONDecoder().decode(DsseInstallProfile.self, from: raw) else {
            return nil
        }
        guard profile.kind == envelopeType else { return nil }
        return profile
    }

    /// accepts answers whether `candidate` may replace `applied`, which is the anti-rollback rule.
    ///
    /// ★★★ AN ANTI-ROLLBACK THAT NEVER REFUSES ANYTHING IS NOT ONE. Two profiles are compared only when BOTH
    /// carry a stamp — a deployment that issued profiles before the field existed must keep working — but a
    /// device that HAS seen a stamp will not take an unstamped successor, because that is the downgrade the
    /// rule exists to stop: strip the field and the comparison disappears with it.
    public static func accepts(applied: String?, candidate: String?) -> Bool {
        let have = (applied ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        let want = (candidate ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        if have.isEmpty { return true }
        if want.isEmpty { return false }
        guard let haveAt = DsseSignedInstallProfile.timestamp(have),
              let wantAt = DsseSignedInstallProfile.timestamp(want) else {
            // A stamp that cannot be read is not newer than one that can.
            return false
        }
        return wantAt >= haveAt
    }

    private static func timestamp(_ s: String) -> Date? {
        let withFraction = ISO8601DateFormatter()
        withFraction.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let d = withFraction.date(from: s) { return d }
        return ISO8601DateFormatter().date(from: s)
    }
}
