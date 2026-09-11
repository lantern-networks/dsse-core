import Foundation
import CryptoKit
import Security

// Where a device keeps the anchors it adopted from a signed trust bundle, and the serial it adopted them at.
//
// The provisioned anchor file is what a device is born with. It stops being current the moment the fleet rotates
// past it, and a device that was switched off through the rotation cannot be told — that is the deadlock this
// whole area exists to remove. Cross-signing keeps the provisioned anchor working for the overlap; the bundle is
// how a device catches up on its own, and this is where the result is written down so it survives a restart.
//
// The adopted set REPLACES the provisioned one rather than adding to it. That is deliberate and is the only way
// an anchor can ever be WITHDRAWN: a union could only widen what the device accepts, so a compromised CA would
// stay trusted forever. It is safe to be authoritative here because nothing reaches this store unverified — the
// bundle was signed by the pinned key and its serial had to advance — and because a device that somehow ends up
// with an unusable set can re-fetch the bundle over a channel it does not need to authenticate.
//
// The serial is the point of persisting anything at all. Replay protection is a comparison against the highest
// bundle this device has ever accepted; if that number is forgotten on restart, an old bundle becomes acceptable
// again and a withdrawn CA can be restored.

public struct DsseAdoptedTrustAnchors: Sendable, Equatable {
    public let serial: Int64
    public let fingerprints: [String]
    public let adoptedAt: String
}

public enum DsseAdoptedTrustAnchorStore {
    public static let anchorsFileName = "trust_anchors_adopted.pem"
    public static let pointerFileName = "trust_anchor_pointer.json"

    private struct Pointer: Codable {
        let serial: Int64
        let fingerprints: [String]
        let adoptedAt: String
        /// The interception roots the Edge said it signs under, kept so the agent can look for them in this
        /// machine's trust store on every report rather than only at the moment a bundle arrives.
        let interceptionRootSHA256: [String]?
        /// The policy-signing keys the Edge advertised. Kept so the key in force can change without every
        /// device having to be re-provisioned — the overlap that makes this key rotatable at all.
        let agentPolicyPublicKeys: [String]?
        /// The name this organization's devices should send as the TLS server name. Kept here, beside the
        /// anchors it belongs with: the name and the certificate it selects are one fact, and storing them
        /// apart is how a device ends up asking for a certificate it cannot verify.
        let transportServerName: String?
        /// The name that reaches the expired-certificate renewal path on the main port, once the agent plane is
        /// folded onto one. Kept with the rest: a device recovering from expiry is a device that cannot ask.
        let renewalRecoverySNI: String?
        /// ★★★ WHOSE DEPLOYMENT THIS WAS ADOPTED FROM (2026-08-29, measured on a real Mac). Everything else in
        /// this pointer is meaningless without it. This store is authoritative — the adopted set REPLACES the
        /// provisioned one — so a device re-installed onto a DIFFERENT deployment carried the previous one's
        /// anchors and the previous one's announced name straight through the install, and they beat the anchor
        /// the installer had just placed. The Edge said so plainly and nobody was reading its log:
        ///
        ///	transport_server_name: a device asked for "44paeq….dsse.invalid", which this node does not serve
        ///	door=agent-plane http: TLS handshake error: remote error: tls: unknown certificate
        ///
        /// A fresh, correct install of the current product, refused by the deployment it was installed for,
        /// with every field of its configuration right.
        let tenantID: String?
        enum CodingKeys: String, CodingKey {
            case serial
            case fingerprints
            case adoptedAt = "adopted_at"
            case interceptionRootSHA256 = "interception_root_sha256"
            case agentPolicyPublicKeys = "agent_policy_public_keys"
            case transportServerName = "transport_server_name"
            case renewalRecoverySNI = "renewal_recovery_sni"
            case tenantID = "tenant_id"
        }
    }

    /// lastAcceptedSerial is what must be passed back to verification. 0 when this device has never adopted a
    /// bundle — never treat an unreadable pointer as "no restriction", which is why a parse failure also
    /// returns 0 only after the anchors themselves are ignored (see currentAnchors).
    public static func lastAcceptedSerial(configDirectory: URL) -> Int64 {
        guard let p = readPointer(configDirectory: configDirectory) else { return 0 }
        return p.serial
    }

    public static func current(configDirectory: URL) -> DsseAdoptedTrustAnchors? {
        guard let p = readPointer(configDirectory: configDirectory) else { return nil }
        return DsseAdoptedTrustAnchors(serial: p.serial, fingerprints: p.fingerprints, adoptedAt: p.adoptedAt)
    }

    /// currentAnchors returns the adopted anchors, or nil when there are none to use.
    ///
    /// Returns nil — not an empty array — when the pointer exists but the anchor file is missing or yields
    /// nothing usable. An empty array at the call site is indistinguishable from "trust nothing" and would make
    /// the transport fail closed forever; nil means "I have nothing adopted", and the caller falls back to the
    /// provisioned anchors, which is the state the device was working in before.
    /// advertisedInterceptionRoots is what the Edge last said it signs intercepted traffic under. Empty when
    /// no bundle has been adopted or the deployment did not say — which the Edge reads as "not reported",
    /// never as "trusts none".
    public static func advertisedInterceptionRoots(configDirectory: URL) -> [String] {
        readPointer(configDirectory: configDirectory)?.interceptionRootSHA256 ?? []
    }

    /// acceptedAgentPolicyKeys is the set of policy-signing keys the Edge advertised in the last bundle this
    /// device ADOPTED — verified against the key in force at the time, so its provenance is established
    /// before any of it is trusted. Empty when nothing was said, and the caller then uses only its
    /// provisioned pin, which is exactly the behaviour that existed before this list did.
    /// advertisedTransportServerName is the name the last adopted bundle told this device to send, or "" when
    /// it named none.
    ///
    /// ★ ONLY WHAT WAS ADOPTED. A device that invented a name would ask for a certificate nobody serves, and a
    /// device that read it from an unverified document would let whoever served that document choose which
    /// certificate it is shown — which is the whole reason this rides in the SIGNED bundle.
    public static func advertisedTransportServerName(configDirectory: URL) -> String {
        guard let pointer = readPointer(configDirectory: configDirectory) else { return "" }
        return (pointer.transportServerName ?? "").trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    }

    /// advertisedRenewalRecoverySNI is the name the last adopted bundle said reaches the expired-certificate
    /// renewal path on the main transport port, or "" when it named none.
    public static func advertisedRenewalRecoverySNI(configDirectory: URL) -> String {
        guard let pointer = readPointer(configDirectory: configDirectory) else { return "" }
        return (pointer.renewalRecoverySNI ?? "").trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    }

    public static func acceptedAgentPolicyKeys(configDirectory: URL) -> [String] {
        readPointer(configDirectory: configDirectory)?.agentPolicyPublicKeys ?? []
    }

    public static func currentAnchors(configDirectory: URL) -> [SecCertificate]? {
        guard let pointer = readPointer(configDirectory: configDirectory) else { return nil }
        let url = configDirectory.appendingPathComponent(anchorsFileName)
        guard let pem = try? String(contentsOf: url, encoding: .utf8) else { return nil }
        let anchors = DsseSignedTrustBundle.parseAnchors(pem)
        if anchors.isEmpty { return nil }
        // Torn-write guard. The anchors are written FIRST and the pointer SECOND, so a crash during a
        // RE-adoption can leave the NEW anchors file beside the STILL-OLD pointer/serial. The stated guarantee —
        // "a crash leaves the device on its provisioned anchors" — holds only for the very first adoption (no
        // prior pointer); on a re-adoption the torn pair would otherwise be served as the new anchors under the
        // OLD serial. Because the adopted set REPLACES the provisioned one, that rolls the monotonic replay guard
        // back and a withdrawn CA at an intermediate serial could be re-adopted until the next recovery
        // self-heals. The pointer records the fingerprints it was committed WITH, so a file that does not match
        // them is exactly that torn pair: read it as "nothing adopted" and fall back to the provisioned anchors —
        // the safe state the write order intends. Skipped for a pre-fingerprint pointer, which cannot be checked.
        if !pointer.fingerprints.isEmpty && !anchorsMatchFingerprints(anchors, pointer.fingerprints) {
            return nil
        }
        return anchors
    }

    /// anchorsMatchFingerprints reports whether the anchor set on disk is EXACTLY the set the pointer was
    /// committed with (compared as a set of SHA-256 fingerprints). A mismatch means the anchors file and the
    /// pointer are from different adoptions — a torn two-file write — and must not be trusted as a consistent pair.
    private static func anchorsMatchFingerprints(_ anchors: [SecCertificate], _ want: [String]) -> Bool {
        let have = Set(anchors.map { fingerprint($0).lowercased() })
        let wantSet = Set(want
            .map { $0.lowercased().trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty })
        return have == wantSet
    }

    /// install writes a verified bundle's anchors. Refuses anything that would leave the device worse off than
    /// it is now: an unusable anchor set, or a serial that does not advance.
    @discardableResult
    public static func install(_ bundle: DsseVerifiedTrustBundle, configDirectory: URL,
                               now: Date = Date()) throws -> DsseAdoptedTrustAnchors {
        let anchors = DsseSignedTrustBundle.parseAnchors(bundle.anchorsPEM)
        guard !anchors.isEmpty else {
            throw DsseAdoptedTrustAnchorStoreError.noUsableAnchors
        }
        let previous = lastAcceptedSerial(configDirectory: configDirectory)
        guard bundle.serial > previous else {
            throw DsseAdoptedTrustAnchorStoreError.serialDoesNotAdvance(bundle.serial, previous)
        }
        let fingerprints = anchors.map { fingerprint($0) }

        // Anchors first, pointer second. The pointer is what makes the anchors live, so a crash between the two
        // leaves a device using its provisioned anchors — the state it was already working in — rather than
        // pointing at a file that is not there yet.
        let anchorsURL = configDirectory.appendingPathComponent(anchorsFileName)
        try writeAtomically(Data(bundle.anchorsPEM.utf8), to: anchorsURL)

        let pointer = Pointer(serial: bundle.serial, fingerprints: fingerprints,
                              adoptedAt: ISO8601DateFormatter().string(from: now),
                              interceptionRootSHA256: bundle.interceptionRootSHA256,
                              agentPolicyPublicKeys: bundle.agentPolicyPublicKeys,
                              transportServerName: bundle.transportServerName.isEmpty ? nil : bundle.transportServerName,
                              renewalRecoverySNI: bundle.renewalRecoverySNI.isEmpty ? nil : bundle.renewalRecoverySNI,
                              tenantID: bundle.tenantID.isEmpty ? nil : bundle.tenantID)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try writeAtomically(try encoder.encode(pointer), to: configDirectory.appendingPathComponent(pointerFileName))

        return DsseAdoptedTrustAnchors(serial: pointer.serial, fingerprints: pointer.fingerprints, adoptedAt: pointer.adoptedAt)
    }

    /// Which deployment this device is installed FOR, read from the profile in force. nil when there is no
    /// profile to ask — a pre-profile deployment, where this check cannot be made and must not be invented.
    static func tenantInForce(configDirectory: URL) -> String? {
        DsseAdoptedTenantScope.tenantInForce(configDirectory: configDirectory)
    }

    public static func fingerprint(_ cert: SecCertificate) -> String {
        let der = SecCertificateCopyData(cert) as Data
        return sha256Hex(der)
    }

    private static func readPointer(configDirectory: URL) -> Pointer? {
        let url = configDirectory.appendingPathComponent(pointerFileName)
        guard let data = try? Data(contentsOf: url),
              let p = try? JSONDecoder().decode(Pointer.self, from: data),
              p.serial > 0 else {
            return nil
        }
        // ★★★ ADOPTED FROM ANOTHER DEPLOYMENT IS NOT ADOPTED (2026-08-29). See Pointer.tenantID. Everything
        // this store answers — the anchors, the name to send, the interception roots, the policy keys — belongs
        // to ONE deployment, and this store outranks what the installer placed. So a pointer whose deployment
        // is not the one in force is discarded whole; the device falls back to its provisioned anchors, which
        // is exactly the state a fresh install intends.
        //
        // TWO pieces of evidence, because one of them does not reach the devices that already have the problem:
        // the tenant is only on pointers written from now on, while the NAME is on every pointer that has ever
        // been written. Either one differing is proof this material belongs elsewhere.
        if let reason = adoptedElsewhere(p, configDirectory: configDirectory) {
            dsseRuntimeLog("transport_trust adopted_anchors DISCARDED — \(reason). Falling back to the anchors " +
                           "the installer placed. A device carrying another deployment's anchors asks for a " +
                           "name this deployment does not serve and is refused at every door.")
            return nil
        }
        return p
    }

    /// Why this pointer belongs to another deployment, or nil when nothing on this disk says it does.
    ///
    /// Positive evidence only. "This pointer does not name a deployment" is not evidence — treating it as such
    /// would discard the anchors of every working device in the fleet, roll the replay guard back to 0 and let
    /// a withdrawn CA be adopted again.
    private static func adoptedElsewhere(_ p: Pointer, configDirectory: URL) -> String? {
        let adoptedFor = p.tenantID?.trimmingCharacters(in: .whitespacesAndNewlines)
        let installed = DsseAdoptedTenantScope.tenantInForce(configDirectory: configDirectory)
        if let adoptedFor, !adoptedFor.isEmpty, let installed {
            // The tenant SETTLES it, in both directions. Same deployment and a different name is a RENAME —
            // this device's adopted anchors are still its own, and discarding them would roll the replay guard
            // back to 0 over a name the profile already corrects.
            guard adoptedFor != installed else { return nil }
            return "this device adopted them for \(adoptedFor) and is installed for \(installed)"
        }
        if let adoptedName = p.transportServerName?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased(),
           !adoptedName.isEmpty,
           let served = DsseAdoptedTenantScope.transportServerNameInForce(configDirectory: configDirectory),
           adoptedName != served {
            return "this device would ask for \(adoptedName) and the deployment it is installed for serves \(served)"
        }
        return nil
    }

    private static func writeAtomically(_ data: Data, to url: URL) throws {
        let tmp = url.deletingLastPathComponent()
            .appendingPathComponent("." + url.lastPathComponent + ".tmp")
        try data.write(to: tmp, options: .atomic)
        // 0644: the anchors are public certificates and the pointer names only fingerprints. Readable is fine;
        // writable by anyone is not, which is what the explicit mode pins.
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: tmp.path)
        _ = try FileManager.default.replaceItemAt(url, withItemAt: tmp)
    }

    private static func sha256Hex(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}

public enum DsseAdoptedTrustAnchorStoreError: Error, Equatable {
    case noUsableAnchors
    case serialDoesNotAdvance(Int64, Int64)
}
