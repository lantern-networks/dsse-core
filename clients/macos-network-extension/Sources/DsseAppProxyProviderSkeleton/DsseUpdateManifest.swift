import Foundation

// DsseUpdateManifest — the macOS half of the signed statement "version V of the agent is these exact bytes".
//
// ★ WHY THIS FILE EXISTS AT ALL, and it is a correction rather than a new feature. The Step 1 design said the
// Swift verifier could be REUSED for update manifests because they ride the same envelope. That was almost
// true and the gap was recorded as OUTSTANDING: DsseSignedAgentPolicy hardcoded
// `env.type == "dsse_agent_steer_policy.v1"`, so an update manifest could not be verified on this platform at
// all. "The verifier can be reused" and "the same crypto plus one type constant" are different claims, and
// only the second one was ever true.
//
// ★ THE TYPE CHECK IS THE SECURITY PROPERTY, not the parsing convenience. The same key may legitimately sign
// several documents on this surface, and the signature check is pure crypto that does not look at what kind of
// document it is. Without the type, a validly-signed steer policy is a validly-signed update manifest — a
// substitution that every cryptographic check passes. That is why verifiedPayloadBytes takes the expected type
// as a REQUIRED argument and why the test below asserts the cross-type refusal explicitly.
//
// The key that signs THIS document is not the agent-policy key. The Go side enforces the separation (an Edge
// can mint a policy and cannot mint a manifest); this file only verifies, so what it needs is the caller
// passing the right pin. Passing the agent-policy pin here would fail, which is the correct outcome and is
// worth knowing before someone "fixes" it by widening the accepted set.

public struct DsseUpdateManifestPayload: Codable, Equatable {
    public let schema: String
    public let version: String
    public let platform: String
    public let arch: String
    public let channel: String
    public let delivery: String
    public let artifactKind: String
    public let artifactURL: String
    public let artifactSHA256: String
    public let artifactSize: Int64
    public let minFromVersion: String
    public let releasedAt: String
    public let notAfter: String

    enum CodingKeys: String, CodingKey {
        case schema
        case version
        case platform
        case arch
        case channel
        case delivery
        case artifactKind = "artifact_kind"
        case artifactURL = "artifact_url"
        case artifactSHA256 = "artifact_sha256"
        case artifactSize = "artifact_size"
        case minFromVersion = "min_from_version"
        case releasedAt = "released_at"
        case notAfter = "not_after"
    }
}

public enum DsseUpdateManifest {
    /// The document kind. Must match agentupdate.EnvelopeType on the Go side; the cross-language fixture test
    /// is what keeps the two strings from drifting, because nothing else would notice until a fleet refused
    /// every manifest.
    public static let envelopeType = "dsse_agent_update_manifest.v1"

    /// verified returns the manifest ONLY when the bytes are an envelope of the right TYPE that verifies
    /// against one of the pinned update-signing keys and has not expired.
    ///
    /// Every failure returns nil. Fail-closed here means "do not update", which is the safe direction: this
    /// device keeps running the version it has.
    ///
    /// `now` is injected so expiry is testable without waiting a month.
    public static func verified(envelopeData: Data, pinnedUpdateKeysHex: [String],
                                now: Date = Date()) -> DsseUpdateManifestPayload? {
        guard let first = pinnedUpdateKeysHex.first else { return nil }
        let rest = Array(pinnedUpdateKeysHex.dropFirst())
        guard let raw = DsseSignedAgentPolicy.verifiedPayloadBytes(
            envelopeData: envelopeData, expectedType: envelopeType,
            pinnedPublicKeyHex: first, alsoAccept: rest) else {
            return nil
        }
        guard let m = try? JSONDecoder().decode(DsseUpdateManifestPayload.self, from: raw) else {
            return nil
        }
        // not_after bounds replay: a manifest captured today must not be usable against this device in a year,
        // when the build it names may have a known flaw. Enforced HERE and not left to the caller, because a
        // caller that forgets produces a device that accepts an indefinitely old authorisation to run code.
        guard let notAfter = iso8601(m.notAfter), now <= notAfter else { return nil }
        return m
    }

    /// verified(path:) is the same check over a file — the courier-written manifest on disk.
    public static func verified(path: String, pinnedUpdateKeysHex: [String],
                                now: Date = Date()) -> DsseUpdateManifestPayload? {
        let p = path.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !p.isEmpty, let data = try? Data(contentsOf: URL(fileURLWithPath: p)) else { return nil }
        return verified(envelopeData: data, pinnedUpdateKeysHex: pinnedUpdateKeysHex, now: now)
    }

    /// appliesToThisDevice reports whether the manifest is for this platform and architecture.
    ///
    /// Separate from `verified` on purpose: "this document is authentic" and "this document is for me" are
    /// different questions, and collapsing them makes a manifest for another platform indistinguishable from a
    /// forged one — which is the difference between "nothing to do" and "somebody should look tonight".
    public static func appliesToThisDevice(_ m: DsseUpdateManifestPayload) -> Bool {
        guard m.platform == "darwin" else { return false }
        #if arch(arm64)
        return m.arch == "arm64"
        #elseif arch(x86_64)
        return m.arch == "amd64"
        #else
        return false
        #endif
    }

    private static func iso8601(_ s: String) -> Date? {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime]
        if let d = f.date(from: s) { return d }
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f.date(from: s)
    }
}
