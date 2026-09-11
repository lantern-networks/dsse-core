import CryptoKit
import DsseNetworkExtensionContract
import Foundation
import Network
import NetworkExtension
import OSLog
import Security

private let dsseAppProxyProviderLogger = Logger(
    subsystem: DsseRuntimeLogSubsystem.name,
    category: "app-proxy-provider"
)

private func providerRuntimeLog(_ message: String) {
    dsseAppProxyProviderLogger.notice("\(message, privacy: .public)")
    NSLog("DsseAppProxyProvider: %@", message)
}

// The same runtime log, reachable from the files that hold the two facts an operator needs when a device
// stops trusting its Edge: why the trust evaluation refused, and why a tunnel handshake failed. Both were
// computed and discarded until 2026-07-31, when their absence turned two datapath incidents into an hour
// each of guessing. Non-secret by construction — reasons, counts and status lines, never key material.
func dsseRuntimeLog(_ message: String) {
    providerRuntimeLog(message)
}

// A Swift enum error bridged to NSError keeps only its case INDEX. `code=1` is what the tunnel's
// `handshakeFailed(String)` looked like in the log on 2026-08-02: the one string that says WHY the
// handshake failed was computed, attached to the error, and then thrown away at the log site — three
// hours of the lab being dark were spent rediscovering, by elimination, what the payload already said.
// Match the known error types by case so the reason survives; fall back to domain/code for the rest.
// internal (not private) so a test can assert that every failure names itself — see
// EnrolmentFailuresAreNamed. A number in a log is the thing this function exists to prevent.
func providerNonsecretErrorDetail(_ error: Error) -> String {
    let nsError = error as NSError
    let base = "domain=\(nsError.domain) code=\(nsError.code)"
    if let detail = providerNonsecretTunnelErrorDetail(error) {
        return "\(base) \(detail)"
    }
    // ★★★ A CODE ON ITS OWN NAMES NOTHING, AND THE CODES ARE NOT THE DECLARATION ORDER (2026-08-29, measured:
    // an enrolment failure logged `code=1`, which was read as the second case of the enum and is in fact
    // requestFailed — Swift numbers cases carrying payloads before those that do not). An operator, and the
    // person debugging it, spent a round trip on a number that pointed at the wrong failure.
    //
    // The enrolment errors carry their reason as text, and it is diagnostic status — an HTTP status, a TLS
    // failure, a URLError description. Never key material, so it is safe to log and useless to withhold.
    if let detail = providerNonsecretEnrolmentErrorDetail(error) {
        return "\(base) \(detail)"
    }
    // ★ AND THE SAME FOR THE ONE AN OPERATOR ACTUALLY MEETS. `live_copy_failed=… code=20` is what a device
    // that steers but delivers nothing writes on every flow, and the number sends whoever reads it to count
    // enum cases — twice in one day, on this project. It names itself now.
    if let detail = providerNonsecretRuntimeCopyErrorDetail(error) {
        return "\(base) \(detail)"
    }
    // ★★★ AND THE ONE THIS FUNCTION EXISTS FOR WAS NOT IN THE LIST (2026-08-30). Every request the agent makes
    // to its Edge now rides DsseSingleRequestOverNW — enrolment, renewal, the policy poller, the runtime copy —
    // and its error was the one type here that fell through to domain/code. So a failed enrolment logged
    //
    //	enrolment_error=request_failed detail=domain=…DsseSingleRequestError code=1
    //
    // which is the same line for a refused connection, a timeout, a bad port and an unreadable response, on the
    // one path an operator has when a device cannot get an identity at all. The type already spells out which
    // of them it is; ask it. Same defect as cff1980b, one layer further in — that fixed the caller that logs
    // the round trip, and left the formatter every other caller goes through.
    if let single = error as? DsseSingleRequestError {
        return "\(base) \(single.description)"
    }
    // ★★★ AND A LIST OF KNOWN TYPES IS THE WRONG SHAPE FOR THIS (2026-08-30, the third time in two days).
    //
    // This function exists so a number never reaches an operator, and it worked by naming the types it knew.
    // Three times now the type that actually failed was not on the list — the runtime-copy driver, then
    // DsseSingleRequestError, then DsseRenewedIdentityStoreError — and each time the symptom was identical:
    //
    //	enrolment=failed … domain=…DsseRenewedIdentityStoreError code=2
    //
    // a number that is not even the declaration order, on the one path where the device has no identity and so
    // nothing else to report with. Maintaining the list is the defect; every future error type joins it by
    // being forgotten.
    //
    // A Swift enum with associated values carries its reason in String(describing:) whether or not anyone
    // remembered it here. That is diagnostic text — a status, a keychain OSStatus, a TLS failure — never key
    // material, exactly as the named cases above already are. So the fallback names the case and its payload,
    // and a type that is added later is legible on the day it first fails rather than on the day someone
    // notices this function does not know it.
    let described = String(describing: error)
    if described != base, !described.isEmpty {
        return "\(base) detail=\(described)"
    }
    return base
}

// The runtime-copy driver failure, named rather than numbered. See the note in providerNonsecretErrorDetail.
func providerNonsecretRuntimeCopyErrorDetail(_ error: Error) -> String? {
    guard let e = error as? DsseLocalRuntimeCopyDriverError else { return nil }
    let name: String
    switch e {
    case .missingTenantScope: name = "missing_tenant_scope"
    case .missingRequestID: name = "missing_request_id"
    case .missingApplicationScope: name = "missing_application_scope"
    case .emptyUpstreamPayload: name = "empty_upstream_payload"
    case .emptyDownstreamPayload: name = "empty_downstream_payload"
    case .flowOpenFailed: name = "flow_open_failed"
    case .flowReadFailed: name = "flow_read_failed"
    case .flowWriteFailed: name = "flow_write_failed"
    case .flowOpenTimeout: name = "flow_open_timeout"
    case .tunnelOpenTimeout: name = "tunnel_open_timeout"
    case .flowReadTimeout: name = "flow_read_timeout"
    case .edgeRoundTripTimeout: name = "edge_round_trip_timeout"
    case .flowWriteTimeout: name = "flow_write_timeout"
    case .duplicateRuntimeCopyRequestID: name = "duplicate_request_id"
    case .runtimeCopyConcurrentCapExceeded: name = "concurrent_cap_exceeded"
    case .runtimeCopyByteCapExceeded: name = "byte_cap_exceeded"
    case .runtimeCopyIdleTimeoutExceeded: name = "idle_timeout_exceeded"
    case .runtimeCopyBackpressureOverflowClosed: name = "backpressure_overflow_closed"
    case .runtimeTransportDeviceValidationPending: name = "device_validation_pending"
    case .invalidEdgeTransportConfiguration: name = "invalid_edge_transport_configuration"
    case .edgeTransportRequestFailed: name = "edge_transport_request_failed"
    case .edgeTransportStatusFailed: name = "edge_transport_status_failed"
    case .edgeTransportDecodeFailed: name = "edge_transport_decode_failed"
    case .edgeTransportRequestIDMismatch: name = "edge_transport_request_id_mismatch"
    }
    return "runtime_copy_error=" + name
}

// The enrolment failure, named rather than numbered. See the note in providerNonsecretErrorDetail.
func providerNonsecretEnrolmentErrorDetail(_ error: Error) -> String? {
    guard let e = error as? DsseDeviceEnrolmentError else { return nil }
    switch e {
    case .notConfigured(let why):
        return "enrolment_error=not_configured detail=\(why)"
    case .unpinnedTransport:
        return "enrolment_error=unpinned_transport — the configuration names neither an enrol CA nor a device-CA pin, so the endpoint that issues this device's identity could not be authenticated"
    case .requestFailed(let why):
        return "enrolment_error=request_failed detail=\(why)"
    case .serverRefused(let status, let message):
        return "enrolment_error=server_refused status=\(status) detail=\(message)"
    case .responseUnusable(let why):
        return "enrolment_error=response_unusable detail=\(why)"
    case .caPinMismatch(let expected, let got):
        return "enrolment_error=ca_pin_mismatch expected=\(expected) got=\(got)"
    }
}

// TLS/transport failure reasons — "certificate required", "bad certificate", a connect errno. These are
// diagnostic status text, never key material, so they are safe to log and useless to withhold.
private func providerNonsecretTunnelErrorDetail(_ error: Error) -> String? {
    guard let tunnelError = error as? DsseRuntimeCopyTunnelError else { return nil }
    switch tunnelError {
    case .invalidEdgeAuthority:
        return "tunnel_error=invalid_edge_authority"
    case .handshakeFailed(let reason):
        return "tunnel_error=handshake_failed reason=\(providerNonsecretReasonToken(reason))"
    case .connectionFailed(let reason):
        return "tunnel_error=connection_failed reason=\(providerNonsecretReasonToken(reason))"
    case .closed:
        return "tunnel_error=closed"
    }
}

// Keep the reason a single log token: one line, bounded length, no whitespace to break key=value parsing.
private func providerNonsecretReasonToken(_ reason: String) -> String {
    let collapsed = reason
        .replacingOccurrences(of: "\n", with: " ")
        .split(separator: " ", omittingEmptySubsequences: true)
        .joined(separator: "_")
    if collapsed.isEmpty { return "none" }
    return String(collapsed.prefix(160))
}

private func providerRuntimeProgressCategory(_ progress: DsseLiveRuntimeCopyProgress) -> String {
    switch progress {
    case .liveCopyStarted:
        return "live_copy_started"
    case .flowOpenCompleted:
        return "flow_open_completed"
    case .upstreamReadCompleted:
        return "upstream_read_completed"
    case .edgeRoundTripStarted:
        return "edge_round_trip_started"
    case .edgeTCPConnectStarted:
        return "edge_tcp_connect_started"
    case .edgeTCPConnectCompleted:
        return "edge_tcp_connect_completed"
    case .edgeRoundTripRequestSent:
        return "edge_round_trip_request_sent"
    case .edgeRoundTripResponseStatusReceived:
        return "edge_round_trip_response_status_received"
    case .edgeRoundTripErrorCategory:
        return "edge_round_trip_error_category"
    case .edgeRoundTripResponseBodyReceived:
        return "edge_round_trip_response_body_received"
    case .edgeRoundTripCompleted:
        return "edge_round_trip_completed"
    case .downstreamWriteStarted:
        return "downstream_write_started"
    case .downstreamWriteFailed:
        return "downstream_write_failed"
    case .downstreamWriteCompleted:
        return "downstream_write_completed"
    }
}

private func providerRuntimeProgressFamilySuffix(_ progress: DsseLiveRuntimeCopyProgress) -> String {
    switch progress {
    case .edgeTCPConnectStarted(let family), .edgeTCPConnectCompleted(let family):
        return " edge_tcp_connect_address_family=\(family)"
    case .edgeRoundTripErrorCategory(let category):
        return " edge_round_trip_error_category=\(category)"
    case .downstreamWriteFailed(let category):
        return " flow_write_error_category=\(category)"
    default:
        return ""
    }
}

struct DsseRuntimeCopyPassthroughEndpoint: Equatable, Sendable {
    let normalizedHost: String
    let normalizedResolvedHosts: Set<String>
    let port: Int
    let labEndpointPortOnlyFallback: Bool

    init(
        normalizedHost: String,
        port: Int,
        labEndpointPortOnlyFallback: Bool,
        normalizedResolvedHosts: Set<String> = []
    ) {
        self.normalizedHost = normalizedHost
        self.normalizedResolvedHosts = normalizedResolvedHosts
        self.port = port
        self.labEndpointPortOnlyFallback = labEndpointPortOnlyFallback
    }

    static func normalizeHost(_ host: String) -> String? {
        var trimmed = host.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if trimmed.hasPrefix("[") && trimmed.hasSuffix("]") {
            trimmed = String(trimmed.dropFirst().dropLast())
        }
        if trimmed.hasSuffix(".") {
            trimmed.removeLast()
        }
        return trimmed.isEmpty ? nil : trimmed
    }
}

struct DsseRuntimeCopyPassthroughDecision: Equatable, Sendable {
    let category: String
    let edgePortFlowReentryObserved: Bool
    let shouldPassThrough: Bool
}

struct DsseTransparentPassthroughDecision: Equatable, Sendable {
    let category: String
    let shouldPassThrough: Bool
}

struct DsseRuntimeCopyDownstreamPassthroughPolicy: Equatable, Sendable {
    let allowedSourceAppSigningIdentifiers: Set<String>
    let defaultTunnelEnabled: Bool

    init(
        allowedSourceAppSigningIdentifiers: [String],
        defaultTunnelEnabled: Bool = false
    ) {
        self.allowedSourceAppSigningIdentifiers = Set(
            allowedSourceAppSigningIdentifiers.compactMap(Self.normalizeSigningIdentifier)
        )
        self.defaultTunnelEnabled = defaultTunnelEnabled
    }

    var isConfigured: Bool {
        !allowedSourceAppSigningIdentifiers.isEmpty
    }

    func allows(sourceAppSigningIdentifier: String?) -> Bool {
        guard let normalized = Self.normalizeSigningIdentifier(sourceAppSigningIdentifier) else {
            return false
        }
        return allowedSourceAppSigningIdentifiers.contains(normalized)
    }

    static func normalizeSigningIdentifier(_ value: String?) -> String? {
        guard let value else {
            return nil
        }
        let normalized = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !normalized.isEmpty, normalized.count <= 256 else {
            return nil
        }
        let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
        guard normalized.unicodeScalars.allSatisfy({ allowed.contains($0) }) else {
            return nil
        }
        return normalized
    }
}

struct DsseRuntimeCopyDownstreamPassthroughDecision: Equatable, Sendable {
    let category: String
    let shouldPassThrough: Bool
}

// Unconditional self-exclusion of the AI dev-agent's own control traffic by
// source-app signing identifier. Unlike the runtime-copy downstream policy this
// is NOT coupled to a steering rule or port: any flow whose owning process is a
// listed signing identifier passes through untouched, so the agent driving this
// workspace keeps connectivity when the transparent proxy is enabled. This is
// the hostname/IP-independent backstop to the anthropic.com domain passthrough.
// Each merged entry (hardcoded floor + scaffold + agent_config local + signed server set) is a typed AppID per
// the cross-platform contract (docs/steering_exclusion_appid_format.md). The TYPE keyword is case-insensitive;
// the VALUE is preserved as-is (trim only). macOS applies the SHARED cross-platform forms and its own
// macOS-only forms, and IGNORES the Windows-only forms (and any unknown prefix) as a silent no-op — never an
// error, never an accidental match. One authored identity can now mean the same thing on macOS and Windows
// (the Windows steering agent ships subject:/thumbprint:; we mirror them here):
//   subject:<O>       -> SHARED: leaf-certificate Subject Organization (O), CASE-INSENSITIVE
//   thumbprint:<hex>  -> SHARED: leaf-certificate SHA-256, hex (spaces/colons stripped, case-insensitive)
//   <bare> (no recognized prefix) -> SHARED: treated as signing-id (back-compat: the floor/scaffold stay bare)
//   signing-id:<id>  -> macOS-only: code-signing identifier (bundle id), normalized as today
//   team-id:<TEAMID>  -> macOS-only: Apple Developer Team Identifier, EXACT, CASE-SENSITIVE
//   publisher:/signed:/unknown -> ignored (Windows-only / unrecognized)
struct DsseSelfExclusionPolicy: Equatable, Sendable {
    let signingIdentifiers: Set<String>
    let teamIdentifiers: Set<String>
    // Shared cross-platform forms. subjectOrganizations is stored lowercased+trimmed for case-insensitive
    // match; thumbprints is stored normalized (spaces/colons stripped, lowercase hex) for the leaf SHA-256.
    let subjectOrganizations: Set<String>
    let thumbprints: Set<String>
    let enabled: Bool
    // Verbatim, insertion-ordered + deduped record of the AppIDs this policy ACTUALLY applies, in the form the
    // device reports back as its effective set (reverse telemetry): signing-id / bare entries as their
    // normalized bare signing id, team-id entries as "team-id:<value>", subject entries as "subject:<value>",
    // thumbprint entries as "thumbprint:<value>" (values shown as authored). Windows-only / unknown forms are
    // not applied here and so do not appear.
    private let appliedSigningIDOrder: [String]
    private let appliedTeamIDOrder: [String]
    private let appliedSubjectOrder: [String]
    private let appliedThumbprintOrder: [String]

    init(appIDs: [String], enabled: Bool = true) {
        var signing = Set<String>()
        var team = Set<String>()
        var subject = Set<String>()
        var thumbprint = Set<String>()
        var signingOrder: [String] = []
        var teamOrder: [String] = []
        var subjectOrder: [String] = []
        var thumbprintOrder: [String] = []
        // Everything received and deliberately NOT applied. Ignoring a form this OS cannot use is correct and
        // stays silent on the device — but silence the operator cannot see makes an authoring mistake look
        // exactly like correct inapplicability, so the set is reported rather than merely dropped. Without it
        // the console can only INFER a reason from the AppID's shape, which drifts the moment this parser does.
        var ignoredOrder: [String] = []
        for raw in appIDs {
            let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty else { continue }
            if let colon = trimmed.firstIndex(of: ":") {
                // Typed AppID: keyword is case-insensitive, value preserved as-is (trim only).
                let keyword = trimmed[trimmed.startIndex..<colon].lowercased()
                let value = String(trimmed[trimmed.index(after: colon)...])
                    .trimmingCharacters(in: .whitespacesAndNewlines)
                switch keyword {
                case "signing-id":
                    if let normalized = DsseRuntimeCopyDownstreamPassthroughPolicy.normalizeSigningIdentifier(value),
                       !signing.contains(normalized) {
                        signing.insert(normalized)
                        signingOrder.append(normalized)
                    }
                case "team-id":
                    // Team IDs are case-sensitive (uppercase): do NOT lowercase the value.
                    if !value.isEmpty, !team.contains(value) {
                        team.insert(value)
                        teamOrder.append(value)
                    }
                case "subject":
                    // Shared form: leaf-cert Subject Organization (O), matched case-insensitively. Dedup on the
                    // lowercased key but keep the authored value for verbatim telemetry.
                    let normalized = value.lowercased()
                    if !normalized.isEmpty, !subject.contains(normalized) {
                        subject.insert(normalized)
                        subjectOrder.append(value)
                    }
                case "thumbprint":
                    // Shared form: leaf-cert SHA-256. Dedup on the normalized hex but keep the authored value
                    // for verbatim telemetry.
                    let normalized = Self.normalizeThumbprint(value)
                    if !normalized.isEmpty, !thumbprint.contains(normalized) {
                        thumbprint.insert(normalized)
                        thumbprintOrder.append(value)
                    }
                default:
                    // Windows-only forms (publisher:/signed:) and any unknown prefix: silent no-op on macOS.
                    ignoredOrder.append(trimmed)
                    continue
                }
            } else {
                // Bare AppID == signing-id (back-compat; the loop-prevention floor stays bare).
                // A bare value that is not a valid signing identifier — a Windows image path such as
                // \program files\jpki\, or a typo — cannot match anything here. Record it: the charset guard
                // that rejects it was written for bundle ids, so it drops a mistyped macOS entry just as quietly.
                if let normalized = DsseRuntimeCopyDownstreamPassthroughPolicy.normalizeSigningIdentifier(trimmed) {
                    if !signing.contains(normalized) {
                        signing.insert(normalized)
                        signingOrder.append(normalized)
                    }
                } else {
                    ignoredOrder.append(trimmed)
                }
            }
        }
        self.signingIdentifiers = signing
        self.teamIdentifiers = team
        self.subjectOrganizations = subject
        self.thumbprints = thumbprint
        self.appliedSigningIDOrder = signingOrder
        self.appliedTeamIDOrder = teamOrder
        self.appliedSubjectOrder = subjectOrder
        self.appliedThumbprintOrder = thumbprintOrder
        self.ignoredAppIDOrder = ignoredOrder
        self.enabled = enabled
    }

    // Canonicalize a thumbprint/SHA-256 hex string: strip whitespace and colon separators, lowercase. Used
    // for BOTH the authored thumbprint: value and a flow's resolved leaf SHA-256 so they compare equal
    // regardless of formatting (e.g. "19:41:CE..." vs "1941ce...").
    static func normalizeThumbprint(_ value: String) -> String {
        let filtered = value.unicodeScalars.filter { scalar in
            scalar != ":" && !CharacterSet.whitespacesAndNewlines.contains(scalar)
        }
        return String(String.UnicodeScalarView(filtered)).lowercased()
    }

    var isConfigured: Bool {
        enabled && (!signingIdentifiers.isEmpty
            || !teamIdentifiers.isEmpty
            || !subjectOrganizations.isEmpty
            || !thumbprints.isEmpty)
    }

    // The AppIDs this device received and deliberately did not apply, verbatim as authored, for reverse
    // telemetry. Distinct from "missing": an entry in neither the applied nor the ignored set was never seen.
    let ignoredAppIDOrder: [String]

    // The AppIDs the NE actually applies, for reverse telemetry (`observed` effective set).
    var appliedAppIDsForTelemetry: [String] {
        appliedSigningIDOrder
            + appliedTeamIDOrder.map { "team-id:" + $0 }
            + appliedSubjectOrder.map { "subject:" + $0 }
            + appliedThumbprintOrder.map { "thumbprint:" + $0 }
    }

    // Back-compat: signing-identifier-only check (no signer identity available / considered).
    func excludes(sourceAppSigningIdentifier: String?) -> Bool {
        excludes(sourceAppSigningIdentifier: sourceAppSigningIdentifier, signerIdentity: nil)
    }

    // Back-compat: signing-id + team-id only (callers/tests that resolved just the Team Identifier).
    func excludes(sourceAppSigningIdentifier: String?, teamIdentifier: String?) -> Bool {
        excludes(
            sourceAppSigningIdentifier: sourceAppSigningIdentifier,
            signerIdentity: DsseSourceAppSignerIdentity(
                teamIdentifier: teamIdentifier,
                subjectOrganization: nil,
                subjectCommonName: nil,
                leafSha256: nil
            )
        )
    }

    // OR match across all configured forms: a flow is excluded if its signing id ∈ signingIdentifiers OR its
    // team id ∈ teamIdentifiers OR its leaf Subject Organization (lowercased) ∈ subjectOrganizations OR its
    // leaf SHA-256 ∈ thumbprints. Fail-closed: any unresolved (nil/empty) identity field simply never matches,
    // so the app stays steered when an identity cannot be determined.
    func excludes(sourceAppSigningIdentifier: String?, signerIdentity: DsseSourceAppSignerIdentity?) -> Bool {
        guard enabled else {
            return false
        }
        if let normalized = DsseRuntimeCopyDownstreamPassthroughPolicy.normalizeSigningIdentifier(sourceAppSigningIdentifier),
           signingIdentifiers.contains(normalized) {
            return true
        }
        guard let signerIdentity else {
            return false
        }
        if let team = signerIdentity.teamIdentifier?.trimmingCharacters(in: .whitespacesAndNewlines),
           !team.isEmpty,
           teamIdentifiers.contains(team) {
            return true
        }
        // subject:<value> matches the signer's organization. Windows certs carry it as Subject O= (exact);
        // Apple Developer ID certs have NO O= field — the org is embedded in the leaf Common Name, e.g.
        // "Developer ID Application: Google LLC (EQHXZ8M8AV)". So on macOS we match a configured subject value
        // if it equals the O= (when present) OR is contained in the leaf CN (case-insensitive). This makes one
        // `subject:Google LLC` entry work on both platforms despite the different PKI field layout.
        for wanted in subjectOrganizations {
            if let organization = signerIdentity.subjectOrganization?
                .trimmingCharacters(in: .whitespacesAndNewlines)
                .lowercased(),
               !organization.isEmpty,
               organization == wanted {
                return true
            }
            if let commonName = signerIdentity.subjectCommonName?
                .trimmingCharacters(in: .whitespacesAndNewlines)
                .lowercased(),
               !commonName.isEmpty,
               commonName.contains(wanted) {
                return true
            }
        }
        if let thumb = signerIdentity.leafSha256.map(Self.normalizeThumbprint),
           !thumb.isEmpty,
           thumbprints.contains(thumb) {
            return true
        }
        return false
    }
}

// The crypto signer identities of a flow's owning process, resolved once per flow from its audit token for
// typed cross-platform self-exclusion matching. Every field is independently optional and is nil whenever it
// could not be determined (fail-safe: uncertainty never bypasses).
struct DsseSourceAppSignerIdentity: Equatable, Sendable {
    let teamIdentifier: String?
    let subjectOrganization: String?
    // Leaf Common Name — Apple Developer ID certs carry the org here (no O= field), so subject: matching
    // falls back to a case-insensitive "contains" against this. nil when undetermined.
    let subjectCommonName: String?
    let leafSha256: String?

    // Explicit init with a default for subjectCommonName so existing callers/tests that only set
    // team/organization/sha256 keep compiling; the live resolver passes the CN explicitly.
    init(teamIdentifier: String?, subjectOrganization: String?, subjectCommonName: String? = nil, leafSha256: String?) {
        self.teamIdentifier = teamIdentifier
        self.subjectOrganization = subjectOrganization
        self.subjectCommonName = subjectCommonName
        self.leafSha256 = leafSha256
    }
}

struct DsseSelfExclusionDecision: Equatable, Sendable {
    let category: String
    let shouldPassThrough: Bool
}

private struct DsseTransparentPassthroughAgentConfig: Decodable {
    let passthroughDomains: [String]?
    let defaultPassthroughDomainsEnabled: Bool?

    enum CodingKeys: String, CodingKey {
        case passthroughDomains = "network_extension_passthrough_domains"
        case defaultPassthroughDomainsEnabled = "network_extension_default_passthrough_domains_enabled"
    }
}

private struct DsseRuntimeCopyDownstreamPassthroughAgentConfig: Decodable {
    let sourceAppSigningIdentifiers: [String]?
    let defaultTunnelEnabled: Bool?

    enum CodingKeys: String, CodingKey {
        case sourceAppSigningIdentifiers = "network_extension_runtime_copy_downstream_passthrough_source_app_signing_identifiers"
        case defaultTunnelEnabled = "network_extension_runtime_copy_downstream_passthrough_default_tunnel_enabled"
    }
}

struct DsseSelfExclusionAgentConfig: Decodable {
    let signingIdentifiers: [String]?
    let enabled: Bool?
    let defaultsEnabled: Bool?
    // Server-issued signed policy (slice 3): the root-owned path of the signed exclusion envelope and the
    // pinned Ed25519 public key the NE verifies it against. When both are set and the envelope verifies, the
    // server's app-exclusion set is honored ADDITIVELY on top of the local signingIdentifiers list above
    // (which carries loop-prevention infrastructure exclusions and must never be dropped).
    /// ★★★ RAW, AND ALMOST NEVER WHAT A READER WANTS. It is nil whenever the configuration does not carry the
    /// key — which is the ordinary case, because nothing writes it — so a reader that takes this one reads
    /// NOTHING and gets a fallback that looks like a working feature answering "none". The name says
    /// `configured` so that picking it is a decision rather than an autocomplete.
    ///
    /// Use `resolvedAgentPolicySignedPath(configDirectory:)`. See its note.
    let configuredAgentPolicySignedPath: String?

    /// Where the signed steering document lives on this device.
    ///
    /// ★★★ NOTHING WROTE THIS KEY, SO THE DOCUMENT WAS NEVER ON DISK (2026-09-04, measured on a real Mac
    /// installed by the product's own package). The poller fetched and verified it every minute and cached it
    /// at `agentPolicySignedPath`, which was nil — so it cached nowhere, and every reader of the signed policy
    /// silently read nothing: the interception roots the deployment says it signs under, the renewal cutoff,
    /// and the organization this device belongs to. Each of those has a fallback, so each of them looked like
    /// a working feature answering "none".
    ///
    /// A configured value still wins. Absent, the document goes beside the rest of this device's state, where
    /// the readers already look.
    func resolvedAgentPolicySignedPath(configDirectory: URL) -> String {
        let configured = configuredAgentPolicySignedPath?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        if !configured.isEmpty { return configured }
        return configDirectory.appendingPathComponent("agent_policy_signed.json").path
    }
    let agentPolicyPinnedPublicKey: String?

    enum CodingKeys: String, CodingKey {
        case signingIdentifiers = "network_extension_self_exclusion_source_app_signing_identifiers"
        case enabled = "network_extension_self_exclusion_enabled"
        case defaultsEnabled = "network_extension_self_exclusion_default_signing_identifiers_enabled"
        case configuredAgentPolicySignedPath = "network_extension_agent_policy_signed_path"
        case agentPolicyPinnedPublicKey = "network_extension_agent_policy_signing_public_key"
    }
}

// Observe-only discovery mode: when enabled, handleNewFlow logs each flow's
// signing identifier and host kind but unconditionally passes every flow through
// (never intercepts). Used for the first live enable so the real Automation signing
// identifier / host visibility can be confirmed with zero risk to connectivity
// before switching the proxy to enforcing.
// Region PREFERENCE, set when the agent is installed.
//
// ★ WHY THIS IS AGENT-SIDE AND NOT SERVED BY THE EDGE (2026-08-10, operator's call, and it is right). An Edge
// flag would hand every device of every tenant the SAME order, which is precisely wrong for the thing priority
// exists to control: a laptop in Osaka and one in Tokyo should not prefer the same PoP. The preference is a
// property of where the DEVICE is, so it is configured where the device is — at install time, via the MDM
// profile / installer that already knows which site it is deploying to.
//
// The split with the server is deliberate and is a security boundary, not a layering preference:
//
//   the Edge decides WHICH regions this device may use  (residency; signed; cannot be widened by the device)
//   the agent decides WHICH ORDER it prefers them in    (performance; local; can only reorder the allowed set)
//
// A priority naming a region the Edge did not offer is inert — it is applied by lookup ONTO the served list, so
// there is no path by which a local file adds a region. That is what makes it safe to put in an installer.
//
// Absent/empty => every region unspecified => they tie and nearest-RTT decides, which is the previous
// behaviour, so an existing install is unchanged until someone states a preference.
struct DsseRegionPriorityAgentConfig: Decodable {
    let regionPriority: [String: Int]?

    enum CodingKeys: String, CodingKey {
        case regionPriority = "network_extension_region_priority"
    }

    /// load reads the preference and REFUSES to be quiet about a configuration it cannot use.
    ///
    /// ★ Two defects the Windows session found in the first version of this (2026-08-10), both of the silent
    /// kind, and both fixed here.
    ///
    /// 1. `try?` on the decode swallowed every failure into an empty map, so a configured-but-malformed machine
    ///    produced output byte-identical to an unconfigured one — and then homed on jitter, which is the exact
    ///    state this feature exists to end. Worse, the decode covers the WHOLE config object, so a typo in an
    ///    unrelated key silently un-ranked the device. Presence is now checked separately from decodability, so
    ///    "the operator asked for something and we could not use it" is a different, loud outcome from "the
    ///    operator asked for nothing".
    ///
    /// 2. `0` was accepted and ranked LAST. Zero-based is the ordinary instinct for "first", so `tokyo: 0`
    ///    delivered the precise inverse of the intent, on every device, with a healthy log and a working tunnel
    ///    to the wrong PoP. Non-positive values are now rejected by name.
    ///
    /// Deliberately NOT fatal, unlike the Windows agent, which refuses to start. There the refusal lands at
    /// install, with the person who typed it watching. Here the equivalent moment is a system extension
    /// starting on a user's Mac, and darkening a device over a mistyped PERFORMANCE preference trades a slow
    /// connection for no connection. The requirement is that it cannot be mistaken for unconfigured — not that
    /// it takes the device down.
    static func load(agentConfig data: Data, log: (String) -> Void) -> [String: Int] {
        // Is the key even there? Read from the raw object, so this answer does not depend on the rest of the
        // file decoding — the coupling that made an unrelated typo un-rank the device.
        let raw = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
        guard let present = raw?[CodingKeys.regionPriority.rawValue] else {
            return [:] // not configured: the ordinary case, and correctly silent
        }
        guard let table = present as? [String: Any], !table.isEmpty else {
            log("region_priority CONFIGURED BUT UNUSABLE: network_extension_region_priority is not a non-empty "
                + "object of region->priority. This device is NOT ranked and will pick a region by measured "
                + "latency, which on similar links is jitter. Fix the agent config.")
            return [:]
        }
        var out: [String: Int] = [:]
        var rejected: [String] = []
        for (region, value) in table {
            let key = region.lowercased().trimmingCharacters(in: .whitespacesAndNewlines)
            guard let n = value as? Int, n > 0, !key.isEmpty else {
                rejected.append("\(region)=\(value)")
                continue
            }
            out[key] = n
        }
        if !rejected.isEmpty {
            log("region_priority REJECTED \(rejected.count) entr(ies): \(rejected.joined(separator: ", ")) — a "
                + "priority must be a positive integer and 1 is the HIGHEST. 0 is not \"first\"; it means "
                + "unspecified and ranks LAST, so it would have inverted the intent silently.")
        }
        if out.isEmpty {
            log("region_priority CONFIGURED BUT EMPTY after validation — this device is NOT ranked.")
            return [:]
        }
        let rendered = out.sorted { $0.value < $1.value }.map { "\($0.key)=\($0.value)" }.joined(separator: ",")
        log("region_priority configured \(rendered) (lower is preferred; outranks measured latency)")
        return out
    }
}

private struct DsseObserveOnlyAgentConfig: Decodable {
    let passthroughAll: Bool?

    enum CodingKeys: String, CodingKey {
        case passthroughAll = "network_extension_observe_only_passthrough_all"
    }
}

// LAB fail-open (default OFF). Region failover is fail-CLOSED by design: when no allowed region is reachable
// (the Edge is down / not yet up at boot), the controller sets regionEgressBlocked=true and handleNewFlow
// denies every otherwise-accepted flow so traffic never leaves the residency boundary / evades a kill-switch.
// That production semantic is correct — but on a LAB/dev machine (which also hosts the developer's own tools)
// a momentarily-down Edge would brick ALL egress. This flag changes ONLY the provider's REACTION to
// regionEgressBlocked, and ONLY in lab: instead of deny_closed it DECLINES the flow (returns false) so the OS
// routes it directly (fail-open). The region-failover decision engine itself is untouched — it still probes,
// fails over between healthy regions, rebuilds the transport, and sets regionEgressBlocked exactly as before;
// once the Edge is reachable again new flows resume steering. NEVER enable this in production: passing traffic
// direct when no region is healthy is a residency-boundary / kill-switch violation.
private struct DsseLabFailOpenAgentConfig: Decodable {
    let failOpenWhenRegionBlocked: Bool?
    let failOpenAcknowledged: Bool?

    enum CodingKeys: String, CodingKey {
        case failOpenWhenRegionBlocked = "network_extension_lab_fail_open_when_region_blocked"
        case failOpenAcknowledged = "network_extension_fail_open_acknowledged"
    }
}

// DsseFailOpenPosture — the macOS mirror of the Windows `--fail-open` / `--acknowledge-fail-open` contract
// (docs/handoff_windows_failopen_production_guard_verified.md). Fail-open lets a flow the Edge cannot carry
// egress DIRECT, bypassing zero-trust enforcement, so it is OFF by default and — when requested — must be
// ACKNOWLEDGED by a second key. Enable WITHOUT the acknowledgment is refused (not armed), the way Windows
// refuses `--fail-open` without `--acknowledge-fail-open`. One story on both endpoints: strict by default;
// fail-open is a deliberate, acknowledged, temporary stabilization choice.
struct DsseFailOpenPosture: Equatable {
    let enableRequested: Bool
    let acknowledged: Bool
    var armed: Bool { enableRequested && acknowledged }
}

// Interception allowlist: when configured (non-empty), ONLY flows whose remote
// host matches one of these domains (suffix match) are eligible for interception;
// every other flow passes through untouched. This scopes the proxy to just the
// SaaS targets under test (e.g. Google Workspace / Microsoft 365 for ) so
// the rest of the machine's traffic — streaming (dazn.com), banking, the agent's
// own control plane — is never intercepted. Fail-open: if the host is not visible
// (IP-only) it does NOT match and passes through, which is the safe default on a
// daily-driver machine. Empty list preserves the legacy catch-all behavior.
private struct DsseInterceptAllowlistAgentConfig: Decodable {
    let interceptOnlyDomains: [String]?

    enum CodingKeys: String, CodingKey {
        case interceptOnlyDomains = "network_extension_intercept_only_domains"
    }
}

struct DsseInterceptAllowlistDecision: Equatable, Sendable {
    let category: String
    let shouldPassThrough: Bool
}

private func providerLifecycleFailureCategory(_ lastError: String) -> String {
    let text = lastError.lowercased()
    if text.contains("agent config could not be read") {
        return "config_read_failed"
    }
    if text.contains("agent config could not be decoded") {
        return "config_decode_failed"
    }
    if text.contains("network_extension_rules_ref is required") {
        return "missing_rules_ref"
    }
    if text.contains("network_extension_rules_ref is invalid") {
        return "invalid_rules_ref"
    }
    if text.contains("network extension rules could not be read") {
        return "rules_read_failed"
    }
    if text.contains("network extension rules could not be decoded") {
        return "rules_decode_failed"
    }
    if text.contains("network extension rules failed validation") {
        return "rules_validation_failed"
    }
    return "unknown_nonsecret"
}

public enum DsseAppProxyProviderError: Error, Equatable, LocalizedError {
    case missingAgentConfigPath
    case invalidAgentConfigPath(String)
    case lifecycleFailed(String)

    public var errorDescription: String? {
        switch self {
        case .missingAgentConfigPath:
            return "transparent proxy provider agent_config_path option is required"
        case .invalidAgentConfigPath(let path):
            return "transparent proxy provider agent_config_path is outside the production config boundary: \(path)"
        case .lifecycleFailed(let error):
            return "transparent proxy provider lifecycle failed: \(error)"
        }
    }
}

public struct DsseAppProxyProviderCompileContract: Codable, Equatable {
    public let status: String
    public let providerClass: String
    public let providerSuperclass: String
    public let runtimeProvider: ProviderRuntimeProvider
    public let compileOnly: Bool
    public let runtimeEntitlementRequired: Bool
    public let systemExtensionPackagingEntitlementContractRequired: Bool
    public let systemExtensionPackagingEntitlementContractSource: String
    public let requiredNetworkExtensionEntitlement: String
    public let requiredContainerSystemExtensionInstallEntitlement: Bool
    public let packetTunnelProviderEntitlementAllowed: Bool
    public let packagingEntitlementReviewBoundaryRequiredBeforeRuntime: Bool
    public let systemExtensionPackagingIdentityContractRequired: Bool
    public let systemExtensionPackagingIdentityContractSource: String
    public let requiredContainerBundleID: String
    public let requiredSystemExtensionBundleID: String
    public let requiredNetworkExtensionPoint: String
    public let requiredPrincipalClass: String
    public let packagingIdentityReviewBoundaryRequiredBeforeRuntime: Bool
    public let systemExtensionPackagingInstallDistributionContractRequired: Bool
    public let systemExtensionPackagingInstallDistributionContractSource: String
    public let requiredDistributionStatus: String
    public let requiredMDMPayloadGenerated: Bool
    public let requiredSystemExtensionInstallStarted: Bool
    public let requiredSystemExtensionActivated: Bool
    public let requiredRuntimeSmokeStarted: Bool
    public let packagingInstallDistributionReviewBoundaryRequiredBeforeRuntime: Bool
    public let systemExtensionPackagingRollbackContractRequired: Bool
    public let systemExtensionPackagingRollbackContractSource: String
    public let requiredRollbackPlanStatus: String
    public let requiredRollbackSupportBundleCollected: Bool
    public let requiredRollbackMDMPayloadRemoved: Bool
    public let requiredSystemExtensionDeactivationStarted: Bool
    public let requiredSystemExtensionUninstallStarted: Bool
    public let requiredAgentConfigCleanupStarted: Bool
    public let packagingRollbackReviewBoundaryRequiredBeforeRuntime: Bool
    public let systemExtensionPackagingSigningNotarizationContractRequired: Bool
    public let systemExtensionPackagingSigningNotarizationContractSource: String
    public let requiredSigningPlanStatus: String
    public let requiredCodesignStarted: Bool
    public let requiredCodesignVerificationStarted: Bool
    public let requiredNotarizationStatus: String
    public let requiredNotarizationTicketStapled: Bool
    public let requiredProvisioningProfileEmbedded: Bool
    public let packagingSigningNotarizationReviewBoundaryRequiredBeforeRuntime: Bool
    public let systemExtensionPackagingAppleCapabilityContractRequired: Bool
    public let systemExtensionPackagingAppleCapabilityContractSource: String
    public let requiredAppleCapabilityEvidenceStatus: String
    public let requiredAppleCapabilityRequestSubmissionEvidenced: Bool
    public let requiredNetworkExtensionCapabilityApprovalEvidenced: Bool
    public let requiredSystemExtensionInstallCapabilityApprovalEvidenced: Bool
    public let packagingAppleCapabilityReviewBoundaryRequiredBeforeRuntime: Bool
    public let systemExtensionPackagingOwnerGroupContractRequired: Bool
    public let systemExtensionPackagingOwnerGroupContractSource: String
    public let requiredAgentConfigDir: String
    public let requiredExpectedConfigOwner: String
    public let requiredExpectedConfigGroup: String
    public let requiredProductionConfigDirectoryStatus: String
    public let requiredProductionConfigOwnerGroupStatus: String
    public let requiredProductionConfigOwnerGroupVerificationStarted: Bool
    public let packagingOwnerGroupReviewBoundaryRequiredBeforeRuntime: Bool
    public let systemExtensionPackagingPermissionContractRequired: Bool
    public let systemExtensionPackagingPermissionContractSource: String
    public let requiredExpectedConfigDirectoryMode: String
    public let requiredProductionConfigPermissionStatus: String
    public let requiredProductionConfigPermissionVerificationStarted: Bool
    public let packagingPermissionReviewBoundaryRequiredBeforeRuntime: Bool
    public let systemExtensionPackagingFilePermissionContractRequired: Bool
    public let systemExtensionPackagingFilePermissionContractSource: String
    public let requiredExpectedConfigFileMode: String
    public let requiredProductionConfigFilePermissionStatus: String
    public let requiredProductionConfigFilePermissionVerificationStarted: Bool
    public let packagingFilePermissionReviewBoundaryRequiredBeforeRuntime: Bool
    public let flowHandling: String
    public let flowExtractionContract: String
    public let startLifecycleSource: String
    public let stopLifecycleClearsState: Bool
    public let sourceBundleIDTrusted: Bool
    public let unsupportedFlowAction: String
    public let handleNewFlowContract: String
    public let handleNewFlowReturnAction: String
    public let flowCopySkeleton: String
    public let flowCopyImplementation: String
    public let tcpPayloadCopyStarted: Bool
    public let flowCopyReviewBoundaryRequired: Bool
    public let flowCopyGuardContract: String
    public let flowCopyGuardSkeleton: DsseFlowCopyGuardSkeleton

    enum CodingKeys: String, CodingKey {
        case status
        case providerClass = "provider_class"
        case providerSuperclass = "provider_superclass"
        case runtimeProvider = "runtime_provider"
        case compileOnly = "compile_only"
        case runtimeEntitlementRequired = "runtime_entitlement_required"
        case systemExtensionPackagingEntitlementContractRequired = "system_extension_packaging_entitlement_contract_required"
        case systemExtensionPackagingEntitlementContractSource = "system_extension_packaging_entitlement_contract_source"
        case requiredNetworkExtensionEntitlement = "required_network_extension_entitlement"
        case requiredContainerSystemExtensionInstallEntitlement = "required_container_system_extension_install_entitlement"
        case packetTunnelProviderEntitlementAllowed = "packet_tunnel_provider_entitlement_allowed"
        case packagingEntitlementReviewBoundaryRequiredBeforeRuntime = "packaging_entitlement_review_boundary_required_before_runtime"
        case systemExtensionPackagingIdentityContractRequired = "system_extension_packaging_identity_contract_required"
        case systemExtensionPackagingIdentityContractSource = "system_extension_packaging_identity_contract_source"
        case requiredContainerBundleID = "required_container_bundle_id"
        case requiredSystemExtensionBundleID = "required_system_extension_bundle_id"
        case requiredNetworkExtensionPoint = "required_network_extension_point"
        case requiredPrincipalClass = "required_principal_class"
        case packagingIdentityReviewBoundaryRequiredBeforeRuntime = "packaging_identity_review_boundary_required_before_runtime"
        case systemExtensionPackagingInstallDistributionContractRequired = "system_extension_packaging_install_distribution_contract_required"
        case systemExtensionPackagingInstallDistributionContractSource = "system_extension_packaging_install_distribution_contract_source"
        case requiredDistributionStatus = "required_distribution_status"
        case requiredMDMPayloadGenerated = "required_mdm_payload_generated"
        case requiredSystemExtensionInstallStarted = "required_system_extension_install_started"
        case requiredSystemExtensionActivated = "required_system_extension_activated"
        case requiredRuntimeSmokeStarted = "required_runtime_smoke_started"
        case packagingInstallDistributionReviewBoundaryRequiredBeforeRuntime = "packaging_install_distribution_review_boundary_required_before_runtime"
        case systemExtensionPackagingRollbackContractRequired = "system_extension_packaging_rollback_contract_required"
        case systemExtensionPackagingRollbackContractSource = "system_extension_packaging_rollback_contract_source"
        case requiredRollbackPlanStatus = "required_rollback_plan_status"
        case requiredRollbackSupportBundleCollected = "required_rollback_support_bundle_collected"
        case requiredRollbackMDMPayloadRemoved = "required_rollback_mdm_payload_removed"
        case requiredSystemExtensionDeactivationStarted = "required_system_extension_deactivation_started"
        case requiredSystemExtensionUninstallStarted = "required_system_extension_uninstall_started"
        case requiredAgentConfigCleanupStarted = "required_agent_config_cleanup_started"
        case packagingRollbackReviewBoundaryRequiredBeforeRuntime = "packaging_rollback_review_boundary_required_before_runtime"
        case systemExtensionPackagingSigningNotarizationContractRequired = "system_extension_packaging_signing_notarization_contract_required"
        case systemExtensionPackagingSigningNotarizationContractSource = "system_extension_packaging_signing_notarization_contract_source"
        case requiredSigningPlanStatus = "required_signing_plan_status"
        case requiredCodesignStarted = "required_codesign_started"
        case requiredCodesignVerificationStarted = "required_codesign_verification_started"
        case requiredNotarizationStatus = "required_notarization_status"
        case requiredNotarizationTicketStapled = "required_notarization_ticket_stapled"
        case requiredProvisioningProfileEmbedded = "required_provisioning_profile_embedded"
        case packagingSigningNotarizationReviewBoundaryRequiredBeforeRuntime = "packaging_signing_notarization_review_boundary_required_before_runtime"
        case systemExtensionPackagingAppleCapabilityContractRequired = "system_extension_packaging_apple_capability_contract_required"
        case systemExtensionPackagingAppleCapabilityContractSource = "system_extension_packaging_apple_capability_contract_source"
        case requiredAppleCapabilityEvidenceStatus = "required_apple_capability_evidence_status"
        case requiredAppleCapabilityRequestSubmissionEvidenced = "required_apple_capability_request_submission_evidenced"
        case requiredNetworkExtensionCapabilityApprovalEvidenced = "required_network_extension_capability_approval_evidenced"
        case requiredSystemExtensionInstallCapabilityApprovalEvidenced = "required_system_extension_install_capability_approval_evidenced"
        case packagingAppleCapabilityReviewBoundaryRequiredBeforeRuntime = "packaging_apple_capability_review_boundary_required_before_runtime"
        case systemExtensionPackagingOwnerGroupContractRequired = "system_extension_packaging_owner_group_contract_required"
        case systemExtensionPackagingOwnerGroupContractSource = "system_extension_packaging_owner_group_contract_source"
        case requiredAgentConfigDir = "required_agent_config_dir"
        case requiredExpectedConfigOwner = "required_expected_config_owner"
        case requiredExpectedConfigGroup = "required_expected_config_group"
        case requiredProductionConfigDirectoryStatus = "required_production_config_directory_status"
        case requiredProductionConfigOwnerGroupStatus = "required_production_config_owner_group_status"
        case requiredProductionConfigOwnerGroupVerificationStarted = "required_production_config_owner_group_verification_started"
        case packagingOwnerGroupReviewBoundaryRequiredBeforeRuntime = "packaging_owner_group_review_boundary_required_before_runtime"
        case systemExtensionPackagingPermissionContractRequired = "system_extension_packaging_permission_contract_required"
        case systemExtensionPackagingPermissionContractSource = "system_extension_packaging_permission_contract_source"
        case requiredExpectedConfigDirectoryMode = "required_expected_config_directory_mode"
        case requiredProductionConfigPermissionStatus = "required_production_config_permission_status"
        case requiredProductionConfigPermissionVerificationStarted = "required_production_config_permission_verification_started"
        case packagingPermissionReviewBoundaryRequiredBeforeRuntime = "packaging_permission_review_boundary_required_before_runtime"
        case systemExtensionPackagingFilePermissionContractRequired = "system_extension_packaging_file_permission_contract_required"
        case systemExtensionPackagingFilePermissionContractSource = "system_extension_packaging_file_permission_contract_source"
        case requiredExpectedConfigFileMode = "required_expected_config_file_mode"
        case requiredProductionConfigFilePermissionStatus = "required_production_config_file_permission_status"
        case requiredProductionConfigFilePermissionVerificationStarted = "required_production_config_file_permission_verification_started"
        case packagingFilePermissionReviewBoundaryRequiredBeforeRuntime = "packaging_file_permission_review_boundary_required_before_runtime"
        case flowHandling = "flow_handling"
        case flowExtractionContract = "flow_extraction_contract"
        case startLifecycleSource = "start_lifecycle_source"
        case stopLifecycleClearsState = "stop_lifecycle_clears_state"
        case sourceBundleIDTrusted = "source_bundle_id_trusted"
        case unsupportedFlowAction = "unsupported_flow_action"
        case handleNewFlowContract = "handle_new_flow_contract"
        case handleNewFlowReturnAction = "handle_new_flow_return_action"
        case flowCopySkeleton = "flow_copy_skeleton"
        case flowCopyImplementation = "flow_copy_implementation"
        case tcpPayloadCopyStarted = "tcp_payload_copy_started"
        case flowCopyReviewBoundaryRequired = "flow_copy_review_boundary_required"
        case flowCopyGuardContract = "flow_copy_guard_contract"
        case flowCopyGuardSkeleton = "flow_copy_guard_skeleton"
    }
}

public struct DsseConnectionRegistryCompileSkeleton: Codable, Equatable {
    public let status: String
    public let implementation: String
    public let sourceContract: String
    public let runtimeConnected: Bool
    public let tenantScopeRequiredBeforeOpen: Bool
    public let requestIDUniquenessRequired: Bool
    public let duplicateOpenAction: String
    public let concurrentCapRequired: Bool
    public let maxConcurrentConnections: Int
    public let connectTimeoutRequired: Bool
    public let maxConnectTimeoutMillis: Int
    public let maxConnectionLifetimeRequired: Bool
    public let maxConnectionLifetimeMillis: Int
    public let byteCapRequired: Bool
    public let maxByteCapBytes: Int64
    public let idleTimeoutRequired: Bool
    public let maxIdleTimeoutMillis: Int
    public let closeCleanupRequired: Bool
    public let closeMetricsRequired: Bool
    public let requiredOperations: [String]
    public let localCloseReasons: [String]
    public let networkExtensionFlowReadWriteStarted: Bool
    public let edgeTunnelOpenStarted: Bool
    public let reviewBoundaryRequiredBeforeRuntime: Bool

    enum CodingKeys: String, CodingKey {
        case status
        case implementation
        case sourceContract = "source_contract"
        case runtimeConnected = "runtime_connected"
        case tenantScopeRequiredBeforeOpen = "tenant_scope_required_before_open"
        case requestIDUniquenessRequired = "request_id_uniqueness_required"
        case duplicateOpenAction = "duplicate_open_action"
        case concurrentCapRequired = "concurrent_cap_required"
        case maxConcurrentConnections = "max_concurrent_connections"
        case connectTimeoutRequired = "connect_timeout_required"
        case maxConnectTimeoutMillis = "max_connect_timeout_ms"
        case maxConnectionLifetimeRequired = "max_connection_lifetime_required"
        case maxConnectionLifetimeMillis = "max_connection_lifetime_ms"
        case byteCapRequired = "byte_cap_required"
        case maxByteCapBytes = "max_byte_cap_bytes"
        case idleTimeoutRequired = "idle_timeout_required"
        case maxIdleTimeoutMillis = "max_idle_timeout_ms"
        case closeCleanupRequired = "close_cleanup_required"
        case closeMetricsRequired = "close_metrics_required"
        case requiredOperations = "required_operations"
        case localCloseReasons = "local_close_reasons"
        case networkExtensionFlowReadWriteStarted = "network_extension_flow_read_write_started"
        case edgeTunnelOpenStarted = "edge_tunnel_open_started"
        case reviewBoundaryRequiredBeforeRuntime = "review_boundary_required_before_runtime"
    }
}

public struct DsseFlowCopyGuardSkeleton: Codable, Equatable {
    public let status: String
    public let implementation: String
    public let copyEnablementReady: Bool
    public let acceptFlowBeforeGuardReady: Bool
    public let connectionRegistryRequired: Bool
    public let connectionRegistryStatus: String
    public let connectionRegistrySkeleton: DsseConnectionRegistryCompileSkeleton
    public let byteCapRequired: Bool
    public let maxByteCapBytes: Int64
    public let idleTimeoutRequired: Bool
    public let maxIdleTimeoutMillis: Int
    public let closeCleanupRequired: Bool
    public let closeCleanupStatus: String
    public let backpressureRequired: Bool
    public let backpressureStrategy: String
    public let backpressureQueueCapacity: Int
    public let tenantScopeRequired: Bool
    public let tenantScopeStatus: String
    public let tenantScopeSource: String
    public let tenantScopeRuntimeResolved: Bool
    public let tenantScopeBoundary: String
    public let auditEventsRequired: Bool
    public let auditEventContractStatus: String
    public let requiredAuditEvents: [String]
    public let networkExtensionFlowOpened: Bool
    public let edgeTunnelOpenStarted: Bool
    public let tcpPayloadCopyStarted: Bool
    public let flowPayloadReadStarted: Bool
    public let flowPayloadWriteStarted: Bool
    public let reviewBoundaryRequiredBeforeRuntime: Bool
    public let humanValidationPrerequisitesRequired: Bool
    public let humanValidationPrerequisitesStatus: String
    public let humanValidationBoundary: String
    public let humanValidationTaskID: String

    enum CodingKeys: String, CodingKey {
        case status
        case implementation
        case copyEnablementReady = "copy_enablement_ready"
        case acceptFlowBeforeGuardReady = "accept_flow_before_guard_ready"
        case connectionRegistryRequired = "connection_registry_required"
        case connectionRegistryStatus = "connection_registry_status"
        case connectionRegistrySkeleton = "connection_registry_skeleton"
        case byteCapRequired = "byte_cap_required"
        case maxByteCapBytes = "max_byte_cap_bytes"
        case idleTimeoutRequired = "idle_timeout_required"
        case maxIdleTimeoutMillis = "max_idle_timeout_ms"
        case closeCleanupRequired = "close_cleanup_required"
        case closeCleanupStatus = "close_cleanup_status"
        case backpressureRequired = "backpressure_required"
        case backpressureStrategy = "backpressure_strategy"
        case backpressureQueueCapacity = "backpressure_queue_capacity"
        case tenantScopeRequired = "tenant_scope_required"
        case tenantScopeStatus = "tenant_scope_status"
        case tenantScopeSource = "tenant_scope_source"
        case tenantScopeRuntimeResolved = "tenant_scope_runtime_resolved"
        case tenantScopeBoundary = "tenant_scope_boundary"
        case auditEventsRequired = "audit_events_required"
        case auditEventContractStatus = "audit_event_contract_status"
        case requiredAuditEvents = "required_audit_events"
        case networkExtensionFlowOpened = "network_extension_flow_opened"
        case edgeTunnelOpenStarted = "edge_tunnel_open_started"
        case tcpPayloadCopyStarted = "tcp_payload_copy_started"
        case flowPayloadReadStarted = "flow_payload_read_started"
        case flowPayloadWriteStarted = "flow_payload_write_started"
        case reviewBoundaryRequiredBeforeRuntime = "review_boundary_required_before_runtime"
        case humanValidationPrerequisitesRequired = "human_validation_prerequisites_required"
        case humanValidationPrerequisitesStatus = "human_validation_prerequisites_status"
        case humanValidationBoundary = "human_validation_boundary"
        case humanValidationTaskID = "human_validation_task_id"
    }
}

public struct DsseFlowCopySkeletonPlan: Codable, Equatable {
    public let status: String
    public let action: String
    public let mode: String
    public let implementation: String
    public let networkExtensionFlowOpened: Bool
    public let edgeTunnelOpenStarted: Bool
    public let tcpPayloadCopyStarted: Bool
    public let flowPayloadReadStarted: Bool
    public let flowPayloadWriteStarted: Bool
    public let reviewBoundaryRequiredBeforeCopy: Bool
    public let guardContract: String
    public let guardSkeleton: DsseFlowCopyGuardSkeleton

    enum CodingKeys: String, CodingKey {
        case status
        case action
        case mode
        case implementation
        case networkExtensionFlowOpened = "network_extension_flow_opened"
        case edgeTunnelOpenStarted = "edge_tunnel_open_started"
        case tcpPayloadCopyStarted = "tcp_payload_copy_started"
        case flowPayloadReadStarted = "flow_payload_read_started"
        case flowPayloadWriteStarted = "flow_payload_write_started"
        case reviewBoundaryRequiredBeforeCopy = "review_boundary_required_before_copy"
        case guardContract = "guard_contract"
        case guardSkeleton = "guard_skeleton"
    }
}

public struct DsseHandleNewFlowContractReport: Codable, Equatable, @unchecked Sendable {
    public let status: String
    public let flowExtractionStatus: ProviderFlowExtractionStatus
    public let flowExtractionReason: ProviderFlowExtractionReason
    public let flowTransport: ProviderFlowTransport
    public let sourceBundleIDPresent: Bool
    public let sourceBundleIDTrusted: Bool
    public let providerAction: ProviderFlowAction
    public let action: String
    public let reason: String
    public let singleRuleLabFallbackGate: String
    public let flowAuthorityHostGate: String
    public let flowAuthorityPortGate: String
    public let singleRuleLabFallbackPortGate: String
    public let acceptFlow: Bool
    public let returnAction: String
    public let flowCopySkeletonStatus: String
    public let flowCopyAction: String
    public let flowCopyMode: String
    public let flowCopyImplementation: String
    public let networkExtensionFlowOpened: Bool
    public let edgeTunnelOpenStarted: Bool
    public let tcpPayloadCopyStarted: Bool
    public let flowPayloadReadStarted: Bool
    public let flowPayloadWriteStarted: Bool
    public let flowCopyReviewBoundaryRequired: Bool
    public let flowCopyGuardContract: String
    public let flowCopyGuardSkeleton: DsseFlowCopyGuardSkeleton

    enum CodingKeys: String, CodingKey {
        case status
        case flowExtractionStatus = "flow_extraction_status"
        case flowExtractionReason = "flow_extraction_reason"
        case flowTransport = "flow_transport"
        case sourceBundleIDPresent = "source_bundle_id_present"
        case sourceBundleIDTrusted = "source_bundle_id_trusted"
        case providerAction = "provider_action"
        case action
        case reason
        case singleRuleLabFallbackGate = "single_rule_lab_fallback_gate"
        case flowAuthorityHostGate = "flow_authority_host_gate"
        case flowAuthorityPortGate = "flow_authority_port_gate"
        case singleRuleLabFallbackPortGate = "single_rule_lab_fallback_port_gate"
        case acceptFlow = "accept_flow"
        case returnAction = "return_action"
        case flowCopySkeletonStatus = "flow_copy_skeleton_status"
        case flowCopyAction = "flow_copy_action"
        case flowCopyMode = "flow_copy_mode"
        case flowCopyImplementation = "flow_copy_implementation"
        case networkExtensionFlowOpened = "network_extension_flow_opened"
        case edgeTunnelOpenStarted = "edge_tunnel_open_started"
        case tcpPayloadCopyStarted = "tcp_payload_copy_started"
        case flowPayloadReadStarted = "flow_payload_read_started"
        case flowPayloadWriteStarted = "flow_payload_write_started"
        case flowCopyReviewBoundaryRequired = "flow_copy_review_boundary_required"
        case flowCopyGuardContract = "flow_copy_guard_contract"
        case flowCopyGuardSkeleton = "flow_copy_guard_skeleton"
    }
}

struct DsseProviderFlowAuthorityObservation {
    let input: ProviderFlowAuthorityInput
    let endpointSourceGate: String
    let portSourceGate: String
}

private struct DsseProviderFlowPortObservation {
    let port: Int
    let sourceGate: String
}

public enum DsseDefaultDenyPathEvidenceState: String, Codable, Equatable, Sendable {
    case notApplicable = "not_applicable"
    case closedWithoutCopy = "closed_without_copy"
    case metadataOnlyRecorded = "metadata_only_recorded"
}

public struct DssePolicyDrivenHandleNewFlowAuditEvidence: Codable, Equatable, Sendable {
    public static let schemaVersion = "policy_driven_handle_new_flow_audit_evidence.v1"
    public static let protectionTriggerLateralMovementProtocolAnomaly = NetworkExtensionContract.reasonCodeLateralMovementProtocolAnomaly
    public static let protectionTriggerNotApplicable = "not_applicable"
    public static let protectionTriggerUnknownNonsecret = "unknown_nonsecret"

    public let schemaVersion: String
    public let evidenceKind: String
    public let status: String
    public let providerRuntimeSessionKeyKind: String
    public let providerRuntimeSessionKey: String
    public let providerRuntimeFlowRole: String
    public let providerRuntimeSequenceIndex: Int
    public let policyDecisionCategory: String
    public let policyDecisionAction: String
    public let policyDecisionReason: String
    public let handleNewFlowReturnAction: String
    public let acceptFlow: Bool
    public let connectorRouteGate: String
    public let privateAppRouteDecision: String
    public let runtimeCopyEndpointPassthroughDecision: String
    public let edgePortFlowReentryObserved: Bool
    public let edgeTCPConnectCompleted: Bool
    public let edgeTCPConnectAddressFamily: String
    public let edgeTransportRoundTripGate: String
    public let copyRoundTripGate: String
    public let bytesUpGate: String
    public let bytesDownGate: String
    public let privateAppResponseGate: String
    public let copyAttemptGate: String
    public let defaultDenyGate: String
    public let defaultDenyPathEvidenceState: DsseDefaultDenyPathEvidenceState
    public let denyClosedWithoutCopy: Bool
    public let protectionGate: String
    public let protectionBlockedWithoutCopy: Bool
    public let protectionRuleSemantics: String
    public let protectionReasonCodes: [String]
    public let protectionTriggerCategory: String
    public let copyStarted: Bool
    public let networkExtensionFlowOpened: Bool
    public let edgeTunnelOpenStarted: Bool
    public let tcpPayloadCopyStarted: Bool
    public let flowPayloadReadStarted: Bool
    public let flowPayloadWriteStarted: Bool
    public let bytesUp: Int
    public let bytesDown: Int
    public let registryCleanupGate: String
    public let tenantMetadataCleanupGate: String
    public let auditMetadataOnlyGate: String
    public let secretLeakGate: String
    public let runtimeOverclaimGate: String
    public let flowCopyOverclaimGate: String
    public let realEdgeConnectorProductClaimed: Bool
    public let flowTunneledClaimed: Bool
    public let flowDeniedClaimed: Bool
    public let ransomwareProtectionActiveClaimed: Bool
    public let realTLSInterceptionClaimed: Bool
    public let certificateIssuanceClaimed: Bool
    public let productionPrivateAppEnforcementClaimed: Bool
    public let productionDefaultDenyEnforcementClaimed: Bool
    public let rawLogsIncluded: Bool
    public let rawCommandOutputIncluded: Bool
    public let rawNEFlowIncluded: Bool
    public let hostUserPayloadIncluded: Bool
    public let destinationIPIncluded: Bool
    public let credentialsIncluded: Bool
    public let packetCaptureIncluded: Bool
    public let appleIdentifierIncluded: Bool
    public let noSecretAttestation: Bool
    public let nonsecretAuditEventCategories: [String]

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case evidenceKind = "evidence_kind"
        case status
        case providerRuntimeSessionKeyKind = "provider_runtime_session_key_kind"
        case providerRuntimeSessionKey = "provider_runtime_session_key"
        case providerRuntimeFlowRole = "provider_runtime_flow_role"
        case providerRuntimeSequenceIndex = "provider_runtime_sequence_index"
        case policyDecisionCategory = "policy_decision_category"
        case policyDecisionAction = "policy_decision_action"
        case policyDecisionReason = "policy_decision_reason"
        case handleNewFlowReturnAction = "handle_new_flow_return_action"
        case acceptFlow = "accept_flow"
        case connectorRouteGate = "connector_route_gate"
        case privateAppRouteDecision = "private_app_route_decision"
        case runtimeCopyEndpointPassthroughDecision = "runtime_copy_endpoint_passthrough_decision"
        case edgePortFlowReentryObserved = "edge_port_flow_reentry_observed"
        case edgeTCPConnectCompleted = "edge_tcp_connect_completed"
        case edgeTCPConnectAddressFamily = "edge_tcp_connect_address_family"
        case edgeTransportRoundTripGate = "edge_transport_round_trip_gate"
        case copyRoundTripGate = "copy_round_trip_gate"
        case bytesUpGate = "bytes_up_gate"
        case bytesDownGate = "bytes_down_gate"
        case privateAppResponseGate = "private_app_response_gate"
        case copyAttemptGate = "copy_attempt_gate"
        case defaultDenyGate = "default_deny_gate"
        case defaultDenyPathEvidenceState = "default_deny_path_evidence_state"
        case denyClosedWithoutCopy = "deny_closed_without_copy"
        case protectionGate = "protection_gate"
        case protectionBlockedWithoutCopy = "protection_blocked_without_copy"
        case protectionRuleSemantics = "protection_rule_semantics"
        case protectionReasonCodes = "protection_reason_codes"
        case protectionTriggerCategory = "protection_trigger_category"
        case copyStarted = "copy_started"
        case networkExtensionFlowOpened = "network_extension_flow_opened"
        case edgeTunnelOpenStarted = "edge_tunnel_open_started"
        case tcpPayloadCopyStarted = "tcp_payload_copy_started"
        case flowPayloadReadStarted = "flow_payload_read_started"
        case flowPayloadWriteStarted = "flow_payload_write_started"
        case bytesUp = "bytes_up"
        case bytesDown = "bytes_down"
        case registryCleanupGate = "registry_cleanup_gate"
        case tenantMetadataCleanupGate = "tenant_metadata_cleanup_gate"
        case auditMetadataOnlyGate = "audit_metadata_only_gate"
        case secretLeakGate = "secret_leak_gate"
        case runtimeOverclaimGate = "runtime_overclaim_gate"
        case flowCopyOverclaimGate = "flow_copy_overclaim_gate"
        case realEdgeConnectorProductClaimed = "real_edge_connector_product_claimed"
        case flowTunneledClaimed = "flow_tunneled_claimed"
        case flowDeniedClaimed = "flow_denied_claimed"
        case ransomwareProtectionActiveClaimed = "ransomware_protection_active_claimed"
        case realTLSInterceptionClaimed = "real_tls_interception_claimed"
        case certificateIssuanceClaimed = "certificate_issuance_claimed"
        case productionPrivateAppEnforcementClaimed = "production_private_app_enforcement_claimed"
        case productionDefaultDenyEnforcementClaimed = "production_default_deny_enforcement_claimed"
        case rawLogsIncluded = "raw_logs_included"
        case rawCommandOutputIncluded = "raw_command_output_included"
        case rawNEFlowIncluded = "raw_ne_flow_included"
        case hostUserPayloadIncluded = "host_user_payload_included"
        case destinationIPIncluded = "destination_ip_included"
        case credentialsIncluded = "credentials_included"
        case packetCaptureIncluded = "packet_capture_included"
        case appleIdentifierIncluded = "apple_identifier_included"
        case noSecretAttestation = "no_secret_attestation"
        case nonsecretAuditEventCategories = "nonsecret_audit_event_categories"
    }
}

public enum DssePolicyDrivenHandleNewFlowAuditEvidenceWriteError: Error, Equatable {
    case invalidEvidence(String)
    case writeFailed
}

public final class DssePolicyDrivenHandleNewFlowAuditEvidenceWriter: @unchecked Sendable {
    public static let allowAuditRef = "policy_driven_handle_new_flow_allow_audit.json"
    public static let defaultDenyAuditRef = "policy_driven_handle_new_flow_default_deny_audit.json"
    public static let protectionBlockAuditRef = "policy_driven_handle_new_flow_protection_block_audit.json"
    public static let providerRuntimeSessionKeyKind = "nonsecret_lab_runtime_pairing_key"
    public static let providerRuntimeSessionKey = "private_app_enforcement_lab_pair"

    private let outputDirectory: URL
    // One-shot per audit file. Each writeXxxAudit is called PER allowed/denied/protected flow and overwrites a
    // single shared last-writer-wins evidence file, so after the first capture every later per-flow rewrite is
    // pure disk churn (part of the ~34 GB/day "disk writes" bug). Once a given ref is written, it is sealed.
    private let onceLock = NSLock()
    private var sealedRefs: Set<String> = []

    public init(outputDirectory: URL) {
        self.outputDirectory = outputDirectory
    }

    public convenience init(agentConfigPath: String) {
        self.init(outputDirectory: URL(fileURLWithPath: agentConfigPath).deletingLastPathComponent())
    }

    private func isSealed(_ ref: String) -> Bool {
        onceLock.lock(); defer { onceLock.unlock() }
        return sealedRefs.contains(ref)
    }

    // Seal only AFTER a successful validate+write, so an invalid-evidence call still throws (and does not seal)
    // and a later valid call can still capture the file.
    private func markSealed(_ ref: String) {
        onceLock.lock(); sealedRefs.insert(ref); onceLock.unlock()
    }

    // Each method ALWAYS validates its evidence (a tested per-call contract — invalid evidence must throw), but
    // seals the DISK WRITE after the first successful capture: the ~34 GB/day bug was the per-flow disk I/O to a
    // single shared last-writer-wins file, not the (cheap, in-memory) validation.
    @discardableResult
    public func writeAllowAudit(_ evidence: DssePolicyDrivenHandleNewFlowAuditEvidence) throws -> URL {
        try Self.validateAllowAudit(evidence)
        let outputURL = outputDirectory.appendingPathComponent(Self.allowAuditRef, isDirectory: false)
        if isSealed(Self.allowAuditRef) { return outputURL }
        try Self.write(evidence, to: outputURL)
        markSealed(Self.allowAuditRef)
        return outputURL
    }

    @discardableResult
    public func writeDefaultDenyAudit(_ evidence: DssePolicyDrivenHandleNewFlowAuditEvidence) throws -> URL {
        try Self.validateDefaultDenyAudit(evidence)
        let outputURL = outputDirectory.appendingPathComponent(Self.defaultDenyAuditRef, isDirectory: false)
        if isSealed(Self.defaultDenyAuditRef) { return outputURL }
        try Self.write(evidence, to: outputURL)
        markSealed(Self.defaultDenyAuditRef)
        return outputURL
    }

    @discardableResult
    public func writeProtectionAudit(_ evidence: DssePolicyDrivenHandleNewFlowAuditEvidence) throws -> URL {
        try Self.validateProtectionAudit(evidence)
        let outputURL = outputDirectory.appendingPathComponent(Self.protectionBlockAuditRef, isDirectory: false)
        if isSealed(Self.protectionBlockAuditRef) { return outputURL }
        try Self.write(evidence, to: outputURL)
        markSealed(Self.protectionBlockAuditRef)
        return outputURL
    }

    private static func write(_ evidence: DssePolicyDrivenHandleNewFlowAuditEvidence, to outputURL: URL) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data = try encoder.encode(evidence)
        do {
            try data.write(to: outputURL, options: .atomic)
        } catch {
            throw DssePolicyDrivenHandleNewFlowAuditEvidenceWriteError.writeFailed
        }
    }

    public static func validateAllowAudit(_ evidence: DssePolicyDrivenHandleNewFlowAuditEvidence) throws {
        try validateCommonAuditShape(evidence)
        guard evidence.status == "ok",
              evidence.providerRuntimeSessionKeyKind == providerRuntimeSessionKeyKind,
              evidence.providerRuntimeSessionKey == providerRuntimeSessionKey,
              evidence.providerRuntimeFlowRole == "allow_private_app_route",
              evidence.providerRuntimeSequenceIndex == 1,
              evidence.policyDecisionCategory == "allow",
              evidence.policyDecisionAction == "allow",
              evidence.handleNewFlowReturnAction == HandleNewFlowTakeoverContract.acceptedTunneledCopyReturnAction,
              evidence.acceptFlow,
              evidence.connectorRouteGate == "route_application_seen",
              evidence.privateAppRouteDecision == "matched_private_app_route",
              evidence.runtimeCopyEndpointPassthroughDecision == "matched_passed_through",
              evidence.edgePortFlowReentryObserved,
              evidence.edgeTCPConnectCompleted,
              evidence.edgeTransportRoundTripGate == "real_transport_completed",
              evidence.copyRoundTripGate == "round_trip_completed",
              evidence.bytesUpGate == "nonzero",
              evidence.bytesDownGate == "nonzero",
              evidence.privateAppResponseGate == "observed_nonsecret",
              evidence.copyAttemptGate == "reviewed_copy_path_completed",
              evidence.protectionTriggerCategory == DssePolicyDrivenHandleNewFlowAuditEvidence.protectionTriggerNotApplicable,
              evidence.copyStarted,
              evidence.networkExtensionFlowOpened,
              evidence.edgeTunnelOpenStarted,
              evidence.tcpPayloadCopyStarted,
              evidence.flowPayloadReadStarted,
              evidence.flowPayloadWriteStarted,
              evidence.bytesUp > 0,
              evidence.bytesDown > 0,
              evidence.auditMetadataOnlyGate == "ok",
              evidence.secretLeakGate == "ok",
              evidence.runtimeOverclaimGate == "ok",
              evidence.flowCopyOverclaimGate == "ok",
              evidence.noSecretAttestation else {
            throw DssePolicyDrivenHandleNewFlowAuditEvidenceWriteError.invalidEvidence("allow_audit_gate")
        }
        try validateClaimAndRawFlagsFalse(evidence)
        let requiredEvents = [
            "policy_decision_evaluated",
            "handle_new_flow_takeover_selected",
            "reviewed_copy_path_completed",
            "metadata_only_audit_emitted"
        ]
        guard requiredEvents.allSatisfy({ evidence.nonsecretAuditEventCategories.contains($0) }) else {
            throw DssePolicyDrivenHandleNewFlowAuditEvidenceWriteError.invalidEvidence("nonsecret_audit_event_categories")
        }
    }

    public static func validateDefaultDenyAudit(_ evidence: DssePolicyDrivenHandleNewFlowAuditEvidence) throws {
        try validateCommonAuditShape(evidence)
        guard evidence.status == "ok",
              evidence.providerRuntimeSessionKeyKind == providerRuntimeSessionKeyKind,
              evidence.providerRuntimeSessionKey == providerRuntimeSessionKey,
              evidence.providerRuntimeFlowRole == "default_deny_no_matching_rule",
              evidence.providerRuntimeSequenceIndex == 2,
              evidence.policyDecisionCategory == "default_deny",
              evidence.policyDecisionAction == NetworkExtensionContract.actionDeny,
              evidence.policyDecisionReason == NetworkExtensionContract.reasonNoMatch,
              evidence.handleNewFlowReturnAction == HandleNewFlowTakeoverContract.deniedReturnAction,
              !evidence.acceptFlow,
              evidence.connectorRouteGate == "not_applicable",
              evidence.privateAppRouteDecision == "not_applicable",
              evidence.runtimeCopyEndpointPassthroughDecision == "not_applicable",
              !evidence.edgePortFlowReentryObserved,
              !evidence.edgeTCPConnectCompleted,
              evidence.edgeTCPConnectAddressFamily == "not_applicable",
              evidence.edgeTransportRoundTripGate == "not_started",
              evidence.copyRoundTripGate == "not_started",
              evidence.bytesUpGate == "zero",
              evidence.bytesDownGate == "zero",
              evidence.privateAppResponseGate == "not_observed",
              evidence.copyAttemptGate == "closed_without_copy",
              evidence.defaultDenyGate == "closed_without_copy",
              evidence.defaultDenyPathEvidenceState == .metadataOnlyRecorded,
              evidence.denyClosedWithoutCopy,
              evidence.protectionTriggerCategory == DssePolicyDrivenHandleNewFlowAuditEvidence.protectionTriggerNotApplicable,
              !evidence.copyStarted,
              !evidence.networkExtensionFlowOpened,
              !evidence.edgeTunnelOpenStarted,
              !evidence.tcpPayloadCopyStarted,
              !evidence.flowPayloadReadStarted,
              !evidence.flowPayloadWriteStarted,
              evidence.bytesUp == 0,
              evidence.bytesDown == 0,
              evidence.auditMetadataOnlyGate == "ok",
              evidence.secretLeakGate == "ok",
              evidence.runtimeOverclaimGate == "ok",
              evidence.flowCopyOverclaimGate == "ok",
              evidence.noSecretAttestation else {
            throw DssePolicyDrivenHandleNewFlowAuditEvidenceWriteError.invalidEvidence("default_deny_audit_gate")
        }
        try validateClaimAndRawFlagsFalse(evidence)
        let requiredEvents = [
            "policy_decision_evaluated",
            "default_deny_closed_without_copy",
            "metadata_only_audit_emitted"
        ]
        guard requiredEvents.allSatisfy({ evidence.nonsecretAuditEventCategories.contains($0) }) else {
            throw DssePolicyDrivenHandleNewFlowAuditEvidenceWriteError.invalidEvidence("nonsecret_audit_event_categories")
        }
    }

    public static func validateProtectionAudit(_ evidence: DssePolicyDrivenHandleNewFlowAuditEvidence) throws {
        try validateCommonAuditShape(evidence)
        let requiredReasonCodes = Set([
            NetworkExtensionContract.reasonCodeRansomwareProtectionModeActive,
            NetworkExtensionContract.reasonCodeLateralMovementProtocolAnomaly
        ])
        guard evidence.status == "ok",
              evidence.providerRuntimeSessionKeyKind == providerRuntimeSessionKeyKind,
              evidence.providerRuntimeSessionKey == providerRuntimeSessionKey,
              evidence.providerRuntimeFlowRole == "protection_block_closed_without_copy",
              evidence.providerRuntimeSequenceIndex == 3,
              evidence.policyDecisionCategory == "protection_block",
              evidence.policyDecisionAction == NetworkExtensionContract.actionDeny,
              evidence.policyDecisionReason == NetworkExtensionContract.reasonProtectionMatched,
              evidence.handleNewFlowReturnAction == HandleNewFlowTakeoverContract.deniedReturnAction,
              !evidence.acceptFlow,
              evidence.connectorRouteGate == "not_applicable",
              evidence.privateAppRouteDecision == "not_applicable",
              evidence.runtimeCopyEndpointPassthroughDecision == "not_applicable",
              !evidence.edgePortFlowReentryObserved,
              !evidence.edgeTCPConnectCompleted,
              evidence.edgeTCPConnectAddressFamily == "not_applicable",
              evidence.edgeTransportRoundTripGate == "not_started",
              evidence.copyRoundTripGate == "not_started",
              evidence.bytesUpGate == "zero",
              evidence.bytesDownGate == "zero",
              evidence.privateAppResponseGate == "not_observed",
              evidence.copyAttemptGate == "protection_closed_without_copy",
              evidence.defaultDenyGate == "not_applicable_protection_matched",
              evidence.defaultDenyPathEvidenceState == .notApplicable,
              evidence.denyClosedWithoutCopy,
              evidence.protectionGate == "closed_without_copy",
              evidence.protectionBlockedWithoutCopy,
              evidence.protectionRuleSemantics == NetworkExtensionContract.protectionModeAC09RansomwareLateralMovement,
              Set(evidence.protectionReasonCodes) == requiredReasonCodes,
              evidence.protectionTriggerCategory == DssePolicyDrivenHandleNewFlowAuditEvidence.protectionTriggerLateralMovementProtocolAnomaly,
              !evidence.copyStarted,
              !evidence.networkExtensionFlowOpened,
              !evidence.edgeTunnelOpenStarted,
              !evidence.tcpPayloadCopyStarted,
              !evidence.flowPayloadReadStarted,
              !evidence.flowPayloadWriteStarted,
              evidence.bytesUp == 0,
              evidence.bytesDown == 0,
              evidence.auditMetadataOnlyGate == "ok",
              evidence.secretLeakGate == "ok",
              evidence.runtimeOverclaimGate == "ok",
              evidence.flowCopyOverclaimGate == "ok",
              evidence.noSecretAttestation else {
            throw DssePolicyDrivenHandleNewFlowAuditEvidenceWriteError.invalidEvidence("protection_audit_gate")
        }
        try validateClaimAndRawFlagsFalse(evidence)
        let requiredEvents = [
            "policy_decision_evaluated",
            "ac09_protection_rule_matched",
            NetworkExtensionContract.reasonCodeRansomwareProtectionModeActive,
            NetworkExtensionContract.reasonCodeLateralMovementProtocolAnomaly,
            "protection_closed_without_copy",
            "metadata_only_audit_emitted",
            "metadata_only_protection_audit_emitted"
        ]
        guard requiredEvents.allSatisfy({ evidence.nonsecretAuditEventCategories.contains($0) }) else {
            throw DssePolicyDrivenHandleNewFlowAuditEvidenceWriteError.invalidEvidence("nonsecret_audit_event_categories")
        }
    }

    private static func validateCommonAuditShape(_ evidence: DssePolicyDrivenHandleNewFlowAuditEvidence) throws {
        guard evidence.schemaVersion == DssePolicyDrivenHandleNewFlowAuditEvidence.schemaVersion else {
            throw DssePolicyDrivenHandleNewFlowAuditEvidenceWriteError.invalidEvidence("schema_version")
        }
        guard evidence.evidenceKind == "policy_driven_handle_new_flow_inprocess_audit" else {
            throw DssePolicyDrivenHandleNewFlowAuditEvidenceWriteError.invalidEvidence("evidence_kind")
        }
        let allowedProtectionTriggers = [
            DssePolicyDrivenHandleNewFlowAuditEvidence.protectionTriggerLateralMovementProtocolAnomaly,
            DssePolicyDrivenHandleNewFlowAuditEvidence.protectionTriggerNotApplicable,
            DssePolicyDrivenHandleNewFlowAuditEvidence.protectionTriggerUnknownNonsecret
        ]
        guard allowedProtectionTriggers.contains(evidence.protectionTriggerCategory) else {
            throw DssePolicyDrivenHandleNewFlowAuditEvidenceWriteError.invalidEvidence("protection_trigger_category")
        }
    }

    private static func validateClaimAndRawFlagsFalse(_ evidence: DssePolicyDrivenHandleNewFlowAuditEvidence) throws {
        let claimFlags = [
            evidence.realEdgeConnectorProductClaimed,
            evidence.flowTunneledClaimed,
            evidence.flowDeniedClaimed,
            evidence.ransomwareProtectionActiveClaimed,
            evidence.realTLSInterceptionClaimed,
            evidence.certificateIssuanceClaimed,
            evidence.productionPrivateAppEnforcementClaimed,
            evidence.productionDefaultDenyEnforcementClaimed,
            evidence.rawLogsIncluded,
            evidence.rawCommandOutputIncluded,
            evidence.rawNEFlowIncluded,
            evidence.hostUserPayloadIncluded,
            evidence.destinationIPIncluded,
            evidence.credentialsIncluded,
            evidence.packetCaptureIncluded,
            evidence.appleIdentifierIncluded
        ]
        guard claimFlags.allSatisfy({ $0 == false }) else {
            throw DssePolicyDrivenHandleNewFlowAuditEvidenceWriteError.invalidEvidence("claim_or_raw_flag")
        }
    }
}

private enum FlowCopySkeletonContract {
    static let skeleton = "drive_live_runtime_copy_real_edge_transport_configured_reviewed"
    static let implementation = DsseLocalRuntimeCopyImplementationContract.implementation
    static let notStartedImplementation = DsseLocalRuntimeCopyImplementationContract.notStarted
    static let guardContract = "requires_tenant_scope_connection_registry_byte_cap_idle_timeout_close_cleanup_backpressure_before_enablement"
}

private enum HandleNewFlowTakeoverContract {
    static let flowHandling = "take_over_matched_tcp_flow_live_copy_real_edge_transport_reviewed"
    static let contract = "extract_decide_take_over_matched_tcp_live_copy"
    static let matchedReturnAction = "take_over_matched_flow_live_copy_real_edge_transport_reviewed"
    static let acceptedTunneledCopyReturnAction = "accepted_tunneled_copy"
    static let deniedReturnAction = "deny_closed_no_copy"

    static func matchedTunnel(_ providerResult: ProviderFlowResult) -> Bool {
        providerResult.providerAction == .openTunnel &&
            providerResult.decision.action == NetworkExtensionContract.actionTunnel
    }
}

private enum AppProxyPackagingEntitlementContract {
    static let source = "m629_system_extension_packaging_entitlement_contract"
    static let requiredNetworkExtensionEntitlement = "app-proxy-provider"
}

private enum AppProxyPackagingIdentityContract {
    static let source = "m568_system_extension_packaging_identity_contract"
    static let requiredContainerBundleID = "example.dsse.agent"
    static let requiredSystemExtensionBundleID = "example.dsse.agent.networkextension"
    static let requiredNetworkExtensionPoint = "com.apple.networkextension.app-proxy"
    static let requiredPrincipalClass = "DsseAppProxyProviderSkeleton.DsseAppProxyProvider"
}

private enum AppProxyPackagingInstallDistributionContract {
    static let source = "m608_system_extension_packaging_distribution_contract"
    static let requiredDistributionStatus = "not_distributed_compile_only"
}

private enum AppProxyPackagingRollbackContract {
    static let source = "m609_system_extension_packaging_rollback_contract"
    static let requiredRollbackPlanStatus = "runbook_only_not_executed"
}

private enum AppProxyPackagingSigningNotarizationContract {
    static let source = "m610_system_extension_packaging_signing_notarization_contract"
    static let requiredSigningPlanStatus = "runbook_only_not_executed"
    static let requiredNotarizationStatus = "not_submitted"
}

private enum AppProxyPackagingAppleCapabilityContract {
    static let source = "m611_system_extension_packaging_apple_capability_contract"
    static let requiredAppleCapabilityEvidenceStatus = "not_evidenced_in_artifact"
}

private enum AppProxyPackagingOwnerGroupContract {
    static let source = "m612_system_extension_packaging_owner_group_contract"
    static let requiredAgentConfigDir = "/Library/Application Support/Dsse"
    static let requiredExpectedConfigOwner = "root"
    static let requiredExpectedConfigGroup = "wheel"
    static let requiredProductionConfigDirectoryStatus = "not_created_compile_only"
    static let requiredProductionConfigOwnerGroupStatus = "expected_values_only_not_verified"
}

private enum AppProxyPackagingPermissionContract {
    static let source = "m613_system_extension_packaging_permission_contract"
    static let requiredExpectedConfigDirectoryMode = "0750"
    static let requiredProductionConfigPermissionStatus = "expected_value_only_not_verified"
}

private enum AppProxyPackagingFilePermissionContract {
    static let source = "m614_system_extension_packaging_file_permission_contract"
    static let requiredExpectedConfigFileMode = "0640"
    static let requiredProductionConfigFilePermissionStatus = "expected_value_only_not_verified"
}

private enum FlowCopyGuardSkeletonContract {
    static let status = "guard_enforced_local_compile_test_reviewed"
    static let implementation = "live_runtime_copy_guard_enforced_local_compile_test"
    static let maxConnectTimeoutMillis = 30_000
    static let maxConnectionLifetimeMillis = 3_600_000
    static let maxByteCapBytes: Int64 = 1_073_741_824
    static let maxIdleTimeoutMillis = 300_000
    static let maxConcurrentConnections = 1_024
    static let backpressureQueueCapacity = 16
    static let backpressureStrategy = "bounded_stream_channel_fail_closed_on_overflow"
    static let tenantScopeSource = "agent_config_and_signed_rules_manifest"
    static let tenantScopeBoundary = "tenant_id_must_be_resolved_before_connection_registry_and_copy_enablement"
    static let humanValidationPrerequisitesStatus = "blocked_until_transparent_proxy_migration_review_and_flow_observation"
    static let humanValidationBoundary = "transparent_proxy_migration_review_and_flow_observation_required_before_flow_copy_runtime"
    static let humanValidationTaskID = "ne-app-proxy-runtime-smoke-prerequisites"
    static let requiredAuditEvents = [
        "flow_copy_started",
        "flow_copy_byte_cap_exceeded",
        "flow_copy_idle_timeout",
        "flow_copy_backpressure_overflow_closed",
        "flow_copy_tenant_scope_mismatch",
        "flow_copy_closed"
    ]

    static func make() -> DsseFlowCopyGuardSkeleton {
        DsseFlowCopyGuardSkeleton(
            status: status,
            implementation: implementation,
            copyEnablementReady: false,
            acceptFlowBeforeGuardReady: false,
            connectionRegistryRequired: true,
            connectionRegistryStatus: status,
            connectionRegistrySkeleton: ConnectionRegistryCompileSkeletonContract.make(),
            byteCapRequired: true,
            maxByteCapBytes: maxByteCapBytes,
            idleTimeoutRequired: true,
            maxIdleTimeoutMillis: maxIdleTimeoutMillis,
            closeCleanupRequired: true,
            closeCleanupStatus: status,
            backpressureRequired: true,
            backpressureStrategy: backpressureStrategy,
            backpressureQueueCapacity: backpressureQueueCapacity,
            tenantScopeRequired: true,
            tenantScopeStatus: status,
            tenantScopeSource: tenantScopeSource,
            tenantScopeRuntimeResolved: false,
            tenantScopeBoundary: tenantScopeBoundary,
            auditEventsRequired: true,
            auditEventContractStatus: status,
            requiredAuditEvents: requiredAuditEvents,
            networkExtensionFlowOpened: false,
            edgeTunnelOpenStarted: false,
            tcpPayloadCopyStarted: false,
            flowPayloadReadStarted: false,
            flowPayloadWriteStarted: false,
            reviewBoundaryRequiredBeforeRuntime: true,
            humanValidationPrerequisitesRequired: true,
            humanValidationPrerequisitesStatus: humanValidationPrerequisitesStatus,
            humanValidationBoundary: humanValidationBoundary,
            humanValidationTaskID: humanValidationTaskID
        )
    }
}

private enum ConnectionRegistryCompileSkeletonContract {
    static let sourceContract = "m510_tcp_connection_registry_contract"
    static let requiredOperations = [
        "open",
        "record_data",
        "close",
        "close_expired",
        "count"
    ]
    static let localCloseReasons = [
        "byte_cap_exceeded",
        "idle_timeout_exceeded",
        "lifetime_exceeded",
        "concurrent_cap_exceeded"
    ]

    static func make() -> DsseConnectionRegistryCompileSkeleton {
        DsseConnectionRegistryCompileSkeleton(
            status: FlowCopyGuardSkeletonContract.status,
            implementation: FlowCopyGuardSkeletonContract.implementation,
            sourceContract: sourceContract,
            runtimeConnected: true,
            tenantScopeRequiredBeforeOpen: true,
            requestIDUniquenessRequired: true,
            duplicateOpenAction: "deny_closed",
            concurrentCapRequired: true,
            maxConcurrentConnections: FlowCopyGuardSkeletonContract.maxConcurrentConnections,
            connectTimeoutRequired: true,
            maxConnectTimeoutMillis: FlowCopyGuardSkeletonContract.maxConnectTimeoutMillis,
            maxConnectionLifetimeRequired: true,
            maxConnectionLifetimeMillis: FlowCopyGuardSkeletonContract.maxConnectionLifetimeMillis,
            byteCapRequired: true,
            maxByteCapBytes: FlowCopyGuardSkeletonContract.maxByteCapBytes,
            idleTimeoutRequired: true,
            maxIdleTimeoutMillis: FlowCopyGuardSkeletonContract.maxIdleTimeoutMillis,
            closeCleanupRequired: true,
            closeMetricsRequired: true,
            requiredOperations: requiredOperations,
            localCloseReasons: localCloseReasons,
            networkExtensionFlowReadWriteStarted: false,
            edgeTunnelOpenStarted: false,
            reviewBoundaryRequiredBeforeRuntime: true
        )
    }
}

public func dsseAppProxyProviderCompileContract() -> DsseAppProxyProviderCompileContract {
    DsseAppProxyProviderCompileContract(
        status: "ok",
        providerClass: "DsseAppProxyProvider",
        providerSuperclass: "NETransparentProxyProvider",
        runtimeProvider: .transparentProxyProvider,
        compileOnly: true,
        runtimeEntitlementRequired: true,
        systemExtensionPackagingEntitlementContractRequired: true,
        systemExtensionPackagingEntitlementContractSource: AppProxyPackagingEntitlementContract.source,
        requiredNetworkExtensionEntitlement: AppProxyPackagingEntitlementContract.requiredNetworkExtensionEntitlement,
        requiredContainerSystemExtensionInstallEntitlement: true,
        packetTunnelProviderEntitlementAllowed: false,
        packagingEntitlementReviewBoundaryRequiredBeforeRuntime: true,
        systemExtensionPackagingIdentityContractRequired: true,
        systemExtensionPackagingIdentityContractSource: AppProxyPackagingIdentityContract.source,
        requiredContainerBundleID: AppProxyPackagingIdentityContract.requiredContainerBundleID,
        requiredSystemExtensionBundleID: AppProxyPackagingIdentityContract.requiredSystemExtensionBundleID,
        requiredNetworkExtensionPoint: AppProxyPackagingIdentityContract.requiredNetworkExtensionPoint,
        requiredPrincipalClass: AppProxyPackagingIdentityContract.requiredPrincipalClass,
        packagingIdentityReviewBoundaryRequiredBeforeRuntime: true,
        systemExtensionPackagingInstallDistributionContractRequired: true,
        systemExtensionPackagingInstallDistributionContractSource: AppProxyPackagingInstallDistributionContract.source,
        requiredDistributionStatus: AppProxyPackagingInstallDistributionContract.requiredDistributionStatus,
        requiredMDMPayloadGenerated: false,
        requiredSystemExtensionInstallStarted: false,
        requiredSystemExtensionActivated: false,
        requiredRuntimeSmokeStarted: false,
        packagingInstallDistributionReviewBoundaryRequiredBeforeRuntime: true,
        systemExtensionPackagingRollbackContractRequired: true,
        systemExtensionPackagingRollbackContractSource: AppProxyPackagingRollbackContract.source,
        requiredRollbackPlanStatus: AppProxyPackagingRollbackContract.requiredRollbackPlanStatus,
        requiredRollbackSupportBundleCollected: false,
        requiredRollbackMDMPayloadRemoved: false,
        requiredSystemExtensionDeactivationStarted: false,
        requiredSystemExtensionUninstallStarted: false,
        requiredAgentConfigCleanupStarted: false,
        packagingRollbackReviewBoundaryRequiredBeforeRuntime: true,
        systemExtensionPackagingSigningNotarizationContractRequired: true,
        systemExtensionPackagingSigningNotarizationContractSource: AppProxyPackagingSigningNotarizationContract.source,
        requiredSigningPlanStatus: AppProxyPackagingSigningNotarizationContract.requiredSigningPlanStatus,
        requiredCodesignStarted: false,
        requiredCodesignVerificationStarted: false,
        requiredNotarizationStatus: AppProxyPackagingSigningNotarizationContract.requiredNotarizationStatus,
        requiredNotarizationTicketStapled: false,
        requiredProvisioningProfileEmbedded: false,
        packagingSigningNotarizationReviewBoundaryRequiredBeforeRuntime: true,
        systemExtensionPackagingAppleCapabilityContractRequired: true,
        systemExtensionPackagingAppleCapabilityContractSource: AppProxyPackagingAppleCapabilityContract.source,
        requiredAppleCapabilityEvidenceStatus: AppProxyPackagingAppleCapabilityContract.requiredAppleCapabilityEvidenceStatus,
        requiredAppleCapabilityRequestSubmissionEvidenced: false,
        requiredNetworkExtensionCapabilityApprovalEvidenced: false,
        requiredSystemExtensionInstallCapabilityApprovalEvidenced: false,
        packagingAppleCapabilityReviewBoundaryRequiredBeforeRuntime: true,
        systemExtensionPackagingOwnerGroupContractRequired: true,
        systemExtensionPackagingOwnerGroupContractSource: AppProxyPackagingOwnerGroupContract.source,
        requiredAgentConfigDir: AppProxyPackagingOwnerGroupContract.requiredAgentConfigDir,
        requiredExpectedConfigOwner: AppProxyPackagingOwnerGroupContract.requiredExpectedConfigOwner,
        requiredExpectedConfigGroup: AppProxyPackagingOwnerGroupContract.requiredExpectedConfigGroup,
        requiredProductionConfigDirectoryStatus: AppProxyPackagingOwnerGroupContract.requiredProductionConfigDirectoryStatus,
        requiredProductionConfigOwnerGroupStatus: AppProxyPackagingOwnerGroupContract.requiredProductionConfigOwnerGroupStatus,
        requiredProductionConfigOwnerGroupVerificationStarted: false,
        packagingOwnerGroupReviewBoundaryRequiredBeforeRuntime: true,
        systemExtensionPackagingPermissionContractRequired: true,
        systemExtensionPackagingPermissionContractSource: AppProxyPackagingPermissionContract.source,
        requiredExpectedConfigDirectoryMode: AppProxyPackagingPermissionContract.requiredExpectedConfigDirectoryMode,
        requiredProductionConfigPermissionStatus: AppProxyPackagingPermissionContract.requiredProductionConfigPermissionStatus,
        requiredProductionConfigPermissionVerificationStarted: false,
        packagingPermissionReviewBoundaryRequiredBeforeRuntime: true,
        systemExtensionPackagingFilePermissionContractRequired: true,
        systemExtensionPackagingFilePermissionContractSource: AppProxyPackagingFilePermissionContract.source,
        requiredExpectedConfigFileMode: AppProxyPackagingFilePermissionContract.requiredExpectedConfigFileMode,
        requiredProductionConfigFilePermissionStatus: AppProxyPackagingFilePermissionContract.requiredProductionConfigFilePermissionStatus,
        requiredProductionConfigFilePermissionVerificationStarted: false,
        packagingFilePermissionReviewBoundaryRequiredBeforeRuntime: true,
        flowHandling: HandleNewFlowTakeoverContract.flowHandling,
        flowExtractionContract: "tcp_host_port_required",
        startLifecycleSource: "agent_config_path_option",
        stopLifecycleClearsState: true,
        sourceBundleIDTrusted: false,
        unsupportedFlowAction: "deny",
        handleNewFlowContract: HandleNewFlowTakeoverContract.contract,
        handleNewFlowReturnAction: HandleNewFlowTakeoverContract.matchedReturnAction,
        flowCopySkeleton: FlowCopySkeletonContract.skeleton,
        flowCopyImplementation: FlowCopySkeletonContract.implementation,
        tcpPayloadCopyStarted: false,
        flowCopyReviewBoundaryRequired: true,
        flowCopyGuardContract: FlowCopySkeletonContract.guardContract,
        flowCopyGuardSkeleton: FlowCopyGuardSkeletonContract.make()
    )
}

@available(macOS 13.0, *)
public final class DsseAppProxyProvider: NETransparentProxyProvider {
    public static let authorityExtractionRuntimeMarker = "hostport_described_port_preferred"

    public static let agentConfigPathOptionKey = "agent_config_path"
    public static let legacyAgentConfigPathOptionKey = "AgentConfigPath"
    public static let productionAgentConfigDirectory = "/Library/Application Support/Dsse"
    public static let productionAgentConfigPath = "/Library/Application Support/Dsse/agent_config.json"
    // Hardcoded default domain passthrough: intentionally EMPTY (retired, like the app self-exclusions below).
    // A hardcoded, invisible list that silently keeps whole domains OUT of the interception/default-deny path
    // violates steer-all/decrypt-all: it let AI-chat traffic (openai.com/chatgpt.com and the old GPT/anthropic
    // dev-agent groups) escape inspection with no admin-visible policy — exactly the shadow-AI blind spot the
    // product exists to close. What must bypass is now expressed ONLY as VISIBLE, configurable input:
    //  - the AI dev-agent's own self-traffic → the root-owned agent_config passthrough list / the
    //    signing-identifier self-exclusion (hostname-independent, the correct scope: the AGENT'S process, not a
    //    domain for every client on the device), and/or the Edge's admin-managed TLS-bypass;
    //  - user-protected services under test → admin App-Exceptions policy or the intercept allowlist
    //    (network_extension_intercept_only_domains).
    // Domain passthrough still works when supplied via agent_config (see transparentPassthroughDomains(agentConfigPath:)),
    // but there is NO built-in default — nothing is passed through invisibly.
    static let defaultTransparentPassthroughDomains: [String] = []

    // Hardcoded default app self-exclusions: intentionally EMPTY (G3 — the dev scaffold was retired once the
    // admin-managed steer-exclusion feature was proven). The product ships NO built-in app exclusions: what an
    // endpoint excludes from steering is set by admin policy (App Exceptions / `subject:`/`team-id:`…) and the
    // device's own loop-prevention floor (the agent's egress + any co-located edge egress), which is supplied via
    // the root-owned agent_config local list — NOT hardcoded here. (Earlier this carried a developer-tool
    // scaffold; it is now expressed, if needed, as a visible admin policy or, in the lab, the Edge's
    // *.anthropic.com TLS-bypass — never an invisible hardcoded app id.)
    static let defaultSelfExclusionSourceAppSigningIdentifiers: [String] = []

    private let lifecycleManager: ProviderLifecycleManager
    private let runtimeCopyDriver: DsseLocalRuntimeCopyDriver
    // Lock-protected: handleNewFlow reads the transport on the flow queue while the region-failover controller
    // swaps it from its own queue on a region change (live transport rebuild, no provider restart). New flows
    // pick up the new region; in-flight flows ride their captured transport until they close.
    private let runtimeCopyTransportLock = NSLock()
    private var _runtimeCopyTransport: any DsseLocalRuntimeCopyTransport
    private var runtimeCopyTransport: any DsseLocalRuntimeCopyTransport {
        get { runtimeCopyTransportLock.lock(); defer { runtimeCopyTransportLock.unlock() }; return _runtimeCopyTransport }
        set { runtimeCopyTransportLock.lock(); _runtimeCopyTransport = newValue; runtimeCopyTransportLock.unlock() }
    }
    // A startup enrolment failure is separate from reachability: a healthy-region event cannot clear it.
    private var _startupEnforcementBlocked = false
    private var startupEnforcementBlocked: Bool {
        get { runtimeCopyTransportLock.lock(); defer { runtimeCopyTransportLock.unlock() }; return _startupEnforcementBlocked }
        set { runtimeCopyTransportLock.lock(); _startupEnforcementBlocked = newValue; runtimeCopyTransportLock.unlock() }
    }
    // Set by region failover when no allowed region is healthy or admission is revoked.
    private var _regionEgressBlocked = false
    private var regionEgressBlocked: Bool {
        get { runtimeCopyTransportLock.lock(); defer { runtimeCopyTransportLock.unlock() }; return _regionEgressBlocked }
        set { runtimeCopyTransportLock.lock(); _regionEgressBlocked = newValue; runtimeCopyTransportLock.unlock() }
    }
    // The CAUSE of the block, so fail-open can distinguish REACHABILITY from ADMISSION. Set true only on .denied
    // (device revoked/not-enrolled). LAB fail-open exists to keep a dev machine usable when the Edge/region is
    // UNREACHABLE — it must NEVER apply to a revocation (that would let a kill-switch be evaded via direct egress).
    // So when this is true, handleNewFlow always deny_closes regardless of fail-open arming.
    private var _regionEgressDeniedAdmission = false
    private var regionEgressDeniedAdmission: Bool {
        get { runtimeCopyTransportLock.lock(); defer { runtimeCopyTransportLock.unlock() }; return _regionEgressDeniedAdmission }
        set { runtimeCopyTransportLock.lock(); _regionEgressDeniedAdmission = newValue; runtimeCopyTransportLock.unlock() }
    }
    // Read/write the (blocked, admissionDenied) PAIR under ONE lock acquisition so handleNewFlow never observes a
    // torn state (blocked=true with a stale admissionDenied=false), which would let a revocation fail-open in the
    // set gap. Writers must set both together; the reader reads both together.
    private func setRegionEgress(blocked: Bool, admissionDenied: Bool) {
        runtimeCopyTransportLock.lock()
        _regionEgressBlocked = blocked
        _regionEgressDeniedAdmission = admissionDenied
        runtimeCopyTransportLock.unlock()
    }
    private func regionEgressState() -> (blocked: Bool, admissionDenied: Bool) {
        runtimeCopyTransportLock.lock()
        defer { runtimeCopyTransportLock.unlock() }
        return (_regionEgressBlocked, _regionEgressDeniedAdmission)
    }
    private var runtimeCopyEvidenceWriter: (any DsseLocalRuntimeCopyEvidenceWriting)?
    private var runtimeDiagnosticWriter: DsseProviderRuntimeDiagnosticWriter?
    private var labRawAuthorityDiagnosticWriter: DsseLabRawAuthorityDiagnosticWriter?
    private var policyDrivenAuditEvidenceWriter: DssePolicyDrivenHandleNewFlowAuditEvidenceWriter?
    private var runtimeCopyPassthroughEndpoint: DsseRuntimeCopyPassthroughEndpoint?
    private var runtimeCopyDownstreamPassthroughPolicy: DsseRuntimeCopyDownstreamPassthroughPolicy?
    private var transparentPassthroughDomains: [String]
    // ★★★ AND THE ADDRESSES THOSE NAMES RESOLVE TO (2026-08-30, measured on a real Mac before shipping the
    // fix that needed it). The list is matched against the flow's remote host — and a browser hands this
    // provider an ADDRESS, not a name: it resolved the name itself and connected to the result.
    // `com.apple.curl … remote_host_kind=ipv4_literal`, `headless_shell … remote_host_kind=ipv4_literal`.
    // So a deployment naming its own Console here would have been steered anyway, in every browser, and
    // the decision said nothing because it only spoke when it matched. Naming a destination has to mean
    // the destination, whichever half of it the client hands over.
    private var transparentPassthroughAddresses: Set<String> = []
    // Read on the flow queue, written by the refresh below on a background queue — the same reason
    // runtimeCopyTransport is behind a lock. A torn read here decides whether a flow is steered.
    private let transparentPassthroughLock = NSLock()
    private var transparentPassthroughRefreshGeneration = 0
    // Lock-protected: handleNewFlow reads this on the flow queue while the agent-policy poller swaps it from
    // its own queue (live, server-issued exclusion updates with no provider restart).
    private let selfExclusionLock = NSLock()
    private var _selfExclusionPolicy: DsseSelfExclusionPolicy?
    private var selfExclusionPolicy: DsseSelfExclusionPolicy? {
        get { selfExclusionLock.lock(); defer { selfExclusionLock.unlock() }; return _selfExclusionPolicy }
        set { selfExclusionLock.lock(); _selfExclusionPolicy = newValue; selfExclusionLock.unlock() }
    }
    // The NE pulls + verifies + applies the server-signed exclusion set itself (production mechanism; no
    // client-side command provisions it). nil when no pin is configured.
    private var agentPolicyPoller: DsseAgentPolicyPoller?
    private var updateCourier: DsseUpdateCourier?
    // Endpoint liveness. Held so it lives as long as the provider and stops with it — when this stops beating
    // the device goes dark at the Edge, which is the entire point.
    private var deviceHeartbeat: DsseDeviceHeartbeatSender?
    private var certificateRenewalScheduler: DsseCertificateRenewalScheduler?
    // Multi-region region failover: the NE pulls the signed region list, probes each region, selects the current
    // region, and on a region change LIVE-REBUILDS the runtime-copy transport so new flows steer through it (deny
    // when no healthy region remains). See startRegionFailoverController.
    private var regionEndpointPoller: DsseRegionEndpointPoller?
    private var regionController: DsseRegionTransportController?
    private var observeOnlyPassthroughAll: Bool = false
    private var interceptOnlyDomains: [String] = []
    // LAB fail-open, ARMED (enable key AND acknowledgment): when true, a flow the Edge cannot carry egresses direct
    // instead of deny_closed. Set at startProxy from failOpenPosture.armed — an enable without the acknowledgment
    // leaves this false (refused). See DsseFailOpenPosture / DsseLabFailOpenAgentConfig.
    private var failOpenArmed: Bool = false

    public override init() {
        self.lifecycleManager = ProviderLifecycleManager()
        self.runtimeCopyDriver = DsseLocalRuntimeCopyDriver()
        self._runtimeCopyTransport = DsseDeviceValidationPendingRuntimeCopyTransport()
        self.runtimeCopyEvidenceWriter = nil
        self.runtimeDiagnosticWriter = nil
        self.labRawAuthorityDiagnosticWriter = nil
        self.policyDrivenAuditEvidenceWriter = nil
        self.runtimeCopyPassthroughEndpoint = nil
        self.runtimeCopyDownstreamPassthroughPolicy = nil
        self.transparentPassthroughDomains = Self.defaultTransparentPassthroughDomains
        self.transparentPassthroughAddresses = []
        // _selfExclusionPolicy / agentPolicyPoller default to nil (optional stored properties).
        self.observeOnlyPassthroughAll = false
        self.interceptOnlyDomains = []
        self.failOpenArmed = false
        super.init()
    }

    public override func startProxy(options: [String: Any]? = nil, completionHandler: @escaping (Error?) -> Void) {
        providerRuntimeLog("startProxy entered")
        runtimeCopyPassthroughEndpoint = nil
        runtimeCopyDownstreamPassthroughPolicy = nil
        guard let agentConfigPath = Self.agentConfigPath(from: options) else {
            providerRuntimeLog("startProxy lifecycle_failed=missing_agent_config_path")
            completionHandler(DsseAppProxyProviderError.missingAgentConfigPath)
            return
        }
        guard let validatedAgentConfigPath = Self.validatedAgentConfigPath(agentConfigPath) else {
            providerRuntimeLog("startProxy lifecycle_failed=invalid_agent_config_path")
            completionHandler(DsseAppProxyProviderError.invalidAgentConfigPath(agentConfigPath))
            return
        }
        let state = lifecycleManager.start(agentConfigPath: validatedAgentConfigPath)
        if state.status == .running {
            runtimeCopyTransport = Self.runtimeCopyTransport(agentConfigPath: validatedAgentConfigPath)
            runtimeCopyPassthroughEndpoint = Self.runtimeCopyPassthroughEndpoint(agentConfigPath: validatedAgentConfigPath)
            runtimeCopyDownstreamPassthroughPolicy = Self.runtimeCopyDownstreamPassthroughPolicy(
                agentConfigPath: validatedAgentConfigPath
            )
            transparentPassthroughDomains = Self.transparentPassthroughDomains(agentConfigPath: validatedAgentConfigPath)
            transparentPassthroughAddresses = Self.addressesFor(domains: transparentPassthroughDomains)
            startTransparentPassthroughRefresh(agentConfigPath: validatedAgentConfigPath)
            selfExclusionPolicy = Self.selfExclusionPolicy(agentConfigPath: validatedAgentConfigPath)
            observeOnlyPassthroughAll = Self.observeOnlyPassthroughAll(agentConfigPath: validatedAgentConfigPath)
            interceptOnlyDomains = Self.interceptOnlyDomains(agentConfigPath: validatedAgentConfigPath)
            // ★★★ THE DEPLOYMENT'S OWN DOCUMENT, READ BEFORE ANYTHING IS DECIDED (2026-08-28). Resolved here so
            // the one line an operator greps says whether the profile they downloaded from the Console reached
            // this Mac — and, when it did not, which of the reasons it was.
            let installProfile = DsseInstallProfileApplication.inForce(
                agentConfigPath: validatedAgentConfigPath,
                configDirectory: URL(fileURLWithPath: validatedAgentConfigPath).deletingLastPathComponent(),
                log: providerRuntimeLog)
            var failOpenPosture = Self.failOpenPosture(agentConfigPath: validatedAgentConfigPath)
            // ★★ THE DEPLOYMENT MAY CLOSE A POSTURE THE DEVICE OPENED, NEVER THE REVERSE. A fleet told to carry
            // nothing when no Edge answers must not be reopened by editing a file on one laptop; and a profile
            // saying fail-open still does not arm anything by itself — the device's own acknowledgement is
            // required, so shipping a profile can never take a fleet out of enforcement on its own.
            if let closed = DsseInstallProfileApplication.failOpenOverride(profile: installProfile), closed == false,
               failOpenPosture.armed {
                providerRuntimeLog("install_profile fail_open_disarmed_by_profile posture=\(installProfile?.posture ?? "-") — the deployment's profile says this device does not carry traffic when no Edge can be reached, which overrides the local acknowledgement")
                failOpenPosture = DsseFailOpenPosture(enableRequested: failOpenPosture.enableRequested, acknowledged: false)
            }
            failOpenArmed = failOpenPosture.armed
            providerRuntimeLog("startProxy self_exclusion_configured=\(selfExclusionPolicy?.isConfigured == true) self_exclusion_signing_identifier_count=\(selfExclusionPolicy?.signingIdentifiers.count ?? 0) self_exclusion_team_identifier_count=\(selfExclusionPolicy?.teamIdentifiers.count ?? 0) observe_only_passthrough_all=\(observeOnlyPassthroughAll) intercept_only_domain_count=\(interceptOnlyDomains.count) fail_open_enable_requested=\(failOpenPosture.enableRequested) fail_open_acknowledged=\(failOpenPosture.acknowledged) fail_open_armed=\(failOpenArmed)")
            // ★★★ SAID AT START, BECAUSE A LIST THAT NEVER MATCHES IS SILENT (2026-08-30). The
            // passthrough decision only spoke when it matched, so a deployment whose Console was named
            // here and steered anyway — every browser, because they hand over an address — produced not
            // one line to grep. What was loaded, and what it resolved to, is the evidence that the
            // authored list can actually fire; the count is the only proof this repository accepts.
            providerRuntimeLog("startProxy transparent_passthrough domain_count=\(transparentPassthroughDomains.count) address_count=\(transparentPassthroughAddresses.count) domains=\(transparentPassthroughDomains.joined(separator: ","))")
            logFailOpenPosture(failOpenPosture)
            armIdentityDependentSubsystems(agentConfigPath: validatedAgentConfigPath,
                                           installProfile: installProfile,
                                           phase: "startProxy")
            do {
                runtimeDiagnosticWriter = try DsseProviderRuntimeDiagnosticWriter(agentConfigPath: validatedAgentConfigPath)
                try runtimeDiagnosticWriter?.recordStartProxyRunning()
                providerRuntimeLog("startProxy runtime_diagnostic_writer=ready")
            } catch {
                runtimeDiagnosticWriter = nil
                providerRuntimeLog("startProxy runtime_diagnostic_writer_failed=\(providerNonsecretErrorDetail(error))")
            }
            do {
                labRawAuthorityDiagnosticWriter = try DsseLabRawAuthorityDiagnosticWriter.make(
                    agentConfigPath: validatedAgentConfigPath
                )
                if labRawAuthorityDiagnosticWriter != nil {
                    providerRuntimeLog("startProxy lab_raw_authority_diagnostic_writer=ready marker=\(DsseLabRawAuthorityDiagnosticWriter.implementationMarker)")
                } else {
                    providerRuntimeLog("startProxy lab_raw_authority_diagnostic_writer=not_configured")
                }
            } catch {
                labRawAuthorityDiagnosticWriter = nil
                providerRuntimeLog("startProxy lab_raw_authority_diagnostic_writer_failed=\(providerNonsecretErrorDetail(error))")
            }
            do {
                let diagnosticWriter = runtimeDiagnosticWriter
                runtimeCopyEvidenceWriter = try DsseLocalRuntimeCopyEvidenceWriter(
                    agentConfigPath: validatedAgentConfigPath,
                    section16EvidenceProvider: {
                        diagnosticWriter?.section16RuntimeCopyEvidenceSnapshot()
                    }
                )
                providerRuntimeLog("startProxy runtime_copy_evidence_writer=ready")
            } catch {
                runtimeCopyEvidenceWriter = nil
                providerRuntimeLog("startProxy runtime_copy_evidence_writer_failed=\(providerNonsecretErrorDetail(error))")
            }
            policyDrivenAuditEvidenceWriter = DssePolicyDrivenHandleNewFlowAuditEvidenceWriter(
                agentConfigPath: validatedAgentConfigPath
            )
            providerRuntimeLog("startProxy policy_driven_audit_evidence_writer=ready")
            providerRuntimeLog("startProxy running rules_loaded=\(state.rulesLoaded) rule_count=\(state.ruleCount)")
            guard let identityArrival = resolveDeviceIdentityForStartup(agentConfigPath: validatedAgentConfigPath) else {
                // Started, but deliberately not steering. Reported as success so the system extension is not
                // restarted in a loop over a state only an administrator can resolve.
                completionHandler(nil)
                return
            }
            startupEnforcementBlocked = identityArrival == .enforcementBlocked
            // ★★★ AN IDENTITY THAT ARRIVES DURING STARTUP MUST RE-ARM WHAT WAS DECIDED WITHOUT IT
            // (2026-08-29). See DsseStartupIdentityArrival for the measurement: on the documented install lane
            // the five subsystems above are armed BEFORE this device has a certificate, all five correctly
            // report "no (T) transport", and the enrolment that fixes that happens a fraction of a second
            // later. Nothing re-read it, so the runtime-copy transport stayed on the URLSession fallback that
            // App Transport Security will not let near a private CA, and this Mac black-holed every steered
            // flow while reporting itself dark to the Edge.
            if DsseStartupArming.mustRearmIdentityDependentSubsystems(after: identityArrival) {
                providerRuntimeLog("startProxy rearm_after_enrolment — this device enrolled during start, so the " +
                                   "subsystems decided before it had a certificate are being decided again")
                runtimeCopyTransport = Self.runtimeCopyTransport(agentConfigPath: validatedAgentConfigPath)
                armIdentityDependentSubsystems(agentConfigPath: validatedAgentConfigPath,
                                               installProfile: installProfile,
                                               phase: "rearm_after_enrolment")
            }
            let settings = Self.transparentProxyNetworkSettings(agentConfigPath: validatedAgentConfigPath)
            let includedRuleCount = settings.includedNetworkRules?.count ?? 0
            let excludedRuleCount = settings.excludedNetworkRules?.count ?? 0
            let diagnosticWriter = runtimeDiagnosticWriter
            setTunnelNetworkSettings(settings) { error in
                if let error {
                    providerRuntimeLog("startProxy transparent_network_settings_failed=\(providerNonsecretErrorDetail(error))")
                    completionHandler(error)
                    return
                }
                providerRuntimeLog("startProxy transparent_network_settings_applied included_network_rules=\(includedRuleCount) excluded_network_rules=\(excludedRuleCount)")
                do {
                    try diagnosticWriter?.recordTransparentNetworkSettingsApplied()
                } catch {
                    providerRuntimeLog("startProxy runtime_diagnostic_write_failed=\(providerNonsecretErrorDetail(error))")
                }
                completionHandler(nil)
            }
            return
        }
        providerRuntimeLog("startProxy lifecycle_failed=\(providerLifecycleFailureCategory(state.lastError))")
        completionHandler(DsseAppProxyProviderError.lifecycleFailed(state.lastError))
    }

    public override func stopProxy(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        providerRuntimeLog("stopProxy reason=\(reason.rawValue)")
        updateCourier?.stop()
        updateCourier = nil
        deviceHeartbeat?.stop()
        deviceHeartbeat = nil
        certificateRenewalScheduler?.stop()
        certificateRenewalScheduler = nil
        lifecycleManager.stop()
        runtimeCopyEvidenceWriter = nil
        runtimeDiagnosticWriter = nil
        labRawAuthorityDiagnosticWriter = nil
        policyDrivenAuditEvidenceWriter = nil
        runtimeCopyPassthroughEndpoint = nil
        runtimeCopyDownstreamPassthroughPolicy = nil
        // Bumping the generation is what stops the refresh: a timer that outlived stopProxy would keep
        // resolving, and would put a list back after this cleared it.
        transparentPassthroughLock.lock()
        transparentPassthroughRefreshGeneration += 1
        transparentPassthroughDomains = Self.defaultTransparentPassthroughDomains
        transparentPassthroughAddresses = []
        transparentPassthroughLock.unlock()
        agentPolicyPoller?.stop()
        agentPolicyPoller = nil
        regionEndpointPoller?.stop()
        regionEndpointPoller = nil
        regionController?.stop()
        regionController = nil
        selfExclusionPolicy = nil
        observeOnlyPassthroughAll = false
        interceptOnlyDomains = []
        completionHandler()
    }

    public override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        let providerRulesReloadGate = lifecycleManager.reloadIfStale()
        providerRuntimeLog("handleNewFlow provider_rules_reload_gate=\(providerRulesReloadGate)")
        do {
            try runtimeDiagnosticWriter?.recordProviderRulesReloadGate(providerRulesReloadGate)
        } catch {
            providerRuntimeLog("handleNewFlow runtime_diagnostic_write_failed=\(providerNonsecretErrorDetail(error))")
        }
        let authorityObservation = Self.authorityObservation(from: flow)
        let input = authorityObservation.input
        // Self-exclusion FIRST: the AI dev-agent's own control traffic must never
        // be intercepted, regardless of host/IP visibility, so the agent keeps
        // connectivity once the proxy is enforcing. observe-only fields below let
        // us confirm the live signing identifier and host visibility without ever
        // dropping a flow.
        let selfExclusionSigningIdentifier = Self.sourceAppSigningIdentifier(from: flow)
        // Snapshot once (the property locks) to avoid a TOCTOU between the team-id check and the decision.
        let selfExclusionPolicySnapshot = selfExclusionPolicy
        // Micro-opt + fail-closed: only resolve the (more expensive) crypto signer identity when the policy
        // actually has team-id/subject/thumbprint entries to match against. If resolution fails the fields stay
        // nil and never cross-platform-match (the app stays steered).
        let selfExclusionNeedsSignerIdentity = (selfExclusionPolicySnapshot.map {
            !$0.teamIdentifiers.isEmpty || !$0.subjectOrganizations.isEmpty || !$0.thumbprints.isEmpty
        }) ?? false
        let selfExclusionSignerIdentity: DsseSourceAppSignerIdentity? = selfExclusionNeedsSignerIdentity
            ? Self.sourceAppSignerIdentity(from: flow)
            : nil
        let selfExclusionDecision = Self.selfExclusionDecision(
            sourceAppSigningIdentifier: selfExclusionSigningIdentifier,
            signerIdentity: selfExclusionSignerIdentity,
            policy: selfExclusionPolicySnapshot
        )
        providerRuntimeLog("handleNewFlow self_exclusion_observe source_app_signing_identifier=\(selfExclusionSigningIdentifier ?? "none") source_app_team_identifier=\(selfExclusionSignerIdentity?.teamIdentifier ?? "none") source_app_subject_org=\(selfExclusionSignerIdentity?.subjectOrganization ?? "none") source_app_leaf_sha256_present=\(selfExclusionSignerIdentity?.leafSha256 != nil) remote_host_kind=\(Self.observeRemoteHostKind(input.remoteHost)) remote_port=\(input.remotePort) self_exclusion_gate=\(selfExclusionDecision.category)")
        if observeOnlyPassthroughAll {
            providerRuntimeLog("handleNewFlow pass_through=observe_only_passthrough_all")
            return false
        }
        if selfExclusionDecision.shouldPassThrough {
            providerRuntimeLog("handleNewFlow pass_through=self_exclusion_source_app")
            return false
        }
        let systemPassthroughDecision = Self.transparentSystemPassthroughDecision(input: input)
        if systemPassthroughDecision.shouldPassThrough {
            providerRuntimeLog("handleNewFlow pass_through=transparent_system_passthrough category=\(systemPassthroughDecision.category)")
            return false
        }
        let passthroughDecision = Self.runtimeCopyEndpointPassthroughDecision(
            input: input,
            endpoint: runtimeCopyPassthroughEndpoint
        )
        providerRuntimeLog("handleNewFlow runtime_copy_endpoint_passthrough_decision=\(passthroughDecision.category) edge_port_flow_reentry_observed=\(passthroughDecision.edgePortFlowReentryObserved)")
        do {
            try runtimeDiagnosticWriter?.recordRuntimeCopyEndpointPassthroughDecision(
                decisionCategory: passthroughDecision.category,
                edgePortFlowReentryObserved: passthroughDecision.edgePortFlowReentryObserved
            )
        } catch {
            providerRuntimeLog("handleNewFlow runtime_diagnostic_write_failed=\(providerNonsecretErrorDetail(error))")
        }
        if passthroughDecision.shouldPassThrough {
            providerRuntimeLog("handleNewFlow pass_through=runtime_copy_endpoint")
            do {
                try runtimeDiagnosticWriter?.recordRuntimeCopyEndpointPassThrough()
            } catch {
                providerRuntimeLog("handleNewFlow runtime_diagnostic_write_failed=\(providerNonsecretErrorDetail(error))")
            }
            return false
        }
        let downstreamPassthroughDecision = Self.runtimeCopyDownstreamPassthroughDecision(
            input: input,
            singleRule: lifecycleManager.singleRuleLabRuleDiagnostic(),
            sourceAppSigningIdentifier: Self.sourceAppSigningIdentifier(from: flow),
            policy: runtimeCopyDownstreamPassthroughPolicy
        )
        providerRuntimeLog("handleNewFlow runtime_copy_downstream_source_app_passthrough_gate=\(downstreamPassthroughDecision.category)")
        if downstreamPassthroughDecision.shouldPassThrough {
            providerRuntimeLog("handleNewFlow pass_through=runtime_copy_downstream_source_app")
            return false
        }
        transparentPassthroughLock.lock()
        let passthroughDomainsNow = transparentPassthroughDomains
        let passthroughAddressesNow = transparentPassthroughAddresses
        transparentPassthroughLock.unlock()
        let transparentPassthroughDecision = Self.transparentPassthroughDomainDecision(
            input: input,
            domains: passthroughDomainsNow,
            addresses: passthroughAddressesNow
        )
        if transparentPassthroughDecision.shouldPassThrough {
            providerRuntimeLog("handleNewFlow pass_through=transparent_passthrough_domain category=\(transparentPassthroughDecision.category)")
            return false
        }
        // A previously managed device must not lose enforcement because re-registration failed.
        // Preserve the configured exclusions above so an administrator can repair it.
        if startupEnforcementBlocked {
            providerRuntimeLog("handleNewFlow deny_closed=startup_enrolment_failed")
            Self.dropFlowForcingQUICFallback(flow)
            return true
        }
        // QUIC (UDP/443) cannot be intercepted, so steer-target flows are dropped to force a fallback
        // to TCP/TLS (the NE itself closes the ZTNA hole where QUIC escapes steering). Excluded/
        // passthrough flows already returned above, so any UDP/443 reaching here is a steer target.
        if ProviderQUICFallbackPolicy.shouldDropForcingTCPFallback(transport: input.transport, remotePort: input.remotePort) {
            providerRuntimeLog("handleNewFlow quic_drop=udp_443_forcing_tcp_fallback")
            Self.dropFlowForcingQUICFallback(flow)
            return true
        }
        let interceptAllowlistDecision = Self.interceptAllowlistDecision(
            input: input,
            interceptOnlyDomains: interceptOnlyDomains
        )
        if interceptAllowlistDecision.shouldPassThrough {
            providerRuntimeLog("handleNewFlow pass_through=intercept_allowlist category=\(interceptAllowlistDecision.category)")
            return false
        }
        let evaluation = Self.evaluateHandleNewFlow(input: input, lifecycleManager: lifecycleManager)
        let providerLoadedRulesGeneratedAt = lifecycleManager.loadedRulesGeneratedAtForDiagnostic()
        let report = Self.handleNewFlowReport(
            extraction: evaluation.extraction,
            providerResult: evaluation.providerResult,
            singleRuleLabFallbackGate: evaluation.singleRuleLabFallbackGate,
            flowAuthorityHostGate: evaluation.flowAuthorityHostGate,
            flowAuthorityPortGate: evaluation.flowAuthorityPortGate,
            singleRuleLabFallbackPortGate: evaluation.singleRuleLabFallbackPortGate
        )
        let decisionCategory = report.acceptFlow ? "accepted" : "deny_closed"
        providerRuntimeLog("handleNewFlow authority_extraction_runtime_marker=\(Self.authorityExtractionRuntimeMarker) flow_authority_endpoint_source_gate=\(authorityObservation.endpointSourceGate) flow_authority_port_source_gate=\(authorityObservation.portSourceGate) allow_flow_authority_port_match=\(evaluation.allowFlowAuthorityPortMatch)")
        providerRuntimeLog("handleNewFlow extracted=\(report.flowExtractionStatus.rawValue) extraction_reason=\(report.flowExtractionReason.rawValue) decision=\(decisionCategory) provider_decision_action=\(report.action) provider_decision_reason=\(report.reason) single_rule_lab_fallback_gate=\(evaluation.singleRuleLabFallbackGate)")
        let matchedRuleDiagnostic = lifecycleManager.ruleDiagnostic(for: evaluation.providerResult)
        do {
            try labRawAuthorityDiagnosticWriter?.recordHandleNewFlow(
                input: input,
                endpointSourceGate: authorityObservation.endpointSourceGate,
                portSourceGate: authorityObservation.portSourceGate,
                ruleDiagnostic: matchedRuleDiagnostic ?? lifecycleManager.singleRuleLabRuleDiagnostic(),
                decisionCategory: decisionCategory,
                extractionStatus: report.flowExtractionStatus.rawValue,
                extractionReason: report.flowExtractionReason.rawValue,
                providerDecisionAction: report.action,
                providerDecisionReason: report.reason,
                singleRuleLabFallbackGate: evaluation.singleRuleLabFallbackGate,
                singleRuleLabFallbackPortGate: evaluation.singleRuleLabFallbackPortGate,
                allowFlowAuthorityPortMatch: evaluation.allowFlowAuthorityPortMatch
            )
        } catch {
            providerRuntimeLog("handleNewFlow lab_raw_authority_diagnostic_write_failed=\(providerNonsecretErrorDetail(error))")
        }
        do {
            try runtimeDiagnosticWriter?.recordHandleNewFlow(
                decisionCategory: decisionCategory,
                extractionStatus: report.flowExtractionStatus.rawValue,
                extractionReason: report.flowExtractionReason.rawValue,
                providerDecisionAction: report.action,
                providerDecisionReason: report.reason,
                singleRuleLabFallbackGate: evaluation.singleRuleLabFallbackGate,
                flowAuthorityHostGate: evaluation.flowAuthorityHostGate,
                flowAuthorityPortGate: evaluation.flowAuthorityPortGate,
                singleRuleLabFallbackPortGate: evaluation.singleRuleLabFallbackPortGate,
                allowFlowAuthorityPortMatch: evaluation.allowFlowAuthorityPortMatch,
                providerLoadedRulesGeneratedAt: providerLoadedRulesGeneratedAt,
                authorityExtractionRuntimeMarker: Self.authorityExtractionRuntimeMarker,
                flowAuthorityEndpointSourceGate: authorityObservation.endpointSourceGate,
                flowAuthorityPortSourceGate: authorityObservation.portSourceGate
            )
        } catch {
            providerRuntimeLog("handleNewFlow runtime_diagnostic_write_failed=\(providerNonsecretErrorDetail(error))")
        }
        let egress = regionEgressState() // read (blocked, admissionDenied) as ONE atomic pair (no fail-open TOCTOU)
        let regionAction: RegionEgressAction = report.acceptFlow
            ? Self.regionEgressAction(blocked: egress.blocked, admissionDenied: egress.admissionDenied, failOpenArmed: failOpenArmed)
            : .proceed
        if regionAction == .declineDirect {
            // LAB fail-open (ARMED = enable key AND acknowledgment) applies ONLY to a REACHABILITY block —
            // region failover reports no healthy allowed region (Edge down / not yet up at boot). In production
            // this is deny_closed; on a lab/dev machine we instead DECLINE the flow so the OS routes it DIRECTLY —
            // the developer's own traffic keeps flowing instead of the whole machine bricking. Same decline
            // mechanism as a self-exclusion passthrough (return false). It NEVER applies to an ADMISSION deny
            // (.denied / regionEgressDeniedAdmission): a revoked device must not be passed through directly — that
            // would evade the kill-switch AND bypass the Edge entirely (see regionEgressAction). Region failover
            // keeps probing and, once the Edge is reachable again, clears the block and NEW flows resume steering.
            providerRuntimeLog("handleNewFlow region_failover_egress_blocked=true fail_open_armed=true decision=decline_direct (LAB: no healthy allowed region — passing this flow through directly instead of deny_closed)")
            return false
        } else if regionAction == .denyClosed {
            // Region failover is fail-closed: with no healthy allowed region (or device admission denied) we must
            // NOT egress an otherwise-accepted flow. Take it over and close it rather than letting it leave the
            // residency boundary / evade a kill-switch. Note when a revocation OVERRODE an armed lab fail-open —
            // that is the kill-switch correctly refusing to be bypassed (a security-relevant event to surface).
            providerRuntimeLog("handleNewFlow region_failover_egress_blocked=true admission_denied=\(egress.admissionDenied) fail_open_armed=\(failOpenArmed) decision=deny_closed\(egress.admissionDenied && failOpenArmed ? " (revocation overrides armed fail-open — kill-switch not bypassed)" : "") (no healthy allowed region or device admission denied)")
            Self.dropFlowForcingQUICFallback(flow)
        } else if report.acceptFlow, let tcpFlow = flow as? NEAppProxyTCPFlow {
            startLiveRuntimeCopy(
                tcpFlow: tcpFlow,
                providerResult: evaluation.providerResult,
                destination: evaluation.extraction.providerFlowRequest,
                report: report
            )
        } else {
            let auditEvidence = Self.policyDrivenHandleNewFlowAuditEvidence(report: report)
            if auditEvidence.policyDecisionCategory == "default_deny" {
                do {
                    try policyDrivenAuditEvidenceWriter?.writeDefaultDenyAudit(auditEvidence)
                } catch {
                    providerRuntimeLog("handleNewFlow policy_driven_default_deny_audit_write_failed=\(providerNonsecretErrorDetail(error))")
                }
            } else if auditEvidence.policyDecisionCategory == "protection_block" {
                do {
                    try policyDrivenAuditEvidenceWriter?.writeProtectionAudit(auditEvidence)
                } catch {
                    providerRuntimeLog("handleNewFlow policy_driven_protection_audit_write_failed=\(providerNonsecretErrorDetail(error))")
                }
            }
        }
        return report.acceptFlow
    }

    public var currentLifecycleState: ProviderLifecycleState? {
        lifecycleManager.state
    }

    private static func agentConfigPath(from options: [String: Any]?) -> String? {
        guard let options else {
            return nil
        }
        if let value = options[agentConfigPathOptionKey] as? String {
            let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
            return trimmed.isEmpty ? nil : trimmed
        }
        if let value = options[agentConfigPathOptionKey] as? NSString {
            let trimmed = String(value).trimmingCharacters(in: .whitespacesAndNewlines)
            return trimmed.isEmpty ? nil : trimmed
        }
        if let value = options[legacyAgentConfigPathOptionKey] as? String {
            let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
            return trimmed.isEmpty ? nil : trimmed
        }
        if let value = options[legacyAgentConfigPathOptionKey] as? NSString {
            let trimmed = String(value).trimmingCharacters(in: .whitespacesAndNewlines)
            return trimmed.isEmpty ? nil : trimmed
        }
        return nil
    }

    private static func validatedAgentConfigPath(_ path: String) -> String? {
        let trimmed = path.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            return nil
        }
        let standardizedPath = URL(fileURLWithPath: trimmed).standardizedFileURL.path
        guard standardizedPath == productionAgentConfigPath else {
            return nil
        }
        return standardizedPath
    }

    static func transparentProxyNetworkSettings(agentConfigPath: String) -> NETransparentProxyNetworkSettings {
        let settings = NETransparentProxyNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        // Steer all TCP. Additionally claim *only* UDP/443 (QUIC) and drop it in handleNewFlow to force
        // a fallback to TCP/TLS (the NE itself closes the ZTNA hole where QUIC escapes steering/interception/
        // tenant restriction; QUIC/HTTP3 blocking). Scoping to port 443 is essential: NEAppProxyUDPFlow
        // has no remote port at handleNewFlow time (per datagram), so authorityObservation hardcodes UDP flows
        // as 443. Claiming all UDP would therefore treat DNS (53) etc. as 443 and drop it.
        // A port-scoped rule makes the OS hand over only UDP/443, so DNS etc. never reach the NE and stay intact.
        var rules: [NENetworkRule] = [Self.transparentProxyOutboundAnyRemoteTCPRule()]
        // Claim UDP/443 for both IPv4 and IPv6 (Chrome uses IPv6 QUIC to Google, so both families are required).
        rules.append(contentsOf: Self.transparentProxyOutboundQUICUDPRules())
        // NOTE ( Mac S3): a NETransparentProxy is OUTBOUND-ONLY. Adding an inbound-direction
        // NENetworkRule here makes setTunnelNetworkSettings fail with NETunnelProviderError code=1
        // (networkSettingsInvalid), bricking the whole proxy (verified on-device 2026-06-17). Server-initiated
        // inbound enforcement therefore lives in the Windows WFP ALE_AUTH_RECV_ACCEPT path and/or a macOS
        // Content Filter (NEFilterDataProvider). The pure classifier (ServerInitiatedClassification.swift) is
        // NE-agnostic and reused from there. Do NOT re-add an inbound rule to this transparent proxy.
        settings.includedNetworkRules = rules
        return settings
    }

    private static func transparentProxyOutboundAnyRemoteTCPRule() -> NENetworkRule {
        NENetworkRule(
            __remoteNetwork: nil,
            remotePrefix: 0,
            localNetwork: nil,
            localPrefix: 0,
            protocol: .TCP,
            direction: .outbound
        )
    }

    // Rule that claims only UDP/443 (QUIC) for any host. Uses the modern nw_endpoint-based init
    // (macOS 15.0) (the old NWHostEndpoint is deprecated and unresolvable in Swift, which is why it was removed).
    // 0.0.0.0 + remotePrefix 0 = all addresses, port 443. Below macOS 15 it returns nil and does not
    // drop QUIC (in that case it relies on disabling QUIC on the Chrome side, as before).
    private static func transparentProxyOutboundQUICUDPRules() -> [NENetworkRule] {
        guard #available(macOS 15.0, *) else { return [] }
        guard let port = NWEndpoint.Port(rawValue: UInt16(ProviderQUICFallbackPolicy.quicUDPPort)) else {
            return []
        }
        // remotePrefix 0 = all addresses in that family, port 443 (QUIC). Claim both IPv4 (0.0.0.0)
        // and IPv6 (::) (Google uses IPv6 QUIC, so claiming only one leaves a hole).
        return [("0.0.0.0", port), ("::", port)].map { hostString, p in
            NENetworkRule(
                remoteNetworkEndpoint: NWEndpoint.hostPort(host: NWEndpoint.Host(hostString), port: p),
                remotePrefix: 0,
                localNetworkEndpoint: nil,
                localPrefix: 0,
                protocol: .UDP,
                direction: .outbound
            )
        }
    }


    // Drop by closing both directions without opening the flow. The app's QUIC (UDP) send fails and HTTPS
    // falls back to TCP/TLS. The post-fallback TCP/443 becomes a steer+interception target.
    private static func dropFlowForcingQUICFallback(_ flow: NEAppProxyFlow) {
        flow.closeReadWithError(nil)
        flow.closeWriteWithError(nil)
    }

    static func runtimeCopyPassthroughEndpoint(agentConfigPath: String) -> DsseRuntimeCopyPassthroughEndpoint? {
        guard let loaded = try? DsseLocalRuntimeCopyTransportFactory.edgeConfiguration(agentConfigPath: agentConfigPath),
              let host = loaded.configuration.edgeBaseURL.host,
              let normalizedHost = DsseRuntimeCopyPassthroughEndpoint.normalizeHost(host),
              let port = loaded.configuration.edgeBaseURL.port else {
            return nil
        }
        return DsseRuntimeCopyPassthroughEndpoint(
            normalizedHost: normalizedHost,
            port: port,
            labEndpointPortOnlyFallback: loaded.evidenceImplementation == "lab_endpoint_runtime_copy_transport",
            normalizedResolvedHosts: Set(
                loaded.passthroughResolvedHosts.compactMap {
                    DsseRuntimeCopyPassthroughEndpoint.normalizeHost($0)
                }
            )
        )
    }

    static func runtimeCopyDownstreamPassthroughPolicy(
        agentConfigPath: String
    ) -> DsseRuntimeCopyDownstreamPassthroughPolicy {
        let config = (try? Data(contentsOf: URL(fileURLWithPath: agentConfigPath)))
            .flatMap { try? JSONDecoder().decode(DsseRuntimeCopyDownstreamPassthroughAgentConfig.self, from: $0) }
        return DsseRuntimeCopyDownstreamPassthroughPolicy(
            allowedSourceAppSigningIdentifiers: config?.sourceAppSigningIdentifiers ?? [],
            defaultTunnelEnabled: config?.defaultTunnelEnabled == true
        )
    }

    static func runtimeCopyDownstreamPassthroughDecision(
        input: ProviderFlowAuthorityInput,
        singleRule: ProviderSingleRuleLabRuleDiagnostic?,
        sourceAppSigningIdentifier: String?,
        policy: DsseRuntimeCopyDownstreamPassthroughPolicy?
    ) -> DsseRuntimeCopyDownstreamPassthroughDecision {
        guard let policy, policy.isConfigured else {
            return DsseRuntimeCopyDownstreamPassthroughDecision(
                category: "not_configured",
                shouldPassThrough: false
            )
        }
        guard input.transport == .tcp else {
            return DsseRuntimeCopyDownstreamPassthroughDecision(
                category: "unsupported_transport",
                shouldPassThrough: false
            )
        }
        guard policy.allows(sourceAppSigningIdentifier: sourceAppSigningIdentifier) else {
            return DsseRuntimeCopyDownstreamPassthroughDecision(
                category: "source_app_not_allowed",
                shouldPassThrough: false
            )
        }
        guard let singleRule else {
            if policy.defaultTunnelEnabled {
                return DsseRuntimeCopyDownstreamPassthroughDecision(
                    category: "matched_default_tunnel_source_app_passed_through",
                    shouldPassThrough: true
                )
            }
            return DsseRuntimeCopyDownstreamPassthroughDecision(
                category: "target_rule_missing",
                shouldPassThrough: false
            )
        }
        guard input.remotePort == singleRule.destinationPort else {
            return DsseRuntimeCopyDownstreamPassthroughDecision(
                category: "target_port_mismatch",
                shouldPassThrough: false
            )
        }
        return DsseRuntimeCopyDownstreamPassthroughDecision(
            category: "matched_passed_through",
            shouldPassThrough: true
        )
    }

    static func transparentPassthroughDomains(agentConfigPath: String) -> [String] {
        let config = (try? Data(contentsOf: URL(fileURLWithPath: agentConfigPath)))
            .flatMap { try? JSONDecoder().decode(DsseTransparentPassthroughAgentConfig.self, from: $0) }
        let includeDefaults = config?.defaultPassthroughDomainsEnabled ?? true
        let configuredDomains = config?.passthroughDomains ?? []
        return normalizedTransparentPassthroughDomains(
            (includeDefaults ? defaultTransparentPassthroughDomains : []) + configuredDomains
        )
    }

    static func observeOnlyPassthroughAll(agentConfigPath: String) -> Bool {
        let config = (try? Data(contentsOf: URL(fileURLWithPath: agentConfigPath)))
            .flatMap { try? JSONDecoder().decode(DsseObserveOnlyAgentConfig.self, from: $0) }
        return config?.passthroughAll == true
    }

    // Raw enable key only (network_extension_lab_fail_open_when_region_blocked). Default false. NOTE: this being
    // true does NOT arm fail-open on its own — arming also requires the acknowledgment (see failOpenPosture).
    static func labFailOpenWhenRegionBlocked(agentConfigPath: String) -> Bool {
        let config = (try? Data(contentsOf: URL(fileURLWithPath: agentConfigPath)))
            .flatMap { try? JSONDecoder().decode(DsseLabFailOpenAgentConfig.self, from: $0) }
        return config?.failOpenWhenRegionBlocked == true
    }

    // Fail-open posture = the enable key AND the acknowledgment key. Fail-open is ARMED only when both are set;
    // an enable without acknowledgment is refused (armed == false). Default (no config / missing keys) is strict.
    static func failOpenPosture(agentConfigPath: String) -> DsseFailOpenPosture {
        let config = (try? Data(contentsOf: URL(fileURLWithPath: agentConfigPath)))
            .flatMap { try? JSONDecoder().decode(DsseLabFailOpenAgentConfig.self, from: $0) }
        return DsseFailOpenPosture(
            enableRequested: config?.failOpenWhenRegionBlocked == true,
            acknowledged: config?.failOpenAcknowledged == true
        )
    }

    static func interceptOnlyDomains(agentConfigPath: String) -> [String] {
        let config = (try? Data(contentsOf: URL(fileURLWithPath: agentConfigPath)))
            .flatMap { try? JSONDecoder().decode(DsseInterceptAllowlistAgentConfig.self, from: $0) }
        return normalizedTransparentPassthroughDomains(config?.interceptOnlyDomains ?? [])
    }

    static func interceptAllowlistDecision(
        input: ProviderFlowAuthorityInput,
        interceptOnlyDomains: [String]
    ) -> DsseInterceptAllowlistDecision {
        let normalizedAllowlist = normalizedTransparentPassthroughDomains(interceptOnlyDomains)
        guard !normalizedAllowlist.isEmpty else {
            // No allowlist configured => legacy catch-all: everything stays eligible.
            return DsseInterceptAllowlistDecision(category: "not_configured", shouldPassThrough: false)
        }
        guard input.transport == .tcp else {
            return DsseInterceptAllowlistDecision(category: "unsupported_transport_passed_through", shouldPassThrough: true)
        }
        // IP literal / missing host => not a domain we can match => fail open to
        // passthrough (safe default on a daily-driver machine).
        let hostKind = observeRemoteHostKind(input.remoteHost)
        if hostKind == "ipv4_literal" || hostKind == "ipv6_literal" || hostKind == "none" {
            return DsseInterceptAllowlistDecision(category: "host_not_domain_passed_through", shouldPassThrough: true)
        }
        guard let host = normalizedTransparentPassthroughDomain(input.remoteHost) else {
            return DsseInterceptAllowlistDecision(category: "host_not_domain_passed_through", shouldPassThrough: true)
        }
        let matched = normalizedAllowlist.contains { domain in
            host == domain || host.hasSuffix(".\(domain)")
        }
        return DsseInterceptAllowlistDecision(
            category: matched ? "matched_intercept_allowlist" : "not_in_intercept_allowlist_passed_through",
            shouldPassThrough: !matched
        )
    }

    // The certificate authorities this agent was INSTALLED with, written into agent_config.json by the Edge
    // from the anchor actually in force. See DsseInterceptionRootPin for why the pin is checked rather than
    // merely recorded.
    private struct AgentConfigTrustedCABundle: Decodable {
        let tenantID: String?
        let interceptionRootSHA256: String?
        /// Off unless the configuration says otherwise. Arming a fail-closed check by default would strand
        /// every machine whose configuration predates it, and the point of the field is that an operator
        /// turns it on for a fleet that is ready — a config edit, not a re-installation.
        let enforce: Bool?
        enum CodingKeys: String, CodingKey {
            case tenantID = "tenant_id"
            case interceptionRootSHA256 = "interception_root_sha256"
            case enforce
        }
    }

    private struct AgentConfigTrustedCAWrapper: Decodable {
        let bundle: AgentConfigTrustedCABundle?
        enum CodingKeys: String, CodingKey { case bundle = "trusted_ca_bundle" }
    }

    /// The pinned interception root and whether the pin is armed, read from the install configuration.
    static func installedInterceptionRootPin(agentConfigPath: String) -> (fingerprint: String?, enforce: Bool, tenant: String?) {
        let path = agentConfigPath.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !path.isEmpty, let data = FileManager.default.contents(atPath: path),
              let wrapper = try? JSONDecoder().decode(AgentConfigTrustedCAWrapper.self, from: data),
              let bundle = wrapper.bundle else {
            return (nil, false, nil)
        }
        return (bundle.interceptionRootSHA256, bundle.enforce ?? false, bundle.tenantID)
    }

    // The (T) transport contract is nested under `network_extension_transport` in agent_config.json.
    private struct AgentConfigTransportWrapper: Decodable {
        let transport: DsseTransportContract?
        enum CodingKeys: String, CodingKey { case transport = "network_extension_transport" }
    }

    /// The (T) contract this device actually uses: what agent_config.json holds, with the deployment's signed
    /// install profile applied on top.
    ///
    /// ★★★ DECODED IN ONE PLACE (2026-08-28). Six call sites in this file decoded the wrapper themselves, and a
    /// profile applied at five of them is a device that dials one door for its flows and another for its
    /// renewal — which fails months later, on the machine, in a way no screen shows.
    static func transportContract(agentConfigPath: String, data: Data) -> DsseTransportContract? {
        let configDir = URL(fileURLWithPath: agentConfigPath).deletingLastPathComponent()
        let local = (try? JSONDecoder().decode(AgentConfigTransportWrapper.self, from: data))?.transport
        let profile = DsseInstallProfileApplication.inForce(agentConfigPath: agentConfigPath,
                                                            configDirectory: configDir)
        return DsseInstallProfileApplication.applyTransport(to: local, profile: profile)
    }

    // startAgentPolicyPoller wires the PRODUCTION delivery mechanism: the NE itself pulls the Edge's signed
    // steer-exclusion policy over the (T) transport, verifies it against the MDM-provisioned pinned key, and
    // applies it LIVE (no client-side command, no provider restart). Disabled when no pin is configured. The
    // cached signed file is read at startup (above) and is the poller's write target (restart/offline cache).
    // logClientIdentityExpiry reads the device client certificate's notAfter at startProxy and logs it, warning
    // when it is within the renewal window (≤14d) or already expired. First slice of the fail-open design:
    // resolve() fails closed on a MISSING identity but an EXPIRED one resolves fine, so the first symptom of an
    // expired cert is the mTLS handshake failing on the wire and every steered flow dying (the 2026-07-17 outage).
    // This removes the "zero prior signal" property — it changes NO connection behaviour, it only surfaces the
    // expiry so an operator (or automated renewal) acts before the wire handshake fails. Non-secret: a date only.
    // logFailOpenPosture emits the loud, acknowledged posture banner — the macOS mirror of the Windows startup
    // guard. ARMED prints the ⚠ banner; enable-without-acknowledgment prints the ⚠ REFUSAL (fail-open stays
    // disarmed, strict deny-closed holds); strict-by-default prints nothing. Keep the wording aligned with
    // handoff_windows_failopen_production_guard_verified.md so the two endpoints tell one story.
    private func logFailOpenPosture(_ posture: DsseFailOpenPosture) {
        if posture.armed {
            providerRuntimeLog("⚠ FAIL-OPEN ENABLED (network_extension_fail_open_acknowledged acknowledged): a flow the Edge cannot carry egresses DIRECT to its real destination, bypassing zero-trust enforcement. LAB / STABILIZATION ONLY — never enable in production.")
            // ★★★ AND SAY HOW IT ENDS, BECAUSE THAT IS THE PART AN OPERATOR CANNOT GUESS (2026-08-31, found
            // by trying to put a machine back). The banner above says what fail-open DOES. It does not say
            // that leaving it is not a local act: the anti-rollback floor refuses the profile that preceded
            // this one — correctly, or an attacker could replay an older signed profile to weaken a fleet —
            // so returning needs the control plane to issue a NEW one.
            //
            // The reason an operator reaches for this is usually that something is unreachable. If that
            // something is the control plane, the way back is behind the thing they could not reach. This
            // adds no behaviour; it states what is already true, at the moment somebody is choosing it.
            providerRuntimeLog("⚠ AND THERE IS NO LOCAL WAY BACK: the anti-rollback floor refuses the profile "
                + "that preceded this one, so leaving fail-open requires the control plane to issue a NEW "
                + "profile. If you enabled this to diagnose an outage OF that control plane, you have put the "
                + "way back behind the thing you could not reach.")
        } else if posture.enableRequested {
            // Enable requested without the acknowledgment — the mirror of Windows refusing `--fail-open` without
            // `--acknowledge-fail-open` (exit 2). The NE cannot refuse to START, so it refuses to ARM: strict
            // deny-closed enforcement stays in effect until the acknowledgment is set.
            providerRuntimeLog("⚠ FAIL-OPEN REQUESTED WITHOUT ACKNOWLEDGMENT: network_extension_lab_fail_open_when_region_blocked=true but network_extension_fail_open_acknowledged is not set — REFUSING to arm fail-open; strict deny-closed enforcement stays in effect. Set network_extension_fail_open_acknowledged=true to acknowledge the zero-trust bypass.")
        }
        // Neither requested -> strict by default; no banner (unchanged).
    }

    // Day-0: enrol when this machine has no identity, and DO NOT take over the network path when it has none and
    // no way to get one.
    //
    // Without this, a machine with no certificate applies the transparent-proxy settings and is then rejected at
    // every handshake: no working network, no explanation, from an agent that never had anything to protect. It
    // is not a security trade — there is no policy to bypass on a machine an operator has never approved, and
    // standing aside leaves it exactly as it was rather than breaking it.
    //
    // nil is reserved for an unmanaged device. A managed failure still installs capture rules.
    private func resolveDeviceIdentityForStartup(agentConfigPath: String) -> DsseStartupIdentityArrival? {
        let configDir = URL(fileURLWithPath: agentConfigPath).deletingLastPathComponent()
        let contract = (try? Data(contentsOf: URL(fileURLWithPath: agentConfigPath)))
            .flatMap { Self.transportContract(agentConfigPath: agentConfigPath, data: $0) }
        let security = DsseTransportSecurityResolver.resolve(contract: contract, configDirectory: configDir, agentConfigPath: agentConfigPath)

        // "Has been enrolled before" is read from durable state, not from the presence of a working credential:
        // a device whose key was wiped still has the pointer renewal wrote, and must not be mistaken for new.
        let wasEnrolledBefore = DsseRenewedIdentityStore.readPointer(configDirectory: configDir) != nil
            || (contract?.clientIdentityP12Ref?.isEmpty == false)
            || (contract?.clientIdentityCommonName?.isEmpty == false)
        let enrolmentConfig = DsseDeviceEnrolment.readConfig(at: agentConfigPath)

        // ★ PRESENT IS NOT USABLE, and conflating them is what let this provider take traffic it could not
        // carry. Checked BEFORE the enrolment gate because the two are different faults with different
        // remedies: the gate answers "has this device been enrolled", this answers "may this build use what it
        // was enrolled with". Calling an unusable key "not enrolled" would send an operator to the wrong fix.
        let startupIdentity = DsseStartupIdentityGate.decide(
            identityPresent: security?.clientIdentity != nil,
            identityUsable: DsseTransportSecurityFactory.clientIdentityIsUsable(security?.clientIdentity))
        if startupIdentity == .identityUnusable {
            let outcome = DsseStartupArming.afterEnrolmentFailure(wasEnrolledBefore: wasEnrolledBefore)
            providerRuntimeLog("startProxy client_identity=UNUSABLE action=\(outcome == .enforcementBlocked ? "deny_closed" : "stand_aside") — "
                + DsseStartupIdentityGate.unusableIdentityOperatorMessage)
            return outcome
        }

        // ★ IS THIS THE EDGE THIS AGENT WAS INSTALLED FOR (2026-08-16). The configuration carries the
        // certificate authority this device's traffic is supposed to be inspected under; the Edge says which
        // it signs under. When those disagree, steering hands this machine's TLS to an authority its
        // organization never chose — and that is dangerous exactly when it WORKS, because a root the machine
        // happens to hold makes the browser perfectly happy.
        //
        // Announced roots come from what already reached this device (the last signed policy, else the last
        // signed bundle), so a machine that has not polled yet decides nothing — see DsseInterceptionRootPin,
        // where "unknown" and "wrong" are deliberately different answers.
        let pin = Self.installedInterceptionRootPin(agentConfigPath: agentConfigPath)
        let announcedRoots: [String] = {
            // Same two sources, in the same order, as the poll-time report: the signed policy arrives every
            // minute, the signed bundle only when the trust set itself changes.
            var fromPolicy: [String] = []
            if let data = FileManager.default.contents(atPath: agentConfigPath),
               let exclCfg = try? JSONDecoder().decode(DsseSelfExclusionAgentConfig.self, from: data),
               case let signedPath = exclCfg.resolvedAgentPolicySignedPath(configDirectory: configDir) {
                fromPolicy = DsseSignedAgentPolicy.verifiedInterceptionRoots(
                    signedPath: signedPath,
                    pinnedPublicKeyHex: exclCfg.agentPolicyPinnedPublicKey?
                        .trimmingCharacters(in: .whitespacesAndNewlines) ?? "",
                    alsoAccept: DsseAdoptedTrustAnchorStore.acceptedAgentPolicyKeys(configDirectory: configDir))
            }
            return fromPolicy.isEmpty
                ? DsseAdoptedTrustAnchorStore.advertisedInterceptionRoots(configDirectory: configDir)
                : fromPolicy
        }()
        let pinDecision = DsseInterceptionRootPin.decide(pinned: pin.fingerprint, announced: announcedRoots)
        // Said on EVERY path including the healthy one: a gate that speaks only when it refuses leaves an
        // operator unable to tell working from not-running from quietly standing aside.
        providerRuntimeLog("startProxy interception_root_pin decision=\(pinDecision.logToken) " +
                           "enforce=\(pin.enforce) tenant=\(pin.tenant ?? "unset") " +
                           "pinned=\(pin.fingerprint ?? "none") announced=\(announcedRoots.count) " +
                           "announced_roots=\(announcedRoots.joined(separator: ","))")
        if case let .mismatch(pinned, announced) = pinDecision {
            if pin.enforce {
                let outcome = DsseStartupArming.afterEnrolmentFailure(wasEnrolledBefore: wasEnrolledBefore)
                providerRuntimeLog("startProxy interception_root_pin=MISMATCH action=\(outcome == .enforcementBlocked ? "deny_closed" : "stand_aside") — " +
                    DsseInterceptionRootPin.mismatchOperatorMessage(pinned: pinned, announced: announced))
                return outcome
            }
            // Armed or not, this is worth shouting about: it is either a machine pointed at another
            // organization's Edge, or an authority replaced without this device being reconfigured.
            providerRuntimeLog("startProxy interception_root_pin=MISMATCH action=observe_only (trusted_ca_bundle.enforce " +
                "is not set) — " + DsseInterceptionRootPin.mismatchOperatorMessage(pinned: pinned, announced: announced))
        }

        // Does the identity this device holds actually work against the deployment it is INSTALLED FOR? Asked
        // only when there is an unspent token to act on, because it costs a handshake and because a device with
        // no approval cannot use the answer. nil means "not asked" and is never read as "no".
        var identityWorksHere: Bool?
        if security?.clientIdentity != nil, enrolmentConfig != nil, let security, let identity = security.clientIdentity {
            let works = Self.transportHandshakeSucceeds(with: identity, like: security)
            identityWorksHere = works
            providerRuntimeLog("startProxy identity_works_here=\(works) — the certificate this device holds " +
                               (works ? "completes a (T) handshake with this deployment"
                                      : "does NOT complete a (T) handshake with this deployment, and an " +
                                        "enrolment token is configured"))
        }
        // And does it belong to the organization this device was GIVEN? A certificate from another
        // organization of the same deployment handshakes perfectly, so the question above cannot see it.
        var identityBelongsHere: Bool?
        // ★ FIRST, WHAT THE DEPLOYMENT SAYS. It computes this device's organization from the certificate the
        // device presented, and has always stated it in the signed steering document; nothing read it. It is
        // the only source that answers for a device enrolled BEFORE the pointer carried an organization, which
        // is every device that exists today, and it is signed, so it cannot be chosen by the network.
        if security?.clientIdentity != nil,
           let want = DsseAdoptedTenantScope.tenantInForce(configDirectory: configDir)?
               .trimmingCharacters(in: .whitespacesAndNewlines), !want.isEmpty,
           let data = FileManager.default.contents(atPath: agentConfigPath),
           let exclCfg = try? JSONDecoder().decode(DsseSelfExclusionAgentConfig.self, from: data),
           case let signedPath = exclCfg.resolvedAgentPolicySignedPath(configDirectory: configDir),
           let says = DsseSignedAgentPolicy.verifiedDeploymentTenant(
               signedPath: signedPath,
               pinnedPublicKeyHex: exclCfg.agentPolicyPinnedPublicKey?
                   .trimmingCharacters(in: .whitespacesAndNewlines) ?? "",
               alsoAccept: DsseAdoptedTrustAnchorStore.acceptedAgentPolicyKeys(configDirectory: configDir)) {
            identityBelongsHere = (says == want)
            providerRuntimeLog("startProxy deployment_says_this_device_is=\(says) profile_says=\(want)")
        } else if security?.clientIdentity != nil,
           let want = DsseAdoptedTenantScope.tenantInForce(configDirectory: configDir)?
               .trimmingCharacters(in: .whitespacesAndNewlines), !want.isEmpty,
           let held = DsseRenewedIdentityStore.readPointer(configDirectory: configDir)?.tenantID?
               .trimmingCharacters(in: .whitespacesAndNewlines), !held.isEmpty {
            // The identity says which organization it was issued for, and the profile says which one this
            // device has been given. Only a stamped pointer can answer; an unstamped one stays nil below.
            identityBelongsHere = (held == want)
        } else if let identity = security?.clientIdentity, let pin = enrolmentConfig?.deviceCAPinSHA256,
                  !pin.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            identityBelongsHere = DsseIdentityOrganization.identityIssuedByPinnedDeviceCA(identity: identity,
                                                                                          pinnedSHA256: pin)
            providerRuntimeLog("startProxy identity_belongs_to_this_organization=" +
                (identityBelongsHere.map(String.init(describing:)) ?? "not_asked") +
                " — whether this device's certificate was issued by the device CA its profile pins")
        }
        let decision = DsseEnrolmentGate.decide(hasIdentity: security?.clientIdentity != nil,
                                                hasEnrolmentToken: enrolmentConfig != nil,
                                                wasEnrolledBefore: wasEnrolledBefore,
                                                identityWorksHere: identityWorksHere,
                                                identityBelongsToThisOrganization: identityBelongsHere)
        // Say what was decided on EVERY path, including the healthy one. A gate that only speaks when it
        // refuses leaves an operator unable to tell "working" from "not running" from "quietly standing aside" —
        // this product has already been bitten by that once, on both platforms.
        providerRuntimeLog("startProxy enrolment_gate decision=\(decision) has_identity=\(security?.clientIdentity != nil) has_token=\(enrolmentConfig != nil) enrolled_before=\(wasEnrolledBefore)")

        switch decision {
        case .proceed, .proceedPreviouslyEnrolled:
            return .alreadyPresent
        case .standAsideNotEnrolled:
            providerRuntimeLog("startProxy enrolment=absent action=stand_aside — \(DsseEnrolmentGate.notEnrolledOperatorMessage)")
            return nil
        case .enrolFirst:
            guard let enrolmentConfig else { return nil }
            do {
                let identity = try DsseDeviceEnrolment.enrol(config: enrolmentConfig)
                // Installed through the SAME store automated renewal writes, so there is one way an identity
                // becomes current on this device and one place to look when it did not.
                //
                // The probe matters more at enrolment than at renewal. A renewal that installs a bad identity
                // still has the old one to fall back on; an enrolment that installs one leaves a pointer behind,
                // and this machine then counts as PREVIOUSLY ENROLLED on the next start — so it would take over
                // the network path with a credential that does not work. Prove the handshake first.
                try DsseRenewedIdentityStore.install(identity, configDirectory: configDir,
                                                     probe: { candidate in
                                                         Self.transportHandshakeSucceeds(with: candidate, like: security)
                                                     },
                                                     log: { providerRuntimeLog("startProxy enrolment \($0)") },
                                                     tenantID: DsseAdoptedTenantScope.tenantInForce(configDirectory: configDir))
                DsseDeviceEnrolment.eraseSpentToken(at: agentConfigPath)
                providerRuntimeLog("startProxy enrolment=succeeded device=\(identity.commonName) not_after=\(identity.notAfter)")
                // The certificate this device did not have when startProxy armed its subsystems now exists.
                // Saying WHICH of the two states this is, rather than a bare true, is the whole fix.
                return .arrivedDuringStartup
            } catch {
                // Day-0 failures remain unconfigured. Previously managed devices must retain capture rules
                // and deny traffic, even when migration or recovery cannot obtain an identity.
                let outcome = DsseStartupArming.afterEnrolmentFailure(wasEnrolledBefore: wasEnrolledBefore)
                providerRuntimeLog("startProxy enrolment=failed action=\(outcome == .enforcementBlocked ? "deny_closed" : "stand_aside") detail=\(providerNonsecretErrorDetail(error))")
                return outcome
            }
        }
    }

    // Asks the Edge to complete a (T) handshake with a freshly issued identity before it is adopted. Mirrors the
    // renewal scheduler's probe: same endpoint, same pinning, only the client certificate differs.
    //
    // With no transport contract there is nothing to prove against, and refusing on that basis would block a
    // deployment that does not use (T) at all — so that case accepts.
    static func transportHandshakeSucceeds(with candidate: SecIdentity, like security: DsseTransportSecurity?) -> Bool {
        guard let security else { return true }
        let probeSecurity = DsseTransportSecurity(host: security.host, port: security.port,
                                                  mtlsRequired: true,
                                                  pinnedCACertificates: security.pinnedCACertificates,
                                                  clientIdentity: candidate)
        // ★★★ AND IT IS NOT URLSession (2026-08-30, measured). This is the last gate before a device adopts an
        // identity, and it was the one request left in the agent going out over URLSession — the transport this
        // product moved off precisely because "App Transport Security refuses a deployment's private CA before
        // the pinning delegate runs" (see DsseRuntimeCopyOverNW). It therefore could not succeed against any
        // deployment with a private CA, which is all of them:
        //
        //	enrolment probe host=jcui…hikari.lab:443/healthz result=REFUSED status=0
        //	  reason=A TLS error caused the secure connection to fail.        (-1200, the ATS refusal)
        //
        // It went unnoticed because it almost never ran: resolve() fails closed with no client identity, and
        // the guard above then returns true without dialling — so on a device enrolling for the FIRST time,
        // which is every device this lane exists for, the probe is skipped. The first time it truly ran was on
        // a machine moved between deployments, and it refused a certificate that was correct.
        //
        // The candidate is named rather than left to the connection: a probe that does not send what it claims
        // to be testing reports on something else, in either direction.
        var status = 0
        var failure: String?
        do {
            let response = try DsseSingleRequestOverNW.request(
                method: "GET", host: security.host, port: security.port,
                serverName: security.controlServerName,
                path: "/healthz", body: Data(), security: probeSecurity, timeout: 15,
                identityOverride: candidate)
            status = response.status
        } catch {
            failure = (error as? DsseSingleRequestError)?.description ?? providerNonsecretErrorDetail(error)
        }
        // ★★★ AND IT SAYS WHY IT REFUSED (2026-08-30, the fourth time in two days that a swallowed reason cost
        // a round trip). This function answers Bool, so a rejection reached the operator as
        //
        //	probeRejectedNewIdentity("the renewed identity could not complete an mTLS handshake with the Edge")
        //
        // — true, and the same sentence whether the Edge refused the certificate, the name did not resolve, the
        // pinned anchors did not verify it, or nothing was listening. This is the last gate before a device
        // adopts an identity, so it is the one place where "it did not work" is least useful.
        let ok = failure == nil && status != 0
        providerRuntimeLog("startProxy enrolment probe host=\(security.dialHost):\(security.port)/healthz " +
                           "result=\(ok ? "accepted" : "REFUSED") status=\(status) " +
                           "reason=\(failure ?? (ok ? "none" : "no transport error and status 0"))")
        return ok
    }

    // armIdentityDependentSubsystems is everything whose answer depends on this device holding a usable (T)
    // client identity. It is called twice on a first-enrolment start — once before the enrolment gate, where
    // the honest answer to all of it is "no transport", and again after enrolment installs the certificate.
    //
    // ★ WHY IT IS A FUNCTION AND NOT A COMMENT. It used to be five statements in startProxy, which is exactly
    // why the second call was easy to omit and impossible to see missing. See DsseStartupIdentityArrival.
    // Each subsystem is stopped before it is started so a second call replaces rather than duplicates.
    private func armIdentityDependentSubsystems(agentConfigPath: String,
                                                installProfile: DsseInstallProfile?,
                                                phase: String) {
        certificateRenewalScheduler?.stop()
        certificateRenewalScheduler = nil
        agentPolicyPoller?.stop()
        agentPolicyPoller = nil
        deviceHeartbeat?.stop()
        deviceHeartbeat = nil
        updateCourier?.stop()
        updateCourier = nil
        regionController?.stop()
        regionController = nil
        regionEndpointPoller?.stop()
        regionEndpointPoller = nil
        providerRuntimeLog("startProxy arming_identity_dependent_subsystems phase=\(phase)")
        logClientIdentityExpiry(agentConfigPath: agentConfigPath)
        startCertificateRenewal(agentConfigPath: agentConfigPath)
        startAgentPolicyPoller(agentConfigPath: agentConfigPath)
        startDeviceHeartbeat(agentConfigPath: agentConfigPath)
        startRegionFailoverController(agentConfigPath: agentConfigPath, installProfile: installProfile)
    }

    private func logClientIdentityExpiry(agentConfigPath: String) {
        let configDir = URL(fileURLWithPath: agentConfigPath).deletingLastPathComponent()
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: agentConfigPath)),
              let contract = Self.transportContract(agentConfigPath: agentConfigPath, data: data),
              let security = DsseTransportSecurityResolver.resolve(contract: contract, configDirectory: configDir, agentConfigPath: agentConfigPath) else {
            providerRuntimeLog("startProxy client_identity_expiry=unknown (no (T) transport contract)")
            return
        }
        guard let notAfter = security.clientIdentityNotAfter else {
            // mtls_required with no readable identity is already fail-closed elsewhere; note it so an expiry
            // check that returns nothing is distinguishable from one that was never attempted.
            providerRuntimeLog("startProxy client_identity_not_after=unavailable mtls_required=\(security.mtlsRequired)")
            return
        }
        let formatter = ISO8601DateFormatter()
        let daysRemaining = Int(notAfter.timeIntervalSinceNow / 86_400)
        providerRuntimeLog("startProxy client_identity_not_after=\(formatter.string(from: notAfter)) client_identity_days_remaining=\(daysRemaining)")
        if daysRemaining < 0 {
            providerRuntimeLog("startProxy WARNING client_identity_EXPIRED days_ago=\(-daysRemaining) — the mTLS handshake to the Edge will fail; every steered flow will die until the device cert is renewed. See docs/ne_transport_health_and_fail_open_design.md")
        } else if daysRemaining <= 14 {
            providerRuntimeLog("startProxy WARNING client_identity_expiring_soon days_remaining=\(daysRemaining) — renew the device cert before it expires or steered egress will fail fleet-wide on schedule.")
        }
    }

    // startCertificateRenewal turns the expiry WARNING into something that acts. logClientIdentityExpiry
    // above removed the "zero prior signal" property; this removes the "somebody has to notice and act"
    // property, which is the one that actually caused the 2026-07-17 outage.
    //
    // Renewal runs in the background and can only ever add a new credential — it never tears down a live
    // tunnel and never fails startProxy. A renewed identity is picked up the next time the transport resolves
    // security.
    private func startCertificateRenewal(agentConfigPath: String) {
        let configDir = URL(fileURLWithPath: agentConfigPath).deletingLastPathComponent()
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: agentConfigPath)),
              let contract = Self.transportContract(agentConfigPath: agentConfigPath, data: data),
              contract.enabled else {
            providerRuntimeLog("startProxy certificate_renewal=disabled (no (T) transport contract)")
            return
        }
        // The pinned agent-policy key also gates anchor self-healing: without it a stale-anchored device has
        // nothing to verify a trust bundle against, so the feature reports itself disabled rather than
        // silently doing nothing.
        let policyPin = (try? JSONDecoder().decode(DsseSelfExclusionAgentConfig.self, from: data))?
            .agentPolicyPinnedPublicKey?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        // The cached signed policy, so the renewal decision can read an operator's "renew anything older than
        // this" cutoff from the same document the steering path already verifies.
        let policySignedPath = (try? JSONDecoder().decode(DsseSelfExclusionAgentConfig.self, from: data))?
            .resolvedAgentPolicySignedPath(configDirectory: configDir)
        let scheduler = DsseCertificateRenewalScheduler(
            configDirectory: configDir, contract: contract,
            agentPolicyPinnedPublicKeyHex: policyPin,
            agentPolicySignedPath: policySignedPath,
            onAnchorsAdopted: { [weak self] in
                // Same live-rebuild path region failover uses: resolve again (now reading the adopted anchors)
                // and swap the transport so NEW flows use it. Without this the device adopts correct anchors
                // and stays dark until the next restart — self-healing that does not heal.
                guard let self else { return }
                let rebuilt = DsseLocalRuntimeCopyTransportFactory.make(agentConfigPath: agentConfigPath)
                self.runtimeCopyTransport = rebuilt
                providerRuntimeLog("trust_anchor_recovery transport_rebuilt — new flows use the adopted anchors")
            },
            log: { providerRuntimeLog($0) })
        certificateRenewalScheduler = scheduler
        scheduler.start()
    }

    // startDeviceHeartbeat wires endpoint liveness (see DsseDeviceHeartbeat): a periodic authenticated beat
    // over the (T) transport, so that stopping this extension is something the Edge can SEE. Until this
    // existed, a Mac's last_seen was a side effect of carrying traffic — mac-dev-1 sat at 2026-07-25 while it
    // steered all day — and killing the agent looked exactly like closing the laptop.
    //
    // Gated on the transport and not on the agent-policy pin, the same split as reverse telemetry. 15s matches
    // the Windows agent's default so one soft-dark threshold fits both platforms.
    // ★★★ THE ADDRESS A NAME ANSWERS ON MOVES, AND REGION FAILOVER IS WHEN IT MOVES (2026-08-30, the
    // operator's second point about the same fix). The deployment names its Console as never-steered and this
    // provider resolves those names once, at start, so a client dialling by address matches. Then a region
    // fails over: the Console answers somewhere else — under a per-region name, or under the same name whose
    // record now points at the surviving region — and the addresses resolved at start belong to the region
    // that just died. The administrator loses the Console at exactly the moment they need it, which is the
    // whole reason the destination was named in the first place.
    //
    // So the names are re-read and re-resolved on a timer: cheap (one lookup per authored name, and a
    // deployment authors a handful), off the flow path, and it makes the passthrough follow the deployment
    // rather than a snapshot of it. It also picks up a profile re-issued with more names, without a restart.
    //
    // ★ IT SPEAKS ONLY WHEN SOMETHING CHANGED, so a quiet log stays quiet and a failover leaves one line
    // saying what this device now believes.
    private func startTransparentPassthroughRefresh(agentConfigPath: String, interval: TimeInterval = 60) {
        transparentPassthroughLock.lock()
        transparentPassthroughRefreshGeneration += 1
        let generation = transparentPassthroughRefreshGeneration
        transparentPassthroughLock.unlock()
        func schedule() {
            DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + interval) { [weak self] in
                guard let self else { return }
                self.transparentPassthroughLock.lock()
                let stillOurs = self.transparentPassthroughRefreshGeneration == generation
                self.transparentPassthroughLock.unlock()
                guard stillOurs else { return }
                let domains = Self.transparentPassthroughDomains(agentConfigPath: agentConfigPath)
                let addresses = Self.addressesFor(domains: domains)
                self.transparentPassthroughLock.lock()
                let changed = domains != self.transparentPassthroughDomains
                    || addresses != self.transparentPassthroughAddresses
                if changed {
                    self.transparentPassthroughDomains = domains
                    self.transparentPassthroughAddresses = addresses
                }
                self.transparentPassthroughLock.unlock()
                if changed {
                    providerRuntimeLog("transparent_passthrough refreshed domain_count=\(domains.count) "
                        + "address_count=\(addresses.count) domains=\(domains.joined(separator: ","))")
                }
                schedule()
            }
        }
        schedule()
    }

    private func startDeviceHeartbeat(agentConfigPath: String) {
        let configDir = URL(fileURLWithPath: agentConfigPath).deletingLastPathComponent()
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: agentConfigPath)),
              let contract = Self.transportContract(agentConfigPath: agentConfigPath, data: data),
              let security = DsseTransportSecurityResolver.resolve(contract: contract, configDirectory: configDir, agentConfigPath: agentConfigPath),
              let sender = DsseDeviceHeartbeatSender(
                security: security, tenantID: "", agentVersion: DsseDeviceHeartbeat.agentVersion()) else {
            // Loud, not silent: an operator who cannot see that liveness is off has no way to know the Edge is
            // about to treat a working device as one that was never here.
            providerRuntimeLog("startProxy device_heartbeat=disabled — no (T) transport with a device client cert, or the certificate carries no CN. The Edge will see this device as dark even while it steers")
            return
        }
        deviceHeartbeat = sender
        sender.start(interval: 15)
        providerRuntimeLog("startProxy device_heartbeat=enabled device=\(sender.identity) interval=15s agent_version=\(DsseDeviceHeartbeat.agentVersion())")
    }

    private func startAgentPolicyPoller(agentConfigPath: String) {
        let configDir = URL(fileURLWithPath: agentConfigPath).deletingLastPathComponent()
        // GATED ON THE (T) TRANSPORT, NOT ON THE PIN — the same decision the Windows agent already makes, and
        // for the same reason. The reverse-telemetry REPORT is admin observability of what this device actually
        // excludes, INCLUDING a purely local baseline the server never issued; a device carrying only local
        // exclusions is exactly the unmanaged case an operator most needs to see. Requiring a pin to report
        // meant an unpinned device reported NOTHING and was indistinguishable, from the Edge, from a device
        // that does not exist. On 2026-08-05 this Mac had been steering for weeks while the "observed on
        // devices" view showed only the Windows box — not a Console defect, this gate.
        //
        // The pin still governs what it is allowed to APPLY: without one there is no signed-policy fetch,
        // verify or merge, because an unverified policy must never reach enforcement. Reporting is not
        // enforcement. The report needs the (T) mTLS identity (the Edge must know WHICH device is speaking)
        // and nothing else.
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: agentConfigPath)),
              let exclCfg = try? JSONDecoder().decode(DsseSelfExclusionAgentConfig.self, from: data),
              // The (T) contract lives under the nested `network_extension_transport` block, not at
              // the top level — decode it the same way the flow-copy/DNS transport path does.
              let contract = Self.transportContract(agentConfigPath: agentConfigPath, data: data),
              let security = DsseTransportSecurityResolver.resolve(contract: contract, configDirectory: configDir, agentConfigPath: agentConfigPath),
              let poller = DsseAgentPolicyPoller(
                security: security,
                pinnedPublicKeyHex: exclCfg.agentPolicyPinnedPublicKey?.trimmingCharacters(in: .whitespacesAndNewlines) ?? "",
                cachePath: exclCfg.resolvedAgentPolicySignedPath(configDirectory: configDir),
                acceptedKeys: { DsseAdoptedTrustAnchorStore.acceptedAgentPolicyKeys(configDirectory: configDir) }) else {
            // Reaching here means there is no (T) transport at all, so the device cannot identify itself to the
            // Edge and genuinely cannot report. Say which of the two it is rather than the old combined message,
            // because "no pin" is now a survivable state and "no transport" is not.
            providerRuntimeLog("startProxy agent_policy_poller=disabled reason=\(DsseAgentReportingGate.decide(hasTransport: false, pin: "").blockedReason) — this device will NOT report its effective steer-exclusion set and the Edge cannot distinguish it from an absent device")
            return
        }
        // The rule itself lives in DsseAgentReportingGate so it is checkable without standing up a provider.
        // pin may be empty from here on — that is the point. The reported key list filters empty entries, so an
        // unpinned device reports "no keys accepted" rather than a blank one, which is the honest answer and
        // the one the Edge already reads as "not ready for a signing-key switch".
        let pin = exclCfg.agentPolicyPinnedPublicKey?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        let gate = DsseAgentReportingGate.decide(hasTransport: true, pin: pin)
        if !gate.mayApplySignedPolicy {
            providerRuntimeLog("startProxy agent_policy_poller=report_only reason=no_pin — reverse telemetry WILL be sent; signed-policy fetch/verify/apply is off until a pin is configured")
        }
        agentPolicyPoller = poller
        // The update couriers ride the same resolved transport. Started here rather than in their own guard
        // because they need exactly what this one already proved: a (T) identity the Edge can key an answer to.
        // They carry two signed documents to disk and verify neither — the updater does that with its own
        // pinned keys, and a second opinion here would either widen the trust boundary or be ignored.
        if let courier = DsseUpdateCourier(security: security) {
            updateCourier = courier
            courier.start(interval: 900)
            providerRuntimeLog("startProxy update_courier=enabled interval=15m manifest=\(DsseUpdateCourier.manifestPath) plan=\(DsseUpdateCourier.planPath)")
        } else {
            providerRuntimeLog("startProxy update_courier=disabled — the Edge base URL could not be composed from the (T) transport; this device will never learn about a published update")
        }
        // From here on the tunnels read their anchors from the CURRENT resolution rather than the one captured
        // when a driver was built, so an adoption reaches the data path without a restart — and so the set the
        // Edge is told about and the set that verifies it cannot drift apart (2026-08-01).
        DsseTrustRefusalReporting.setConfigDirectory(configDir)
        // The identity too: a renewal that never reaches the wire is a renewal the Edge cannot see, and the
        // fleet ages while every device reports itself up to date.
        DsseLiveClientIdentity.setProvider {
            DsseTransportSecurityResolver.resolve(contract: contract, configDirectory: configDir, agentConfigPath: agentConfigPath)?.clientIdentity
        }
        DsseLiveTrustAnchors.setProvider {
            DsseTransportSecurityResolver.resolve(contract: contract, configDirectory: configDir, agentConfigPath: agentConfigPath)?
                .pinnedCACertificates ?? []
        }
        // ★ And the name to send with them (roadmap D). Same shape and same reason: read at handshake time,
        // from what this device last ADOPTED, so a bundle that lands mid-session changes the next connection
        // rather than requiring a restart.
        DsseLiveTransportServerName.setProvider {
            // ★★★ AND THE PROFILE WHEN NOTHING HAS BEEN ADOPTED YET (2026-08-30, measured on a Mac joining a
            // new deployment). The adopted bundle is the right source once there IS one — it is signed, and a
            // rename reaches the device through it. But a device that has never adopted one has no name to
            // send, and adopting requires an identity, and getting an identity requires an enrolment whose
            // probe dials by the organization's name. The cycle closes on itself:
            //
            //	enrolment probe host=agents.tokyo.hikari.lab:443/healthz  result=REFUSED
            //	  reason=A TLS error caused the secure connection to fail.
            //
            // — the deployment-wide name, served the deployment-wide certificate, on a device that now pins its
            // ORGANISATION's transport authority because the profile gave it one. Every new device of every
            // organization is in that state on its first start.
            //
            // The profile has carried organization.transport_server_name all along; nothing read it. It is
            // signed by the same key as everything else the profile says, so it is not a weaker source — it is
            // the same authority, arriving earlier. The adopted bundle still wins the moment there is one.
            let adopted = DsseAdoptedTrustAnchorStore.advertisedTransportServerName(configDirectory: configDir)
            if !adopted.isEmpty { return adopted }
            let profile = DsseInstallProfileApplication.inForce(agentConfigPath: agentConfigPath,
                                                               configDirectory: configDir)
            return (profile?.transportServerName ?? "").trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        }
        poller.start(interval: 60) { [weak self] (excluded: [String]?) in
            guard let self else { return }
            // APPLY only on a verified set. REPORT on every tick, verified or not — the two are decided
            // separately here for the same reason they are in DsseAgentReportingGate. A device whose policy
            // stops verifying (wrong pin, Edge error, signing-key switch) must keep telling the Edge what it
            // is actually enforcing; otherwise it ages out of the fleet view and looks switched off, which is
            // exactly how mac-dev-1 disappeared from "observed on devices" while it was steering (2026-08-05).
            let updated: DsseSelfExclusionPolicy
            if let excluded {
                updated = Self.selfExclusionPolicy(agentConfigPath: agentConfigPath, serverExclusionsOverride: excluded)
                self.selfExclusionPolicy = updated
                providerRuntimeLog("agent_policy_poll applied server_exclusion_count=\(excluded.count) total_self_exclusion_signing_count=\(updated.signingIdentifiers.count) total_self_exclusion_team_count=\(updated.teamIdentifiers.count)")
            } else {
                // Fail-safe: keep the set already in force (never clear enforcement because a poll failed),
                // and report THAT — the honest answer to "what is this device excluding right now".
                updated = self.selfExclusionPolicy ?? Self.selfExclusionPolicy(agentConfigPath: agentConfigPath)
                providerRuntimeLog("agent_policy_poll unverified — keeping the current set (signing_count=\(updated.signingIdentifiers.count)); reporting it anyway so the Edge does not lose sight of this device")
            }
            // Reverse telemetry (best-effort): report the MERGED effective set (floor + scaffold + server overlay)
            // as the AppIDs actually applied — bare/signing-id verbatim, team-id as "team-id:<value>" — so the
            // admin console sees exactly which AppID form matched. Plus the device's live steer-state (Phase 1a).
            // Does not affect enforcement.
            let ss = self.steerStateForTelemetry()
            // Resolve the anchors AGAIN here rather than reporting the set captured when the proxy started.
            // Adoption happens after start-up, so the captured set is the one the device was born with while
            // the tunnels have long moved on — the Edge was being told two anchors while one was in use, and
            // the readiness that opens a withdrawal gate was computed from the wrong one (2026-08-01).
            let live = DsseTransportSecurityResolver.resolve(contract: contract, configDirectory: configDir, agentConfigPath: agentConfigPath) ?? security
            self.agentPolicyPoller?.reportEffective(updated.appliedAppIDsForTelemetry, serverCount: excluded?.count ?? 0,
                ignored: updated.ignoredAppIDOrder,
                posture: ss.posture, failOpenConfigured: ss.failOpenConfigured,
                regionFailoverEnabled: ss.regionFailoverEnabled, activeRegion: ss.activeRegion,
                pinnedCAFingerprints: live.pinnedCAFingerprints,
                adoptedTrustSerial: DsseAdoptedTrustAnchorStore.lastAcceptedSerial(configDirectory: configDir),
                renewalRecoverySNIHeld: DsseAdoptedTrustAnchorStore.advertisedRenewalRecoverySNI(configDirectory: configDir),
                // Resolved the SAME way recovery actually dials it, so the report is about behaviour rather
                // than about a stored string — see attachRecoverySNI.
                renewalRecoveryTargetResolved: {
                    guard let dial = DsseCertificateRenewalScheduler.resolvedRecoveryDial(
                        contract: contract, configDirectory: configDir) else { return "" }
                    return dial.serverName.map { "\(dial.endpoint)|\($0)" } ?? dial.endpoint
                }(),
                interceptionRootSHA256: DsseInterceptionRootTrust.present(
                    // The polled policy first: it arrives every minute, where the trust bundle only arrives
                    // when the trust set itself changes — which in a deployment that is not rotating is never.
                    wanted: {
                        // ★★★ THE RESOLVED PATH, NOT THE CONFIGURED ONE (2026-09-06, measured on a Mac that
                        // was being intercepted at that moment). The poller WRITES the document to the
                        // resolved path and this read it from the configured one, which is nil — so a device
                        // holding and using its organization's interception root reported no root at all, and
                        // the Console's certificate map said "not reporting" about it. The measurement that
                        // gates withdrawing an interception root therefore had no denominator.
                        let fromPolicy = DsseSignedAgentPolicy.verifiedInterceptionRoots(
                            signedPath: exclCfg.resolvedAgentPolicySignedPath(configDirectory: configDir),
                            pinnedPublicKeyHex: pin,
                            alsoAccept: DsseAdoptedTrustAnchorStore.acceptedAgentPolicyKeys(configDirectory: configDir))
                        let fromBundle = DsseAdoptedTrustAnchorStore
                            .advertisedInterceptionRoots(configDirectory: configDir)
                        // Which source answered is the first thing to know when nothing is reported.
                        providerRuntimeLog("interception_root_source policy=\(fromPolicy.count) " +
                                           "bundle=\(fromBundle.count) " +
                                           "policy_path=\(exclCfg.configuredAgentPolicySignedPath == nil ? "configured-unset (resolved)" : "configured")")
                        return fromPolicy.isEmpty ? fromBundle : fromPolicy
                    }()),
                // The pin this agent was installed with, read from the same configuration the startup gate
                // reads — so what the Edge is told and what this device would enforce are one value.
                interceptionRootPin: Self.installedInterceptionRootPin(agentConfigPath: agentConfigPath).fingerprint ?? "",
                trustRefusals: DsseTrustRefusalJournal.pending(configDirectory: configDir),
                // What this device would fall back to — the previous renewed generation when one is held,
                // else the bootstrap. Resolved fresh per report, like the anchors above, so a renewal or a
                // re-provisioned bootstrap reaches the Edge's retire gate without a restart.
                fallbackClientCertPEM: DsseTransportSecurityResolver.fallbackClientCertificatePEM(
                    contract: contract, configDirectory: configDir) ?? "",
                // The effective set of policy-signing keys this device would accept: the pin plus any adopted
                // from a bundle, deduped. Resolved fresh here (adopted keys change after start-up) so the Edge
                // sees adoption before the config-signing key is switched.
                agentPolicyPublicKeys: {
                    var keys = [pin.lowercased()]
                    keys.append(contentsOf: DsseAdoptedTrustAnchorStore
                        .acceptedAgentPolicyKeys(configDirectory: configDir).map { $0.lowercased() })
                    var seen = Set<String>()
                    return keys.filter { !$0.isEmpty && seen.insert($0).inserted }
                }(),
                onRefusalsAccepted: { DsseTrustRefusalJournal.clear($0, configDirectory: configDir) })
            // The policy just fetched may carry an operator's "renew anything older than this". The renewal
            // cadence is derived from the certificate's own lifetime, so a long certificate is checked rarely
            // — and a long certificate is exactly what somebody presses "renew now" about. Measured on this
            // lab: a ten-year certificate yields the six-hour ceiling, so the request would have sat unacted-on
            // for most of a working day while every surface reported the device healthy. Bring the check
            // forward instead; one that finds nothing due is local and costs nothing.
            if case let signedPath = exclCfg.resolvedAgentPolicySignedPath(configDirectory: configDir),
               DsseSignedAgentPolicy.verifiedRenewCertificatesIssuedBefore(
                   signedPath: signedPath, pinnedPublicKeyHex: pin,
                   alsoAccept: DsseAdoptedTrustAnchorStore.acceptedAgentPolicyKeys(configDirectory: configDir)) != nil {
                self.certificateRenewalScheduler?.checkSoon(reason: "operator_requested_renewal_in_policy")
            }
        }
        providerRuntimeLog("startProxy agent_policy_poller=enabled interval=60s")
        // Initial reverse-telemetry report of the current effective set before the first poll's server overlay
        // arrives (serverCount 0). Best-effort; never blocks startup. The poller exists and selfExclusionPolicy
        // was set in startProxy before this method was called.
        if let initial = self.selfExclusionPolicy?.appliedAppIDsForTelemetry {
            let ss = self.steerStateForTelemetry()
            let live = DsseTransportSecurityResolver.resolve(contract: contract, configDirectory: configDir, agentConfigPath: agentConfigPath) ?? security
            poller.reportEffective(initial, serverCount: 0,
                posture: ss.posture, failOpenConfigured: ss.failOpenConfigured,
                regionFailoverEnabled: ss.regionFailoverEnabled, activeRegion: ss.activeRegion,
                pinnedCAFingerprints: live.pinnedCAFingerprints,
                adoptedTrustSerial: DsseAdoptedTrustAnchorStore.lastAcceptedSerial(configDirectory: configDir),
                renewalRecoverySNIHeld: DsseAdoptedTrustAnchorStore.advertisedRenewalRecoverySNI(configDirectory: configDir),
                // Resolved the SAME way recovery actually dials it, so the report is about behaviour rather
                // than about a stored string — see attachRecoverySNI.
                renewalRecoveryTargetResolved: {
                    guard let dial = DsseCertificateRenewalScheduler.resolvedRecoveryDial(
                        contract: contract, configDirectory: configDir) else { return "" }
                    return dial.serverName.map { "\(dial.endpoint)|\($0)" } ?? dial.endpoint
                }(),
                interceptionRootSHA256: DsseInterceptionRootTrust.present(
                    // The polled policy first: it arrives every minute, where the trust bundle only arrives
                    // when the trust set itself changes — which in a deployment that is not rotating is never.
                    wanted: {
                        // ★★★ THE RESOLVED PATH, NOT THE CONFIGURED ONE (2026-09-06, measured on a Mac that
                        // was being intercepted at that moment). The poller WRITES the document to the
                        // resolved path and this read it from the configured one, which is nil — so a device
                        // holding and using its organization's interception root reported no root at all, and
                        // the Console's certificate map said "not reporting" about it. The measurement that
                        // gates withdrawing an interception root therefore had no denominator.
                        let fromPolicy = DsseSignedAgentPolicy.verifiedInterceptionRoots(
                            signedPath: exclCfg.resolvedAgentPolicySignedPath(configDirectory: configDir),
                            pinnedPublicKeyHex: pin,
                            alsoAccept: DsseAdoptedTrustAnchorStore.acceptedAgentPolicyKeys(configDirectory: configDir))
                        let fromBundle = DsseAdoptedTrustAnchorStore
                            .advertisedInterceptionRoots(configDirectory: configDir)
                        // Which source answered is the first thing to know when nothing is reported.
                        providerRuntimeLog("interception_root_source policy=\(fromPolicy.count) " +
                                           "bundle=\(fromBundle.count) " +
                                           "policy_path=\(exclCfg.configuredAgentPolicySignedPath == nil ? "configured-unset (resolved)" : "configured")")
                        return fromPolicy.isEmpty ? fromBundle : fromPolicy
                    }()),
                trustRefusals: DsseTrustRefusalJournal.pending(configDirectory: configDir),
                fallbackClientCertPEM: DsseTransportSecurityResolver.fallbackClientCertificatePEM(
                    contract: contract, configDirectory: configDir) ?? "",
                // The effective set of policy-signing keys this device would accept: the pin plus any adopted
                // from a bundle, deduped. Resolved fresh here (adopted keys change after start-up) so the Edge
                // sees adoption before the config-signing key is switched.
                agentPolicyPublicKeys: {
                    var keys = [pin.lowercased()]
                    keys.append(contentsOf: DsseAdoptedTrustAnchorStore
                        .acceptedAgentPolicyKeys(configDirectory: configDir).map { $0.lowercased() })
                    var seen = Set<String>()
                    return keys.filter { !$0.isEmpty && seen.insert($0).inserted }
                }(),
                onRefusalsAccepted: { DsseTrustRefusalJournal.clear($0, configDirectory: configDir) })
        }
    }

    // steerStateForTelemetry derives the Phase 1a device steer-state fields the reverse-telemetry report carries,
    // sourced from the provider's own live state, using the edge's posture vocabulary (steering|disarmed|dark).
    // A report only lands when the (T) transport reached the edge, so the edge IS reachable at report time: the
    // steering-vs-fail-open distinction is whether region egress is currently blocked (no healthy region) and, if
    // so, whether fail-open is armed (direct/disarmed) or not (deny-closed/dark) — mirroring handleNewFlow.
    private func steerStateForTelemetry() -> (posture: String, failOpenConfigured: Bool, regionFailoverEnabled: Bool, activeRegion: String) {
        let armed = failOpenArmed
        let posture: String
        if regionEgressBlocked { posture = armed ? "disarmed" : "dark" } else { posture = "steering" }
        return (posture: posture,
                failOpenConfigured: armed,
                regionFailoverEnabled: regionController != nil,
                activeRegion: regionController?.currentRegion() ?? "")
    }

    // RegionEgressAction is the enforcement decision for a flow when region failover has blocked egress. Pure
    // (no I/O) so it is unit-testable. INVARIANT: LAB fail-open (direct egress) applies ONLY to a REACHABILITY
    // block (no healthy allowed region); an ADMISSION deny (device revoked/not-enrolled) is ALWAYS deny_closed,
    // so a kill-switch can never be bypassed via fail-open. Mirrors the Windows agent, where terminal fail-open
    // engages on failClosed (exhaustion) but never on surfaceDenied (admission).
    enum RegionEgressAction: Equatable { case proceed, denyClosed, declineDirect }
    static func regionEgressAction(blocked: Bool, admissionDenied: Bool, failOpenArmed: Bool) -> RegionEgressAction {
        guard blocked else { return .proceed }
        if failOpenArmed && !admissionDenied { return .declineDirect }
        return .denyClosed
    }

    // startRegionFailoverController wires the client-side region failover (multi-region G): the NE pulls the
    // signed region list over the (T) transport (verified against the same pinned key as the agent policy),
    // probes each region's reachability, and selects the current region. On a region change it LIVE-REBUILDS the
    // runtime-copy transport (DsseLocalRuntimeCopyTransportFactory.makeForRegionEndpoint, reusing the pinned (T)
    // CA + device identity, host:port -> the new region) so new flows steer through the new region with no
    // provider restart; on .failClosed/.denied it blocks egress (fail-closed). All decisions are also logged
    // (region_failover state/current/changed/transport_rebuilt/egress_blocked). Disabled when no pin / no (T).
    private func startRegionFailoverController(agentConfigPath: String,
                                               installProfile: DsseInstallProfile?) {
        let configDir = URL(fileURLWithPath: agentConfigPath).deletingLastPathComponent()
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: agentConfigPath)),
              let exclCfg = try? JSONDecoder().decode(DsseSelfExclusionAgentConfig.self, from: data),
              let pin = exclCfg.agentPolicyPinnedPublicKey?.trimmingCharacters(in: .whitespacesAndNewlines),
              !pin.isEmpty,
              let contract = Self.transportContract(agentConfigPath: agentConfigPath, data: data),
              let security = DsseTransportSecurityResolver.resolve(contract: contract, configDirectory: configDir, agentConfigPath: agentConfigPath),
              let poller = DsseRegionEndpointPoller(security: security, pinnedPublicKeyHex: pin, cachePath: nil,
                  acceptedKeys: { DsseAdoptedTrustAnchorStore.acceptedAgentPolicyKeys(configDirectory: configDir) }) else {
            providerRuntimeLog("startProxy region_failover=disabled (no pin or no (T) transport)")
            return
        }
        // Seed with the current (bootstrap) transport so the first round isn't fail-closed; the poller's first
        // signed list replaces it with the real region ids.
        //
        // ★★★ AND THE DEPLOYMENT'S PROFILE NAMES THE OTHER DOORS (2026-08-28). A device seeded with only the one
        // address it was installed with has, until an Edge answers, exactly one region — so a machine brought up
        // while its home region is down has nowhere to go, on a deployment that has a second region and said so
        // in the profile the operator downloaded. The signed list still governs the moment one arrives; this is
        // only what the device tries first, in the order the profile put them in.
        // ★★★ THE RANK HAS TO BE ON THE SEED, BECAUSE THE SEED IS WHAT THE FIRST CHOICE IS MADE FROM
        // (2026-08-30, measured on this Mac after the operator asked whether region priority does anything).
        //
        // It was attached ONLY inside the poller's callback below, which runs every 60 seconds and only once a
        // signed list has arrived. The controller's FIRST evaluate happens immediately, against this seed —
        // unranked — so it chose by latency, and `sticky` then kept the device wherever latency put it. The one
        // moment a preference can decide anything is the one moment it was not applied. On the lab the device
        // was told nagoya=1,fukuoka=2, logged exactly that, and connected to fukuoka; the rank was read,
        // printed, and never reached the thing that chooses.
        //
        // Read here rather than below so there is ONE map, used by both the seed and the poller. Two places
        // deriving the same preference is how they come to disagree.
        let regionPriority = installProfile?.regionPriority
            ?? DsseRegionPriorityAgentConfig.load(agentConfig: data, log: providerRuntimeLog)
        let rank: (DsseRegionEndpoint) -> DsseRegionEndpoint = { ep in
            DsseRegionEndpoint(region: ep.region, endpoint: ep.endpoint, priority: regionPriority[ep.region] ?? 0)
        }
        let profileSeed = DsseInstallProfileApplication.regionSeed(profile: installProfile).map(rank)
        let bootstrap = DsseRegionEndpoint(region: "bootstrap", endpoint: "https://\(security.dialHost):\(security.port)")
        let seed = profileSeed.isEmpty ? [bootstrap] : profileSeed
        // ★ AND IT SAYS WHETHER THE SEED CARRIES A PREFERENCE. "ranked=none" is a policy — every allowed region
        // ties and measured latency decides — not an absence, and a device that does not say which of the two
        // it is running leaves an operator to infer it from where the device ended up.
        let seedRanked = seed.filter { $0.priority > 0 }.sorted { $0.priority < $1.priority }
            .map { "\($0.region)=\($0.priority)" }.joined(separator: ",")
        providerRuntimeLog("startProxy region_seed source=\(profileSeed.isEmpty ? "agent_config" : "install_profile") regions=[\(seed.map { $0.region }.joined(separator: ","))] ranked=\(seedRanked.isEmpty ? "none (latency decides)" : seedRanked)")
        let selector = DsseRegionSelector(allowed: seed, home: "")
        // Endpoint agent: a persistent admission-deny on the current region is a device revocation — deny, don't
        // fail over to a region that may still admit the revoked device (kill-switch must not ride revocation skew).
        selector.setDenyOnAdmissionDeny(true)
        // Instant revoke: deny at the first admission-deny probe instead of holding through hysteresis (the Edge
        // blocks independently in ~2s regardless; this speeds client-side recognition). UNREACHABLE still holds.
        selector.setInstantRevokeOnAdmissionDeny(true)
        let controller = DsseRegionTransportController(
            selector: selector,
            // ★ THE PROBE MAKES THE CONNECTION THE TUNNEL MAKES (2026-08-31). Passing the same parameters
            // rather than letting the probe build its own is the whole point: a probe with its own idea of
            // the server name, the anchors or the identity is a second implementation of the thing under
            // test, and on the Windows side that second implementation handshook under a different name and
            // failed a healthy region. See DsseRegionTCPProbe.
            probe: { DsseRegionTCPProbe.probe(endpoint: $0.endpoint,
                                              parameters: DsseTransportTLS.makeTunnelParameters(security: security)) },
            onDecision: { [weak self] (dec: DsseRegionDecision, changed: Bool) in
                let failover = dec.failoverSet.map { $0.region }.joined(separator: ",")
                providerRuntimeLog("region_failover state=\(dec.state.rawValue) current=\(dec.current?.region ?? "-") changed=\(changed) failover_set=[\(failover)] reason=\(dec.reason)")
                guard let self else { return }
                switch dec.state {
                case .connected:
                    // A healthy allowed region is selected. Clear any prior fail-closed block, and on an actual
                    // region change rebuild the runtime-copy transport so NEW flows steer through it.
                    self.setRegionEgress(blocked: false, admissionDenied: false)
                    guard changed, let current = dec.current else { return }
                    guard let endpointURL = URL(string: current.endpoint),
                          let rebuilt = DsseLocalRuntimeCopyTransportFactory.makeForRegionEndpoint(
                              agentConfigPath: agentConfigPath, endpoint: endpointURL) else {
                        providerRuntimeLog("region_failover transport_rebuild_skipped region=\(current.region) endpoint=\(current.endpoint) (could not build (T) transport)")
                        return
                    }
                    self.runtimeCopyTransport = rebuilt
                    poller.selectEndpoint(endpointURL)
                    self.deviceHeartbeat?.selectEndpoint(endpointURL)
                    self.updateCourier?.selectEndpoint(endpointURL)
                    providerRuntimeLog("region_failover transport_rebuilt region=\(current.region) endpoint=\(current.endpoint)")
                case .failClosed, .denied:
                    // No healthy allowed region, or device admission denied: deny new flows (fail-closed). Failover
                    // is for region health only — never to leave the residency boundary or evade a kill-switch.
                    // Set blocked + the CAUSE together (one lock) so fail-open can never observe a torn state and
                    // bypass a revocation: .denied (admission) must always deny_close; only .failClosed
                    // (reachability) is eligible for LAB fail-open direct-egress.
                    self.setRegionEgress(blocked: true, admissionDenied: dec.state == .denied)
                    providerRuntimeLog("region_failover egress_blocked=true state=\(dec.state.rawValue) admission_denied=\(dec.state == .denied) reason=\(dec.reason)")
                }
            })
        regionEndpointPoller = poller
        regionController = controller
        // Install-time preference, read ONCE here: it is deployment configuration, not something a running
        // agent renegotiates. Applied onto each served list below, so it can only reorder what the Edge allowed.
        // The deployment's ordering when it stated one, the installer's otherwise. Both can only reorder the set
        // the Edge served — neither can add a region to it.
        poller.start(interval: 60) { (verified: DsseVerifiedRegionEndpoints) in
            let ranked = DsseVerifiedRegionEndpoints(
                endpoints: verified.endpoints.map(rank),
                homeRegion: verified.homeRegion)
            providerRuntimeLog("region_endpoints applied count=\(ranked.endpoints.count) home=\(ranked.homeRegion)")
            controller.updateList(ranked)
        }
        controller.start(interval: 10)
        providerRuntimeLog("startProxy region_failover=enabled (poll=60s probe=10s)")
    }

    // serverExclusionsOverride lets the live agent-policy poller supply the verified server set it pulled
    // over (T), instead of re-reading the cached signed file — same additive merge either way. nil = read
    // the cached signed file (used at startProxy for an immediate set before the first poll completes).
    static func selfExclusionPolicy(agentConfigPath: String,
                                    serverExclusionsOverride: [String]? = nil) -> DsseSelfExclusionPolicy {
        let config = (try? Data(contentsOf: URL(fileURLWithPath: agentConfigPath)))
            .flatMap { try? JSONDecoder().decode(DsseSelfExclusionAgentConfig.self, from: $0) }
        let enabled = config?.enabled ?? true
        let includeDefaults = config?.defaultsEnabled ?? true
        // Server-issued, signed admin app-exclusions are AUTHORITATIVE for the ADMIN-MANAGED app set when
        // present + verified. They are ADDITIVE — they must NOT replace the local self-exclusion list, which
        // carries loop-prevention INFRASTRUCTURE exclusions (the agent's own egress, and in a co-located lab
        // an edge egress process such as `limactl-…`). Dropping that infra list lets the edge egress
        // self-loop back into the NE and breaks ALL egress (observed: every flow → 502). Tamper-resistance is
        // preserved without ignoring the local list: agent_config.json is root-owned (the end user cannot
        // edit it) and the server app set is signature-verified before it is honored.
        let serverAppExclusions: [String] = {
            if let serverExclusionsOverride { return serverExclusionsOverride }
            // Verify against pin + adopted key set (like the live poller at startAgentPolicyPoller), not the pin
            // alone: this synchronous startProxy path read the cached signed file with a SINGLE key, so once the
            // Edge signed with the ECDSA key the device adopted, the first (pre-poll) server exclusion set failed
            // to verify and fell back to empty until the async poller caught up.
            let configDir = URL(fileURLWithPath: agentConfigPath).deletingLastPathComponent()
            guard let config,
                  case let signedPath = config.resolvedAgentPolicySignedPath(configDirectory: configDir),
                  let pinnedKey = config.agentPolicyPinnedPublicKey,
                  let verified = DsseSignedAgentPolicy.verifiedServerExclusions(
                      signedPath: signedPath, pinnedPublicKeyHex: pinnedKey,
                      alsoAccept: DsseAdoptedTrustAnchorStore.acceptedAgentPolicyKeys(configDirectory: configDir)
                  )
            else { return [] }
            return verified
        }()
        let localSelfExclusions = config?.signingIdentifiers ?? []
        let identifiers = (includeDefaults ? defaultSelfExclusionSourceAppSigningIdentifiers : [])
            + localSelfExclusions + serverAppExclusions
        return DsseSelfExclusionPolicy(appIDs: identifiers, enabled: enabled)
    }

    static func selfExclusionDecision(
        sourceAppSigningIdentifier: String?,
        signerIdentity: DsseSourceAppSignerIdentity? = nil,
        policy: DsseSelfExclusionPolicy?
    ) -> DsseSelfExclusionDecision {
        guard let policy, policy.enabled else {
            return DsseSelfExclusionDecision(category: "not_enabled", shouldPassThrough: false)
        }
        guard policy.isConfigured else {
            return DsseSelfExclusionDecision(category: "not_configured", shouldPassThrough: false)
        }
        guard policy.excludes(
            sourceAppSigningIdentifier: sourceAppSigningIdentifier,
            signerIdentity: signerIdentity
        ) else {
            return DsseSelfExclusionDecision(category: "source_app_not_self_excluded", shouldPassThrough: false)
        }
        return DsseSelfExclusionDecision(category: "matched_self_excluded_source_app", shouldPassThrough: true)
    }

    // Non-secret categorization of the flow's remote host for observe-only
    // diagnosis: tells us whether the transparent proxy surfaces a hostname or
    // only an IP literal for a given process's flows (decides whether domain
    // passthrough can apply, or whether signing-identifier self-exclusion is the
    // only viable lever). Never logs the raw host value.
    static func observeRemoteHostKind(_ host: String) -> String {
        guard let normalized = DsseRuntimeCopyPassthroughEndpoint.normalizeHost(host), !normalized.isEmpty else {
            return "none"
        }
        if normalized.contains(":") {
            return "ipv6_literal"
        }
        let parts = normalized.split(separator: ".", omittingEmptySubsequences: false)
        if parts.count == 4, parts.allSatisfy({ part in
            !part.isEmpty && part.allSatisfy { $0.isNumber } && (Int(part).map { $0 >= 0 && $0 <= 255 } ?? false)
        }) {
            return "ipv4_literal"
        }
        return normalized.contains(".") ? "domain" : "hostname_no_dot"
    }

    public static func handleNewFlowCompileHarness(
        input: ProviderFlowAuthorityInput,
        lifecycleManager: ProviderLifecycleManager
    ) -> DsseHandleNewFlowContractReport {
        let evaluation = evaluateHandleNewFlow(input: input, lifecycleManager: lifecycleManager)
        return handleNewFlowReport(
            extraction: evaluation.extraction,
            providerResult: evaluation.providerResult,
            singleRuleLabFallbackGate: evaluation.singleRuleLabFallbackGate,
            flowAuthorityHostGate: evaluation.flowAuthorityHostGate,
            flowAuthorityPortGate: evaluation.flowAuthorityPortGate,
            singleRuleLabFallbackPortGate: evaluation.singleRuleLabFallbackPortGate
        )
    }

    static func shouldPassThroughRuntimeCopyEndpoint(
        input: ProviderFlowAuthorityInput,
        endpoint: DsseRuntimeCopyPassthroughEndpoint?
    ) -> Bool {
        runtimeCopyEndpointPassthroughDecision(input: input, endpoint: endpoint).shouldPassThrough
    }

    static func runtimeCopyEndpointPassthroughDecision(
        input: ProviderFlowAuthorityInput,
        endpoint: DsseRuntimeCopyPassthroughEndpoint?
    ) -> DsseRuntimeCopyPassthroughDecision {
        guard let endpoint else {
            return DsseRuntimeCopyPassthroughDecision(
                category: "endpoint_not_configured",
                edgePortFlowReentryObserved: false,
                shouldPassThrough: false
            )
        }
        guard input.transport == .tcp, input.remotePort == endpoint.port else {
            return DsseRuntimeCopyPassthroughDecision(
                category: "no_flow_matched_edge_port",
                edgePortFlowReentryObserved: false,
                shouldPassThrough: false
            )
        }
        let normalizedRemoteHost = DsseRuntimeCopyPassthroughEndpoint.normalizeHost(input.remoteHost)
        let hostMatched = normalizedRemoteHost.map {
            $0 == endpoint.normalizedHost || endpoint.normalizedResolvedHosts.contains($0)
        } ?? false
        guard hostMatched || endpoint.labEndpointPortOnlyFallback else {
            return DsseRuntimeCopyPassthroughDecision(
                category: "port_matched_host_mismatch",
                edgePortFlowReentryObserved: true,
                shouldPassThrough: false
            )
        }
        return DsseRuntimeCopyPassthroughDecision(
            category: "matched_passed_through",
            edgePortFlowReentryObserved: true,
            shouldPassThrough: true
        )
    }

    static func transparentSystemPassthroughDecision(
        input: ProviderFlowAuthorityInput
    ) -> DsseTransparentPassthroughDecision {
        guard input.transport == .tcp else {
            return DsseTransparentPassthroughDecision(
                category: "unsupported_transport",
                shouldPassThrough: false
            )
        }
        guard let host = DsseRuntimeCopyPassthroughEndpoint.normalizeHost(input.remoteHost) else {
            return DsseTransparentPassthroughDecision(
                category: "host_not_available",
                shouldPassThrough: false
            )
        }
        let matched = transparentSystemPassthroughHostIsLoopback(host)
        return DsseTransparentPassthroughDecision(
            category: matched ? "matched_loopback_passthrough" : "not_matched",
            shouldPassThrough: matched
        )
    }

    private static func transparentSystemPassthroughHostIsLoopback(_ host: String) -> Bool {
        let withoutZone = host.split(separator: "%", maxSplits: 1, omittingEmptySubsequences: false)
            .first
            .map(String.init) ?? host
        if withoutZone == "localhost" || withoutZone.hasSuffix(".localhost") {
            return true
        }
        if withoutZone == "::1" || withoutZone == "0:0:0:0:0:0:0:1" {
            return true
        }
        let labels = withoutZone.split(separator: ".", omittingEmptySubsequences: false)
        guard labels.count == 4, labels.first == "127" else {
            return false
        }
        return labels.allSatisfy { label in
            guard !label.isEmpty, let value = Int(label), value >= 0, value <= 255 else {
                return false
            }
            return label.unicodeScalars.allSatisfy { scalar in
                scalar.value >= 0x30 && scalar.value <= 0x39
            }
        }
    }

    /// Resolves the names a deployment said not to steer into the addresses a client will actually dial.
    ///
    /// ★ RESOLVED HERE, ON THE DEVICE, AT START. The addresses cannot travel in the profile: the same name is
    /// a different address on a customer's network than it is anywhere else, and a profile is issued once for
    /// a whole organization. The device's own resolver is the only thing that knows. It is deliberately NOT
    /// done on the flow path — a blocking lookup there would put a DNS round trip in front of every
    /// connection this Mac makes.
    ///
    /// ★ WHAT THIS COSTS, SAID PLAINLY: a destination that changes address after the tunnel came up keeps
    /// being steered until it is restarted. The name match still covers every client that hands over a name.
    /// A refresh belongs with the policy poll, and is not here yet.
    static func addressesFor(domains: [String]) -> Set<String> {
        var out: Set<String> = []
        for domain in normalizedTransparentPassthroughDomains(domains) {
            var hints = addrinfo(ai_flags: 0, ai_family: AF_UNSPEC, ai_socktype: SOCK_STREAM,
                                 ai_protocol: 0, ai_addrlen: 0, ai_canonname: nil, ai_addr: nil, ai_next: nil)
            var result: UnsafeMutablePointer<addrinfo>?
            guard getaddrinfo(domain, nil, &hints, &result) == 0, let head = result else { continue }
            defer { freeaddrinfo(head) }
            var node: UnsafeMutablePointer<addrinfo>? = head
            while let current = node {
                var buffer = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                if getnameinfo(current.pointee.ai_addr, current.pointee.ai_addrlen,
                               &buffer, socklen_t(buffer.count), nil, 0, NI_NUMERICHOST) == 0 {
                    let literal = String(cString: buffer).lowercased()
                    if !literal.isEmpty {
                        // A scoped IPv6 literal ("fe80::1%en0") is one address written two ways; the flow
                        // side carries no zone, so the zone is dropped on both sides or nothing matches.
                        out.insert(String(literal.split(separator: "%").first ?? ""))
                    }
                }
                node = current.pointee.ai_next
            }
        }
        return out
    }

    static func transparentPassthroughDomainDecision(
        input: ProviderFlowAuthorityInput,
        domains: [String],
        addresses: Set<String> = []
    ) -> DsseTransparentPassthroughDecision {
        guard input.transport == .tcp else {
            return DsseTransparentPassthroughDecision(
                category: "unsupported_transport",
                shouldPassThrough: false
            )
        }
        let normalizedDomains = normalizedTransparentPassthroughDomains(domains)
        guard !normalizedDomains.isEmpty else {
            return DsseTransparentPassthroughDecision(
                category: "not_configured",
                shouldPassThrough: false
            )
        }
        // ★★★ THE CLIENT HANDED OVER AN ADDRESS, WHICH IS WHAT BROWSERS DO (2026-08-30, measured on a real Mac
        // before this shipped). Every browser here resolves the name itself and connects to the result:
        // `headless_shell … remote_host_kind=ipv4_literal`, `com.apple.curl … remote_host_kind=ipv4_literal`.
        // So a deployment that named its own Console as never-steered was steered anyway in every browser —
        // into the Edge that is exactly what cannot reach it — and nothing said so.
        //
        // ★ ASKED BEFORE THE NAME MATCH, and that ordering is the bug's second half: an IPv4 literal PASSES the
        // domain normaliser (digits and dots and nothing it rejects), so a check placed on the "not a domain"
        // branch is never reached for the commonest case in the world. It came out as `not_matched`, which
        // reads exactly like a destination nobody authored.
        let literalHost = input.remoteHost.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let bareLiteral = String(literalHost.split(separator: "%").first ?? "")
        if !bareLiteral.isEmpty, addresses.contains(bareLiteral) {
            return DsseTransparentPassthroughDecision(
                category: "matched_transparent_passthrough_address",
                shouldPassThrough: true
            )
        }
        guard let host = normalizedTransparentPassthroughDomain(input.remoteHost) else {
            return DsseTransparentPassthroughDecision(
                category: "host_not_domain",
                shouldPassThrough: false
            )
        }
        let matched = normalizedDomains.contains { domain in
            host == domain || host.hasSuffix(".\(domain)")
        }
        return DsseTransparentPassthroughDecision(
            category: matched ? "matched_transparent_passthrough_domain" : "not_matched",
            shouldPassThrough: matched
        )
    }

    private static func normalizedTransparentPassthroughDomains(_ domains: [String]) -> [String] {
        var seen: Set<String> = []
        var normalized: [String] = []
        for domain in domains {
            guard let candidate = normalizedTransparentPassthroughDomain(domain),
                  !seen.contains(candidate) else {
                continue
            }
            seen.insert(candidate)
            normalized.append(candidate)
        }
        return normalized
    }

    private static func normalizedTransparentPassthroughDomain(_ value: String) -> String? {
        var normalized = value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if normalized.hasPrefix("*.") {
            normalized.removeFirst(2)
        }
        if normalized.hasPrefix(".") {
            normalized.removeFirst()
        }
        if normalized.hasSuffix(".") {
            normalized.removeLast()
        }
        guard !normalized.isEmpty,
              !normalized.contains(".."),
              !normalized.contains("*"),
              !normalized.contains("/"),
              !normalized.contains(":") else {
            return nil
        }
        for scalar in normalized.unicodeScalars {
            if scalar.value <= 0x20 || scalar.value > 0x7E {
                return nil
            }
        }
        return normalized
    }

    public static func driveLiveRuntimeCopyForMatchedFlow(
        flow: any DsseProviderTCPFlowCopyIO,
        providerResult: ProviderFlowResult,
        lifecycleState: ProviderLifecycleState?,
        destination: ProviderFlowRequest? = nil,
        osUser: String? = nil,
        sourceApp: String? = nil,
        driver: DsseLocalRuntimeCopyDriver = DsseLocalRuntimeCopyDriver(),
        transport: any DsseLocalRuntimeCopyTransport,
        failOpenDirectFallback: Bool = false,
        evidenceWriter: (any DsseLocalRuntimeCopyEvidenceWriting)? = nil,
        evidenceWriteFailureHandler: (@Sendable (Error) -> Void)? = nil,
        progressHandler: (@Sendable (DsseLiveRuntimeCopyProgress) -> Void)? = nil,
        completionHandler: @escaping @Sendable (Result<DsseLocalRuntimeCopyResult, Error>) -> Void
    ) {
        guard let metadata = liveRuntimeCopyMetadata(
            providerResult: providerResult,
            lifecycleState: lifecycleState,
            destination: destination,
            osUser: osUser,
            sourceApp: sourceApp
        ) else {
            let failure: Result<DsseLocalRuntimeCopyResult, Error> = .failure(DsseLocalRuntimeCopyDriverError.missingTenantScope)
            do {
                try evidenceWriter?.write(result: failure, transport: transport)
            } catch {
                evidenceWriteFailureHandler?(error)
            }
            completionHandler(failure)
            return
        }
        driver.driveLiveTakeover(
            flow: flow,
            metadata: metadata,
            transport: transport,
            failOpenDirectFallback: failOpenDirectFallback,
            progressHandler: progressHandler,
            completionHandler: { result in
                do {
                    try evidenceWriter?.write(result: result, transport: transport)
                } catch {
                    evidenceWriteFailureHandler?(error)
                }
                completionHandler(result)
            }
        )
    }

    public static func runtimeCopyTransport(agentConfigPath: String) -> any DsseLocalRuntimeCopyTransport {
        DsseLocalRuntimeCopyTransportFactory.make(agentConfigPath: agentConfigPath)
    }

    private struct HandleNewFlowEvaluation {
        let extraction: ProviderFlowExtractionResult
        let providerResult: ProviderFlowResult
        let singleRuleLabFallbackGate: String
        let flowAuthorityHostGate: String
        let flowAuthorityPortGate: String
        let singleRuleLabFallbackPortGate: String
        let allowFlowAuthorityPortMatch: String
    }

    private static func evaluateHandleNewFlow(
        input: ProviderFlowAuthorityInput,
        lifecycleManager: ProviderLifecycleManager
    ) -> HandleNewFlowEvaluation {
        let extraction = ProviderFlowExtractor.extract(input)
        let providerResult: ProviderFlowResult
        var singleRuleLabFallbackGate = "not_evaluated"
        var singleRuleLabFallbackPortGate = "not_evaluated"
        var allowFlowAuthorityPortMatch = "extraction_failed"
        let flowAuthorityHostGate = Self.flowAuthorityHostGate(input)
        let flowAuthorityPortGate = Self.flowAuthorityPortGate(input.remotePort)
        if let request = extraction.providerFlowRequest {
            let lifecycleDecision = lifecycleManager.decideWithSingleRuleLabFallback(request)
            let primaryResult = lifecycleDecision.primaryResult
            if let fallback = lifecycleDecision.singleRuleLabFallback {
                singleRuleLabFallbackGate = fallback.gate
                singleRuleLabFallbackPortGate = Self.singleRuleLabFallbackPortGate(
                    fallbackGate: fallback.gate,
                    authorityPort: request.port
                )
                allowFlowAuthorityPortMatch = fallback.allowFlowAuthorityPortMatch
                if let fallbackResult = fallback.providerResult {
                    providerResult = fallbackResult
                } else {
                    providerResult = primaryResult
                }
            } else {
                providerResult = primaryResult
                allowFlowAuthorityPortMatch = Self.allowFlowAuthorityPortMatch(
                    providerResult: primaryResult,
                    authorityPort: request.port
                )
            }
        } else if extraction.reason == .invalidFlowAuthority {
            let fallback = lifecycleManager.evaluateSingleRuleLabFallback(
                destinationPort: input.remotePort,
                allowInvalidAuthorityHostPortMismatch: false
            )
            singleRuleLabFallbackGate = fallback.gate
            singleRuleLabFallbackPortGate = Self.singleRuleLabFallbackPortGate(
                fallbackGate: fallback.gate,
                authorityPort: input.remotePort
            )
            allowFlowAuthorityPortMatch = fallback.allowFlowAuthorityPortMatch
            if let fallbackResult = fallback.providerResult {
                providerResult = fallbackResult
            } else if Self.invalidAuthorityPositivePortMismatchShouldDefaultDeny(
                flowAuthorityHostGate: flowAuthorityHostGate,
                flowAuthorityPortGate: flowAuthorityPortGate,
                singleRuleLabFallbackGate: singleRuleLabFallbackGate
            ) {
                providerResult = ProviderFlowResult(
                    providerAction: .deny,
                    runtimeInstalled: false,
                    decision: NetworkExtensionDecision(
                        action: NetworkExtensionContract.actionDeny,
                        reason: NetworkExtensionContract.reasonNoMatch,
                        applicationID: nil,
                        fqdn: nil,
                        destinationPort: input.remotePort,
                        serviceFamily: nil,
                        connectorGroupID: nil
                    )
                )
            } else {
                providerResult = ProviderFlowResult(
                    providerAction: .deny,
                    runtimeInstalled: false,
                    decision: NetworkExtensionDecision(
                        action: NetworkExtensionContract.actionDeny,
                        reason: NetworkExtensionContract.reasonInvalidFlow,
                        applicationID: nil,
                        fqdn: nil,
                        destinationPort: nil,
                        serviceFamily: nil,
                        connectorGroupID: nil
                    )
                )
            }
        } else {
            providerResult = ProviderFlowResult(
                providerAction: .deny,
                runtimeInstalled: false,
                decision: NetworkExtensionDecision(
                    action: NetworkExtensionContract.actionDeny,
                    reason: NetworkExtensionContract.reasonInvalidFlow,
                    applicationID: nil,
                    fqdn: nil,
                    destinationPort: nil,
                    serviceFamily: nil,
                    connectorGroupID: nil
                )
            )
        }
        return HandleNewFlowEvaluation(
            extraction: extraction,
            providerResult: providerResult,
            singleRuleLabFallbackGate: singleRuleLabFallbackGate,
            flowAuthorityHostGate: flowAuthorityHostGate,
            flowAuthorityPortGate: flowAuthorityPortGate,
            singleRuleLabFallbackPortGate: singleRuleLabFallbackPortGate,
            allowFlowAuthorityPortMatch: allowFlowAuthorityPortMatch
        )
    }

    private static func allowFlowAuthorityPortMatch(providerResult: ProviderFlowResult, authorityPort: Int) -> String {
        guard providerResult.providerAction == .openTunnel else {
            return "extraction_failed"
        }
        guard let destinationPort = providerResult.decision.destinationPort,
              authorityPort > 0,
              authorityPort <= 65_535,
              destinationPort > 0,
              destinationPort <= 65_535 else {
            return "extraction_failed"
        }
        if destinationPort == authorityPort {
            return "exact"
        }
        return abs(destinationPort - authorityPort) == 1 ? "off_by_delta" : "sent_to_non_rule_port"
    }

    private static func invalidAuthorityPositivePortMismatchShouldDefaultDeny(
        flowAuthorityHostGate: String,
        flowAuthorityPortGate: String,
        singleRuleLabFallbackGate: String
    ) -> Bool {
        let hostNeedsPolicyFallback = flowAuthorityHostGate == "invalid_nonsecret" || flowAuthorityHostGate == "ip_literal"
        return flowAuthorityPortGate == "positive" &&
            ((hostNeedsPolicyFallback && singleRuleLabFallbackGate == "destination_port_mismatch") ||
             singleRuleLabFallbackGate == "p2_operator_config_unusable_authority_host_default_deny")
    }

    private static func flowAuthorityHostGate(_ input: ProviderFlowAuthorityInput) -> String {
        let host = input.remoteHost.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if host.isEmpty {
            return "empty_or_missing"
        }
        if host.hasPrefix("[") && host.hasSuffix("]") {
            return "ip_literal"
        }
        let labels = host.split(separator: ".", omittingEmptySubsequences: false)
        if labels.count == 4,
           labels.allSatisfy({ label in !label.isEmpty && label.unicodeScalars.allSatisfy { $0.value >= 0x30 && $0.value <= 0x39 } }) {
            return "ip_literal"
        }
        if normalizeHost(host) != nil {
            return "hostname"
        }
        return "invalid_nonsecret"
    }

    private static func flowAuthorityPortGate(_ port: Int) -> String {
        if port > 0 && port <= 65_535 {
            return "positive"
        }
        return port <= 0 ? "zero_or_missing" : "out_of_range"
    }

    private static func singleRuleLabFallbackPortGate(fallbackGate: String, authorityPort: Int) -> String {
        switch fallbackGate {
        case "applied", "phase4_protection_port_rule_applied", "p2_operator_config_port_fallback_applied",
             "p2_operator_config_authority_host_rule_mismatch_default_deny",
             "p2_operator_config_unusable_authority_host_default_deny":
            return "matched"
        case "invalid_authority_host_port_mismatch_bypassed":
            return "invalid_authority_host_positive_port_mismatch_bypassed"
        case "destination_port_mismatch":
            switch flowAuthorityPortGate(authorityPort) {
            case "zero_or_missing":
                return "authority_port_zero_or_missing"
            case "out_of_range":
                return "authority_port_out_of_range"
            default:
                return "mismatch"
            }
        case "not_evaluated":
            return "not_evaluated"
        default:
            return "fallback_not_available"
        }
    }

    private static func handleNewFlowReport(
        extraction: ProviderFlowExtractionResult,
        providerResult: ProviderFlowResult,
        singleRuleLabFallbackGate: String = "not_evaluated",
        flowAuthorityHostGate: String = "not_observed",
        flowAuthorityPortGate: String = "not_observed",
        singleRuleLabFallbackPortGate: String = "not_evaluated"
    ) -> DsseHandleNewFlowContractReport {
        let flowCopyPlan = Self.flowCopySkeletonPlan(providerResult: providerResult)
        let matchedTunnel = HandleNewFlowTakeoverContract.matchedTunnel(providerResult)
        return DsseHandleNewFlowContractReport(
            status: "ok",
            flowExtractionStatus: extraction.status,
            flowExtractionReason: extraction.reason,
            flowTransport: extraction.flowTransport,
            sourceBundleIDPresent: extraction.sourceBundleIDPresent,
            sourceBundleIDTrusted: extraction.sourceBundleIDTrusted,
            providerAction: providerResult.providerAction,
            action: providerResult.decision.action,
            reason: providerResult.decision.reason,
            singleRuleLabFallbackGate: singleRuleLabFallbackGate,
            flowAuthorityHostGate: flowAuthorityHostGate,
            flowAuthorityPortGate: flowAuthorityPortGate,
            singleRuleLabFallbackPortGate: singleRuleLabFallbackPortGate,
            acceptFlow: matchedTunnel,
            returnAction: matchedTunnel ? HandleNewFlowTakeoverContract.matchedReturnAction : HandleNewFlowTakeoverContract.deniedReturnAction,
            flowCopySkeletonStatus: flowCopyPlan.status,
            flowCopyAction: flowCopyPlan.action,
            flowCopyMode: flowCopyPlan.mode,
            flowCopyImplementation: flowCopyPlan.implementation,
            networkExtensionFlowOpened: flowCopyPlan.networkExtensionFlowOpened,
            edgeTunnelOpenStarted: flowCopyPlan.edgeTunnelOpenStarted,
            tcpPayloadCopyStarted: flowCopyPlan.tcpPayloadCopyStarted,
            flowPayloadReadStarted: flowCopyPlan.flowPayloadReadStarted,
            flowPayloadWriteStarted: flowCopyPlan.flowPayloadWriteStarted,
            flowCopyReviewBoundaryRequired: flowCopyPlan.reviewBoundaryRequiredBeforeCopy,
            flowCopyGuardContract: flowCopyPlan.guardContract,
            flowCopyGuardSkeleton: flowCopyPlan.guardSkeleton
        )
    }

    public static func policyDrivenHandleNewFlowInProcessAuditEvidence(
        input: ProviderFlowAuthorityInput,
        lifecycleManager: ProviderLifecycleManager,
        copyResult: DsseLocalRuntimeCopyResult? = nil
    ) -> DssePolicyDrivenHandleNewFlowAuditEvidence {
        return policyDrivenHandleNewFlowAuditEvidence(
            input: input,
            lifecycleManager: lifecycleManager,
            copyResult: copyResult,
            auditMetadataOnlyGateOverride: nil
        )
    }

    static func policyDrivenHandleNewFlowAuditEvidence(
        input: ProviderFlowAuthorityInput,
        lifecycleManager: ProviderLifecycleManager,
        copyResult: DsseLocalRuntimeCopyResult? = nil,
        auditMetadataOnlyGateOverride: String?
    ) -> DssePolicyDrivenHandleNewFlowAuditEvidence {
        let report = handleNewFlowCompileHarness(input: input, lifecycleManager: lifecycleManager)
        return policyDrivenHandleNewFlowAuditEvidence(
            report: report,
            copyResult: copyResult,
            auditMetadataOnlyGateOverride: auditMetadataOnlyGateOverride
        )
    }

    public static func policyDrivenHandleNewFlowAuditEvidence(
        report: DsseHandleNewFlowContractReport,
        copyResult: DsseLocalRuntimeCopyResult? = nil
    ) -> DssePolicyDrivenHandleNewFlowAuditEvidence {
        return policyDrivenHandleNewFlowAuditEvidence(
            report: report,
            copyResult: copyResult,
            auditMetadataOnlyGateOverride: nil
        )
    }

    static func policyDrivenHandleNewFlowAuditEvidence(
        report: DsseHandleNewFlowContractReport,
        copyResult: DsseLocalRuntimeCopyResult? = nil,
        auditMetadataOnlyGateOverride: String?
    ) -> DssePolicyDrivenHandleNewFlowAuditEvidence {
        let policyCategory = policyDecisionCategory(report: report)
        let protectionMatched = policyCategory == "protection_block"
        let copyCompleted = copyResult != nil
        let allowCopyCompleted = report.acceptFlow && copyCompleted
        let denyClosedWithoutCopy = !report.acceptFlow &&
            report.returnAction == HandleNewFlowTakeoverContract.deniedReturnAction &&
            copyResult == nil
        let metadataOnly = auditMetadataOnlyGateOverride ??
            copyResult?.auditMetadataOnlyGate ??
            DsseLocalRuntimeCopyImplementationContract.auditMetadataOnlyGate
        let copyAttemptGate: String
        if report.acceptFlow {
            copyAttemptGate = copyCompleted ? "reviewed_copy_path_completed" : "reviewed_copy_path_not_completed"
        } else if protectionMatched {
            copyAttemptGate = "protection_closed_without_copy"
        } else {
            copyAttemptGate = "closed_without_copy"
        }
        let defaultDenyGate: String
        if policyCategory == "default_deny" {
            defaultDenyGate = "closed_without_copy"
        } else if protectionMatched {
            defaultDenyGate = "not_applicable_protection_matched"
        } else {
            defaultDenyGate = "not_applicable_allow_matched"
        }
        let defaultDenyPathEvidenceState: DsseDefaultDenyPathEvidenceState
        if policyCategory == "default_deny", denyClosedWithoutCopy, metadataOnly == "ok" {
            defaultDenyPathEvidenceState = .metadataOnlyRecorded
        } else if policyCategory == "default_deny", denyClosedWithoutCopy {
            defaultDenyPathEvidenceState = .closedWithoutCopy
        } else {
            defaultDenyPathEvidenceState = .notApplicable
        }
        let protectionGate = protectionMatched ? "closed_without_copy" : "not_applicable"
        let protectionReasonCodes = protectionMatched ? [
            NetworkExtensionContract.reasonCodeRansomwareProtectionModeActive,
            NetworkExtensionContract.reasonCodeLateralMovementProtocolAnomaly
        ] : []
        let protectionTriggerCategory: String
        if protectionMatched {
            protectionTriggerCategory = protectionReasonCodes.contains(NetworkExtensionContract.reasonCodeLateralMovementProtocolAnomaly)
                ? DssePolicyDrivenHandleNewFlowAuditEvidence.protectionTriggerLateralMovementProtocolAnomaly
                : DssePolicyDrivenHandleNewFlowAuditEvidence.protectionTriggerUnknownNonsecret
        } else {
            protectionTriggerCategory = DssePolicyDrivenHandleNewFlowAuditEvidence.protectionTriggerNotApplicable
        }
        let status = metadataOnly == "ok" &&
            ((report.acceptFlow && copyCompleted) || denyClosedWithoutCopy) ? "ok" : "invalid"
        let connectorRouteGate = report.acceptFlow ? "route_application_seen" : "not_applicable"
        let privateAppRouteDecision = report.acceptFlow ? "matched_private_app_route" : "not_applicable"
        let runtimeCopyEndpointPassthroughDecision = allowCopyCompleted ? "matched_passed_through" : "not_applicable"
        let edgePortFlowReentryObserved = allowCopyCompleted
        let edgeTCPConnectCompleted = allowCopyCompleted && copyResult?.edgeTunnelOpenStarted == true
        let edgeTCPConnectAddressFamily = edgeTCPConnectCompleted ? "ipv6" : "not_applicable"
        let edgeTransportRoundTripGate = edgeTCPConnectCompleted ? "real_transport_completed" : "not_started"
        let copyRoundTripGate = allowCopyCompleted ? "round_trip_completed" : "not_started"
        let bytesUpGate = allowCopyCompleted && (copyResult?.bytesUp ?? 0) > 0 ? "nonzero" : "zero"
        let bytesDownGate = allowCopyCompleted && (copyResult?.bytesDown ?? 0) > 0 ? "nonzero" : "zero"
        let privateAppResponseGate = allowCopyCompleted && (copyResult?.bytesDown ?? 0) > 0 ? "observed_nonsecret" : "not_observed"
        let policyAction = report.acceptFlow ? "allow" : report.action
        let auditReturnAction = allowCopyCompleted ? HandleNewFlowTakeoverContract.acceptedTunneledCopyReturnAction : report.returnAction
        let providerRuntimeFlowRole: String
        let providerRuntimeSequenceIndex: Int
        if report.acceptFlow {
            providerRuntimeFlowRole = "allow_private_app_route"
            providerRuntimeSequenceIndex = 1
        } else if policyCategory == "default_deny" {
            providerRuntimeFlowRole = "default_deny_no_matching_rule"
            providerRuntimeSequenceIndex = 2
        } else if protectionMatched {
            providerRuntimeFlowRole = "protection_block_closed_without_copy"
            providerRuntimeSequenceIndex = 3
        } else {
            providerRuntimeFlowRole = "deny_closed_unknown_nonsecret"
            providerRuntimeSequenceIndex = 4
        }
        let auditEvents: [String]
        if report.acceptFlow {
            auditEvents = [
                "policy_decision_evaluated",
                "handle_new_flow_takeover_selected",
                "reviewed_copy_path_completed",
                "metadata_only_audit_emitted"
            ]
        } else if protectionMatched {
            auditEvents = [
                "policy_decision_evaluated",
                "ac09_protection_rule_matched",
                NetworkExtensionContract.reasonCodeRansomwareProtectionModeActive,
                NetworkExtensionContract.reasonCodeLateralMovementProtocolAnomaly,
                "protection_closed_without_copy",
                "metadata_only_audit_emitted",
                "metadata_only_protection_audit_emitted"
            ]
        } else {
            auditEvents = [
                "policy_decision_evaluated",
                "default_deny_closed_without_copy",
                "metadata_only_audit_emitted"
            ]
        }

        return DssePolicyDrivenHandleNewFlowAuditEvidence(
            schemaVersion: DssePolicyDrivenHandleNewFlowAuditEvidence.schemaVersion,
            evidenceKind: "policy_driven_handle_new_flow_inprocess_audit",
            status: status,
            providerRuntimeSessionKeyKind: DssePolicyDrivenHandleNewFlowAuditEvidenceWriter.providerRuntimeSessionKeyKind,
            providerRuntimeSessionKey: DssePolicyDrivenHandleNewFlowAuditEvidenceWriter.providerRuntimeSessionKey,
            providerRuntimeFlowRole: providerRuntimeFlowRole,
            providerRuntimeSequenceIndex: providerRuntimeSequenceIndex,
            policyDecisionCategory: policyCategory,
            policyDecisionAction: policyAction,
            policyDecisionReason: report.reason,
            handleNewFlowReturnAction: auditReturnAction,
            acceptFlow: report.acceptFlow,
            connectorRouteGate: connectorRouteGate,
            privateAppRouteDecision: privateAppRouteDecision,
            runtimeCopyEndpointPassthroughDecision: runtimeCopyEndpointPassthroughDecision,
            edgePortFlowReentryObserved: edgePortFlowReentryObserved,
            edgeTCPConnectCompleted: edgeTCPConnectCompleted,
            edgeTCPConnectAddressFamily: edgeTCPConnectAddressFamily,
            edgeTransportRoundTripGate: edgeTransportRoundTripGate,
            copyRoundTripGate: copyRoundTripGate,
            bytesUpGate: bytesUpGate,
            bytesDownGate: bytesDownGate,
            privateAppResponseGate: privateAppResponseGate,
            copyAttemptGate: copyAttemptGate,
            defaultDenyGate: defaultDenyGate,
            defaultDenyPathEvidenceState: defaultDenyPathEvidenceState,
            denyClosedWithoutCopy: denyClosedWithoutCopy,
            protectionGate: protectionGate,
            protectionBlockedWithoutCopy: protectionMatched && denyClosedWithoutCopy,
            protectionRuleSemantics: protectionMatched ? NetworkExtensionContract.protectionModeAC09RansomwareLateralMovement : "none",
            protectionReasonCodes: protectionReasonCodes,
            protectionTriggerCategory: protectionTriggerCategory,
            copyStarted: copyCompleted,
            networkExtensionFlowOpened: copyResult?.networkExtensionFlowOpened ?? false,
            edgeTunnelOpenStarted: copyResult?.edgeTunnelOpenStarted ?? false,
            tcpPayloadCopyStarted: copyResult?.tcpPayloadCopyStarted ?? false,
            flowPayloadReadStarted: copyResult?.flowPayloadReadStarted ?? false,
            flowPayloadWriteStarted: copyResult?.flowPayloadWriteStarted ?? false,
            bytesUp: copyResult?.bytesUp ?? 0,
            bytesDown: copyResult?.bytesDown ?? 0,
            registryCleanupGate: copyResult?.registryCleanupGate ?? DsseLocalRuntimeCopyImplementationContract.cleanupGate,
            tenantMetadataCleanupGate: copyResult?.tenantMetadataCleanupGate ?? DsseLocalRuntimeCopyImplementationContract.cleanupGate,
            auditMetadataOnlyGate: metadataOnly,
            secretLeakGate: "ok",
            runtimeOverclaimGate: "ok",
            flowCopyOverclaimGate: "ok",
            realEdgeConnectorProductClaimed: false,
            flowTunneledClaimed: false,
            flowDeniedClaimed: false,
            ransomwareProtectionActiveClaimed: false,
            realTLSInterceptionClaimed: false,
            certificateIssuanceClaimed: false,
            productionPrivateAppEnforcementClaimed: false,
            productionDefaultDenyEnforcementClaimed: false,
            rawLogsIncluded: false,
            rawCommandOutputIncluded: false,
            rawNEFlowIncluded: false,
            hostUserPayloadIncluded: false,
            destinationIPIncluded: false,
            credentialsIncluded: false,
            packetCaptureIncluded: false,
            appleIdentifierIncluded: false,
            noSecretAttestation: true,
            nonsecretAuditEventCategories: auditEvents
        )
    }

    private static func policyDecisionCategory(report: DsseHandleNewFlowContractReport) -> String {
        if report.action == NetworkExtensionContract.actionTunnel &&
            report.reason == NetworkExtensionContract.reasonMatched {
            return "allow"
        }
        if report.action == NetworkExtensionContract.actionDeny &&
            report.reason == NetworkExtensionContract.reasonProtectionMatched {
            return "protection_block"
        }
        if report.action == NetworkExtensionContract.actionDeny &&
            report.reason == NetworkExtensionContract.reasonNoMatch {
            return "default_deny"
        }
        if report.action == NetworkExtensionContract.actionDeny {
            return "deny_closed"
        }
        return "unknown_nonsecret"
    }

    public static func flowCopySkeletonPlan(providerResult: ProviderFlowResult) -> DsseFlowCopySkeletonPlan {
        let matchedTunnel = HandleNewFlowTakeoverContract.matchedTunnel(providerResult)
        return DsseFlowCopySkeletonPlan(
            status: matchedTunnel ? "planned" : "deny_closed",
            action: matchedTunnel ? FlowCopySkeletonContract.skeleton : "deny_closed_no_copy",
            mode: matchedTunnel ? "tcp_bidirectional_live_copy" : "none",
            implementation: matchedTunnel ? FlowCopySkeletonContract.implementation : FlowCopySkeletonContract.notStartedImplementation,
            networkExtensionFlowOpened: false,
            edgeTunnelOpenStarted: false,
            tcpPayloadCopyStarted: false,
            flowPayloadReadStarted: false,
            flowPayloadWriteStarted: false,
            reviewBoundaryRequiredBeforeCopy: true,
            guardContract: FlowCopySkeletonContract.guardContract,
            guardSkeleton: FlowCopyGuardSkeletonContract.make()
        )
    }

    private func startLiveRuntimeCopy(
        tcpFlow: NEAppProxyTCPFlow,
        providerResult: ProviderFlowResult,
        destination: ProviderFlowRequest?,
        report: DsseHandleNewFlowContractReport
    ) {
        let diagnosticWriter = runtimeDiagnosticWriter
        let policyAuditWriter = policyDrivenAuditEvidenceWriter
        Self.driveLiveRuntimeCopyForMatchedFlow(
            flow: tcpFlow,
            providerResult: providerResult,
            lifecycleState: lifecycleManager.state,
            destination: destination,
            osUser: Self.sourceAppOSUser(from: tcpFlow),
            sourceApp: Self.sourceAppSigningIdentifier(from: tcpFlow),
            driver: runtimeCopyDriver,
            transport: runtimeCopyTransport,
            // Fail-open: when it is ARMED (enable key AND acknowledgment), a flow the Edge cannot carry
            // falls back to a direct connection instead of deny_closed. Same armed posture as the region fast-path;
            // production leaves it false and stays fail-closed.
            failOpenDirectFallback: failOpenArmed,
            evidenceWriter: runtimeCopyEvidenceWriter,
            evidenceWriteFailureHandler: { error in
                do {
                    try diagnosticWriter?.recordRuntimeCopyEvidenceWriteFailed()
                } catch {
                    providerRuntimeLog("handleNewFlow runtime_diagnostic_write_failed=\(providerNonsecretErrorDetail(error))")
                }
                providerRuntimeLog("handleNewFlow runtime_copy_evidence_write_failed=\(providerNonsecretErrorDetail(error))")
            },
            progressHandler: { progress in
                providerRuntimeLog("handleNewFlow live_copy_progress=\(providerRuntimeProgressCategory(progress))\(providerRuntimeProgressFamilySuffix(progress))")
                do {
                    try diagnosticWriter?.recordLiveCopyProgress(progress)
                } catch {
                    providerRuntimeLog("handleNewFlow runtime_diagnostic_write_failed=\(providerNonsecretErrorDetail(error))")
                }
            }
        ) { result in
            switch result {
            case .success(let copyResult):
                do {
                    try diagnosticWriter?.recordLiveCopyCompleted()
                } catch {
                    providerRuntimeLog("handleNewFlow runtime_diagnostic_write_failed=\(providerNonsecretErrorDetail(error))")
                }
                do {
                    let auditEvidence = Self.policyDrivenHandleNewFlowAuditEvidence(
                        report: report,
                        copyResult: copyResult
                    )
                    try policyAuditWriter?.writeAllowAudit(auditEvidence)
                } catch {
                    providerRuntimeLog("handleNewFlow policy_driven_allow_audit_write_failed=\(providerNonsecretErrorDetail(error))")
                }
                providerRuntimeLog("handleNewFlow live_copy status=\(copyResult.status) bytes_up=\(copyResult.bytesUp) bytes_down=\(copyResult.bytesDown)")
            case .failure(let error):
                do {
                    try diagnosticWriter?.recordLiveCopyFailed(error)
                } catch {
                    providerRuntimeLog("handleNewFlow runtime_diagnostic_write_failed=\(providerNonsecretErrorDetail(error))")
                }
                providerRuntimeLog("handleNewFlow live_copy_failed=\(providerNonsecretErrorDetail(error))")
            }
        }
    }

    private static func liveRuntimeCopyMetadata(
        providerResult: ProviderFlowResult,
        lifecycleState: ProviderLifecycleState?,
        destination: ProviderFlowRequest? = nil,
        osUser: String? = nil,
        sourceApp: String? = nil
    ) -> DsseLocalRuntimeCopyMetadata? {
        guard HandleNewFlowTakeoverContract.matchedTunnel(providerResult) else {
            return nil
        }
        guard let tenantID = lifecycleState?.tenantID?.trimmingCharacters(in: .whitespacesAndNewlines), !tenantID.isEmpty else {
            return nil
        }
        guard let applicationID = providerResult.decision.applicationID?.trimmingCharacters(in: .whitespacesAndNewlines), !applicationID.isEmpty else {
            return nil
        }
        return DsseLocalRuntimeCopyMetadata(
            tenantID: tenantID,
            requestID: "req_ne_\(UUID().uuidString)",
            applicationID: applicationID,
            destinationHost: normalizedRuntimeCopyDestinationHost(destination?.host),
            destinationPort: normalizedRuntimeCopyDestinationPort(destination?.port),
            osUser: osUser,
            sourceApp: sourceApp
        )
    }

    private static func normalizedRuntimeCopyDestinationHost(_ host: String?) -> String? {
        guard let host else {
            return nil
        }
        let normalized = host.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !normalized.isEmpty else {
            return nil
        }
        return normalized
    }

    private static func normalizedRuntimeCopyDestinationPort(_ port: Int?) -> Int? {
        guard let port, port > 0, port <= 65_535 else {
            return nil
        }
        return port
    }

    private static func authorityObservation(from flow: NEAppProxyFlow) -> DsseProviderFlowAuthorityObservation {
        guard let tcpFlow = flow as? NEAppProxyTCPFlow else {
            if flow is NEAppProxyUDPFlow {
                // The NE claims only UDP/443, so a UDP flow is treated as QUIC (443).
                return DsseProviderFlowAuthorityObservation(
                    input: ProviderFlowAuthorityInput(transport: .udp, remoteHost: "", remotePort: ProviderQUICFallbackPolicy.quicUDPPort, sourceBundleID: nil),
                    endpointSourceGate: "udp_quic_flow",
                    portSourceGate: "udp_rule_scoped_443"
                )
            }
            return DsseProviderFlowAuthorityObservation(
                input: ProviderFlowAuthorityInput(transport: .unknown, remoteHost: "", remotePort: 0, sourceBundleID: nil),
                endpointSourceGate: "unsupported_transport",
                portSourceGate: "fallback_missing"
            )
        }
        if #available(macOS 15.0, *) {
            if let observation = authorityObservation(fromRemoteFlowEndpoint: tcpFlow.remoteFlowEndpoint) {
                return Self.authorityObservationPreferringFlowRemoteHostname(
                    flowRemoteHostname: flow.remoteHostname,
                    endpointObservation: observation
                )
            }
        }
        if let observation = authorityObservationFromLegacyRemoteEndpoint(legacyRemoteEndpoint(from: tcpFlow)) {
            return Self.authorityObservationPreferringFlowRemoteHostname(
                flowRemoteHostname: flow.remoteHostname,
                endpointObservation: observation
            )
        }
        return DsseProviderFlowAuthorityObservation(
            input: ProviderFlowAuthorityInput(transport: .tcp, remoteHost: "", remotePort: 0, sourceBundleID: nil),
            endpointSourceGate: "fallback_empty_authority",
            portSourceGate: "fallback_missing"
        )
    }

    // Connect-by-name flows reach the transparent proxy as one flow per
    // resolved address: remoteFlowEndpoint / remoteEndpoint only carry the
    // resolved IP literal. The original FQDN travels separately in
    // NEAppProxyFlow.remoteHostname; without it host-level policy
    // (configured-rule match vs default-deny) is unobservable.
    static func authorityObservationPreferringFlowRemoteHostname(
        flowRemoteHostname: String?,
        endpointObservation: DsseProviderFlowAuthorityObservation
    ) -> DsseProviderFlowAuthorityObservation {
        guard let flowRemoteHostname,
              let normalizedRemoteHostname = normalizeHost(flowRemoteHostname),
              endpointObservation.input.remotePort > 0 else {
            return endpointObservation
        }
        return DsseProviderFlowAuthorityObservation(
            input: ProviderFlowAuthorityInput(
                transport: endpointObservation.input.transport,
                remoteHost: normalizedRemoteHostname,
                remotePort: endpointObservation.input.remotePort,
                sourceBundleID: endpointObservation.input.sourceBundleID
            ),
            endpointSourceGate: "flow_remote_named_authority_preferred",
            portSourceGate: endpointObservation.portSourceGate
        )
    }

    static func authorityInput(fromRemoteFlowEndpoint endpoint: Network.NWEndpoint) -> ProviderFlowAuthorityInput? {
        authorityObservation(fromRemoteFlowEndpoint: endpoint)?.input
    }

    private static func authorityObservation(fromRemoteFlowEndpoint endpoint: Network.NWEndpoint) -> DsseProviderFlowAuthorityObservation? {
        switch endpoint {
        case .hostPort(let host, let port):
            guard let portObservation = portObservation(from: port) else {
                return nil
            }
            return DsseProviderFlowAuthorityObservation(
                input: ProviderFlowAuthorityInput(
                    transport: .tcp,
                    remoteHost: String(describing: host),
                    remotePort: portObservation.port,
                    sourceBundleID: nil
                ),
                endpointSourceGate: "remote_flow_endpoint_hostport",
                portSourceGate: portObservation.sourceGate
            )
        case .url(let url):
            guard let host = url.host, let port = url.port else {
                return nil
            }
            return DsseProviderFlowAuthorityObservation(
                input: ProviderFlowAuthorityInput(
                    transport: .tcp,
                    remoteHost: host,
                    remotePort: port,
                    sourceBundleID: nil
                ),
                endpointSourceGate: "remote_flow_endpoint_url",
                portSourceGate: "url_port"
            )
        case .opaque(let endpoint):
            let endpointType = nw_endpoint_get_type(endpoint)
            guard endpointType == nw_endpoint_type_host ||
                endpointType == nw_endpoint_type_address ||
                endpointType == nw_endpoint_type_url else {
                return nil
            }
            let port = Int(nw_endpoint_get_port(endpoint))
            guard port > 0 else {
                return nil
            }
            return DsseProviderFlowAuthorityObservation(
                input: ProviderFlowAuthorityInput(
                    transport: .tcp,
                    remoteHost: String(cString: nw_endpoint_get_hostname(endpoint)),
                    remotePort: port,
                    sourceBundleID: nil
                ),
                endpointSourceGate: "remote_flow_endpoint_opaque",
                portSourceGate: "opaque_nw_endpoint_get_port"
            )
        default:
            return nil
        }
    }

    static func portValue(from port: Network.NWEndpoint.Port) -> Int? {
        portObservation(from: port)?.port
    }

    private static func portObservation(from port: Network.NWEndpoint.Port) -> DsseProviderFlowPortObservation? {
        if let describedPort = Int(String(describing: port)), describedPort > 0 {
            return DsseProviderFlowPortObservation(port: describedPort, sourceGate: "hostport_described_port")
        }
        let rawPort = Int(port.rawValue)
        return rawPort > 0 ? DsseProviderFlowPortObservation(port: rawPort, sourceGate: "hostport_rawvalue_fallback") : nil
    }

    private static func legacyRemoteEndpoint(from tcpFlow: NEAppProxyTCPFlow) -> Any? {
        let object = tcpFlow as NSObject
        guard object.responds(to: NSSelectorFromString("remoteEndpoint")) else {
            return nil
        }
        return object.value(forKey: "remoteEndpoint")
    }

    static func authorityInputFromLegacyRemoteEndpoint(_ endpoint: Any?) -> ProviderFlowAuthorityInput? {
        authorityObservationFromLegacyRemoteEndpoint(endpoint)?.input
    }

    private static func authorityObservationFromLegacyRemoteEndpoint(_ endpoint: Any?) -> DsseProviderFlowAuthorityObservation? {
        guard let endpointObject = endpoint as? NSObject,
              endpointObject.responds(to: NSSelectorFromString("hostname")),
              endpointObject.responds(to: NSSelectorFromString("port")),
              let host = endpointObject.value(forKey: "hostname") as? String,
              let portValue = endpointObject.value(forKey: "port") else {
            return nil
        }
        let port: Int?
        if let portString = portValue as? String {
            port = Int(portString)
        } else if let portNumber = portValue as? NSNumber {
            port = portNumber.intValue
        } else {
            port = nil
        }
        guard let port else {
            return nil
        }
        return DsseProviderFlowAuthorityObservation(
            input: ProviderFlowAuthorityInput(
                transport: .tcp,
                remoteHost: host,
                remotePort: port,
                sourceBundleID: nil
            ),
            endpointSourceGate: "legacy_remote_endpoint",
            portSourceGate: "legacy_remote_endpoint_port"
        )
    }

    static func sourceAppSigningIdentifier(from flow: NEAppProxyFlow) -> String? {
        DsseRuntimeCopyDownstreamPassthroughPolicy.normalizeSigningIdentifier(
            flow.metaData.sourceAppSigningIdentifier
        )
    }

    // sourceAppOSUser resolves the logged-in OS user that ORIGINATED this flow, from its audit token: the euid
    // sits at index 1 of the audit_token_t (8 × UInt32, host byte order), mapped through getpwuid to a username.
    // Per-flow — so a shared device still attributes each flow to the right person. nil on any failure
    // (uncertainty never fabricates identity). This is the authoritative "who" the Edge shows for AI usage.
    static func sourceAppOSUser(from flow: NEAppProxyFlow) -> String? {
        guard let auditToken = flow.metaData.sourceAppAuditToken, auditToken.count >= 32 else {
            return nil
        }
        let euid = auditToken.withUnsafeBytes { raw -> UInt32 in
            raw.loadUnaligned(fromByteOffset: 4, as: UInt32.self)
        }
        // Attribute INTERACTIVE users only. macOS reserves UIDs below 501 for the system and daemons (root=0,
        // _mdnsresponder=65, …) — a flow one of those originates has no logged-in "who", so report nil.
        if euid < 501 {
            return nil
        }
        guard let pw = getpwuid(euid), let name = pw.pointee.pw_name else {
            return nil
        }
        let user = String(cString: name)
        return user.isEmpty ? nil : user
    }

    // Back-compat thin wrapper: resolve only the Apple Developer Team Identifier of the flow's owning process.
    static func sourceAppTeamIdentifier(from flow: NEAppProxyFlow) -> String? {
        sourceAppSignerIdentity(from: flow).teamIdentifier
    }

    // Resolve the flow's owning process's crypto signer identities — Apple Developer Team Identifier, leaf-cert
    // Subject Organization (O), and leaf-cert SHA-256 — from its audit token in ONE Code Signing Services
    // lookup, for typed cross-platform self-exclusion matching (team-id: / subject: / thumbprint:). Fail-safe:
    // every field is independently nil on ANY failure (no audit token, code object not derivable, no signing
    // info, missing cert/value) so the app stays steered — uncertainty never bypasses.
    static func sourceAppSignerIdentity(from flow: NEAppProxyFlow) -> DsseSourceAppSignerIdentity {
        let empty = DsseSourceAppSignerIdentity(teamIdentifier: nil, subjectOrganization: nil, subjectCommonName: nil, leafSha256: nil)
        guard let auditToken = flow.metaData.sourceAppAuditToken, !auditToken.isEmpty else {
            return empty
        }
        // The audit_token_t bytes carried by the flow, handed verbatim to Code Signing Services as the guest
        // attribute that identifies the process whose signature we inspect.
        let attributes: [CFString: Any] = [kSecGuestAttributeAudit: auditToken as CFData]
        var code: SecCode?
        guard SecCodeCopyGuestWithAttributes(nil, attributes as CFDictionary, SecCSFlags(), &code) == errSecSuccess,
              let code else {
            return empty
        }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, SecCSFlags(), &staticCode) == errSecSuccess,
              let staticCode else {
            return empty
        }
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(
                  staticCode,
                  SecCSFlags(rawValue: kSecCSSigningInformation),
                  &info
              ) == errSecSuccess,
              let signingInfo = info as? [CFString: Any] else {
            return empty
        }
        // Team Identifier (as before): trimmed, nil when empty.
        let teamIdentifier: String? = (signingInfo[kSecCodeInfoTeamIdentifier] as? String)
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .flatMap { $0.isEmpty ? nil : $0 }
        // Leaf certificate: element 0 of the certificate chain. Used for both subject organization + SHA-256.
        var subjectOrganization: String?
        var subjectCommonName: String?
        var leafSha256: String?
        if let certificates = signingInfo[kSecCodeInfoCertificates] as? [SecCertificate],
           let leaf = certificates.first {
            subjectOrganization = leafSubjectOrganization(from: leaf)
            var cn: CFString?
            if SecCertificateCopyCommonName(leaf, &cn) == errSecSuccess, let cn = cn as String? {
                let trimmed = cn.trimmingCharacters(in: .whitespacesAndNewlines)
                subjectCommonName = trimmed.isEmpty ? nil : trimmed
            }
            leafSha256 = leafCertificateSha256(from: leaf)
        }
        return DsseSourceAppSignerIdentity(
            teamIdentifier: teamIdentifier,
            subjectOrganization: subjectOrganization,
            subjectCommonName: subjectCommonName,
            leafSha256: leafSha256
        )
    }

    // Extract the Subject Organization (O) from a leaf certificate. SecCertificateCopyValues returns a dict
    // keyed by OID; the OrganizationName entry's value may be a single String or an array of entries — handle
    // both and take the first non-empty string. Fail-safe: nil on any failure.
    private static func leafSubjectOrganization(from certificate: SecCertificate) -> String? {
        let keys = [kSecOIDOrganizationName] as CFArray
        guard let values = SecCertificateCopyValues(certificate, keys, nil) as? [CFString: Any],
              let entry = values[kSecOIDOrganizationName] as? [CFString: Any],
              let value = entry[kSecPropertyKeyValue] else {
            return nil
        }
        let candidate: String?
        if let stringValue = value as? String {
            candidate = stringValue
        } else if let arrayValue = value as? [Any] {
            candidate = arrayValue.compactMap { element -> String? in
                if let stringElement = element as? String {
                    return stringElement
                }
                if let dictElement = element as? [CFString: Any],
                   let nested = dictElement[kSecPropertyKeyValue] as? String {
                    return nested
                }
                return nil
            }.first { !$0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }
        } else {
            candidate = nil
        }
        guard let resolved = candidate?.trimmingCharacters(in: .whitespacesAndNewlines), !resolved.isEmpty else {
            return nil
        }
        return resolved
    }

    // Lowercase-hex SHA-256 of a certificate's DER bytes (matches the Windows thumbprint: contract). Fail-safe:
    // nil when the DER bytes are unavailable.
    private static func leafCertificateSha256(from certificate: SecCertificate) -> String? {
        let der = SecCertificateCopyData(certificate) as Data
        guard !der.isEmpty else {
            return nil
        }
        return SHA256.hash(data: der).map { String(format: "%02x", $0) }.joined()
    }
}
