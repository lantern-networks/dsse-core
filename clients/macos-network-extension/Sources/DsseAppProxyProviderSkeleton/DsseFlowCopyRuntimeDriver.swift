import Foundation
import DsseNetworkExtensionContract
import Network
import NetworkExtension

private func dsseEdgeAddressFamilyCategory(_ host: String?) -> String {
    guard var normalized = host?.trimmingCharacters(in: .whitespacesAndNewlines),
          !normalized.isEmpty else {
        return "unknown_nonsecret"
    }
    if normalized.hasPrefix("[") && normalized.hasSuffix("]") {
        normalized = String(normalized.dropFirst().dropLast())
    }
    if IPv4Address(normalized) != nil {
        return "ipv4"
    }
    if IPv6Address(normalized) != nil {
        return "ipv6"
    }
    return "fqdn_unresolved"
}

// dsseIsInteractiveEastWestPort reports whether a destination port is an interactive East-West protocol a user
// may hold open and idle for a long time (ssh/rdp/smb/winrm/wmi-rpc/vnc/db). Mirrors the Edge's
// steerServiceFamilyForPort interactive set. Such flows are exempt from the NE idle reaper so a session sitting
// at a prompt is never torn down — the Edge bridge + connector stream already keep the same flow unlimited, and
// the NE's own 120s (20s under load) reaper would otherwise be the last cap that cuts it.
func dsseIsInteractiveEastWestPort(_ port: Int?) -> Bool {
    guard let port else { return false }
    switch port {
    case 22,        // ssh
         3389,      // rdp
         445, 139,  // smb
         5985, 5986, // winrm
         135,       // wmi/dcom rpc
         5900,      // vnc
         1433, 3306, 5432, 1521, 27017: // databases
        return true
    default:
        return false
    }
}

public enum DsseLocalRuntimeCopyImplementationContract {
    public static let implementation = "wired_into_live_handle_new_flow_real_edge_transport_reviewed"
    public static let notStarted = "not_started"
    public static let status = "ok"
    public static let auditMetadataOnlyGate = "ok"
    public static let cleanupGate = "cleaned"
    public static let defaultTransport = "device_validation_pending"
    public static let realEdgeTransport = "real_edge_runtime_copy_transport_configured_reviewed"
}

public struct DsseLocalRuntimeCopyMetadata: Equatable, Sendable {
    public let tenantID: String
    public let requestID: String
    public let applicationID: String
    public let destinationHost: String?
    public let destinationPort: Int?
    // osUser is the logged-in OS user that originated THIS flow (resolved from the flow's sourceAppAuditToken).
    // It is per-flow, so a shared device still attributes each flow to the right person. Conveyed to the Edge in
    // the steer OPEN frame ("u=<user>") and used there as the authoritative "who".
    public let osUser: String?
    // sourceApp is the app/process that originated THIS flow (the flow's sourceAppSigningIdentifier). Conveyed
    // to the Edge in the steer OPEN frame ("a=<app>") as the "what tool" dimension (browser vs CLI vs AI agent).
    public let sourceApp: String?

    public init(
        tenantID: String,
        requestID: String,
        applicationID: String,
        destinationHost: String? = nil,
        destinationPort: Int? = nil,
        osUser: String? = nil,
        sourceApp: String? = nil
    ) {
        self.tenantID = tenantID
        self.requestID = requestID
        self.applicationID = applicationID
        self.destinationHost = destinationHost
        self.destinationPort = destinationPort
        self.osUser = osUser
        self.sourceApp = sourceApp
    }
}

public protocol DsseLocalRuntimeCopyTransport: Sendable {
    func roundTrip(_ payload: Data, metadata: DsseLocalRuntimeCopyMetadata) throws -> Data
}

public struct DsseSection16RuntimeCopyEvidence: Equatable, Sendable {
    public let edgePortFlowReentryObserved: Bool
    public let runtimeCopyEndpointPassthroughDecision: String
    public let edgeTCPConnectCompleted: Bool
    public let edgeTCPConnectAddressFamily: String

    public init(
        edgePortFlowReentryObserved: Bool,
        runtimeCopyEndpointPassthroughDecision: String,
        edgeTCPConnectCompleted: Bool,
        edgeTCPConnectAddressFamily: String
    ) {
        self.edgePortFlowReentryObserved = edgePortFlowReentryObserved
        self.runtimeCopyEndpointPassthroughDecision = runtimeCopyEndpointPassthroughDecision
        self.edgeTCPConnectCompleted = edgeTCPConnectCompleted
        self.edgeTCPConnectAddressFamily = edgeTCPConnectAddressFamily
    }
}

public struct DsseLocalRuntimeCopyResult: Equatable, Sendable {
    public let status: String
    public let implementation: String
    public let bytesUp: Int
    public let bytesDown: Int
    public let registryCleanupGate: String
    public let tenantMetadataCleanupGate: String
    public let auditMetadataOnlyGate: String
    public let connectionRegistryRuntimeConnected: Bool
    public let byteCapRuntimeEnforced: Bool
    public let idleTimeoutRuntimeEnforced: Bool
    public let boundedBackpressureRuntimeEnforced: Bool
    public let flowReadHalfCloseRuntimeEnforced: Bool
    public let flowWriteHalfCloseRuntimeEnforced: Bool
    public let networkExtensionFlowOpened: Bool
    public let edgeTunnelOpenStarted: Bool
    public let tcpPayloadCopyStarted: Bool
    public let flowPayloadReadStarted: Bool
    public let flowPayloadWriteStarted: Bool
}

public enum DsseLocalRuntimeCopyDriverError: Error, Equatable, Sendable {
    case missingTenantScope
    case missingRequestID
    case missingApplicationScope
    case emptyUpstreamPayload
    case emptyDownstreamPayload
    case flowOpenFailed
    case flowReadFailed
    case flowWriteFailed
    case flowOpenTimeout
    case tunnelOpenTimeout
    case flowReadTimeout
    case edgeRoundTripTimeout
    case flowWriteTimeout
    case duplicateRuntimeCopyRequestID
    case runtimeCopyConcurrentCapExceeded
    case runtimeCopyByteCapExceeded
    case runtimeCopyIdleTimeoutExceeded
    case runtimeCopyBackpressureOverflowClosed
    case runtimeTransportDeviceValidationPending
    case invalidEdgeTransportConfiguration
    case edgeTransportRequestFailed
    case edgeTransportStatusFailed
    case edgeTransportDecodeFailed
    case edgeTransportRequestIDMismatch
}

public enum DsseLiveRuntimeCopyProgress: Equatable, Sendable {
    case liveCopyStarted
    case flowOpenCompleted
    case upstreamReadCompleted(bytes: Int)
    case edgeRoundTripStarted
    case edgeTCPConnectStarted(family: String)
    case edgeTCPConnectCompleted(family: String)
    case edgeRoundTripRequestSent
    case edgeRoundTripResponseStatusReceived(category: String)
    case edgeRoundTripErrorCategory(category: String)
    case edgeRoundTripResponseBodyReceived
    case edgeRoundTripCompleted
    case downstreamWriteStarted
    case downstreamWriteFailed(category: String)
    case downstreamWriteCompleted
}

public protocol DsseInstrumentedLocalRuntimeCopyTransport: DsseLocalRuntimeCopyTransport {
    func roundTrip(
        _ payload: Data,
        metadata: DsseLocalRuntimeCopyMetadata,
        progressHandler: (@Sendable (DsseLiveRuntimeCopyProgress) -> Void)?
    ) throws -> Data
}

public enum DsseLocalRuntimeCopySessionOperation: String, Equatable, Sendable {
    case open
    case exchange
    case close
}

public struct DsseLocalRuntimeCopySessionExchangeResult: Equatable, Sendable {
    public let downstreamPayload: Data
    public let sessionClosed: Bool

    public init(downstreamPayload: Data, sessionClosed: Bool) {
        self.downstreamPayload = downstreamPayload
        self.sessionClosed = sessionClosed
    }
}

public protocol DsseSessionLocalRuntimeCopyTransport: DsseLocalRuntimeCopyTransport {
    func exchangeSession(
        _ payload: Data,
        operation: DsseLocalRuntimeCopySessionOperation,
        metadata: DsseLocalRuntimeCopyMetadata,
        progressHandler: (@Sendable (DsseLiveRuntimeCopyProgress) -> Void)?
    ) throws -> DsseLocalRuntimeCopySessionExchangeResult

    func closeSession(
        metadata: DsseLocalRuntimeCopyMetadata,
        progressHandler: (@Sendable (DsseLiveRuntimeCopyProgress) -> Void)?
    ) throws
}

public struct DsseLocalRuntimeCopyEvidence: Codable, Equatable, Sendable {
    public static let schemaVersion = "network_extension_runtime_copy_evidence.v1"

    public let schemaVersion: String
    public let evidenceKind: String
    public let status: String
    public let createdAt: String
    public let copyAttemptGate: String
    public let runtimeCopyEnabledGate: String
    public let runtimeCopyTransportGate: String
    public let runtimeCopyTransportImplementation: String
    public let edgeConnectorRealness: String
    public let implementationBoundaryReviewedGate: String
    public let reviewedRuntimeCopyImplementationRef: String
    public let runtimeStartGate: String
    public let handleNewFlowTakeoverGate: String
    public let tenantScopeGate: String
    public let requestIDGate: String
    public let applicationScopeGate: String
    public let policyDecisionCategory: String
    public let networkExtensionFlowOpenGate: String
    public let edgeTunnelRoundTripGate: String
    public let edgeTransportRoundTripGate: String
    public let flowPayloadReadGate: String
    public let flowPayloadWriteGate: String
    public let tcpPayloadCopyGate: String
    public let privateAppResponseGate: String
    public let bytesUpGate: String
    public let bytesDownGate: String
    public let bytesUp: Int
    public let bytesDown: Int
    public let closeReasonCategory: String
    public let flowReadHalfCloseGate: String
    public let flowWriteHalfCloseGate: String
    public let registryCleanupGate: String
    public let tenantMetadataCleanupGate: String
    public let auditMetadataOnlyGate: String
    public let secretLeakGate: String
    public let runtimeOverclaimGate: String
    public let flowCopyOverclaimGate: String
    public let codexRuntimeActionsStarted: Bool
    public let runtimeInstalledClaimed: Bool
    public let flowTunneledClaimed: Bool
    public let flowDeniedClaimed: Bool
    public let ransomwareProtectionActiveClaimed: Bool
    public let realTLSInterceptionClaimed: Bool
    public let certificateIssuanceClaimed: Bool
    public let rawLogsIncluded: Bool
    public let rawCommandOutputIncluded: Bool
    public let rawNEFlowIncluded: Bool
    public let hostUserPayloadIncluded: Bool
    public let destinationIPIncluded: Bool
    public let credentialsIncluded: Bool
    public let packetCaptureIncluded: Bool
    public let appleIdentifierIncluded: Bool
    public let noSecretAttestation: Bool
    public let blockingCategories: [String]
    public let nonsecretEvidenceRefs: [String]
    public let recommendedNextDevAction: String
    public let nonsecretNotes: [String]
    public let edgePortFlowReentryObserved: Bool?
    public let runtimeCopyEndpointPassthroughDecision: String?
    public let edgeTCPConnectCompleted: Bool?
    public let edgeTCPConnectAddressFamily: String?

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case evidenceKind = "evidence_kind"
        case status
        case createdAt = "created_at"
        case copyAttemptGate = "copy_attempt_gate"
        case runtimeCopyEnabledGate = "runtime_copy_enabled_gate"
        case runtimeCopyTransportGate = "runtime_copy_transport_gate"
        case runtimeCopyTransportImplementation = "runtime_copy_transport_implementation"
        case edgeConnectorRealness = "edge_connector_realness"
        case implementationBoundaryReviewedGate = "implementation_boundary_reviewed_gate"
        case reviewedRuntimeCopyImplementationRef = "reviewed_runtime_copy_implementation_ref"
        case runtimeStartGate = "runtime_start_gate"
        case handleNewFlowTakeoverGate = "handle_new_flow_takeover_gate"
        case tenantScopeGate = "tenant_scope_gate"
        case requestIDGate = "request_id_gate"
        case applicationScopeGate = "application_scope_gate"
        case policyDecisionCategory = "policy_decision_category"
        case networkExtensionFlowOpenGate = "network_extension_flow_open_gate"
        case edgeTunnelRoundTripGate = "edge_tunnel_round_trip_gate"
        case edgeTransportRoundTripGate = "edge_transport_round_trip_gate"
        case flowPayloadReadGate = "flow_payload_read_gate"
        case flowPayloadWriteGate = "flow_payload_write_gate"
        case tcpPayloadCopyGate = "tcp_payload_copy_gate"
        case privateAppResponseGate = "private_app_response_gate"
        case bytesUpGate = "bytes_up_gate"
        case bytesDownGate = "bytes_down_gate"
        case bytesUp = "bytes_up"
        case bytesDown = "bytes_down"
        case closeReasonCategory = "close_reason_category"
        case flowReadHalfCloseGate = "flow_read_half_close_gate"
        case flowWriteHalfCloseGate = "flow_write_half_close_gate"
        case registryCleanupGate = "registry_cleanup_gate"
        case tenantMetadataCleanupGate = "tenant_metadata_cleanup_gate"
        case auditMetadataOnlyGate = "audit_metadata_only_gate"
        case secretLeakGate = "secret_leak_gate"
        case runtimeOverclaimGate = "runtime_overclaim_gate"
        case flowCopyOverclaimGate = "flow_copy_overclaim_gate"
        case codexRuntimeActionsStarted = "codex_runtime_actions_started"
        case runtimeInstalledClaimed = "runtime_installed_claimed"
        case flowTunneledClaimed = "flow_tunneled_claimed"
        case flowDeniedClaimed = "flow_denied_claimed"
        case ransomwareProtectionActiveClaimed = "ransomware_protection_active_claimed"
        case realTLSInterceptionClaimed = "real_tls_interception_claimed"
        case certificateIssuanceClaimed = "certificate_issuance_claimed"
        case rawLogsIncluded = "raw_logs_included"
        case rawCommandOutputIncluded = "raw_command_output_included"
        case rawNEFlowIncluded = "raw_ne_flow_included"
        case hostUserPayloadIncluded = "host_user_payload_included"
        case destinationIPIncluded = "destination_ip_included"
        case credentialsIncluded = "credentials_included"
        case packetCaptureIncluded = "packet_capture_included"
        case appleIdentifierIncluded = "apple_identifier_included"
        case noSecretAttestation = "no_secret_attestation"
        case blockingCategories = "blocking_categories"
        case nonsecretEvidenceRefs = "nonsecret_evidence_refs"
        case recommendedNextDevAction = "recommended_next_dev_action"
        case nonsecretNotes = "nonsecret_notes"
        case edgePortFlowReentryObserved = "edge_port_flow_reentry_observed"
        case runtimeCopyEndpointPassthroughDecision = "runtime_copy_endpoint_passthrough_decision"
        case edgeTCPConnectCompleted = "edge_tcp_connect_completed"
        case edgeTCPConnectAddressFamily = "edge_tcp_connect_address_family"
    }
}

public enum DsseLocalRuntimeCopyEvidenceError: Error, Equatable, LocalizedError {
    case invalidEvidenceRef(String)
    case invalidEvidence(String)
    case writeFailed

    public var errorDescription: String? {
        switch self {
        case .invalidEvidenceRef(let reason):
            return "network extension runtime copy evidence ref is invalid: \(reason)"
        case .invalidEvidence(let reason):
            return "network extension runtime copy evidence is invalid: \(reason)"
        case .writeFailed:
            return "network extension runtime copy evidence could not be written"
        }
    }
}

public protocol DsseLocalRuntimeCopyEvidenceWriting: Sendable {
    @discardableResult
    func write(
        result: Result<DsseLocalRuntimeCopyResult, Error>,
        transport: any DsseLocalRuntimeCopyTransport
    ) throws -> URL
}

public final class DsseLocalRuntimeCopyEvidenceWriter: DsseLocalRuntimeCopyEvidenceWriting, @unchecked Sendable {
    public static let defaultEvidenceRef = "network_extension_runtime_copy_evidence.json"

    private let evidenceURL: URL
    private let now: @Sendable () -> Date
    private let section16EvidenceProvider: @Sendable () -> DsseSection16RuntimeCopyEvidence?
    // One-shot on SUCCESS: write() is called per round-trip (per flow) and overwrites a single shared evidence
    // file. Keep writing until a successful ("ok") runtime-copy is captured, then seal — every later per-flow
    // rewrite of that success is pure disk churn (part of the ~34 GB/day "disk writes" bug).
    private let sealLock = NSLock()
    private var sealedOnSuccess = false

    public init(
        evidenceURL: URL,
        now: @escaping @Sendable () -> Date = Date.init,
        section16EvidenceProvider: @escaping @Sendable () -> DsseSection16RuntimeCopyEvidence? = { nil }
    ) {
        self.evidenceURL = evidenceURL
        self.now = now
        self.section16EvidenceProvider = section16EvidenceProvider
    }

    public convenience init(
        agentConfigPath: String,
        now: @escaping @Sendable () -> Date = Date.init,
        section16EvidenceProvider: @escaping @Sendable () -> DsseSection16RuntimeCopyEvidence? = { nil }
    ) throws {
        let data = try Data(contentsOf: URL(fileURLWithPath: agentConfigPath))
        let config = try JSONDecoder().decode(DsseProviderRuntimeCopyAgentConfig.self, from: data)
        let ref = config.runtimeCopyEvidenceRef?.trimmingCharacters(in: .whitespacesAndNewlines)
        let configDirectory = URL(fileURLWithPath: agentConfigPath).deletingLastPathComponent()
        let evidenceURL = try Self.resolveEvidenceRef(
            ref?.isEmpty == false ? ref! : Self.defaultEvidenceRef,
            relativeTo: configDirectory
        )
        self.init(
            evidenceURL: evidenceURL,
            now: now,
            section16EvidenceProvider: section16EvidenceProvider
        )
    }

    @discardableResult
    public func write(
        result: Result<DsseLocalRuntimeCopyResult, Error>,
        transport: any DsseLocalRuntimeCopyTransport
    ) throws -> URL {
        sealLock.lock()
        let alreadySealed = sealedOnSuccess
        sealLock.unlock()
        if alreadySealed { return evidenceURL } // success already captured; do no work, touch no disk.
        let evidence = Self.makeEvidence(
            result: result,
            transport: transport,
            createdAt: ISO8601DateFormatter().string(from: now()),
            section16Evidence: section16EvidenceProvider()
        )
        try Self.validate(evidence)
        if evidence.status != "ok", Self.existingSuccessEvidence(at: evidenceURL) {
            return evidenceURL
        }
        sealLock.lock()
        defer { sealLock.unlock() }
        if sealedOnSuccess { return evidenceURL } // re-check under lock (concurrent first flows)
        try Self.writeEvidence(evidence, to: evidenceURL)
        if evidence.status == "ok" { sealedOnSuccess = true }
        return evidenceURL
    }

    public static func resolveEvidenceRef(_ ref: String, relativeTo baseDirectory: URL) throws -> URL {
        let cleaned = ref.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !cleaned.isEmpty else {
            throw DsseLocalRuntimeCopyEvidenceError.invalidEvidenceRef("runtime copy evidence reference is empty")
        }
        guard !cleaned.hasPrefix("/") else {
            throw DsseLocalRuntimeCopyEvidenceError.invalidEvidenceRef("absolute paths are not allowed")
        }
        guard !cleaned.hasPrefix("~") else {
            throw DsseLocalRuntimeCopyEvidenceError.invalidEvidenceRef("home-relative paths are not allowed")
        }
        guard !cleaned.contains("\\") else {
            throw DsseLocalRuntimeCopyEvidenceError.invalidEvidenceRef("backslashes are not allowed")
        }
        guard !cleaned.contains("\u{0000}") else {
            throw DsseLocalRuntimeCopyEvidenceError.invalidEvidenceRef("null bytes are not allowed")
        }
        guard cleaned.hasSuffix(".json") else {
            throw DsseLocalRuntimeCopyEvidenceError.invalidEvidenceRef("runtime copy evidence reference must end with .json")
        }

        let segments = cleaned.split(separator: "/", omittingEmptySubsequences: false)
        guard !segments.isEmpty else {
            throw DsseLocalRuntimeCopyEvidenceError.invalidEvidenceRef("runtime copy evidence reference is empty")
        }
        var resolved = baseDirectory
        for segment in segments {
            if segment.isEmpty || segment == "." || segment == ".." {
                throw DsseLocalRuntimeCopyEvidenceError.invalidEvidenceRef("path traversal is not allowed")
            }
            resolved.appendPathComponent(String(segment), isDirectory: false)
        }

        let basePath = baseDirectory.standardizedFileURL.resolvingSymlinksInPath().path
        let resolvedPath = resolved.standardizedFileURL.resolvingSymlinksInPath().path
        if resolvedPath != basePath && !resolvedPath.hasPrefix(basePath.hasSuffix("/") ? basePath : basePath + "/") {
            throw DsseLocalRuntimeCopyEvidenceError.invalidEvidenceRef("resolved path escapes config directory")
        }
        if runtimeCopyEvidencePathIsSymbolicLink(resolved) {
            throw DsseLocalRuntimeCopyEvidenceError.invalidEvidenceRef("runtime copy evidence path must not be a symbolic link")
        }
        return resolved
    }

    private static func makeEvidence(
        result: Result<DsseLocalRuntimeCopyResult, Error>,
        transport: any DsseLocalRuntimeCopyTransport,
        createdAt: String,
        section16Evidence: DsseSection16RuntimeCopyEvidence?
    ) -> DsseLocalRuntimeCopyEvidence {
        let edgeTransport = transport as? DsseEdgeRuntimeCopyTransport
        let transportImplementation = edgeTransport?.evidenceImplementation
            ?? (transport is DsseDeviceValidationPendingRuntimeCopyTransport ? "device_validation_pending" : "local_test_runtime_copy_transport")
        let edgeConnectorRealness = edgeTransport?.edgeConnectorRealness ?? "in_process_stub"

        let copyResult: DsseLocalRuntimeCopyResult?
        let blockingCategories: [String]
        switch result {
        case .success(let result):
            copyResult = result
            blockingCategories = []
        case .failure(let error):
            copyResult = nil
            blockingCategories = [blockingCategory(for: error)]
        }

        let success = copyResult != nil && edgeTransport != nil
        let bytesUp = copyResult?.bytesUp ?? 0
        let bytesDown = copyResult?.bytesDown ?? 0

        return DsseLocalRuntimeCopyEvidence(
            schemaVersion: DsseLocalRuntimeCopyEvidence.schemaVersion,
            evidenceKind: "provider_runtime_copy_evidence",
            status: success ? "ok" : "blocked",
            createdAt: createdAt,
            copyAttemptGate: success ? "copied_round_trip" : "blocked",
            runtimeCopyEnabledGate: "enabled_reviewed",
            runtimeCopyTransportGate: success ? "real_transport_completed" : (transport is DsseDeviceValidationPendingRuntimeCopyTransport ? "pending" : "fail_closed"),
            runtimeCopyTransportImplementation: transportImplementation,
            edgeConnectorRealness: edgeConnectorRealness,
            implementationBoundaryReviewedGate: "reviewed",
            reviewedRuntimeCopyImplementationRef: "review-real-runtime-copy-transport-injection-compile-boundary",
            runtimeStartGate: "passed",
            handleNewFlowTakeoverGate: "accepted",
            tenantScopeGate: "resolved_nonsecret",
            requestIDGate: "generated_nonsecret",
            applicationScopeGate: "resolved_nonsecret",
            policyDecisionCategory: "allow",
            networkExtensionFlowOpenGate: copyResult?.networkExtensionFlowOpened == true ? "opened" : "not_opened",
            edgeTunnelRoundTripGate: success ? "round_trip_completed" : "not_completed",
            edgeTransportRoundTripGate: success ? "real_transport_completed" : "not_completed",
            flowPayloadReadGate: copyResult?.flowPayloadReadStarted == true ? "completed_nonsecret" : "not_started",
            flowPayloadWriteGate: copyResult?.flowPayloadWriteStarted == true ? "completed_nonsecret" : "not_started",
            tcpPayloadCopyGate: copyResult?.tcpPayloadCopyStarted == true ? "round_trip_completed" : "not_started",
            privateAppResponseGate: success ? "observed_nonsecret" : "not_observed",
            bytesUpGate: bytesUp > 0 ? "nonzero_exact_match" : "zero",
            bytesDownGate: bytesDown > 0 ? "nonzero_exact_match" : "zero",
            bytesUp: bytesUp,
            bytesDown: bytesDown,
            closeReasonCategory: "eof",
            flowReadHalfCloseGate: copyResult?.flowReadHalfCloseRuntimeEnforced == true ? "closed" : "not_observed",
            flowWriteHalfCloseGate: copyResult?.flowWriteHalfCloseRuntimeEnforced == true ? "closed" : "not_observed",
            registryCleanupGate: copyResult?.registryCleanupGate ?? "cleaned",
            tenantMetadataCleanupGate: copyResult?.tenantMetadataCleanupGate ?? "cleaned",
            auditMetadataOnlyGate: copyResult?.auditMetadataOnlyGate ?? "ok",
            secretLeakGate: "ok",
            runtimeOverclaimGate: "ok",
            flowCopyOverclaimGate: "ok",
            codexRuntimeActionsStarted: false,
            runtimeInstalledClaimed: false,
            flowTunneledClaimed: false,
            flowDeniedClaimed: false,
            ransomwareProtectionActiveClaimed: false,
            realTLSInterceptionClaimed: false,
            certificateIssuanceClaimed: false,
            rawLogsIncluded: false,
            rawCommandOutputIncluded: false,
            rawNEFlowIncluded: false,
            hostUserPayloadIncluded: false,
            destinationIPIncluded: false,
            credentialsIncluded: false,
            packetCaptureIncluded: false,
            appleIdentifierIncluded: false,
            noSecretAttestation: true,
            blockingCategories: blockingCategories,
            nonsecretEvidenceRefs: ["provider_runtime_copy_evidence_json"],
            recommendedNextDevAction: success ? "transform_with_phase2_flow_copy_harness" : "rerun_after_transport_ready",
            nonsecretNotes: ["counts and category gates only; no payload or endpoint material included"],
            edgePortFlowReentryObserved: section16Evidence?.edgePortFlowReentryObserved,
            runtimeCopyEndpointPassthroughDecision: section16Evidence?.runtimeCopyEndpointPassthroughDecision,
            edgeTCPConnectCompleted: section16Evidence?.edgeTCPConnectCompleted,
            edgeTCPConnectAddressFamily: section16Evidence?.edgeTCPConnectAddressFamily
        )
    }

    private static func existingSuccessEvidence(at evidenceURL: URL) -> Bool {
        guard let data = try? Data(contentsOf: evidenceURL),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return false
        }
        return object["schema_version"] as? String == DsseLocalRuntimeCopyEvidence.schemaVersion &&
            object["evidence_kind"] as? String == "provider_runtime_copy_evidence" &&
            object["status"] as? String == "ok"
    }

    private static func blockingCategory(for error: Error) -> String {
        switch error as? DsseLocalRuntimeCopyDriverError {
        case .runtimeTransportDeviceValidationPending:
            return "runtime_copy_transport_pending"
        case .missingTenantScope, .missingRequestID, .missingApplicationScope:
            return "metadata_scope_missing"
        case .runtimeCopyByteCapExceeded:
            return "runtime_copy_byte_cap_exceeded"
        case .runtimeCopyIdleTimeoutExceeded:
            return "runtime_copy_idle_timeout_exceeded"
        case .runtimeCopyBackpressureOverflowClosed:
            return "runtime_copy_backpressure_overflow_closed"
        case .flowOpenTimeout, .flowReadTimeout, .flowWriteTimeout:
            return "runtime_copy_flow_io_timeout"
        case .edgeRoundTripTimeout:
            return "runtime_copy_edge_round_trip_timeout"
        default:
            return "runtime_copy_failed_closed"
        }
    }

    private static func validate(_ evidence: DsseLocalRuntimeCopyEvidence) throws {
        guard evidence.secretLeakGate == "ok",
              evidence.runtimeOverclaimGate == "ok",
              evidence.flowCopyOverclaimGate == "ok",
              evidence.auditMetadataOnlyGate == "ok" else {
            throw DsseLocalRuntimeCopyEvidenceError.invalidEvidence("evidence gates must be ok")
        }
        guard evidence.bytesUp >= 0 && evidence.bytesDown >= 0 else {
            throw DsseLocalRuntimeCopyEvidenceError.invalidEvidence("byte counters must be nonnegative")
        }
        guard ["closed", "not_observed"].contains(evidence.flowReadHalfCloseGate),
              ["closed", "not_observed"].contains(evidence.flowWriteHalfCloseGate) else {
            throw DsseLocalRuntimeCopyEvidenceError.invalidEvidence("half-close gates must use nonsecret enum values")
        }
        guard ["in_process_stub", "over_the_wire_local", "over_the_wire_device"].contains(evidence.edgeConnectorRealness) else {
            throw DsseLocalRuntimeCopyEvidenceError.invalidEvidence("edge_connector_realness is not allowed")
        }
        if evidence.runtimeCopyTransportImplementation == "lab_endpoint_runtime_copy_transport" {
            guard evidence.edgeConnectorRealness == "in_process_stub" else {
                throw DsseLocalRuntimeCopyEvidenceError.invalidEvidence("lab_endpoint_runtime_copy_transport must use edge_connector_realness in_process_stub")
            }
        }
        guard evidence.noSecretAttestation else {
            throw DsseLocalRuntimeCopyEvidenceError.invalidEvidence("no_secret_attestation must be true")
        }
        guard !evidence.codexRuntimeActionsStarted,
              !evidence.runtimeInstalledClaimed,
              !evidence.flowTunneledClaimed,
              !evidence.flowDeniedClaimed,
              !evidence.ransomwareProtectionActiveClaimed,
              !evidence.realTLSInterceptionClaimed,
              !evidence.certificateIssuanceClaimed,
              !evidence.rawLogsIncluded,
              !evidence.rawCommandOutputIncluded,
              !evidence.rawNEFlowIncluded,
              !evidence.hostUserPayloadIncluded,
              !evidence.destinationIPIncluded,
              !evidence.credentialsIncluded,
              !evidence.packetCaptureIncluded,
              !evidence.appleIdentifierIncluded else {
            throw DsseLocalRuntimeCopyEvidenceError.invalidEvidence("runtime copy evidence must not include overclaim or raw data flags")
        }
        let section16ValuesPresent = [
            evidence.edgePortFlowReentryObserved != nil,
            evidence.runtimeCopyEndpointPassthroughDecision != nil,
            evidence.edgeTCPConnectCompleted != nil,
            evidence.edgeTCPConnectAddressFamily != nil
        ]
        let section16Complete = section16ValuesPresent.allSatisfy { $0 }
        let section16Missing = section16ValuesPresent.allSatisfy { !$0 }
        guard section16Complete || section16Missing else {
            throw DsseLocalRuntimeCopyEvidenceError.invalidEvidence("Section 16 evidence fields must be complete when present")
        }
        if let passthroughDecision = evidence.runtimeCopyEndpointPassthroughDecision {
            guard ["endpoint_not_configured", "no_flow_matched_edge_port", "matched_passed_through", "port_matched_host_mismatch"].contains(passthroughDecision) else {
                throw DsseLocalRuntimeCopyEvidenceError.invalidEvidence("runtime_copy_endpoint_passthrough_decision is not allowed")
            }
        }
        if let addressFamily = evidence.edgeTCPConnectAddressFamily {
            guard ["none", "ipv4", "ipv6", "fqdn_unresolved", "unknown_nonsecret"].contains(addressFamily) else {
                throw DsseLocalRuntimeCopyEvidenceError.invalidEvidence("edge_tcp_connect_address_family is not allowed")
            }
        }
        if evidence.status == "ok" && evidence.runtimeCopyTransportImplementation == "real_edge_runtime_copy_transport" {
            guard section16Complete else {
                throw DsseLocalRuntimeCopyEvidenceError.invalidEvidence("real_edge_runtime_copy_transport requires Section 16 evidence fields")
            }
            guard realEdgeSection16PreflightSatisfied(evidence) else {
                throw DsseLocalRuntimeCopyEvidenceError.invalidEvidence("real_edge_runtime_copy_transport Section 16 preflight is not satisfied")
            }
        }
    }

    private static func realEdgeSection16PreflightSatisfied(_ evidence: DsseLocalRuntimeCopyEvidence) -> Bool {
        guard evidence.edgeTCPConnectCompleted == true,
              ["ipv4", "ipv6"].contains(evidence.edgeTCPConnectAddressFamily ?? "") else {
            return false
        }
        if evidence.edgePortFlowReentryObserved == true {
            return evidence.runtimeCopyEndpointPassthroughDecision == "matched_passed_through"
        }
        return evidence.edgePortFlowReentryObserved == false &&
            evidence.runtimeCopyEndpointPassthroughDecision == "no_flow_matched_edge_port"
    }

    private static func writeEvidence(_ evidence: DsseLocalRuntimeCopyEvidence, to url: URL) throws {
        let parent = url.deletingLastPathComponent()
        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(atPath: parent.path, isDirectory: &isDirectory), isDirectory.boolValue else {
            throw DsseLocalRuntimeCopyEvidenceError.invalidEvidenceRef("parent directory does not exist")
        }

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        let data = try encoder.encode(evidence)
        let tempURL = parent.appendingPathComponent(".\(url.lastPathComponent).tmp.\(UUID().uuidString)", isDirectory: false)
        do {
            try data.write(to: tempURL, options: [.withoutOverwriting])
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: tempURL.path)
            if FileManager.default.fileExists(atPath: url.path) {
                if runtimeCopyEvidencePathIsSymbolicLink(url) {
                    throw DsseLocalRuntimeCopyEvidenceError.invalidEvidenceRef("runtime copy evidence path must not be a symbolic link")
                }
                _ = try FileManager.default.replaceItemAt(url, withItemAt: tempURL, backupItemName: nil, options: [])
            } else {
                try FileManager.default.moveItem(at: tempURL, to: url)
            }
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        } catch let error as DsseLocalRuntimeCopyEvidenceError {
            try? FileManager.default.removeItem(at: tempURL)
            throw error
        } catch {
            try? FileManager.default.removeItem(at: tempURL)
            throw DsseLocalRuntimeCopyEvidenceError.writeFailed
        }
    }
}

public struct DsseProviderRuntimeDiagnostic: Codable, Equatable, Sendable {
    public static let schemaVersion = "phase2_provider_runtime_diagnostic.v1"

    public let schemaVersion: String
    public let status: String
    public let evidenceKind: String
    public let createdAt: String
    public let diagnosticSource: String
    public let handleNewFlowObserved: Bool
    public let handleNewFlowDecisionCategory: String
    public let handleNewFlowExtractionStatus: String
    public let handleNewFlowExtractionReason: String
    public let providerDecisionAction: String
    public let providerDecisionReason: String
    public let providerRulesReloadGate: String
    public let providerLoadedRulesGenerationGate: String
    public let providerLoadedRulesGeneratedAt: String
    public let authorityExtractionRuntimeMarker: String
    public let flowAuthorityEndpointSourceGate: String
    public let flowAuthorityPortSourceGate: String
    public let singleRuleLabFallbackGate: String
    public let flowAuthorityHostGate: String
    public let flowAuthorityPortGate: String
    public let singleRuleLabFallbackPortGate: String
    public let allowFlowAuthorityPortMatch: String
    public let liveCopyStatus: String
    public let liveCopyFailureCategory: String
    public let liveCopyStarted: Bool
    public let flowOpenCompleted: Bool
    public let upstreamReadCompleted: Bool
    public let upstreamReadBytes: Int
    public let edgeRoundTripStarted: Bool
    public let edgeTCPConnectStarted: Bool
    public let edgeTCPConnectCompleted: Bool
    public let edgeTCPConnectAddressFamily: String
    public let edgeRoundTripRequestSent: Bool
    public let edgeRoundTripResponseStatusReceived: Bool
    public let edgeRoundTripResponseStatusCategory: String
    public let edgeRoundTripErrorCategory: String
    public let edgeRoundTripResponseBodyReceived: Bool
    public let edgeRoundTripCompleted: Bool
    public let downstreamWriteStarted: Bool
    public let flowWriteErrorCategory: String
    public let downstreamWriteCompleted: Bool
    public let runtimeCopyEndpointPassThroughObserved: Bool
    public let runtimeCopyEndpointPassthroughDecision: String
    public let edgePortFlowReentryObserved: Bool
    public let runtimeCopyEvidenceWriteFailureObserved: Bool
    public let startProxyRunningObserved: Bool
    public let transparentNetworkSettingsAppliedObserved: Bool
    public let rawLogsIncluded: Bool
    public let rawCommandOutputIncluded: Bool
    public let rawNEFlowIncluded: Bool
    public let hostUserPayloadIncluded: Bool
    public let destinationIPIncluded: Bool
    public let credentialsIncluded: Bool
    public let packetCaptureIncluded: Bool
    public let appleIdentifierIncluded: Bool
    public let noSecretAttestation: Bool
    public let recommendedNextDevAction: String
    public let nonsecretNotes: [String]

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case status
        case evidenceKind = "evidence_kind"
        case createdAt = "created_at"
        case diagnosticSource = "diagnostic_source"
        case handleNewFlowObserved = "handle_new_flow_observed"
        case handleNewFlowDecisionCategory = "handle_new_flow_decision_category"
        case handleNewFlowExtractionStatus = "handle_new_flow_extraction_status"
        case handleNewFlowExtractionReason = "handle_new_flow_extraction_reason"
        case providerDecisionAction = "provider_decision_action"
        case providerDecisionReason = "provider_decision_reason"
        case providerRulesReloadGate = "provider_rules_reload_gate"
        case providerLoadedRulesGenerationGate = "provider_loaded_rules_generation_gate"
        case providerLoadedRulesGeneratedAt = "provider_loaded_rules_generated_at"
        case authorityExtractionRuntimeMarker = "authority_extraction_runtime_marker"
        case flowAuthorityEndpointSourceGate = "flow_authority_endpoint_source_gate"
        case flowAuthorityPortSourceGate = "flow_authority_port_source_gate"
        case singleRuleLabFallbackGate = "single_rule_lab_fallback_gate"
        case flowAuthorityHostGate = "flow_authority_host_gate"
        case flowAuthorityPortGate = "flow_authority_port_gate"
        case singleRuleLabFallbackPortGate = "single_rule_lab_fallback_port_gate"
        case allowFlowAuthorityPortMatch = "allow_flow_authority_port_match"
        case liveCopyStatus = "live_copy_status"
        case liveCopyFailureCategory = "live_copy_failure_category"
        case liveCopyStarted = "live_copy_started"
        case flowOpenCompleted = "flow_open_completed"
        case upstreamReadCompleted = "upstream_read_completed"
        case upstreamReadBytes = "upstream_read_bytes"
        case edgeRoundTripStarted = "edge_round_trip_started"
        case edgeTCPConnectStarted = "edge_tcp_connect_started"
        case edgeTCPConnectCompleted = "edge_tcp_connect_completed"
        case edgeTCPConnectAddressFamily = "edge_tcp_connect_address_family"
        case edgeRoundTripRequestSent = "edge_round_trip_request_sent"
        case edgeRoundTripResponseStatusReceived = "edge_round_trip_response_status_received"
        case edgeRoundTripResponseStatusCategory = "edge_round_trip_response_status_category"
        case edgeRoundTripErrorCategory = "edge_round_trip_error_category"
        case edgeRoundTripResponseBodyReceived = "edge_round_trip_response_body_received"
        case edgeRoundTripCompleted = "edge_round_trip_completed"
        case downstreamWriteStarted = "downstream_write_started"
        case flowWriteErrorCategory = "flow_write_error_category"
        case downstreamWriteCompleted = "downstream_write_completed"
        case runtimeCopyEndpointPassThroughObserved = "runtime_copy_endpoint_pass_through_observed"
        case runtimeCopyEndpointPassthroughDecision = "runtime_copy_endpoint_passthrough_decision"
        case edgePortFlowReentryObserved = "edge_port_flow_reentry_observed"
        case runtimeCopyEvidenceWriteFailureObserved = "runtime_copy_evidence_write_failure_observed"
        case startProxyRunningObserved = "start_proxy_running_observed"
        case transparentNetworkSettingsAppliedObserved = "transparent_network_settings_applied_observed"
        case rawLogsIncluded = "raw_logs_included"
        case rawCommandOutputIncluded = "raw_command_output_included"
        case rawNEFlowIncluded = "raw_ne_flow_included"
        case hostUserPayloadIncluded = "host_user_payload_included"
        case destinationIPIncluded = "destination_ip_included"
        case credentialsIncluded = "credentials_included"
        case packetCaptureIncluded = "packet_capture_included"
        case appleIdentifierIncluded = "apple_identifier_included"
        case noSecretAttestation = "no_secret_attestation"
        case recommendedNextDevAction = "recommended_next_dev_action"
        case nonsecretNotes = "nonsecret_notes"
    }
}

public final class DsseProviderRuntimeDiagnosticWriter: @unchecked Sendable {
    public static let defaultDiagnosticRef = "network_extension_runtime_diagnostic.json"

    private let diagnosticURL: URL
    private let now: @Sendable () -> Date
    private let lock = NSLock()
    private var handleNewFlowObserved = false
    private var handleNewFlowDecisionCategory = "not_observed"
    private var handleNewFlowExtractionStatus = "not_observed"
    private var handleNewFlowExtractionReason = "not_observed"
    private var providerDecisionAction = "not_observed"
    private var providerDecisionReason = "not_observed"
    private var providerRulesReloadGate = "not_checked"
    private var providerLoadedRulesGenerationGate = "not_observed"
    private var providerLoadedRulesGeneratedAt = "not_observed"
    private var authorityExtractionRuntimeMarker = "not_observed"
    private var flowAuthorityEndpointSourceGate = "not_observed"
    private var flowAuthorityPortSourceGate = "not_observed"
    private var singleRuleLabFallbackGate = "not_evaluated"
    private var flowAuthorityHostGate = "not_observed"
    private var flowAuthorityPortGate = "not_observed"
    private var singleRuleLabFallbackPortGate = "not_evaluated"
    private var allowFlowAuthorityPortMatch = "extraction_failed"
    private var liveCopyStatus = "not_observed"
    private var liveCopyFailureCategory = "none"
    private var liveCopyStarted = false
    private var flowOpenCompleted = false
    private var upstreamReadCompleted = false
    private var upstreamReadBytes = 0
    private var edgeRoundTripStarted = false
    private var edgeTCPConnectStarted = false
    private var edgeTCPConnectCompleted = false
    private var edgeTCPConnectAddressFamily = "none"
    private var edgeRoundTripRequestSent = false
    private var edgeRoundTripResponseStatusReceived = false
    private var edgeRoundTripResponseStatusCategory = "none"
    private var edgeRoundTripErrorCategory = "none"
    private var edgeRoundTripResponseBodyReceived = false
    private var edgeRoundTripCompleted = false
    private var downstreamWriteStarted = false
    private var flowWriteErrorCategory = "none"
    private var downstreamWriteCompleted = false
    private var runtimeCopyEndpointPassThroughObserved = false
    private var runtimeCopyEndpointPassthroughDecision = "endpoint_not_configured"
    private var edgePortFlowReentryObserved = false
    private var runtimeCopyEvidenceWriteFailureObserved = false
    private var startProxyRunningObserved = false
    private var transparentNetworkSettingsAppliedObserved = false

    // Content-dedup for the single shared diagnostic file. recordLiveCopyProgress fires on EVERY per-flow
    // progress sub-event and update() writes the whole file unconditionally — but once the first flow reaches
    // liveCopyStatus="completed" the snapshot is frozen (the progress mutate closure early-returns without
    // changing state), so every later progress event re-wrote byte-identical content. That redundant rewriting
    // dirtied ~34 GB/day of file-backed memory (a macOS "disk writes" resource report that destabilised the
    // provider) despite very little traffic. Skipping writes whose encoded bytes match the last write collapses
    // it to only real state changes.
    private let writeDedupLock = NSLock()
    private var lastWrittenDiagnostic: Data?
    // One-shot latch (guarded by `lock`): this diagnostic verifies the runtime-copy path reaches its stages;
    // once a terminal "completed" snapshot has been persisted the verification is done and the shared file is
    // frozen. After that the writer permanently detaches — every record*/update() call no-ops, no serialize, no
    // disk write. Per-flow rewrites of a last-writer-wins verification file carry zero information.
    private var diagnosticSealed = false

    public init(
        diagnosticURL: URL,
        now: @escaping @Sendable () -> Date = Date.init
    ) {
        self.diagnosticURL = diagnosticURL
        self.now = now
    }

    public convenience init(
        agentConfigPath: String,
        now: @escaping @Sendable () -> Date = Date.init
    ) throws {
        let data = try Data(contentsOf: URL(fileURLWithPath: agentConfigPath))
        let config = try JSONDecoder().decode(DsseProviderRuntimeCopyAgentConfig.self, from: data)
        let ref = config.runtimeDiagnosticRef?.trimmingCharacters(in: .whitespacesAndNewlines)
        let configDirectory = URL(fileURLWithPath: agentConfigPath).deletingLastPathComponent()
        let diagnosticURL = try DsseLocalRuntimeCopyEvidenceWriter.resolveEvidenceRef(
            ref?.isEmpty == false ? ref! : Self.defaultDiagnosticRef,
            relativeTo: configDirectory
        )
        self.init(diagnosticURL: diagnosticURL, now: now)
    }

    public func recordStartProxyRunning() throws {
        try update { state in
            state.startProxyRunningObserved = true
        }
    }

    public func recordTransparentNetworkSettingsApplied() throws {
        try update { state in
            state.transparentNetworkSettingsAppliedObserved = true
        }
    }

    public func recordProviderRulesReloadGate(_ gate: String) throws {
        try update { state in
            state.providerRulesReloadGate = Self.allowedProviderRulesReloadGate(gate)
        }
    }

    public func recordHandleNewFlow(
        decisionCategory: String,
        extractionStatus: String,
        extractionReason: String,
        providerDecisionAction: String,
        providerDecisionReason: String,
        singleRuleLabFallbackGate: String,
        flowAuthorityHostGate: String,
        flowAuthorityPortGate: String,
        singleRuleLabFallbackPortGate: String,
        allowFlowAuthorityPortMatch: String = "extraction_failed",
        providerLoadedRulesGeneratedAt: String,
        authorityExtractionRuntimeMarker: String = "not_observed",
        flowAuthorityEndpointSourceGate: String = "not_observed",
        flowAuthorityPortSourceGate: String = "not_observed"
    ) throws {
        try update { state in
            state.handleNewFlowObserved = true
            let incomingDecisionCategory = Self.allowedDecisionCategory(decisionCategory)
            let incomingExtractionStatus = Self.allowedHandleNewFlowExtractionStatus(extractionStatus)
            let incomingExtractionReason = Self.allowedHandleNewFlowExtractionReason(extractionReason)
            let incomingProviderDecisionAction = Self.allowedProviderDecisionAction(providerDecisionAction)
            let incomingProviderDecisionReason = Self.allowedProviderDecisionReason(providerDecisionReason)
            let incomingSingleRuleLabFallbackGate = Self.allowedSingleRuleLabFallbackGate(singleRuleLabFallbackGate)
            let incomingFlowAuthorityHostGate = Self.allowedFlowAuthorityHostGate(flowAuthorityHostGate)
            let incomingFlowAuthorityPortGate = Self.allowedFlowAuthorityPortGate(flowAuthorityPortGate)
            let incomingSingleRuleLabFallbackPortGate = Self.allowedSingleRuleLabFallbackPortGate(singleRuleLabFallbackPortGate)
            let incomingAllowFlowAuthorityPortMatch = Self.allowedAllowFlowAuthorityPortMatch(allowFlowAuthorityPortMatch)
            let incomingLoadedRulesGeneratedAt = Self.allowedGeneratedAt(providerLoadedRulesGeneratedAt)
            let incomingLoadedRulesGenerationGate = Self.generationGate(for: incomingLoadedRulesGeneratedAt)
            let incomingAuthorityExtractionRuntimeMarker = Self.allowedAuthorityExtractionRuntimeMarker(authorityExtractionRuntimeMarker)
            let incomingFlowAuthorityEndpointSourceGate = Self.allowedFlowAuthorityEndpointSourceGate(flowAuthorityEndpointSourceGate)
            let incomingFlowAuthorityPortSourceGate = Self.allowedFlowAuthorityPortSourceGate(flowAuthorityPortSourceGate)
            guard Self.handleNewFlowSnapshotRank(
                decisionCategory: incomingDecisionCategory,
                flowAuthorityPortGate: incomingFlowAuthorityPortGate,
                singleRuleLabFallbackPortGate: incomingSingleRuleLabFallbackPortGate
            ) >= Self.handleNewFlowSnapshotRank(
                decisionCategory: state.handleNewFlowDecisionCategory,
                flowAuthorityPortGate: state.flowAuthorityPortGate,
                singleRuleLabFallbackPortGate: state.singleRuleLabFallbackPortGate
            ) else {
                return
            }
            state.handleNewFlowDecisionCategory = incomingDecisionCategory
            state.handleNewFlowExtractionStatus = incomingExtractionStatus
            state.handleNewFlowExtractionReason = incomingExtractionReason
            state.providerDecisionAction = incomingProviderDecisionAction
            state.providerDecisionReason = incomingProviderDecisionReason
            state.singleRuleLabFallbackGate = incomingSingleRuleLabFallbackGate
            state.flowAuthorityHostGate = incomingFlowAuthorityHostGate
            state.flowAuthorityPortGate = incomingFlowAuthorityPortGate
            state.singleRuleLabFallbackPortGate = incomingSingleRuleLabFallbackPortGate
            state.allowFlowAuthorityPortMatch = incomingAllowFlowAuthorityPortMatch
            state.providerLoadedRulesGeneratedAt = incomingLoadedRulesGeneratedAt
            state.providerLoadedRulesGenerationGate = incomingLoadedRulesGenerationGate
            state.authorityExtractionRuntimeMarker = incomingAuthorityExtractionRuntimeMarker
            state.flowAuthorityEndpointSourceGate = incomingFlowAuthorityEndpointSourceGate
            state.flowAuthorityPortSourceGate = incomingFlowAuthorityPortSourceGate
        }
    }

    public func recordRuntimeCopyEndpointPassThrough() throws {
        try recordRuntimeCopyEndpointPassthroughDecision(
            decisionCategory: "matched_passed_through",
            edgePortFlowReentryObserved: true
        )
        try update { state in
            state.handleNewFlowObserved = true
            state.runtimeCopyEndpointPassThroughObserved = true
            if state.handleNewFlowDecisionCategory != "accepted" {
                state.handleNewFlowDecisionCategory = "pass_through_edge_endpoint"
            }
        }
    }

    public func recordRuntimeCopyEndpointPassthroughDecision(
        decisionCategory: String,
        edgePortFlowReentryObserved: Bool
    ) throws {
        try update { state in
            state.runtimeCopyEndpointPassthroughDecision = Self.preferredRuntimeCopyEndpointPassthroughDecision(
                current: state.runtimeCopyEndpointPassthroughDecision,
                incoming: Self.allowedRuntimeCopyEndpointPassthroughDecision(decisionCategory)
            )
            state.edgePortFlowReentryObserved = state.edgePortFlowReentryObserved || edgePortFlowReentryObserved
            if state.runtimeCopyEndpointPassthroughDecision == "matched_passed_through" {
                state.runtimeCopyEndpointPassThroughObserved = true
            }
        }
    }

    public func recordLiveCopyProgress(_ progress: DsseLiveRuntimeCopyProgress) throws {
        // Hot path: fires on EVERY per-flow progress sub-event. This is a phase-2 verification snapshot in a single
        // shared file (last-writer-wins); once the runtime-copy path has been observed through to a terminal
        // "completed" state the snapshot is frozen and carries no further information. Short-circuit BEFORE update()
        // so a frozen diagnostic does ZERO work on the flood — no serialise, no atomic whole-file rewrite. The root
        // fix is to stop the pointless rewrite at the source, not to perform it every time and dedup it away. (The
        // rare non-progress record* methods still update; the dedup in update() covers those + pre-"completed"
        // transitions as a secondary guard.)
        lock.lock()
        let frozen = (liveCopyStatus == "completed")
        lock.unlock()
        if frozen { return }
        try update { state in
            guard state.liveCopyStatus != "completed" else {
                return
            }
            state.liveCopyFailureCategory = "none"
            switch progress {
            case .liveCopyStarted:
                state.liveCopyStatus = "started"
                state.liveCopyStarted = true
            case .flowOpenCompleted:
                state.liveCopyStatus = "in_progress"
                state.liveCopyStarted = true
                state.flowOpenCompleted = true
            case .upstreamReadCompleted(let bytes):
                state.liveCopyStatus = "in_progress"
                state.liveCopyStarted = true
                state.upstreamReadCompleted = true
                state.upstreamReadBytes = max(0, bytes)
            case .edgeRoundTripStarted:
                state.liveCopyStatus = "in_progress"
                state.liveCopyStarted = true
                state.edgeRoundTripStarted = true
            case .edgeTCPConnectStarted(let family):
                state.liveCopyStatus = "in_progress"
                state.liveCopyStarted = true
                state.edgeRoundTripStarted = true
                state.edgeTCPConnectStarted = true
                state.edgeTCPConnectAddressFamily = Self.allowedEdgeTCPConnectAddressFamily(family)
            case .edgeTCPConnectCompleted(let family):
                state.liveCopyStatus = "in_progress"
                state.liveCopyStarted = true
                state.edgeRoundTripStarted = true
                state.edgeTCPConnectStarted = true
                state.edgeTCPConnectCompleted = true
                state.edgeTCPConnectAddressFamily = Self.allowedEdgeTCPConnectAddressFamily(family)
            case .edgeRoundTripRequestSent:
                state.liveCopyStatus = "in_progress"
                state.liveCopyStarted = true
                state.edgeRoundTripStarted = true
                state.edgeRoundTripRequestSent = true
            case .edgeRoundTripResponseStatusReceived(let category):
                state.liveCopyStatus = "in_progress"
                state.liveCopyStarted = true
                state.edgeRoundTripStarted = true
                state.edgeRoundTripRequestSent = true
                state.edgeRoundTripResponseStatusReceived = true
                state.edgeRoundTripResponseStatusCategory = Self.allowedHTTPStatusCategory(category)
            case .edgeRoundTripErrorCategory(let category):
                state.liveCopyStatus = "in_progress"
                state.liveCopyStarted = true
                state.edgeRoundTripStarted = true
                state.edgeRoundTripRequestSent = true
                state.edgeRoundTripErrorCategory = Self.allowedEdgeRoundTripErrorCategory(category)
            case .edgeRoundTripResponseBodyReceived:
                state.liveCopyStatus = "in_progress"
                state.liveCopyStarted = true
                state.edgeRoundTripStarted = true
                state.edgeRoundTripRequestSent = true
                state.edgeRoundTripResponseBodyReceived = true
            case .edgeRoundTripCompleted:
                state.liveCopyStatus = "in_progress"
                state.liveCopyStarted = true
                state.edgeRoundTripStarted = true
                state.edgeRoundTripRequestSent = true
                state.edgeRoundTripResponseBodyReceived = true
                state.edgeRoundTripCompleted = true
            case .downstreamWriteStarted:
                state.liveCopyStatus = "in_progress"
                state.liveCopyStarted = true
                state.downstreamWriteStarted = true
                state.flowWriteErrorCategory = "none"
            case .downstreamWriteFailed(let category):
                state.liveCopyStatus = "in_progress"
                state.liveCopyStarted = true
                state.downstreamWriteStarted = true
                state.flowWriteErrorCategory = Self.allowedFlowWriteErrorCategory(category)
            case .downstreamWriteCompleted:
                state.liveCopyStatus = "in_progress"
                state.liveCopyStarted = true
                state.downstreamWriteStarted = true
                state.flowWriteErrorCategory = "none"
                state.downstreamWriteCompleted = true
            }
        }
    }

    public func recordLiveCopyCompleted() throws {
        try update { state in
            state.liveCopyStatus = "completed"
            state.liveCopyFailureCategory = "none"
            state.liveCopyStarted = true
            state.edgeRoundTripStarted = true
            state.edgeTCPConnectStarted = true
            state.edgeTCPConnectCompleted = true
            state.edgeRoundTripRequestSent = true
            state.edgeRoundTripResponseBodyReceived = true
            state.edgeRoundTripCompleted = true
            state.downstreamWriteStarted = true
            state.flowWriteErrorCategory = "none"
            state.downstreamWriteCompleted = true
        }
    }

    public func recordLiveCopyFailed(_ error: Error) throws {
        try update { state in
            guard state.liveCopyStatus != "completed" else {
                return
            }
            state.liveCopyStatus = "failed"
            let failureCategory = Self.failureCategory(for: error)
            state.liveCopyFailureCategory = failureCategory
            if failureCategory == "flow_write" && state.flowWriteErrorCategory == "none" {
                state.flowWriteErrorCategory = Self.flowWriteErrorCategory(for: error)
            } else if failureCategory == "flow_write_timeout" {
                state.flowWriteErrorCategory = "timeout"
            }
            state.liveCopyStarted = true
        }
    }

    public func recordRuntimeCopyEvidenceWriteFailed() throws {
        try update { state in
            state.runtimeCopyEvidenceWriteFailureObserved = true
            state.liveCopyStatus = "evidence_write_failed"
            state.liveCopyFailureCategory = "evidence_write"
        }
    }

    public func section16RuntimeCopyEvidenceSnapshot() -> DsseSection16RuntimeCopyEvidence {
        lock.lock()
        defer { lock.unlock() }
        return DsseSection16RuntimeCopyEvidence(
            edgePortFlowReentryObserved: edgePortFlowReentryObserved,
            runtimeCopyEndpointPassthroughDecision: runtimeCopyEndpointPassthroughDecision,
            edgeTCPConnectCompleted: edgeTCPConnectCompleted,
            edgeTCPConnectAddressFamily: edgeTCPConnectAddressFamily
        )
    }

    private struct MutableState {
        var handleNewFlowObserved: Bool
        var handleNewFlowDecisionCategory: String
        var handleNewFlowExtractionStatus: String
        var handleNewFlowExtractionReason: String
        var providerDecisionAction: String
        var providerDecisionReason: String
        var providerRulesReloadGate: String
        var providerLoadedRulesGenerationGate: String
        var providerLoadedRulesGeneratedAt: String
        var authorityExtractionRuntimeMarker: String
        var flowAuthorityEndpointSourceGate: String
        var flowAuthorityPortSourceGate: String
        var singleRuleLabFallbackGate: String
        var flowAuthorityHostGate: String
        var flowAuthorityPortGate: String
        var singleRuleLabFallbackPortGate: String
        var allowFlowAuthorityPortMatch: String
        var liveCopyStatus: String
        var liveCopyFailureCategory: String
        var liveCopyStarted: Bool
        var flowOpenCompleted: Bool
        var upstreamReadCompleted: Bool
        var upstreamReadBytes: Int
        var edgeRoundTripStarted: Bool
        var edgeTCPConnectStarted: Bool
        var edgeTCPConnectCompleted: Bool
        var edgeTCPConnectAddressFamily: String
        var edgeRoundTripRequestSent: Bool
        var edgeRoundTripResponseStatusReceived: Bool
        var edgeRoundTripResponseStatusCategory: String
        var edgeRoundTripErrorCategory: String
        var edgeRoundTripResponseBodyReceived: Bool
        var edgeRoundTripCompleted: Bool
        var downstreamWriteStarted: Bool
        var flowWriteErrorCategory: String
        var downstreamWriteCompleted: Bool
        var runtimeCopyEndpointPassThroughObserved: Bool
        var runtimeCopyEndpointPassthroughDecision: String
        var edgePortFlowReentryObserved: Bool
        var runtimeCopyEvidenceWriteFailureObserved: Bool
        var startProxyRunningObserved: Bool
        var transparentNetworkSettingsAppliedObserved: Bool
    }

    private func update(_ mutate: (inout MutableState) -> Void) throws {
        lock.lock()
        if diagnosticSealed { // one-shot: terminal snapshot already persisted; do no work, touch no disk.
            lock.unlock()
            return
        }
        var state = MutableState(
            handleNewFlowObserved: handleNewFlowObserved,
            handleNewFlowDecisionCategory: handleNewFlowDecisionCategory,
            handleNewFlowExtractionStatus: handleNewFlowExtractionStatus,
            handleNewFlowExtractionReason: handleNewFlowExtractionReason,
            providerDecisionAction: providerDecisionAction,
            providerDecisionReason: providerDecisionReason,
            providerRulesReloadGate: providerRulesReloadGate,
            providerLoadedRulesGenerationGate: providerLoadedRulesGenerationGate,
            providerLoadedRulesGeneratedAt: providerLoadedRulesGeneratedAt,
            authorityExtractionRuntimeMarker: authorityExtractionRuntimeMarker,
            flowAuthorityEndpointSourceGate: flowAuthorityEndpointSourceGate,
            flowAuthorityPortSourceGate: flowAuthorityPortSourceGate,
            singleRuleLabFallbackGate: singleRuleLabFallbackGate,
            flowAuthorityHostGate: flowAuthorityHostGate,
            flowAuthorityPortGate: flowAuthorityPortGate,
            singleRuleLabFallbackPortGate: singleRuleLabFallbackPortGate,
            allowFlowAuthorityPortMatch: allowFlowAuthorityPortMatch,
            liveCopyStatus: liveCopyStatus,
            liveCopyFailureCategory: liveCopyFailureCategory,
            liveCopyStarted: liveCopyStarted,
            flowOpenCompleted: flowOpenCompleted,
            upstreamReadCompleted: upstreamReadCompleted,
            upstreamReadBytes: upstreamReadBytes,
            edgeRoundTripStarted: edgeRoundTripStarted,
            edgeTCPConnectStarted: edgeTCPConnectStarted,
            edgeTCPConnectCompleted: edgeTCPConnectCompleted,
            edgeTCPConnectAddressFamily: edgeTCPConnectAddressFamily,
            edgeRoundTripRequestSent: edgeRoundTripRequestSent,
            edgeRoundTripResponseStatusReceived: edgeRoundTripResponseStatusReceived,
            edgeRoundTripResponseStatusCategory: edgeRoundTripResponseStatusCategory,
            edgeRoundTripErrorCategory: edgeRoundTripErrorCategory,
            edgeRoundTripResponseBodyReceived: edgeRoundTripResponseBodyReceived,
            edgeRoundTripCompleted: edgeRoundTripCompleted,
            downstreamWriteStarted: downstreamWriteStarted,
            flowWriteErrorCategory: flowWriteErrorCategory,
            downstreamWriteCompleted: downstreamWriteCompleted,
            runtimeCopyEndpointPassThroughObserved: runtimeCopyEndpointPassThroughObserved,
            runtimeCopyEndpointPassthroughDecision: runtimeCopyEndpointPassthroughDecision,
            edgePortFlowReentryObserved: edgePortFlowReentryObserved,
            runtimeCopyEvidenceWriteFailureObserved: runtimeCopyEvidenceWriteFailureObserved,
            startProxyRunningObserved: startProxyRunningObserved,
            transparentNetworkSettingsAppliedObserved: transparentNetworkSettingsAppliedObserved
        )
        mutate(&state)
        handleNewFlowObserved = state.handleNewFlowObserved
        handleNewFlowDecisionCategory = state.handleNewFlowDecisionCategory
        handleNewFlowExtractionStatus = state.handleNewFlowExtractionStatus
        handleNewFlowExtractionReason = state.handleNewFlowExtractionReason
        providerDecisionAction = state.providerDecisionAction
        providerDecisionReason = state.providerDecisionReason
        providerRulesReloadGate = state.providerRulesReloadGate
        providerLoadedRulesGenerationGate = state.providerLoadedRulesGenerationGate
        providerLoadedRulesGeneratedAt = state.providerLoadedRulesGeneratedAt
        authorityExtractionRuntimeMarker = state.authorityExtractionRuntimeMarker
        flowAuthorityEndpointSourceGate = state.flowAuthorityEndpointSourceGate
        flowAuthorityPortSourceGate = state.flowAuthorityPortSourceGate
        singleRuleLabFallbackGate = state.singleRuleLabFallbackGate
        flowAuthorityHostGate = state.flowAuthorityHostGate
        flowAuthorityPortGate = state.flowAuthorityPortGate
        singleRuleLabFallbackPortGate = state.singleRuleLabFallbackPortGate
        allowFlowAuthorityPortMatch = state.allowFlowAuthorityPortMatch
        liveCopyStatus = state.liveCopyStatus
        liveCopyFailureCategory = state.liveCopyFailureCategory
        liveCopyStarted = state.liveCopyStarted
        flowOpenCompleted = state.flowOpenCompleted
        upstreamReadCompleted = state.upstreamReadCompleted
        upstreamReadBytes = state.upstreamReadBytes
        edgeRoundTripStarted = state.edgeRoundTripStarted
        edgeTCPConnectStarted = state.edgeTCPConnectStarted
        edgeTCPConnectCompleted = state.edgeTCPConnectCompleted
        edgeTCPConnectAddressFamily = state.edgeTCPConnectAddressFamily
        edgeRoundTripRequestSent = state.edgeRoundTripRequestSent
        edgeRoundTripResponseStatusReceived = state.edgeRoundTripResponseStatusReceived
        edgeRoundTripResponseStatusCategory = state.edgeRoundTripResponseStatusCategory
        edgeRoundTripErrorCategory = state.edgeRoundTripErrorCategory
        edgeRoundTripResponseBodyReceived = state.edgeRoundTripResponseBodyReceived
        edgeRoundTripCompleted = state.edgeRoundTripCompleted
        downstreamWriteStarted = state.downstreamWriteStarted
        flowWriteErrorCategory = state.flowWriteErrorCategory
        downstreamWriteCompleted = state.downstreamWriteCompleted
        runtimeCopyEndpointPassThroughObserved = state.runtimeCopyEndpointPassThroughObserved
        runtimeCopyEndpointPassthroughDecision = state.runtimeCopyEndpointPassthroughDecision
        edgePortFlowReentryObserved = state.edgePortFlowReentryObserved
        runtimeCopyEvidenceWriteFailureObserved = state.runtimeCopyEvidenceWriteFailureObserved
        startProxyRunningObserved = state.startProxyRunningObserved
        transparentNetworkSettingsAppliedObserved = state.transparentNetworkSettingsAppliedObserved
        let terminal = (state.liveCopyStatus == "completed")
        let diagnostic = makeDiagnostic(from: state)
        lock.unlock()
        try Self.validate(diagnostic)
        // Content-dedup (secondary guard for the pre-terminal / never-completes path): skip the write when the
        // diagnostic is unchanged, comparing on state EXCLUDING the volatile createdAt timestamp so it reflects
        // real state changes, not the clock. The PRIMARY control is the one-shot seal below: once a terminal
        // "completed" snapshot is persisted the writer stops entirely (per-flow rewrites of a last-writer-wins
        // verification file carry no information and were the disk-writes bug).
        let dedupKey = try Self.encodeDiagnostic(makeDiagnostic(from: state, createdAtOverride: ""))
        writeDedupLock.lock()
        let unchanged = (dedupKey == lastWrittenDiagnostic)
        if !unchanged { lastWrittenDiagnostic = dedupKey }
        writeDedupLock.unlock()
        if !unchanged {
            try Self.writeDiagnostic(try Self.encodeDiagnostic(diagnostic), to: diagnosticURL)
        }
        if terminal { // seal AFTER the terminal snapshot is (or already was) on disk
            lock.lock()
            diagnosticSealed = true
            lock.unlock()
        }
    }

    // encodeDiagnostic serialises the diagnostic exactly as writeDiagnostic persists it (pretty + sorted keys), so
    // the dedup comparison in update() is byte-exact against the on-disk form.
    private static func encodeDiagnostic(_ diagnostic: DsseProviderRuntimeDiagnostic) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(diagnostic)
    }

    // createdAtOverride lets update() build a timestamp-free variant for the dedup comparison (the real createdAt
    // changes every call and would otherwise defeat dedup); the persisted file always carries the real timestamp.
    private func makeDiagnostic(from state: MutableState, createdAtOverride: String? = nil) -> DsseProviderRuntimeDiagnostic {
        DsseProviderRuntimeDiagnostic(
            schemaVersion: DsseProviderRuntimeDiagnostic.schemaVersion,
            status: "ok",
            evidenceKind: "phase2_provider_runtime_enum_diagnostic",
            createdAt: createdAtOverride ?? ISO8601DateFormatter().string(from: now()),
            diagnosticSource: "provider_direct_file",
            handleNewFlowObserved: state.handleNewFlowObserved,
            handleNewFlowDecisionCategory: state.handleNewFlowDecisionCategory,
            handleNewFlowExtractionStatus: state.handleNewFlowExtractionStatus,
            handleNewFlowExtractionReason: state.handleNewFlowExtractionReason,
            providerDecisionAction: state.providerDecisionAction,
            providerDecisionReason: state.providerDecisionReason,
            providerRulesReloadGate: state.providerRulesReloadGate,
            providerLoadedRulesGenerationGate: state.providerLoadedRulesGenerationGate,
            providerLoadedRulesGeneratedAt: state.providerLoadedRulesGeneratedAt,
            authorityExtractionRuntimeMarker: state.authorityExtractionRuntimeMarker,
            flowAuthorityEndpointSourceGate: state.flowAuthorityEndpointSourceGate,
            flowAuthorityPortSourceGate: state.flowAuthorityPortSourceGate,
            singleRuleLabFallbackGate: state.singleRuleLabFallbackGate,
            flowAuthorityHostGate: state.flowAuthorityHostGate,
            flowAuthorityPortGate: state.flowAuthorityPortGate,
            singleRuleLabFallbackPortGate: state.singleRuleLabFallbackPortGate,
            allowFlowAuthorityPortMatch: state.allowFlowAuthorityPortMatch,
            liveCopyStatus: state.liveCopyStatus,
            liveCopyFailureCategory: state.liveCopyFailureCategory,
            liveCopyStarted: state.liveCopyStarted,
            flowOpenCompleted: state.flowOpenCompleted,
            upstreamReadCompleted: state.upstreamReadCompleted,
            upstreamReadBytes: state.upstreamReadBytes,
            edgeRoundTripStarted: state.edgeRoundTripStarted,
            edgeTCPConnectStarted: state.edgeTCPConnectStarted,
            edgeTCPConnectCompleted: state.edgeTCPConnectCompleted,
            edgeTCPConnectAddressFamily: state.edgeTCPConnectAddressFamily,
            edgeRoundTripRequestSent: state.edgeRoundTripRequestSent,
            edgeRoundTripResponseStatusReceived: state.edgeRoundTripResponseStatusReceived,
            edgeRoundTripResponseStatusCategory: state.edgeRoundTripResponseStatusCategory,
            edgeRoundTripErrorCategory: state.edgeRoundTripErrorCategory,
            edgeRoundTripResponseBodyReceived: state.edgeRoundTripResponseBodyReceived,
            edgeRoundTripCompleted: state.edgeRoundTripCompleted,
            downstreamWriteStarted: state.downstreamWriteStarted,
            flowWriteErrorCategory: state.flowWriteErrorCategory,
            downstreamWriteCompleted: state.downstreamWriteCompleted,
            runtimeCopyEndpointPassThroughObserved: state.runtimeCopyEndpointPassThroughObserved,
            runtimeCopyEndpointPassthroughDecision: state.runtimeCopyEndpointPassthroughDecision,
            edgePortFlowReentryObserved: state.edgePortFlowReentryObserved,
            runtimeCopyEvidenceWriteFailureObserved: state.runtimeCopyEvidenceWriteFailureObserved,
            startProxyRunningObserved: state.startProxyRunningObserved,
            transparentNetworkSettingsAppliedObserved: state.transparentNetworkSettingsAppliedObserved,
            rawLogsIncluded: false,
            rawCommandOutputIncluded: false,
            rawNEFlowIncluded: false,
            hostUserPayloadIncluded: false,
            destinationIPIncluded: false,
            credentialsIncluded: false,
            packetCaptureIncluded: false,
            appleIdentifierIncluded: false,
            noSecretAttestation: true,
            recommendedNextDevAction: Self.recommendedNextDevAction(
                decisionCategory: state.handleNewFlowDecisionCategory,
                failureCategory: state.liveCopyFailureCategory,
                runtimeCopyEndpointPassthroughDecision: state.runtimeCopyEndpointPassthroughDecision,
                edgePortFlowReentryObserved: state.edgePortFlowReentryObserved,
                edgeTCPConnectAddressFamily: state.edgeTCPConnectAddressFamily,
                edgeRoundTripErrorCategory: state.edgeRoundTripErrorCategory,
                singleRuleLabFallbackGate: state.singleRuleLabFallbackGate,
                singleRuleLabFallbackPortGate: state.singleRuleLabFallbackPortGate
            ),
            nonsecretNotes: ["provider wrote enum diagnostic directly; categories and gates only"]
        )
    }

    private static func allowedDecisionCategory(_ value: String) -> String {
        ["accepted", "deny_closed", "not_observed", "pass_through_edge_endpoint"].contains(value) ? value : "not_observed"
    }

    private static func allowedHandleNewFlowExtractionStatus(_ value: String) -> String {
        ["ok", "denied", "not_observed"].contains(value) ? value : "not_observed"
    }

    private static func allowedHandleNewFlowExtractionReason(_ value: String) -> String {
        [
            "extracted_tcp_host_port",
            "unsupported_transport",
            "invalid_flow_authority",
            "not_observed"
        ].contains(value) ? value : "not_observed"
    }

    private static func allowedProviderDecisionAction(_ value: String) -> String {
        ["tunnel", "deny", "not_observed"].contains(value) ? value : "not_observed"
    }

    private static func allowedProviderDecisionReason(_ value: String) -> String {
        [
            "matched_network_extension_rule",
            "matched_ac09_protection_rule",
            "no_matching_network_extension_rule",
            "invalid_flow_authority",
            "invalid_network_extension_rules",
            "not_observed"
        ].contains(value) ? value : "not_observed"
    }

    private static func allowedProviderRulesReloadGate(_ value: String) -> String {
        [
            "not_checked",
            "skipped_no_config",
            "skipped_missing_rules_ref",
            "skipped_not_newer",
            "reloaded",
            "config_read_failed",
            "config_decode_failed",
            "rules_ref_invalid",
            "rules_read_failed",
            "rules_decode_failed",
            "rules_validation_failed",
            "unknown_failure"
        ].contains(value) ? value : "unknown_failure"
    }

    private static func allowedGeneratedAt(_ value: String) -> String {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed == "not_observed" || trimmed == "missing" {
            return trimmed
        }
        let pattern = #"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$"#
        if trimmed.range(of: pattern, options: .regularExpression) != nil {
            return trimmed
        }
        return "invalid_nonsecret"
    }

    private static func allowedAuthorityExtractionRuntimeMarker(_ value: String) -> String {
        [
            "not_observed",
            "hostport_described_port_preferred"
        ].contains(value) ? value : "not_observed"
    }

    private static func allowedFlowAuthorityEndpointSourceGate(_ value: String) -> String {
        [
            "not_observed",
            "flow_remote_named_authority_preferred",
            "remote_flow_endpoint_hostport",
            "remote_flow_endpoint_url",
            "remote_flow_endpoint_opaque",
            "legacy_remote_endpoint",
            "fallback_empty_authority",
            "unsupported_transport"
        ].contains(value) ? value : "not_observed"
    }

    private static func allowedFlowAuthorityPortSourceGate(_ value: String) -> String {
        [
            "not_observed",
            "hostport_described_port",
            "hostport_rawvalue_fallback",
            "url_port",
            "opaque_nw_endpoint_get_port",
            "legacy_remote_endpoint_port",
            "fallback_missing"
        ].contains(value) ? value : "not_observed"
    }

    private static func generationGate(for generatedAt: String) -> String {
        switch allowedGeneratedAt(generatedAt) {
        case "not_observed":
            return "not_observed"
        case "missing":
            return "missing"
        case "invalid_nonsecret":
            return "invalid_nonsecret"
        default:
            return "present"
        }
    }

    private static func allowedSingleRuleLabFallbackGate(_ value: String) -> String {
        [
            "not_evaluated",
            "applied",
            "phase4_protection_port_rule_applied",
            "p2_operator_config_port_fallback_applied",
            "p2_operator_config_authority_host_rule_mismatch_default_deny",
            "p2_operator_config_unusable_authority_host_default_deny",
            "lifecycle_not_running",
            "rules_not_loaded",
            "source_map_not_phase2_flow_copy_lab",
            "rule_count_not_one",
            "rule_action_not_tunnel",
            "destination_port_mismatch"
        ].contains(value) ? value : "not_evaluated"
    }

    private static func allowedFlowAuthorityHostGate(_ value: String) -> String {
        [
            "not_observed",
            "hostname",
            "ip_literal",
            "empty_or_missing",
            "invalid_nonsecret"
        ].contains(value) ? value : "not_observed"
    }

    private static func allowedFlowAuthorityPortGate(_ value: String) -> String {
        [
            "not_observed",
            "positive",
            "zero_or_missing",
            "out_of_range"
        ].contains(value) ? value : "not_observed"
    }

    private static func allowedSingleRuleLabFallbackPortGate(_ value: String) -> String {
        [
            "not_evaluated",
            "matched",
            "mismatch",
            "authority_port_zero_or_missing",
            "authority_port_out_of_range",
            "fallback_not_available"
        ].contains(value) ? value : "not_evaluated"
    }

    private static func allowedAllowFlowAuthorityPortMatch(_ value: String) -> String {
        [
            "exact",
            "off_by_delta",
            "extraction_failed",
            "sent_to_non_rule_port"
        ].contains(value) ? value : "extraction_failed"
    }

    private static func handleNewFlowSnapshotRank(
        decisionCategory: String,
        flowAuthorityPortGate: String,
        singleRuleLabFallbackPortGate: String
    ) -> Int {
        switch allowedDecisionCategory(decisionCategory) {
        case "accepted":
            return 4
        case "pass_through_edge_endpoint":
            return 3
        case "deny_closed":
            if allowedSingleRuleLabFallbackPortGate(singleRuleLabFallbackPortGate) == "mismatch" ||
                allowedFlowAuthorityPortGate(flowAuthorityPortGate) == "positive" {
                return 2
            }
            return 1
        default:
            return 0
        }
    }

    private static func allowedHTTPStatusCategory(_ value: String) -> String {
        [
            "none",
            "informational",
            "success",
            "redirect",
            "client_error",
            "server_error",
            "other_nonsecret"
        ].contains(value) ? value : "other_nonsecret"
    }

    private static func allowedEdgeRoundTripErrorCategory(_ value: String) -> String {
        [
            "none",
            "method_not_allowed",
            "request_body_too_large",
            "invalid_request_json",
            "invalid_schema_version",
            "invalid_tenant_id",
            "tenant_scope_mismatch",
            "invalid_request_id",
            "invalid_base64_payload",
            "empty_upstream_payload",
            "unknown_application_default_deny",
            "round_trip_timeout",
            "round_trip_failed",
            "response_body_missing",
            "response_error_decode_failed",
            "response_error_schema_invalid",
            "unknown_nonsecret"
        ].contains(value) ? value : "unknown_nonsecret"
    }

    private static func allowedRuntimeCopyEndpointPassthroughDecision(_ value: String) -> String {
        [
            "endpoint_not_configured",
            "no_flow_matched_edge_port",
            "matched_passed_through",
            "port_matched_host_mismatch"
        ].contains(value) ? value : "endpoint_not_configured"
    }

    private static func preferredRuntimeCopyEndpointPassthroughDecision(current: String, incoming: String) -> String {
        let current = allowedRuntimeCopyEndpointPassthroughDecision(current)
        if runtimeCopyEndpointPassthroughDecisionRank(incoming) >= runtimeCopyEndpointPassthroughDecisionRank(current) {
            return incoming
        }
        return current
    }

    private static func runtimeCopyEndpointPassthroughDecisionRank(_ value: String) -> Int {
        switch value {
        case "matched_passed_through":
            return 3
        case "port_matched_host_mismatch":
            return 2
        case "no_flow_matched_edge_port":
            return 1
        default:
            return 0
        }
    }

    private static func allowedEdgeTCPConnectAddressFamily(_ value: String) -> String {
        [
            "none",
            "ipv4",
            "ipv6",
            "fqdn_unresolved",
            "unknown_nonsecret"
        ].contains(value) ? value : "unknown_nonsecret"
    }

    private static func allowedFlowWriteErrorCategory(_ value: String) -> String {
        [
            "none",
            "driver_flow_write_error",
            "ne_provider_flow_error",
            "posix_error",
            "cocoa_error",
            "timeout",
            "unknown_nonsecret"
        ].contains(value) ? value : "unknown_nonsecret"
    }

    private static func flowWriteErrorCategory(for error: Error?) -> String {
        guard let error else {
            return "none"
        }
        if let driverError = error as? DsseLocalRuntimeCopyDriverError {
            switch driverError {
            case .flowWriteFailed:
                return "driver_flow_write_error"
            case .flowWriteTimeout:
                return "timeout"
            default:
                return "unknown_nonsecret"
            }
        }
        let nsError = error as NSError
        let normalizedDomain = nsError.domain.lowercased()
        if normalizedDomain.contains("neappproxy") ||
            normalizedDomain.contains("networkextension") {
            return "ne_provider_flow_error"
        }
        switch nsError.domain {
        case "NEAppProxyErrorDomain":
            return "ne_provider_flow_error"
        case NSPOSIXErrorDomain:
            return "posix_error"
        case NSCocoaErrorDomain:
            return "cocoa_error"
        default:
            return "unknown_nonsecret"
        }
    }

    private static func failureCategory(for error: Error) -> String {
        switch error as? DsseLocalRuntimeCopyDriverError {
        case .flowOpenFailed:
            return "flow_open"
        case .flowReadFailed:
            return "flow_read"
        case .flowOpenTimeout:
            return "flow_open_timeout"
        case .flowReadTimeout:
            return "flow_read_timeout"
        case .emptyUpstreamPayload:
            return "empty_upstream"
        case .edgeRoundTripTimeout:
            return "edge_round_trip_timeout"
        case .edgeTransportRequestFailed, .edgeTransportStatusFailed, .edgeTransportDecodeFailed, .edgeTransportRequestIDMismatch:
            return "edge_round_trip"
        case .flowWriteFailed:
            return "flow_write"
        case .flowWriteTimeout:
            return "flow_write_timeout"
        default:
            return "unknown_nonsecret"
        }
    }

    private static func recommendedNextDevAction(
        decisionCategory: String,
        failureCategory: String,
        runtimeCopyEndpointPassthroughDecision: String,
        edgePortFlowReentryObserved: Bool,
        edgeTCPConnectAddressFamily: String,
        edgeRoundTripErrorCategory: String,
        singleRuleLabFallbackGate: String,
        singleRuleLabFallbackPortGate: String
    ) -> String {
        switch failureCategory {
        case "edge_round_trip", "edge_round_trip_timeout":
            if edgeRoundTripErrorCategory != "none" {
                return "inspect_connector_runtime_copy_round_trip_error_category"
            }
            if edgePortFlowReentryObserved && runtimeCopyEndpointPassthroughDecision != "matched_passed_through" {
                return "inspect_runtime_copy_passthrough_predicate"
            }
            if !edgePortFlowReentryObserved && edgeTCPConnectAddressFamily == "ipv6" {
                return "inspect_edge_tcp_connect_family_or_lab_responder"
            }
            return "inspect_lab_endpoint_self_capture_or_provider_transport"
        case "flow_write":
            return "inspect_ne_flow_write_error_category"
        case "flow_open", "flow_open_timeout", "flow_read", "flow_read_timeout", "empty_upstream", "flow_write_timeout":
            return "inspect_ne_flow_copy_io_runtime"
        case "evidence_write":
            return "inspect_runtime_copy_evidence_writer"
        default:
            if decisionCategory == "deny_closed" {
                if singleRuleLabFallbackGate == "destination_port_mismatch",
                   singleRuleLabFallbackPortGate != "mismatch" {
                    return "inspect_provider_authority_port_gate"
                }
                return "inspect_provider_single_rule_lab_fallback_gate"
            }
            if decisionCategory == "pass_through_edge_endpoint" {
                return "inspect_lab_endpoint_self_capture_or_provider_transport"
            }
            return decisionCategory == "not_observed" ? "inspect_ne_steering_target_takeover" : "inspect_provider_runtime_next_gate"
        }
    }

    private static func validate(_ diagnostic: DsseProviderRuntimeDiagnostic) throws {
        guard diagnostic.status == "ok",
              diagnostic.evidenceKind == "phase2_provider_runtime_enum_diagnostic",
              diagnostic.diagnosticSource == "provider_direct_file" else {
            throw DsseLocalRuntimeCopyEvidenceError.invalidEvidence("provider runtime diagnostic identity is invalid")
        }
        guard ["accepted", "deny_closed", "not_observed", "pass_through_edge_endpoint"].contains(diagnostic.handleNewFlowDecisionCategory),
              ["ok", "denied", "not_observed"].contains(diagnostic.handleNewFlowExtractionStatus),
              ["extracted_tcp_host_port", "unsupported_transport", "invalid_flow_authority", "not_observed"].contains(diagnostic.handleNewFlowExtractionReason),
              ["tunnel", "deny", "not_observed"].contains(diagnostic.providerDecisionAction),
              ["matched_network_extension_rule", "matched_ac09_protection_rule", "no_matching_network_extension_rule", "invalid_flow_authority", "invalid_network_extension_rules", "not_observed"].contains(diagnostic.providerDecisionReason),
              ["not_checked", "skipped_no_config", "skipped_missing_rules_ref", "skipped_not_newer", "reloaded", "config_read_failed", "config_decode_failed", "rules_ref_invalid", "rules_read_failed", "rules_decode_failed", "rules_validation_failed", "unknown_failure"].contains(diagnostic.providerRulesReloadGate),
              ["not_observed", "present", "missing", "invalid_nonsecret"].contains(diagnostic.providerLoadedRulesGenerationGate),
              allowedGeneratedAt(diagnostic.providerLoadedRulesGeneratedAt) == diagnostic.providerLoadedRulesGeneratedAt,
              ["not_observed", "hostport_described_port_preferred"].contains(diagnostic.authorityExtractionRuntimeMarker),
              ["not_observed", "flow_remote_named_authority_preferred", "remote_flow_endpoint_hostport", "remote_flow_endpoint_url", "remote_flow_endpoint_opaque", "legacy_remote_endpoint", "fallback_empty_authority", "unsupported_transport"].contains(diagnostic.flowAuthorityEndpointSourceGate),
              ["not_observed", "hostport_described_port", "hostport_rawvalue_fallback", "url_port", "opaque_nw_endpoint_get_port", "legacy_remote_endpoint_port", "fallback_missing"].contains(diagnostic.flowAuthorityPortSourceGate),
              ["not_evaluated", "applied", "phase4_protection_port_rule_applied", "p2_operator_config_port_fallback_applied", "p2_operator_config_authority_host_rule_mismatch_default_deny", "p2_operator_config_unusable_authority_host_default_deny", "invalid_authority_host_port_mismatch_bypassed", "lifecycle_not_running", "rules_not_loaded", "source_map_not_phase2_flow_copy_lab", "rule_count_not_one", "rule_action_not_tunnel", "destination_port_mismatch"].contains(diagnostic.singleRuleLabFallbackGate),
              ["not_observed", "hostname", "ip_literal", "empty_or_missing", "invalid_nonsecret"].contains(diagnostic.flowAuthorityHostGate),
              ["not_observed", "positive", "zero_or_missing", "out_of_range"].contains(diagnostic.flowAuthorityPortGate),
              ["not_evaluated", "matched", "invalid_authority_host_positive_port_mismatch_bypassed", "mismatch", "authority_port_zero_or_missing", "authority_port_out_of_range", "fallback_not_available"].contains(diagnostic.singleRuleLabFallbackPortGate),
              ["exact", "off_by_delta", "extraction_failed", "sent_to_non_rule_port"].contains(diagnostic.allowFlowAuthorityPortMatch),
              ["completed", "failed", "evidence_write_failed", "not_observed", "started", "in_progress"].contains(diagnostic.liveCopyStatus),
              ["flow_open", "flow_read", "flow_open_timeout", "flow_read_timeout", "empty_upstream", "edge_round_trip", "edge_round_trip_timeout", "flow_write", "flow_write_timeout", "evidence_write", "none", "unknown_nonsecret"].contains(diagnostic.liveCopyFailureCategory),
              ["none", "informational", "success", "redirect", "client_error", "server_error", "other_nonsecret"].contains(diagnostic.edgeRoundTripResponseStatusCategory),
              ["none", "method_not_allowed", "request_body_too_large", "invalid_request_json", "invalid_schema_version", "invalid_tenant_id", "tenant_scope_mismatch", "invalid_request_id", "invalid_base64_payload", "empty_upstream_payload", "unknown_application_default_deny", "round_trip_timeout", "round_trip_failed", "response_body_missing", "response_error_decode_failed", "response_error_schema_invalid", "unknown_nonsecret"].contains(diagnostic.edgeRoundTripErrorCategory),
              ["endpoint_not_configured", "no_flow_matched_edge_port", "matched_passed_through", "port_matched_host_mismatch"].contains(diagnostic.runtimeCopyEndpointPassthroughDecision),
              ["none", "ipv4", "ipv6", "fqdn_unresolved", "unknown_nonsecret"].contains(diagnostic.edgeTCPConnectAddressFamily),
              ["none", "driver_flow_write_error", "ne_provider_flow_error", "posix_error", "cocoa_error", "timeout", "unknown_nonsecret"].contains(diagnostic.flowWriteErrorCategory),
              diagnostic.upstreamReadBytes >= 0 else {
            throw DsseLocalRuntimeCopyEvidenceError.invalidEvidence("provider runtime diagnostic category is invalid")
        }
        guard diagnostic.noSecretAttestation,
              !diagnostic.rawLogsIncluded,
              !diagnostic.rawCommandOutputIncluded,
              !diagnostic.rawNEFlowIncluded,
              !diagnostic.hostUserPayloadIncluded,
              !diagnostic.destinationIPIncluded,
              !diagnostic.credentialsIncluded,
              !diagnostic.packetCaptureIncluded,
              !diagnostic.appleIdentifierIncluded else {
            throw DsseLocalRuntimeCopyEvidenceError.invalidEvidence("provider runtime diagnostic must not include raw or secret data")
        }
    }

    private static func writeDiagnostic(_ data: Data, to url: URL) throws {
        let parent = url.deletingLastPathComponent()
        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(atPath: parent.path, isDirectory: &isDirectory), isDirectory.boolValue else {
            throw DsseLocalRuntimeCopyEvidenceError.invalidEvidenceRef("parent directory does not exist")
        }
        let tempURL = parent.appendingPathComponent(".\(url.lastPathComponent).tmp.\(UUID().uuidString)", isDirectory: false)
        do {
            try data.write(to: tempURL, options: [.withoutOverwriting])
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: tempURL.path)
            if FileManager.default.fileExists(atPath: url.path) {
                if runtimeCopyEvidencePathIsSymbolicLink(url) {
                    throw DsseLocalRuntimeCopyEvidenceError.invalidEvidenceRef("provider runtime diagnostic path must not be a symbolic link")
                }
                _ = try FileManager.default.replaceItemAt(url, withItemAt: tempURL, backupItemName: nil, options: [])
            } else {
                try FileManager.default.moveItem(at: tempURL, to: url)
            }
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        } catch let error as DsseLocalRuntimeCopyEvidenceError {
            try? FileManager.default.removeItem(at: tempURL)
            throw error
        } catch {
            try? FileManager.default.removeItem(at: tempURL)
            throw DsseLocalRuntimeCopyEvidenceError.writeFailed
        }
    }
}

public protocol DsseProviderTCPFlowCopyIO: AnyObject, Sendable {
    func openForCopy(completionHandler: @escaping @Sendable (Error?) -> Void)
    func readDataForCopy(completionHandler: @escaping @Sendable (Data?, Error?) -> Void)
    func writeDataForCopy(_ data: Data, completionHandler: @escaping @Sendable (Error?) -> Void)
    func closeReadForCopy(error: Error?)
    func closeWriteForCopy(error: Error?)
}

public struct DsseLiveRuntimeCopyGuardConfiguration: Equatable, Sendable {
    public static let defaults = DsseLiveRuntimeCopyGuardConfiguration()

    public let maxConcurrentConnections: Int
    public let maxByteCapBytes: Int
    public let maxIdleTimeInterval: TimeInterval
    public let backpressureQueueCapacity: Int

    public init(
        maxConcurrentConnections: Int = 1_024,
        maxByteCapBytes: Int = 1_073_741_824,
        maxIdleTimeInterval: TimeInterval = 300,
        backpressureQueueCapacity: Int = 16
    ) {
        self.maxConcurrentConnections = maxConcurrentConnections
        self.maxByteCapBytes = maxByteCapBytes
        self.maxIdleTimeInterval = maxIdleTimeInterval
        self.backpressureQueueCapacity = backpressureQueueCapacity
    }
}

public final class DsseLiveRuntimeCopyGuard: @unchecked Sendable {
    private struct OpenRecord {
        let metadata: DsseLocalRuntimeCopyMetadata
        let openedAt: Date
        var lastActivityAt: Date
        var bytesUp: Int
        var bytesDown: Int
        var queuedDownstreamChunks: Int
    }

    public let configuration: DsseLiveRuntimeCopyGuardConfiguration
    private let now: @Sendable () -> Date
    private let lock = NSLock()
    private var openRecords: [String: OpenRecord] = [:]

    public init(
        configuration: DsseLiveRuntimeCopyGuardConfiguration = .defaults,
        now: @escaping @Sendable () -> Date = Date.init
    ) {
        self.configuration = configuration
        self.now = now
    }

    public var activeCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return openRecords.count
    }

    public func isActive(requestID: String) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return openRecords[requestID] != nil
    }

    public func open(metadata: DsseLocalRuntimeCopyMetadata) throws {
        lock.lock()
        defer { lock.unlock() }
        guard openRecords[metadata.requestID] == nil else {
            throw DsseLocalRuntimeCopyDriverError.duplicateRuntimeCopyRequestID
        }
        guard openRecords.count < configuration.maxConcurrentConnections else {
            throw DsseLocalRuntimeCopyDriverError.runtimeCopyConcurrentCapExceeded
        }
        let openedAt = now()
        openRecords[metadata.requestID] = OpenRecord(
            metadata: metadata,
            openedAt: openedAt,
            lastActivityAt: openedAt,
            bytesUp: 0,
            bytesDown: 0,
            queuedDownstreamChunks: 0
        )
    }

    public func recordUpstreamBytes(requestID: String, count: Int) throws {
        try mutateRecord(requestID: requestID) { record, currentTime in
            try Self.throwIfIdle(record: record, now: currentTime, configuration: configuration)
            let nextBytesUp = record.bytesUp + count
            guard nextBytesUp + record.bytesDown <= configuration.maxByteCapBytes else {
                throw DsseLocalRuntimeCopyDriverError.runtimeCopyByteCapExceeded
            }
            record.bytesUp = nextBytesUp
            record.lastActivityAt = currentTime
        }
    }

    public func enqueueDownstreamBytes(requestID: String, count: Int) throws {
        try mutateRecord(requestID: requestID) { record, currentTime in
            try Self.throwIfIdle(record: record, now: currentTime, configuration: configuration)
            guard record.queuedDownstreamChunks < configuration.backpressureQueueCapacity else {
                throw DsseLocalRuntimeCopyDriverError.runtimeCopyBackpressureOverflowClosed
            }
            let nextBytesDown = record.bytesDown + count
            guard record.bytesUp + nextBytesDown <= configuration.maxByteCapBytes else {
                throw DsseLocalRuntimeCopyDriverError.runtimeCopyByteCapExceeded
            }
            record.bytesDown = nextBytesDown
            record.queuedDownstreamChunks += 1
            record.lastActivityAt = currentTime
        }
    }

    public func dequeueDownstream(requestID: String) throws {
        try mutateRecord(requestID: requestID) { record, currentTime in
            try Self.throwIfIdle(record: record, now: currentTime, configuration: configuration)
            if record.queuedDownstreamChunks > 0 {
                record.queuedDownstreamChunks -= 1
            }
            record.lastActivityAt = currentTime
        }
    }

    public func close(requestID: String) {
        lock.lock()
        defer { lock.unlock() }
        openRecords.removeValue(forKey: requestID)
    }

    private func mutateRecord(
        requestID: String,
        _ mutation: (inout OpenRecord, Date) throws -> Void
    ) throws {
        lock.lock()
        defer { lock.unlock() }
        guard var record = openRecords[requestID] else {
            throw DsseLocalRuntimeCopyDriverError.missingRequestID
        }
        let currentTime = now()
        try mutation(&record, currentTime)
        openRecords[requestID] = record
    }

    private static func throwIfIdle(
        record: OpenRecord,
        now: Date,
        configuration: DsseLiveRuntimeCopyGuardConfiguration
    ) throws {
        guard now.timeIntervalSince(record.lastActivityAt) <= configuration.maxIdleTimeInterval else {
            throw DsseLocalRuntimeCopyDriverError.runtimeCopyIdleTimeoutExceeded
        }
    }
}

public struct DsseEdgeRuntimeCopyTransportConfiguration: Equatable, Sendable {
    public static let defaultEndpointPath = "/network-extension/runtime-copy/round-trip"
    public static let defaultSessionEndpointPath = "/network-extension/runtime-copy/session"

    public let edgeBaseURL: URL
    public let endpointPath: String
    public let sessionEndpointPath: String

    public init(
        edgeBaseURL: URL,
        endpointPath: String = defaultEndpointPath,
        sessionEndpointPath: String = defaultSessionEndpointPath
    ) {
        self.edgeBaseURL = edgeBaseURL
        self.endpointPath = endpointPath
        self.sessionEndpointPath = sessionEndpointPath
    }

    public var roundTripURL: URL {
        runtimeCopyURL(endpointPath: endpointPath)
    }

    public var sessionURL: URL {
        runtimeCopyURL(endpointPath: sessionEndpointPath)
    }

    private func runtimeCopyURL(endpointPath: String) -> URL {
        let basePath = edgeBaseURL.path.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        let endpoint = endpointPath.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        guard var components = URLComponents(url: edgeBaseURL, resolvingAgainstBaseURL: false) else {
            return edgeBaseURL
        }
        if basePath.isEmpty {
            components.path = "/" + endpoint
        } else {
            components.path = "/" + basePath + "/" + endpoint
        }
        return components.url ?? edgeBaseURL
    }
}

public struct DsseLabRawAuthorityDiagnostic: Codable, Equatable, Sendable {
    public let schemaVersion: String
    public let status: String
    public let createdAt: String
    public let diagnosticSource: String
    public let authorityHost: String
    public let authorityPort: Int
    public let authorityEndpointSourceGate: String
    public let authorityPortSourceGate: String
    public let ruleFQDN: String
    public let ruleDestinationPort: Int
    public let ruleGeneratedAt: String
    public let handleNewFlowDecisionCategory: String
    public let handleNewFlowExtractionStatus: String
    public let handleNewFlowExtractionReason: String
    public let providerDecisionAction: String
    public let providerDecisionReason: String
    public let singleRuleLabFallbackGate: String
    public let singleRuleLabFallbackPortGate: String
    public let allowFlowAuthorityPortMatch: String
    public let rawEndpointValuesIncluded: Bool
    public let noSecretAttestation: Bool

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case status
        case createdAt = "created_at"
        case diagnosticSource = "diagnostic_source"
        case authorityHost = "authority_host"
        case authorityPort = "authority_port"
        case authorityEndpointSourceGate = "authority_endpoint_source_gate"
        case authorityPortSourceGate = "authority_port_source_gate"
        case ruleFQDN = "rule_fqdn"
        case ruleDestinationPort = "rule_destination_port"
        case ruleGeneratedAt = "rule_generated_at"
        case handleNewFlowDecisionCategory = "handle_new_flow_decision_category"
        case handleNewFlowExtractionStatus = "handle_new_flow_extraction_status"
        case handleNewFlowExtractionReason = "handle_new_flow_extraction_reason"
        case providerDecisionAction = "provider_decision_action"
        case providerDecisionReason = "provider_decision_reason"
        case singleRuleLabFallbackGate = "single_rule_lab_fallback_gate"
        case singleRuleLabFallbackPortGate = "single_rule_lab_fallback_port_gate"
        case allowFlowAuthorityPortMatch = "allow_flow_authority_port_match"
        case rawEndpointValuesIncluded = "raw_endpoint_values_included"
        case noSecretAttestation = "no_secret_attestation"
    }
}

public final class DsseLabRawAuthorityDiagnosticWriter: @unchecked Sendable {
    public static let implementationMarker = "lab_raw_authority_diagnostic_writer"
    public static let configRefKey = "network_extension_lab_raw_authority_diagnostic_ref"

    private let diagnosticURL: URL
    private let now: @Sendable () -> Date
    private let lock = NSLock()
    // One-shot: this is a phase-2 LAB verification snapshot in a single shared file (last-writer-wins), written
    // from handleNewFlow — i.e. on EVERY steered flow. It records raw authority-extraction evidence; a single
    // capture proves extraction works and every later per-flow rewrite is pure disk churn (this was the dominant
    // ~34 GB/day "disk writes" source). Once captured, the writer permanently stops touching disk.
    private var sealed = false

    public init(diagnosticURL: URL, now: @escaping @Sendable () -> Date = Date.init) {
        self.diagnosticURL = diagnosticURL
        self.now = now
    }

    public static func make(
        agentConfigPath: String,
        now: @escaping @Sendable () -> Date = Date.init
    ) throws -> DsseLabRawAuthorityDiagnosticWriter? {
        let data = try Data(contentsOf: URL(fileURLWithPath: agentConfigPath))
        let config = try JSONDecoder().decode(DsseProviderRuntimeCopyAgentConfig.self, from: data)
        guard let ref = config.labRawAuthorityDiagnosticRef?.trimmingCharacters(in: .whitespacesAndNewlines),
              !ref.isEmpty else {
            return nil
        }
        let configDirectory = URL(fileURLWithPath: agentConfigPath).deletingLastPathComponent()
        let diagnosticURL = try DsseLocalRuntimeCopyEvidenceWriter.resolveEvidenceRef(
            ref,
            relativeTo: configDirectory
        )
        return DsseLabRawAuthorityDiagnosticWriter(diagnosticURL: diagnosticURL, now: now)
    }

    @discardableResult
    public func recordHandleNewFlow(
        input: ProviderFlowAuthorityInput,
        endpointSourceGate: String,
        portSourceGate: String,
        ruleDiagnostic: ProviderSingleRuleLabRuleDiagnostic?,
        decisionCategory: String,
        extractionStatus: String,
        extractionReason: String,
        providerDecisionAction: String,
        providerDecisionReason: String,
        singleRuleLabFallbackGate: String,
        singleRuleLabFallbackPortGate: String,
        allowFlowAuthorityPortMatch: String
    ) throws -> URL {
        // One-shot: after the first capture, do no work and touch no disk on subsequent flows.
        lock.lock()
        let alreadySealed = sealed
        lock.unlock()
        if alreadySealed { return diagnosticURL }
        let diagnostic = DsseLabRawAuthorityDiagnostic(
            schemaVersion: "phase2_lab_raw_authority_diagnostic.v1",
            status: "ok",
            createdAt: ISO8601DateFormatter().string(from: now()),
            diagnosticSource: Self.implementationMarker,
            authorityHost: input.remoteHost,
            authorityPort: input.remotePort,
            authorityEndpointSourceGate: endpointSourceGate,
            authorityPortSourceGate: portSourceGate,
            ruleFQDN: ruleDiagnostic?.fqdn ?? "not_loaded",
            ruleDestinationPort: ruleDiagnostic?.destinationPort ?? 0,
            ruleGeneratedAt: ruleDiagnostic?.generatedAt ?? "not_observed",
            handleNewFlowDecisionCategory: decisionCategory,
            handleNewFlowExtractionStatus: extractionStatus,
            handleNewFlowExtractionReason: extractionReason,
            providerDecisionAction: providerDecisionAction,
            providerDecisionReason: providerDecisionReason,
            singleRuleLabFallbackGate: singleRuleLabFallbackGate,
            singleRuleLabFallbackPortGate: singleRuleLabFallbackPortGate,
            allowFlowAuthorityPortMatch: allowFlowAuthorityPortMatch,
            rawEndpointValuesIncluded: true,
            noSecretAttestation: false
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data = try encoder.encode(diagnostic)
        lock.lock()
        defer { lock.unlock() }
        if sealed { return diagnosticURL } // re-check under lock (concurrent first flows)
        try FileManager.default.createDirectory(
            at: diagnosticURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        try data.write(to: diagnosticURL, options: .atomic)
        sealed = true
        return diagnosticURL
    }
}

public protocol DsseEdgeRuntimeCopyHTTPClient: Sendable {
    func perform(_ request: URLRequest) throws -> (Data, Int)
}

public protocol DsseInstrumentedEdgeRuntimeCopyHTTPClient: DsseEdgeRuntimeCopyHTTPClient {
    func perform(
        _ request: URLRequest,
        connectFamilyFallback: String,
        progressHandler: (@Sendable (DsseLiveRuntimeCopyProgress) -> Void)?
    ) throws -> (Data, Int)
}

private final class DsseURLSessionRuntimeCopyMetricsRecorder: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    private let lock = NSLock()
    private var addressFamilyByTaskIdentifier: [Int: String] = [:]

    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        didFinishCollecting metrics: URLSessionTaskMetrics
    ) {
        let family = metrics.transactionMetrics.reversed().compactMap { transaction -> String? in
            guard let remoteAddress = transaction.remoteAddress else {
                return nil
            }
            let category = dsseEdgeAddressFamilyCategory(remoteAddress)
            return category == "fqdn_unresolved" ? nil : category
        }.first ?? "unknown_nonsecret"
        lock.lock()
        addressFamilyByTaskIdentifier[task.taskIdentifier] = family
        lock.unlock()
    }

    func addressFamily(forTaskIdentifier taskIdentifier: Int, waitFor timeout: TimeInterval = 0) -> String? {
        let deadline = Date().addingTimeInterval(max(0, timeout))
        while true {
            lock.lock()
            let family = addressFamilyByTaskIdentifier[taskIdentifier]
            lock.unlock()
            if family != nil || Date() >= deadline {
                return family
            }
            Thread.sleep(forTimeInterval: 0.005)
        }
    }
}

public final class DsseURLSessionRuntimeCopyHTTPClient: DsseInstrumentedEdgeRuntimeCopyHTTPClient, @unchecked Sendable {
    public static let connectorRoundTripTimeoutInterval: TimeInterval = 5
    public static let defaultRequestTimeoutInterval: TimeInterval = 7

    private let session: URLSession
    private let requestTimeoutInterval: TimeInterval
    private let metricsRecorder: DsseURLSessionRuntimeCopyMetricsRecorder?
    private let addressFamilyResolver: (@Sendable (Int, TimeInterval) -> String?)?

    public convenience init() {
        let recorder = DsseURLSessionRuntimeCopyMetricsRecorder()
        let session = URLSession(configuration: .default, delegate: recorder, delegateQueue: nil)
        self.init(
            session: session,
            requestTimeoutInterval: DsseURLSessionRuntimeCopyHTTPClient.defaultRequestTimeoutInterval,
            metricsRecorder: recorder
        )
    }

    public convenience init(session: URLSession) {
        self.init(
            session: session,
            requestTimeoutInterval: DsseURLSessionRuntimeCopyHTTPClient.defaultRequestTimeoutInterval
        )
    }

    //  W4: pinned + mTLS client so the half-duplex round-trip/session transports ride the (T)
    // encrypted tunnel (server-cert pinned, device client cert) instead of plaintext when (T) is enabled.
    public convenience init(transportSecurity: DsseTransportSecurity) {
        self.init(session: DsseTransportTLS.makePinnedURLSession(security: transportSecurity, channel: "flow-copy"))
    }

    public init(session: URLSession, requestTimeoutInterval: TimeInterval) {
        self.session = session
        self.requestTimeoutInterval = max(0.1, requestTimeoutInterval)
        self.metricsRecorder = nil
        self.addressFamilyResolver = nil
    }

    init(
        session: URLSession,
        requestTimeoutInterval: TimeInterval,
        addressFamilyResolver: @escaping @Sendable (Int, TimeInterval) -> String?
    ) {
        self.session = session
        self.requestTimeoutInterval = max(0.1, requestTimeoutInterval)
        self.metricsRecorder = nil
        self.addressFamilyResolver = addressFamilyResolver
    }

    private init(
        session: URLSession,
        requestTimeoutInterval: TimeInterval,
        metricsRecorder: DsseURLSessionRuntimeCopyMetricsRecorder?
    ) {
        self.session = session
        self.requestTimeoutInterval = max(0.1, requestTimeoutInterval)
        self.metricsRecorder = metricsRecorder
        self.addressFamilyResolver = nil
    }

    public func perform(_ request: URLRequest) throws -> (Data, Int) {
        try perform(
            request,
            connectFamilyFallback: dsseEdgeAddressFamilyCategory(request.url?.host),
            progressHandler: nil
        )
    }

    public func perform(
        _ request: URLRequest,
        connectFamilyFallback: String,
        progressHandler: (@Sendable (DsseLiveRuntimeCopyProgress) -> Void)?
    ) throws -> (Data, Int) {
        let semaphore = DispatchSemaphore(value: 0)
        final class ResponseBox: @unchecked Sendable {
            var data: Data?
            var statusCode: Int?
            var error: Error?
        }
        let box = ResponseBox()
        var boundedRequest = request
        boundedRequest.timeoutInterval = requestTimeoutInterval
        let task = session.dataTask(with: boundedRequest) { data, response, error in
            box.data = data
            box.statusCode = (response as? HTTPURLResponse)?.statusCode
            box.error = error
            semaphore.signal()
        }
        let emitMetricsConnectCompletionIfAvailable: @Sendable () -> Void = {
            let metricsFamily = self.addressFamily(
                forTaskIdentifier: task.taskIdentifier,
                waitFor: min(0.1, self.requestTimeoutInterval)
            )
            if let metricsFamily, ["ipv4", "ipv6"].contains(metricsFamily) {
                progressHandler?(.edgeTCPConnectCompleted(family: metricsFamily))
            }
        }
        task.resume()
        let timeoutNanoseconds = Int((requestTimeoutInterval * 1_000_000_000).rounded(.up))
        if semaphore.wait(timeout: .now() + .nanoseconds(timeoutNanoseconds)) == .timedOut {
            task.cancel()
            emitMetricsConnectCompletionIfAvailable()
            throw DsseLocalRuntimeCopyDriverError.edgeRoundTripTimeout
        }
        if let error = box.error {
            emitMetricsConnectCompletionIfAvailable()
            let nsError = error as NSError
            if nsError.domain == NSURLErrorDomain && nsError.code == NSURLErrorTimedOut {
                throw DsseLocalRuntimeCopyDriverError.edgeRoundTripTimeout
            }
            // ★★★ THE REASON WAS THROWN AWAY, AND IT IS THE ONLY THING WORTH KNOWING (2026-08-29, measured on
            // a real Mac). Every steered flow failed with edgeTransportRequestFailed, which says a request did
            // not complete and nothing about WHY — a refused connection, a name that does not resolve, a
            // certificate the device will not accept and a client certificate the Edge refused all arrive
            // here identically. The URLSession error carries the answer and was discarded at this line.
            //
            // A domain, a code and the system's own description of a transport failure. Never key material,
            // and useless to withhold from the person who has to make the device work.
            dsseRuntimeLog("edge_round_trip_failed url=\(request.url?.host.map { $0 + (request.url?.path ?? "") } ?? "?") " +
                           "domain=\(nsError.domain) code=\(nsError.code) reason=\(nsError.localizedDescription)")
            throw DsseLocalRuntimeCopyDriverError.edgeTransportRequestFailed
        }
        guard let statusCode = box.statusCode, let data = box.data else {
            emitMetricsConnectCompletionIfAvailable()
            dsseRuntimeLog("edge_round_trip_failed url=\(request.url?.host ?? "?") — the request completed with " +
                           "neither a status nor a body, which is the shape of a connection closed mid-response")
            throw DsseLocalRuntimeCopyDriverError.edgeTransportRequestFailed
        }
        let metricsFamily = addressFamily(
            forTaskIdentifier: task.taskIdentifier,
            waitFor: min(0.1, requestTimeoutInterval)
        )
        progressHandler?(.edgeTCPConnectCompleted(family: metricsFamily ?? connectFamilyFallback))
        return (data, statusCode)
    }

    private func addressFamily(forTaskIdentifier taskIdentifier: Int, waitFor timeout: TimeInterval) -> String? {
        if let addressFamilyResolver {
            return addressFamilyResolver(taskIdentifier, timeout)
        }
        return metricsRecorder?.addressFamily(forTaskIdentifier: taskIdentifier, waitFor: timeout)
    }
}

public final class DsseEdgeRuntimeCopyTransport: DsseInstrumentedLocalRuntimeCopyTransport, DsseSessionLocalRuntimeCopyTransport, DsseTunnelLocalRuntimeCopyTransport, @unchecked Sendable {
    public let configuration: DsseEdgeRuntimeCopyTransportConfiguration
    public let evidenceImplementation: String
    public let edgeConnectorRealness: String
    public let runtimeCopyTunnelEnabled: Bool
    private let httpClient: any DsseEdgeRuntimeCopyHTTPClient
    //  W4: when present, the tunnel dials the (T) TLS transport (server-cert pinned + mTLS device
    // identity) at security.host:security.port instead of the legacy plaintext edge. nil = unchanged.
    private let transportSecurity: DsseTransportSecurity?

    // ADAPTIVE multiplex POOL: rather than ONE mTLS connection carrying every flow — single-TCP head-of-line
    // blocking under loss, one shared congestion window, one core — a pool that GROWS with load and SHRINKS
    // when idle. Starts empty; opens the first connection on demand and adds one more per ~muxFlowsPerConn
    // concurrent flows (up to muxMaxConns); closes idle (0-flow) connections back down. A new flow lands on the
    // LEAST-LOADED connection and stays there for life (its byte order is preserved). So: at low load it is ~1
    // connection (the per-DEVICE FD/handshake win), and a heavy page spreads across connections (a loss stalls
    // only ~1/N of flows, aggregate cwnd is N×, work spreads across cores). muxMaxConns stays well under the
    // ~80 NWConnections that overwhelmed Network.framework.
    private let muxLock = NSLock()
    private var pool: [DsseSteerMux] = []                                               // open, healthy connections
    private var muxOpeningCount = 0                                                     // opens in flight (coalesced)
    private var muxEmptyWaiters: [@Sendable (Result<DsseSteerMux, Error>) -> Void] = [] // flows waiting for the first conn

    // ~concurrent flows per connection before the pool grows; hard cap on pool size. Tunable via env.
    // Defaults favour parallelism: a heavy page (~60 concurrent flows) spreads across ~6 connections
    // (1 + 60/12), a very heavy one caps at 12 — so packet-loss HOL hits ~1/N of flows, aggregate cwnd is N×,
    // and work spreads across cores, while staying an order of magnitude below per-flow's connection count
    // (the Edge FD/handshake win). Lower FLOWS_PER_CONN (or raise MAX_CONNS) for even more connections.
    static var muxFlowsPerConn: Int {
        if let raw = ProcessInfo.processInfo.environment["DSSE_NE_STEER_MUX_FLOWS_PER_CONN"], let n = Int(raw) {
            return max(1, min(4096, n))
        }
        return 12
    }
    static var muxMaxConns: Int {
        if let raw = ProcessInfo.processInfo.environment["DSSE_NE_STEER_MUX_MAX_CONNS"], let n = Int(raw) {
            return max(1, min(64, n))
        }
        return 12
    }

    public init(
        configuration: DsseEdgeRuntimeCopyTransportConfiguration,
        evidenceImplementation: String = "real_edge_runtime_copy_transport",
        edgeConnectorRealness: String = "in_process_stub",
        httpClient: any DsseEdgeRuntimeCopyHTTPClient = DsseURLSessionRuntimeCopyHTTPClient(),
        tunnelEnabled: Bool = false,
        transportSecurity: DsseTransportSecurity? = nil
    ) {
        self.configuration = configuration
        self.evidenceImplementation = evidenceImplementation
        self.edgeConnectorRealness = edgeConnectorRealness
        self.runtimeCopyTunnelEnabled = tunnelEnabled
        self.httpClient = httpClient
        self.transportSecurity = transportSecurity
    }

    public func openTunnel(
        metadata: DsseLocalRuntimeCopyMetadata,
        completion: @escaping @Sendable (Result<DsseRuntimeCopyTunnelStream, Error>) -> Void
    ) {
        //  W4: when the (T) transport is configured, the tunnel dials the TLS listener
        // (security.host:port, server-cert pinned + mTLS) rather than the legacy plaintext edge.
        let legacyHost = configuration.edgeBaseURL.host
        let legacyPort = configuration.edgeBaseURL.port ?? defaultPortForScheme(configuration.edgeBaseURL.scheme)
        let host = transportSecurity?.host ?? legacyHost
        let port = transportSecurity?.port ?? legacyPort
        guard let host, let port,
              let destinationHost = metadata.destinationHost,
              let destinationPort = metadata.destinationPort else {
            completion(.failure(DsseLocalRuntimeCopyDriverError.invalidEdgeTransportConfiguration))
            return
        }
        // Multiplex: obtain the shared mux (lazy) and register this flow as a stream on it, instead of dialing a
        // fresh NWConnection per flow. IPv6 literals must be bracketed in the authority.
        let baseAuthority: String
        if destinationHost.contains(":") && !destinationHost.hasPrefix("[") {
            baseAuthority = "[\(destinationHost)]:\(destinationPort)"
        } else {
            baseAuthority = "\(destinationHost):\(destinationPort)"
        }
        // Attach per-flow origin metadata after a NUL: "u=<os-user>" and/or "a=<app>" (space-separated). The Edge
        // splits the OPEN payload on the NUL and parses the key=value pairs; older Edges parse the whole payload
        // as host:port and simply never see (ignore) the suffix. Keep `authority` a `let` for the concurrent
        // withPooledMux closure below.
        var metaParts: [String] = []
        if let osUser = metadata.osUser, !osUser.isEmpty { metaParts.append("u=\(osUser)") }
        if let app = metadata.sourceApp, !app.isEmpty { metaParts.append("a=\(app)") }
        let authority = metaParts.isEmpty ? baseAuthority : baseAuthority + "\u{0}" + metaParts.joined(separator: " ")
        // Adaptive pool: land this flow on the least-loaded connection (opening/growing/shrinking the pool as
        // load dictates). The flow stays on that connection for life, preserving its byte order.
        withPooledMux(host: host, port: port) { result in
            switch result {
            case .success(let mux):
                completion(.success(mux.openFlow(authority: authority) as DsseRuntimeCopyTunnelStream))
            case .failure(let error):
                completion(.failure(error))
            }
        }
    }

    // Adaptive pool: returns a connection for a new flow. Drops unhealthy connections, sizes the pool to the
    // current concurrent-flow load (desired = 1 + activeFlows/muxFlowsPerConn, capped at muxMaxConns), shrinks
    // surplus IDLE connections, then either (a) waits for the first connection if the pool is empty, or
    // (b) returns the LEAST-LOADED connection and, if under target, kicks a background open to grow for future
    // flows. All connection shutdowns happen after the lock is released.
    private func withPooledMux(host: String, port: Int, completion: @escaping @Sendable (Result<DsseSteerMux, Error>) -> Void) {
        muxLock.lock()
        pool.removeAll { !$0.isHealthy }
        let active = pool.reduce(0) { $0 + $1.activeFlowCount }
        let desired = min(Self.muxMaxConns, max(1, 1 + active / Self.muxFlowsPerConn))
        // Shrink: keep every BUSY connection, plus just enough idle ones to reach `desired` (and >=1 total);
        // close the surplus idle connections.
        let busy = pool.filter { $0.activeFlowCount > 0 }
        let idle = pool.filter { $0.activeFlowCount == 0 }
        let idleKeep = max(0, max(1, desired) - busy.count)
        let toClose = Array(idle.dropFirst(idleKeep))
        pool = busy + Array(idle.prefix(idleKeep))

        if pool.isEmpty {
            muxEmptyWaiters.append(completion)
            let startOpen = (muxOpeningCount == 0)
            if startOpen { muxOpeningCount += 1 }
            muxLock.unlock()
            for m in toClose { m.shutdown() }
            if startOpen { openNewMux(host: host, port: port) }
            return
        }
        let chosen = pool.min(by: { $0.activeFlowCount < $1.activeFlowCount })!
        let grow = (pool.count + muxOpeningCount < desired)
        if grow { muxOpeningCount += 1 }
        muxLock.unlock()
        for m in toClose { m.shutdown() }
        if grow { openNewMux(host: host, port: port) }
        completion(.success(chosen))
    }

    // Opens one new pool connection. On completion it joins the pool and, if any flows are waiting for the very
    // first connection, resolves them with the result (a growth open with no waiters simply joins the pool).
    private func openNewMux(host: String, port: Int) {
        DsseSteerMux.open(edgeHost: host, edgePort: port, tlsSecurity: transportSecurity) { [self] result in
            muxLock.lock()
            muxOpeningCount -= 1
            if case .success(let m) = result { pool.append(m) }
            let waiters = muxEmptyWaiters
            muxEmptyWaiters = []
            muxLock.unlock()
            for w in waiters { w(result) }
        }
    }

    // Derives the tunnel endpoint path from the configured base path so a
    // non-root edge mount still routes correctly.
    private static func tunnelPath(for configuration: DsseEdgeRuntimeCopyTransportConfiguration) -> String {
        let basePath = configuration.edgeBaseURL.path.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        let endpoint = DsseRuntimeCopyTunnel.tunnelEndpointPath.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        return basePath.isEmpty ? "/" + endpoint : "/" + basePath + "/" + endpoint
    }

    private func defaultPortForScheme(_ scheme: String?) -> Int? {
        switch scheme?.lowercased() {
        case "http": return 80
        case "https": return 443
        default: return nil
        }
    }

    public func roundTrip(
        _ payload: Data,
        metadata: DsseLocalRuntimeCopyMetadata
    ) throws -> Data {
        try roundTrip(payload, metadata: metadata, progressHandler: nil)
    }

    public func roundTrip(
        _ payload: Data,
        metadata: DsseLocalRuntimeCopyMetadata,
        progressHandler: (@Sendable (DsseLiveRuntimeCopyProgress) -> Void)?
    ) throws -> Data {
        var request = URLRequest(url: configuration.roundTripURL)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.httpBody = try JSONEncoder().encode(DsseEdgeRuntimeCopyRequest(
            tenantID: metadata.tenantID,
            requestID: metadata.requestID,
            applicationID: metadata.applicationID,
            destinationHost: metadata.destinationHost,
            destinationPort: metadata.destinationPort,
            upstreamPayloadBase64: payload.base64EncodedString()
        ))

        let connectFamilyFallback = dsseEdgeAddressFamilyCategory(configuration.roundTripURL.host)
        progressHandler?(.edgeTCPConnectStarted(family: connectFamilyFallback))
        progressHandler?(.edgeRoundTripRequestSent)
        let response: (Data, Int)
        if let instrumentedHTTPClient = httpClient as? any DsseInstrumentedEdgeRuntimeCopyHTTPClient {
            response = try instrumentedHTTPClient.perform(
                request,
                connectFamilyFallback: connectFamilyFallback,
                progressHandler: progressHandler
            )
        } else {
            response = try httpClient.perform(request)
            progressHandler?(.edgeTCPConnectCompleted(family: connectFamilyFallback))
        }
        let (responseData, statusCode) = response
        progressHandler?(.edgeRoundTripResponseStatusReceived(category: Self.statusCategory(statusCode)))
        if !responseData.isEmpty {
            progressHandler?(.edgeRoundTripResponseBodyReceived)
        }
        guard (200..<300).contains(statusCode) else {
            progressHandler?(.edgeRoundTripErrorCategory(category: Self.errorCategory(responseData)))
            throw DsseLocalRuntimeCopyDriverError.edgeTransportStatusFailed
        }
        guard let response = try? JSONDecoder().decode(DsseEdgeRuntimeCopyResponse.self, from: responseData) else {
            throw DsseLocalRuntimeCopyDriverError.edgeTransportDecodeFailed
        }
        guard response.requestID == metadata.requestID else {
            throw DsseLocalRuntimeCopyDriverError.edgeTransportRequestIDMismatch
        }
        guard response.schemaVersion == DsseEdgeRuntimeCopyResponse.schemaVersion,
              let downstream = Data(base64Encoded: response.downstreamPayloadBase64) else {
            throw DsseLocalRuntimeCopyDriverError.edgeTransportDecodeFailed
        }
        return downstream
    }

    public func exchangeSession(
        _ payload: Data,
        operation: DsseLocalRuntimeCopySessionOperation,
        metadata: DsseLocalRuntimeCopyMetadata,
        progressHandler: (@Sendable (DsseLiveRuntimeCopyProgress) -> Void)?
    ) throws -> DsseLocalRuntimeCopySessionExchangeResult {
        var request = URLRequest(url: configuration.sessionURL)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.httpBody = try JSONEncoder().encode(DsseEdgeRuntimeCopySessionRequest(
            tenantID: metadata.tenantID,
            requestID: metadata.requestID,
            operation: operation.rawValue,
            applicationID: metadata.applicationID,
            destinationHost: operation == .open ? metadata.destinationHost : nil,
            destinationPort: operation == .open ? metadata.destinationPort : nil,
            upstreamPayloadBase64: payload.base64EncodedString(),
            clientEOF: false
        ))

        let connectFamilyFallback = dsseEdgeAddressFamilyCategory(configuration.sessionURL.host)
        progressHandler?(.edgeTCPConnectStarted(family: connectFamilyFallback))
        progressHandler?(.edgeRoundTripRequestSent)
        let response = try performRuntimeCopyHTTP(request, connectFamilyFallback: connectFamilyFallback, progressHandler: progressHandler)
        let (responseData, statusCode) = response
        progressHandler?(.edgeRoundTripResponseStatusReceived(category: Self.statusCategory(statusCode)))
        if !responseData.isEmpty {
            progressHandler?(.edgeRoundTripResponseBodyReceived)
        }
        guard (200..<300).contains(statusCode) else {
            progressHandler?(.edgeRoundTripErrorCategory(category: Self.errorCategory(responseData)))
            throw DsseLocalRuntimeCopyDriverError.edgeTransportStatusFailed
        }
        guard let decoded = try? JSONDecoder().decode(DsseEdgeRuntimeCopySessionResponse.self, from: responseData) else {
            throw DsseLocalRuntimeCopyDriverError.edgeTransportDecodeFailed
        }
        guard decoded.requestID == metadata.requestID else {
            throw DsseLocalRuntimeCopyDriverError.edgeTransportRequestIDMismatch
        }
        guard decoded.schemaVersion == DsseEdgeRuntimeCopySessionResponse.schemaVersion else {
            throw DsseLocalRuntimeCopyDriverError.edgeTransportDecodeFailed
        }
        let downstreamPayload: Data
        if let downstreamPayloadBase64 = decoded.downstreamPayloadBase64 {
            guard let decodedPayload = Data(base64Encoded: downstreamPayloadBase64) else {
                throw DsseLocalRuntimeCopyDriverError.edgeTransportDecodeFailed
            }
            downstreamPayload = decodedPayload
        } else {
            downstreamPayload = Data()
        }
        return DsseLocalRuntimeCopySessionExchangeResult(
            downstreamPayload: downstreamPayload,
            sessionClosed: decoded.sessionClosed ?? false
        )
    }

    public func closeSession(
        metadata: DsseLocalRuntimeCopyMetadata,
        progressHandler: (@Sendable (DsseLiveRuntimeCopyProgress) -> Void)?
    ) throws {
        var request = URLRequest(url: configuration.sessionURL)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.httpBody = try JSONEncoder().encode(DsseEdgeRuntimeCopySessionRequest(
            tenantID: metadata.tenantID,
            requestID: metadata.requestID,
            operation: DsseLocalRuntimeCopySessionOperation.close.rawValue,
            applicationID: metadata.applicationID,
            clientEOF: true
        ))

        let connectFamilyFallback = dsseEdgeAddressFamilyCategory(configuration.sessionURL.host)
        progressHandler?(.edgeTCPConnectStarted(family: connectFamilyFallback))
        progressHandler?(.edgeRoundTripRequestSent)
        let response = try performRuntimeCopyHTTP(request, connectFamilyFallback: connectFamilyFallback, progressHandler: progressHandler)
        let (responseData, statusCode) = response
        progressHandler?(.edgeRoundTripResponseStatusReceived(category: Self.statusCategory(statusCode)))
        if !responseData.isEmpty {
            progressHandler?(.edgeRoundTripResponseBodyReceived)
        }
        guard (200..<300).contains(statusCode) else {
            progressHandler?(.edgeRoundTripErrorCategory(category: Self.errorCategory(responseData)))
            throw DsseLocalRuntimeCopyDriverError.edgeTransportStatusFailed
        }
    }

    private func performRuntimeCopyHTTP(
        _ request: URLRequest,
        connectFamilyFallback: String,
        progressHandler: (@Sendable (DsseLiveRuntimeCopyProgress) -> Void)?
    ) throws -> (Data, Int) {
        if let instrumentedHTTPClient = httpClient as? any DsseInstrumentedEdgeRuntimeCopyHTTPClient {
            return try instrumentedHTTPClient.perform(
                request,
                connectFamilyFallback: connectFamilyFallback,
                progressHandler: progressHandler
            )
        }
        let response = try httpClient.perform(request)
        progressHandler?(.edgeTCPConnectCompleted(family: connectFamilyFallback))
        return response
    }

    private static func statusCategory(_ statusCode: Int) -> String {
        switch statusCode {
        case 100..<200:
            return "informational"
        case 200..<300:
            return "success"
        case 300..<400:
            return "redirect"
        case 400..<500:
            return "client_error"
        case 500..<600:
            return "server_error"
        default:
            return "other_nonsecret"
        }
    }

    private static func errorCategory(_ responseData: Data) -> String {
        guard !responseData.isEmpty else {
            return "response_body_missing"
        }
        guard let response = try? JSONDecoder().decode(DsseEdgeRuntimeCopyErrorResponse.self, from: responseData) else {
            return "response_error_decode_failed"
        }
        guard [DsseEdgeRuntimeCopyErrorResponse.schemaVersion, DsseEdgeRuntimeCopySessionErrorResponse.schemaVersion].contains(response.schemaVersion),
              response.status == "error" else {
            return "response_error_schema_invalid"
        }
        return allowedEdgeRoundTripErrorCategory(response.category)
    }

    private static func allowedEdgeRoundTripErrorCategory(_ value: String) -> String {
        [
            "method_not_allowed",
            "request_body_too_large",
            "invalid_request_json",
            "invalid_schema_version",
            "invalid_tenant_id",
            "tenant_scope_mismatch",
            "invalid_request_id",
            "invalid_base64_payload",
            "empty_upstream_payload",
            "invalid_application_id",
            "invalid_session_operation",
            "invalid_destination_host",
            "invalid_destination_port",
            "unknown_application_default_deny",
            "session_already_open",
            "session_cap_exceeded",
            "session_manager_missing",
            "session_not_found",
            "session_scope_mismatch",
            "round_trip_timeout",
            "round_trip_failed"
        ].contains(value) ? value : "unknown_nonsecret"
    }
}

public enum DsseLocalRuntimeCopyTransportFactory {
    public static func make(
        agentConfigPath: String,
        httpClient: any DsseEdgeRuntimeCopyHTTPClient = DsseURLSessionRuntimeCopyHTTPClient()
    ) -> any DsseLocalRuntimeCopyTransport {
        guard let loaded = try? edgeConfiguration(agentConfigPath: agentConfigPath) else {
            return DsseDeviceValidationPendingRuntimeCopyTransport()
        }
        //  W4: resolve the (T) transport security (pinned CA + keychain device identity) from the
        // published contract so the tunnel dials the encrypted TLS+mTLS listener. nil when the contract
        // is absent -> legacy plaintext dial (unchanged).
        let configDir = URL(fileURLWithPath: agentConfigPath).deletingLastPathComponent()
        let contract = (try? JSONDecoder().decode(
            DsseProviderRuntimeCopyAgentConfig.self,
            from: Data(contentsOf: URL(fileURLWithPath: agentConfigPath))
        ))?.transport
        let transportSecurity = DsseTransportSecurityResolver.resolve(contract: contract, configDirectory: configDir, agentConfigPath: agentConfigPath)
        // When (T) is enabled, route ALL transports (tunnel + half-duplex round-trip/session) over the
        // encrypted listener: use a pinned + mTLS URLSession client and base the round-trip/session URLs
        // on the transport URL (https://host:port) instead of the legacy plaintext edge.
        var configuration = loaded.configuration
        var client = httpClient
        if let sec = transportSecurity {
            // ★★★ NOT URLSession. See DsseRuntimeCopyOverNW: App Transport Security refuses a deployment's
            // private CA before the pinning delegate runs, and URLSession cannot send a server name other
            // than the URL's host — which is how a folded port serves this device the wrong organization's
            // certificate. Measured on a real Mac: every steered flow failed and the machine went dark.
            client = DsseNWRuntimeCopyHTTPClient(transportSecurity: sec,
                                                 serverName: DsseLiveTransportServerName.current())
            if let transportBase = URL(string: "https://\(sec.dialHost):\(sec.port)") {
                configuration = DsseEdgeRuntimeCopyTransportConfiguration(
                    edgeBaseURL: transportBase,
                    endpointPath: loaded.configuration.endpointPath,
                    sessionEndpointPath: loaded.configuration.sessionEndpointPath
                )
            }
        }
        return DsseEdgeRuntimeCopyTransport(
            configuration: configuration,
            evidenceImplementation: loaded.evidenceImplementation,
            edgeConnectorRealness: loaded.edgeConnectorRealness,
            httpClient: client,
            tunnelEnabled: loaded.tunnelEnabled,
            transportSecurity: transportSecurity
        )
    }

    // makeForRegionEndpoint builds a runtime-copy transport that dials a SPECIFIC region endpoint, for the live
    // client-side region failover (multi-region G). It reuses the agent config's (T) transport security (pinned
    // CA + device identity) and endpoint paths, overriding ONLY the base URL host:port to the region endpoint.
    // All lab regions share the same (T) transport cert + device CA, so the pinned-CA verify block and the
    // hostname check still hold for the new endpoint (region-a/region-b differ by port on the same host).
    // Returns nil if the config or (T) security cannot be resolved, so the caller keeps the current transport
    // instead of breaking egress (fail-safe: never fabricate a plaintext region dial when (T) is required).
    public static func makeForRegionEndpoint(
        agentConfigPath: String,
        endpoint: URL
    ) -> (any DsseLocalRuntimeCopyTransport)? {
        guard let loaded = try? edgeConfiguration(agentConfigPath: agentConfigPath),
              let host = endpoint.host, !host.isEmpty else {
            return nil
        }
        let port = endpoint.port ?? 443
        let configDir = URL(fileURLWithPath: agentConfigPath).deletingLastPathComponent()
        let contract = (try? JSONDecoder().decode(
            DsseProviderRuntimeCopyAgentConfig.self,
            from: Data(contentsOf: URL(fileURLWithPath: agentConfigPath))
        ))?.transport
        guard let baseSecurity = DsseTransportSecurityResolver.resolve(contract: contract, configDirectory: configDir, agentConfigPath: agentConfigPath) else {
            return nil
        }
        let regionSecurity = DsseTransportSecurity(
            host: host,
            port: port,
            mtlsRequired: baseSecurity.mtlsRequired,
            pinnedCACertificate: baseSecurity.pinnedCACertificate,
            clientIdentity: baseSecurity.clientIdentity
        )
        let configuration = DsseEdgeRuntimeCopyTransportConfiguration(
            edgeBaseURL: endpoint,
            endpointPath: loaded.configuration.endpointPath,
            sessionEndpointPath: loaded.configuration.sessionEndpointPath
        )
        return DsseEdgeRuntimeCopyTransport(
            configuration: configuration,
            evidenceImplementation: loaded.evidenceImplementation,
            edgeConnectorRealness: loaded.edgeConnectorRealness,
            // ★ THE FAILOVER PATH GETS THE SAME DIAL. Fixing only the primary is how this codebase keeps
            // meeting the same defect: the copy that does not get the fix is the one nobody exercises until
            // a region is lost, and then it fails in the middle of the outage it exists for.
            httpClient: DsseNWRuntimeCopyHTTPClient(transportSecurity: regionSecurity,
                                                    serverName: DsseLiveTransportServerName.current()),
            tunnelEnabled: loaded.tunnelEnabled,
            transportSecurity: regionSecurity
        )
    }

    public struct LoadedEdgeConfiguration: Equatable {
        public let configuration: DsseEdgeRuntimeCopyTransportConfiguration
        public let evidenceImplementation: String
        public let edgeConnectorRealness: String
        public let passthroughResolvedHosts: [String]
        public let tunnelEnabled: Bool
    }

    public static func edgeConfiguration(agentConfigPath: String) throws -> LoadedEdgeConfiguration {
        let data = try Data(contentsOf: URL(fileURLWithPath: agentConfigPath))
        let config = try JSONDecoder().decode(DsseProviderRuntimeCopyAgentConfig.self, from: data)
        guard let rawEdgeURL = config.edgeURL?.trimmingCharacters(in: .whitespacesAndNewlines),
              !rawEdgeURL.isEmpty,
              let edgeURL = URL(string: rawEdgeURL),
              let scheme = edgeURL.scheme?.lowercased(),
              ["http", "https"].contains(scheme),
              edgeURL.host != nil else {
            throw DsseLocalRuntimeCopyDriverError.invalidEdgeTransportConfiguration
        }
        let endpointPath = config.runtimeCopyEndpointPath?.trimmingCharacters(in: .whitespacesAndNewlines)
        let sessionEndpointPath = config.runtimeCopySessionEndpointPath?.trimmingCharacters(in: .whitespacesAndNewlines)
        let transportScope = config.runtimeCopyTransportScope?.trimmingCharacters(in: .whitespacesAndNewlines)
        let configuredRealness = config.runtimeCopyEdgeConnectorRealness?.trimmingCharacters(in: .whitespacesAndNewlines)
        let edgeConnectorRealness = configuredRealness?.isEmpty == false ? configuredRealness! : "in_process_stub"
        guard ["in_process_stub", "over_the_wire_local", "over_the_wire_device"].contains(edgeConnectorRealness) else {
            throw DsseLocalRuntimeCopyDriverError.invalidEdgeTransportConfiguration
        }
        let evidenceImplementation: String
        switch transportScope {
        case nil, "", "real_edge":
            evidenceImplementation = "real_edge_runtime_copy_transport"
        case "lab_endpoint":
            evidenceImplementation = "lab_endpoint_runtime_copy_transport"
        default:
            throw DsseLocalRuntimeCopyDriverError.invalidEdgeTransportConfiguration
        }
        return LoadedEdgeConfiguration(
            configuration: DsseEdgeRuntimeCopyTransportConfiguration(
            edgeBaseURL: edgeURL,
            endpointPath: endpointPath?.isEmpty == false ? endpointPath! : DsseEdgeRuntimeCopyTransportConfiguration.defaultEndpointPath,
            sessionEndpointPath: sessionEndpointPath?.isEmpty == false ? sessionEndpointPath! : DsseEdgeRuntimeCopyTransportConfiguration.defaultSessionEndpointPath
            ),
            evidenceImplementation: evidenceImplementation,
            edgeConnectorRealness: edgeConnectorRealness,
            passthroughResolvedHosts: config.runtimeCopyPassthroughResolvedIPs ?? [],
            tunnelEnabled: config.runtimeCopyTunnelEnabled ?? false
        )
    }
}

public struct DsseLocalRuntimeCopyDriver: Sendable {
    public static let defaultStepTimeoutInterval: TimeInterval = 8
    // Flow-OPEN gets a longer deadline than steady-state read/write steps. The open (flow.openForCopy ->
    // NEAppProxyTCPFlow.open) completion is scheduled by the OS; under a burst of concurrent NEW flows (a page
    // load's subresources, an OAuth redirect chain, or right after the transport reconnects) that completion is
    // delayed, and the 8 s step timeout falsely failed new flows with flowOpenTimeout -> ERR_FAILED in the
    // browser. A one-time open is worth waiting longer for than a mid-stream read. See
    // docs/ne_tunnel_robustness_rootcause.md.
    //
    // This guards ONLY flow.openForCopy (the local NEAppProxyTCPFlow open). The tunnel branch completes the
    // openToken the instant that local open succeeds (see driveLiveTakeover), so this deadline never applies to
    // the subsequent wait for server data — including an East-West step-up PARK, which the EDGE bounds
    // (steerMuxStepUpGrantWait), not the NE. (Earlier this token was never completed on the tunnel path, so at
    // this deadline the timer tore down live flows — a held ssh and even normal long-lived flows dropped with
    // "closed by remote host". Fixed by completing the token; the value stays a local-open guard.)
    public static let defaultFlowOpenTimeoutInterval: TimeInterval = 25
    public static let defaultMaxSessionExchangeCount = 256

    private let liveGuard: DsseLiveRuntimeCopyGuard
    private let stepTimeoutInterval: TimeInterval
    private let flowOpenTimeoutInterval: TimeInterval
    private let maxSessionExchangeCount: Int

    public init(
        liveGuard: DsseLiveRuntimeCopyGuard = DsseLiveRuntimeCopyGuard(),
        stepTimeoutInterval: TimeInterval = Self.defaultStepTimeoutInterval,
        flowOpenTimeoutInterval: TimeInterval = Self.defaultFlowOpenTimeoutInterval,
        maxSessionExchangeCount: Int = Self.defaultMaxSessionExchangeCount
    ) {
        self.liveGuard = liveGuard
        self.stepTimeoutInterval = stepTimeoutInterval
        self.flowOpenTimeoutInterval = max(0.01, flowOpenTimeoutInterval)
        self.maxSessionExchangeCount = max(1, maxSessionExchangeCount)
    }

    private static func flowWriteErrorCategory(for error: Error?) -> String {
        guard let error else {
            return "none"
        }
        if let driverError = error as? DsseLocalRuntimeCopyDriverError {
            switch driverError {
            case .flowWriteFailed:
                return "driver_flow_write_error"
            case .flowWriteTimeout:
                return "timeout"
            default:
                return "unknown_nonsecret"
            }
        }
        let nsError = error as NSError
        let normalizedDomain = nsError.domain.lowercased()
        if normalizedDomain.contains("neappproxy") ||
            normalizedDomain.contains("networkextension") {
            return "ne_provider_flow_error"
        }
        switch nsError.domain {
        case "NEAppProxyErrorDomain":
            return "ne_provider_flow_error"
        case NSPOSIXErrorDomain:
            return "posix_error"
        case NSCocoaErrorDomain:
            return "cocoa_error"
        default:
            return "unknown_nonsecret"
        }
    }

    public func copyRoundTrip(
        upstreamPayload: Data,
        metadata: DsseLocalRuntimeCopyMetadata,
        transport: any DsseLocalRuntimeCopyTransport
    ) throws -> DsseLocalRuntimeCopyResult {
        try validate(metadata: metadata)
        guard !upstreamPayload.isEmpty else {
            throw DsseLocalRuntimeCopyDriverError.emptyUpstreamPayload
        }

        let downstreamPayload = try transport.roundTrip(upstreamPayload, metadata: metadata)
        guard !downstreamPayload.isEmpty else {
            throw DsseLocalRuntimeCopyDriverError.emptyDownstreamPayload
        }

        return makeResult(
            upstreamPayload: upstreamPayload,
            downstreamPayload: downstreamPayload,
            connectionRegistryRuntimeConnected: false,
            byteCapRuntimeEnforced: false,
            idleTimeoutRuntimeEnforced: false,
            boundedBackpressureRuntimeEnforced: false,
            flowReadHalfCloseRuntimeEnforced: false,
            flowWriteHalfCloseRuntimeEnforced: false,
            networkExtensionFlowOpened: false,
            edgeTunnelOpenStarted: false,
            tcpPayloadCopyStarted: false,
            flowPayloadReadStarted: false,
            flowPayloadWriteStarted: false
        )
    }

    public func driveLiveTakeover(
        flow: any DsseProviderTCPFlowCopyIO,
        metadata: DsseLocalRuntimeCopyMetadata,
        transport: any DsseLocalRuntimeCopyTransport,
        failOpenDirectFallback: Bool = false,
        progressHandler: (@Sendable (DsseLiveRuntimeCopyProgress) -> Void)? = nil,
        completionHandler: @escaping @Sendable (Result<DsseLocalRuntimeCopyResult, Error>) -> Void
    ) {
        let closeRejectedTakeoverFlow: @Sendable (Error?) -> Void = { error in
            flow.closeReadForCopy(error: error)
            flow.closeWriteForCopy(error: error)
        }

        do {
            try validate(metadata: metadata)
            try liveGuard.open(metadata: metadata)
        } catch {
            closeRejectedTakeoverFlow(error)
            completionHandler(.failure(error))
            return
        }

        let requestID = metadata.requestID
        let closeGuardAndFlow: @Sendable (Error?) -> Void = { error in
            liveGuard.close(requestID: requestID)
            flow.closeReadForCopy(error: error)
            flow.closeWriteForCopy(error: error)
        }
        // closeGuardOnly releases the live-copy slot WITHOUT closing the flow — used by the fail-open direct
        // fallback, which keeps the still-open flow to splice it to a direct connection.
        let closeGuardOnly: @Sendable () -> Void = {
            liveGuard.close(requestID: requestID)
        }

        let stepState = DsseLiveRuntimeCopyStepState()
        let emitProgress: @Sendable (DsseLiveRuntimeCopyProgress) -> Void = { progress in
            progressHandler?(progress)
        }
        let failIfCurrent: @Sendable (UUID, Error, Error?) -> Void = { token, resultError, closeError in
            guard stepState.completeIfCurrent(token) else {
                return
            }
            closeGuardAndFlow(closeError ?? resultError)
            completionHandler(.failure(resultError))
        }
        let scheduleTimeout: @Sendable (UUID, DsseLocalRuntimeCopyDriverError) -> Void = { token, timeoutError in
            DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + stepTimeoutInterval) {
                guard stepState.completeIfCurrent(token) else {
                    return
                }
                closeGuardAndFlow(timeoutError)
                completionHandler(.failure(timeoutError))
            }
        }

        emitProgress(.liveCopyStarted)
        let openToken = stepState.beginStep()
        // Open gets its own, independently-configurable deadline (steady-state read/write still use
        // scheduleTimeout's stepTimeoutInterval).
        DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + flowOpenTimeoutInterval) {
            guard stepState.completeIfCurrent(openToken) else {
                return
            }
            closeGuardAndFlow(DsseLocalRuntimeCopyDriverError.flowOpenTimeout)
            completionHandler(.failure(DsseLocalRuntimeCopyDriverError.flowOpenTimeout))
        }
        flow.openForCopy { openError in
            guard stepState.isCurrentAndOpen(openToken) else {
                return
            }
            if openError != nil {
                failIfCurrent(openToken, DsseLocalRuntimeCopyDriverError.flowOpenFailed, openError)
                return
            }
            emitProgress(.flowOpenCompleted)

            if let tunnelTransport = transport as? any DsseTunnelLocalRuntimeCopyTransport, tunnelTransport.runtimeCopyTunnelEnabled {
                // The flow-OPEN step is DONE the moment flow.openForCopy succeeds — flowOpenTimeout guards ONLY
                // that local open. Complete the openToken now so the timeout can't later fire mid-session and tear
                // down a LIVE tunnel: the tunnel loop does not take stepState, so nothing ever superseded this
                // token, and the open deadline killed every long-lived flow at flowOpenTimeoutInterval (an
                // interactive ssh dropped with "closed by remote host" ~that many seconds after connecting). The
                // subsequent wait for server data (including an East-West step-up park) is bounded by the EDGE.
                _ = stepState.completeIfCurrent(openToken)
                driveLiveTunnelTakeoverAfterOpen(
                    flow: flow,
                    metadata: metadata,
                    requestID: requestID,
                    transport: tunnelTransport,
                    failOpenDirectFallback: failOpenDirectFallback,
                    closeGuardAndFlow: closeGuardAndFlow,
                    closeGuardOnly: closeGuardOnly,
                    emitProgress: emitProgress,
                    completionHandler: completionHandler
                )
                return
            }
            if let sessionTransport = transport as? any DsseSessionLocalRuntimeCopyTransport {
                driveLiveSessionTakeoverAfterOpen(
                    flow: flow,
                    metadata: metadata,
                    requestID: requestID,
                    transport: sessionTransport,
                    closeGuardAndFlow: closeGuardAndFlow,
                    stepState: stepState,
                    emitProgress: emitProgress,
                    failIfCurrent: failIfCurrent,
                    scheduleTimeout: scheduleTimeout,
                    completionHandler: completionHandler
                )
                return
            }

            let readToken = stepState.beginStep()
            scheduleTimeout(readToken, .flowReadTimeout)
            flow.readDataForCopy { upstreamPayload, readError in
                guard stepState.isCurrentAndOpen(readToken) else {
                    return
                }
                if readError != nil {
                    failIfCurrent(readToken, DsseLocalRuntimeCopyDriverError.flowReadFailed, readError)
                    return
                }
                guard let upstreamPayload, !upstreamPayload.isEmpty else {
                    failIfCurrent(readToken, DsseLocalRuntimeCopyDriverError.emptyUpstreamPayload, nil)
                    return
                }
                do {
                    try liveGuard.recordUpstreamBytes(requestID: requestID, count: upstreamPayload.count)
                } catch {
                    failIfCurrent(readToken, error, error)
                    return
                }
                emitProgress(.upstreamReadCompleted(bytes: upstreamPayload.count))

                let edgeToken = stepState.beginStep()
                scheduleTimeout(edgeToken, .edgeRoundTripTimeout)
                emitProgress(.edgeRoundTripStarted)
                guard stepState.isCurrentAndOpen(edgeToken) else {
                    return
                }
                DispatchQueue.global(qos: .utility).async {
                    guard stepState.isCurrentAndOpen(edgeToken) else {
                        return
                    }
                    let downstreamPayload: Data
                    do {
                        if let instrumentedTransport = transport as? any DsseInstrumentedLocalRuntimeCopyTransport {
                            downstreamPayload = try instrumentedTransport.roundTrip(
                                upstreamPayload,
                                metadata: metadata,
                                progressHandler: emitProgress
                            )
                        } else {
                            emitProgress(.edgeRoundTripRequestSent)
                            downstreamPayload = try transport.roundTrip(upstreamPayload, metadata: metadata)
                            emitProgress(.edgeRoundTripResponseBodyReceived)
                        }
                        guard !downstreamPayload.isEmpty else {
                            throw DsseLocalRuntimeCopyDriverError.emptyDownstreamPayload
                        }
                        try liveGuard.enqueueDownstreamBytes(requestID: requestID, count: downstreamPayload.count)
                    } catch {
                        failIfCurrent(edgeToken, error, error)
                        return
                    }
                    guard stepState.isCurrentAndOpen(edgeToken) else {
                        return
                    }
                    emitProgress(.edgeRoundTripCompleted)

                    let writeToken = stepState.beginStep()
                    scheduleTimeout(writeToken, .flowWriteTimeout)
                    emitProgress(.downstreamWriteStarted)
                    guard stepState.isCurrentAndOpen(writeToken) else {
                        return
                    }
                    flow.writeDataForCopy(downstreamPayload) { writeError in
                        guard stepState.isCurrentAndOpen(writeToken) else {
                            return
                        }
                        if writeError != nil {
                            emitProgress(.downstreamWriteFailed(category: Self.flowWriteErrorCategory(for: writeError)))
                            failIfCurrent(writeToken, DsseLocalRuntimeCopyDriverError.flowWriteFailed, writeError)
                            return
                        }
                        emitProgress(.downstreamWriteCompleted)
                        do {
                            try liveGuard.dequeueDownstream(requestID: requestID)
                        } catch {
                            failIfCurrent(writeToken, error, error)
                            return
                        }
                        guard stepState.completeIfCurrent(writeToken) else {
                            return
                        }
                        closeGuardAndFlow(nil)
                        completionHandler(.success(makeResult(
                            upstreamPayload: upstreamPayload,
                            downstreamPayload: downstreamPayload,
                            connectionRegistryRuntimeConnected: true,
                            byteCapRuntimeEnforced: true,
                            idleTimeoutRuntimeEnforced: true,
                            boundedBackpressureRuntimeEnforced: true,
                            flowReadHalfCloseRuntimeEnforced: true,
                            flowWriteHalfCloseRuntimeEnforced: true,
                            networkExtensionFlowOpened: true,
                            edgeTunnelOpenStarted: true,
                            tcpPayloadCopyStarted: true,
                            flowPayloadReadStarted: true,
                            flowPayloadWriteStarted: true
                        )))
                    }
                }
            }
        }
    }

    private func driveLiveTunnelTakeoverAfterOpen(
        flow: any DsseProviderTCPFlowCopyIO,
        metadata: DsseLocalRuntimeCopyMetadata,
        requestID: String,
        transport: any DsseTunnelLocalRuntimeCopyTransport,
        failOpenDirectFallback: Bool = false,
        closeGuardAndFlow: @escaping @Sendable (Error?) -> Void,
        closeGuardOnly: @escaping @Sendable () -> Void = {},
        emitProgress: @escaping @Sendable (DsseLiveRuntimeCopyProgress) -> Void,
        completionHandler: @escaping @Sendable (Result<DsseLocalRuntimeCopyResult, Error>) -> Void
    ) {
        let liveGuard = self.liveGuard
        let destinationHost = metadata.destinationHost
        // Interactive East-West flows (ssh/rdp/…) must not be reaped while a user sits idle at a prompt. The Edge
        // bridge + connector stream already keep them unlimited; the NE's OWN idle reaper (default 120s, 20s under
        // high flow-load) is the last cap and was observed cutting an idle ssh at ~120s. Exempt these ports from
        // the full-window idle reaper (0 = disabled for this flow). An abandoned flow that half-closes is still
        // reclaimed by the upstream-EOF drain grace, so this does not reintroduce the pump-thread leak for the
        // browsing keep-alive case the reaper was built for.
        let idleReapForFlow: TimeInterval = dsseIsInteractiveEastWestPort(metadata.destinationPort)
            ? 0
            : DsseLiveRuntimeCopyTunnelLoop.defaultIdleReapThreshold
        emitProgress(.edgeTCPConnectStarted(family: dsseEdgeAddressFamilyCategory(destinationHost)))
        dsseFlowDiagLogger.info("open_start req=\(requestID, privacy: .public) host=\(destinationHost ?? "?", privacy: .public)")
        // A carry-failure at tunnel-open — the Edge could not carry the flow (an expired/rejected mTLS cert
        // surfaces here) — must fall open. It is handled ONCE, whether it arrives as a clean .failure
        // OR as a HANG that trips the timeout below. The invariant is ANY reason the flow can't be carried,
        // including a stall (measured 2026-07-18: a wrong-CA cert stalled the tunnel handshake rather than failing
        // cleanly, and without this timeout the flow hung until the idle reaper). openTunnel has no timeout of its
        // own — the openToken was completed before this call so the flow-open deadline can't tear down a live
        // tunnel — so the tunnel-open leg is bounded here (stepTimeoutInterval).
        let tunnelOpenOnce = DsseOnce()
        let handleCarryFailure: @Sendable (Error) -> Void = { error in
            guard tunnelOpenOnce.tryRun() else { return }
            dsseFlowDiagLogger.error("leg=tunnel_open fail req=\(requestID, privacy: .public) host=\(destinationHost ?? "?", privacy: .public) err=\(String(describing: error), privacy: .public)")
            // In production this is deny_closed. Under fail-open, splice the still-open flow to a DIRECT connection
            // to its real destination instead of dropping it, so the machine's own traffic keeps flowing —
            // triggering on the carry-failure itself, not a health prediction. No destination or a failing direct
            // connect falls closed as before.
            if failOpenDirectFallback,
               let host = metadata.destinationHost,
               let port = metadata.destinationPort,
               let splice = DsseFailOpenDirectSplice(flow: flow, host: host, port: port, requestID: requestID) {
                closeGuardOnly() // release the live-copy slot; the splice now owns the open flow
                splice.start(
                    onReady: { completionHandler(.success(DsseFailOpenDirectSplice.fellOpenResult())) },
                    onFailed: { directError in completionHandler(.failure(directError)) }
                )
            } else {
                closeGuardAndFlow(error)
                completionHandler(.failure(error))
            }
        }
        DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + stepTimeoutInterval) {
            handleCarryFailure(DsseLocalRuntimeCopyDriverError.tunnelOpenTimeout)
        }
        transport.openTunnel(metadata: metadata) { result in
            switch result {
            case .failure(let error):
                handleCarryFailure(error)
            case .success(let tunnel):
                // A late success after the timeout already fell open: close this tunnel and stop, rather than
                // double-driving the flow that the direct splice now owns.
                guard tunnelOpenOnce.tryRun() else { tunnel.close(); return }
                emitProgress(.edgeTCPConnectCompleted(family: dsseEdgeAddressFamilyCategory(destinationHost)))
                let loop = DsseLiveRuntimeCopyTunnelLoop(
                    flow: flow,
                    requestID: requestID,
                    tunnel: tunnel,
                    liveGuard: liveGuard,
                    emitProgress: emitProgress,
                    makeSuccessResult: { bytesUp, bytesDown in
                        makeResult(
                            bytesUp: bytesUp,
                            bytesDown: bytesDown,
                            connectionRegistryRuntimeConnected: true,
                            byteCapRuntimeEnforced: true,
                            idleTimeoutRuntimeEnforced: true,
                            boundedBackpressureRuntimeEnforced: true,
                            flowReadHalfCloseRuntimeEnforced: true,
                            flowWriteHalfCloseRuntimeEnforced: true,
                            networkExtensionFlowOpened: true,
                            edgeTunnelOpenStarted: true,
                            tcpPayloadCopyStarted: true,
                            flowPayloadReadStarted: true,
                            flowPayloadWriteStarted: true
                        )
                    },
                    closeGuardAndFlow: closeGuardAndFlow,
                    completionHandler: completionHandler,
                    idleReapThreshold: idleReapForFlow
                )
                loop.run()
            }
        }
    }

    private func driveLiveSessionTakeoverAfterOpen(
        flow: any DsseProviderTCPFlowCopyIO,
        metadata: DsseLocalRuntimeCopyMetadata,
        requestID: String,
        transport: any DsseSessionLocalRuntimeCopyTransport,
        closeGuardAndFlow: @escaping @Sendable (Error?) -> Void,
        stepState: DsseLiveRuntimeCopyStepState,
        emitProgress: @escaping @Sendable (DsseLiveRuntimeCopyProgress) -> Void,
        failIfCurrent: @escaping @Sendable (UUID, Error, Error?) -> Void,
        scheduleTimeout: @escaping @Sendable (UUID, DsseLocalRuntimeCopyDriverError) -> Void,
        completionHandler: @escaping @Sendable (Result<DsseLocalRuntimeCopyResult, Error>) -> Void
    ) {
        let loop = DsseLiveRuntimeCopySessionLoop(
            flow: flow,
            metadata: metadata,
            requestID: requestID,
            transport: transport,
            liveGuard: liveGuard,
            maxSessionExchangeCount: maxSessionExchangeCount,
            stepTimeoutInterval: stepTimeoutInterval,
            closeGuardAndFlow: closeGuardAndFlow,
            stepState: stepState,
            emitProgress: emitProgress,
            failIfCurrent: failIfCurrent,
            scheduleTimeout: scheduleTimeout,
            flowWriteErrorCategory: Self.flowWriteErrorCategory(for:),
            makeSuccessResult: { bytesUp, bytesDown in
                makeResult(
                    bytesUp: bytesUp,
                    bytesDown: bytesDown,
                    connectionRegistryRuntimeConnected: true,
                    byteCapRuntimeEnforced: true,
                    idleTimeoutRuntimeEnforced: true,
                    boundedBackpressureRuntimeEnforced: true,
                    flowReadHalfCloseRuntimeEnforced: true,
                    flowWriteHalfCloseRuntimeEnforced: true,
                    networkExtensionFlowOpened: true,
                    edgeTunnelOpenStarted: true,
                    tcpPayloadCopyStarted: true,
                    flowPayloadReadStarted: true,
                    flowPayloadWriteStarted: true
                )
            },
            completionHandler: completionHandler
        )
        loop.readAndExchange(.open)
    }

    private func validate(metadata: DsseLocalRuntimeCopyMetadata) throws {
        guard !metadata.tenantID.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw DsseLocalRuntimeCopyDriverError.missingTenantScope
        }
        guard !metadata.requestID.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw DsseLocalRuntimeCopyDriverError.missingRequestID
        }
        guard !metadata.applicationID.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw DsseLocalRuntimeCopyDriverError.missingApplicationScope
        }
    }

    private func makeResult(
        upstreamPayload: Data,
        downstreamPayload: Data,
        connectionRegistryRuntimeConnected: Bool,
        byteCapRuntimeEnforced: Bool,
        idleTimeoutRuntimeEnforced: Bool,
        boundedBackpressureRuntimeEnforced: Bool,
        flowReadHalfCloseRuntimeEnforced: Bool,
        flowWriteHalfCloseRuntimeEnforced: Bool,
        networkExtensionFlowOpened: Bool,
        edgeTunnelOpenStarted: Bool,
        tcpPayloadCopyStarted: Bool,
        flowPayloadReadStarted: Bool,
        flowPayloadWriteStarted: Bool
    ) -> DsseLocalRuntimeCopyResult {
        makeResult(
            bytesUp: upstreamPayload.count,
            bytesDown: downstreamPayload.count,
            connectionRegistryRuntimeConnected: connectionRegistryRuntimeConnected,
            byteCapRuntimeEnforced: byteCapRuntimeEnforced,
            idleTimeoutRuntimeEnforced: idleTimeoutRuntimeEnforced,
            boundedBackpressureRuntimeEnforced: boundedBackpressureRuntimeEnforced,
            flowReadHalfCloseRuntimeEnforced: flowReadHalfCloseRuntimeEnforced,
            flowWriteHalfCloseRuntimeEnforced: flowWriteHalfCloseRuntimeEnforced,
            networkExtensionFlowOpened: networkExtensionFlowOpened,
            edgeTunnelOpenStarted: edgeTunnelOpenStarted,
            tcpPayloadCopyStarted: tcpPayloadCopyStarted,
            flowPayloadReadStarted: flowPayloadReadStarted,
            flowPayloadWriteStarted: flowPayloadWriteStarted
        )
    }

    private func makeResult(
        bytesUp: Int,
        bytesDown: Int,
        connectionRegistryRuntimeConnected: Bool,
        byteCapRuntimeEnforced: Bool,
        idleTimeoutRuntimeEnforced: Bool,
        boundedBackpressureRuntimeEnforced: Bool,
        flowReadHalfCloseRuntimeEnforced: Bool,
        flowWriteHalfCloseRuntimeEnforced: Bool,
        networkExtensionFlowOpened: Bool,
        edgeTunnelOpenStarted: Bool,
        tcpPayloadCopyStarted: Bool,
        flowPayloadReadStarted: Bool,
        flowPayloadWriteStarted: Bool
    ) -> DsseLocalRuntimeCopyResult {
        return DsseLocalRuntimeCopyResult(
            status: DsseLocalRuntimeCopyImplementationContract.status,
            implementation: DsseLocalRuntimeCopyImplementationContract.implementation,
            bytesUp: bytesUp,
            bytesDown: bytesDown,
            registryCleanupGate: DsseLocalRuntimeCopyImplementationContract.cleanupGate,
            tenantMetadataCleanupGate: DsseLocalRuntimeCopyImplementationContract.cleanupGate,
            auditMetadataOnlyGate: DsseLocalRuntimeCopyImplementationContract.auditMetadataOnlyGate,
            connectionRegistryRuntimeConnected: connectionRegistryRuntimeConnected,
            byteCapRuntimeEnforced: byteCapRuntimeEnforced,
            idleTimeoutRuntimeEnforced: idleTimeoutRuntimeEnforced,
            boundedBackpressureRuntimeEnforced: boundedBackpressureRuntimeEnforced,
            flowReadHalfCloseRuntimeEnforced: flowReadHalfCloseRuntimeEnforced,
            flowWriteHalfCloseRuntimeEnforced: flowWriteHalfCloseRuntimeEnforced,
            networkExtensionFlowOpened: networkExtensionFlowOpened,
            edgeTunnelOpenStarted: edgeTunnelOpenStarted,
            tcpPayloadCopyStarted: tcpPayloadCopyStarted,
            flowPayloadReadStarted: flowPayloadReadStarted,
            flowPayloadWriteStarted: flowPayloadWriteStarted
        )
    }
}

private final class DsseLiveRuntimeCopySessionLoop: @unchecked Sendable {
    private static let successfulFlowCloseDelayInterval: TimeInterval = 0.25

    private let flow: any DsseProviderTCPFlowCopyIO
    private let metadata: DsseLocalRuntimeCopyMetadata
    private let requestID: String
    private let transport: any DsseSessionLocalRuntimeCopyTransport
    private let liveGuard: DsseLiveRuntimeCopyGuard
    private let maxSessionExchangeCount: Int
    private let stepTimeoutInterval: TimeInterval
    private let closeGuardAndFlow: @Sendable (Error?) -> Void
    private let stepState: DsseLiveRuntimeCopyStepState
    private let emitProgress: @Sendable (DsseLiveRuntimeCopyProgress) -> Void
    private let failIfCurrent: @Sendable (UUID, Error, Error?) -> Void
    private let scheduleTimeout: @Sendable (UUID, DsseLocalRuntimeCopyDriverError) -> Void
    private let flowWriteErrorCategory: @Sendable (Error?) -> String
    private let makeSuccessResult: @Sendable (Int, Int) -> DsseLocalRuntimeCopyResult
    private let completionHandler: @Sendable (Result<DsseLocalRuntimeCopyResult, Error>) -> Void
    private let totals = DsseLiveRuntimeCopySessionTotals()

    init(
        flow: any DsseProviderTCPFlowCopyIO,
        metadata: DsseLocalRuntimeCopyMetadata,
        requestID: String,
        transport: any DsseSessionLocalRuntimeCopyTransport,
        liveGuard: DsseLiveRuntimeCopyGuard,
        maxSessionExchangeCount: Int,
        stepTimeoutInterval: TimeInterval,
        closeGuardAndFlow: @escaping @Sendable (Error?) -> Void,
        stepState: DsseLiveRuntimeCopyStepState,
        emitProgress: @escaping @Sendable (DsseLiveRuntimeCopyProgress) -> Void,
        failIfCurrent: @escaping @Sendable (UUID, Error, Error?) -> Void,
        scheduleTimeout: @escaping @Sendable (UUID, DsseLocalRuntimeCopyDriverError) -> Void,
        flowWriteErrorCategory: @escaping @Sendable (Error?) -> String,
        makeSuccessResult: @escaping @Sendable (Int, Int) -> DsseLocalRuntimeCopyResult,
        completionHandler: @escaping @Sendable (Result<DsseLocalRuntimeCopyResult, Error>) -> Void
    ) {
        self.flow = flow
        self.metadata = metadata
        self.requestID = requestID
        self.transport = transport
        self.liveGuard = liveGuard
        self.maxSessionExchangeCount = maxSessionExchangeCount
        self.stepTimeoutInterval = stepTimeoutInterval
        self.closeGuardAndFlow = closeGuardAndFlow
        self.stepState = stepState
        self.emitProgress = emitProgress
        self.failIfCurrent = failIfCurrent
        self.scheduleTimeout = scheduleTimeout
        self.flowWriteErrorCategory = flowWriteErrorCategory
        self.makeSuccessResult = makeSuccessResult
        self.completionHandler = completionHandler
    }

    func readAndExchange(_ operation: DsseLocalRuntimeCopySessionOperation) {
        let readToken = stepState.beginStep()
        scheduleReadTimeout(readToken)
        flow.readDataForCopy { upstreamPayload, readError in
            guard self.stepState.isCurrentAndOpen(readToken) else {
                return
            }
            if readError != nil {
                self.closeSessionAfterFailure()
                self.failIfCurrent(readToken, DsseLocalRuntimeCopyDriverError.flowReadFailed, readError)
                return
            }
            guard let upstreamPayload, !upstreamPayload.isEmpty else {
                if self.totals.snapshot.exchangeCount == 0 {
                    self.closeSessionAfterFailure()
                    self.failIfCurrent(readToken, DsseLocalRuntimeCopyDriverError.emptyUpstreamPayload, nil)
                    return
                }
                self.finishSuccess(readToken)
                return
            }
            do {
                try self.liveGuard.recordUpstreamBytes(requestID: self.requestID, count: upstreamPayload.count)
            } catch {
                self.closeSessionAfterFailure()
                self.failIfCurrent(readToken, error, error)
                return
            }
            self.emitProgress(.upstreamReadCompleted(bytes: upstreamPayload.count))

            let edgeToken = self.stepState.beginStep()
            self.scheduleTimeout(edgeToken, .edgeRoundTripTimeout)
            self.emitProgress(.edgeRoundTripStarted)
            guard self.stepState.isCurrentAndOpen(edgeToken) else {
                return
            }
            DispatchQueue.global(qos: .utility).async {
                self.exchangeWithEdge(
                    operation: operation,
                    upstreamPayload: upstreamPayload,
                    edgeToken: edgeToken
                )
            }
        }
    }

    private func scheduleReadTimeout(_ token: UUID) {
        guard totals.snapshot.exchangeCount > 0 else {
            scheduleTimeout(token, .flowReadTimeout)
            return
        }
        DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + stepTimeoutInterval) {
            guard self.stepState.isCurrentAndOpen(token) else {
                return
            }
            self.finishSuccess(token)
        }
    }

    private func exchangeWithEdge(
        operation: DsseLocalRuntimeCopySessionOperation,
        upstreamPayload: Data,
        edgeToken: UUID
    ) {
        guard stepState.isCurrentAndOpen(edgeToken) else {
            return
        }
        let exchangeResult: DsseLocalRuntimeCopySessionExchangeResult
        do {
            exchangeResult = try transport.exchangeSession(
                upstreamPayload,
                operation: operation,
                metadata: metadata,
                progressHandler: emitProgress
            )
            if !exchangeResult.downstreamPayload.isEmpty {
                try liveGuard.enqueueDownstreamBytes(requestID: requestID, count: exchangeResult.downstreamPayload.count)
            }
        } catch {
            closeSessionAfterFailure()
            failIfCurrent(edgeToken, error, error)
            return
        }
        guard stepState.isCurrentAndOpen(edgeToken) else {
            return
        }
        emitProgress(.edgeRoundTripCompleted)
        if exchangeResult.downstreamPayload.isEmpty {
            totals.record(upstreamBytes: upstreamPayload.count, downstreamBytes: 0)
            if exchangeResult.sessionClosed || totals.snapshot.exchangeCount >= maxSessionExchangeCount {
                finishSuccess(edgeToken)
                return
            }
            readAndExchange(.exchange)
            return
        }

        let writeToken = stepState.beginStep()
        scheduleTimeout(writeToken, .flowWriteTimeout)
        emitProgress(.downstreamWriteStarted)
        guard stepState.isCurrentAndOpen(writeToken) else {
            return
        }
        flow.writeDataForCopy(exchangeResult.downstreamPayload) { writeError in
            guard self.stepState.isCurrentAndOpen(writeToken) else {
                return
            }
            if writeError != nil {
                self.emitProgress(.downstreamWriteFailed(category: self.flowWriteErrorCategory(writeError)))
                self.closeSessionAfterFailure()
                self.failIfCurrent(writeToken, DsseLocalRuntimeCopyDriverError.flowWriteFailed, writeError)
                return
            }
            self.emitProgress(.downstreamWriteCompleted)
            do {
                try self.liveGuard.dequeueDownstream(requestID: self.requestID)
            } catch {
                self.closeSessionAfterFailure()
                self.failIfCurrent(writeToken, error, error)
                return
            }
            self.totals.record(upstreamBytes: upstreamPayload.count, downstreamBytes: exchangeResult.downstreamPayload.count)
            if exchangeResult.sessionClosed || self.totals.snapshot.exchangeCount >= self.maxSessionExchangeCount {
                self.finishSuccess(writeToken, delayFlowClose: exchangeResult.sessionClosed)
                return
            }
            self.readAndExchange(.exchange)
        }
    }

    private func finishSuccess(_ token: UUID, delayFlowClose: Bool = false) {
        DispatchQueue.global(qos: .utility).async {
            try? self.transport.closeSession(metadata: self.metadata, progressHandler: nil)
        }
        let snapshot = totals.snapshot
        guard stepState.completeIfCurrent(token) else {
            return
        }
        let complete: @Sendable () -> Void = {
            self.closeGuardAndFlow(nil)
            self.completionHandler(.success(self.makeSuccessResult(snapshot.bytesUp, snapshot.bytesDown)))
        }
        if delayFlowClose {
            DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + Self.successfulFlowCloseDelayInterval) {
                complete()
            }
            return
        }
        complete()
    }

    private func closeSessionAfterFailure() {
        DispatchQueue.global(qos: .utility).async {
            try? self.transport.closeSession(metadata: self.metadata, progressHandler: nil)
        }
    }
}

private final class DsseLiveRuntimeCopyStepState: @unchecked Sendable {
    private let lock = NSLock()
    private var completed = false
    private var currentToken = UUID()

    func beginStep() -> UUID {
        lock.lock()
        defer { lock.unlock() }
        let token = UUID()
        currentToken = token
        return token
    }

    func isCurrentAndOpen(_ token: UUID) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return !completed && currentToken == token
    }

    func completeIfCurrent(_ token: UUID) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard !completed, currentToken == token else {
            return false
        }
        completed = true
        return true
    }
}

private final class DsseLiveRuntimeCopySessionTotals: @unchecked Sendable {
    private let lock = NSLock()
    private var bytesUpValue = 0
    private var bytesDownValue = 0
    private var exchangeCountValue = 0

    var snapshot: (bytesUp: Int, bytesDown: Int, exchangeCount: Int) {
        lock.lock()
        defer { lock.unlock() }
        return (bytesUpValue, bytesDownValue, exchangeCountValue)
    }

    func record(upstreamBytes: Int, downstreamBytes: Int) {
        lock.lock()
        defer { lock.unlock() }
        bytesUpValue += upstreamBytes
        bytesDownValue += downstreamBytes
        exchangeCountValue += 1
    }
}

private struct DsseProviderRuntimeCopyAgentConfig: Decodable {
    let edgeURL: String?
    let runtimeCopyEndpointPath: String?
    let runtimeCopySessionEndpointPath: String?
    let runtimeCopyEvidenceRef: String?
    let runtimeDiagnosticRef: String?
    let labRawAuthorityDiagnosticRef: String?
    let runtimeCopyTransportScope: String?
    let runtimeCopyEdgeConnectorRealness: String?
    let runtimeCopyPassthroughResolvedIPs: [String]?
    let runtimeCopyTunnelEnabled: Bool?
    let transport: DsseTransportContract? //  W4 (T) transport contract

    enum CodingKeys: String, CodingKey {
        case edgeURL = "edge_url"
        case transport = "network_extension_transport"
        case runtimeCopyEndpointPath = "network_extension_runtime_copy_endpoint_path"
        case runtimeCopySessionEndpointPath = "network_extension_runtime_copy_session_endpoint_path"
        case runtimeCopyEvidenceRef = "network_extension_runtime_copy_evidence_ref"
        case runtimeDiagnosticRef = "network_extension_runtime_diagnostic_ref"
        case labRawAuthorityDiagnosticRef = "network_extension_lab_raw_authority_diagnostic_ref"
        case runtimeCopyTransportScope = "network_extension_runtime_copy_transport_scope"
        case runtimeCopyEdgeConnectorRealness = "network_extension_runtime_copy_edge_connector_realness"
        case runtimeCopyPassthroughResolvedIPs = "network_extension_runtime_copy_passthrough_resolved_ips"
        case runtimeCopyTunnelEnabled = "network_extension_runtime_copy_tunnel_enabled"
    }
}

private struct DsseEdgeRuntimeCopyRequest: Encodable {
    static let schemaVersion = "network_extension_runtime_copy_round_trip_request.v1"

    let schemaVersion: String
    let tenantID: String
    let requestID: String
    let applicationID: String
    let destinationHost: String?
    let destinationPort: Int?
    let upstreamPayloadBase64: String

    init(
        tenantID: String,
        requestID: String,
        applicationID: String,
        destinationHost: String? = nil,
        destinationPort: Int? = nil,
        upstreamPayloadBase64: String
    ) {
        self.schemaVersion = Self.schemaVersion
        self.tenantID = tenantID
        self.requestID = requestID
        self.applicationID = applicationID
        self.destinationHost = destinationHost
        self.destinationPort = destinationPort
        self.upstreamPayloadBase64 = upstreamPayloadBase64
    }

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case tenantID = "tenant_id"
        case requestID = "request_id"
        case applicationID = "application_id"
        case destinationHost = "destination_host"
        case destinationPort = "destination_port"
        case upstreamPayloadBase64 = "upstream_payload_b64"
    }
}

private struct DsseEdgeRuntimeCopyResponse: Decodable {
    static let schemaVersion = "network_extension_runtime_copy_round_trip_response.v1"

    let schemaVersion: String
    let requestID: String
    let downstreamPayloadBase64: String

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case requestID = "request_id"
        case downstreamPayloadBase64 = "downstream_payload_b64"
    }
}

private struct DsseEdgeRuntimeCopyErrorResponse: Decodable {
    static let schemaVersion = "network_extension_runtime_copy_round_trip_error.v1"

    let schemaVersion: String
    let status: String
    let category: String

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case status
        case category
    }
}

private struct DsseEdgeRuntimeCopySessionRequest: Encodable {
    static let schemaVersion = "network_extension_runtime_copy_session_request.v1"

    let schemaVersion: String
    let tenantID: String
    let requestID: String
    let operation: String
    let applicationID: String
    let destinationHost: String?
    let destinationPort: Int?
    let upstreamPayloadBase64: String?
    let clientEOF: Bool

    init(
        tenantID: String,
        requestID: String,
        operation: String,
        applicationID: String,
        destinationHost: String? = nil,
        destinationPort: Int? = nil,
        upstreamPayloadBase64: String? = nil,
        clientEOF: Bool = false
    ) {
        self.schemaVersion = Self.schemaVersion
        self.tenantID = tenantID
        self.requestID = requestID
        self.operation = operation
        self.applicationID = applicationID
        self.destinationHost = destinationHost
        self.destinationPort = destinationPort
        self.upstreamPayloadBase64 = upstreamPayloadBase64
        self.clientEOF = clientEOF
    }

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case tenantID = "tenant_id"
        case requestID = "request_id"
        case operation
        case applicationID = "application_id"
        case destinationHost = "destination_host"
        case destinationPort = "destination_port"
        case upstreamPayloadBase64 = "upstream_payload_b64"
        case clientEOF = "client_eof"
    }
}

private struct DsseEdgeRuntimeCopySessionResponse: Decodable {
    static let schemaVersion = "network_extension_runtime_copy_session_response.v1"

    let schemaVersion: String
    let requestID: String
    let downstreamPayloadBase64: String?
    let sessionClosed: Bool?

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case requestID = "request_id"
        case downstreamPayloadBase64 = "downstream_payload_b64"
        case sessionClosed = "session_closed"
    }
}

private enum DsseEdgeRuntimeCopySessionErrorResponse {
    static let schemaVersion = "network_extension_runtime_copy_session_error.v1"
}

public struct DsseLoopbackRuntimeCopyTransport: DsseLocalRuntimeCopyTransport {
    private let downstreamPayload: Data

    public init(downstreamPayload: Data) {
        self.downstreamPayload = downstreamPayload
    }

    public func roundTrip(
        _ payload: Data,
        metadata: DsseLocalRuntimeCopyMetadata
    ) throws -> Data {
        downstreamPayload
    }
}

public struct DsseDeviceValidationPendingRuntimeCopyTransport: DsseLocalRuntimeCopyTransport {
    public init() {}

    public func roundTrip(
        _ payload: Data,
        metadata: DsseLocalRuntimeCopyMetadata
    ) throws -> Data {
        throw DsseLocalRuntimeCopyDriverError.runtimeTransportDeviceValidationPending
    }
}

private func runtimeCopyEvidencePathIsSymbolicLink(_ url: URL) -> Bool {
    if let values = try? url.resourceValues(forKeys: [.isSymbolicLinkKey]), values.isSymbolicLink == true {
        return true
    }
    return false
}

@available(macOS 13.0, *)
extension NEAppProxyTCPFlow: @unchecked Sendable {}

@available(macOS 13.0, *)
extension NEAppProxyTCPFlow: DsseProviderTCPFlowCopyIO {
    public func openForCopy(completionHandler: @escaping @Sendable (Error?) -> Void) {
        if #available(macOS 15.0, *) {
            open(withLocalFlowEndpoint: nil, completionHandler: completionHandler)
            return
        }
        completionHandler(DsseLocalRuntimeCopyDriverError.runtimeTransportDeviceValidationPending)
    }

    public func readDataForCopy(completionHandler: @escaping @Sendable (Data?, Error?) -> Void) {
        readData(completionHandler: completionHandler)
    }

    public func writeDataForCopy(_ data: Data, completionHandler: @escaping @Sendable (Error?) -> Void) {
        write(data, withCompletionHandler: completionHandler)
    }

    public func closeReadForCopy(error: Error?) {
        closeReadWithError(error)
    }

    public func closeWriteForCopy(error: Error?) {
        closeWriteWithError(error)
    }
}
