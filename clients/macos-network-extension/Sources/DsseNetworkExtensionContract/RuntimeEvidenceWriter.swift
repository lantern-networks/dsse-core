import Foundation

public enum ProviderRuntimeEvidenceSource: String, Codable, Equatable {
    case notInstalledContract = "not_installed_contract"
    case providerRuntime = "provider_runtime"
    case agentStatus = "agent_status"
}

public struct ProviderRuntimeEvidence: Codable, Equatable {
    public let status: String
    public let createdAt: String
    public let runtimeInstalled: Bool
    public let runtimeRunning: Bool
    public let runtimeProvider: ProviderRuntimeProvider
    public let rulesLoaded: Bool
    public let ruleCount: Int
    public let flowExtractionAttempted: Int
    public let flowExtractionSucceeded: Int
    public let flowExtractionDenied: Int
    public let flowExtractionGate: String
    public let flowAttempted: Int
    public let flowTunneled: Int
    public let flowDenied: Int
    public let lastError: String?
    public let evidenceSource: ProviderRuntimeEvidenceSource
    public let secretLeakGate: String

    enum CodingKeys: String, CodingKey {
        case status
        case createdAt = "created_at"
        case runtimeInstalled = "runtime_installed"
        case runtimeRunning = "runtime_running"
        case runtimeProvider = "runtime_provider"
        case rulesLoaded = "rules_loaded"
        case ruleCount = "rule_count"
        case flowExtractionAttempted = "flow_extraction_attempted"
        case flowExtractionSucceeded = "flow_extraction_succeeded"
        case flowExtractionDenied = "flow_extraction_denied"
        case flowExtractionGate = "flow_extraction_gate"
        case flowAttempted = "flow_attempted"
        case flowTunneled = "flow_tunneled"
        case flowDenied = "flow_denied"
        case lastError = "last_error"
        case evidenceSource = "evidence_source"
        case secretLeakGate = "secret_leak_gate"
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(status, forKey: .status)
        try container.encode(createdAt, forKey: .createdAt)
        try container.encode(runtimeInstalled, forKey: .runtimeInstalled)
        try container.encode(runtimeRunning, forKey: .runtimeRunning)
        try container.encode(runtimeProvider, forKey: .runtimeProvider)
        try container.encode(rulesLoaded, forKey: .rulesLoaded)
        try container.encode(ruleCount, forKey: .ruleCount)
        try container.encode(flowExtractionAttempted, forKey: .flowExtractionAttempted)
        try container.encode(flowExtractionSucceeded, forKey: .flowExtractionSucceeded)
        try container.encode(flowExtractionDenied, forKey: .flowExtractionDenied)
        try container.encode(flowExtractionGate, forKey: .flowExtractionGate)
        try container.encode(flowAttempted, forKey: .flowAttempted)
        try container.encode(flowTunneled, forKey: .flowTunneled)
        try container.encode(flowDenied, forKey: .flowDenied)
        if let lastError {
            try container.encode(lastError, forKey: .lastError)
        } else {
            try container.encodeNil(forKey: .lastError)
        }
        try container.encode(evidenceSource, forKey: .evidenceSource)
        try container.encode(secretLeakGate, forKey: .secretLeakGate)
    }
}

public enum ProviderRuntimeEvidenceError: Error, Equatable, LocalizedError {
    case missingRuntimeEvidenceRef
    case invalidRuntimeEvidenceRef(String)
    case invalidEvidence(String)
    case writeFailed

    public var errorDescription: String? {
        switch self {
        case .missingRuntimeEvidenceRef:
            return "provider agent config network_extension_runtime_evidence_ref is required"
        case .invalidRuntimeEvidenceRef(let reason):
            return "provider agent config network_extension_runtime_evidence_ref is invalid: \(reason)"
        case .invalidEvidence(let reason):
            return "provider runtime evidence is invalid: \(reason)"
        case .writeFailed:
            return "provider runtime evidence could not be written"
        }
    }
}

public struct ProviderRuntimeEvidenceWriter {
    public init() {}

    @discardableResult
    public func write(
        agentConfigPath: String,
        runtimeProvider: ProviderRuntimeProvider,
        runtimeRunning: Bool,
        rulesLoaded: Bool,
        ruleCount: Int,
        flowExtractionAttempted: Int,
        flowExtractionSucceeded: Int,
        flowExtractionDenied: Int,
        flowAttempted: Int,
        flowTunneled: Int,
        flowDenied: Int,
        lastError: String?
    ) throws -> URL {
        let config = try loadRuntimeEvidenceAgentConfig(from: agentConfigPath)
        guard let evidenceRef = config.networkExtensionRuntimeEvidenceRef?.trimmingCharacters(in: .whitespacesAndNewlines), !evidenceRef.isEmpty else {
            throw ProviderRuntimeEvidenceError.missingRuntimeEvidenceRef
        }
        let configDirectory = URL(fileURLWithPath: agentConfigPath).deletingLastPathComponent()
        let evidenceURL = try resolveProviderRuntimeEvidenceRef(evidenceRef, relativeTo: configDirectory)
        let sanitizedLastError = sanitizeProviderRuntimeEvidenceLastError(lastError)
        let evidence = ProviderRuntimeEvidence(
            status: "ok",
            createdAt: ISO8601DateFormatter().string(from: Date()),
            runtimeInstalled: runtimeProvider != .notInstalled,
            runtimeRunning: runtimeRunning,
            runtimeProvider: runtimeProvider,
            rulesLoaded: rulesLoaded,
            ruleCount: ruleCount,
            flowExtractionAttempted: flowExtractionAttempted,
            flowExtractionSucceeded: flowExtractionSucceeded,
            flowExtractionDenied: flowExtractionDenied,
            flowExtractionGate: "ok",
            flowAttempted: flowAttempted,
            flowTunneled: flowTunneled,
            flowDenied: flowDenied,
            lastError: sanitizedLastError,
            evidenceSource: runtimeProvider == .notInstalled ? .notInstalledContract : .providerRuntime,
            secretLeakGate: "ok"
        )
        try validateProviderRuntimeEvidence(evidence)
        try writeProviderRuntimeEvidence(evidence, to: evidenceURL)
        return evidenceURL
    }
}

public func resolveProviderRuntimeEvidenceRef(_ ref: String, relativeTo baseDirectory: URL) throws -> URL {
    let cleaned = ref.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !cleaned.isEmpty else {
        throw ProviderRuntimeEvidenceError.missingRuntimeEvidenceRef
    }
    guard !cleaned.hasPrefix("/") else {
        throw ProviderRuntimeEvidenceError.invalidRuntimeEvidenceRef("absolute paths are not allowed")
    }
    guard !cleaned.hasPrefix("~") else {
        throw ProviderRuntimeEvidenceError.invalidRuntimeEvidenceRef("home-relative paths are not allowed")
    }
    guard !cleaned.contains("\\") else {
        throw ProviderRuntimeEvidenceError.invalidRuntimeEvidenceRef("backslashes are not allowed")
    }
    guard !cleaned.contains("\u{0000}") else {
        throw ProviderRuntimeEvidenceError.invalidRuntimeEvidenceRef("null bytes are not allowed")
    }
    guard cleaned.hasSuffix(".json") else {
        throw ProviderRuntimeEvidenceError.invalidRuntimeEvidenceRef("runtime evidence reference must end with .json")
    }
    let segments = cleaned.split(separator: "/", omittingEmptySubsequences: false)
    guard !segments.isEmpty else {
        throw ProviderRuntimeEvidenceError.invalidRuntimeEvidenceRef("runtime evidence reference is empty")
    }
    var resolved = baseDirectory
    for segment in segments {
        if segment.isEmpty || segment == "." || segment == ".." {
            throw ProviderRuntimeEvidenceError.invalidRuntimeEvidenceRef("path traversal is not allowed")
        }
        resolved.appendPathComponent(String(segment), isDirectory: false)
    }
    let basePath = baseDirectory.standardizedFileURL.resolvingSymlinksInPath().path
    let resolvedPath = resolved.standardizedFileURL.resolvingSymlinksInPath().path
    if resolvedPath != basePath && !resolvedPath.hasPrefix(basePath.hasSuffix("/") ? basePath : basePath + "/") {
        throw ProviderRuntimeEvidenceError.invalidRuntimeEvidenceRef("resolved path escapes config directory")
    }
    if providerPathIsSymbolicLink(resolved) {
        throw ProviderRuntimeEvidenceError.invalidRuntimeEvidenceRef("runtime evidence path must not be a symbolic link")
    }
    return resolved
}

public func validateProviderRuntimeEvidence(_ evidence: ProviderRuntimeEvidence) throws {
    guard evidence.status == "ok" else {
        throw ProviderRuntimeEvidenceError.invalidEvidence("status must be ok")
    }
    guard evidence.secretLeakGate == "ok" else {
        throw ProviderRuntimeEvidenceError.invalidEvidence("secret leak gate must be ok")
    }
    guard evidence.flowExtractionGate == "ok" else {
        throw ProviderRuntimeEvidenceError.invalidEvidence("flow extraction gate must be ok")
    }
    if providerRuntimeEvidenceLastErrorContainsForbiddenMarker(evidence.lastError) {
        throw ProviderRuntimeEvidenceError.invalidEvidence("last_error contains forbidden marker")
    }
    guard evidence.ruleCount >= 0 &&
        evidence.flowExtractionAttempted >= 0 &&
        evidence.flowExtractionSucceeded >= 0 &&
        evidence.flowExtractionDenied >= 0 &&
        evidence.flowAttempted >= 0 &&
        evidence.flowTunneled >= 0 &&
        evidence.flowDenied >= 0 else {
        throw ProviderRuntimeEvidenceError.invalidEvidence("counters must be nonnegative")
    }
    guard evidence.flowExtractionSucceeded <= evidence.flowExtractionAttempted &&
        evidence.flowExtractionDenied <= evidence.flowExtractionAttempted &&
        evidence.flowExtractionSucceeded + evidence.flowExtractionDenied <= evidence.flowExtractionAttempted else {
        throw ProviderRuntimeEvidenceError.invalidEvidence("flow extraction outcomes must not exceed attempted extractions")
    }
    guard evidence.flowAttempted <= evidence.flowExtractionSucceeded else {
        throw ProviderRuntimeEvidenceError.invalidEvidence("flow decisions must not exceed successful flow extractions")
    }
    if !evidence.runtimeInstalled {
        guard evidence.runtimeRunning == false else {
            throw ProviderRuntimeEvidenceError.invalidEvidence("not-installed evidence must not claim running runtime")
        }
        guard evidence.runtimeProvider == .notInstalled else {
            throw ProviderRuntimeEvidenceError.invalidEvidence("not-installed evidence must use runtime_provider=not_installed")
        }
        guard evidence.rulesLoaded == false && evidence.ruleCount == 0 else {
            throw ProviderRuntimeEvidenceError.invalidEvidence("not-installed evidence must not claim loaded rules")
        }
        guard evidence.flowExtractionAttempted == 0 &&
            evidence.flowExtractionSucceeded == 0 &&
            evidence.flowExtractionDenied == 0 &&
            evidence.flowAttempted == 0 &&
            evidence.flowTunneled == 0 &&
            evidence.flowDenied == 0 else {
            throw ProviderRuntimeEvidenceError.invalidEvidence("not-installed evidence must keep flow counters at zero")
        }
        guard evidence.evidenceSource == .notInstalledContract else {
            throw ProviderRuntimeEvidenceError.invalidEvidence("not-installed evidence must use not_installed_contract source")
        }
        return
    }
    guard evidence.runtimeProvider != .notInstalled else {
        throw ProviderRuntimeEvidenceError.invalidEvidence("installed evidence must name a real provider")
    }
    guard evidence.evidenceSource != .notInstalledContract else {
        throw ProviderRuntimeEvidenceError.invalidEvidence("installed evidence must not use not_installed_contract source")
    }
    guard evidence.evidenceSource != .agentStatus else {
        throw ProviderRuntimeEvidenceError.invalidEvidence("agent_status evidence must not claim installed runtime")
    }
    guard evidence.flowTunneled <= evidence.flowAttempted && evidence.flowDenied <= evidence.flowAttempted else {
        throw ProviderRuntimeEvidenceError.invalidEvidence("flow outcomes must not exceed attempted flows")
    }
    guard evidence.flowTunneled + evidence.flowDenied <= evidence.flowAttempted else {
        throw ProviderRuntimeEvidenceError.invalidEvidence("flow outcomes must not exceed attempted flows")
    }
    if !evidence.runtimeRunning {
        guard evidence.flowExtractionAttempted == 0 &&
            evidence.flowExtractionSucceeded == 0 &&
            evidence.flowExtractionDenied == 0 &&
            evidence.flowAttempted == 0 &&
            evidence.flowTunneled == 0 &&
            evidence.flowDenied == 0 else {
            throw ProviderRuntimeEvidenceError.invalidEvidence("stopped runtime evidence must keep flow counters at zero")
        }
    }
    if !evidence.rulesLoaded {
        guard evidence.ruleCount == 0 &&
            evidence.flowExtractionAttempted == 0 &&
            evidence.flowExtractionSucceeded == 0 &&
            evidence.flowExtractionDenied == 0 &&
            evidence.flowAttempted == 0 &&
            evidence.flowTunneled == 0 &&
            evidence.flowDenied == 0 else {
            throw ProviderRuntimeEvidenceError.invalidEvidence("evidence without loaded rules must keep rule and flow counters at zero")
        }
    } else {
        guard evidence.ruleCount > 0 else {
            throw ProviderRuntimeEvidenceError.invalidEvidence("evidence with loaded rules must have a positive rule_count")
        }
    }
}

public func sanitizeProviderRuntimeEvidenceLastError(_ lastError: String?) -> String? {
    guard let lastError else {
        return nil
    }
    let normalized = lastError
        .replacingOccurrences(of: "\r", with: " ")
        .replacingOccurrences(of: "\n", with: " ")
        .trimmingCharacters(in: .whitespacesAndNewlines)
    guard !normalized.isEmpty else {
        return nil
    }
    if providerRuntimeEvidenceLastErrorContainsForbiddenMarker(normalized) {
        return "provider runtime error redacted"
    }
    if normalized.count > 256 {
        return String(normalized.prefix(256))
    }
    return normalized
}

private func providerRuntimeEvidenceLastErrorContainsForbiddenMarker(_ value: String?) -> Bool {
    guard let value else {
        return false
    }
    if value.contains("/Users/") {
        return true
    }
    let lowercased = value.lowercased()
    let forbidden = [
        "local-connector-secret",
        "runtime_secret_from_config",
        "super-secret",
        "client_secret",
        "id_token",
        "access_token",
        "refresh_token"
    ]
    return forbidden.contains { lowercased.contains($0) }
}

private func loadRuntimeEvidenceAgentConfig(from path: String) throws -> AgentNetworkExtensionConfig {
    let data: Data
    do {
        data = try Data(contentsOf: URL(fileURLWithPath: path))
    } catch {
        throw ProviderLifecycleError.configReadFailed
    }
    do {
        return try JSONDecoder().decode(AgentNetworkExtensionConfig.self, from: data)
    } catch {
        throw ProviderLifecycleError.configDecodeFailed
    }
}

private func writeProviderRuntimeEvidence(_ evidence: ProviderRuntimeEvidence, to url: URL) throws {
    let parent = url.deletingLastPathComponent()
    var isDirectory: ObjCBool = false
    guard FileManager.default.fileExists(atPath: parent.path, isDirectory: &isDirectory), isDirectory.boolValue else {
        throw ProviderRuntimeEvidenceError.invalidRuntimeEvidenceRef("parent directory does not exist")
    }

    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
    let data = try encoder.encode(evidence)
    let tempURL = parent.appendingPathComponent(".\(url.lastPathComponent).tmp.\(UUID().uuidString)", isDirectory: false)
    do {
        try data.write(to: tempURL, options: [.withoutOverwriting])
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: tempURL.path)
        if FileManager.default.fileExists(atPath: url.path) {
            if providerPathIsSymbolicLink(url) {
                throw ProviderRuntimeEvidenceError.invalidRuntimeEvidenceRef("runtime evidence path must not be a symbolic link")
            }
            _ = try FileManager.default.replaceItemAt(url, withItemAt: tempURL, backupItemName: nil, options: [])
        } else {
            try FileManager.default.moveItem(at: tempURL, to: url)
        }
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    } catch let error as ProviderRuntimeEvidenceError {
        try? FileManager.default.removeItem(at: tempURL)
        throw error
    } catch {
        try? FileManager.default.removeItem(at: tempURL)
        throw ProviderRuntimeEvidenceError.writeFailed
    }
}

private func providerPathIsSymbolicLink(_ url: URL) -> Bool {
    if let values = try? url.resourceValues(forKeys: [.isSymbolicLinkKey]), values.isSymbolicLink == true {
        return true
    }
    return false
}
