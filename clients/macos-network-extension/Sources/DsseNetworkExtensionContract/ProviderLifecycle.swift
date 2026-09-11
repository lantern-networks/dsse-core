import Foundation

public enum ProviderLifecycleStatus: String, Codable, Equatable {
    case running
    case failed
}

public enum ProviderRuntimeProvider: String, Codable, Equatable {
    case notInstalled = "not_installed"
    case appProxyProvider = "app_proxy_provider"
    case transparentProxyProvider = "transparent_proxy_provider"
    case packetTunnelProvider = "packet_tunnel_provider"
}

public struct ProviderLifecycleState: Codable, Equatable {
    public let status: ProviderLifecycleStatus
    public let agentConfig: String
    public let rulesManifest: String?
    public let tenantID: String?
    public let runtimeInstalled: Bool
    public let runtimeRunning: Bool
    public let runtimeProvider: ProviderRuntimeProvider
    public let rulesLoaded: Bool
    public let ruleCount: Int
    public let lastError: String

    enum CodingKeys: String, CodingKey {
        case status = "provider_lifecycle_status"
        case agentConfig = "agent_config"
        case rulesManifest = "rules_manifest"
        case tenantID = "tenant_id"
        case runtimeInstalled = "runtime_installed"
        case runtimeRunning = "runtime_running"
        case runtimeProvider = "runtime_provider"
        case rulesLoaded = "rules_loaded"
        case ruleCount = "rule_count"
        case lastError = "last_error"
    }
}

public enum ProviderLifecycleError: Error, Equatable, LocalizedError {
    case configReadFailed
    case configDecodeFailed
    case missingRulesRef
    case invalidRulesRef(String)
    case rulesReadFailed
    case rulesDecodeFailed
    case rulesValidationFailed

    public var errorDescription: String? {
        switch self {
        case .configReadFailed:
            return "provider agent config could not be read"
        case .configDecodeFailed:
            return "provider agent config could not be decoded"
        case .missingRulesRef:
            return "provider agent config network_extension_rules_ref is required"
        case .invalidRulesRef(let reason):
            return "provider agent config network_extension_rules_ref is invalid: \(reason)"
        case .rulesReadFailed:
            return "provider network extension rules could not be read"
        case .rulesDecodeFailed:
            return "provider network extension rules could not be decoded"
        case .rulesValidationFailed:
            return "provider network extension rules failed validation"
        }
    }
}

public struct AgentNetworkExtensionConfig: Decodable, Equatable {
    public let networkExtensionRulesRef: String?
    public let networkExtensionRuntimeEvidenceRef: String?

    enum CodingKeys: String, CodingKey {
        case networkExtensionRulesRef = "network_extension_rules_ref"
        case networkExtensionRuntimeEvidenceRef = "network_extension_runtime_evidence_ref"
    }
}

public final class ProviderLifecycleManager {
    private static let phase2FlowCopyLabProtectedAppMap = "protected_app_map_phase2_flow_copy_lab.json"
    private static let productizationP2OperatorConfigProtectedAppMap = "protected_app_map_operator_config.json"

    private let reloadLock = NSLock()
    private var decider: ProviderFlowDeciding?
    private var loadedRules: NetworkExtensionRules?
    private var lifecycleState: ProviderLifecycleState?
    private var lastRulesModificationDate: Date?
    private var lastAgentConfigPath: String?

    public var state: ProviderLifecycleState? {
        reloadLock.lock()
        defer { reloadLock.unlock() }
        return lifecycleState
    }

    public init() {}

    @discardableResult
    public func start(agentConfigPath: String) -> ProviderLifecycleState {
        let agentConfigName = URL(fileURLWithPath: agentConfigPath).lastPathComponent
        do {
            let config = try loadAgentConfig(from: agentConfigPath)
            guard let rulesRef = config.networkExtensionRulesRef?.trimmingCharacters(in: .whitespacesAndNewlines), !rulesRef.isEmpty else {
                throw ProviderLifecycleError.missingRulesRef
            }
            let configDirectory = URL(fileURLWithPath: agentConfigPath).deletingLastPathComponent()
            let rulesURL = try resolveProviderRulesRef(rulesRef, relativeTo: configDirectory)
            let rules = try loadRules(from: rulesURL)
            try NetworkExtensionRulesValidator.validate(rules)
            let rulesModificationDate = rulesFileModificationDate(from: rulesURL)
            let nextState = ProviderLifecycleState(
                status: .running,
                agentConfig: agentConfigName,
                rulesManifest: rulesRef,
                tenantID: rules.tenantID,
                runtimeInstalled: false,
                runtimeRunning: false,
                runtimeProvider: .notInstalled,
                rulesLoaded: true,
                ruleCount: rules.rules.count,
                lastError: ""
            )
            reloadLock.lock()
            self.decider = RulesBackedProviderFlowDecider(rules: rules)
            self.loadedRules = rules
            self.lifecycleState = nextState
            self.lastRulesModificationDate = rulesModificationDate
            self.lastAgentConfigPath = agentConfigPath
            reloadLock.unlock()
            return nextState
        } catch {
            let nextState = ProviderLifecycleState(
                status: .failed,
                agentConfig: agentConfigName,
                rulesManifest: nil,
                tenantID: nil,
                runtimeInstalled: false,
                runtimeRunning: false,
                runtimeProvider: .notInstalled,
                rulesLoaded: false,
                ruleCount: 0,
                lastError: providerLifecycleErrorDescription(error)
            )
            reloadLock.lock()
            self.decider = nil
            self.loadedRules = nil
            self.lifecycleState = nextState
            self.lastRulesModificationDate = nil
            self.lastAgentConfigPath = nil
            reloadLock.unlock()
            return nextState
        }
    }

    public func decide(_ flow: ProviderFlowRequest) -> ProviderFlowResult {
        let currentDecider: ProviderFlowDeciding?
        reloadLock.lock()
        currentDecider = decider
        reloadLock.unlock()
        return Self.decide(flow, decider: currentDecider)
    }

    public func decideWithSingleRuleLabFallback(_ flow: ProviderFlowRequest) -> ProviderLifecycleFlowDecision {
        let currentDecider: ProviderFlowDeciding?
        let currentState: ProviderLifecycleState?
        let currentRules: NetworkExtensionRules?
        reloadLock.lock()
        currentDecider = decider
        currentState = lifecycleState
        currentRules = loadedRules
        reloadLock.unlock()

        let primaryResult = Self.decide(flow, decider: currentDecider)
        let fallbackDecision: ProviderSingleRuleLabFallbackDecision?
        if primaryResult.decision.action == NetworkExtensionContract.actionDeny,
           primaryResult.decision.reason == NetworkExtensionContract.reasonNoMatch {
            fallbackDecision = Self.singleRuleLabFallbackDecision(
                state: currentState,
                rules: currentRules,
                destinationPort: flow.port,
                authorityHost: flow.host,
                allowInvalidAuthorityHostPortMismatch: false
            )
        } else {
            fallbackDecision = nil
        }
        return ProviderLifecycleFlowDecision(
            primaryResult: primaryResult,
            singleRuleLabFallback: fallbackDecision
        )
    }

    public func decideSingleRuleLabFallback(destinationPort: Int) -> ProviderFlowResult? {
        evaluateSingleRuleLabFallback(destinationPort: destinationPort).providerResult
    }

    public func evaluateSingleRuleLabFallback(
        destinationPort: Int,
        authorityHost: String = "",
        allowInvalidAuthorityHostPortMismatch: Bool = false
    ) -> ProviderSingleRuleLabFallbackDecision {
        let currentState: ProviderLifecycleState?
        let currentRules: NetworkExtensionRules?
        reloadLock.lock()
        currentState = lifecycleState
        currentRules = loadedRules
        reloadLock.unlock()
        return Self.singleRuleLabFallbackDecision(
            state: currentState,
            rules: currentRules,
            destinationPort: destinationPort,
            authorityHost: authorityHost,
            allowInvalidAuthorityHostPortMismatch: allowInvalidAuthorityHostPortMismatch
        )
    }

    public func loadedRulesGeneratedAtForDiagnostic() -> String {
        let currentRules: NetworkExtensionRules?
        reloadLock.lock()
        currentRules = loadedRules
        reloadLock.unlock()
        guard let currentRules else {
            return "not_observed"
        }
        let generatedAt = currentRules.generatedAt.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !generatedAt.isEmpty else {
            return "missing"
        }
        return generatedAt
    }

    public func ruleDiagnostic(for providerResult: ProviderFlowResult) -> ProviderSingleRuleLabRuleDiagnostic? {
        guard providerResult.providerAction == .openTunnel,
              providerResult.decision.action == NetworkExtensionContract.actionTunnel,
              let fqdn = providerResult.decision.fqdn?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased(),
              !fqdn.isEmpty,
              let destinationPort = providerResult.decision.destinationPort,
              destinationPort > 0 else {
            return nil
        }
        let currentRules: NetworkExtensionRules?
        reloadLock.lock()
        currentRules = loadedRules
        reloadLock.unlock()
        guard let currentRules else {
            return nil
        }
        return ProviderSingleRuleLabRuleDiagnostic(
            fqdn: fqdn,
            destinationPort: destinationPort,
            generatedAt: currentRules.generatedAt.trimmingCharacters(in: .whitespacesAndNewlines)
        )
    }

    public func singleRuleLabRuleDiagnostic() -> ProviderSingleRuleLabRuleDiagnostic? {
        let currentRules: NetworkExtensionRules?
        reloadLock.lock()
        currentRules = loadedRules
        reloadLock.unlock()
        guard let currentRules,
              currentRules.sourceProtectedAppMap == Self.phase2FlowCopyLabProtectedAppMap,
              currentRules.rules.count == 1,
              let rule = currentRules.rules.first else {
            return nil
        }
        return ProviderSingleRuleLabRuleDiagnostic(
            fqdn: rule.fqdn.trimmingCharacters(in: .whitespacesAndNewlines).lowercased(),
            destinationPort: rule.destinationPort,
            generatedAt: currentRules.generatedAt.trimmingCharacters(in: .whitespacesAndNewlines)
        )
    }

    private static func decide(_ flow: ProviderFlowRequest, decider: ProviderFlowDeciding?) -> ProviderFlowResult {
        guard let decider else {
            return invalidRulesProviderFlowResult()
        }
        return decider.decide(flow)
    }

    private static func invalidRulesProviderFlowResult() -> ProviderFlowResult {
        ProviderFlowResult(
            providerAction: .deny,
            runtimeInstalled: false,
            decision: NetworkExtensionDecision(
                action: NetworkExtensionContract.actionDeny,
                reason: NetworkExtensionContract.reasonInvalidRules,
                applicationID: nil,
                fqdn: nil,
                destinationPort: nil,
                serviceFamily: nil,
                connectorGroupID: nil
            )
        )
    }

    private static func singleRuleLabFallbackDecision(
        state: ProviderLifecycleState?,
        rules: NetworkExtensionRules?,
        destinationPort: Int,
        authorityHost: String = "",
        allowInvalidAuthorityHostPortMismatch: Bool
    ) -> ProviderSingleRuleLabFallbackDecision {
        guard state?.status == .running else {
            return ProviderSingleRuleLabFallbackDecision(
                gate: "lifecycle_not_running",
                providerResult: nil,
                allowFlowAuthorityPortMatch: "extraction_failed"
            )
        }
        guard let rules else {
            return ProviderSingleRuleLabFallbackDecision(
                gate: "rules_not_loaded",
                providerResult: nil,
                allowFlowAuthorityPortMatch: "extraction_failed"
            )
        }
        if rules.sourceProtectedAppMap == productizationP2OperatorConfigProtectedAppMap {
            return p2OperatorConfigPortFallbackDecision(
                rules: rules,
                destinationPort: destinationPort,
                authorityHost: authorityHost
            )
        }
        guard rules.sourceProtectedAppMap == phase2FlowCopyLabProtectedAppMap else {
            return ProviderSingleRuleLabFallbackDecision(
                gate: "source_map_not_phase2_flow_copy_lab",
                providerResult: nil,
                allowFlowAuthorityPortMatch: "extraction_failed"
            )
        }
        if let protectionRule = phase4ProtectionPortFallbackRule(
            rules: rules,
            destinationPort: destinationPort
        ) {
            return ProviderSingleRuleLabFallbackDecision(
                gate: "phase4_protection_port_rule_applied",
                providerResult: Self.phase4ProtectionPortFallbackResult(rule: protectionRule),
                allowFlowAuthorityPortMatch: "exact"
            )
        }
        guard rules.rules.count == 1, let rule = rules.rules.first else {
            return ProviderSingleRuleLabFallbackDecision(
                gate: "rule_count_not_one",
                providerResult: nil,
                allowFlowAuthorityPortMatch: "extraction_failed"
            )
        }
        guard rule.action == NetworkExtensionContract.actionTunnel else {
            return ProviderSingleRuleLabFallbackDecision(
                gate: "rule_action_not_tunnel",
                providerResult: nil,
                allowFlowAuthorityPortMatch: "extraction_failed"
            )
        }
        guard rule.destinationPort == destinationPort else {
            let portMatch = Self.allowFlowAuthorityPortMatch(ruleDestinationPort: rule.destinationPort, authorityPort: destinationPort)
            if allowInvalidAuthorityHostPortMismatch && destinationPort > 0 && destinationPort <= 65_535 {
                return ProviderSingleRuleLabFallbackDecision(
                    gate: "invalid_authority_host_port_mismatch_bypassed",
                    providerResult: Self.singleRuleLabFallbackResult(rule: rule),
                    allowFlowAuthorityPortMatch: portMatch
                )
            }
            return ProviderSingleRuleLabFallbackDecision(
                gate: "destination_port_mismatch",
                providerResult: nil,
                allowFlowAuthorityPortMatch: portMatch
            )
        }
        return ProviderSingleRuleLabFallbackDecision(
            gate: "applied",
            providerResult: Self.singleRuleLabFallbackResult(rule: rule),
            allowFlowAuthorityPortMatch: "exact"
        )
    }

    private static func p2OperatorConfigPortFallbackDecision(
        rules: NetworkExtensionRules,
        destinationPort: Int,
        authorityHost: String = ""
    ) -> ProviderSingleRuleLabFallbackDecision {
        guard destinationPort > 0, destinationPort <= 65_535 else {
            return ProviderSingleRuleLabFallbackDecision(
                gate: "destination_port_mismatch",
                providerResult: nil,
                allowFlowAuthorityPortMatch: "extraction_failed"
            )
        }
        let samePortRules = rules.rules.filter { $0.destinationPort == destinationPort }
        let tunnelRules = samePortRules.filter { $0.action == NetworkExtensionContract.actionTunnel }
        guard tunnelRules.count == 1, let rule = tunnelRules.first else {
            if samePortRules.contains(where: { $0.action != NetworkExtensionContract.actionTunnel }) {
                return ProviderSingleRuleLabFallbackDecision(
                    gate: "rule_action_not_tunnel",
                    providerResult: nil,
                    allowFlowAuthorityPortMatch: "exact"
                )
            }
            return ProviderSingleRuleLabFallbackDecision(
                gate: samePortRules.isEmpty ? "destination_port_mismatch" : "rule_count_not_one",
                providerResult: nil,
                allowFlowAuthorityPortMatch: samePortRules.isEmpty ? "extraction_failed" : "exact"
            )
        }
        // Productization P2 policy enforcement must not tunnel a flow whose
        // host cannot be evaluated against the operator-authored allow list.
        guard let normalizedAuthorityHost = normalizeHost(authorityHost) else {
            return ProviderSingleRuleLabFallbackDecision(
                gate: "p2_operator_config_unusable_authority_host_default_deny",
                providerResult: nil,
                allowFlowAuthorityPortMatch: "exact"
            )
        }
        if normalizedAuthorityHost != normalizeHost(rule.fqdn) {
            return ProviderSingleRuleLabFallbackDecision(
                gate: "p2_operator_config_authority_host_rule_mismatch_default_deny",
                providerResult: nil,
                allowFlowAuthorityPortMatch: "exact"
            )
        }
        return ProviderSingleRuleLabFallbackDecision(
            gate: "p2_operator_config_port_fallback_applied",
            providerResult: Self.singleRuleLabFallbackResult(rule: rule),
            allowFlowAuthorityPortMatch: "exact"
        )
    }

    private static func allowFlowAuthorityPortMatch(ruleDestinationPort: Int, authorityPort: Int) -> String {
        guard authorityPort > 0, authorityPort <= 65_535, ruleDestinationPort > 0, ruleDestinationPort <= 65_535 else {
            return "extraction_failed"
        }
        if ruleDestinationPort == authorityPort {
            return "exact"
        }
        return abs(ruleDestinationPort - authorityPort) == 1 ? "off_by_delta" : "sent_to_non_rule_port"
    }

    private static func singleRuleLabFallbackResult(rule: NetworkExtensionRule) -> ProviderFlowResult {
        let decision = NetworkExtensionDecision(
            action: NetworkExtensionContract.actionTunnel,
            reason: NetworkExtensionContract.reasonMatched,
            applicationID: rule.applicationID.trimmingCharacters(in: .whitespacesAndNewlines),
            fqdn: rule.fqdn.trimmingCharacters(in: .whitespacesAndNewlines).lowercased(),
            destinationPort: rule.destinationPort,
            serviceFamily: rule.serviceFamily.trimmingCharacters(in: .whitespacesAndNewlines),
            connectorGroupID: rule.connectorGroupID?.trimmingCharacters(in: .whitespacesAndNewlines)
        )
        return ProviderFlowResult(providerAction: .openTunnel, runtimeInstalled: false, decision: decision)
    }

    private static func phase4ProtectionPortFallbackRule(
        rules: NetworkExtensionRules,
        destinationPort: Int
    ) -> NetworkExtensionRule? {
        guard rules.rules.count == 2,
              destinationPort > 0,
              destinationPort <= 65_535 else {
            return nil
        }
        return rules.rules.first { rule in
            let reasonCodes = Set((rule.protectionReasonCodes ?? []).map {
                $0.trimmingCharacters(in: .whitespacesAndNewlines)
            })
            return rule.destinationPort == destinationPort &&
                rule.action.trimmingCharacters(in: .whitespacesAndNewlines) == NetworkExtensionContract.actionDeny &&
                rule.protectionMode?.trimmingCharacters(in: .whitespacesAndNewlines) ==
                    NetworkExtensionContract.protectionModeAC09RansomwareLateralMovement &&
                reasonCodes.contains(NetworkExtensionContract.reasonCodeRansomwareProtectionModeActive) &&
                reasonCodes.contains(NetworkExtensionContract.reasonCodeLateralMovementProtocolAnomaly)
        }
    }

    private static func phase4ProtectionPortFallbackResult(rule: NetworkExtensionRule) -> ProviderFlowResult {
        let decision = NetworkExtensionDecision(
            action: NetworkExtensionContract.actionDeny,
            reason: NetworkExtensionContract.reasonProtectionMatched,
            applicationID: rule.applicationID.trimmingCharacters(in: .whitespacesAndNewlines),
            fqdn: rule.fqdn.trimmingCharacters(in: .whitespacesAndNewlines).lowercased(),
            destinationPort: rule.destinationPort,
            serviceFamily: rule.serviceFamily.trimmingCharacters(in: .whitespacesAndNewlines),
            connectorGroupID: nil,
            protectionMode: rule.protectionMode?.trimmingCharacters(in: .whitespacesAndNewlines),
            protectionReasonCodes: (rule.protectionReasonCodes ?? []).map {
                $0.trimmingCharacters(in: .whitespacesAndNewlines)
            }
        )
        return ProviderFlowResult(providerAction: .deny, runtimeInstalled: false, decision: decision)
    }

    @discardableResult
    public func reloadIfStale() -> String {
        reloadLock.lock()
        defer { reloadLock.unlock() }
        guard let configPath = lastAgentConfigPath else {
            return "skipped_no_config"
        }
        do {
            let config = try loadAgentConfig(from: configPath)
            guard let rulesRef = config.networkExtensionRulesRef?.trimmingCharacters(in: .whitespacesAndNewlines),
                  !rulesRef.isEmpty else {
                return "skipped_missing_rules_ref"
            }
            let configDirectory = URL(fileURLWithPath: configPath).deletingLastPathComponent()
            let rulesURL = try resolveProviderRulesRef(rulesRef, relativeTo: configDirectory)
            let currentDate = rulesFileModificationDate(from: rulesURL)
            if let currentDate, let lastRulesModificationDate {
                guard currentDate > lastRulesModificationDate else {
                    return "skipped_not_newer"
                }
            } else {
                guard currentDate != lastRulesModificationDate else {
                    return "skipped_not_newer"
                }
            }
            let rules = try loadRules(from: rulesURL)
            try NetworkExtensionRulesValidator.validate(rules)
            self.decider = RulesBackedProviderFlowDecider(rules: rules)
            self.loadedRules = rules
            self.lastRulesModificationDate = currentDate
            self.lifecycleState = ProviderLifecycleState(
                status: .running,
                agentConfig: URL(fileURLWithPath: configPath).lastPathComponent,
                rulesManifest: rulesRef,
                tenantID: rules.tenantID,
                runtimeInstalled: false,
                runtimeRunning: false,
                runtimeProvider: .notInstalled,
                rulesLoaded: true,
                ruleCount: rules.rules.count,
                lastError: ""
            )
            return "reloaded"
        } catch {
            return Self.reloadFailureGate(error)
        }
    }

    private static func reloadFailureGate(_ error: Error) -> String {
        guard let lifecycleError = error as? ProviderLifecycleError else {
            return "unknown_failure"
        }
        switch lifecycleError {
        case .configReadFailed:
            return "config_read_failed"
        case .configDecodeFailed:
            return "config_decode_failed"
        case .missingRulesRef:
            return "skipped_missing_rules_ref"
        case .invalidRulesRef:
            return "rules_ref_invalid"
        case .rulesReadFailed:
            return "rules_read_failed"
        case .rulesDecodeFailed:
            return "rules_decode_failed"
        case .rulesValidationFailed:
            return "rules_validation_failed"
        }
    }

    public func stop() {
        reloadLock.lock()
        self.decider = nil
        self.loadedRules = nil
        self.lifecycleState = nil
        self.lastRulesModificationDate = nil
        self.lastAgentConfigPath = nil
        reloadLock.unlock()
    }
}

public struct ProviderLifecycleFlowDecision: Equatable {
    public let primaryResult: ProviderFlowResult
    public let singleRuleLabFallback: ProviderSingleRuleLabFallbackDecision?

    public init(
        primaryResult: ProviderFlowResult,
        singleRuleLabFallback: ProviderSingleRuleLabFallbackDecision?
    ) {
        self.primaryResult = primaryResult
        self.singleRuleLabFallback = singleRuleLabFallback
    }
}

public struct ProviderSingleRuleLabRuleDiagnostic: Equatable {
    public let fqdn: String
    public let destinationPort: Int
    public let generatedAt: String

    public init(fqdn: String, destinationPort: Int, generatedAt: String) {
        self.fqdn = fqdn
        self.destinationPort = destinationPort
        self.generatedAt = generatedAt
    }
}

public struct ProviderSingleRuleLabFallbackDecision: Equatable {
    public let gate: String
    public let providerResult: ProviderFlowResult?
    public let allowFlowAuthorityPortMatch: String

    public init(
        gate: String,
        providerResult: ProviderFlowResult?,
        allowFlowAuthorityPortMatch: String = "extraction_failed"
    ) {
        self.gate = gate
        self.providerResult = providerResult
        self.allowFlowAuthorityPortMatch = allowFlowAuthorityPortMatch
    }
}

public func resolveProviderRulesRef(_ ref: String, relativeTo baseDirectory: URL) throws -> URL {
    let cleaned = ref.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !cleaned.isEmpty else {
        throw ProviderLifecycleError.missingRulesRef
    }
    guard !cleaned.hasPrefix("/") else {
        throw ProviderLifecycleError.invalidRulesRef("absolute paths are not allowed")
    }
    guard !cleaned.hasPrefix("~") else {
        throw ProviderLifecycleError.invalidRulesRef("home-relative paths are not allowed")
    }
    guard !cleaned.contains("\\") else {
        throw ProviderLifecycleError.invalidRulesRef("backslashes are not allowed")
    }
    guard !cleaned.contains("\u{0000}") else {
        throw ProviderLifecycleError.invalidRulesRef("null bytes are not allowed")
    }
    guard cleaned.hasSuffix(".json") else {
        throw ProviderLifecycleError.invalidRulesRef("rules reference must end with .json")
    }
    let segments = cleaned.split(separator: "/", omittingEmptySubsequences: false)
    guard !segments.isEmpty else {
        throw ProviderLifecycleError.invalidRulesRef("rules reference is empty")
    }
    var resolved = baseDirectory
    for segment in segments {
        if segment.isEmpty || segment == "." || segment == ".." {
            throw ProviderLifecycleError.invalidRulesRef("path traversal is not allowed")
        }
        resolved.appendPathComponent(String(segment), isDirectory: false)
    }
    let basePath = baseDirectory.standardizedFileURL.resolvingSymlinksInPath().path
    let resolvedPath = resolved.standardizedFileURL.resolvingSymlinksInPath().path
    if resolvedPath != basePath && !resolvedPath.hasPrefix(basePath.hasSuffix("/") ? basePath : basePath + "/") {
        throw ProviderLifecycleError.invalidRulesRef("resolved path escapes config directory")
    }
    return resolved
}

private func loadAgentConfig(from path: String) throws -> AgentNetworkExtensionConfig {
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

private func loadRules(from url: URL) throws -> NetworkExtensionRules {
    let data: Data
    do {
        data = try Data(contentsOf: url)
    } catch {
        throw ProviderLifecycleError.rulesReadFailed
    }
    do {
        return try JSONDecoder().decode(NetworkExtensionRules.self, from: data)
    } catch {
        throw ProviderLifecycleError.rulesDecodeFailed
    }
}

private func rulesFileModificationDate(from url: URL) -> Date? {
    (try? FileManager.default.attributesOfItem(atPath: url.path))?[.modificationDate] as? Date
}

private func providerLifecycleErrorDescription(_ error: Error) -> String {
    if let lifecycleError = error as? ProviderLifecycleError {
        return lifecycleError.localizedDescription
    }
    if error is NetworkExtensionRulesError {
        return ProviderLifecycleError.rulesValidationFailed.localizedDescription
    }
    return "provider lifecycle failed"
}
