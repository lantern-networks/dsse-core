import Foundation
import Network

public enum NetworkExtensionContract {
    public static let schemaVersion = "network_extension_steering_rules.v1"
    public static let actionTunnel = "tunnel"
    public static let actionDeny = "deny"
    public static let reasonMatched = "matched_network_extension_rule"
    public static let reasonDefaultTunnel = "matched_default_network_extension_tunnel"
    public static let reasonProtectionMatched = "matched_ac09_protection_rule"
    public static let reasonNoMatch = "no_matching_network_extension_rule"
    public static let reasonInvalidFlow = "invalid_flow_authority"
    public static let reasonInvalidRules = "invalid_network_extension_rules"
    public static let protectionModeAC09RansomwareLateralMovement = "ac09_ransomware_lateral_movement"
    public static let reasonCodeRansomwareProtectionModeActive = "ransomware_protection_mode_active"
    public static let reasonCodeLateralMovementProtocolAnomaly = "risk_signal_lateral_movement_protocol_anomaly"
}

public struct NetworkExtensionRules: Codable, Equatable {
    public let schemaVersion: String
    public let tenantID: String
    public let version: String
    public let sourceProtectedAppMap: String
    public let generatedAt: String
    public let defaultAction: String
    public let rules: [NetworkExtensionRule]

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case tenantID = "tenant_id"
        case version
        case sourceProtectedAppMap = "source_protected_app_map"
        case generatedAt = "generated_at"
        case defaultAction = "default_action"
        case rules
    }

    public static func load(from path: String) throws -> NetworkExtensionRules {
        let url = URL(fileURLWithPath: path)
        let data = try Data(contentsOf: url)
        let decoder = JSONDecoder()
        return try decoder.decode(NetworkExtensionRules.self, from: data)
    }
}

public struct NetworkExtensionRule: Codable, Equatable {
    public let applicationID: String
    public let fqdn: String
    public let destinationPort: Int
    public let serviceFamily: String
    public let steeringMode: String
    public let action: String
    public let connectorGroupID: String?
    public let protectionMode: String?
    public let protectionReasonCodes: [String]?

    enum CodingKeys: String, CodingKey {
        case applicationID = "application_id"
        case fqdn
        case destinationPort = "destination_port"
        case serviceFamily = "service_family"
        case steeringMode = "steering_mode"
        case action
        case connectorGroupID = "connector_group_id"
        case protectionMode = "protection_mode"
        case protectionReasonCodes = "protection_reason_codes"
    }
}

public struct NetworkExtensionDecision: Codable, Equatable {
    public let action: String
    public let reason: String
    public let applicationID: String?
    public let fqdn: String?
    public let destinationPort: Int?
    public let serviceFamily: String?
    public let connectorGroupID: String?
    public let protectionMode: String?
    public let protectionReasonCodes: [String]

    public init(
        action: String,
        reason: String,
        applicationID: String?,
        fqdn: String?,
        destinationPort: Int?,
        serviceFamily: String?,
        connectorGroupID: String?,
        protectionMode: String? = nil,
        protectionReasonCodes: [String] = []
    ) {
        self.action = action
        self.reason = reason
        self.applicationID = applicationID
        self.fqdn = fqdn
        self.destinationPort = destinationPort
        self.serviceFamily = serviceFamily
        self.connectorGroupID = connectorGroupID
        self.protectionMode = protectionMode
        self.protectionReasonCodes = protectionReasonCodes
    }

    enum CodingKeys: String, CodingKey {
        case action
        case reason
        case applicationID = "application_id"
        case fqdn
        case destinationPort = "destination_port"
        case serviceFamily = "service_family"
        case connectorGroupID = "connector_group_id"
        case protectionMode = "protection_mode"
        case protectionReasonCodes = "protection_reason_codes"
    }
}

public enum NetworkExtensionRulesError: Error, Equatable, LocalizedError {
    case invalidSchemaVersion
    case missingTenantID
    case missingVersion
    case missingSourceProtectedAppMap
    case missingGeneratedAt
    case invalidDefaultAction
    case emptyRules
    case missingApplicationID
    case invalidFQDN(applicationID: String)
    case invalidDestinationPort(applicationID: String)
    case missingServiceFamily(applicationID: String)
    case invalidSteeringMode(applicationID: String)
    case invalidAction(applicationID: String)
    case invalidProtectionRule(applicationID: String)
    case duplicateDestination(String)

    public var errorDescription: String? {
        switch self {
        case .invalidSchemaVersion:
            return "network extension rules schema_version must be \(NetworkExtensionContract.schemaVersion)"
        case .missingTenantID:
            return "network extension rules tenant_id is required"
        case .missingVersion:
            return "network extension rules version is required"
        case .missingSourceProtectedAppMap:
            return "network extension rules source_protected_app_map is required"
        case .missingGeneratedAt:
            return "network extension rules generated_at is required"
        case .invalidDefaultAction:
            return "network extension rules default_action must be deny or tunnel"
        case .emptyRules:
            return "network extension rules must not be empty unless default_action is tunnel"
        case .missingApplicationID:
            return "network extension rule application_id is required"
        case .invalidFQDN(let applicationID):
            return "network extension rule fqdn is invalid for \(applicationID)"
        case .invalidDestinationPort(let applicationID):
            return "network extension rule destination_port is invalid for \(applicationID)"
        case .missingServiceFamily(let applicationID):
            return "network extension rule service_family is required for \(applicationID)"
        case .invalidSteeringMode(let applicationID):
            return "network extension rule steering_mode must be network_extension for \(applicationID)"
        case .invalidAction(let applicationID):
            return "network extension rule action must be tunnel or deny for \(applicationID)"
        case .invalidProtectionRule(let applicationID):
            return "network extension deny rule must carry AC-09 protection semantics for \(applicationID)"
        case .duplicateDestination(let destination):
            return "duplicate network extension destination \(destination)"
        }
    }
}

public enum NetworkExtensionRulesValidator {
    public static func validate(_ rules: NetworkExtensionRules) throws {
        guard rules.schemaVersion.trimmingCharacters(in: .whitespacesAndNewlines) == NetworkExtensionContract.schemaVersion else {
            throw NetworkExtensionRulesError.invalidSchemaVersion
        }
        guard !rules.tenantID.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw NetworkExtensionRulesError.missingTenantID
        }
        guard !rules.version.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw NetworkExtensionRulesError.missingVersion
        }
        guard !rules.sourceProtectedAppMap.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw NetworkExtensionRulesError.missingSourceProtectedAppMap
        }
        guard !rules.generatedAt.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw NetworkExtensionRulesError.missingGeneratedAt
        }
        let defaultAction = rules.defaultAction.trimmingCharacters(in: .whitespacesAndNewlines)
        guard defaultAction == NetworkExtensionContract.actionDeny || defaultAction == NetworkExtensionContract.actionTunnel else {
            throw NetworkExtensionRulesError.invalidDefaultAction
        }
        guard !rules.rules.isEmpty || defaultAction == NetworkExtensionContract.actionTunnel else {
            throw NetworkExtensionRulesError.emptyRules
        }

        var seen: Set<String> = []
        for rule in rules.rules {
            let applicationID = rule.applicationID.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !applicationID.isEmpty else {
                throw NetworkExtensionRulesError.missingApplicationID
            }
            guard let host = normalizeHost(rule.fqdn) else {
                throw NetworkExtensionRulesError.invalidFQDN(applicationID: applicationID)
            }
            guard validPort(rule.destinationPort) else {
                throw NetworkExtensionRulesError.invalidDestinationPort(applicationID: applicationID)
            }
            guard !rule.serviceFamily.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                throw NetworkExtensionRulesError.missingServiceFamily(applicationID: applicationID)
            }
            guard rule.steeringMode.trimmingCharacters(in: .whitespacesAndNewlines) == "network_extension" else {
                throw NetworkExtensionRulesError.invalidSteeringMode(applicationID: applicationID)
            }
            let action = rule.action.trimmingCharacters(in: .whitespacesAndNewlines)
            guard action == NetworkExtensionContract.actionTunnel || action == NetworkExtensionContract.actionDeny else {
                throw NetworkExtensionRulesError.invalidAction(applicationID: applicationID)
            }
            if action == NetworkExtensionContract.actionDeny {
                let protectionMode = rule.protectionMode?.trimmingCharacters(in: .whitespacesAndNewlines)
                let reasonCodes = Set((rule.protectionReasonCodes ?? []).map {
                    $0.trimmingCharacters(in: .whitespacesAndNewlines)
                })
                guard protectionMode == NetworkExtensionContract.protectionModeAC09RansomwareLateralMovement,
                      reasonCodes.contains(NetworkExtensionContract.reasonCodeRansomwareProtectionModeActive),
                      reasonCodes.contains(NetworkExtensionContract.reasonCodeLateralMovementProtocolAnomaly) else {
                    throw NetworkExtensionRulesError.invalidProtectionRule(applicationID: applicationID)
                }
            }
            let destination = destinationKey(host: host, port: rule.destinationPort)
            guard !seen.contains(destination) else {
                throw NetworkExtensionRulesError.duplicateDestination(destination)
            }
            seen.insert(destination)
        }
    }
}

public enum NetworkExtensionFlowEvaluator {
    public static func evaluate(_ rules: NetworkExtensionRules, host: String, port: Int) -> NetworkExtensionDecision {
        do {
            try NetworkExtensionRulesValidator.validate(rules)
        } catch {
            return NetworkExtensionDecision(
                action: NetworkExtensionContract.actionDeny,
                reason: NetworkExtensionContract.reasonInvalidRules,
                applicationID: nil,
                fqdn: nil,
                destinationPort: nil,
                serviceFamily: nil,
                connectorGroupID: nil
            )
        }
        guard let normalizedAuthorityHost = normalizeFlowAuthorityHost(host), validPort(port) else {
            return NetworkExtensionDecision(
                action: NetworkExtensionContract.actionDeny,
                reason: NetworkExtensionContract.reasonInvalidFlow,
                applicationID: nil,
                fqdn: nil,
                destinationPort: nil,
                serviceFamily: nil,
                connectorGroupID: nil
            )
        }
        let normalizedRuleCandidateHost = normalizeHost(host)
        for rule in rules.rules {
            guard let normalizedRuleCandidateHost else {
                continue
            }
            guard let ruleHost = normalizeHost(rule.fqdn) else {
                continue
            }
            if ruleHost != normalizedRuleCandidateHost || rule.destinationPort != port {
                continue
            }
            let connectorGroupID = rule.connectorGroupID?.trimmingCharacters(in: .whitespacesAndNewlines)
            let action = rule.action.trimmingCharacters(in: .whitespacesAndNewlines)
            let reason = action == NetworkExtensionContract.actionTunnel
                ? NetworkExtensionContract.reasonMatched
                : NetworkExtensionContract.reasonProtectionMatched
            return NetworkExtensionDecision(
                action: action,
                reason: reason,
                applicationID: rule.applicationID.trimmingCharacters(in: .whitespacesAndNewlines),
                fqdn: ruleHost,
                destinationPort: rule.destinationPort,
                serviceFamily: rule.serviceFamily.trimmingCharacters(in: .whitespacesAndNewlines),
                connectorGroupID: connectorGroupID?.isEmpty == true ? nil : connectorGroupID,
                protectionMode: action == NetworkExtensionContract.actionDeny
                    ? rule.protectionMode?.trimmingCharacters(in: .whitespacesAndNewlines)
                    : nil,
                protectionReasonCodes: action == NetworkExtensionContract.actionDeny
                    ? (rule.protectionReasonCodes ?? []).map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
                    : []
            )
        }
        if rules.defaultAction.trimmingCharacters(in: .whitespacesAndNewlines) == NetworkExtensionContract.actionTunnel {
            return NetworkExtensionDecision(
                action: NetworkExtensionContract.actionTunnel,
                reason: NetworkExtensionContract.reasonDefaultTunnel,
                applicationID: "default_network_extension_tunnel",
                fqdn: normalizedAuthorityHost,
                destinationPort: port,
                serviceFamily: defaultServiceFamily(port),
                connectorGroupID: nil
            )
        }
        return NetworkExtensionDecision(
            action: NetworkExtensionContract.actionDeny,
            reason: NetworkExtensionContract.reasonNoMatch,
            applicationID: nil,
            fqdn: nil,
            destinationPort: nil,
            serviceFamily: nil,
            connectorGroupID: nil
        )
    }
}

private func defaultServiceFamily(_ port: Int) -> String {
    switch port {
    case 443:
        return "https"
    case 80:
        return "http"
    default:
        return "tcp"
    }
}

public func normalizeHost(_ host: String) -> String? {
    var normalized = host.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    if normalized.hasSuffix(".") {
        normalized.removeLast()
    }
    if normalized.isEmpty {
        return nil
    }
    if normalized.contains("*") || normalized.contains("/") || normalized.contains(":") || normalized.contains("..") {
        return nil
    }
    for scalar in normalized.unicodeScalars {
        if scalar.value <= 0x20 || scalar.value > 0x7E {
            return nil
        }
    }
    let labels = normalized.split(separator: ".", omittingEmptySubsequences: false)
    if isIPv4Literal(labels) {
        return nil
    }
    for label in labels {
        if label.isEmpty || label.count > 63 || label.hasPrefix("-") || label.hasSuffix("-") {
            return nil
        }
        for scalar in label.unicodeScalars {
            let value = scalar.value
            let isLowercaseLetter = value >= 0x61 && value <= 0x7A
            let isDigit = value >= 0x30 && value <= 0x39
            let isHyphen = value == 0x2D
            if !isLowercaseLetter && !isDigit && !isHyphen {
                return nil
            }
        }
    }
    return normalized
}

public func normalizeFlowAuthorityHost(_ host: String) -> String? {
    var normalized = host.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    if normalized.hasPrefix("[") && normalized.hasSuffix("]") {
        normalized = String(normalized.dropFirst().dropLast())
    }
    if normalized.isEmpty {
        return nil
    }
    for scalar in normalized.unicodeScalars {
        if scalar.value <= 0x20 || scalar.value > 0x7E {
            return nil
        }
    }
    if normalized.contains("*") || normalized.contains("/") || normalized.contains("\\") || normalized.contains("@") || normalized.contains("%") {
        return nil
    }
    if let ipLiteral = normalizeNonLoopbackIPLiteral(normalized) {
        return ipLiteral
    }
    if normalized.contains(":") {
        return nil
    }
    return normalizeHost(normalized)
}

private func isIPv4Literal(_ labels: [Substring]) -> Bool {
    if labels.count != 4 {
        return false
    }
    for label in labels {
        if label.isEmpty {
            return false
        }
        for scalar in label.unicodeScalars {
            if scalar.value < 0x30 || scalar.value > 0x39 {
                return false
            }
        }
    }
    return true
}

private func normalizeNonLoopbackIPLiteral(_ host: String) -> String? {
    if IPv4Address(host) != nil {
        let labels = host.split(separator: ".", omittingEmptySubsequences: false)
        guard labels.count == 4, labels.first != "127" else {
            return nil
        }
        return host
    }
    if let address = IPv6Address(host) {
        guard !isLoopbackIPv6Literal(address) else {
            return nil
        }
        return host
    }
    return nil
}

private func isLoopbackIPv6Literal(_ address: IPv6Address) -> Bool {
    let bytes = Array(address.rawValue)
    guard bytes.count == 16 else {
        return true
    }
    if bytes.prefix(15).allSatisfy({ $0 == 0 }) && bytes[15] == 1 {
        return true
    }
    if bytes.prefix(10).allSatisfy({ $0 == 0 }) && bytes[10] == 0xff && bytes[11] == 0xff && bytes[12] == 127 {
        return true
    }
    if bytes.prefix(12).allSatisfy({ $0 == 0 }) && bytes[12] == 127 {
        return true
    }
    return false
}

public func validPort(_ port: Int) -> Bool {
    port > 0 && port <= 65_535
}

public func destinationKey(host: String, port: Int) -> String {
    "\(host):\(port)"
}
