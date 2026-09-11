import Foundation

public enum ProviderFlowAction: String, Codable, Equatable {
    case openTunnel = "open_tunnel"
    case deny = "deny"
}

public struct ProviderFlowRequest: Codable, Equatable {
    public let host: String
    public let port: Int
    public let sourceBundleID: String?

    enum CodingKeys: String, CodingKey {
        case host
        case port
        case sourceBundleID = "source_bundle_id"
    }

    public init(host: String, port: Int, sourceBundleID: String? = nil) {
        self.host = host
        self.port = port
        self.sourceBundleID = sourceBundleID
    }
}

public struct ProviderFlowResult: Codable, Equatable {
    public let providerAction: ProviderFlowAction
    public let runtimeInstalled: Bool
    public let decision: NetworkExtensionDecision

    enum CodingKeys: String, CodingKey {
        case providerAction = "provider_action"
        case runtimeInstalled = "runtime_installed"
        case decision
    }

    public init(providerAction: ProviderFlowAction, runtimeInstalled: Bool, decision: NetworkExtensionDecision) {
        self.providerAction = providerAction
        self.runtimeInstalled = runtimeInstalled
        self.decision = decision
    }
}

public protocol ProviderFlowDeciding {
    func decide(_ flow: ProviderFlowRequest) -> ProviderFlowResult
}

public final class RulesBackedProviderFlowDecider: ProviderFlowDeciding {
    private let rules: NetworkExtensionRules

    public init(rules: NetworkExtensionRules) {
        self.rules = rules
    }

    public func decide(_ flow: ProviderFlowRequest) -> ProviderFlowResult {
        let decision = NetworkExtensionFlowEvaluator.evaluate(rules, host: flow.host, port: flow.port)
        let action: ProviderFlowAction = decision.action == NetworkExtensionContract.actionTunnel ? .openTunnel : .deny
        return ProviderFlowResult(
            providerAction: action,
            runtimeInstalled: false,
            decision: decision
        )
    }
}
