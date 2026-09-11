import Foundation

public enum ProviderPersistentRuntimeStateContractError: Error, Equatable, LocalizedError, Sendable {
    case scopedSteeringBroken
    case persistedReferenceMissing(String)
    case volatileStatePersisted(String)
    case restartSequenceInvalid
    case failSecureRestartMissing
    case rawOrSecretEvidenceIncluded
    case overclaim

    public var errorDescription: String? {
        switch self {
        case .scopedSteeringBroken:
            return "provider persistent runtime state contract must keep steering scoped"
        case .persistedReferenceMissing(let field):
            return "provider persistent runtime state contract missing persisted reference: \(field)"
        case .volatileStatePersisted(let field):
            return "provider persistent runtime state contract must not persist volatile state: \(field)"
        case .restartSequenceInvalid:
            return "provider persistent runtime state restart sequence is invalid"
        case .failSecureRestartMissing:
            return "provider persistent runtime state contract must fail secure on invalid restart state"
        case .rawOrSecretEvidenceIncluded:
            return "provider persistent runtime state contract must not include raw or secret evidence"
        case .overclaim:
            return "provider persistent runtime state contract overclaims runtime execution"
        }
    }
}

public struct ProviderPersistentRuntimeStateContract: Codable, Equatable, Sendable {
    public let schemaVersion: String
    public let stateScope: String
    public let restartSemanticsGate: String
    public let persistedReferenceFields: [String]
    public let volatileStateFields: [String]
    public let restartSequence: [String]
    public let stopSequence: [String]
    public let failSecureRestartStates: [String]
    public let scopedSteeringGate: String
    public let defaultUnmatchedOutboundTCPAction: String
    public let allOutboundTCPCaptureEnabled: Bool
    public let transparentProxyCatchAllEnabled: Bool
    public let developerNormalTrafficPassthrough: Bool
    public let gitGithubBackupPassthrough: Bool
    public let healthEvidenceFields: [String]
    public let rawLogsIncluded: Bool
    public let rawEndpointValuesIncluded: Bool
    public let rawHostValuesIncluded: Bool
    public let rawNetworkValuesIncluded: Bool
    public let rawNEFlowIncluded: Bool
    public let credentialsIncluded: Bool
    public let authMaterialIncluded: Bool
    public let networkExtensionRuntimeStartedByAutomation: String
    public let systemExtensionInstallStartedByAutomation: String
    public let persistentRuntimeDeployClaimed: Bool
    public let productionScaleClaimed: Bool
    public let shippingProductClaimed: Bool
    public let noSecretAttestation: Bool

    public static let current = ProviderPersistentRuntimeStateContract(
        schemaVersion: "productization_p1_ne_provider_persistent_state_contract.v1",
        stateScope: "provider_persistent_state_refs_only_no_live_flow_resume",
        restartSemanticsGate: "restart_rehydrates_rules_from_agent_config_and_closes_live_flows",
        persistedReferenceFields: [
            "agent_config_path_ref",
            "network_extension_rules_ref",
            "network_extension_runtime_diagnostic_ref",
            "network_extension_runtime_evidence_ref"
        ],
        volatileStateFields: [
            "in_memory_provider_flow_decider",
            "loaded_rules_cache",
            "live_ne_app_proxy_flows",
            "live_tcp_copy_registry",
            "runtime_copy_transport_instance",
            "raw_flow_authority"
        ],
        restartSequence: [
            "start_proxy_receives_agent_config_path",
            "validate_agent_config_path",
            "read_agent_config_refs",
            "resolve_rules_ref_relative_to_config_dir",
            "load_and_validate_rules",
            "initialize_runtime_diagnostic_writer",
            "write_start_proxy_running_enum",
            "apply_scoped_steering_rules"
        ],
        stopSequence: [
            "stop_proxy_called",
            "clear_in_memory_decider",
            "clear_loaded_rules_cache",
            "clear_runtime_diagnostic_writer",
            "clear_runtime_copy_transport_instance",
            "complete_stop_without_persisting_live_flows"
        ],
        failSecureRestartStates: [
            "missing_agent_config_path",
            "invalid_agent_config_path",
            "missing_rules_ref",
            "rules_read_failed",
            "rules_validation_failed"
        ],
        scopedSteeringGate: "configured_private_app_destinations_only",
        defaultUnmatchedOutboundTCPAction: "passthrough",
        allOutboundTCPCaptureEnabled: false,
        transparentProxyCatchAllEnabled: false,
        developerNormalTrafficPassthrough: true,
        gitGithubBackupPassthrough: true,
        healthEvidenceFields: [
            "provider_lifecycle_status",
            "provider_rules_reload_gate",
            "provider_loaded_rules_generation_gate",
            "start_proxy_running_observed",
            "transparent_network_settings_applied_observed",
            "last_error_category"
        ],
        rawLogsIncluded: false,
        rawEndpointValuesIncluded: false,
        rawHostValuesIncluded: false,
        rawNetworkValuesIncluded: false,
        rawNEFlowIncluded: false,
        credentialsIncluded: false,
        authMaterialIncluded: false,
        networkExtensionRuntimeStartedByAutomation: "not_run",
        systemExtensionInstallStartedByAutomation: "not_run",
        persistentRuntimeDeployClaimed: false,
        productionScaleClaimed: false,
        shippingProductClaimed: false,
        noSecretAttestation: true
    )

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case stateScope = "state_scope"
        case restartSemanticsGate = "restart_semantics_gate"
        case persistedReferenceFields = "persisted_reference_fields"
        case volatileStateFields = "volatile_state_fields"
        case restartSequence = "restart_sequence"
        case stopSequence = "stop_sequence"
        case failSecureRestartStates = "fail_secure_restart_states"
        case scopedSteeringGate = "scoped_steering_gate"
        case defaultUnmatchedOutboundTCPAction = "default_unmatched_outbound_tcp_action"
        case allOutboundTCPCaptureEnabled = "all_outbound_tcp_capture_enabled"
        case transparentProxyCatchAllEnabled = "transparent_proxy_catch_all_enabled"
        case developerNormalTrafficPassthrough = "developer_normal_traffic_passthrough"
        case gitGithubBackupPassthrough = "git_github_backup_passthrough"
        case healthEvidenceFields = "health_evidence_fields"
        case rawLogsIncluded = "raw_logs_included"
        case rawEndpointValuesIncluded = "raw_endpoint_values_included"
        case rawHostValuesIncluded = "raw_host_values_included"
        case rawNetworkValuesIncluded = "raw_network_values_included"
        case rawNEFlowIncluded = "raw_ne_flow_included"
        case credentialsIncluded = "credentials_included"
        case authMaterialIncluded = "auth_material_included"
        case networkExtensionRuntimeStartedByAutomation = "network_extension_runtime_started_by_codex"
        case systemExtensionInstallStartedByAutomation = "system_extension_install_started_by_codex"
        case persistentRuntimeDeployClaimed = "persistent_runtime_deploy_claimed"
        case productionScaleClaimed = "production_scale_claimed"
        case shippingProductClaimed = "shipping_product_claimed"
        case noSecretAttestation = "no_secret_attestation"
    }
}

public func validateProviderPersistentRuntimeStateContract(
    _ contract: ProviderPersistentRuntimeStateContract = .current
) throws {
    guard contract.scopedSteeringGate == "configured_private_app_destinations_only",
          contract.defaultUnmatchedOutboundTCPAction == "passthrough",
          contract.allOutboundTCPCaptureEnabled == false,
          contract.transparentProxyCatchAllEnabled == false,
          contract.developerNormalTrafficPassthrough,
          contract.gitGithubBackupPassthrough else {
        throw ProviderPersistentRuntimeStateContractError.scopedSteeringBroken
    }

    for field in [
        "agent_config_path_ref",
        "network_extension_rules_ref",
        "network_extension_runtime_diagnostic_ref",
        "network_extension_runtime_evidence_ref"
    ] where !contract.persistedReferenceFields.contains(field) {
        throw ProviderPersistentRuntimeStateContractError.persistedReferenceMissing(field)
    }

    for field in [
        "live_ne_app_proxy_flows",
        "live_tcp_copy_registry",
        "raw_flow_authority"
    ] where !contract.volatileStateFields.contains(field) {
        throw ProviderPersistentRuntimeStateContractError.volatileStatePersisted(field)
    }

    guard contract.restartSequence.first == "start_proxy_receives_agent_config_path",
          contract.restartSequence.contains("load_and_validate_rules"),
          contract.restartSequence.contains("apply_scoped_steering_rules"),
          contract.stopSequence.contains("complete_stop_without_persisting_live_flows") else {
        throw ProviderPersistentRuntimeStateContractError.restartSequenceInvalid
    }

    guard contract.failSecureRestartStates.contains("missing_agent_config_path"),
          contract.failSecureRestartStates.contains("rules_validation_failed") else {
        throw ProviderPersistentRuntimeStateContractError.failSecureRestartMissing
    }

    guard contract.rawLogsIncluded == false,
          contract.rawEndpointValuesIncluded == false,
          contract.rawHostValuesIncluded == false,
          contract.rawNetworkValuesIncluded == false,
          contract.rawNEFlowIncluded == false,
          contract.credentialsIncluded == false,
          contract.authMaterialIncluded == false,
          contract.noSecretAttestation else {
        throw ProviderPersistentRuntimeStateContractError.rawOrSecretEvidenceIncluded
    }

    guard contract.networkExtensionRuntimeStartedByAutomation == "not_run",
          contract.systemExtensionInstallStartedByAutomation == "not_run",
          contract.persistentRuntimeDeployClaimed == false,
          contract.productionScaleClaimed == false,
          contract.shippingProductClaimed == false else {
        throw ProviderPersistentRuntimeStateContractError.overclaim
    }
}
