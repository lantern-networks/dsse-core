import XCTest
@testable import DsseNetworkExtensionContract

final class ProviderPersistentRuntimeStateContractTests: XCTestCase {
    func testCurrentContractPreservesScopedSteeringAndNoRuntimeExecutionClaim() throws {
        let contract = ProviderPersistentRuntimeStateContract.current

        XCTAssertNoThrow(try validateProviderPersistentRuntimeStateContract(contract))
        XCTAssertEqual(contract.schemaVersion, "productization_p1_ne_provider_persistent_state_contract.v1")
        XCTAssertEqual(contract.scopedSteeringGate, "configured_private_app_destinations_only")
        XCTAssertEqual(contract.defaultUnmatchedOutboundTCPAction, "passthrough")
        XCTAssertFalse(contract.allOutboundTCPCaptureEnabled)
        XCTAssertFalse(contract.transparentProxyCatchAllEnabled)
        XCTAssertTrue(contract.developerNormalTrafficPassthrough)
        XCTAssertTrue(contract.gitGithubBackupPassthrough)
        XCTAssertEqual(contract.networkExtensionRuntimeStartedByAutomation, "not_run")
        XCTAssertEqual(contract.systemExtensionInstallStartedByAutomation, "not_run")
        XCTAssertFalse(contract.persistentRuntimeDeployClaimed)
        XCTAssertFalse(contract.productionScaleClaimed)
        XCTAssertFalse(contract.shippingProductClaimed)
    }

    func testCurrentContractSeparatesPersistedRefsFromVolatileLiveState() throws {
        let contract = ProviderPersistentRuntimeStateContract.current

        XCTAssertEqual(
            contract.persistedReferenceFields,
            [
                "agent_config_path_ref",
                "network_extension_rules_ref",
                "network_extension_runtime_diagnostic_ref",
                "network_extension_runtime_evidence_ref"
            ]
        )
        XCTAssertTrue(contract.volatileStateFields.contains("live_ne_app_proxy_flows"))
        XCTAssertTrue(contract.volatileStateFields.contains("live_tcp_copy_registry"))
        XCTAssertTrue(contract.volatileStateFields.contains("raw_flow_authority"))
        XCTAssertFalse(contract.persistedReferenceFields.contains("live_ne_app_proxy_flows"))
        XCTAssertFalse(contract.persistedReferenceFields.contains("raw_flow_authority"))
        XCTAssertTrue(contract.stopSequence.contains("complete_stop_without_persisting_live_flows"))
    }

    func testCurrentContractRestartSequenceFailsSecureBeforeRuntimeClaim() throws {
        let contract = ProviderPersistentRuntimeStateContract.current

        XCTAssertEqual(contract.restartSequence.first, "start_proxy_receives_agent_config_path")
        XCTAssertTrue(contract.restartSequence.contains("read_agent_config_refs"))
        XCTAssertTrue(contract.restartSequence.contains("load_and_validate_rules"))
        XCTAssertTrue(contract.restartSequence.contains("write_start_proxy_running_enum"))
        XCTAssertTrue(contract.restartSequence.contains("apply_scoped_steering_rules"))
        XCTAssertTrue(contract.failSecureRestartStates.contains("missing_agent_config_path"))
        XCTAssertTrue(contract.failSecureRestartStates.contains("invalid_agent_config_path"))
        XCTAssertTrue(contract.failSecureRestartStates.contains("rules_validation_failed"))
        XCTAssertEqual(contract.restartSemanticsGate, "restart_rehydrates_rules_from_agent_config_and_closes_live_flows")
    }

    func testValidateRejectsAllOutboundCapture() throws {
        var contract = ProviderPersistentRuntimeStateContract.current
        contract = ProviderPersistentRuntimeStateContract(
            schemaVersion: contract.schemaVersion,
            stateScope: contract.stateScope,
            restartSemanticsGate: contract.restartSemanticsGate,
            persistedReferenceFields: contract.persistedReferenceFields,
            volatileStateFields: contract.volatileStateFields,
            restartSequence: contract.restartSequence,
            stopSequence: contract.stopSequence,
            failSecureRestartStates: contract.failSecureRestartStates,
            scopedSteeringGate: contract.scopedSteeringGate,
            defaultUnmatchedOutboundTCPAction: contract.defaultUnmatchedOutboundTCPAction,
            allOutboundTCPCaptureEnabled: true,
            transparentProxyCatchAllEnabled: contract.transparentProxyCatchAllEnabled,
            developerNormalTrafficPassthrough: contract.developerNormalTrafficPassthrough,
            gitGithubBackupPassthrough: contract.gitGithubBackupPassthrough,
            healthEvidenceFields: contract.healthEvidenceFields,
            rawLogsIncluded: contract.rawLogsIncluded,
            rawEndpointValuesIncluded: contract.rawEndpointValuesIncluded,
            rawHostValuesIncluded: contract.rawHostValuesIncluded,
            rawNetworkValuesIncluded: contract.rawNetworkValuesIncluded,
            rawNEFlowIncluded: contract.rawNEFlowIncluded,
            credentialsIncluded: contract.credentialsIncluded,
            authMaterialIncluded: contract.authMaterialIncluded,
            networkExtensionRuntimeStartedByAutomation: contract.networkExtensionRuntimeStartedByAutomation,
            systemExtensionInstallStartedByAutomation: contract.systemExtensionInstallStartedByAutomation,
            persistentRuntimeDeployClaimed: contract.persistentRuntimeDeployClaimed,
            productionScaleClaimed: contract.productionScaleClaimed,
            shippingProductClaimed: contract.shippingProductClaimed,
            noSecretAttestation: contract.noSecretAttestation
        )

        XCTAssertThrowsError(try validateProviderPersistentRuntimeStateContract(contract)) { error in
            XCTAssertEqual(error as? ProviderPersistentRuntimeStateContractError, .scopedSteeringBroken)
        }
    }

    func testValidateRejectsRawFlowPersistenceAndOverclaim() throws {
        let base = ProviderPersistentRuntimeStateContract.current
        let rawContract = ProviderPersistentRuntimeStateContract(
            schemaVersion: base.schemaVersion,
            stateScope: base.stateScope,
            restartSemanticsGate: base.restartSemanticsGate,
            persistedReferenceFields: base.persistedReferenceFields,
            volatileStateFields: base.volatileStateFields,
            restartSequence: base.restartSequence,
            stopSequence: base.stopSequence,
            failSecureRestartStates: base.failSecureRestartStates,
            scopedSteeringGate: base.scopedSteeringGate,
            defaultUnmatchedOutboundTCPAction: base.defaultUnmatchedOutboundTCPAction,
            allOutboundTCPCaptureEnabled: base.allOutboundTCPCaptureEnabled,
            transparentProxyCatchAllEnabled: base.transparentProxyCatchAllEnabled,
            developerNormalTrafficPassthrough: base.developerNormalTrafficPassthrough,
            gitGithubBackupPassthrough: base.gitGithubBackupPassthrough,
            healthEvidenceFields: base.healthEvidenceFields,
            rawLogsIncluded: base.rawLogsIncluded,
            rawEndpointValuesIncluded: base.rawEndpointValuesIncluded,
            rawHostValuesIncluded: base.rawHostValuesIncluded,
            rawNetworkValuesIncluded: base.rawNetworkValuesIncluded,
            rawNEFlowIncluded: true,
            credentialsIncluded: base.credentialsIncluded,
            authMaterialIncluded: base.authMaterialIncluded,
            networkExtensionRuntimeStartedByAutomation: base.networkExtensionRuntimeStartedByAutomation,
            systemExtensionInstallStartedByAutomation: base.systemExtensionInstallStartedByAutomation,
            persistentRuntimeDeployClaimed: base.persistentRuntimeDeployClaimed,
            productionScaleClaimed: base.productionScaleClaimed,
            shippingProductClaimed: base.shippingProductClaimed,
            noSecretAttestation: base.noSecretAttestation
        )
        XCTAssertThrowsError(try validateProviderPersistentRuntimeStateContract(rawContract)) { error in
            XCTAssertEqual(error as? ProviderPersistentRuntimeStateContractError, .rawOrSecretEvidenceIncluded)
        }

        let overclaimed = ProviderPersistentRuntimeStateContract(
            schemaVersion: base.schemaVersion,
            stateScope: base.stateScope,
            restartSemanticsGate: base.restartSemanticsGate,
            persistedReferenceFields: base.persistedReferenceFields,
            volatileStateFields: base.volatileStateFields,
            restartSequence: base.restartSequence,
            stopSequence: base.stopSequence,
            failSecureRestartStates: base.failSecureRestartStates,
            scopedSteeringGate: base.scopedSteeringGate,
            defaultUnmatchedOutboundTCPAction: base.defaultUnmatchedOutboundTCPAction,
            allOutboundTCPCaptureEnabled: base.allOutboundTCPCaptureEnabled,
            transparentProxyCatchAllEnabled: base.transparentProxyCatchAllEnabled,
            developerNormalTrafficPassthrough: base.developerNormalTrafficPassthrough,
            gitGithubBackupPassthrough: base.gitGithubBackupPassthrough,
            healthEvidenceFields: base.healthEvidenceFields,
            rawLogsIncluded: base.rawLogsIncluded,
            rawEndpointValuesIncluded: base.rawEndpointValuesIncluded,
            rawHostValuesIncluded: base.rawHostValuesIncluded,
            rawNetworkValuesIncluded: base.rawNetworkValuesIncluded,
            rawNEFlowIncluded: base.rawNEFlowIncluded,
            credentialsIncluded: base.credentialsIncluded,
            authMaterialIncluded: base.authMaterialIncluded,
            networkExtensionRuntimeStartedByAutomation: "run",
            systemExtensionInstallStartedByAutomation: base.systemExtensionInstallStartedByAutomation,
            persistentRuntimeDeployClaimed: true,
            productionScaleClaimed: base.productionScaleClaimed,
            shippingProductClaimed: base.shippingProductClaimed,
            noSecretAttestation: base.noSecretAttestation
        )
        XCTAssertThrowsError(try validateProviderPersistentRuntimeStateContract(overclaimed)) { error in
            XCTAssertEqual(error as? ProviderPersistentRuntimeStateContractError, .overclaim)
        }
    }
}
