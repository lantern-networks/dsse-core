@testable import DsseAppProxyProviderSkeleton
import DsseNetworkExtensionContract
import Foundation
import Network
import XCTest

private final class LegacyRemoteEndpointProbe: NSObject {
    @objc let hostname: String
    @objc let port: String

    init(hostname: String, port: String) {
        self.hostname = hostname
        self.port = port
    }
}

final class HandleNewFlowTakeoverTests: XCTestCase {
    // Kill-switch invariant: LAB fail-open (direct egress) applies ONLY to a REACHABILITY block; an admission
    // deny (device revoked/not-enrolled) is ALWAYS deny_closed, so fail-open can never bypass a revocation.
    func testRegionEgressActionNeverFailsOpenOnAdmissionDeny() {
        typealias A = DsseAppProxyProvider.RegionEgressAction
        // Not blocked -> proceed, regardless of arming.
        XCTAssertEqual(DsseAppProxyProvider.regionEgressAction(blocked: false, admissionDenied: false, failOpenArmed: true), A.proceed)
        // Reachability block (no admission deny): armed -> decline_direct; disarmed -> deny_closed.
        XCTAssertEqual(DsseAppProxyProvider.regionEgressAction(blocked: true, admissionDenied: false, failOpenArmed: true), A.declineDirect)
        XCTAssertEqual(DsseAppProxyProvider.regionEgressAction(blocked: true, admissionDenied: false, failOpenArmed: false), A.denyClosed)
        // Admission deny (revocation): ALWAYS deny_closed — even with fail-open armed (the fix).
        XCTAssertEqual(DsseAppProxyProvider.regionEgressAction(blocked: true, admissionDenied: true, failOpenArmed: true), A.denyClosed)
        XCTAssertEqual(DsseAppProxyProvider.regionEgressAction(blocked: true, admissionDenied: true, failOpenArmed: false), A.denyClosed)
    }

    func testMatchedTCPFlowTakeoverWiresLiveCopyContractWithoutRuntimeCopyOverclaim() throws {
        let manager = try startedLifecycleManager()

        let report = DsseAppProxyProvider.handleNewFlowCompileHarness(
            input: ProviderFlowAuthorityInput(
                transport: .tcp,
                remoteHost: "dummy-postgres.local",
                remotePort: 5432
            ),
            lifecycleManager: manager
        )

        XCTAssertEqual(report.status, "ok")
        XCTAssertEqual(report.flowExtractionStatus, .ok)
        XCTAssertEqual(report.flowExtractionReason, .extracted)
        XCTAssertEqual(report.providerAction, .openTunnel)
        XCTAssertEqual(report.action, NetworkExtensionContract.actionTunnel)
        XCTAssertEqual(report.reason, NetworkExtensionContract.reasonMatched)
        XCTAssertTrue(report.acceptFlow)
        XCTAssertEqual(report.returnAction, "take_over_matched_flow_live_copy_real_edge_transport_reviewed")
        XCTAssertEqual(report.flowCopySkeletonStatus, "planned")
        XCTAssertEqual(report.flowCopyAction, "drive_live_runtime_copy_real_edge_transport_configured_reviewed")
        XCTAssertEqual(report.flowCopyMode, "tcp_bidirectional_live_copy")
        XCTAssertEqual(report.flowCopyImplementation, DsseLocalRuntimeCopyImplementationContract.implementation)
        XCTAssertTrue(report.flowCopyReviewBoundaryRequired)
        assertRuntimeCopyNotStarted(report)

        let guardSkeleton = report.flowCopyGuardSkeleton
        XCTAssertFalse(guardSkeleton.copyEnablementReady)
        XCTAssertFalse(guardSkeleton.acceptFlowBeforeGuardReady)
        XCTAssertTrue(guardSkeleton.connectionRegistryRequired)
        XCTAssertTrue(guardSkeleton.byteCapRequired)
        XCTAssertTrue(guardSkeleton.idleTimeoutRequired)
        XCTAssertTrue(guardSkeleton.closeCleanupRequired)
        XCTAssertTrue(guardSkeleton.backpressureRequired)
        XCTAssertTrue(guardSkeleton.tenantScopeRequired)
        XCTAssertTrue(guardSkeleton.auditEventsRequired)
        XCTAssertFalse(guardSkeleton.tenantScopeRuntimeResolved)
        XCTAssertEqual(guardSkeleton.status, "guard_enforced_local_compile_test_reviewed")
        XCTAssertEqual(guardSkeleton.implementation, "live_runtime_copy_guard_enforced_local_compile_test")
        XCTAssertTrue(guardSkeleton.connectionRegistrySkeleton.runtimeConnected)
    }

    func testM1137MatchedHandleNewFlowTakeoverDrivesLiveCopyContractCompileOnly() throws {
        let manager = try startedLifecycleManager()
        let upstreamPayload = Data("client-bytes".utf8)
        let downstreamPayload = Data("private-response".utf8)
        let flow = MockProviderTCPFlowCopyIO(upstreamPayload: upstreamPayload)
        let transport = RecordingRuntimeCopyTransport(downstreamPayload: downstreamPayload)
        let progressEvents = RuntimeCopyProgressBox()
        let completion = expectation(description: " matched handleNewFlow drove live copy contract")
        let completedResult = RuntimeCopyResultBox()

        let report = DsseAppProxyProvider.handleNewFlowCompileHarness(
            input: ProviderFlowAuthorityInput(
                transport: .tcp,
                remoteHost: "dummy-postgres.local",
                remotePort: 5432
            ),
            lifecycleManager: manager
        )

        XCTAssertTrue(report.acceptFlow)
        XCTAssertEqual(report.returnAction, "take_over_matched_flow_live_copy_real_edge_transport_reviewed")
        XCTAssertNotEqual(report.returnAction, "deny_closed_until_tcp_tunnel_copy")
        XCTAssertEqual(report.flowCopyImplementation, DsseLocalRuntimeCopyImplementationContract.implementation)

        let providerResult = manager.decide(ProviderFlowRequest(host: "dummy-postgres.local", port: 5432))
        DsseAppProxyProvider.driveLiveRuntimeCopyForMatchedFlow(
            flow: flow,
            providerResult: providerResult,
            lifecycleState: manager.state,
            destination: ProviderFlowRequest(host: "dummy-postgres.local", port: 5432),
            transport: transport,
            progressHandler: { progress in
                progressEvents.append(progress)
            }
        ) { result in
            completedResult.result = result
            completion.fulfill()
        }
        wait(for: [completion], timeout: 1.0)

        let result = try XCTUnwrap(completedResult.result).get()
        XCTAssertTrue(flow.opened)
        XCTAssertEqual(flow.readCount, 1)
        XCTAssertEqual(flow.writtenPayloads, [downstreamPayload])
        XCTAssertTrue(flow.closedRead)
        XCTAssertTrue(flow.closedWrite)
        XCTAssertEqual(transport.seenPayloads, [upstreamPayload])
        XCTAssertEqual(transport.seenMetadata.first?.destinationHost, "dummy-postgres.local")
        XCTAssertEqual(transport.seenMetadata.first?.destinationPort, 5432)
        XCTAssertEqual(result.bytesUp, upstreamPayload.count)
        XCTAssertEqual(result.bytesDown, downstreamPayload.count)
        XCTAssertEqual(result.implementation, DsseLocalRuntimeCopyImplementationContract.implementation)
        XCTAssertTrue(result.networkExtensionFlowOpened)
        XCTAssertTrue(result.tcpPayloadCopyStarted)
        XCTAssertTrue(result.flowPayloadReadStarted)
        XCTAssertTrue(result.flowPayloadWriteStarted)
        XCTAssertEqual(progressEvents.values, [
            .liveCopyStarted,
            .flowOpenCompleted,
            .upstreamReadCompleted(bytes: upstreamPayload.count),
            .edgeRoundTripStarted,
            .edgeRoundTripRequestSent,
            .edgeRoundTripResponseBodyReceived,
            .edgeRoundTripCompleted,
            .downstreamWriteStarted,
            .downstreamWriteCompleted
        ])
    }

    func testM1139PolicyDrivenDefaultDenyInProcessBoundaryEmitsMetadataOnlyAuditEvidence() throws {
        let manager = try startedLifecycleManager()
        let upstreamPayload = Data("client-payload".utf8)
        let downstreamPayload = Data("private-response".utf8)
        let flow = MockProviderTCPFlowCopyIO(upstreamPayload: upstreamPayload)
        let transport = RecordingRuntimeCopyTransport(downstreamPayload: downstreamPayload)
        let progressEvents = RuntimeCopyProgressBox()
        let completion = expectation(description: " allow path completed reviewed copy")
        let completedResult = RuntimeCopyResultBox()

        let allowInput = ProviderFlowAuthorityInput(
            transport: .tcp,
            remoteHost: "dummy-postgres.local",
            remotePort: 5432
        )
        let allowReport = DsseAppProxyProvider.handleNewFlowCompileHarness(
            input: allowInput,
            lifecycleManager: manager
        )
        XCTAssertTrue(allowReport.acceptFlow)
        XCTAssertEqual(allowReport.action, NetworkExtensionContract.actionTunnel)
        XCTAssertEqual(allowReport.reason, NetworkExtensionContract.reasonMatched)
        XCTAssertEqual(allowReport.returnAction, "take_over_matched_flow_live_copy_real_edge_transport_reviewed")

        let providerResult = manager.decide(ProviderFlowRequest(host: "dummy-postgres.local", port: 5432))
        DsseAppProxyProvider.driveLiveRuntimeCopyForMatchedFlow(
            flow: flow,
            providerResult: providerResult,
            lifecycleState: manager.state,
            transport: transport,
            progressHandler: { progress in
                progressEvents.append(progress)
            }
        ) { result in
            completedResult.result = result
            completion.fulfill()
        }
        wait(for: [completion], timeout: 1.0)

        let allowCopyResult = try XCTUnwrap(completedResult.result).get()
        let allowEvidence = DsseAppProxyProvider.policyDrivenHandleNewFlowInProcessAuditEvidence(
            input: allowInput,
            lifecycleManager: manager,
            copyResult: allowCopyResult
        )
        XCTAssertEqual(allowEvidence.status, "ok")
        XCTAssertEqual(allowEvidence.providerRuntimeSessionKeyKind, "nonsecret_lab_runtime_pairing_key")
        XCTAssertEqual(allowEvidence.providerRuntimeSessionKey, "private_app_enforcement_lab_pair")
        XCTAssertEqual(allowEvidence.providerRuntimeFlowRole, "allow_private_app_route")
        XCTAssertEqual(allowEvidence.providerRuntimeSequenceIndex, 1)
        XCTAssertEqual(allowEvidence.policyDecisionCategory, "allow")
        XCTAssertEqual(allowEvidence.policyDecisionAction, "allow")
        XCTAssertEqual(allowEvidence.handleNewFlowReturnAction, "accepted_tunneled_copy")
        XCTAssertEqual(allowEvidence.connectorRouteGate, "route_application_seen")
        XCTAssertEqual(allowEvidence.privateAppRouteDecision, "matched_private_app_route")
        XCTAssertEqual(allowEvidence.runtimeCopyEndpointPassthroughDecision, "matched_passed_through")
        XCTAssertTrue(allowEvidence.edgePortFlowReentryObserved)
        XCTAssertTrue(allowEvidence.edgeTCPConnectCompleted)
        XCTAssertEqual(allowEvidence.edgeTCPConnectAddressFamily, "ipv6")
        XCTAssertEqual(allowEvidence.edgeTransportRoundTripGate, "real_transport_completed")
        XCTAssertEqual(allowEvidence.copyRoundTripGate, "round_trip_completed")
        XCTAssertEqual(allowEvidence.bytesUpGate, "nonzero")
        XCTAssertEqual(allowEvidence.bytesDownGate, "nonzero")
        XCTAssertEqual(allowEvidence.privateAppResponseGate, "observed_nonsecret")
        XCTAssertEqual(allowEvidence.copyAttemptGate, "reviewed_copy_path_completed")
        XCTAssertEqual(allowEvidence.defaultDenyGate, "not_applicable_allow_matched")
        XCTAssertEqual(allowEvidence.defaultDenyPathEvidenceState, .notApplicable)
        XCTAssertFalse(allowEvidence.denyClosedWithoutCopy)
        XCTAssertEqual(
            allowEvidence.protectionTriggerCategory,
            DssePolicyDrivenHandleNewFlowAuditEvidence.protectionTriggerNotApplicable
        )
        XCTAssertTrue(allowEvidence.copyStarted)
        XCTAssertTrue(allowEvidence.networkExtensionFlowOpened)
        XCTAssertTrue(allowEvidence.edgeTunnelOpenStarted)
        XCTAssertTrue(allowEvidence.tcpPayloadCopyStarted)
        XCTAssertTrue(allowEvidence.flowPayloadReadStarted)
        XCTAssertTrue(allowEvidence.flowPayloadWriteStarted)
        XCTAssertEqual(allowEvidence.bytesUp, upstreamPayload.count)
        XCTAssertEqual(allowEvidence.bytesDown, downstreamPayload.count)
        XCTAssertEqual(allowEvidence.registryCleanupGate, "cleaned")
        XCTAssertEqual(allowEvidence.tenantMetadataCleanupGate, "cleaned")
        try assertMetadataOnlyPolicyAuditEvidence(
            allowEvidence,
            forbiddenFragments: [
                "tenant_lab_001",
                "app_dummy_postgres",
                "dummy-postgres.local",
                "client-payload",
                "private-response"
            ]
        )

        let denyInput = ProviderFlowAuthorityInput(
            transport: .tcp,
            remoteHost: "dummy-private-app.local",
            remotePort: 443
        )
        let denyEvidence = DsseAppProxyProvider.policyDrivenHandleNewFlowInProcessAuditEvidence(
            input: denyInput,
            lifecycleManager: manager
        )
        XCTAssertEqual(denyEvidence.status, "ok")
        XCTAssertEqual(denyEvidence.providerRuntimeSessionKeyKind, allowEvidence.providerRuntimeSessionKeyKind)
        XCTAssertEqual(denyEvidence.providerRuntimeSessionKey, allowEvidence.providerRuntimeSessionKey)
        XCTAssertEqual(denyEvidence.providerRuntimeFlowRole, "default_deny_no_matching_rule")
        XCTAssertEqual(denyEvidence.providerRuntimeSequenceIndex, 2)
        XCTAssertEqual(denyEvidence.policyDecisionCategory, "default_deny")
        XCTAssertEqual(denyEvidence.policyDecisionAction, NetworkExtensionContract.actionDeny)
        XCTAssertEqual(denyEvidence.policyDecisionReason, NetworkExtensionContract.reasonNoMatch)
        XCTAssertEqual(denyEvidence.handleNewFlowReturnAction, "deny_closed_no_copy")
        XCTAssertFalse(denyEvidence.acceptFlow)
        XCTAssertEqual(denyEvidence.copyAttemptGate, "closed_without_copy")
        XCTAssertEqual(denyEvidence.defaultDenyGate, "closed_without_copy")
        XCTAssertEqual(denyEvidence.defaultDenyPathEvidenceState, .metadataOnlyRecorded)
        XCTAssertTrue(denyEvidence.denyClosedWithoutCopy)
        XCTAssertEqual(
            denyEvidence.protectionTriggerCategory,
            DssePolicyDrivenHandleNewFlowAuditEvidence.protectionTriggerNotApplicable
        )
        XCTAssertFalse(denyEvidence.copyStarted)
        XCTAssertFalse(denyEvidence.networkExtensionFlowOpened)
        XCTAssertFalse(denyEvidence.edgeTunnelOpenStarted)
        XCTAssertFalse(denyEvidence.tcpPayloadCopyStarted)
        XCTAssertFalse(denyEvidence.flowPayloadReadStarted)
        XCTAssertFalse(denyEvidence.flowPayloadWriteStarted)
        XCTAssertEqual(denyEvidence.bytesUp, 0)
        XCTAssertEqual(denyEvidence.bytesDown, 0)
        XCTAssertEqual(transport.seenPayloads, [upstreamPayload])
        XCTAssertEqual(transport.seenMetadata.count, 1)
        try assertMetadataOnlyPolicyAuditEvidence(
            denyEvidence,
            forbiddenFragments: [
                "tenant_lab_001",
                "app_dummy_postgres",
                "dummy-private-app.local",
                "client-payload",
                "private-response"
            ]
        )
        XCTAssertEqual(progressEvents.values, [
            .liveCopyStarted,
            .flowOpenCompleted,
            .upstreamReadCompleted(bytes: upstreamPayload.count),
            .edgeRoundTripStarted,
            .edgeRoundTripRequestSent,
            .edgeRoundTripResponseBodyReceived,
            .edgeRoundTripCompleted,
            .downstreamWriteStarted,
            .downstreamWriteCompleted
        ])
    }

    func testM1141PolicyDefaultDenyEdgeConnectorLocalSeamUsesPackageFrameBytesOnlyForAllow() throws {
        let manager = try startedLifecycleManager()
        let upstreamPayload = Data("phase2-client-byte-check".utf8)
        let downstreamPayload = Data("phase2-lab-endpoint-response".utf8)
        let flow = MockProviderTCPFlowCopyIO(upstreamPayload: upstreamPayload)
        let transport = RecordingRuntimeCopyTransport(downstreamPayload: downstreamPayload)
        let completion = expectation(description: " allow path reached local package-frame copy evidence")
        let completedResult = RuntimeCopyResultBox()

        let allowInput = ProviderFlowAuthorityInput(
            transport: .tcp,
            remoteHost: "dummy-postgres.local",
            remotePort: 5432
        )
        let providerResult = manager.decide(ProviderFlowRequest(host: "dummy-postgres.local", port: 5432))
        DsseAppProxyProvider.driveLiveRuntimeCopyForMatchedFlow(
            flow: flow,
            providerResult: providerResult,
            lifecycleState: manager.state,
            transport: transport
        ) { result in
            completedResult.result = result
            completion.fulfill()
        }
        wait(for: [completion], timeout: 1.0)

        let allowCopyResult = try XCTUnwrap(completedResult.result).get()
        let allowEvidence = DsseAppProxyProvider.policyDrivenHandleNewFlowInProcessAuditEvidence(
            input: allowInput,
            lifecycleManager: manager,
            copyResult: allowCopyResult
        )
        XCTAssertEqual(allowEvidence.status, "ok")
        XCTAssertEqual(allowEvidence.policyDecisionCategory, "allow")
        XCTAssertEqual(allowEvidence.policyDecisionAction, "allow")
        XCTAssertEqual(allowEvidence.handleNewFlowReturnAction, "accepted_tunneled_copy")
        XCTAssertEqual(allowEvidence.connectorRouteGate, "route_application_seen")
        XCTAssertEqual(allowEvidence.privateAppRouteDecision, "matched_private_app_route")
        XCTAssertEqual(allowEvidence.runtimeCopyEndpointPassthroughDecision, "matched_passed_through")
        XCTAssertTrue(allowEvidence.edgePortFlowReentryObserved)
        XCTAssertTrue(allowEvidence.edgeTCPConnectCompleted)
        XCTAssertEqual(allowEvidence.edgeTCPConnectAddressFamily, "ipv6")
        XCTAssertEqual(allowEvidence.edgeTransportRoundTripGate, "real_transport_completed")
        XCTAssertEqual(allowEvidence.copyRoundTripGate, "round_trip_completed")
        XCTAssertEqual(allowEvidence.bytesUpGate, "nonzero")
        XCTAssertEqual(allowEvidence.bytesDownGate, "nonzero")
        XCTAssertEqual(allowEvidence.privateAppResponseGate, "observed_nonsecret")
        XCTAssertEqual(allowEvidence.copyAttemptGate, "reviewed_copy_path_completed")
        XCTAssertEqual(allowEvidence.defaultDenyPathEvidenceState, .notApplicable)
        XCTAssertTrue(allowEvidence.copyStarted)
        XCTAssertEqual(allowEvidence.bytesUp, 24)
        XCTAssertEqual(allowEvidence.bytesDown, 28)
        XCTAssertEqual(allowEvidence.bytesUp, upstreamPayload.count)
        XCTAssertEqual(allowEvidence.bytesDown, downstreamPayload.count)
        XCTAssertEqual(transport.seenPayloads, [upstreamPayload])
        XCTAssertEqual(transport.seenMetadata.count, 1)
        try assertMetadataOnlyPolicyAuditEvidence(
            allowEvidence,
            forbiddenFragments: [
                "tenant_lab_001",
                "app_dummy_postgres",
                "dummy-postgres.local",
                "phase2-client-byte-check",
                "phase2-lab-endpoint-response"
            ]
        )

        let denyEvidence = DsseAppProxyProvider.policyDrivenHandleNewFlowInProcessAuditEvidence(
            input: ProviderFlowAuthorityInput(
                transport: .tcp,
                remoteHost: "dummy-private-app.local",
                remotePort: 443
            ),
            lifecycleManager: manager
        )
        XCTAssertEqual(denyEvidence.status, "ok")
        XCTAssertEqual(denyEvidence.policyDecisionCategory, "default_deny")
        XCTAssertEqual(denyEvidence.copyAttemptGate, "closed_without_copy")
        XCTAssertEqual(denyEvidence.defaultDenyGate, "closed_without_copy")
        XCTAssertEqual(denyEvidence.defaultDenyPathEvidenceState, .metadataOnlyRecorded)
        XCTAssertTrue(denyEvidence.denyClosedWithoutCopy)
        XCTAssertFalse(denyEvidence.copyStarted)
        XCTAssertFalse(denyEvidence.networkExtensionFlowOpened)
        XCTAssertFalse(denyEvidence.edgeTunnelOpenStarted)
        XCTAssertFalse(denyEvidence.tcpPayloadCopyStarted)
        XCTAssertFalse(denyEvidence.flowPayloadReadStarted)
        XCTAssertFalse(denyEvidence.flowPayloadWriteStarted)
        XCTAssertEqual(denyEvidence.bytesUp, 0)
        XCTAssertEqual(denyEvidence.bytesDown, 0)
        XCTAssertEqual(transport.seenPayloads, [upstreamPayload])
        XCTAssertEqual(transport.seenMetadata.count, 1)
        try assertMetadataOnlyPolicyAuditEvidence(
            denyEvidence,
            forbiddenFragments: [
                "tenant_lab_001",
                "app_dummy_postgres",
                "dummy-private-app.local",
                "phase2-client-byte-check",
                "phase2-lab-endpoint-response"
            ]
        )
    }

    func testM1283PolicyDrivenAllowAuditWriterEmitsFixedProviderAuditFile() throws {
        let manager = try startedLifecycleManager()
        let upstreamPayload = Data("phase2-client-byte-check".utf8)
        let downstreamPayload = Data("phase2-lab-endpoint-response".utf8)
        let flow = MockProviderTCPFlowCopyIO(upstreamPayload: upstreamPayload)
        let transport = RecordingRuntimeCopyTransport(downstreamPayload: downstreamPayload)
        let completion = expectation(description: " allow audit writer copy completed")
        let completedResult = RuntimeCopyResultBox()

        let allowInput = ProviderFlowAuthorityInput(
            transport: .tcp,
            remoteHost: "dummy-postgres.local",
            remotePort: 5432
        )
        let providerResult = manager.decide(ProviderFlowRequest(host: "dummy-postgres.local", port: 5432))
        DsseAppProxyProvider.driveLiveRuntimeCopyForMatchedFlow(
            flow: flow,
            providerResult: providerResult,
            lifecycleState: manager.state,
            transport: transport
        ) { result in
            completedResult.result = result
            completion.fulfill()
        }
        wait(for: [completion], timeout: 1.0)

        let allowCopyResult = try XCTUnwrap(completedResult.result).get()
        let allowEvidence = DsseAppProxyProvider.policyDrivenHandleNewFlowInProcessAuditEvidence(
            input: allowInput,
            lifecycleManager: manager,
            copyResult: allowCopyResult
        )
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("dsse-policy-driven-allow-audit-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        addTeardownBlock {
            try? FileManager.default.removeItem(at: directory)
        }
        let writer = DssePolicyDrivenHandleNewFlowAuditEvidenceWriter(outputDirectory: directory)
        let auditURL = try writer.writeAllowAudit(allowEvidence)

        XCTAssertEqual(auditURL.lastPathComponent, "policy_driven_handle_new_flow_allow_audit.json")
        let rawAudit = try String(contentsOf: auditURL, encoding: .utf8)
        XCTAssertFalse(rawAudit.contains("tenant_lab_001"))
        XCTAssertFalse(rawAudit.contains("app_dummy_postgres"))
        XCTAssertFalse(rawAudit.contains("dummy-postgres.local"))
        XCTAssertFalse(rawAudit.contains("phase2-client-byte-check"))
        XCTAssertFalse(rawAudit.contains("phase2-lab-endpoint-response"))
        let audit = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(rawAudit.utf8)) as? [String: Any])
        XCTAssertEqual(audit["schema_version"] as? String, "policy_driven_handle_new_flow_audit_evidence.v1")
        XCTAssertEqual(audit["evidence_kind"] as? String, "policy_driven_handle_new_flow_inprocess_audit")
        XCTAssertEqual(audit["status"] as? String, "ok")
        XCTAssertEqual(audit["provider_runtime_session_key_kind"] as? String, "nonsecret_lab_runtime_pairing_key")
        XCTAssertEqual(audit["provider_runtime_session_key"] as? String, "private_app_enforcement_lab_pair")
        XCTAssertEqual(audit["provider_runtime_flow_role"] as? String, "allow_private_app_route")
        XCTAssertEqual(audit["provider_runtime_sequence_index"] as? Int, 1)
        XCTAssertEqual(audit["policy_decision_category"] as? String, "allow")
        XCTAssertEqual(audit["handle_new_flow_return_action"] as? String, "accepted_tunneled_copy")
        XCTAssertEqual(audit["connector_route_gate"] as? String, "route_application_seen")
        XCTAssertEqual(audit["private_app_route_decision"] as? String, "matched_private_app_route")
        XCTAssertEqual(audit["runtime_copy_endpoint_passthrough_decision"] as? String, "matched_passed_through")
        XCTAssertEqual(audit["copy_round_trip_gate"] as? String, "round_trip_completed")
        XCTAssertEqual(audit["protection_trigger_category"] as? String, "not_applicable")
        XCTAssertEqual(audit["bytes_up"] as? Int, upstreamPayload.count)
        XCTAssertEqual(audit["bytes_down"] as? Int, downstreamPayload.count)
        XCTAssertEqual(audit["flow_tunneled_claimed"] as? Bool, false)
        XCTAssertEqual(audit["production_private_app_enforcement_claimed"] as? Bool, false)
        XCTAssertEqual(audit["no_secret_attestation"] as? Bool, true)

        let denyEvidence = DsseAppProxyProvider.policyDrivenHandleNewFlowInProcessAuditEvidence(
            input: ProviderFlowAuthorityInput(
                transport: .tcp,
                remoteHost: "dummy-private-app.local",
                remotePort: 443
            ),
            lifecycleManager: manager
        )
        let defaultDenyURL = try writer.writeDefaultDenyAudit(denyEvidence)
        XCTAssertEqual(defaultDenyURL.lastPathComponent, "policy_driven_handle_new_flow_default_deny_audit.json")
        let rawDefaultDenyAudit = try String(contentsOf: defaultDenyURL, encoding: .utf8)
        XCTAssertFalse(rawDefaultDenyAudit.contains("tenant_lab_001"))
        XCTAssertFalse(rawDefaultDenyAudit.contains("app_dummy_postgres"))
        XCTAssertFalse(rawDefaultDenyAudit.contains("dummy-private-app.local"))
        let defaultDenyAudit = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(rawDefaultDenyAudit.utf8)) as? [String: Any]
        )
        XCTAssertEqual(defaultDenyAudit["provider_runtime_session_key_kind"] as? String, "nonsecret_lab_runtime_pairing_key")
        XCTAssertEqual(defaultDenyAudit["provider_runtime_session_key"] as? String, "private_app_enforcement_lab_pair")
        XCTAssertEqual(defaultDenyAudit["provider_runtime_flow_role"] as? String, "default_deny_no_matching_rule")
        XCTAssertEqual(defaultDenyAudit["provider_runtime_sequence_index"] as? Int, 2)
        XCTAssertEqual(defaultDenyAudit["policy_decision_category"] as? String, "default_deny")
        XCTAssertEqual(defaultDenyAudit["handle_new_flow_return_action"] as? String, "deny_closed_no_copy")
        XCTAssertEqual(defaultDenyAudit["default_deny_gate"] as? String, "closed_without_copy")
        XCTAssertEqual(defaultDenyAudit["protection_trigger_category"] as? String, "not_applicable")
        XCTAssertEqual(defaultDenyAudit["copy_started"] as? Bool, false)
        XCTAssertEqual(defaultDenyAudit["bytes_up"] as? Int, 0)
        XCTAssertEqual(defaultDenyAudit["bytes_down"] as? Int, 0)
        XCTAssertEqual(defaultDenyAudit["flow_denied_claimed"] as? Bool, false)
        XCTAssertEqual(defaultDenyAudit["production_default_deny_enforcement_claimed"] as? Bool, false)
        XCTAssertEqual(defaultDenyAudit["no_secret_attestation"] as? Bool, true)

        let protectionManager = try startedLifecycleManager(rules: phase4ProtectionRulesFixture, expectedRuleCount: 2)
        let protectionEvidence = DsseAppProxyProvider.policyDrivenHandleNewFlowInProcessAuditEvidence(
            input: ProviderFlowAuthorityInput(
                transport: .tcp,
                remoteHost: "dummy-smb-admin-share.local",
                remotePort: 445
            ),
            lifecycleManager: protectionManager
        )
        let protectionURL = try writer.writeProtectionAudit(protectionEvidence)
        XCTAssertEqual(
            protectionURL.lastPathComponent,
            "policy_driven_handle_new_flow_protection_block_audit.json"
        )
        let rawProtectionAudit = try String(contentsOf: protectionURL, encoding: .utf8)
        XCTAssertFalse(rawProtectionAudit.contains("tenant_lab_001"))
        XCTAssertFalse(rawProtectionAudit.contains("app_file_share_admin"))
        XCTAssertFalse(rawProtectionAudit.contains("dummy-smb-admin-share.local"))
        let protectionAudit = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(rawProtectionAudit.utf8)) as? [String: Any]
        )
        XCTAssertEqual(protectionAudit["provider_runtime_session_key_kind"] as? String, "nonsecret_lab_runtime_pairing_key")
        XCTAssertEqual(protectionAudit["provider_runtime_session_key"] as? String, "private_app_enforcement_lab_pair")
        XCTAssertEqual(protectionAudit["provider_runtime_flow_role"] as? String, "protection_block_closed_without_copy")
        XCTAssertEqual(protectionAudit["provider_runtime_sequence_index"] as? Int, 3)
        XCTAssertEqual(protectionAudit["policy_decision_category"] as? String, "protection_block")
        XCTAssertEqual(protectionAudit["policy_decision_reason"] as? String, NetworkExtensionContract.reasonProtectionMatched)
        XCTAssertEqual(protectionAudit["copy_attempt_gate"] as? String, "protection_closed_without_copy")
        XCTAssertEqual(protectionAudit["protection_gate"] as? String, "closed_without_copy")
        XCTAssertEqual(protectionAudit["protection_trigger_category"] as? String, "risk_signal_lateral_movement_protocol_anomaly")
        XCTAssertEqual(protectionAudit["copy_started"] as? Bool, false)
        XCTAssertEqual(protectionAudit["bytes_up"] as? Int, 0)
        XCTAssertEqual(protectionAudit["bytes_down"] as? Int, 0)
        XCTAssertEqual(protectionAudit["ransomware_protection_active_claimed"] as? Bool, false)
        XCTAssertEqual(protectionAudit["no_secret_attestation"] as? Bool, true)
        XCTAssertThrowsError(try writer.writeAllowAudit(denyEvidence)) { error in
            XCTAssertEqual(
                error as? DssePolicyDrivenHandleNewFlowAuditEvidenceWriteError,
                .invalidEvidence("allow_audit_gate")
            )
        }
        XCTAssertThrowsError(try writer.writeDefaultDenyAudit(allowEvidence)) { error in
            XCTAssertEqual(
                error as? DssePolicyDrivenHandleNewFlowAuditEvidenceWriteError,
                .invalidEvidence("default_deny_audit_gate")
            )
        }
        XCTAssertThrowsError(try writer.writeProtectionAudit(allowEvidence)) { error in
            XCTAssertEqual(
                error as? DssePolicyDrivenHandleNewFlowAuditEvidenceWriteError,
                .invalidEvidence("protection_audit_gate")
            )
        }
    }

    func testM1143AC09ProtectionBlockLocalSeamClosesBeforeCopySideEffects() throws {
        let manager = try startedLifecycleManager(rules: phase4ProtectionRulesFixture, expectedRuleCount: 2)
        let upstreamPayload = Data("phase2-client-byte-check".utf8)
        let downstreamPayload = Data("phase2-lab-endpoint-response".utf8)
        let flow = MockProviderTCPFlowCopyIO(upstreamPayload: upstreamPayload)
        let transport = RecordingRuntimeCopyTransport(downstreamPayload: downstreamPayload)
        let completion = expectation(description: " allow path preserved local package-frame copy evidence")
        let completedResult = RuntimeCopyResultBox()

        let allowInput = ProviderFlowAuthorityInput(
            transport: .tcp,
            remoteHost: "dummy-postgres.local",
            remotePort: 5432
        )
        let allowProviderResult = manager.decide(ProviderFlowRequest(host: "dummy-postgres.local", port: 5432))
        DsseAppProxyProvider.driveLiveRuntimeCopyForMatchedFlow(
            flow: flow,
            providerResult: allowProviderResult,
            lifecycleState: manager.state,
            transport: transport
        ) { result in
            completedResult.result = result
            completion.fulfill()
        }
        wait(for: [completion], timeout: 1.0)

        let allowCopyResult = try XCTUnwrap(completedResult.result).get()
        let allowEvidence = DsseAppProxyProvider.policyDrivenHandleNewFlowInProcessAuditEvidence(
            input: allowInput,
            lifecycleManager: manager,
            copyResult: allowCopyResult
        )
        XCTAssertEqual(allowEvidence.status, "ok")
        XCTAssertEqual(allowEvidence.policyDecisionCategory, "allow")
        XCTAssertEqual(allowEvidence.policyDecisionAction, "allow")
        XCTAssertEqual(allowEvidence.handleNewFlowReturnAction, "accepted_tunneled_copy")
        XCTAssertEqual(allowEvidence.connectorRouteGate, "route_application_seen")
        XCTAssertEqual(allowEvidence.privateAppRouteDecision, "matched_private_app_route")
        XCTAssertEqual(allowEvidence.runtimeCopyEndpointPassthroughDecision, "matched_passed_through")
        XCTAssertTrue(allowEvidence.edgePortFlowReentryObserved)
        XCTAssertTrue(allowEvidence.edgeTCPConnectCompleted)
        XCTAssertEqual(allowEvidence.edgeTCPConnectAddressFamily, "ipv6")
        XCTAssertEqual(allowEvidence.edgeTransportRoundTripGate, "real_transport_completed")
        XCTAssertEqual(allowEvidence.copyRoundTripGate, "round_trip_completed")
        XCTAssertEqual(allowEvidence.bytesUpGate, "nonzero")
        XCTAssertEqual(allowEvidence.bytesDownGate, "nonzero")
        XCTAssertEqual(allowEvidence.privateAppResponseGate, "observed_nonsecret")
        XCTAssertEqual(allowEvidence.copyAttemptGate, "reviewed_copy_path_completed")
        XCTAssertEqual(allowEvidence.protectionGate, "not_applicable")
        XCTAssertEqual(allowEvidence.defaultDenyPathEvidenceState, .notApplicable)
        XCTAssertFalse(allowEvidence.protectionBlockedWithoutCopy)
        XCTAssertEqual(allowEvidence.protectionRuleSemantics, "none")
        XCTAssertTrue(allowEvidence.protectionReasonCodes.isEmpty)
        XCTAssertEqual(
            allowEvidence.protectionTriggerCategory,
            DssePolicyDrivenHandleNewFlowAuditEvidence.protectionTriggerNotApplicable
        )
        XCTAssertTrue(allowEvidence.copyStarted)
        XCTAssertEqual(allowEvidence.bytesUp, 24)
        XCTAssertEqual(allowEvidence.bytesDown, 28)
        XCTAssertEqual(transport.seenPayloads, [upstreamPayload])
        XCTAssertEqual(transport.seenMetadata.count, 1)
        try assertMetadataOnlyPolicyAuditEvidence(
            allowEvidence,
            forbiddenFragments: [
                "tenant_lab_001",
                "app_dummy_postgres",
                "dummy-postgres.local",
                "phase2-client-byte-check",
                "phase2-lab-endpoint-response"
            ]
        )

        let protectionInput = ProviderFlowAuthorityInput(
            transport: .tcp,
            remoteHost: "dummy-smb-admin-share.local",
            remotePort: 445
        )
        let protectionReport = DsseAppProxyProvider.handleNewFlowCompileHarness(
            input: protectionInput,
            lifecycleManager: manager
        )
        XCTAssertEqual(protectionReport.providerAction, .deny)
        XCTAssertEqual(protectionReport.action, NetworkExtensionContract.actionDeny)
        XCTAssertEqual(protectionReport.reason, NetworkExtensionContract.reasonProtectionMatched)
        XCTAssertFalse(protectionReport.acceptFlow)
        assertRuntimeCopyNotStarted(protectionReport)

        let protectionEvidence = DsseAppProxyProvider.policyDrivenHandleNewFlowInProcessAuditEvidence(
            input: protectionInput,
            lifecycleManager: manager
        )
        XCTAssertEqual(protectionEvidence.status, "ok")
        XCTAssertEqual(protectionEvidence.policyDecisionCategory, "protection_block")
        XCTAssertEqual(protectionEvidence.policyDecisionAction, NetworkExtensionContract.actionDeny)
        XCTAssertEqual(protectionEvidence.policyDecisionReason, NetworkExtensionContract.reasonProtectionMatched)
        XCTAssertEqual(protectionEvidence.copyAttemptGate, "protection_closed_without_copy")
        XCTAssertEqual(protectionEvidence.defaultDenyGate, "not_applicable_protection_matched")
        XCTAssertEqual(protectionEvidence.defaultDenyPathEvidenceState, .notApplicable)
        XCTAssertEqual(protectionEvidence.protectionGate, "closed_without_copy")
        XCTAssertTrue(protectionEvidence.protectionBlockedWithoutCopy)
        XCTAssertEqual(
            protectionEvidence.protectionRuleSemantics,
            NetworkExtensionContract.protectionModeAC09RansomwareLateralMovement
        )
        XCTAssertEqual(
            Set(protectionEvidence.protectionReasonCodes),
            Set([
                NetworkExtensionContract.reasonCodeRansomwareProtectionModeActive,
                NetworkExtensionContract.reasonCodeLateralMovementProtocolAnomaly
            ])
        )
        XCTAssertEqual(
            protectionEvidence.protectionTriggerCategory,
            DssePolicyDrivenHandleNewFlowAuditEvidence.protectionTriggerLateralMovementProtocolAnomaly
        )
        XCTAssertFalse(protectionEvidence.copyStarted)
        XCTAssertFalse(protectionEvidence.networkExtensionFlowOpened)
        XCTAssertFalse(protectionEvidence.edgeTunnelOpenStarted)
        XCTAssertFalse(protectionEvidence.tcpPayloadCopyStarted)
        XCTAssertFalse(protectionEvidence.flowPayloadReadStarted)
        XCTAssertFalse(protectionEvidence.flowPayloadWriteStarted)
        XCTAssertEqual(protectionEvidence.bytesUp, 0)
        XCTAssertEqual(protectionEvidence.bytesDown, 0)
        XCTAssertEqual(transport.seenPayloads, [upstreamPayload])
        XCTAssertEqual(transport.seenMetadata.count, 1)
        XCTAssertTrue(protectionEvidence.nonsecretAuditEventCategories.contains("ac09_protection_rule_matched"))
        XCTAssertTrue(protectionEvidence.nonsecretAuditEventCategories.contains("metadata_only_protection_audit_emitted"))
        try assertMetadataOnlyPolicyAuditEvidence(
            protectionEvidence,
            forbiddenFragments: [
                "tenant_lab_001",
                "app_dummy_postgres",
                "app_file_share_admin",
                "dummy-postgres.local",
                "dummy-smb-admin-share.local",
                "phase2-client-byte-check",
                "phase2-lab-endpoint-response"
            ]
        )
    }

    func testM1346Phase4ProtectionPortFallbackHandlesInvalidRuntimeAuthorityHost() throws {
        let manager = try startedLifecycleManager(rules: phase4ProtectionRulesFixture, expectedRuleCount: 2)
        let input = ProviderFlowAuthorityInput(
            transport: .tcp,
            remoteHost: "fe80::1%lo0",
            remotePort: 445
        )

        let report = DsseAppProxyProvider.handleNewFlowCompileHarness(
            input: input,
            lifecycleManager: manager
        )

        XCTAssertEqual(report.status, "ok")
        XCTAssertEqual(report.flowExtractionStatus, .denied)
        XCTAssertEqual(report.flowExtractionReason, .invalidFlowAuthority)
        XCTAssertEqual(report.providerAction, .deny)
        XCTAssertEqual(report.action, NetworkExtensionContract.actionDeny)
        XCTAssertEqual(report.reason, NetworkExtensionContract.reasonProtectionMatched)
        XCTAssertEqual(report.singleRuleLabFallbackGate, "phase4_protection_port_rule_applied")
        XCTAssertEqual(report.flowAuthorityHostGate, "invalid_nonsecret")
        XCTAssertEqual(report.flowAuthorityPortGate, "positive")
        XCTAssertEqual(report.singleRuleLabFallbackPortGate, "matched")
        XCTAssertFalse(report.acceptFlow)
        XCTAssertEqual(report.returnAction, "deny_closed_no_copy")
        assertRuntimeCopyNotStarted(report)

        let evidence = DsseAppProxyProvider.policyDrivenHandleNewFlowInProcessAuditEvidence(
            input: input,
            lifecycleManager: manager
        )
        XCTAssertEqual(evidence.status, "ok")
        XCTAssertEqual(evidence.providerRuntimeFlowRole, "protection_block_closed_without_copy")
        XCTAssertEqual(evidence.providerRuntimeSequenceIndex, 3)
        XCTAssertEqual(evidence.policyDecisionCategory, "protection_block")
        XCTAssertEqual(evidence.policyDecisionReason, NetworkExtensionContract.reasonProtectionMatched)
        XCTAssertEqual(evidence.copyAttemptGate, "protection_closed_without_copy")
        XCTAssertEqual(evidence.protectionGate, "closed_without_copy")
        XCTAssertEqual(evidence.protectionTriggerCategory, "risk_signal_lateral_movement_protocol_anomaly")
        XCTAssertFalse(evidence.copyStarted)
        XCTAssertEqual(evidence.bytesUp, 0)
        XCTAssertEqual(evidence.bytesDown, 0)
        XCTAssertTrue(evidence.nonsecretAuditEventCategories.contains("metadata_only_protection_audit_emitted"))
        try assertMetadataOnlyPolicyAuditEvidence(
            evidence,
            forbiddenFragments: [
                "tenant_lab_001",
                "app_file_share_admin",
                "dummy-smb-admin-share.local",
                "fe80::1%lo0"
            ]
        )
    }

    func testDeniedTCPFlowStaysClosedBeforeRuntimeCopy() throws {
        let manager = try startedLifecycleManager()

        let report = DsseAppProxyProvider.handleNewFlowCompileHarness(
            input: ProviderFlowAuthorityInput(
                transport: .tcp,
                remoteHost: "dummy-private-app.local",
                remotePort: 443
            ),
            lifecycleManager: manager
        )

        XCTAssertEqual(report.status, "ok")
        XCTAssertEqual(report.flowExtractionStatus, .ok)
        XCTAssertEqual(report.providerAction, .deny)
        XCTAssertEqual(report.action, NetworkExtensionContract.actionDeny)
        XCTAssertEqual(report.reason, NetworkExtensionContract.reasonNoMatch)
        XCTAssertEqual(report.singleRuleLabFallbackGate, "destination_port_mismatch")
        XCTAssertFalse(report.acceptFlow)
        XCTAssertEqual(report.returnAction, "deny_closed_no_copy")
        XCTAssertEqual(report.flowCopySkeletonStatus, "deny_closed")
        XCTAssertEqual(report.flowCopyAction, "deny_closed_no_copy")
        XCTAssertEqual(report.flowCopyMode, "none")
        XCTAssertEqual(report.flowCopyImplementation, "not_started")
        XCTAssertTrue(report.flowCopyReviewBoundaryRequired)
        assertRuntimeCopyNotStarted(report)
    }

    func testLabSingleRuleFallbackTakesOverWhenRuntimeAuthorityHostIsUnavailableButPortMatches() throws {
        let manager = try startedLifecycleManager()

        let report = DsseAppProxyProvider.handleNewFlowCompileHarness(
            input: ProviderFlowAuthorityInput(
                transport: .tcp,
                remoteHost: "",
                remotePort: 5432
            ),
            lifecycleManager: manager
        )

        XCTAssertEqual(report.status, "ok")
        XCTAssertEqual(report.flowExtractionStatus, .denied)
        XCTAssertEqual(report.flowExtractionReason, .invalidFlowAuthority)
        XCTAssertEqual(report.providerAction, .openTunnel)
        XCTAssertEqual(report.action, NetworkExtensionContract.actionTunnel)
        XCTAssertEqual(report.reason, NetworkExtensionContract.reasonMatched)
        XCTAssertEqual(report.singleRuleLabFallbackGate, "applied")
        XCTAssertEqual(report.flowAuthorityHostGate, "empty_or_missing")
        XCTAssertEqual(report.flowAuthorityPortGate, "positive")
        XCTAssertEqual(report.singleRuleLabFallbackPortGate, "matched")
        XCTAssertTrue(report.acceptFlow)
        XCTAssertEqual(report.returnAction, "take_over_matched_flow_live_copy_real_edge_transport_reviewed")
        assertRuntimeCopyNotStarted(report)
    }

    func testM1160LabSingleRuleFallbackTakesOverWhenRuntimeAuthorityHostAliasDoesNotMatchButPortMatches() throws {
        let manager = try startedLifecycleManager()

        let report = DsseAppProxyProvider.handleNewFlowCompileHarness(
            input: ProviderFlowAuthorityInput(
                transport: .tcp,
                remoteHost: "phase2-target-alias.local",
                remotePort: 5432
            ),
            lifecycleManager: manager
        )

        XCTAssertEqual(report.status, "ok")
        XCTAssertEqual(report.flowExtractionStatus, .ok)
        XCTAssertEqual(report.flowExtractionReason, .extracted)
        XCTAssertEqual(report.providerAction, .openTunnel)
        XCTAssertEqual(report.action, NetworkExtensionContract.actionTunnel)
        XCTAssertEqual(report.reason, NetworkExtensionContract.reasonMatched)
        XCTAssertEqual(report.singleRuleLabFallbackGate, "applied")
        XCTAssertTrue(report.acceptFlow)
        XCTAssertEqual(report.returnAction, "take_over_matched_flow_live_copy_real_edge_transport_reviewed")
        assertRuntimeCopyNotStarted(report)
    }

    func testM1160NonPhase2SingleRuleHostMismatchSamePortRemainsClosed() throws {
        let nonPhase2Rules = rulesFixture.replacingOccurrences(
            of: "\"source_protected_app_map\": \"protected_app_map_phase2_flow_copy_lab.json\"",
            with: "\"source_protected_app_map\": \"protected_app_map_lab.json\""
        )
        let manager = try startedLifecycleManager(rules: nonPhase2Rules)

        let report = DsseAppProxyProvider.handleNewFlowCompileHarness(
            input: ProviderFlowAuthorityInput(
                transport: .tcp,
                remoteHost: "phase2-target-alias.local",
                remotePort: 5432
            ),
            lifecycleManager: manager
        )

        XCTAssertEqual(report.status, "ok")
        XCTAssertEqual(report.flowExtractionStatus, .ok)
        XCTAssertEqual(report.flowExtractionReason, .extracted)
        XCTAssertEqual(report.providerAction, .deny)
        XCTAssertEqual(report.action, NetworkExtensionContract.actionDeny)
        XCTAssertEqual(report.reason, NetworkExtensionContract.reasonNoMatch)
        XCTAssertEqual(report.singleRuleLabFallbackGate, "source_map_not_phase2_flow_copy_lab")
        XCTAssertFalse(report.acceptFlow)
        XCTAssertEqual(report.returnAction, "deny_closed_no_copy")
        assertRuntimeCopyNotStarted(report)
    }

    func testLabSingleRuleFallbackDeniesWhenRuntimeAuthorityPortDoesNotMatch() throws {
        let manager = try startedLifecycleManager()

        let report = DsseAppProxyProvider.handleNewFlowCompileHarness(
            input: ProviderFlowAuthorityInput(
                transport: .tcp,
                remoteHost: "",
                remotePort: 443
            ),
            lifecycleManager: manager
        )

        XCTAssertEqual(report.status, "ok")
        XCTAssertEqual(report.flowExtractionStatus, .denied)
        XCTAssertEqual(report.flowExtractionReason, .invalidFlowAuthority)
        XCTAssertEqual(report.providerAction, .deny)
        XCTAssertEqual(report.action, NetworkExtensionContract.actionDeny)
        XCTAssertEqual(report.reason, NetworkExtensionContract.reasonInvalidFlow)
        XCTAssertEqual(report.singleRuleLabFallbackGate, "destination_port_mismatch")
        XCTAssertEqual(report.flowAuthorityHostGate, "empty_or_missing")
        XCTAssertEqual(report.flowAuthorityPortGate, "positive")
        XCTAssertEqual(report.singleRuleLabFallbackPortGate, "mismatch")
        XCTAssertFalse(report.acceptFlow)
        XCTAssertEqual(report.returnAction, "deny_closed_no_copy")
        assertRuntimeCopyNotStarted(report)
    }

    func testM1292InvalidNonsecretAuthorityHostPositivePortMismatchDefaultDeniesForUnifiedEvidence() throws {
        let manager = try startedLifecycleManager()

        let report = DsseAppProxyProvider.handleNewFlowCompileHarness(
            input: ProviderFlowAuthorityInput(
                transport: .tcp,
                remoteHost: "phase2 target alias local",
                remotePort: 443
            ),
            lifecycleManager: manager
        )

        XCTAssertEqual(report.status, "ok")
        XCTAssertEqual(report.flowExtractionStatus, .denied)
        XCTAssertEqual(report.flowExtractionReason, .invalidFlowAuthority)
        XCTAssertEqual(report.providerAction, .deny)
        XCTAssertEqual(report.action, NetworkExtensionContract.actionDeny)
        XCTAssertEqual(report.reason, NetworkExtensionContract.reasonNoMatch)
        XCTAssertEqual(report.singleRuleLabFallbackGate, "destination_port_mismatch")
        XCTAssertEqual(report.flowAuthorityHostGate, "invalid_nonsecret")
        XCTAssertEqual(report.flowAuthorityPortGate, "positive")
        XCTAssertEqual(report.singleRuleLabFallbackPortGate, "mismatch")
        XCTAssertFalse(report.acceptFlow)
        XCTAssertEqual(report.returnAction, "deny_closed_no_copy")
        assertRuntimeCopyNotStarted(report)

        let evidence = DsseAppProxyProvider.policyDrivenHandleNewFlowInProcessAuditEvidence(
            input: ProviderFlowAuthorityInput(
                transport: .tcp,
                remoteHost: "phase2 target alias local",
                remotePort: 443
            ),
            lifecycleManager: manager
        )
        XCTAssertEqual(evidence.providerRuntimeFlowRole, "default_deny_no_matching_rule")
        XCTAssertEqual(evidence.providerRuntimeSequenceIndex, 2)
        XCTAssertEqual(evidence.policyDecisionCategory, "default_deny")
        XCTAssertEqual(evidence.policyDecisionReason, NetworkExtensionContract.reasonNoMatch)
        XCTAssertEqual(evidence.defaultDenyGate, "closed_without_copy")
        XCTAssertFalse(evidence.copyStarted)
        XCTAssertEqual(evidence.bytesUp, 0)
        XCTAssertEqual(evidence.bytesDown, 0)
    }

    func testM1222InvalidNonsecretAuthorityHostPortMismatchBypassRequiresPhase2SingleRuleLabMap() throws {
        let nonPhase2Rules = rulesFixture.replacingOccurrences(
            of: "\"source_protected_app_map\": \"protected_app_map_phase2_flow_copy_lab.json\"",
            with: "\"source_protected_app_map\": \"protected_app_map_lab.json\""
        )
        let manager = try startedLifecycleManager(rules: nonPhase2Rules)

        let report = DsseAppProxyProvider.handleNewFlowCompileHarness(
            input: ProviderFlowAuthorityInput(
                transport: .tcp,
                remoteHost: "phase2 target alias local",
                remotePort: 443
            ),
            lifecycleManager: manager
        )

        XCTAssertEqual(report.status, "ok")
        XCTAssertEqual(report.flowExtractionStatus, .denied)
        XCTAssertEqual(report.flowExtractionReason, .invalidFlowAuthority)
        XCTAssertEqual(report.providerAction, .deny)
        XCTAssertEqual(report.action, NetworkExtensionContract.actionDeny)
        XCTAssertEqual(report.reason, NetworkExtensionContract.reasonInvalidFlow)
        XCTAssertEqual(report.singleRuleLabFallbackGate, "source_map_not_phase2_flow_copy_lab")
        XCTAssertEqual(report.flowAuthorityHostGate, "invalid_nonsecret")
        XCTAssertEqual(report.flowAuthorityPortGate, "positive")
        XCTAssertEqual(report.singleRuleLabFallbackPortGate, "fallback_not_available")
        XCTAssertFalse(report.acceptFlow)
        XCTAssertEqual(report.returnAction, "deny_closed_no_copy")
        assertRuntimeCopyNotStarted(report)
    }

    func testM1208AuthorityPortGateDiagnosesZeroPortBeforeSingleRuleFallback() throws {
        let manager = try startedLifecycleManager()

        let report = DsseAppProxyProvider.handleNewFlowCompileHarness(
            input: ProviderFlowAuthorityInput(
                transport: .tcp,
                remoteHost: "",
                remotePort: 0
            ),
            lifecycleManager: manager
        )

        XCTAssertEqual(report.status, "ok")
        XCTAssertEqual(report.flowExtractionStatus, .denied)
        XCTAssertEqual(report.flowExtractionReason, .invalidFlowAuthority)
        XCTAssertEqual(report.providerAction, .deny)
        XCTAssertEqual(report.action, NetworkExtensionContract.actionDeny)
        XCTAssertEqual(report.reason, NetworkExtensionContract.reasonInvalidFlow)
        XCTAssertEqual(report.singleRuleLabFallbackGate, "destination_port_mismatch")
        XCTAssertEqual(report.flowAuthorityHostGate, "empty_or_missing")
        XCTAssertEqual(report.flowAuthorityPortGate, "zero_or_missing")
        XCTAssertEqual(report.singleRuleLabFallbackPortGate, "authority_port_zero_or_missing")
        XCTAssertFalse(report.acceptFlow)
        XCTAssertEqual(report.returnAction, "deny_closed_no_copy")
        assertRuntimeCopyNotStarted(report)
    }

    func testM1208IPLiteralAuthorityStillReportsPositivePortForFallbackDiagnosis() throws {
        let manager = try startedLifecycleManager()

        let report = DsseAppProxyProvider.handleNewFlowCompileHarness(
            input: ProviderFlowAuthorityInput(
                transport: .tcp,
                remoteHost: "127.0.0.1",
                remotePort: 5432
            ),
            lifecycleManager: manager
        )

        XCTAssertEqual(report.status, "ok")
        XCTAssertEqual(report.flowExtractionStatus, .denied)
        XCTAssertEqual(report.flowExtractionReason, .invalidFlowAuthority)
        XCTAssertEqual(report.providerAction, .openTunnel)
        XCTAssertEqual(report.action, NetworkExtensionContract.actionTunnel)
        XCTAssertEqual(report.reason, NetworkExtensionContract.reasonMatched)
        XCTAssertEqual(report.singleRuleLabFallbackGate, "applied")
        XCTAssertEqual(report.flowAuthorityHostGate, "ip_literal")
        XCTAssertEqual(report.flowAuthorityPortGate, "positive")
        XCTAssertEqual(report.singleRuleLabFallbackPortGate, "matched")
        XCTAssertTrue(report.acceptFlow)
        XCTAssertEqual(report.returnAction, "take_over_matched_flow_live_copy_real_edge_transport_reviewed")
        assertRuntimeCopyNotStarted(report)
    }

    func testM1564P2OperatorConfigUnusableAuthorityOnRulePortStaysDefaultDeny() throws {
        let manager = try startedLifecycleManager(rules: p2OperatorConfigRulesFixture, expectedRuleCount: 4)

        let report = DsseAppProxyProvider.handleNewFlowCompileHarness(
            input: ProviderFlowAuthorityInput(
                transport: .tcp,
                remoteHost: "127.0.0.1",
                remotePort: 22
            ),
            lifecycleManager: manager
        )

        XCTAssertEqual(report.status, "ok")
        XCTAssertEqual(report.flowExtractionStatus, .denied)
        XCTAssertEqual(report.flowExtractionReason, .invalidFlowAuthority)
        XCTAssertEqual(report.providerAction, .deny)
        XCTAssertEqual(report.action, NetworkExtensionContract.actionDeny)
        XCTAssertEqual(report.reason, NetworkExtensionContract.reasonNoMatch)
        XCTAssertEqual(report.singleRuleLabFallbackGate, "p2_operator_config_unusable_authority_host_default_deny")
        XCTAssertEqual(report.flowAuthorityHostGate, "ip_literal")
        XCTAssertEqual(report.flowAuthorityPortGate, "positive")
        XCTAssertEqual(report.singleRuleLabFallbackPortGate, "matched")
        XCTAssertFalse(report.acceptFlow)
        XCTAssertEqual(report.returnAction, "deny_closed_no_copy")
        assertRuntimeCopyNotStarted(report)
    }

    func testM1547P2OperatorConfigPortFallbackDeniesWhenNoConfiguredPortMatches() throws {
        let manager = try startedLifecycleManager(rules: p2OperatorConfigRulesFixture, expectedRuleCount: 4)

        let report = DsseAppProxyProvider.handleNewFlowCompileHarness(
            input: ProviderFlowAuthorityInput(
                transport: .tcp,
                remoteHost: "127.0.0.1",
                remotePort: 8443
            ),
            lifecycleManager: manager
        )

        XCTAssertEqual(report.status, "ok")
        XCTAssertEqual(report.flowExtractionStatus, .denied)
        XCTAssertEqual(report.flowExtractionReason, .invalidFlowAuthority)
        XCTAssertEqual(report.providerAction, .deny)
        XCTAssertEqual(report.action, NetworkExtensionContract.actionDeny)
        XCTAssertEqual(report.reason, NetworkExtensionContract.reasonNoMatch)
        XCTAssertEqual(report.singleRuleLabFallbackGate, "destination_port_mismatch")
        XCTAssertEqual(report.flowAuthorityHostGate, "ip_literal")
        XCTAssertEqual(report.flowAuthorityPortGate, "positive")
        XCTAssertEqual(report.singleRuleLabFallbackPortGate, "mismatch")
        XCTAssertFalse(report.acceptFlow)
        XCTAssertEqual(report.returnAction, "deny_closed_no_copy")
        assertRuntimeCopyNotStarted(report)
    }

    func testM1561P2OperatorConfigUnboundAuthorityHostOnRulePortStaysDefaultDeny() throws {
        let manager = try startedLifecycleManager(rules: p2OperatorConfigRulesFixture, expectedRuleCount: 4)

        let report = DsseAppProxyProvider.handleNewFlowCompileHarness(
            input: ProviderFlowAuthorityInput(
                transport: .tcp,
                remoteHost: "deny-web-https.p2.dev.example.internal",
                remotePort: 443
            ),
            lifecycleManager: manager
        )

        XCTAssertEqual(report.status, "ok")
        XCTAssertEqual(report.flowExtractionStatus, .ok)
        XCTAssertEqual(report.flowExtractionReason, .extracted)
        XCTAssertEqual(report.providerAction, .deny)
        XCTAssertEqual(report.action, NetworkExtensionContract.actionDeny)
        XCTAssertEqual(report.reason, NetworkExtensionContract.reasonNoMatch)
        XCTAssertEqual(report.singleRuleLabFallbackGate, "p2_operator_config_authority_host_rule_mismatch_default_deny")
        XCTAssertEqual(report.flowAuthorityHostGate, "hostname")
        XCTAssertEqual(report.flowAuthorityPortGate, "positive")
        XCTAssertEqual(report.singleRuleLabFallbackPortGate, "matched")
        XCTAssertFalse(report.acceptFlow)
        XCTAssertEqual(report.returnAction, "deny_closed_no_copy")
        assertRuntimeCopyNotStarted(report)
    }

    func testM1561P2OperatorConfigConfiguredAuthorityHostStillTunnelsViaPrimaryRuleMatch() throws {
        let manager = try startedLifecycleManager(rules: p2OperatorConfigRulesFixture, expectedRuleCount: 4)

        let report = DsseAppProxyProvider.handleNewFlowCompileHarness(
            input: ProviderFlowAuthorityInput(
                transport: .tcp,
                remoteHost: "web.p2.dev.example.internal",
                remotePort: 443
            ),
            lifecycleManager: manager
        )

        XCTAssertEqual(report.status, "ok")
        XCTAssertEqual(report.flowExtractionStatus, .ok)
        XCTAssertEqual(report.flowExtractionReason, .extracted)
        XCTAssertEqual(report.providerAction, .openTunnel)
        XCTAssertEqual(report.action, NetworkExtensionContract.actionTunnel)
        XCTAssertEqual(report.reason, NetworkExtensionContract.reasonMatched)
        XCTAssertEqual(report.singleRuleLabFallbackGate, "not_evaluated")
        XCTAssertEqual(report.flowAuthorityHostGate, "hostname")
        XCTAssertEqual(report.flowAuthorityPortGate, "positive")
        XCTAssertTrue(report.acceptFlow)
        XCTAssertEqual(report.returnAction, "take_over_matched_flow_live_copy_real_edge_transport_reviewed")
        assertRuntimeCopyNotStarted(report)
    }

    func testM1563FlowRemoteNamedAuthorityOverridesResolvedIPLiteralEndpoint() throws {
        let endpointObservation = DsseProviderFlowAuthorityObservation(
            input: ProviderFlowAuthorityInput(
                transport: .tcp,
                remoteHost: "192.0.2.10",
                remotePort: 443,
                sourceBundleID: nil
            ),
            endpointSourceGate: "remote_flow_endpoint_hostport",
            portSourceGate: "hostport_described_port"
        )

        let preferred = DsseAppProxyProvider.authorityObservationPreferringFlowRemoteHostname(
            flowRemoteHostname: "deny-web-https.p2.dev.example.internal",
            endpointObservation: endpointObservation
        )

        XCTAssertEqual(preferred.input.remoteHost, "deny-web-https.p2.dev.example.internal")
        XCTAssertEqual(preferred.input.remotePort, 443)
        XCTAssertEqual(preferred.endpointSourceGate, "flow_remote_named_authority_preferred")
        XCTAssertEqual(preferred.portSourceGate, "hostport_described_port")
    }

    func testM1563FlowRemoteNamedAuthorityKeepsEndpointWhenNameMissingOrUnusable() throws {
        let endpointObservation = DsseProviderFlowAuthorityObservation(
            input: ProviderFlowAuthorityInput(
                transport: .tcp,
                remoteHost: "192.0.2.10",
                remotePort: 5432,
                sourceBundleID: nil
            ),
            endpointSourceGate: "remote_flow_endpoint_hostport",
            portSourceGate: "hostport_described_port"
        )

        for unusable in [nil, "", "   ", "203.0.113.9", "bad..name"] as [String?] {
            let kept = DsseAppProxyProvider.authorityObservationPreferringFlowRemoteHostname(
                flowRemoteHostname: unusable,
                endpointObservation: endpointObservation
            )
            XCTAssertEqual(kept.input.remoteHost, "192.0.2.10")
            XCTAssertEqual(kept.endpointSourceGate, "remote_flow_endpoint_hostport")
        }
    }

    func testDefaultTunnelRulesCaptureWildcardSaaSHostsWithoutExactRule() throws {
        let rulesJSON = """
        {
          "schema_version": "network_extension_steering_rules.v1",
          "tenant_id": "tenant_lab_001",
          "version": "2026.06.12.default-tunnel-test",
          "source_protected_app_map": "admin_console_policy_snapshot",
          "generated_at": "2026-06-12T08:30:00Z",
          "default_action": "tunnel",
          "rules": []
        }
        """
        let rules = try JSONDecoder().decode(NetworkExtensionRules.self, from: Data(rulesJSON.utf8))

        XCTAssertNoThrow(try NetworkExtensionRulesValidator.validate(rules))
        let decision = NetworkExtensionFlowEvaluator.evaluate(rules, host: "mail.google.com", port: 443)

        XCTAssertEqual(decision.action, NetworkExtensionContract.actionTunnel)
        XCTAssertEqual(decision.reason, NetworkExtensionContract.reasonDefaultTunnel)
        XCTAssertEqual(decision.applicationID, "default_network_extension_tunnel")
        XCTAssertEqual(decision.fqdn, "mail.google.com")
        XCTAssertEqual(decision.destinationPort, 443)
        XCTAssertEqual(decision.serviceFamily, "https")
    }

    func testDefaultTunnelRulesCaptureExternalIPLiteralFlowAuthorities() throws {
        let rulesJSON = """
        {
          "schema_version": "network_extension_steering_rules.v1",
          "tenant_id": "tenant_lab_001",
          "version": "2026.06.13.default-tunnel-ip-test",
          "source_protected_app_map": "admin_console_policy_snapshot",
          "generated_at": "2026-06-13T08:30:00Z",
          "default_action": "tunnel",
          "rules": []
        }
        """
        let rules = try JSONDecoder().decode(NetworkExtensionRules.self, from: Data(rulesJSON.utf8))

        XCTAssertNoThrow(try NetworkExtensionRulesValidator.validate(rules))

        let ipv4Decision = NetworkExtensionFlowEvaluator.evaluate(rules, host: "172.217.221.84", port: 443)
        XCTAssertEqual(ipv4Decision.action, NetworkExtensionContract.actionTunnel)
        XCTAssertEqual(ipv4Decision.reason, NetworkExtensionContract.reasonDefaultTunnel)
        XCTAssertEqual(ipv4Decision.applicationID, "default_network_extension_tunnel")
        XCTAssertEqual(ipv4Decision.fqdn, "172.217.221.84")
        XCTAssertEqual(ipv4Decision.destinationPort, 443)
        XCTAssertEqual(ipv4Decision.serviceFamily, "https")

        let ipv6Decision = NetworkExtensionFlowEvaluator.evaluate(rules, host: "[2001:db8::44]", port: 443)
        XCTAssertEqual(ipv6Decision.action, NetworkExtensionContract.actionTunnel)
        XCTAssertEqual(ipv6Decision.reason, NetworkExtensionContract.reasonDefaultTunnel)
        XCTAssertEqual(ipv6Decision.applicationID, "default_network_extension_tunnel")
        XCTAssertEqual(ipv6Decision.fqdn, "2001:db8::44")
        XCTAssertEqual(ipv6Decision.destinationPort, 443)
        XCTAssertEqual(ipv6Decision.serviceFamily, "https")
    }

    func testProviderExtractorAcceptsExternalIPLiteralFlowAuthorities() throws {
        let ipv4 = ProviderFlowExtractor.extract(ProviderFlowAuthorityInput(
            transport: .tcp,
            remoteHost: "172.217.221.84",
            remotePort: 443
        ))
        XCTAssertEqual(ipv4.status, .ok)
        XCTAssertEqual(ipv4.reason, .extracted)
        XCTAssertEqual(ipv4.providerFlowRequest, ProviderFlowRequest(host: "172.217.221.84", port: 443, sourceBundleID: nil))

        let ipv6 = ProviderFlowExtractor.extract(ProviderFlowAuthorityInput(
            transport: .tcp,
            remoteHost: "[2001:db8::44]",
            remotePort: 443
        ))
        XCTAssertEqual(ipv6.status, .ok)
        XCTAssertEqual(ipv6.reason, .extracted)
        XCTAssertEqual(ipv6.providerFlowRequest, ProviderFlowRequest(host: "2001:db8::44", port: 443, sourceBundleID: nil))
    }

    func testProviderExtractorRejectsLoopbackAndScopedIPLiteralFlowAuthorities() throws {
        for remoteHost in ["127.0.0.1", "[::1]", "::ffff:127.0.0.1", "::127.0.0.1", "fe80::1%lo0"] {
            let result = ProviderFlowExtractor.extract(ProviderFlowAuthorityInput(
                transport: .tcp,
                remoteHost: remoteHost,
                remotePort: 443
            ))
            XCTAssertEqual(result.status, .denied)
            XCTAssertEqual(result.reason, .invalidFlowAuthority)
            XCTAssertNil(result.providerFlowRequest)
        }
    }

    func testHandleNewFlowDefaultTunnelAcceptsExternalIPLiteralAuthority() throws {
        let rulesJSON = """
        {
          "schema_version": "network_extension_steering_rules.v1",
          "tenant_id": "tenant_lab_001",
          "version": "2026.06.13.default-tunnel-ip-handle-new-flow-test",
          "source_protected_app_map": "admin_console_policy_snapshot",
          "generated_at": "2026-06-13T08:30:00Z",
          "default_action": "tunnel",
          "rules": []
        }
        """
        let manager = try startedLifecycleManager(rules: rulesJSON, expectedRuleCount: 0)

        let report = DsseAppProxyProvider.handleNewFlowCompileHarness(
            input: ProviderFlowAuthorityInput(
                transport: .tcp,
                remoteHost: "172.217.221.84",
                remotePort: 443
            ),
            lifecycleManager: manager
        )

        XCTAssertEqual(report.status, "ok")
        XCTAssertEqual(report.flowExtractionStatus, .ok)
        XCTAssertEqual(report.flowExtractionReason, .extracted)
        XCTAssertEqual(report.providerAction, .openTunnel)
        XCTAssertEqual(report.action, NetworkExtensionContract.actionTunnel)
        XCTAssertEqual(report.reason, NetworkExtensionContract.reasonDefaultTunnel)
        XCTAssertEqual(report.singleRuleLabFallbackGate, "not_evaluated")
        XCTAssertEqual(report.flowAuthorityHostGate, "ip_literal")
        XCTAssertEqual(report.flowAuthorityPortGate, "positive")
        XCTAssertTrue(report.acceptFlow)
        XCTAssertEqual(report.returnAction, "take_over_matched_flow_live_copy_real_edge_transport_reviewed")
    }

    func testM1216ProviderLifecycleReloadIfStaleSwitchesSingleRuleLabFallbackRules() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("dsse-provider-rules-reload-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        addTeardownBlock {
            try? FileManager.default.removeItem(at: directory)
        }
        let rulesURL = directory.appendingPathComponent("network_extension_steering_rules.json")
        let agentConfigURL = directory.appendingPathComponent("agent_config.json")
        try #"{"network_extension_rules_ref":"network_extension_steering_rules.json"}"#
            .write(to: agentConfigURL, atomically: true, encoding: .utf8)

        let initialRules = rulesFixture
            .replacingOccurrences(of: "\"version\": \"2026.06.02.test\"", with: "\"version\": \"2026.06.06.initial\"")
            .replacingOccurrences(of: "\"destination_port\": 5432", with: "\"destination_port\": 55432")
        try initialRules.write(to: rulesURL, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes(
            [.modificationDate: Date(timeIntervalSince1970: 1_800_000_000)],
            ofItemAtPath: rulesURL.path
        )

        let manager = ProviderLifecycleManager()
        let state = manager.start(agentConfigPath: agentConfigURL.path)
        XCTAssertEqual(state.status, .running)
        XCTAssertEqual(manager.evaluateSingleRuleLabFallback(destinationPort: 55432).gate, "applied")
        XCTAssertEqual(manager.evaluateSingleRuleLabFallback(destinationPort: 65432).gate, "destination_port_mismatch")
        XCTAssertEqual(
            manager.decide(ProviderFlowRequest(host: "dummy-postgres.local", port: 55432)).providerAction,
            .openTunnel
        )

        let updatedRules = rulesFixture
            .replacingOccurrences(of: "\"version\": \"2026.06.02.test\"", with: "\"version\": \"2026.06.06.updated\"")
            .replacingOccurrences(of: "\"destination_port\": 5432", with: "\"destination_port\": 65432")
        try updatedRules.write(to: rulesURL, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes(
            [.modificationDate: Date(timeIntervalSince1970: 1_800_000_120)],
            ofItemAtPath: rulesURL.path
        )

        XCTAssertEqual(manager.reloadIfStale(), "reloaded")

        XCTAssertEqual(manager.state?.status, .running)
        XCTAssertEqual(manager.state?.ruleCount, 1)
        XCTAssertEqual(manager.evaluateSingleRuleLabFallback(destinationPort: 55432).gate, "destination_port_mismatch")
        let updatedFallback = manager.evaluateSingleRuleLabFallback(destinationPort: 65432)
        XCTAssertEqual(updatedFallback.gate, "applied")
        XCTAssertEqual(updatedFallback.providerResult?.decision.destinationPort, 65432)
        XCTAssertEqual(
            manager.decide(ProviderFlowRequest(host: "dummy-postgres.local", port: 55432)).providerAction,
            .deny
        )
        XCTAssertEqual(
            manager.decide(ProviderFlowRequest(host: "dummy-postgres.local", port: 65432)).providerAction,
            .openTunnel
        )
        XCTAssertEqual(manager.reloadIfStale(), "skipped_not_newer")
    }

    func testM1206OpaqueRemoteFlowEndpointFeedsSingleRuleLabFallbackPortMatch() throws {
        let manager = try startedLifecycleManager()
        let endpoint = NWEndpoint.opaque(nw_endpoint_create_host("phase2-target-alias.local", "5432"))
        let input = try XCTUnwrap(DsseAppProxyProvider.authorityInput(fromRemoteFlowEndpoint: endpoint))

        XCTAssertEqual(input.transport, .tcp)
        XCTAssertEqual(input.remoteHost, "phase2-target-alias.local")
        XCTAssertEqual(input.remotePort, 5432)

        let report = DsseAppProxyProvider.handleNewFlowCompileHarness(
            input: input,
            lifecycleManager: manager
        )

        XCTAssertEqual(report.status, "ok")
        XCTAssertEqual(report.flowExtractionStatus, .ok)
        XCTAssertEqual(report.flowExtractionReason, .extracted)
        XCTAssertEqual(report.providerAction, .openTunnel)
        XCTAssertEqual(report.action, NetworkExtensionContract.actionTunnel)
        XCTAssertEqual(report.reason, NetworkExtensionContract.reasonMatched)
        XCTAssertEqual(report.singleRuleLabFallbackGate, "applied")
        XCTAssertTrue(report.acceptFlow)
        XCTAssertEqual(report.returnAction, "take_over_matched_flow_live_copy_real_edge_transport_reviewed")
        assertRuntimeCopyNotStarted(report)
    }

    func testM1295HostPortRemoteFlowEndpointPreservesHighPortForFallback() throws {
        let manager = try startedLifecycleManager(
            rules: rulesFixture.replacingOccurrences(of: "\"destination_port\": 5432", with: "\"destination_port\": 55432")
        )
        let port = try XCTUnwrap(NWEndpoint.Port(rawValue: 55_432))
        let endpoint = NWEndpoint.hostPort(host: .name("phase2-target-alias.local", nil), port: port)
        let input = try XCTUnwrap(DsseAppProxyProvider.authorityInput(fromRemoteFlowEndpoint: endpoint))

        XCTAssertEqual(input.transport, .tcp)
        XCTAssertEqual(input.remoteHost, "phase2-target-alias.local")
        XCTAssertEqual(input.remotePort, 55_432)

        let report = DsseAppProxyProvider.handleNewFlowCompileHarness(
            input: input,
            lifecycleManager: manager
        )

        XCTAssertEqual(report.status, "ok")
        XCTAssertEqual(report.flowExtractionStatus, .ok)
        XCTAssertEqual(report.providerAction, .openTunnel)
        XCTAssertEqual(report.action, NetworkExtensionContract.actionTunnel)
        XCTAssertEqual(report.reason, NetworkExtensionContract.reasonMatched)
        XCTAssertTrue(report.acceptFlow)
        assertRuntimeCopyNotStarted(report)
    }

    func testM1296ProviderRuntimeDiagnosticRecordsAuthorityExtractionSourceGates() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("dsse-provider-runtime-diagnostic-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        addTeardownBlock {
            try? FileManager.default.removeItem(at: directory)
        }

        let diagnosticURL = directory.appendingPathComponent("network_extension_runtime_diagnostic.json")
        let writer = DsseProviderRuntimeDiagnosticWriter(
            diagnosticURL: diagnosticURL,
            now: { Date(timeIntervalSince1970: 1_801_440_000) }
        )

        try writer.recordHandleNewFlow(
            decisionCategory: "deny_closed",
            extractionStatus: "denied",
            extractionReason: "invalid_flow_authority",
            providerDecisionAction: "deny",
            providerDecisionReason: "no_matching_network_extension_rule",
            singleRuleLabFallbackGate: "destination_port_mismatch",
            flowAuthorityHostGate: "invalid_nonsecret",
            flowAuthorityPortGate: "positive",
            singleRuleLabFallbackPortGate: "mismatch",
            allowFlowAuthorityPortMatch: "off_by_delta",
            providerLoadedRulesGeneratedAt: "2026-06-08T00:00:00Z",
            authorityExtractionRuntimeMarker: DsseAppProxyProvider.authorityExtractionRuntimeMarker,
            flowAuthorityEndpointSourceGate: "remote_flow_endpoint_hostport",
            flowAuthorityPortSourceGate: "hostport_described_port"
        )

        let diagnostic = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: diagnosticURL)) as? [String: Any])
        XCTAssertEqual(diagnostic["authority_extraction_runtime_marker"] as? String, "hostport_described_port_preferred")
        XCTAssertEqual(diagnostic["flow_authority_endpoint_source_gate"] as? String, "remote_flow_endpoint_hostport")
        XCTAssertEqual(diagnostic["flow_authority_port_source_gate"] as? String, "hostport_described_port")
        XCTAssertEqual(diagnostic["allow_flow_authority_port_match"] as? String, "off_by_delta")
        XCTAssertEqual(diagnostic["handle_new_flow_decision_category"] as? String, "deny_closed")
        XCTAssertEqual(diagnostic["single_rule_lab_fallback_port_gate"] as? String, "mismatch")
    }

    func testM1206URLRemoteFlowEndpointFeedsSingleRuleLabFallbackPortMatch() throws {
        let manager = try startedLifecycleManager()
        let url = try XCTUnwrap(URL(string: "tcp://phase2-target-alias.local:5432"))
        let input = try XCTUnwrap(DsseAppProxyProvider.authorityInput(fromRemoteFlowEndpoint: .url(url)))

        XCTAssertEqual(input.transport, .tcp)
        XCTAssertEqual(input.remoteHost, "phase2-target-alias.local")
        XCTAssertEqual(input.remotePort, 5432)

        let report = DsseAppProxyProvider.handleNewFlowCompileHarness(
            input: input,
            lifecycleManager: manager
        )

        XCTAssertEqual(report.status, "ok")
        XCTAssertEqual(report.providerAction, .openTunnel)
        XCTAssertEqual(report.action, NetworkExtensionContract.actionTunnel)
        XCTAssertEqual(report.reason, NetworkExtensionContract.reasonMatched)
        XCTAssertEqual(report.singleRuleLabFallbackGate, "applied")
        XCTAssertTrue(report.acceptFlow)
        XCTAssertEqual(report.returnAction, "take_over_matched_flow_live_copy_real_edge_transport_reviewed")
        assertRuntimeCopyNotStarted(report)
    }

    func testM1206LegacyRemoteEndpointFeedsSingleRuleLabFallbackPortMatch() throws {
        let manager = try startedLifecycleManager()
        let endpoint = LegacyRemoteEndpointProbe(hostname: "phase2-target-alias.local", port: "5432")
        let input = try XCTUnwrap(DsseAppProxyProvider.authorityInputFromLegacyRemoteEndpoint(endpoint))

        XCTAssertEqual(input.transport, .tcp)
        XCTAssertEqual(input.remoteHost, "phase2-target-alias.local")
        XCTAssertEqual(input.remotePort, 5432)

        let report = DsseAppProxyProvider.handleNewFlowCompileHarness(
            input: input,
            lifecycleManager: manager
        )

        XCTAssertEqual(report.status, "ok")
        XCTAssertEqual(report.flowExtractionStatus, .ok)
        XCTAssertEqual(report.flowExtractionReason, .extracted)
        XCTAssertEqual(report.providerAction, .openTunnel)
        XCTAssertEqual(report.action, NetworkExtensionContract.actionTunnel)
        XCTAssertEqual(report.reason, NetworkExtensionContract.reasonMatched)
        XCTAssertEqual(report.singleRuleLabFallbackGate, "applied")
        XCTAssertTrue(report.acceptFlow)
        XCTAssertEqual(report.returnAction, "take_over_matched_flow_live_copy_real_edge_transport_reviewed")
        assertRuntimeCopyNotStarted(report)
    }


    func testLocalRuntimeCopyDriverRoundTripsSyntheticBytesWithoutRuntimeFlags() throws {
        let upstreamPayload = Data("synthetic-client-bytes".utf8)
        let downstreamPayload = Data("synthetic-private-response".utf8)
        let metadata = DsseLocalRuntimeCopyMetadata(
            tenantID: "tenant_lab_001",
            requestID: "req_lab_001",
            applicationID: "app_dummy_postgres"
        )

        let result = try DsseLocalRuntimeCopyDriver().copyRoundTrip(
            upstreamPayload: upstreamPayload,
            metadata: metadata,
            transport: DsseLoopbackRuntimeCopyTransport(downstreamPayload: downstreamPayload)
        )

        XCTAssertEqual(result.status, "ok")
        XCTAssertEqual(result.implementation, DsseLocalRuntimeCopyImplementationContract.implementation)
        XCTAssertEqual(result.bytesUp, upstreamPayload.count)
        XCTAssertEqual(result.bytesDown, downstreamPayload.count)
        XCTAssertEqual(result.registryCleanupGate, "cleaned")
        XCTAssertEqual(result.tenantMetadataCleanupGate, "cleaned")
        XCTAssertEqual(result.auditMetadataOnlyGate, "ok")
        XCTAssertFalse(result.connectionRegistryRuntimeConnected)
        XCTAssertFalse(result.byteCapRuntimeEnforced)
        XCTAssertFalse(result.idleTimeoutRuntimeEnforced)
        XCTAssertFalse(result.boundedBackpressureRuntimeEnforced)
        XCTAssertFalse(result.flowReadHalfCloseRuntimeEnforced)
        XCTAssertFalse(result.flowWriteHalfCloseRuntimeEnforced)
        XCTAssertFalse(result.networkExtensionFlowOpened)
        XCTAssertFalse(result.edgeTunnelOpenStarted)
        XCTAssertFalse(result.tcpPayloadCopyStarted)
        XCTAssertFalse(result.flowPayloadReadStarted)
        XCTAssertFalse(result.flowPayloadWriteStarted)
    }

    func testDefaultDenyPathEvidenceStateCoversClosedWithoutCopyAuditDegraded() throws {
        let manager = try startedLifecycleManager()

        let evidence = DsseAppProxyProvider.policyDrivenHandleNewFlowAuditEvidence(
            input: ProviderFlowAuthorityInput(
                transport: .tcp,
                remoteHost: "dummy-private-app.local",
                remotePort: 443
            ),
            lifecycleManager: manager,
            auditMetadataOnlyGateOverride: "not_ok"
        )

        XCTAssertEqual(evidence.status, "invalid")
        XCTAssertEqual(evidence.policyDecisionCategory, "default_deny")
        XCTAssertEqual(evidence.copyAttemptGate, "closed_without_copy")
        XCTAssertEqual(evidence.defaultDenyGate, "closed_without_copy")
        XCTAssertEqual(evidence.defaultDenyPathEvidenceState, .closedWithoutCopy)
        XCTAssertTrue(evidence.denyClosedWithoutCopy)
        XCTAssertFalse(evidence.copyStarted)
        XCTAssertFalse(evidence.networkExtensionFlowOpened)
        XCTAssertFalse(evidence.edgeTunnelOpenStarted)
        XCTAssertFalse(evidence.tcpPayloadCopyStarted)
        XCTAssertFalse(evidence.flowPayloadReadStarted)
        XCTAssertFalse(evidence.flowPayloadWriteStarted)
        XCTAssertEqual(evidence.bytesUp, 0)
        XCTAssertEqual(evidence.bytesDown, 0)
        XCTAssertEqual(evidence.auditMetadataOnlyGate, "not_ok")
    }

    func testLiveRuntimeCopyDriverOpensReadsTransportsWritesAndClosesMockFlow() throws {
        let upstreamPayload = Data("synthetic-client-bytes".utf8)
        let downstreamPayload = Data("synthetic-private-response".utf8)
        let flow = MockProviderTCPFlowCopyIO(upstreamPayload: upstreamPayload)
        let transport = RecordingRuntimeCopyTransport(downstreamPayload: downstreamPayload)
        let liveGuard = DsseLiveRuntimeCopyGuard()
        let metadata = DsseLocalRuntimeCopyMetadata(
            tenantID: "tenant_lab_001",
            requestID: "req_live_001",
            applicationID: "app_dummy_postgres"
        )
        let progressEvents = RuntimeCopyProgressBox()
        let completion = expectation(description: "live runtime copy completed")
        let completedResult = RuntimeCopyResultBox()

        DsseLocalRuntimeCopyDriver(liveGuard: liveGuard).driveLiveTakeover(
            flow: flow,
            metadata: metadata,
            transport: transport,
            progressHandler: { progress in
                progressEvents.append(progress)
            }
        ) { result in
            completedResult.result = result
            completion.fulfill()
        }
        wait(for: [completion], timeout: 1.0)

        let result = try XCTUnwrap(completedResult.result).get()
        XCTAssertTrue(flow.opened)
        XCTAssertEqual(flow.readCount, 1)
        XCTAssertEqual(flow.writtenPayloads, [downstreamPayload])
        XCTAssertTrue(flow.closedRead)
        XCTAssertTrue(flow.closedWrite)
        XCTAssertEqual(transport.seenPayloads, [upstreamPayload])
        XCTAssertEqual(transport.seenMetadata, [metadata])
        XCTAssertEqual(result.status, "ok")
        XCTAssertEqual(result.implementation, DsseLocalRuntimeCopyImplementationContract.implementation)
        XCTAssertEqual(result.bytesUp, upstreamPayload.count)
        XCTAssertEqual(result.bytesDown, downstreamPayload.count)
        XCTAssertEqual(result.registryCleanupGate, "cleaned")
        XCTAssertEqual(result.tenantMetadataCleanupGate, "cleaned")
        XCTAssertEqual(result.auditMetadataOnlyGate, "ok")
        XCTAssertTrue(result.connectionRegistryRuntimeConnected)
        XCTAssertTrue(result.byteCapRuntimeEnforced)
        XCTAssertTrue(result.idleTimeoutRuntimeEnforced)
        XCTAssertTrue(result.boundedBackpressureRuntimeEnforced)
        XCTAssertTrue(result.flowReadHalfCloseRuntimeEnforced)
        XCTAssertTrue(result.flowWriteHalfCloseRuntimeEnforced)
        XCTAssertTrue(result.networkExtensionFlowOpened)
        XCTAssertTrue(result.edgeTunnelOpenStarted)
        XCTAssertTrue(result.tcpPayloadCopyStarted)
        XCTAssertTrue(result.flowPayloadReadStarted)
        XCTAssertTrue(result.flowPayloadWriteStarted)
        XCTAssertEqual(liveGuard.activeCount, 0)
        XCTAssertEqual(progressEvents.values, [
            .liveCopyStarted,
            .flowOpenCompleted,
            .upstreamReadCompleted(bytes: upstreamPayload.count),
            .edgeRoundTripStarted,
            .edgeRoundTripRequestSent,
            .edgeRoundTripResponseBodyReceived,
            .edgeRoundTripCompleted,
            .downstreamWriteStarted,
            .downstreamWriteCompleted
        ])
    }

    func testLiveRuntimeCopyDriverUsesSessionTransportForMultipleFlowChunks() throws {
        let upstreamPayloads = [
            Data("synthetic-client-chunk-1".utf8),
            Data("synthetic-client-chunk-2".utf8)
        ]
        let downstreamPayloads = [
            Data("synthetic-private-response-1".utf8),
            Data("synthetic-private-response-2".utf8)
        ]
        let flow = MultiReadProviderTCPFlowCopyIO(upstreamPayloads: upstreamPayloads)
        let closeCompletion = expectation(description: "session transport closed")
        let transport = RecordingSessionRuntimeCopyTransport(downstreamPayloads: downstreamPayloads) {
            closeCompletion.fulfill()
        }
        let liveGuard = DsseLiveRuntimeCopyGuard()
        let metadata = DsseLocalRuntimeCopyMetadata(
            tenantID: "tenant_lab_001",
            requestID: "req_live_session_001",
            applicationID: "app_dummy_postgres",
            destinationHost: "dummy-postgres.local",
            destinationPort: 5432
        )
        let progressEvents = RuntimeCopyProgressBox()
        let completion = expectation(description: "session live runtime copy completed")
        let completedResult = RuntimeCopyResultBox()

        DsseLocalRuntimeCopyDriver(liveGuard: liveGuard).driveLiveTakeover(
            flow: flow,
            metadata: metadata,
            transport: transport,
            progressHandler: { progress in
                progressEvents.append(progress)
            }
        ) { result in
            completedResult.result = result
            completion.fulfill()
        }
        wait(for: [completion, closeCompletion], timeout: 1.0)

        let result = try XCTUnwrap(completedResult.result).get()
        XCTAssertTrue(flow.opened)
        XCTAssertEqual(flow.readCount, 3)
        XCTAssertEqual(flow.writtenPayloads, downstreamPayloads)
        XCTAssertTrue(flow.closedRead)
        XCTAssertTrue(flow.closedWrite)
        XCTAssertEqual(transport.seenOperations, [.open, .exchange])
        XCTAssertEqual(transport.seenPayloads, upstreamPayloads)
        XCTAssertEqual(transport.closeCount, 1)
        XCTAssertEqual(result.bytesUp, upstreamPayloads.reduce(0) { $0 + $1.count })
        XCTAssertEqual(result.bytesDown, downstreamPayloads.reduce(0) { $0 + $1.count })
        XCTAssertTrue(result.networkExtensionFlowOpened)
        XCTAssertTrue(result.tcpPayloadCopyStarted)
        XCTAssertFalse(liveGuard.isActive(requestID: metadata.requestID))
        XCTAssertTrue(progressEvents.values.contains(.edgeRoundTripCompleted))
        XCTAssertTrue(progressEvents.values.contains(.downstreamWriteCompleted))
    }

    func testLiveRuntimeCopyDriverContinuesSessionAfterEmptyDownstreamFlight() throws {
        let upstreamPayloads = [
            Data("tls-client-hello".utf8),
            Data("tls-client-finished-no-server-flight".utf8),
            Data("tls-http-request".utf8)
        ]
        let firstDownstreamPayload = Data("tls-server-handshake-flight".utf8)
        let finalDownstreamPayload = Data("tls-http-response".utf8)
        let flow = MultiReadProviderTCPFlowCopyIO(upstreamPayloads: upstreamPayloads)
        let closeCompletion = expectation(description: "empty-flight session transport closed")
        let transport = RecordingSessionRuntimeCopyTransport(
            downstreamPayloads: [firstDownstreamPayload, Data(), finalDownstreamPayload]
        ) {
            closeCompletion.fulfill()
        }
        let metadata = DsseLocalRuntimeCopyMetadata(
            tenantID: "tenant_lab_001",
            requestID: "req_live_session_empty_flight",
            applicationID: "app_dummy_tls",
            destinationHost: "example.com",
            destinationPort: 443
        )
        let progressEvents = RuntimeCopyProgressBox()
        let completion = expectation(description: "session live runtime copy skipped empty downstream flight")
        let completedResult = RuntimeCopyResultBox()

        DsseLocalRuntimeCopyDriver().driveLiveTakeover(
            flow: flow,
            metadata: metadata,
            transport: transport,
            progressHandler: { progress in
                progressEvents.append(progress)
            }
        ) { result in
            completedResult.result = result
            completion.fulfill()
        }
        wait(for: [completion, closeCompletion], timeout: 1.0)

        let result = try XCTUnwrap(completedResult.result).get()
        XCTAssertTrue(flow.opened)
        XCTAssertEqual(flow.readCount, 4)
        XCTAssertEqual(flow.writtenPayloads, [firstDownstreamPayload, finalDownstreamPayload])
        XCTAssertTrue(flow.closedRead)
        XCTAssertTrue(flow.closedWrite)
        XCTAssertEqual(transport.seenOperations, [.open, .exchange, .exchange])
        XCTAssertEqual(transport.seenPayloads, upstreamPayloads)
        XCTAssertEqual(transport.closeCount, 1)
        XCTAssertEqual(result.bytesUp, upstreamPayloads.reduce(0) { $0 + $1.count })
        XCTAssertEqual(result.bytesDown, firstDownstreamPayload.count + finalDownstreamPayload.count)
        XCTAssertEqual(progressEvents.values.filter { $0 == .edgeRoundTripCompleted }.count, 3)
        XCTAssertEqual(progressEvents.values.filter { $0 == .downstreamWriteCompleted }.count, 2)
    }

    func testLiveRuntimeCopyDriverCompletesAfterSessionClosedDownstreamWrite() throws {
        let upstreamPayload = Data("tls-http-request".utf8)
        let downstreamPayload = Data("tls-http-response".utf8)
        let flow = MultiReadProviderTCPFlowCopyIO(upstreamPayloads: [upstreamPayload])
        let closeCompletion = expectation(description: "session closed transport closed")
        let transport = RecordingSessionRuntimeCopyTransport(
            downstreamPayloads: [downstreamPayload],
            sessionClosedResponses: [true]
        ) {
            closeCompletion.fulfill()
        }
        let metadata = DsseLocalRuntimeCopyMetadata(
            tenantID: "tenant_lab_001",
            requestID: "req_live_session_closed_after_response",
            applicationID: "app_dummy_tls",
            destinationHost: "example.com",
            destinationPort: 443
        )
        let progressEvents = RuntimeCopyProgressBox()
        let completion = expectation(description: "session live runtime copy completed after closed response")
        let completedResult = RuntimeCopyResultBox()

        DsseLocalRuntimeCopyDriver().driveLiveTakeover(
            flow: flow,
            metadata: metadata,
            transport: transport,
            progressHandler: { progress in
                progressEvents.append(progress)
            }
        ) { result in
            completedResult.result = result
            completion.fulfill()
        }
        wait(for: [completion, closeCompletion], timeout: 1.0)

        let result = try XCTUnwrap(completedResult.result).get()
        XCTAssertTrue(flow.opened)
        XCTAssertEqual(flow.readCount, 1)
        XCTAssertEqual(flow.writtenPayloads, [downstreamPayload])
        XCTAssertTrue(flow.closedRead)
        XCTAssertTrue(flow.closedWrite)
        XCTAssertEqual(transport.seenOperations, [.open])
        XCTAssertEqual(transport.seenPayloads, [upstreamPayload])
        XCTAssertEqual(transport.closeCount, 1)
        XCTAssertEqual(result.bytesUp, upstreamPayload.count)
        XCTAssertEqual(result.bytesDown, downstreamPayload.count)
        XCTAssertEqual(progressEvents.values.filter { $0 == .edgeRoundTripCompleted }.count, 1)
        XCTAssertEqual(progressEvents.values.filter { $0 == .downstreamWriteCompleted }.count, 1)
    }

    func testLiveRuntimeCopyDriverCompletesSessionAfterReadIdleFollowingSuccessfulExchange() throws {
        let upstreamPayload = Data("synthetic-client-first-chunk".utf8)
        let downstreamPayload = Data("synthetic-private-first-response".utf8)
        let flow = HangingAfterPayloadsProviderTCPFlowCopyIO(upstreamPayloads: [upstreamPayload])
        let closeCompletion = expectation(description: "idle session transport closed")
        let transport = RecordingSessionRuntimeCopyTransport(downstreamPayloads: [downstreamPayload]) {
            closeCompletion.fulfill()
        }
        let liveGuard = DsseLiveRuntimeCopyGuard()
        let metadata = DsseLocalRuntimeCopyMetadata(
            tenantID: "tenant_lab_001",
            requestID: "req_live_session_idle_after_success",
            applicationID: "app_dummy_postgres",
            destinationHost: "dummy-postgres.local",
            destinationPort: 5432
        )
        let completion = expectation(description: "idle session live runtime copy completed")
        let completedResult = RuntimeCopyResultBox()

        DsseLocalRuntimeCopyDriver(
            liveGuard: liveGuard,
            stepTimeoutInterval: 0.02
        ).driveLiveTakeover(
            flow: flow,
            metadata: metadata,
            transport: transport
        ) { result in
            completedResult.result = result
            completion.fulfill()
        }
        wait(for: [completion, closeCompletion], timeout: 1.0)

        let result = try XCTUnwrap(completedResult.result).get()
        XCTAssertTrue(flow.opened)
        XCTAssertEqual(flow.readCount, 2)
        XCTAssertEqual(flow.writtenPayloads, [downstreamPayload])
        XCTAssertTrue(flow.closedRead)
        XCTAssertTrue(flow.closedWrite)
        XCTAssertEqual(transport.seenOperations, [.open])
        XCTAssertEqual(transport.seenPayloads, [upstreamPayload])
        XCTAssertEqual(transport.closeCount, 1)
        XCTAssertEqual(result.bytesUp, upstreamPayload.count)
        XCTAssertEqual(result.bytesDown, downstreamPayload.count)
        XCTAssertFalse(liveGuard.isActive(requestID: metadata.requestID))
    }

    func testLiveRuntimeCopyDriverTimesOutWhenFlowOpenDoesNotComplete() throws {
        let upstreamPayload = Data("synthetic-client-bytes".utf8)
        let downstreamPayload = Data("synthetic-private-response".utf8)
        let flow = HangingOpenProviderTCPFlowCopyIO(upstreamPayload: upstreamPayload)
        let transport = RecordingRuntimeCopyTransport(downstreamPayload: downstreamPayload)
        let liveGuard = DsseLiveRuntimeCopyGuard()
        let metadata = DsseLocalRuntimeCopyMetadata(
            tenantID: "tenant_lab_001",
            requestID: "req_live_open_timeout",
            applicationID: "app_dummy_postgres"
        )
        let progressEvents = RuntimeCopyProgressBox()
        let completion = expectation(description: "flow open timeout failed runtime copy")
        let completedResult = RuntimeCopyResultBox()

        DsseLocalRuntimeCopyDriver(
            liveGuard: liveGuard,
            stepTimeoutInterval: 0.05,
            flowOpenTimeoutInterval: 0.05
        ).driveLiveTakeover(
            flow: flow,
            metadata: metadata,
            transport: transport,
            progressHandler: { progress in
                progressEvents.append(progress)
            }
        ) { result in
            completedResult.result = result
            completion.fulfill()
        }
        wait(for: [completion], timeout: 1.0)

        XCTAssertThrowsError(try XCTUnwrap(completedResult.result).get()) { error in
            XCTAssertEqual(error as? DsseLocalRuntimeCopyDriverError, .flowOpenTimeout)
        }
        XCTAssertTrue(flow.openAttempted)
        XCTAssertEqual(flow.readCount, 0)
        XCTAssertEqual(flow.writtenPayloads, [])
        XCTAssertTrue(flow.closedRead)
        XCTAssertTrue(flow.closedWrite)
        XCTAssertEqual(transport.seenPayloads, [])
        XCTAssertFalse(liveGuard.isActive(requestID: metadata.requestID))
        XCTAssertEqual(progressEvents.values, [.liveCopyStarted])
    }

    func testLiveRuntimeCopyDriverTimesOutWhenEdgeRoundTripDoesNotComplete() throws {
        let upstreamPayload = Data("synthetic-client-bytes".utf8)
        let flow = MockProviderTCPFlowCopyIO(upstreamPayload: upstreamPayload)
        let transport = BlockedRuntimeCopyTransport(downstreamPayload: Data("late-response".utf8))
        defer { transport.release.signal() }
        let liveGuard = DsseLiveRuntimeCopyGuard()
        let metadata = DsseLocalRuntimeCopyMetadata(
            tenantID: "tenant_lab_001",
            requestID: "req_live_edge_timeout",
            applicationID: "app_dummy_postgres"
        )
        let progressEvents = RuntimeCopyProgressBox()
        let completion = expectation(description: "edge round trip timeout failed runtime copy")
        let completedResult = RuntimeCopyResultBox()

        DsseLocalRuntimeCopyDriver(
            liveGuard: liveGuard,
            stepTimeoutInterval: 0.05
        ).driveLiveTakeover(
            flow: flow,
            metadata: metadata,
            transport: transport,
            progressHandler: { progress in
                progressEvents.append(progress)
            }
        ) { result in
            completedResult.result = result
            completion.fulfill()
        }
        wait(for: [completion], timeout: 1.0)

        XCTAssertThrowsError(try XCTUnwrap(completedResult.result).get()) { error in
            XCTAssertEqual(error as? DsseLocalRuntimeCopyDriverError, .edgeRoundTripTimeout)
        }
        XCTAssertTrue(flow.opened)
        XCTAssertEqual(flow.readCount, 1)
        XCTAssertEqual(flow.writtenPayloads, [])
        XCTAssertTrue(flow.closedRead)
        XCTAssertTrue(flow.closedWrite)
        XCTAssertEqual(transport.seenPayloads, [upstreamPayload])
        XCTAssertFalse(liveGuard.isActive(requestID: metadata.requestID))
        XCTAssertEqual(progressEvents.values, [
            .liveCopyStarted,
            .flowOpenCompleted,
            .upstreamReadCompleted(bytes: upstreamPayload.count),
            .edgeRoundTripStarted,
            .edgeRoundTripRequestSent
        ])
    }

    func testLiveRuntimeCopyDriverArmsEdgeTimeoutBeforeProgressHandlerCanBlock() throws {
        let upstreamPayload = Data("synthetic-client-bytes".utf8)
        let flow = MockProviderTCPFlowCopyIO(upstreamPayload: upstreamPayload)
        let transport = RecordingRuntimeCopyTransport(downstreamPayload: Data("late-response".utf8))
        let metadata = DsseLocalRuntimeCopyMetadata(
            tenantID: "tenant_lab_001",
            requestID: "req_live_edge_progress_blocked",
            applicationID: "app_dummy_postgres"
        )
        let progressEvents = RuntimeCopyProgressBox()
        let unblockProgress = DispatchSemaphore(value: 0)
        let completion = expectation(description: "edge timeout failed despite blocked progress handler")
        let completedResult = RuntimeCopyResultBox()

        DsseLocalRuntimeCopyDriver(
            stepTimeoutInterval: 0.05
        ).driveLiveTakeover(
            flow: flow,
            metadata: metadata,
            transport: transport,
            progressHandler: { progress in
                progressEvents.append(progress)
                if progress == .edgeRoundTripStarted {
                    _ = unblockProgress.wait(timeout: .now() + 1.0)
                }
            }
        ) { result in
            completedResult.result = result
            completion.fulfill()
        }
        wait(for: [completion], timeout: 1.0)
        unblockProgress.signal()

        XCTAssertThrowsError(try XCTUnwrap(completedResult.result).get()) { error in
            XCTAssertEqual(error as? DsseLocalRuntimeCopyDriverError, .edgeRoundTripTimeout)
        }
        XCTAssertEqual(transport.seenPayloads, [])
        XCTAssertTrue(flow.closedRead)
        XCTAssertTrue(flow.closedWrite)
        XCTAssertEqual(progressEvents.values, [
            .liveCopyStarted,
            .flowOpenCompleted,
            .upstreamReadCompleted(bytes: upstreamPayload.count),
            .edgeRoundTripStarted
        ])
    }

    func testLiveRuntimeCopyDriverReportsFlowWriteFailureAfterEdgeRoundTripCompleted() throws {
        let upstreamPayload = Data("synthetic-client-bytes".utf8)
        let downstreamPayload = Data("synthetic-private-response".utf8)
        let flow = FailingWriteProviderTCPFlowCopyIO(upstreamPayload: upstreamPayload)
        let transport = RecordingRuntimeCopyTransport(downstreamPayload: downstreamPayload)
        let metadata = DsseLocalRuntimeCopyMetadata(
            tenantID: "tenant_lab_001",
            requestID: "req_live_flow_write_failed",
            applicationID: "app_dummy_postgres"
        )
        let progressEvents = RuntimeCopyProgressBox()
        let completion = expectation(description: "flow write failure closed runtime copy")
        let completedResult = RuntimeCopyResultBox()

        DsseLocalRuntimeCopyDriver().driveLiveTakeover(
            flow: flow,
            metadata: metadata,
            transport: transport,
            progressHandler: { progress in
                progressEvents.append(progress)
            }
        ) { result in
            completedResult.result = result
            completion.fulfill()
        }
        wait(for: [completion], timeout: 1.0)

        XCTAssertThrowsError(try XCTUnwrap(completedResult.result).get()) { error in
            XCTAssertEqual(error as? DsseLocalRuntimeCopyDriverError, .flowWriteFailed)
        }
        XCTAssertTrue(flow.opened)
        XCTAssertEqual(flow.readCount, 1)
        XCTAssertEqual(flow.writtenPayloads, [downstreamPayload])
        XCTAssertTrue(flow.closedRead)
        XCTAssertTrue(flow.closedWrite)
        XCTAssertEqual(transport.seenPayloads, [upstreamPayload])
        XCTAssertEqual(progressEvents.values, [
            .liveCopyStarted,
            .flowOpenCompleted,
            .upstreamReadCompleted(bytes: upstreamPayload.count),
            .edgeRoundTripStarted,
            .edgeRoundTripRequestSent,
            .edgeRoundTripResponseBodyReceived,
            .edgeRoundTripCompleted,
            .downstreamWriteStarted,
            .downstreamWriteFailed(category: "driver_flow_write_error")
        ])
    }

    func testLiveRuntimeCopyDriverClassifiesNetworkExtensionFlowWriteNSError() throws {
        let upstreamPayload = Data("synthetic-client-bytes".utf8)
        let downstreamPayload = Data("synthetic-private-response".utf8)
        let flow = FailingWriteProviderTCPFlowCopyIO(
            upstreamPayload: upstreamPayload,
            writeError: NSError(
                domain: "com.apple.NetworkExtension.NEAppProxyFlowError",
                code: 7,
                userInfo: nil
            )
        )
        let transport = RecordingRuntimeCopyTransport(downstreamPayload: downstreamPayload)
        let metadata = DsseLocalRuntimeCopyMetadata(
            tenantID: "tenant_lab_001",
            requestID: "req_live_flow_write_ne_provider_failed",
            applicationID: "app_dummy_postgres"
        )
        let progressEvents = RuntimeCopyProgressBox()
        let completion = expectation(description: "network extension flow write failure classified")
        let completedResult = RuntimeCopyResultBox()

        DsseLocalRuntimeCopyDriver().driveLiveTakeover(
            flow: flow,
            metadata: metadata,
            transport: transport,
            progressHandler: { progress in
                progressEvents.append(progress)
            }
        ) { result in
            completedResult.result = result
            completion.fulfill()
        }
        wait(for: [completion], timeout: 1.0)

        XCTAssertThrowsError(try XCTUnwrap(completedResult.result).get()) { error in
            XCTAssertEqual(error as? DsseLocalRuntimeCopyDriverError, .flowWriteFailed)
        }
        XCTAssertEqual(progressEvents.values, [
            .liveCopyStarted,
            .flowOpenCompleted,
            .upstreamReadCompleted(bytes: upstreamPayload.count),
            .edgeRoundTripStarted,
            .edgeRoundTripRequestSent,
            .edgeRoundTripResponseBodyReceived,
            .edgeRoundTripCompleted,
            .downstreamWriteStarted,
            .downstreamWriteFailed(category: "ne_provider_flow_error")
        ])
    }

    func testLiveRuntimeCopyDriverTimesOutWhenFlowWriteDoesNotComplete() throws {
        let upstreamPayload = Data("synthetic-client-bytes".utf8)
        let downstreamPayload = Data("synthetic-private-response".utf8)
        let flow = HangingWriteProviderTCPFlowCopyIO(upstreamPayload: upstreamPayload)
        let transport = RecordingRuntimeCopyTransport(downstreamPayload: downstreamPayload)
        let metadata = DsseLocalRuntimeCopyMetadata(
            tenantID: "tenant_lab_001",
            requestID: "req_live_flow_write_timeout",
            applicationID: "app_dummy_postgres"
        )
        let progressEvents = RuntimeCopyProgressBox()
        let completion = expectation(description: "flow write timeout closed runtime copy")
        let completedResult = RuntimeCopyResultBox()

        DsseLocalRuntimeCopyDriver(stepTimeoutInterval: 0.05).driveLiveTakeover(
            flow: flow,
            metadata: metadata,
            transport: transport,
            progressHandler: { progress in
                progressEvents.append(progress)
            }
        ) { result in
            completedResult.result = result
            completion.fulfill()
        }
        wait(for: [completion], timeout: 1.0)

        XCTAssertThrowsError(try XCTUnwrap(completedResult.result).get()) { error in
            XCTAssertEqual(error as? DsseLocalRuntimeCopyDriverError, .flowWriteTimeout)
        }
        XCTAssertTrue(flow.opened)
        XCTAssertEqual(flow.readCount, 1)
        XCTAssertEqual(flow.writtenPayloads, [downstreamPayload])
        XCTAssertTrue(flow.closedRead)
        XCTAssertTrue(flow.closedWrite)
        XCTAssertEqual(transport.seenPayloads, [upstreamPayload])
        XCTAssertEqual(progressEvents.values, [
            .liveCopyStarted,
            .flowOpenCompleted,
            .upstreamReadCompleted(bytes: upstreamPayload.count),
            .edgeRoundTripStarted,
            .edgeRoundTripRequestSent,
            .edgeRoundTripResponseBodyReceived,
            .edgeRoundTripCompleted,
            .downstreamWriteStarted
        ])
    }

    func testLiveRuntimeCopyDriverArmsWriteTimeoutBeforeProgressHandlerCanBlock() throws {
        let upstreamPayload = Data("synthetic-client-bytes".utf8)
        let flow = MockProviderTCPFlowCopyIO(upstreamPayload: upstreamPayload)
        let transport = RecordingRuntimeCopyTransport(downstreamPayload: Data("synthetic-private-response".utf8))
        let metadata = DsseLocalRuntimeCopyMetadata(
            tenantID: "tenant_lab_001",
            requestID: "req_live_write_progress_blocked",
            applicationID: "app_dummy_postgres"
        )
        let progressEvents = RuntimeCopyProgressBox()
        let unblockProgress = DispatchSemaphore(value: 0)
        let completion = expectation(description: "write timeout failed despite blocked progress handler")
        let completedResult = RuntimeCopyResultBox()

        DsseLocalRuntimeCopyDriver(stepTimeoutInterval: 0.05).driveLiveTakeover(
            flow: flow,
            metadata: metadata,
            transport: transport,
            progressHandler: { progress in
                progressEvents.append(progress)
                if progress == .downstreamWriteStarted {
                    _ = unblockProgress.wait(timeout: .now() + 1.0)
                }
            }
        ) { result in
            completedResult.result = result
            completion.fulfill()
        }
        wait(for: [completion], timeout: 1.0)
        unblockProgress.signal()

        XCTAssertThrowsError(try XCTUnwrap(completedResult.result).get()) { error in
            XCTAssertEqual(error as? DsseLocalRuntimeCopyDriverError, .flowWriteTimeout)
        }
        XCTAssertEqual(flow.writtenPayloads, [])
        XCTAssertTrue(flow.closedRead)
        XCTAssertTrue(flow.closedWrite)
        XCTAssertEqual(progressEvents.values, [
            .liveCopyStarted,
            .flowOpenCompleted,
            .upstreamReadCompleted(bytes: upstreamPayload.count),
            .edgeRoundTripStarted,
            .edgeRoundTripRequestSent,
            .edgeRoundTripResponseBodyReceived,
            .edgeRoundTripCompleted,
            .downstreamWriteStarted
        ])
    }

    func testLiveRuntimeCopyDriverRejectsDuplicateRequestIDBeforeFlowOpen() throws {
        let upstreamPayload = Data("synthetic-client-bytes".utf8)
        let downstreamPayload = Data("synthetic-private-response".utf8)
        let flow = MockProviderTCPFlowCopyIO(upstreamPayload: upstreamPayload)
        let transport = RecordingRuntimeCopyTransport(downstreamPayload: downstreamPayload)
        let liveGuard = DsseLiveRuntimeCopyGuard()
        let metadata = DsseLocalRuntimeCopyMetadata(
            tenantID: "tenant_lab_001",
            requestID: "req_live_duplicate",
            applicationID: "app_dummy_postgres"
        )
        try liveGuard.open(metadata: metadata)
        defer { liveGuard.close(requestID: metadata.requestID) }
        let completion = expectation(description: "duplicate runtime copy failed before flow open")
        let completedResult = RuntimeCopyResultBox()

        DsseLocalRuntimeCopyDriver(liveGuard: liveGuard).driveLiveTakeover(
            flow: flow,
            metadata: metadata,
            transport: transport
        ) { result in
            completedResult.result = result
            completion.fulfill()
        }
        wait(for: [completion], timeout: 1.0)

        XCTAssertThrowsError(try XCTUnwrap(completedResult.result).get()) { error in
            XCTAssertEqual(error as? DsseLocalRuntimeCopyDriverError, .duplicateRuntimeCopyRequestID)
        }
        XCTAssertFalse(flow.opened)
        XCTAssertEqual(flow.readCount, 0)
        XCTAssertEqual(flow.writtenPayloads, [])
        XCTAssertTrue(flow.closedRead)
        XCTAssertTrue(flow.closedWrite)
        XCTAssertEqual(transport.seenPayloads, [])
        XCTAssertTrue(liveGuard.isActive(requestID: metadata.requestID))
        XCTAssertEqual(liveGuard.activeCount, 1)
    }

    func testLiveRuntimeCopyDriverRejectsConcurrentCapBeforeFlowOpen() throws {
        let upstreamPayload = Data("synthetic-client-bytes".utf8)
        let downstreamPayload = Data("synthetic-private-response".utf8)
        let flow = MockProviderTCPFlowCopyIO(upstreamPayload: upstreamPayload)
        let transport = RecordingRuntimeCopyTransport(downstreamPayload: downstreamPayload)
        let liveGuard = DsseLiveRuntimeCopyGuard(configuration: DsseLiveRuntimeCopyGuardConfiguration(
            maxConcurrentConnections: 1
        ))
        let existingMetadata = DsseLocalRuntimeCopyMetadata(
            tenantID: "tenant_lab_001",
            requestID: "req_live_existing",
            applicationID: "app_dummy_postgres"
        )
        let blockedMetadata = DsseLocalRuntimeCopyMetadata(
            tenantID: "tenant_lab_001",
            requestID: "req_live_concurrent_cap",
            applicationID: "app_dummy_postgres"
        )
        try liveGuard.open(metadata: existingMetadata)
        defer { liveGuard.close(requestID: existingMetadata.requestID) }
        let completion = expectation(description: "concurrent cap failed before flow open")
        let completedResult = RuntimeCopyResultBox()

        DsseLocalRuntimeCopyDriver(liveGuard: liveGuard).driveLiveTakeover(
            flow: flow,
            metadata: blockedMetadata,
            transport: transport
        ) { result in
            completedResult.result = result
            completion.fulfill()
        }
        wait(for: [completion], timeout: 1.0)

        XCTAssertThrowsError(try XCTUnwrap(completedResult.result).get()) { error in
            XCTAssertEqual(error as? DsseLocalRuntimeCopyDriverError, .runtimeCopyConcurrentCapExceeded)
        }
        XCTAssertFalse(flow.opened)
        XCTAssertEqual(flow.readCount, 0)
        XCTAssertEqual(flow.writtenPayloads, [])
        XCTAssertTrue(flow.closedRead)
        XCTAssertTrue(flow.closedWrite)
        XCTAssertEqual(transport.seenPayloads, [])
        XCTAssertTrue(liveGuard.isActive(requestID: existingMetadata.requestID))
        XCTAssertFalse(liveGuard.isActive(requestID: blockedMetadata.requestID))
        XCTAssertEqual(liveGuard.activeCount, 1)
    }

    func testLiveRuntimeCopyDriverByteCapClosesBeforeTransportOrWrite() throws {
        let upstreamPayload = Data("synthetic-client-bytes".utf8)
        let downstreamPayload = Data("synthetic-private-response".utf8)
        let flow = MockProviderTCPFlowCopyIO(upstreamPayload: upstreamPayload)
        let transport = RecordingRuntimeCopyTransport(downstreamPayload: downstreamPayload)
        let liveGuard = DsseLiveRuntimeCopyGuard(configuration: DsseLiveRuntimeCopyGuardConfiguration(
            maxByteCapBytes: upstreamPayload.count - 1
        ))
        let metadata = DsseLocalRuntimeCopyMetadata(
            tenantID: "tenant_lab_001",
            requestID: "req_live_byte_cap",
            applicationID: "app_dummy_postgres"
        )
        let completion = expectation(description: "byte cap closed runtime copy")
        let completedResult = RuntimeCopyResultBox()

        DsseLocalRuntimeCopyDriver(liveGuard: liveGuard).driveLiveTakeover(
            flow: flow,
            metadata: metadata,
            transport: transport
        ) { result in
            completedResult.result = result
            completion.fulfill()
        }
        wait(for: [completion], timeout: 1.0)

        XCTAssertThrowsError(try XCTUnwrap(completedResult.result).get()) { error in
            XCTAssertEqual(error as? DsseLocalRuntimeCopyDriverError, .runtimeCopyByteCapExceeded)
        }
        XCTAssertTrue(flow.opened)
        XCTAssertEqual(flow.readCount, 1)
        XCTAssertEqual(flow.writtenPayloads, [])
        XCTAssertTrue(flow.closedRead)
        XCTAssertTrue(flow.closedWrite)
        XCTAssertEqual(transport.seenPayloads, [])
        XCTAssertFalse(liveGuard.isActive(requestID: metadata.requestID))
    }

    func testLiveRuntimeCopyDriverIdleTimeoutClosesBeforeTransportOrWrite() throws {
        let upstreamPayload = Data("synthetic-client-bytes".utf8)
        let downstreamPayload = Data("synthetic-private-response".utf8)
        let clock = ManualRuntimeCopyClock(now: Date(timeIntervalSince1970: 0))
        let flow = MockProviderTCPFlowCopyIO(upstreamPayload: upstreamPayload) {
            clock.advance(by: 2)
        }
        let transport = RecordingRuntimeCopyTransport(downstreamPayload: downstreamPayload)
        let liveGuard = DsseLiveRuntimeCopyGuard(configuration: DsseLiveRuntimeCopyGuardConfiguration(
            maxIdleTimeInterval: 1
        ), now: {
            clock.now
        })
        let metadata = DsseLocalRuntimeCopyMetadata(
            tenantID: "tenant_lab_001",
            requestID: "req_live_idle_timeout",
            applicationID: "app_dummy_postgres"
        )
        let completion = expectation(description: "idle timeout closed runtime copy")
        let completedResult = RuntimeCopyResultBox()

        DsseLocalRuntimeCopyDriver(liveGuard: liveGuard).driveLiveTakeover(
            flow: flow,
            metadata: metadata,
            transport: transport
        ) { result in
            completedResult.result = result
            completion.fulfill()
        }
        wait(for: [completion], timeout: 1.0)

        XCTAssertThrowsError(try XCTUnwrap(completedResult.result).get()) { error in
            XCTAssertEqual(error as? DsseLocalRuntimeCopyDriverError, .runtimeCopyIdleTimeoutExceeded)
        }
        XCTAssertTrue(flow.opened)
        XCTAssertEqual(flow.readCount, 1)
        XCTAssertEqual(flow.writtenPayloads, [])
        XCTAssertTrue(flow.closedRead)
        XCTAssertTrue(flow.closedWrite)
        XCTAssertEqual(transport.seenPayloads, [])
        XCTAssertFalse(liveGuard.isActive(requestID: metadata.requestID))
    }

    func testLiveRuntimeCopyDriverBackpressureOverflowClosesBeforeFlowWrite() throws {
        let upstreamPayload = Data("synthetic-client-bytes".utf8)
        let downstreamPayload = Data("synthetic-private-response".utf8)
        let flow = MockProviderTCPFlowCopyIO(upstreamPayload: upstreamPayload)
        let transport = RecordingRuntimeCopyTransport(downstreamPayload: downstreamPayload)
        let liveGuard = DsseLiveRuntimeCopyGuard(configuration: DsseLiveRuntimeCopyGuardConfiguration(
            backpressureQueueCapacity: 0
        ))
        let metadata = DsseLocalRuntimeCopyMetadata(
            tenantID: "tenant_lab_001",
            requestID: "req_live_backpressure",
            applicationID: "app_dummy_postgres"
        )
        let completion = expectation(description: "backpressure closed runtime copy")
        let completedResult = RuntimeCopyResultBox()

        DsseLocalRuntimeCopyDriver(liveGuard: liveGuard).driveLiveTakeover(
            flow: flow,
            metadata: metadata,
            transport: transport
        ) { result in
            completedResult.result = result
            completion.fulfill()
        }
        wait(for: [completion], timeout: 1.0)

        XCTAssertThrowsError(try XCTUnwrap(completedResult.result).get()) { error in
            XCTAssertEqual(error as? DsseLocalRuntimeCopyDriverError, .runtimeCopyBackpressureOverflowClosed)
        }
        XCTAssertTrue(flow.opened)
        XCTAssertEqual(flow.readCount, 1)
        XCTAssertEqual(flow.writtenPayloads, [])
        XCTAssertTrue(flow.closedRead)
        XCTAssertTrue(flow.closedWrite)
        XCTAssertEqual(transport.seenPayloads, [upstreamPayload])
        XCTAssertEqual(transport.seenMetadata, [metadata])
        XCTAssertFalse(liveGuard.isActive(requestID: metadata.requestID))
    }

    func testRuntimeCopyTransportFactoryConfiguresRealEdgeTransportFromAgentConfig() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("dsse-runtime-copy-transport-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        addTeardownBlock {
            try? FileManager.default.removeItem(at: directory)
        }
        let agentConfigURL = directory.appendingPathComponent("agent_config.json")
        try """
        {
          "network_extension_rules_ref": "network_extension_steering_rules.json",
          "edge_url": "https://edge.lab.example.local/base",
          "network_extension_runtime_copy_endpoint_path": "/custom/runtime-copy"
        }
        """.write(to: agentConfigURL, atomically: true, encoding: .utf8)

        let loaded = try DsseLocalRuntimeCopyTransportFactory.edgeConfiguration(
            agentConfigPath: agentConfigURL.path
        )
        XCTAssertEqual(loaded.configuration.roundTripURL.absoluteString, "https://edge.lab.example.local/base/custom/runtime-copy")
        XCTAssertEqual(loaded.configuration.sessionURL.absoluteString, "https://edge.lab.example.local/base/network-extension/runtime-copy/session")
        XCTAssertEqual(loaded.evidenceImplementation, "real_edge_runtime_copy_transport")
        XCTAssertEqual(loaded.edgeConnectorRealness, "in_process_stub")

        let transport = DsseAppProxyProvider.runtimeCopyTransport(agentConfigPath: agentConfigURL.path)
        let edgeTransport = try XCTUnwrap(transport as? DsseEdgeRuntimeCopyTransport)
        XCTAssertEqual(edgeTransport.evidenceImplementation, "real_edge_runtime_copy_transport")
        XCTAssertEqual(edgeTransport.edgeConnectorRealness, "in_process_stub")
    }

    func testRuntimeCopyTransportFactoryLabelsLabEndpointTransportFromAgentConfig() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("dsse-runtime-copy-lab-endpoint-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        addTeardownBlock {
            try? FileManager.default.removeItem(at: directory)
        }
        let agentConfigURL = directory.appendingPathComponent("agent_config.json")
        try """
        {
          "network_extension_rules_ref": "network_extension_steering_rules.json",
          "edge_url": "http://127.0.0.1:18090",
          "network_extension_runtime_copy_endpoint_path": "/network-extension/runtime-copy/round-trip",
          "network_extension_runtime_copy_transport_scope": "lab_endpoint"
        }
        """.write(to: agentConfigURL, atomically: true, encoding: .utf8)

        let loaded = try DsseLocalRuntimeCopyTransportFactory.edgeConfiguration(
            agentConfigPath: agentConfigURL.path
        )
        XCTAssertEqual(loaded.configuration.roundTripURL.absoluteString, "http://127.0.0.1:18090/network-extension/runtime-copy/round-trip")
        XCTAssertEqual(loaded.configuration.sessionURL.absoluteString, "http://127.0.0.1:18090/network-extension/runtime-copy/session")
        XCTAssertEqual(loaded.evidenceImplementation, "lab_endpoint_runtime_copy_transport")
        XCTAssertEqual(loaded.edgeConnectorRealness, "in_process_stub")

        let transport = try XCTUnwrap(DsseAppProxyProvider.runtimeCopyTransport(agentConfigPath: agentConfigURL.path) as? DsseEdgeRuntimeCopyTransport)
        XCTAssertEqual(transport.evidenceImplementation, "lab_endpoint_runtime_copy_transport")
        XCTAssertEqual(transport.edgeConnectorRealness, "in_process_stub")
    }

    func testRuntimeCopyLabEndpointUsesHandleNewFlowPassthroughInsteadOfNetworkExclusion() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("dsse-runtime-copy-passthrough-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        addTeardownBlock {
            try? FileManager.default.removeItem(at: directory)
        }
        let agentConfigURL = directory.appendingPathComponent("agent_config.json")
        try """
        {
          "network_extension_rules_ref": "network_extension_steering_rules.json",
          "edge_url": "http://edge.lab.example.local:18090",
          "network_extension_runtime_copy_transport_scope": "lab_endpoint"
        }
        """.write(to: agentConfigURL, atomically: true, encoding: .utf8)

        let endpoint = try XCTUnwrap(DsseAppProxyProvider.runtimeCopyPassthroughEndpoint(agentConfigPath: agentConfigURL.path))
        XCTAssertEqual(endpoint.normalizedHost, "edge.lab.example.local")
        XCTAssertEqual(endpoint.port, 18090)
        XCTAssertTrue(endpoint.labEndpointPortOnlyFallback)
        XCTAssertTrue(DsseAppProxyProvider.shouldPassThroughRuntimeCopyEndpoint(
            input: ProviderFlowAuthorityInput(transport: .tcp, remoteHost: "edge.lab.example.local", remotePort: 18090),
            endpoint: endpoint
        ))
        XCTAssertEqual(DsseAppProxyProvider.runtimeCopyEndpointPassthroughDecision(
            input: ProviderFlowAuthorityInput(transport: .tcp, remoteHost: "edge.lab.example.local", remotePort: 18090),
            endpoint: endpoint
        ), DsseRuntimeCopyPassthroughDecision(
            category: "matched_passed_through",
            edgePortFlowReentryObserved: true,
            shouldPassThrough: true
        ))
        XCTAssertTrue(DsseAppProxyProvider.shouldPassThroughRuntimeCopyEndpoint(
            input: ProviderFlowAuthorityInput(transport: .tcp, remoteHost: "203.0.113.11", remotePort: 18090),
            endpoint: endpoint
        ))
        XCTAssertEqual(DsseAppProxyProvider.runtimeCopyEndpointPassthroughDecision(
            input: ProviderFlowAuthorityInput(transport: .tcp, remoteHost: "203.0.113.11", remotePort: 18090),
            endpoint: DsseRuntimeCopyPassthroughEndpoint(
                normalizedHost: "edge.lab.example.local",
                port: 18090,
                labEndpointPortOnlyFallback: false
            )
        ), DsseRuntimeCopyPassthroughDecision(
            category: "port_matched_host_mismatch",
            edgePortFlowReentryObserved: true,
            shouldPassThrough: false
        ))
        XCTAssertFalse(DsseAppProxyProvider.shouldPassThroughRuntimeCopyEndpoint(
            input: ProviderFlowAuthorityInput(transport: .tcp, remoteHost: "dummy-postgres.local", remotePort: 5432),
            endpoint: endpoint
        ))
        XCTAssertEqual(DsseAppProxyProvider.runtimeCopyEndpointPassthroughDecision(
            input: ProviderFlowAuthorityInput(transport: .tcp, remoteHost: "dummy-postgres.local", remotePort: 5432),
            endpoint: endpoint
        ), DsseRuntimeCopyPassthroughDecision(
            category: "no_flow_matched_edge_port",
            edgePortFlowReentryObserved: false,
            shouldPassThrough: false
        ))
        XCTAssertFalse(DsseAppProxyProvider.shouldPassThroughRuntimeCopyEndpoint(
            input: ProviderFlowAuthorityInput(transport: .udp, remoteHost: "edge.lab.example.local", remotePort: 18090),
            endpoint: endpoint
        ))
        XCTAssertEqual(DsseAppProxyProvider.runtimeCopyEndpointPassthroughDecision(
            input: ProviderFlowAuthorityInput(transport: .tcp, remoteHost: "edge.lab.example.local", remotePort: 18090),
            endpoint: nil
        ), DsseRuntimeCopyPassthroughDecision(
            category: "endpoint_not_configured",
            edgePortFlowReentryObserved: false,
            shouldPassThrough: false
        ))
    }

    func testRuntimeCopyRealEdgePassthroughAllowsReviewedHostAndResolvedIPOnly() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("dsse-real-edge-runtime-copy-passthrough-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        addTeardownBlock {
            try? FileManager.default.removeItem(at: directory)
        }
        let agentConfigURL = directory.appendingPathComponent("agent_config.json")
        try """
        {
          "network_extension_rules_ref": "network_extension_steering_rules.json",
          "edge_url": "https://edge.reviewed.example.test:443",
          "network_extension_runtime_copy_transport_scope": "real_edge",
          "network_extension_runtime_copy_passthrough_resolved_ips": [
            "198.51.100.44",
            "[2001:db8::44]"
          ]
        }
        """.write(to: agentConfigURL, atomically: true, encoding: .utf8)

        let endpoint = try XCTUnwrap(DsseAppProxyProvider.runtimeCopyPassthroughEndpoint(agentConfigPath: agentConfigURL.path))
        XCTAssertEqual(endpoint.normalizedHost, "edge.reviewed.example.test")
        XCTAssertEqual(endpoint.normalizedResolvedHosts, Set(["198.51.100.44", "2001:db8::44"]))
        XCTAssertEqual(endpoint.port, 443)
        XCTAssertFalse(endpoint.labEndpointPortOnlyFallback)
        XCTAssertEqual(DsseAppProxyProvider.runtimeCopyEndpointPassthroughDecision(
            input: ProviderFlowAuthorityInput(transport: .tcp, remoteHost: "edge.reviewed.example.test", remotePort: 443),
            endpoint: endpoint
        ), DsseRuntimeCopyPassthroughDecision(
            category: "matched_passed_through",
            edgePortFlowReentryObserved: true,
            shouldPassThrough: true
        ))
        XCTAssertEqual(DsseAppProxyProvider.runtimeCopyEndpointPassthroughDecision(
            input: ProviderFlowAuthorityInput(transport: .tcp, remoteHost: "198.51.100.44", remotePort: 443),
            endpoint: endpoint
        ), DsseRuntimeCopyPassthroughDecision(
            category: "matched_passed_through",
            edgePortFlowReentryObserved: true,
            shouldPassThrough: true
        ))
        XCTAssertEqual(DsseAppProxyProvider.runtimeCopyEndpointPassthroughDecision(
            input: ProviderFlowAuthorityInput(transport: .tcp, remoteHost: "2001:db8::44", remotePort: 443),
            endpoint: endpoint
        ), DsseRuntimeCopyPassthroughDecision(
            category: "matched_passed_through",
            edgePortFlowReentryObserved: true,
            shouldPassThrough: true
        ))
        XCTAssertEqual(DsseAppProxyProvider.runtimeCopyEndpointPassthroughDecision(
            input: ProviderFlowAuthorityInput(transport: .tcp, remoteHost: "198.51.100.45", remotePort: 443),
            endpoint: endpoint
        ), DsseRuntimeCopyPassthroughDecision(
            category: "port_matched_host_mismatch",
            edgePortFlowReentryObserved: true,
            shouldPassThrough: false
        ))
        XCTAssertEqual(DsseAppProxyProvider.runtimeCopyEndpointPassthroughDecision(
            input: ProviderFlowAuthorityInput(transport: .tcp, remoteHost: "edge.reviewed.example.test", remotePort: 8443),
            endpoint: endpoint
        ), DsseRuntimeCopyPassthroughDecision(
            category: "no_flow_matched_edge_port",
            edgePortFlowReentryObserved: false,
            shouldPassThrough: false
        ))
    }

    func testRuntimeCopyDownstreamPassthroughRequiresConfiguredSourceAppAndRulePort() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("dsse-runtime-copy-downstream-passthrough-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        addTeardownBlock {
            try? FileManager.default.removeItem(at: directory)
        }
        let agentConfigURL = directory.appendingPathComponent("agent_config.json")
        try """
        {
          "network_extension_rules_ref": "network_extension_steering_rules.json",
          "network_extension_runtime_copy_downstream_passthrough_source_app_signing_identifiers": [
            "a.out"
          ],
          "network_extension_runtime_copy_downstream_passthrough_default_tunnel_enabled": true
        }
        """.write(to: agentConfigURL, atomically: true, encoding: .utf8)

        let policy = DsseAppProxyProvider.runtimeCopyDownstreamPassthroughPolicy(
            agentConfigPath: agentConfigURL.path
        )
        XCTAssertEqual(policy.allowedSourceAppSigningIdentifiers, Set(["a.out"]))
        XCTAssertTrue(policy.defaultTunnelEnabled)
        let rule = ProviderSingleRuleLabRuleDiagnostic(
            fqdn: "shinnomac-mini.local",
            destinationPort: 55432,
            generatedAt: "2026-06-08T00:00:00Z"
        )

        XCTAssertEqual(DsseAppProxyProvider.runtimeCopyDownstreamPassthroughDecision(
            input: ProviderFlowAuthorityInput(transport: .tcp, remoteHost: "shinnomac-mini.local", remotePort: 55432),
            singleRule: rule,
            sourceAppSigningIdentifier: "a.out",
            policy: policy
        ), DsseRuntimeCopyDownstreamPassthroughDecision(
            category: "matched_passed_through",
            shouldPassThrough: true
        ))
        XCTAssertEqual(DsseAppProxyProvider.runtimeCopyDownstreamPassthroughDecision(
            input: ProviderFlowAuthorityInput(transport: .tcp, remoteHost: "shinnomac-mini.local", remotePort: 55432),
            singleRule: rule,
            sourceAppSigningIdentifier: "com.apple.ruby",
            policy: policy
        ), DsseRuntimeCopyDownstreamPassthroughDecision(
            category: "source_app_not_allowed",
            shouldPassThrough: false
        ))
        XCTAssertEqual(DsseAppProxyProvider.runtimeCopyDownstreamPassthroughDecision(
            input: ProviderFlowAuthorityInput(transport: .tcp, remoteHost: "shinnomac-mini.local", remotePort: 55433),
            singleRule: rule,
            sourceAppSigningIdentifier: "a.out",
            policy: policy
        ), DsseRuntimeCopyDownstreamPassthroughDecision(
            category: "target_port_mismatch",
            shouldPassThrough: false
        ))
        XCTAssertEqual(DsseAppProxyProvider.runtimeCopyDownstreamPassthroughDecision(
            input: ProviderFlowAuthorityInput(transport: .tcp, remoteHost: "shinnomac-mini.local", remotePort: 55432),
            singleRule: nil,
            sourceAppSigningIdentifier: "a.out",
            policy: policy
        ), DsseRuntimeCopyDownstreamPassthroughDecision(
            category: "matched_default_tunnel_source_app_passed_through",
            shouldPassThrough: true
        ))
        let singleRuleOnlyPolicy = DsseRuntimeCopyDownstreamPassthroughPolicy(
            allowedSourceAppSigningIdentifiers: ["a.out"]
        )
        XCTAssertEqual(DsseAppProxyProvider.runtimeCopyDownstreamPassthroughDecision(
            input: ProviderFlowAuthorityInput(transport: .tcp, remoteHost: "shinnomac-mini.local", remotePort: 55432),
            singleRule: nil,
            sourceAppSigningIdentifier: "a.out",
            policy: singleRuleOnlyPolicy
        ), DsseRuntimeCopyDownstreamPassthroughDecision(
            category: "target_rule_missing",
            shouldPassThrough: false
        ))
        XCTAssertEqual(DsseAppProxyProvider.runtimeCopyDownstreamPassthroughDecision(
            input: ProviderFlowAuthorityInput(transport: .tcp, remoteHost: "shinnomac-mini.local", remotePort: 55432),
            singleRule: rule,
            sourceAppSigningIdentifier: "a.out",
            policy: nil
        ), DsseRuntimeCopyDownstreamPassthroughDecision(
            category: "not_configured",
            shouldPassThrough: false
        ))
    }

    func testTransparentPassthroughDomainsHaveNoHardcodedDefaultAndComeOnlyFromAgentConfig() throws {
        // The hardcoded default passthrough is retired: nothing is passed through invisibly. AI-chat domains
        // (openai.com/chatgpt.com and the old GPT/anthropic dev-agent groups) must be STEERED + inspected — a
        // silent hardcoded bypass of whole domains is the exact shadow-AI blind spot the product exists to close.
        XCTAssertTrue(
            DsseAppProxyProvider.defaultTransparentPassthroughDomains.isEmpty,
            "the hardcoded domain passthrough was retired; the default must be empty"
        )

        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("dsse-transparent-passthrough-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        addTeardownBlock {
            try? FileManager.default.removeItem(at: directory)
        }
        let agentConfigURL = directory.appendingPathComponent("agent_config.json")
        // Passthrough now comes ONLY from the visible, root-owned agent_config (e.g. the dev-agent's own
        // self-traffic), never a hardcoded domain list.
        try """
        {
          "network_extension_rules_ref": "network_extension_steering_rules.json",
          "network_extension_passthrough_domains": ["tool.example.test"]
        }
        """.write(to: agentConfigURL, atomically: true, encoding: .utf8)

        let domains = DsseAppProxyProvider.transparentPassthroughDomains(agentConfigPath: agentConfigURL.path)
        // Only the agent_config-supplied domain is present — the former hardcoded AI-chat entries are gone.
        XCTAssertEqual(domains, ["tool.example.test"])
        XCTAssertFalse(domains.contains("openai.com"))
        XCTAssertFalse(domains.contains("chatgpt.com"))
        XCTAssertFalse(domains.contains("anthropic.com"))

        // The mechanism still works when supplied via config: the configured domain passes through.
        XCTAssertEqual(DsseAppProxyProvider.transparentPassthroughDomainDecision(
            input: ProviderFlowAuthorityInput(transport: .tcp, remoteHost: "svc.tool.example.test", remotePort: 443),
            domains: domains
        ), DsseTransparentPassthroughDecision(
            category: "matched_transparent_passthrough_domain",
            shouldPassThrough: true
        ))
        // AI-chat traffic is NO LONGER passed through — it is steered + inspected.
        for host in ["api.openai.com", "chatgpt.com", "api.anthropic.com", "statsig.anthropic.com"] {
            XCTAssertEqual(DsseAppProxyProvider.transparentPassthroughDomainDecision(
                input: ProviderFlowAuthorityInput(transport: .tcp, remoteHost: host, remotePort: 443),
                domains: domains
            ), DsseTransparentPassthroughDecision(
                category: "not_matched",
                shouldPassThrough: false
            ), "\(host) must be steered/inspected, not passed through")
        }
    }

    func testExcludedSourceAppPassesThroughRegardlessOfHostOrPort() throws {
        // G3: there is NO hardcoded app scaffold any more — the product ships zero built-in app exclusions.
        XCTAssertTrue(
            DsseAppProxyProvider.defaultSelfExclusionSourceAppSigningIdentifiers.isEmpty,
            "the hardcoded developer-tool scaffold was retired; defaults must be empty"
        )

        // An exclusion now comes only from admin policy / the device's config list. Build one explicitly and
        // verify the pass-through mechanic still holds for ANY destination host/IP/port.
        let policy = DsseSelfExclusionPolicy(appIDs: ["com.example.agent"])
        XCTAssertTrue(policy.isConfigured)
        for (host, port) in [("api.example.com", 443), ("160.79.104.10", 443), ("www.google.com", 443), ("dummy-private-app.local", 5432)] {
            XCTAssertEqual(
                DsseAppProxyProvider.selfExclusionDecision(
                    sourceAppSigningIdentifier: "com.example.agent",
                    policy: policy
                ),
                DsseSelfExclusionDecision(category: "matched_self_excluded_source_app", shouldPassThrough: true),
                "an excluded app must pass through for \(host):\(port)"
            )
        }

        // A process that is NOT in the exclusion set (e.g. Chrome) stays eligible for interception — and notably
        // Developer tools are NO LONGER excluded by default now that the scaffold is gone.
        for notExcluded in ["com.google.Chrome", "com.anthropic.claudefordesktop", "com.anthropic.claude-code"] {
            XCTAssertEqual(
                DsseAppProxyProvider.selfExclusionDecision(sourceAppSigningIdentifier: notExcluded, policy: policy),
                DsseSelfExclusionDecision(category: "source_app_not_self_excluded", shouldPassThrough: false),
                "\(notExcluded) must NOT be self-excluded by default"
            )
        }
        XCTAssertEqual(
            DsseAppProxyProvider.selfExclusionDecision(sourceAppSigningIdentifier: nil, policy: policy),
            DsseSelfExclusionDecision(category: "source_app_not_self_excluded", shouldPassThrough: false)
        )
    }

    func testSelfExclusionRespectsConfigOverridesAndDisable() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("dsse-self-exclusion-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: directory) }

        // Disable defaults, supply a custom identifier only.
        let customURL = directory.appendingPathComponent("custom.json")
        try """
        {
          "network_extension_self_exclusion_default_signing_identifiers_enabled": false,
          "network_extension_self_exclusion_source_app_signing_identifiers": ["com.example.agent"]
        }
        """.write(to: customURL, atomically: true, encoding: .utf8)
        let custom = DsseAppProxyProvider.selfExclusionPolicy(agentConfigPath: customURL.path)
        XCTAssertTrue(custom.excludes(sourceAppSigningIdentifier: "com.example.agent"))
        XCTAssertFalse(custom.excludes(sourceAppSigningIdentifier: "com.anthropic.claudefordesktop"))

        // Fully disabled => no flow is self-excluded (everything stays eligible).
        let disabledURL = directory.appendingPathComponent("disabled.json")
        try """
        { "network_extension_self_exclusion_enabled": false }
        """.write(to: disabledURL, atomically: true, encoding: .utf8)
        let disabled = DsseAppProxyProvider.selfExclusionPolicy(agentConfigPath: disabledURL.path)
        XCTAssertEqual(
            DsseAppProxyProvider.selfExclusionDecision(
                sourceAppSigningIdentifier: "com.anthropic.claudefordesktop",
                policy: disabled
            ),
            DsseSelfExclusionDecision(category: "not_enabled", shouldPassThrough: false)
        )
    }

    // MARK: - Typed AppID matching (docs/steering_exclusion_appid_format.md)

    // Ignoring a form this OS cannot use is correct and stays silent on the device. It must not stay silent to
    // the OPERATOR: an authored rule this Mac drops looks, from the console, exactly like a rule that failed to
    // arrive. So the parser records what it deliberately did not apply, and the record has to include the case
    // that is NOT a clean per-OS decision — a bare value rejected by a charset guard written for bundle ids,
    // which drops a mistyped macOS entry just as quietly as a Windows install path.
    func testSelfExclusionRecordsWhatItDeliberatelyDidNotApply() throws {
        let policy = DsseSelfExclusionPolicy(appIDs: [
            "com.example.agent",                 // valid bare signing id: applied
            "team-id:Q6L2SF6YDW",                // macOS form: applied
            "\\program files\\jpki\\",           // Windows image path: cannot be a signing id here
            "publisher:Example Corp",            // Windows-only typed form
            "signed:devtool.exe",                // Windows-only typed form
            "com.example.my app",                // macOS-SHAPED but unusable: a space fails the charset guard
        ])
        XCTAssertTrue(policy.signingIdentifiers.contains("com.example.agent"))
        XCTAssertTrue(policy.teamIdentifiers.contains("Q6L2SF6YDW"))

        let ignored = Set(policy.ignoredAppIDOrder)
        XCTAssertTrue(ignored.contains("\\program files\\jpki\\"), "a Windows image path must be reported as ignored, not vanish")
        XCTAssertTrue(ignored.contains("publisher:Example Corp"))
        XCTAssertTrue(ignored.contains("signed:devtool.exe"))
        XCTAssertTrue(ignored.contains("com.example.my app"), "an unusable bare value is the case the operator most needs told")
        XCTAssertFalse(ignored.contains("com.example.agent"), "an applied AppID must never also be reported as ignored")
        XCTAssertFalse(ignored.contains("team-id:Q6L2SF6YDW"))
    }

    func testSelfExclusionTypedAppIDBareAndSigningIDMatchBySigningIdentifierAndTeamIDDoesNot() throws {
        // bare and signing-id: both resolve to a signing-identifier match.
        let policy = DsseSelfExclusionPolicy(appIDs: [
            "com.example.bare",
            "signing-id:com.example.typed",
            "team-id:EQHXZ8M8AV"
        ])
        XCTAssertTrue(policy.isConfigured)
        // Bare entry matches as a signing id.
        XCTAssertTrue(policy.excludes(sourceAppSigningIdentifier: "com.example.bare", teamIdentifier: nil))
        // signing-id: entry matches as a signing id.
        XCTAssertTrue(policy.excludes(sourceAppSigningIdentifier: "com.example.typed", teamIdentifier: nil))
        // The team-id: VALUE must NOT match via the signing-identifier path.
        XCTAssertFalse(policy.excludes(sourceAppSigningIdentifier: "EQHXZ8M8AV", teamIdentifier: nil))
        XCTAssertFalse(policy.excludes(sourceAppSigningIdentifier: "team-id:EQHXZ8M8AV", teamIdentifier: nil))
        // Back-compat single-arg overload behaves identically for signing ids.
        XCTAssertTrue(policy.excludes(sourceAppSigningIdentifier: "com.example.bare"))
        XCTAssertFalse(policy.excludes(sourceAppSigningIdentifier: "com.unknown"))
    }

    func testSelfExclusionTypedTeamIDMatchesExactCaseSensitive() throws {
        let policy = DsseSelfExclusionPolicy(appIDs: ["team-id:EQHXZ8M8AV"])
        XCTAssertTrue(policy.isConfigured)
        XCTAssertTrue(policy.signingIdentifiers.isEmpty, "team-id only => no signing identifiers")
        XCTAssertEqual(policy.teamIdentifiers, ["EQHXZ8M8AV"])
        // Exact team id matches (OR via the team path; signing id is some unrelated app).
        XCTAssertTrue(policy.excludes(sourceAppSigningIdentifier: "com.some.app", teamIdentifier: "EQHXZ8M8AV"))
        // Case-sensitive: a lowercased team id does NOT match the uppercase value.
        XCTAssertFalse(policy.excludes(sourceAppSigningIdentifier: "com.some.app", teamIdentifier: "eqhxz8m8av"))
        // Fail-closed: an unresolved (nil) team id never team-matches.
        XCTAssertFalse(policy.excludes(sourceAppSigningIdentifier: "com.some.app", teamIdentifier: nil))
    }

    func testSelfExclusionTypedAppIDIgnoresWindowsAndUnknownForms() throws {
        // Only Windows-only / unknown forms => nothing understood => not configured.
        // (subject:/thumbprint: are SHARED cross-platform forms now and are NOT ignored — see their own tests.)
        let windowsOnly = DsseSelfExclusionPolicy(appIDs: [
            "publisher:Google",
            "signed:chrome.exe",
            "mystery:value"
        ])
        XCTAssertFalse(windowsOnly.isConfigured, "Windows-only / unknown forms are inert on macOS")
        XCTAssertTrue(windowsOnly.signingIdentifiers.isEmpty)
        XCTAssertTrue(windowsOnly.teamIdentifiers.isEmpty)
        XCTAssertTrue(windowsOnly.subjectOrganizations.isEmpty)
        XCTAssertTrue(windowsOnly.thumbprints.isEmpty)
        XCTAssertFalse(windowsOnly.excludes(sourceAppSigningIdentifier: "chrome.exe", teamIdentifier: nil))
        XCTAssertFalse(windowsOnly.excludes(sourceAppSigningIdentifier: "Google LLC", teamIdentifier: "Google LLC"))

        // Mixed: only the understood entries take effect; Windows-only forms (publisher:/signed:) ignored
        // silently while the shared subject: form DOES take effect.
        let mixed = DsseSelfExclusionPolicy(appIDs: [
            "signing-id:com.example.app",
            "subject:Google LLC",
            "team-id:EQHXZ8M8AV",
            "signed:chrome.exe"
        ])
        XCTAssertTrue(mixed.isConfigured)
        XCTAssertEqual(mixed.signingIdentifiers, ["com.example.app"])
        XCTAssertEqual(mixed.teamIdentifiers, ["EQHXZ8M8AV"])
        XCTAssertEqual(mixed.subjectOrganizations, ["google llc"], "subject: is a shared form and applies")
        XCTAssertTrue(mixed.thumbprints.isEmpty)
    }

    func testSelfExclusionTypedAppIDAppliedTelemetryReportsAppliedFormsVerbatim() throws {
        let policy = DsseSelfExclusionPolicy(appIDs: [
            "com.example.bare",
            "signing-id:com.example.typed",
            "team-id:EQHXZ8M8AV",
            "subject:Google LLC",   // shared form -> appears as subject:<value>
            "thumbprint:AB:CD:EF",  // shared form -> appears as thumbprint:<value>
            "signed:chrome.exe"     // ignored -> must NOT appear
        ])
        let applied = policy.appliedAppIDsForTelemetry
        // Bare/signing-id entries appear as their bare normalized signing id.
        XCTAssertTrue(applied.contains("com.example.bare"))
        XCTAssertTrue(applied.contains("com.example.typed"))
        // Team-id entries appear prefixed as "team-id:<value>".
        XCTAssertTrue(applied.contains("team-id:EQHXZ8M8AV"))
        // Shared forms appear prefixed with the authored value verbatim.
        XCTAssertTrue(applied.contains("subject:Google LLC"))
        XCTAssertTrue(applied.contains("thumbprint:AB:CD:EF"))
        // Ignored Windows-only forms do not appear in the applied set.
        XCTAssertFalse(applied.contains(where: { $0.contains("chrome.exe") }))
        XCTAssertEqual(applied.count, 5)
    }

    func testSelfExclusionTypedAppIDTypeKeywordIsCaseInsensitive() throws {
        // Type keyword is case-insensitive; the value is preserved as-is.
        let policy = DsseSelfExclusionPolicy(appIDs: [
            "Team-ID:EQHXZ8M8AV",
            "SIGNING-ID:com.example.app"
        ])
        XCTAssertEqual(policy.teamIdentifiers, ["EQHXZ8M8AV"], "Team-ID: parses as team-id (keyword case-insensitive)")
        XCTAssertEqual(policy.signingIdentifiers, ["com.example.app"], "SIGNING-ID: parses as signing-id")
        XCTAssertTrue(policy.excludes(sourceAppSigningIdentifier: "x", teamIdentifier: "EQHXZ8M8AV"))
        XCTAssertTrue(policy.excludes(sourceAppSigningIdentifier: "com.example.app", teamIdentifier: nil))
    }

    // MARK: - Shared cross-platform forms (subject: / thumbprint:)

    func testSelfExclusionTypedSubjectMatchesSubjectOrganizationCaseInsensitive() throws {
        let policy = DsseSelfExclusionPolicy(appIDs: ["subject:OpenJS Foundation"])
        XCTAssertTrue(policy.isConfigured)
        XCTAssertTrue(policy.signingIdentifiers.isEmpty, "subject only => no signing identifiers")
        XCTAssertTrue(policy.teamIdentifiers.isEmpty)
        XCTAssertEqual(policy.subjectOrganizations, ["openjs foundation"], "stored lowercased for case-insensitive match")

        // Exact org matches via the subject path (signing id is some unrelated app).
        XCTAssertTrue(policy.excludes(
            sourceAppSigningIdentifier: "com.some.app",
            signerIdentity: DsseSourceAppSignerIdentity(
                teamIdentifier: nil,
                subjectOrganization: "OpenJS Foundation",
                leafSha256: nil
            )
        ))
        // Case-insensitive: a differently-cased org still matches.
        XCTAssertTrue(policy.excludes(
            sourceAppSigningIdentifier: "com.some.app",
            signerIdentity: DsseSourceAppSignerIdentity(
                teamIdentifier: nil,
                subjectOrganization: "openjs foundation",
                leafSha256: nil
            )
        ))
        // A different org does NOT match.
        XCTAssertFalse(policy.excludes(
            sourceAppSigningIdentifier: "com.some.app",
            signerIdentity: DsseSourceAppSignerIdentity(
                teamIdentifier: nil,
                subjectOrganization: "Google LLC",
                leafSha256: nil
            )
        ))
        // Fail-closed: an unresolved (nil) subject org never matches.
        XCTAssertFalse(policy.excludes(
            sourceAppSigningIdentifier: "com.some.app",
            signerIdentity: DsseSourceAppSignerIdentity(
                teamIdentifier: nil,
                subjectOrganization: nil,
                leafSha256: nil
            )
        ))
        // And the authored lowercased form parses identically.
        let lower = DsseSelfExclusionPolicy(appIDs: ["subject:openjs foundation"])
        XCTAssertEqual(lower.subjectOrganizations, ["openjs foundation"])
        XCTAssertTrue(lower.excludes(
            sourceAppSigningIdentifier: "com.some.app",
            signerIdentity: DsseSourceAppSignerIdentity(
                teamIdentifier: nil,
                subjectOrganization: "OpenJS Foundation",
                leafSha256: nil
            )
        ))
    }

    // Apple Developer ID leaf certs have NO Subject O= field — the org is embedded in the leaf Common Name,
    // e.g. "Developer ID Application: Google LLC (EQHXZ8M8AV)". So `subject:Google LLC` must match via a
    // case-insensitive contains against the CN, making one shared subject: entry work on macOS too.
    func testSelfExclusionSubjectMatchesViaLeafCommonNameWhenNoOrganizationField() throws {
        let policy = DsseSelfExclusionPolicy(appIDs: ["subject:Google LLC"])
        XCTAssertEqual(policy.subjectOrganizations, ["google llc"])
        // Apple-style identity: no O=, org only in the CN -> matches via CN contains.
        XCTAssertTrue(policy.excludes(
            sourceAppSigningIdentifier: "com.google.Chrome",
            signerIdentity: DsseSourceAppSignerIdentity(
                teamIdentifier: "EQHXZ8M8AV",
                subjectOrganization: nil,
                subjectCommonName: "Developer ID Application: Google LLC (EQHXZ8M8AV)",
                leafSha256: nil
            )
        ))
        // A different vendor's CN does NOT match.
        XCTAssertFalse(policy.excludes(
            sourceAppSigningIdentifier: "com.other.app",
            signerIdentity: DsseSourceAppSignerIdentity(
                teamIdentifier: "AAAA111111",
                subjectOrganization: nil,
                subjectCommonName: "Developer ID Application: Other Corp (AAAA111111)",
                leafSha256: nil
            )
        ))
    }

    func testSelfExclusionTypedThumbprintMatchesLeafSha256NormalizedCaseAndSeparators() throws {
        let dummyHash = "1941ce6219bb2a6c4f8d7e0a3b5c2d1e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c"
        let policy = DsseSelfExclusionPolicy(appIDs: ["thumbprint:1941CE62:19BB:2A6C:4F8D:7E0A:3B5C:2D1E:9F8A:7B6C:5D4E:3F2A:1B0C:9D8E:7F6A:5B4C"])
        XCTAssertTrue(policy.isConfigured)
        XCTAssertTrue(policy.signingIdentifiers.isEmpty, "thumbprint only => no signing identifiers")
        XCTAssertEqual(policy.thumbprints, [dummyHash], "stored normalized: colons stripped, lowercase hex")

        // Matches when the flow's leaf SHA-256 equals it (already lowercased, no separators).
        XCTAssertTrue(policy.excludes(
            sourceAppSigningIdentifier: "com.some.app",
            signerIdentity: DsseSourceAppSignerIdentity(
                teamIdentifier: nil,
                subjectOrganization: nil,
                leafSha256: dummyHash
            )
        ))
        // Case-insensitive + separator-insensitive on the resolved side too.
        XCTAssertTrue(policy.excludes(
            sourceAppSigningIdentifier: "com.some.app",
            signerIdentity: DsseSourceAppSignerIdentity(
                teamIdentifier: nil,
                subjectOrganization: nil,
                leafSha256: "1941CE62:19bb:2A6C:4f8d:7E0A:3b5c:2D1E:9f8a:7B6C:5d4e:3F2A:1b0c:9D8E:7f6a:5B4C"
            )
        ))
        // A different hash does NOT match.
        XCTAssertFalse(policy.excludes(
            sourceAppSigningIdentifier: "com.some.app",
            signerIdentity: DsseSourceAppSignerIdentity(
                teamIdentifier: nil,
                subjectOrganization: nil,
                leafSha256: "deadbeef" + String(repeating: "0", count: 56)
            )
        ))
        // Fail-closed: an unresolved (nil) leaf SHA-256 never matches.
        XCTAssertFalse(policy.excludes(
            sourceAppSigningIdentifier: "com.some.app",
            signerIdentity: DsseSourceAppSignerIdentity(
                teamIdentifier: nil,
                subjectOrganization: nil,
                leafSha256: nil
            )
        ))
    }

    func testSelfExclusionSharedFormsStillIgnorePublisherSignedAndUnknownOnMacOS() throws {
        // publisher:/signed:/unknown remain Windows-only / unrecognized => inert.
        let policy = DsseSelfExclusionPolicy(appIDs: [
            "publisher:OpenJS Foundation",
            "signed:node.exe",
            "mystery:value"
        ])
        XCTAssertFalse(policy.isConfigured)
        XCTAssertTrue(policy.subjectOrganizations.isEmpty)
        XCTAssertTrue(policy.thumbprints.isEmpty)
        // Even if a flow's signer identity carries those values, nothing matches (the forms were never applied).
        XCTAssertFalse(policy.excludes(
            sourceAppSigningIdentifier: "node.exe",
            signerIdentity: DsseSourceAppSignerIdentity(
                teamIdentifier: nil,
                subjectOrganization: "OpenJS Foundation",
                leafSha256: "1941ce62" + String(repeating: "0", count: 56)
            )
        ))
    }

    func testSelfExclusionDecisionMatchesViaSignerIdentitySubjectAndThumbprint() throws {
        let dummyHash = "1941ce6219bb2a6c4f8d7e0a3b5c2d1e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c"
        let policy = DsseSelfExclusionPolicy(appIDs: [
            "subject:OpenJS Foundation",
            "thumbprint:\(dummyHash)"
        ])
        // Subject path drives the pass-through decision.
        XCTAssertEqual(
            DsseAppProxyProvider.selfExclusionDecision(
                sourceAppSigningIdentifier: "com.some.app",
                signerIdentity: DsseSourceAppSignerIdentity(
                    teamIdentifier: nil,
                    subjectOrganization: "OpenJS Foundation",
                    leafSha256: nil
                ),
                policy: policy
            ),
            DsseSelfExclusionDecision(category: "matched_self_excluded_source_app", shouldPassThrough: true)
        )
        // Thumbprint path drives the pass-through decision.
        XCTAssertEqual(
            DsseAppProxyProvider.selfExclusionDecision(
                sourceAppSigningIdentifier: "com.some.app",
                signerIdentity: DsseSourceAppSignerIdentity(
                    teamIdentifier: nil,
                    subjectOrganization: nil,
                    leafSha256: dummyHash
                ),
                policy: policy
            ),
            DsseSelfExclusionDecision(category: "matched_self_excluded_source_app", shouldPassThrough: true)
        )
        // No matching identity => stays eligible for interception.
        XCTAssertEqual(
            DsseAppProxyProvider.selfExclusionDecision(
                sourceAppSigningIdentifier: "com.some.app",
                signerIdentity: DsseSourceAppSignerIdentity(
                    teamIdentifier: "EQHXZ8M8AV",
                    subjectOrganization: "Google LLC",
                    leafSha256: nil
                ),
                policy: policy
            ),
            DsseSelfExclusionDecision(category: "source_app_not_self_excluded", shouldPassThrough: false)
        )
    }

    func testInterceptAllowlistScopesInterceptionToTestTargetsAndProtectsEverythingElse() throws {
        // When configured, only the listed SaaS targets are eligible for interception.
        let allowlist = ["google.com", "accounts.google.com", "login.microsoftonline.com"]

        // Google/M365 auth flows under test -> intercepted (do NOT pass through).
        for host in ["accounts.google.com", "www.google.com", "login.microsoftonline.com"] {
            let d = DsseAppProxyProvider.interceptAllowlistDecision(
                input: ProviderFlowAuthorityInput(transport: .tcp, remoteHost: host, remotePort: 443),
                interceptOnlyDomains: allowlist
            )
            XCTAssertEqual(d.category, "matched_intercept_allowlist", "\(host) must be eligible for interception")
            XCTAssertFalse(d.shouldPassThrough)
        }

        // DAZN streaming + everything else -> passed through (protected from the test).
        for host in ["dazn.com", "www.dazn.com", "live.indazn.com", "abc123.akamaized.net", "api.bank.example"] {
            let d = DsseAppProxyProvider.interceptAllowlistDecision(
                input: ProviderFlowAuthorityInput(transport: .tcp, remoteHost: host, remotePort: 443),
                interceptOnlyDomains: allowlist
            )
            XCTAssertEqual(d.category, "not_in_intercept_allowlist_passed_through", "\(host) must be protected")
            XCTAssertTrue(d.shouldPassThrough)
        }

        // IP-only flow (host not visible) -> fail open to passthrough (safe default).
        let ipDecision = DsseAppProxyProvider.interceptAllowlistDecision(
            input: ProviderFlowAuthorityInput(transport: .tcp, remoteHost: "142.250.72.110", remotePort: 443),
            interceptOnlyDomains: allowlist
        )
        XCTAssertEqual(ipDecision.category, "host_not_domain_passed_through")
        XCTAssertTrue(ipDecision.shouldPassThrough)

        // Empty allowlist -> legacy catch-all preserved (nothing forced to pass through here).
        let catchAll = DsseAppProxyProvider.interceptAllowlistDecision(
            input: ProviderFlowAuthorityInput(transport: .tcp, remoteHost: "accounts.google.com", remotePort: 443),
            interceptOnlyDomains: []
        )
        XCTAssertEqual(catchAll.category, "not_configured")
        XCTAssertFalse(catchAll.shouldPassThrough)
    }

    func testNoHardcodedPassthroughDefault_ConfiguredDomainStillWorks() throws {
        // dazn (and every other formerly-hardcoded domain) is no longer a built-in passthrough default: with no
        // agent_config, nothing is passed through. A protected service must be named in a VISIBLE config.
        let noConfig = DsseAppProxyProvider.transparentPassthroughDomains(agentConfigPath: "/nonexistent/agent_config.json")
        XCTAssertTrue(noConfig.isEmpty, "no hardcoded default passthrough may remain")

        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("dsse-passthrough-config-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: directory) }
        let agentConfigURL = directory.appendingPathComponent("agent_config.json")
        try """
        {"network_extension_passthrough_domains": ["dazn.com"]}
        """.write(to: agentConfigURL, atomically: true, encoding: .utf8)
        let domains = DsseAppProxyProvider.transparentPassthroughDomains(agentConfigPath: agentConfigURL.path)
        XCTAssertEqual(domains, ["dazn.com"])
        XCTAssertEqual(DsseAppProxyProvider.transparentPassthroughDomainDecision(
            input: ProviderFlowAuthorityInput(transport: .tcp, remoteHost: "www.dazn.com", remotePort: 443),
            domains: domains
        ), DsseTransparentPassthroughDecision(
            category: "matched_transparent_passthrough_domain",
            shouldPassThrough: true
        ))
    }

    func testInterceptOnlyDomainsLoadsFromConfig() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("dsse-intercept-allowlist-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appendingPathComponent("agent_config.json")
        try """
        {
          "network_extension_intercept_only_domains": ["google.com", "login.microsoftonline.com"]
        }
        """.write(to: url, atomically: true, encoding: .utf8)
        let domains = DsseAppProxyProvider.interceptOnlyDomains(agentConfigPath: url.path)
        XCTAssertEqual(Set(domains), Set(["google.com", "login.microsoftonline.com"]))

        // Missing key => empty => catch-all preserved.
        XCTAssertTrue(DsseAppProxyProvider.interceptOnlyDomains(
            agentConfigPath: "/Library/Application Support/Dsse/agent_config.json"
        ).isEmpty)
    }

    func testObserveOnlyPassthroughAllDefaultsOffAndReadsConfig() throws {
        // Off by default (no config / missing key) => proxy enforces normally.
        XCTAssertFalse(DsseAppProxyProvider.observeOnlyPassthroughAll(
            agentConfigPath: "/Library/Application Support/Dsse/agent_config.json"
        ))

        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("dsse-observe-only-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: directory) }
        let onURL = directory.appendingPathComponent("on.json")
        try """
        { "network_extension_observe_only_passthrough_all": true }
        """.write(to: onURL, atomically: true, encoding: .utf8)
        XCTAssertTrue(DsseAppProxyProvider.observeOnlyPassthroughAll(agentConfigPath: onURL.path))
    }

    func testLabFailOpenWhenRegionBlockedDefaultsOffAndReadsConfig() throws {
        // Default OFF: no config / missing key => production fail-closed reaction to regionEgressBlocked is preserved.
        XCTAssertFalse(DsseAppProxyProvider.labFailOpenWhenRegionBlocked(
            agentConfigPath: "/Library/Application Support/Dsse/agent_config.json"
        ))

        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("dsse-lab-fail-open-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: directory) }

        // Explicit false stays fail-closed.
        let offURL = directory.appendingPathComponent("off.json")
        try """
        { "network_extension_lab_fail_open_when_region_blocked": false }
        """.write(to: offURL, atomically: true, encoding: .utf8)
        XCTAssertFalse(DsseAppProxyProvider.labFailOpenWhenRegionBlocked(agentConfigPath: offURL.path))

        // Explicit true => lab fail-open enable key set (NOTE: enable alone does not ARM — see the posture test).
        let onURL = directory.appendingPathComponent("on.json")
        try """
        { "network_extension_lab_fail_open_when_region_blocked": true }
        """.write(to: onURL, atomically: true, encoding: .utf8)
        XCTAssertTrue(DsseAppProxyProvider.labFailOpenWhenRegionBlocked(agentConfigPath: onURL.path))
    }

    // Slice 3: the macOS mirror of the Windows --fail-open / --acknowledge-fail-open contract. Fail-open ARMS only
    // when the enable key AND the acknowledgment key are both set; every other combination stays disarmed (strict).
    func testFailOpenPostureRequiresBothEnableAndAcknowledgment() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("dsse-fail-open-posture-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: directory) }

        func posture(_ json: String) throws -> DsseFailOpenPosture {
            let url = directory.appendingPathComponent("\(UUID().uuidString).json")
            try json.write(to: url, atomically: true, encoding: .utf8)
            return DsseAppProxyProvider.failOpenPosture(agentConfigPath: url.path)
        }

        // Default / missing keys => strict (disarmed).
        let missing = DsseAppProxyProvider.failOpenPosture(agentConfigPath: "/nonexistent/agent_config.json")
        XCTAssertEqual(missing, DsseFailOpenPosture(enableRequested: false, acknowledged: false))
        XCTAssertFalse(missing.armed)
        XCTAssertEqual(try posture("{}"), DsseFailOpenPosture(enableRequested: false, acknowledged: false))

        // Enable WITHOUT acknowledgment => refused: enable is seen but NOT armed (the Windows exit-2 case).
        let enableOnly = try posture(#"{ "network_extension_lab_fail_open_when_region_blocked": true }"#)
        XCTAssertTrue(enableOnly.enableRequested)
        XCTAssertFalse(enableOnly.acknowledged)
        XCTAssertFalse(enableOnly.armed, "enable alone must NOT arm fail-open")

        // Acknowledgment WITHOUT enable => still disarmed (acknowledging something not requested is inert).
        let ackOnly = try posture(#"{ "network_extension_fail_open_acknowledged": true }"#)
        XCTAssertFalse(ackOnly.armed)

        // Both set => armed.
        let both = try posture(#"""
        { "network_extension_lab_fail_open_when_region_blocked": true, "network_extension_fail_open_acknowledged": true }
        """#)
        XCTAssertTrue(both.enableRequested)
        XCTAssertTrue(both.acknowledged)
        XCTAssertTrue(both.armed, "enable + acknowledgment must arm fail-open")

        // Enable true but acknowledgment explicitly false => refused.
        let ackFalse = try posture(#"""
        { "network_extension_lab_fail_open_when_region_blocked": true, "network_extension_fail_open_acknowledged": false }
        """#)
        XCTAssertFalse(ackFalse.armed)
    }

    func testObserveRemoteHostKindClassifiesDomainVsIPLiteral() throws {
        XCTAssertEqual(DsseAppProxyProvider.observeRemoteHostKind("api.anthropic.com"), "domain")
        XCTAssertEqual(DsseAppProxyProvider.observeRemoteHostKind("160.79.104.10"), "ipv4_literal")
        XCTAssertEqual(DsseAppProxyProvider.observeRemoteHostKind("[2607:6bc0::10]"), "ipv6_literal")
        XCTAssertEqual(DsseAppProxyProvider.observeRemoteHostKind("2607:6bc0::10"), "ipv6_literal")
        XCTAssertEqual(DsseAppProxyProvider.observeRemoteHostKind(""), "none")
    }

    func testTransparentSystemPassthroughKeepsLoopbackOutOfDefaultTunnel() throws {
        XCTAssertEqual(DsseAppProxyProvider.transparentSystemPassthroughDecision(
            input: ProviderFlowAuthorityInput(transport: .tcp, remoteHost: "127.0.0.1", remotePort: 443)
        ), DsseTransparentPassthroughDecision(
            category: "matched_loopback_passthrough",
            shouldPassThrough: true
        ))
        XCTAssertEqual(DsseAppProxyProvider.transparentSystemPassthroughDecision(
            input: ProviderFlowAuthorityInput(transport: .tcp, remoteHost: "localhost", remotePort: 18080)
        ), DsseTransparentPassthroughDecision(
            category: "matched_loopback_passthrough",
            shouldPassThrough: true
        ))
        XCTAssertEqual(DsseAppProxyProvider.transparentSystemPassthroughDecision(
            input: ProviderFlowAuthorityInput(transport: .tcp, remoteHost: "[::1]", remotePort: 18080)
        ), DsseTransparentPassthroughDecision(
            category: "matched_loopback_passthrough",
            shouldPassThrough: true
        ))
        XCTAssertEqual(DsseAppProxyProvider.transparentSystemPassthroughDecision(
            input: ProviderFlowAuthorityInput(transport: .tcp, remoteHost: "www.google.com", remotePort: 443)
        ), DsseTransparentPassthroughDecision(
            category: "not_matched",
            shouldPassThrough: false
        ))
        XCTAssertEqual(DsseAppProxyProvider.transparentSystemPassthroughDecision(
            input: ProviderFlowAuthorityInput(transport: .udp, remoteHost: "127.0.0.1", remotePort: 443)
        ), DsseTransparentPassthroughDecision(
            category: "unsupported_transport",
            shouldPassThrough: false
        ))
    }

    func testTransparentProxyNetworkSettingsIncludesAcceptedOutboundCatchAllTCPRule() throws {
        let settings = DsseAppProxyProvider.transparentProxyNetworkSettings(
            agentConfigPath: "/Library/Application Support/Dsse/agent_config.json"
        )

        let includedRules = try XCTUnwrap(settings.includedNetworkRules)
        // The TCP catch-all is always a single rule (all addresses, outbound).
        let tcpRules = includedRules.filter { $0.matchProtocol == .TCP }
        XCTAssertEqual(tcpRules.count, 1)
        XCTAssertEqual(tcpRules[0].matchRemotePrefix, 0)
        XCTAssertEqual(tcpRules[0].matchDirection, .outbound)
        // On macOS 15+, two UDP/443 rules (IPv4/IPv6) are added to drop QUIC (UDP/443)
        // (port-scoped, so non-443 UDP such as DNS is not claimed). Below 15, no UDP rules.
        let udpRules = includedRules.filter { $0.matchProtocol == .UDP }
        if #available(macOS 15.0, *) {
            XCTAssertEqual(udpRules.count, 2)
            for rule in udpRules {
                XCTAssertEqual(rule.matchDirection, .outbound)
                XCTAssertEqual(rule.matchRemotePrefix, 0)
            }
            XCTAssertEqual(includedRules.count, 3)
        } else {
            XCTAssertEqual(udpRules.count, 0)
            XCTAssertEqual(includedRules.count, 1)
        }
        XCTAssertNil(settings.excludedNetworkRules)
    }

    func testTransparentPassthroughDomainsCanDisableDefaults() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("dsse-transparent-passthrough-disabled-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        addTeardownBlock {
            try? FileManager.default.removeItem(at: directory)
        }
        let agentConfigURL = directory.appendingPathComponent("agent_config.json")
        try """
        {
          "network_extension_rules_ref": "network_extension_steering_rules.json",
          "network_extension_default_passthrough_domains_enabled": false,
          "network_extension_passthrough_domains": ["tool.example.test"]
        }
        """.write(to: agentConfigURL, atomically: true, encoding: .utf8)

        let domains = DsseAppProxyProvider.transparentPassthroughDomains(agentConfigPath: agentConfigURL.path)
        XCTAssertFalse(domains.contains("openai.com"))
        XCTAssertEqual(domains, ["tool.example.test"])
    }

    func testRuntimeCopyTransportFactoryDefaultsToDeviceValidationPendingWhenEdgeURLMissing() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("dsse-runtime-copy-pending-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        addTeardownBlock {
            try? FileManager.default.removeItem(at: directory)
        }
        let agentConfigURL = directory.appendingPathComponent("agent_config.json")
        try #"{"network_extension_rules_ref":"network_extension_steering_rules.json"}"#
            .write(to: agentConfigURL, atomically: true, encoding: .utf8)

        let transport = DsseAppProxyProvider.runtimeCopyTransport(agentConfigPath: agentConfigURL.path)
        XCTAssertTrue(transport is DsseDeviceValidationPendingRuntimeCopyTransport)
        XCTAssertThrowsError(try transport.roundTrip(Data("client".utf8), metadata: DsseLocalRuntimeCopyMetadata(
            tenantID: "tenant_lab_001",
            requestID: "req_pending_001",
            applicationID: "app_dummy_postgres"
        ))) { error in
            XCTAssertEqual(error as? DsseLocalRuntimeCopyDriverError, .runtimeTransportDeviceValidationPending)
        }
    }

    func testEdgeRuntimeCopyTransportPostsMetadataAndReturnsDownstreamBytes() throws {
        let upstreamPayload = Data("client-bytes".utf8)
        let downstreamPayload = Data("private-response".utf8)
        let metadata = DsseLocalRuntimeCopyMetadata(
            tenantID: "tenant_lab_001",
            requestID: "req_edge_001",
            applicationID: "app_dummy_postgres",
            destinationHost: "dummy-postgres.local",
            destinationPort: 5432
        )
        let httpClient = RecordingEdgeRuntimeCopyHTTPClient(response: [
            "schema_version": "network_extension_runtime_copy_round_trip_response.v1",
            "request_id": metadata.requestID,
            "downstream_payload_b64": downstreamPayload.base64EncodedString()
        ])
        let transport = DsseEdgeRuntimeCopyTransport(
            configuration: DsseEdgeRuntimeCopyTransportConfiguration(
                edgeBaseURL: try XCTUnwrap(URL(string: "https://edge.lab.example.local"))
            ),
            httpClient: httpClient
        )
        let progress = RuntimeCopyProgressBox()

        let returnedPayload = try transport.roundTrip(upstreamPayload, metadata: metadata) { checkpoint in
            progress.append(checkpoint)
        }

        XCTAssertEqual(returnedPayload, downstreamPayload)
        XCTAssertEqual(progress.values, [
            .edgeTCPConnectStarted(family: "fqdn_unresolved"),
            .edgeRoundTripRequestSent,
            .edgeTCPConnectCompleted(family: "fqdn_unresolved"),
            .edgeRoundTripResponseStatusReceived(category: "success"),
            .edgeRoundTripResponseBodyReceived
        ])
        let request = try XCTUnwrap(httpClient.requests.first)
        XCTAssertEqual(request.url?.absoluteString, "https://edge.lab.example.local/network-extension/runtime-copy/round-trip")
        XCTAssertEqual(request.httpMethod, "POST")
        let body = try XCTUnwrap(request.httpBody)
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: body) as? [String: Any])
        XCTAssertEqual(json["schema_version"] as? String, "network_extension_runtime_copy_round_trip_request.v1")
        XCTAssertEqual(json["tenant_id"] as? String, metadata.tenantID)
        XCTAssertEqual(json["request_id"] as? String, metadata.requestID)
        XCTAssertEqual(json["application_id"] as? String, metadata.applicationID)
        XCTAssertEqual(json["destination_host"] as? String, "dummy-postgres.local")
        XCTAssertEqual(json["destination_port"] as? Int, 5432)
        XCTAssertEqual(json["upstream_payload_b64"] as? String, upstreamPayload.base64EncodedString())
    }

    func testEdgeRuntimeCopyTransportPostsSessionExchangeToSessionEndpoint() throws {
        let upstreamPayload = Data("client-session-bytes".utf8)
        let downstreamPayload = Data("private-session-response".utf8)
        let metadata = DsseLocalRuntimeCopyMetadata(
            tenantID: "tenant_lab_001",
            requestID: "req_edge_session_001",
            applicationID: "default_network_extension_tunnel",
            destinationHost: "www.google.com",
            destinationPort: 443
        )
        let httpClient = RecordingEdgeRuntimeCopyHTTPClient(response: [
            "schema_version": "network_extension_runtime_copy_session_response.v1",
            "request_id": metadata.requestID,
            "downstream_payload_b64": downstreamPayload.base64EncodedString()
        ])
        let transport = DsseEdgeRuntimeCopyTransport(
            configuration: DsseEdgeRuntimeCopyTransportConfiguration(
                edgeBaseURL: try XCTUnwrap(URL(string: "https://edge.lab.example.local"))
            ),
            httpClient: httpClient
        )

        let result = try transport.exchangeSession(
            upstreamPayload,
            operation: .open,
            metadata: metadata,
            progressHandler: nil
        )

        XCTAssertEqual(result.downstreamPayload, downstreamPayload)
        XCTAssertFalse(result.sessionClosed)
        let request = try XCTUnwrap(httpClient.requests.first)
        XCTAssertEqual(request.url?.absoluteString, "https://edge.lab.example.local/network-extension/runtime-copy/session")
        XCTAssertEqual(request.httpMethod, "POST")
        let body = try XCTUnwrap(request.httpBody)
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: body) as? [String: Any])
        XCTAssertEqual(json["schema_version"] as? String, "network_extension_runtime_copy_session_request.v1")
        XCTAssertEqual(json["tenant_id"] as? String, metadata.tenantID)
        XCTAssertEqual(json["request_id"] as? String, metadata.requestID)
        XCTAssertEqual(json["operation"] as? String, "open")
        XCTAssertEqual(json["application_id"] as? String, metadata.applicationID)
        XCTAssertEqual(json["destination_host"] as? String, "www.google.com")
        XCTAssertEqual(json["destination_port"] as? Int, 443)
        XCTAssertEqual(json["upstream_payload_b64"] as? String, upstreamPayload.base64EncodedString())
    }

    func testM1204EdgeRuntimeCopyTransportEmitsConnectorErrorCategoryWithoutRawResponseBody() throws {
        let upstreamPayload = Data("client-bytes".utf8)
        let metadata = DsseLocalRuntimeCopyMetadata(
            tenantID: "tenant_lab_001",
            requestID: "req_edge_error_001",
            applicationID: "app_dummy_postgres"
        )
        let httpClient = RecordingEdgeRuntimeCopyHTTPClient(
            response: [
                "schema_version": "network_extension_runtime_copy_round_trip_error.v1",
                "status": "error",
                "category": "unknown_application_default_deny",
                "request_id": metadata.requestID
            ],
            statusCode: 502
        )
        let transport = DsseEdgeRuntimeCopyTransport(
            configuration: DsseEdgeRuntimeCopyTransportConfiguration(
                edgeBaseURL: try XCTUnwrap(URL(string: "https://edge.lab.example.local"))
            ),
            httpClient: httpClient
        )
        let progress = RuntimeCopyProgressBox()

        XCTAssertThrowsError(try transport.roundTrip(upstreamPayload, metadata: metadata) { checkpoint in
            progress.append(checkpoint)
        }) { error in
            XCTAssertEqual(error as? DsseLocalRuntimeCopyDriverError, .edgeTransportStatusFailed)
        }

        XCTAssertEqual(progress.values, [
            .edgeTCPConnectStarted(family: "fqdn_unresolved"),
            .edgeRoundTripRequestSent,
            .edgeTCPConnectCompleted(family: "fqdn_unresolved"),
            .edgeRoundTripResponseStatusReceived(category: "server_error"),
            .edgeRoundTripResponseBodyReceived,
            .edgeRoundTripErrorCategory(category: "unknown_application_default_deny")
        ])

        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("dsse-provider-runtime-diagnostic-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        addTeardownBlock {
            try? FileManager.default.removeItem(at: directory)
        }
        let diagnosticURL = directory.appendingPathComponent("network_extension_runtime_diagnostic.json")
        let writer = DsseProviderRuntimeDiagnosticWriter(
            diagnosticURL: diagnosticURL,
            now: { Date(timeIntervalSince1970: 1_801_440_000) }
        )
        for checkpoint in progress.values {
            try writer.recordLiveCopyProgress(checkpoint)
        }
        try writer.recordLiveCopyFailed(DsseLocalRuntimeCopyDriverError.edgeTransportStatusFailed)

        let rawDiagnostic = try String(contentsOf: diagnosticURL, encoding: .utf8)
        XCTAssertFalse(rawDiagnostic.contains("network_extension_runtime_copy_round_trip_error.v1"))
        XCTAssertFalse(rawDiagnostic.contains(metadata.requestID))
        XCTAssertFalse(rawDiagnostic.contains("client-bytes"))
        let diagnostic = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(rawDiagnostic.utf8)) as? [String: Any])
        XCTAssertEqual(diagnostic["live_copy_status"] as? String, "failed")
        XCTAssertEqual(diagnostic["live_copy_failure_category"] as? String, "edge_round_trip")
        XCTAssertEqual(diagnostic["edge_round_trip_response_status_received"] as? Bool, true)
        XCTAssertEqual(diagnostic["edge_round_trip_response_status_category"] as? String, "server_error")
        XCTAssertEqual(diagnostic["edge_round_trip_response_body_received"] as? Bool, true)
        XCTAssertEqual(diagnostic["edge_round_trip_error_category"] as? String, "unknown_application_default_deny")
        XCTAssertEqual(diagnostic["recommended_next_dev_action"] as? String, "inspect_connector_runtime_copy_round_trip_error_category")
        XCTAssertEqual(diagnostic["no_secret_attestation"] as? Bool, true)
    }

    func testM1321RuntimeCopyTimeoutsAllowConnectorTimeoutResponseToSurface() throws {
        XCTAssertGreaterThan(
            DsseURLSessionRuntimeCopyHTTPClient.defaultRequestTimeoutInterval,
            DsseURLSessionRuntimeCopyHTTPClient.connectorRoundTripTimeoutInterval
        )
        XCTAssertGreaterThan(
            DsseLocalRuntimeCopyDriver.defaultStepTimeoutInterval,
            DsseURLSessionRuntimeCopyHTTPClient.defaultRequestTimeoutInterval
        )

        let upstreamPayload = Data("client-bytes".utf8)
        let metadata = DsseLocalRuntimeCopyMetadata(
            tenantID: "tenant_lab_001",
            requestID: "req_edge_timeout_001",
            applicationID: "app_dummy_postgres"
        )
        let httpClient = RecordingEdgeRuntimeCopyHTTPClient(
            response: [
                "schema_version": "network_extension_runtime_copy_round_trip_error.v1",
                "status": "error",
                "category": "round_trip_timeout",
                "request_id": metadata.requestID
            ],
            statusCode: 504
        )
        let transport = DsseEdgeRuntimeCopyTransport(
            configuration: DsseEdgeRuntimeCopyTransportConfiguration(
                edgeBaseURL: try XCTUnwrap(URL(string: "https://edge.lab.example.local"))
            ),
            httpClient: httpClient
        )
        let progress = RuntimeCopyProgressBox()

        XCTAssertThrowsError(try transport.roundTrip(upstreamPayload, metadata: metadata) { checkpoint in
            progress.append(checkpoint)
        }) { error in
            XCTAssertEqual(error as? DsseLocalRuntimeCopyDriverError, .edgeTransportStatusFailed)
        }

        XCTAssertEqual(progress.values, [
            .edgeTCPConnectStarted(family: "fqdn_unresolved"),
            .edgeRoundTripRequestSent,
            .edgeTCPConnectCompleted(family: "fqdn_unresolved"),
            .edgeRoundTripResponseStatusReceived(category: "server_error"),
            .edgeRoundTripResponseBodyReceived,
            .edgeRoundTripErrorCategory(category: "round_trip_timeout")
        ])
    }

    func testURLSessionRuntimeCopyHTTPClientTimesOutBoundedly() throws {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [HangingURLProtocol.self]
        let session = URLSession(configuration: configuration)
        defer { session.invalidateAndCancel() }
        let client = DsseURLSessionRuntimeCopyHTTPClient(
            session: session,
            requestTimeoutInterval: 0.05
        )
        let request = URLRequest(url: try XCTUnwrap(URL(string: "http://edge-timeout.local/round-trip")))

        XCTAssertThrowsError(try client.perform(request)) { error in
            XCTAssertEqual(error as? DsseLocalRuntimeCopyDriverError, .edgeRoundTripTimeout)
        }
    }

    func testURLSessionRuntimeCopyHTTPClientEmitsConnectFamilyBeforeTimeoutFailure() throws {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [HangingURLProtocol.self]
        let session = URLSession(configuration: configuration)
        defer { session.invalidateAndCancel() }
        let client = DsseURLSessionRuntimeCopyHTTPClient(
            session: session,
            requestTimeoutInterval: 0.05,
            addressFamilyResolver: { _, _ in "ipv4" }
        )
        let request = URLRequest(url: try XCTUnwrap(URL(string: "http://edge-timeout.local/round-trip")))
        let progress = RuntimeCopyProgressBox()

        XCTAssertThrowsError(try client.perform(
            request,
            connectFamilyFallback: "fqdn_unresolved",
            progressHandler: { progress.append($0) }
        )) { error in
            XCTAssertEqual(error as? DsseLocalRuntimeCopyDriverError, .edgeRoundTripTimeout)
        }
        XCTAssertEqual(progress.values, [
            .edgeTCPConnectCompleted(family: "ipv4")
        ])
    }

    func testLiveRuntimeCopyEvidenceWriterEmitsNonsecretRealTransportGates() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("dsse-runtime-copy-evidence-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        addTeardownBlock {
            try? FileManager.default.removeItem(at: directory)
        }

        let evidenceURL = directory.appendingPathComponent("network_extension_runtime_copy_evidence.json")
        let writer = DsseLocalRuntimeCopyEvidenceWriter(
            evidenceURL: evidenceURL,
            now: { Date(timeIntervalSince1970: 1_801_440_000) },
            section16EvidenceProvider: {
                DsseSection16RuntimeCopyEvidence(
                    edgePortFlowReentryObserved: true,
                    runtimeCopyEndpointPassthroughDecision: "matched_passed_through",
                    edgeTCPConnectCompleted: true,
                    edgeTCPConnectAddressFamily: "ipv4"
                )
            }
        )
        let manager = try startedLifecycleManager()
        let providerResult = manager.decide(ProviderFlowRequest(host: "dummy-postgres.local", port: 5432))
        let upstreamPayload = Data("synthetic-client-bytes".utf8)
        let downstreamPayload = Data("synthetic-private-response".utf8)
        let flow = MockProviderTCPFlowCopyIO(upstreamPayload: upstreamPayload)
        let httpClient = RecordingEdgeRuntimeCopyHTTPClient(response: [
            "schema_version": "network_extension_runtime_copy_session_response.v1",
            "request_id": "req_ne_placeholder",
            "downstream_payload_b64": downstreamPayload.base64EncodedString()
        ], echoRequestID: true)
        let transport = DsseEdgeRuntimeCopyTransport(
            configuration: DsseEdgeRuntimeCopyTransportConfiguration(
                edgeBaseURL: try XCTUnwrap(URL(string: "https://edge.lab.example.local"))
            ),
            httpClient: httpClient
        )
        let completion = expectation(description: "live runtime copy evidence completed")
        let completedResult = RuntimeCopyResultBox()

        DsseAppProxyProvider.driveLiveRuntimeCopyForMatchedFlow(
            flow: flow,
            providerResult: providerResult,
            lifecycleState: manager.state,
            transport: transport,
            evidenceWriter: writer
        ) { result in
            completedResult.result = result
            completion.fulfill()
        }
        wait(for: [completion], timeout: 1.0)

        let result = try XCTUnwrap(completedResult.result).get()
        XCTAssertEqual(result.bytesUp, upstreamPayload.count)
        XCTAssertEqual(result.bytesDown, downstreamPayload.count)
        let rawEvidence = try String(contentsOf: evidenceURL, encoding: .utf8)
        XCTAssertFalse(rawEvidence.contains("tenant_lab_001"))
        XCTAssertFalse(rawEvidence.contains("app_dummy_postgres"))
        XCTAssertFalse(rawEvidence.contains("synthetic-client-bytes"))
        XCTAssertFalse(rawEvidence.contains("synthetic-private-response"))
        let evidence = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(rawEvidence.utf8)) as? [String: Any])
        XCTAssertEqual(evidence["schema_version"] as? String, "network_extension_runtime_copy_evidence.v1")
        XCTAssertEqual(evidence["evidence_kind"] as? String, "provider_runtime_copy_evidence")
        XCTAssertEqual(evidence["status"] as? String, "ok")
        XCTAssertEqual(evidence["runtime_copy_transport_gate"] as? String, "real_transport_completed")
        XCTAssertEqual(evidence["runtime_copy_transport_implementation"] as? String, "real_edge_runtime_copy_transport")
        XCTAssertEqual(evidence["edge_connector_realness"] as? String, "in_process_stub")
        XCTAssertEqual(evidence["edge_transport_round_trip_gate"] as? String, "real_transport_completed")
        XCTAssertEqual(evidence["network_extension_flow_open_gate"] as? String, "opened")
        XCTAssertEqual(evidence["flow_payload_read_gate"] as? String, "completed_nonsecret")
        XCTAssertEqual(evidence["flow_payload_write_gate"] as? String, "completed_nonsecret")
        XCTAssertEqual(evidence["tcp_payload_copy_gate"] as? String, "round_trip_completed")
        XCTAssertEqual(evidence["bytes_up"] as? Int, upstreamPayload.count)
        XCTAssertEqual(evidence["bytes_down"] as? Int, downstreamPayload.count)
        XCTAssertEqual(evidence["bytes_up_gate"] as? String, "nonzero_exact_match")
        XCTAssertEqual(evidence["bytes_down_gate"] as? String, "nonzero_exact_match")
        XCTAssertEqual(evidence["flow_read_half_close_gate"] as? String, "closed")
        XCTAssertEqual(evidence["flow_write_half_close_gate"] as? String, "closed")
        XCTAssertEqual(evidence["registry_cleanup_gate"] as? String, "cleaned")
        XCTAssertEqual(evidence["audit_metadata_only_gate"] as? String, "ok")
        XCTAssertEqual(evidence["no_secret_attestation"] as? Bool, true)
        XCTAssertEqual(evidence["flow_tunneled_claimed"] as? Bool, false)
        XCTAssertEqual(evidence["raw_ne_flow_included"] as? Bool, false)
        XCTAssertEqual(evidence["edge_port_flow_reentry_observed"] as? Bool, true)
        XCTAssertEqual(evidence["runtime_copy_endpoint_passthrough_decision"] as? String, "matched_passed_through")
        XCTAssertEqual(evidence["edge_tcp_connect_completed"] as? Bool, true)
        XCTAssertEqual(evidence["edge_tcp_connect_address_family"] as? String, "ipv4")
    }

    func testConfigDrivenRealEdgeRuntimeCopyEvidenceUsesProviderDiagnosticSection16Snapshot() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("dsse-real-edge-runtime-copy-harness-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        addTeardownBlock {
            try? FileManager.default.removeItem(at: directory)
        }

        let agentConfigURL = directory.appendingPathComponent("agent_config.json")
        let evidenceURL = directory.appendingPathComponent("network_extension_runtime_copy_evidence.json")
        let diagnosticURL = directory.appendingPathComponent("network_extension_runtime_diagnostic.json")
        try """
        {
          "schema_version": "dsse_agent_config.v1",
          "edge_url": "https://[2001:db8::1]",
          "network_extension_runtime_copy_endpoint_path": "/network-extension/runtime-copy/round-trip",
          "network_extension_runtime_copy_transport_scope": "real_edge",
          "network_extension_runtime_copy_evidence_ref": "network_extension_runtime_copy_evidence.json",
          "network_extension_runtime_diagnostic_ref": "network_extension_runtime_diagnostic.json"
        }
        """.write(to: agentConfigURL, atomically: true, encoding: .utf8)

        let diagnosticWriter = DsseProviderRuntimeDiagnosticWriter(
            diagnosticURL: diagnosticURL,
            now: { Date(timeIntervalSince1970: 1_801_440_000) }
        )
        try diagnosticWriter.recordHandleNewFlow(
            decisionCategory: "accepted",
            extractionStatus: "ok",
            extractionReason: "extracted_tcp_host_port",
            providerDecisionAction: "tunnel",
            providerDecisionReason: "matched_network_extension_rule",
            singleRuleLabFallbackGate: "not_evaluated",
            flowAuthorityHostGate: "hostname",
            flowAuthorityPortGate: "positive",
            singleRuleLabFallbackPortGate: "not_evaluated",
            providerLoadedRulesGeneratedAt: "2026-06-08T00:00:00Z"
        )
        try diagnosticWriter.recordRuntimeCopyEndpointPassthroughDecision(
            decisionCategory: "matched_passed_through",
            edgePortFlowReentryObserved: true
        )
        let writer = try DsseLocalRuntimeCopyEvidenceWriter(
            agentConfigPath: agentConfigURL.path,
            now: { Date(timeIntervalSince1970: 1_801_440_000) },
            section16EvidenceProvider: {
                diagnosticWriter.section16RuntimeCopyEvidenceSnapshot()
            }
        )
        let upstreamPayload = Data("real-edge-local-up".utf8)
        let downstreamPayload = Data("real-edge-local-down".utf8)
        let httpClient = RecordingEdgeRuntimeCopyHTTPClient(response: [
            "schema_version": "network_extension_runtime_copy_session_response.v1",
            "request_id": "req_ne_placeholder",
            "downstream_payload_b64": downstreamPayload.base64EncodedString()
        ], echoRequestID: true)
        let transport = DsseLocalRuntimeCopyTransportFactory.make(
            agentConfigPath: agentConfigURL.path,
            httpClient: httpClient
        )
        let completion = expectation(description: "config-driven real-edge runtime copy completed")
        let completedResult = RuntimeCopyResultBox()

        DsseLocalRuntimeCopyDriver().driveLiveTakeover(
            flow: MockProviderTCPFlowCopyIO(upstreamPayload: upstreamPayload),
            metadata: DsseLocalRuntimeCopyMetadata(
                tenantID: "tenant_lab_001",
                requestID: "req_real_edge_local_001",
                applicationID: "app_dummy_postgres"
            ),
            transport: transport,
            progressHandler: { progress in
                try? diagnosticWriter.recordLiveCopyProgress(progress)
            }
        ) { result in
            switch result {
            case .success:
                try? diagnosticWriter.recordLiveCopyCompleted()
            case .failure(let error):
                try? diagnosticWriter.recordLiveCopyFailed(error)
            }
            completedResult.result = result
            completion.fulfill()
        }
        wait(for: [completion], timeout: 1.0)

        let result = try XCTUnwrap(completedResult.result).get()
        XCTAssertEqual(result.bytesUp, upstreamPayload.count)
        XCTAssertEqual(result.bytesDown, downstreamPayload.count)
        try writer.write(result: .success(result), transport: transport)

        let rawEvidence = try String(contentsOf: evidenceURL, encoding: .utf8)
        XCTAssertFalse(rawEvidence.contains("real-edge-local-up"))
        XCTAssertFalse(rawEvidence.contains("real-edge-local-down"))
        let evidence = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(rawEvidence.utf8)) as? [String: Any])
        XCTAssertEqual(evidence["status"] as? String, "ok")
        XCTAssertEqual(evidence["runtime_copy_transport_implementation"] as? String, "real_edge_runtime_copy_transport")
        XCTAssertEqual(evidence["edge_connector_realness"] as? String, "in_process_stub")
        XCTAssertEqual(evidence["runtime_copy_transport_gate"] as? String, "real_transport_completed")
        XCTAssertEqual(evidence["edge_port_flow_reentry_observed"] as? Bool, true)
        XCTAssertEqual(evidence["runtime_copy_endpoint_passthrough_decision"] as? String, "matched_passed_through")
        XCTAssertEqual(evidence["edge_tcp_connect_completed"] as? Bool, true)
        XCTAssertEqual(evidence["edge_tcp_connect_address_family"] as? String, "ipv6")
        XCTAssertEqual(evidence["flow_tunneled_claimed"] as? Bool, false)

        let diagnostic = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: diagnosticURL)) as? [String: Any])
        XCTAssertEqual(diagnostic["runtime_copy_endpoint_passthrough_decision"] as? String, "matched_passed_through")
        XCTAssertEqual(diagnostic["edge_port_flow_reentry_observed"] as? Bool, true)
        XCTAssertEqual(diagnostic["edge_tcp_connect_completed"] as? Bool, true)
        XCTAssertEqual(diagnostic["edge_tcp_connect_address_family"] as? String, "ipv6")
    }

    func testLiveRuntimeCopyEvidenceWriterRejectsRealEdgeSuccessWithoutSection16Evidence() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("dsse-runtime-copy-evidence-missing-section16-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        addTeardownBlock {
            try? FileManager.default.removeItem(at: directory)
        }

        let evidenceURL = directory.appendingPathComponent("network_extension_runtime_copy_evidence.json")
        let writer = DsseLocalRuntimeCopyEvidenceWriter(
            evidenceURL: evidenceURL,
            now: { Date(timeIntervalSince1970: 1_801_440_000) }
        )
        let manager = try startedLifecycleManager()
        let providerResult = manager.decide(ProviderFlowRequest(host: "dummy-postgres.local", port: 5432))
        let upstreamPayload = Data("client-bytes".utf8)
        let downstreamPayload = Data("private-response".utf8)
        let flow = MockProviderTCPFlowCopyIO(upstreamPayload: upstreamPayload)
        let httpClient = RecordingEdgeRuntimeCopyHTTPClient(response: [
            "schema_version": "network_extension_runtime_copy_session_response.v1",
            "request_id": "req_ne_placeholder",
            "downstream_payload_b64": downstreamPayload.base64EncodedString()
        ], echoRequestID: true)
        let transport = DsseEdgeRuntimeCopyTransport(
            configuration: DsseEdgeRuntimeCopyTransportConfiguration(
                edgeBaseURL: try XCTUnwrap(URL(string: "https://edge.lab.example.local"))
            ),
            httpClient: httpClient
        )
        let completion = expectation(description: "live runtime copy completed before evidence rejection")
        let completedResult = RuntimeCopyResultBox()

        DsseAppProxyProvider.driveLiveRuntimeCopyForMatchedFlow(
            flow: flow,
            providerResult: providerResult,
            lifecycleState: manager.state,
            transport: transport
        ) { result in
            completedResult.result = result
            completion.fulfill()
        }
        wait(for: [completion], timeout: 1.0)

        let result = try XCTUnwrap(completedResult.result).get()
        XCTAssertThrowsError(try writer.write(result: .success(result), transport: transport)) { error in
            XCTAssertEqual(
                error as? DsseLocalRuntimeCopyEvidenceError,
                .invalidEvidence("real_edge_runtime_copy_transport requires Section 16 evidence fields")
            )
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: evidenceURL.path))
    }

    func testLiveRuntimeCopyEvidenceWriterAcceptsRealEdgeSuccessWhenNoEdgePortReentryObserved() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("dsse-runtime-copy-evidence-no-reentry-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        addTeardownBlock {
            try? FileManager.default.removeItem(at: directory)
        }

        let evidenceURL = directory.appendingPathComponent("network_extension_runtime_copy_evidence.json")
        let writer = DsseLocalRuntimeCopyEvidenceWriter(
            evidenceURL: evidenceURL,
            now: { Date(timeIntervalSince1970: 1_801_440_000) },
            section16EvidenceProvider: {
                DsseSection16RuntimeCopyEvidence(
                    edgePortFlowReentryObserved: false,
                    runtimeCopyEndpointPassthroughDecision: "no_flow_matched_edge_port",
                    edgeTCPConnectCompleted: true,
                    edgeTCPConnectAddressFamily: "ipv4"
                )
            }
        )
        let manager = try startedLifecycleManager()
        let providerResult = manager.decide(ProviderFlowRequest(host: "dummy-postgres.local", port: 5432))
        let upstreamPayload = Data("client-bytes".utf8)
        let downstreamPayload = Data("private-response".utf8)
        let flow = MockProviderTCPFlowCopyIO(upstreamPayload: upstreamPayload)
        let httpClient = RecordingEdgeRuntimeCopyHTTPClient(response: [
            "schema_version": "network_extension_runtime_copy_session_response.v1",
            "request_id": "req_ne_placeholder",
            "downstream_payload_b64": downstreamPayload.base64EncodedString()
        ], echoRequestID: true)
        let transport = DsseEdgeRuntimeCopyTransport(
            configuration: DsseEdgeRuntimeCopyTransportConfiguration(
                edgeBaseURL: try XCTUnwrap(URL(string: "https://edge.lab.example.local"))
            ),
            httpClient: httpClient
        )
        let completion = expectation(description: "live runtime copy no-reentry evidence completed")
        let completedResult = RuntimeCopyResultBox()

        DsseAppProxyProvider.driveLiveRuntimeCopyForMatchedFlow(
            flow: flow,
            providerResult: providerResult,
            lifecycleState: manager.state,
            transport: transport
        ) { result in
            completedResult.result = result
            completion.fulfill()
        }
        wait(for: [completion], timeout: 1.0)

        let result = try XCTUnwrap(completedResult.result).get()
        try writer.write(result: .success(result), transport: transport)

        let rawEvidence = try String(contentsOf: evidenceURL, encoding: .utf8)
        XCTAssertFalse(rawEvidence.contains("client-bytes"))
        XCTAssertFalse(rawEvidence.contains("private-response"))
        let evidence = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(rawEvidence.utf8)) as? [String: Any])
        XCTAssertEqual(evidence["status"] as? String, "ok")
        XCTAssertEqual(evidence["runtime_copy_transport_implementation"] as? String, "real_edge_runtime_copy_transport")
        XCTAssertEqual(evidence["runtime_copy_transport_gate"] as? String, "real_transport_completed")
        XCTAssertEqual(evidence["edge_port_flow_reentry_observed"] as? Bool, false)
        XCTAssertEqual(evidence["runtime_copy_endpoint_passthrough_decision"] as? String, "no_flow_matched_edge_port")
        XCTAssertEqual(evidence["edge_tcp_connect_completed"] as? Bool, true)
        XCTAssertEqual(evidence["edge_tcp_connect_address_family"] as? String, "ipv4")
        XCTAssertEqual(evidence["bytes_up"] as? Int, upstreamPayload.count)
        XCTAssertEqual(evidence["bytes_down"] as? Int, downstreamPayload.count)
        XCTAssertEqual(evidence["flow_tunneled_claimed"] as? Bool, false)
    }

    func testM1231RuntimeCopyEvidenceWriterPreservesOkEvidenceAfterLaterBlockedWrite() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("dsse-runtime-copy-evidence-preserve-ok-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        addTeardownBlock {
            try? FileManager.default.removeItem(at: directory)
        }

        let evidenceURL = directory.appendingPathComponent("network_extension_runtime_copy_evidence.json")
        let writer = DsseLocalRuntimeCopyEvidenceWriter(
            evidenceURL: evidenceURL,
            now: { Date(timeIntervalSince1970: 1_801_440_000) },
            section16EvidenceProvider: {
                DsseSection16RuntimeCopyEvidence(
                    edgePortFlowReentryObserved: false,
                    runtimeCopyEndpointPassthroughDecision: "no_flow_matched_edge_port",
                    edgeTCPConnectCompleted: true,
                    edgeTCPConnectAddressFamily: "ipv4"
                )
            }
        )
        let manager = try startedLifecycleManager()
        let providerResult = manager.decide(ProviderFlowRequest(host: "dummy-postgres.local", port: 5432))
        let upstreamPayload = Data("client-bytes".utf8)
        let downstreamPayload = Data("private-response".utf8)
        let httpClient = RecordingEdgeRuntimeCopyHTTPClient(response: [
            "schema_version": "network_extension_runtime_copy_session_response.v1",
            "request_id": "req_ne_placeholder",
            "downstream_payload_b64": downstreamPayload.base64EncodedString()
        ], echoRequestID: true)
        let transport = DsseEdgeRuntimeCopyTransport(
            configuration: DsseEdgeRuntimeCopyTransportConfiguration(
                edgeBaseURL: try XCTUnwrap(URL(string: "https://edge.lab.example.local"))
            ),
            httpClient: httpClient
        )
        let completion = expectation(description: "live runtime copy evidence completed before later blocked write")
        let completedResult = RuntimeCopyResultBox()

        DsseAppProxyProvider.driveLiveRuntimeCopyForMatchedFlow(
            flow: MockProviderTCPFlowCopyIO(upstreamPayload: upstreamPayload),
            providerResult: providerResult,
            lifecycleState: manager.state,
            transport: transport
        ) { result in
            completedResult.result = result
            completion.fulfill()
        }
        wait(for: [completion], timeout: 1.0)

        let result = try XCTUnwrap(completedResult.result).get()
        try writer.write(result: .success(result), transport: transport)
        try writer.write(result: .failure(DsseLocalRuntimeCopyDriverError.flowWriteFailed), transport: transport)

        let evidence = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: evidenceURL)) as? [String: Any])
        XCTAssertEqual(evidence["status"] as? String, "ok")
        XCTAssertEqual(evidence["runtime_copy_transport_gate"] as? String, "real_transport_completed")
        XCTAssertEqual(evidence["runtime_copy_transport_implementation"] as? String, "real_edge_runtime_copy_transport")
        XCTAssertEqual(evidence["bytes_up"] as? Int, upstreamPayload.count)
        XCTAssertEqual(evidence["bytes_down"] as? Int, downstreamPayload.count)
        XCTAssertEqual(evidence["blocking_categories"] as? [String], [])
    }

    func testLiveRuntimeCopyEvidenceWriterMarksPendingTransportAsBlocked() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("dsse-runtime-copy-evidence-pending-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        addTeardownBlock {
            try? FileManager.default.removeItem(at: directory)
        }

        let evidenceURL = directory.appendingPathComponent("network_extension_runtime_copy_evidence.json")
        let writer = DsseLocalRuntimeCopyEvidenceWriter(evidenceURL: evidenceURL)
        try writer.write(
            result: .failure(DsseLocalRuntimeCopyDriverError.runtimeTransportDeviceValidationPending),
            transport: DsseDeviceValidationPendingRuntimeCopyTransport()
        )

        let evidence = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: evidenceURL)) as? [String: Any])
        XCTAssertEqual(evidence["status"] as? String, "blocked")
        XCTAssertEqual(evidence["runtime_copy_transport_gate"] as? String, "pending")
        XCTAssertEqual(evidence["runtime_copy_transport_implementation"] as? String, "device_validation_pending")
        XCTAssertEqual(evidence["edge_connector_realness"] as? String, "in_process_stub")
        XCTAssertEqual(evidence["edge_transport_round_trip_gate"] as? String, "not_completed")
        XCTAssertEqual(evidence["bytes_up"] as? Int, 0)
        XCTAssertEqual(evidence["bytes_down"] as? Int, 0)
        XCTAssertEqual(evidence["blocking_categories"] as? [String], ["runtime_copy_transport_pending"])
        XCTAssertEqual(evidence["flow_tunneled_claimed"] as? Bool, false)
    }

    func testProviderRuntimeDiagnosticWriterEmitsDirectNonsecretEnumCategories() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("dsse-provider-runtime-diagnostic-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        addTeardownBlock {
            try? FileManager.default.removeItem(at: directory)
        }

        let diagnosticURL = directory.appendingPathComponent("network_extension_runtime_diagnostic.json")
        let writer = DsseProviderRuntimeDiagnosticWriter(
            diagnosticURL: diagnosticURL,
            now: { Date(timeIntervalSince1970: 1_801_440_000) }
        )

        try writer.recordStartProxyRunning()
        try writer.recordTransparentNetworkSettingsApplied()
        try writer.recordProviderRulesReloadGate("reloaded")
        try writer.recordHandleNewFlow(
            decisionCategory: "accepted",
            extractionStatus: "ok",
            extractionReason: "extracted_tcp_host_port",
            providerDecisionAction: "tunnel",
            providerDecisionReason: "matched_network_extension_rule",
            singleRuleLabFallbackGate: "not_evaluated",
            flowAuthorityHostGate: "hostname",
            flowAuthorityPortGate: "positive",
            singleRuleLabFallbackPortGate: "not_evaluated",
            providerLoadedRulesGeneratedAt: "2026-06-08T00:00:00Z"
        )
        try writer.recordLiveCopyProgress(.liveCopyStarted)
        try writer.recordLiveCopyProgress(.flowOpenCompleted)
        try writer.recordLiveCopyProgress(.upstreamReadCompleted(bytes: 23))
        try writer.recordLiveCopyProgress(.edgeRoundTripStarted)
        try writer.recordLiveCopyProgress(.edgeTCPConnectStarted(family: "ipv6"))
        try writer.recordLiveCopyProgress(.edgeRoundTripRequestSent)
        try writer.recordLiveCopyProgress(.edgeTCPConnectCompleted(family: "ipv6"))
        try writer.recordLiveCopyProgress(.edgeRoundTripResponseStatusReceived(category: "success"))
        try writer.recordLiveCopyProgress(.edgeRoundTripResponseBodyReceived)
        try writer.recordLiveCopyProgress(.edgeRoundTripCompleted)
        try writer.recordRuntimeCopyEndpointPassThrough()
        try writer.recordLiveCopyProgress(.downstreamWriteStarted)
        try writer.recordLiveCopyProgress(.downstreamWriteFailed(category: "ne_provider_flow_error"))
        try writer.recordLiveCopyFailed(DsseLocalRuntimeCopyDriverError.flowWriteFailed)

        let rawDiagnostic = try String(contentsOf: diagnosticURL, encoding: .utf8)
        XCTAssertFalse(rawDiagnostic.contains("tenant_lab_001"))
        XCTAssertFalse(rawDiagnostic.contains("dummy-postgres.local"))
        XCTAssertFalse(rawDiagnostic.contains("synthetic-client-bytes"))
        let diagnostic = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(rawDiagnostic.utf8)) as? [String: Any])
        XCTAssertEqual(diagnostic["schema_version"] as? String, "phase2_provider_runtime_diagnostic.v1")
        XCTAssertEqual(diagnostic["evidence_kind"] as? String, "phase2_provider_runtime_enum_diagnostic")
        XCTAssertEqual(diagnostic["diagnostic_source"] as? String, "provider_direct_file")
        XCTAssertEqual(diagnostic["handle_new_flow_observed"] as? Bool, true)
        XCTAssertEqual(diagnostic["handle_new_flow_decision_category"] as? String, "accepted")
        XCTAssertEqual(diagnostic["handle_new_flow_extraction_status"] as? String, "ok")
        XCTAssertEqual(diagnostic["handle_new_flow_extraction_reason"] as? String, "extracted_tcp_host_port")
        XCTAssertEqual(diagnostic["provider_decision_action"] as? String, "tunnel")
        XCTAssertEqual(diagnostic["provider_decision_reason"] as? String, "matched_network_extension_rule")
        XCTAssertEqual(diagnostic["provider_rules_reload_gate"] as? String, "reloaded")
        XCTAssertEqual(diagnostic["provider_loaded_rules_generation_gate"] as? String, "present")
        XCTAssertEqual(diagnostic["provider_loaded_rules_generated_at"] as? String, "2026-06-08T00:00:00Z")
        XCTAssertEqual(diagnostic["single_rule_lab_fallback_gate"] as? String, "not_evaluated")
        XCTAssertEqual(diagnostic["live_copy_status"] as? String, "failed")
        XCTAssertEqual(diagnostic["live_copy_failure_category"] as? String, "flow_write")
        XCTAssertEqual(diagnostic["live_copy_started"] as? Bool, true)
        XCTAssertEqual(diagnostic["flow_open_completed"] as? Bool, true)
        XCTAssertEqual(diagnostic["upstream_read_completed"] as? Bool, true)
        XCTAssertEqual(diagnostic["upstream_read_bytes"] as? Int, 23)
        XCTAssertEqual(diagnostic["edge_round_trip_started"] as? Bool, true)
        XCTAssertEqual(diagnostic["edge_tcp_connect_started"] as? Bool, true)
        XCTAssertEqual(diagnostic["edge_tcp_connect_completed"] as? Bool, true)
        XCTAssertEqual(diagnostic["edge_tcp_connect_address_family"] as? String, "ipv6")
        XCTAssertEqual(diagnostic["edge_round_trip_request_sent"] as? Bool, true)
        XCTAssertEqual(diagnostic["edge_round_trip_response_status_received"] as? Bool, true)
        XCTAssertEqual(diagnostic["edge_round_trip_response_status_category"] as? String, "success")
        XCTAssertEqual(diagnostic["edge_round_trip_error_category"] as? String, "none")
        XCTAssertEqual(diagnostic["edge_round_trip_response_body_received"] as? Bool, true)
        XCTAssertEqual(diagnostic["edge_round_trip_completed"] as? Bool, true)
        XCTAssertEqual(diagnostic["downstream_write_started"] as? Bool, true)
        XCTAssertEqual(diagnostic["flow_write_error_category"] as? String, "ne_provider_flow_error")
        XCTAssertEqual(diagnostic["downstream_write_completed"] as? Bool, false)
        XCTAssertEqual(diagnostic["runtime_copy_endpoint_pass_through_observed"] as? Bool, true)
        XCTAssertEqual(diagnostic["runtime_copy_endpoint_passthrough_decision"] as? String, "matched_passed_through")
        XCTAssertEqual(diagnostic["edge_port_flow_reentry_observed"] as? Bool, true)
        XCTAssertEqual(diagnostic["start_proxy_running_observed"] as? Bool, true)
        XCTAssertEqual(diagnostic["transparent_network_settings_applied_observed"] as? Bool, true)
        XCTAssertEqual(diagnostic["raw_logs_included"] as? Bool, false)
        XCTAssertEqual(diagnostic["raw_ne_flow_included"] as? Bool, false)
        XCTAssertEqual(diagnostic["destination_ip_included"] as? Bool, false)
        XCTAssertEqual(diagnostic["apple_identifier_included"] as? Bool, false)
        XCTAssertEqual(diagnostic["no_secret_attestation"] as? Bool, true)
        XCTAssertEqual(diagnostic["recommended_next_dev_action"] as? String, "inspect_ne_flow_write_error_category")

        try writer.recordLiveCopyCompleted()
        let completedDiagnostic = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: diagnosticURL)) as? [String: Any])
        XCTAssertEqual(completedDiagnostic["live_copy_status"] as? String, "completed")
        XCTAssertEqual(completedDiagnostic["live_copy_failure_category"] as? String, "none")
        XCTAssertEqual(completedDiagnostic["downstream_write_started"] as? Bool, true)
        XCTAssertEqual(completedDiagnostic["downstream_write_completed"] as? Bool, true)

        try writer.recordLiveCopyFailed(DsseLocalRuntimeCopyDriverError.flowWriteFailed)
        let preservedDiagnostic = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: diagnosticURL)) as? [String: Any])
        XCTAssertEqual(preservedDiagnostic["live_copy_status"] as? String, "completed")
        XCTAssertEqual(preservedDiagnostic["live_copy_failure_category"] as? String, "none")
        XCTAssertEqual(preservedDiagnostic["flow_write_error_category"] as? String, "none")
        XCTAssertEqual(preservedDiagnostic["downstream_write_completed"] as? Bool, true)
    }

    func testM1173ProviderRuntimeDiagnosticPreservesAcceptedLiveCopySnapshotAfterLaterDeniedFlow() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("dsse-provider-runtime-diagnostic-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        addTeardownBlock {
            try? FileManager.default.removeItem(at: directory)
        }

        let diagnosticURL = directory.appendingPathComponent("network_extension_runtime_diagnostic.json")
        let writer = DsseProviderRuntimeDiagnosticWriter(
            diagnosticURL: diagnosticURL,
            now: { Date(timeIntervalSince1970: 1_801_440_000) }
        )

        try writer.recordRuntimeCopyEndpointPassthroughDecision(
            decisionCategory: "no_flow_matched_edge_port",
            edgePortFlowReentryObserved: false
        )
        try writer.recordHandleNewFlow(
            decisionCategory: "accepted",
            extractionStatus: "ok",
            extractionReason: "extracted_tcp_host_port",
            providerDecisionAction: "tunnel",
            providerDecisionReason: "matched_network_extension_rule",
            singleRuleLabFallbackGate: "applied",
            flowAuthorityHostGate: "hostname",
            flowAuthorityPortGate: "positive",
            singleRuleLabFallbackPortGate: "matched",
            providerLoadedRulesGeneratedAt: "not_observed"
        )
        try writer.recordLiveCopyProgress(.liveCopyStarted)
        try writer.recordLiveCopyProgress(.flowOpenCompleted)
        try writer.recordLiveCopyProgress(.upstreamReadCompleted(bytes: 22))
        try writer.recordLiveCopyProgress(.edgeRoundTripStarted)
        try writer.recordLiveCopyProgress(.edgeTCPConnectStarted(family: "fqdn_unresolved"))
        try writer.recordLiveCopyProgress(.edgeRoundTripRequestSent)

        try writer.recordHandleNewFlow(
            decisionCategory: "deny_closed",
            extractionStatus: "denied",
            extractionReason: "invalid_flow_authority",
            providerDecisionAction: "deny",
            providerDecisionReason: "invalid_flow_authority",
            singleRuleLabFallbackGate: "destination_port_mismatch",
            flowAuthorityHostGate: "empty_or_missing",
            flowAuthorityPortGate: "zero_or_missing",
            singleRuleLabFallbackPortGate: "authority_port_zero_or_missing",
            providerLoadedRulesGeneratedAt: "not_observed"
        )
        try writer.recordLiveCopyFailed(DsseLocalRuntimeCopyDriverError.edgeRoundTripTimeout)

        let diagnostic = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: diagnosticURL)) as? [String: Any])
        XCTAssertEqual(diagnostic["handle_new_flow_decision_category"] as? String, "accepted")
        XCTAssertEqual(diagnostic["handle_new_flow_extraction_status"] as? String, "ok")
        XCTAssertEqual(diagnostic["handle_new_flow_extraction_reason"] as? String, "extracted_tcp_host_port")
        XCTAssertEqual(diagnostic["provider_decision_action"] as? String, "tunnel")
        XCTAssertEqual(diagnostic["provider_decision_reason"] as? String, "matched_network_extension_rule")
        XCTAssertEqual(diagnostic["single_rule_lab_fallback_gate"] as? String, "applied")
        XCTAssertEqual(diagnostic["live_copy_status"] as? String, "failed")
        XCTAssertEqual(diagnostic["live_copy_failure_category"] as? String, "edge_round_trip_timeout")
        XCTAssertEqual(diagnostic["live_copy_started"] as? Bool, true)
        XCTAssertEqual(diagnostic["edge_tcp_connect_completed"] as? Bool, false)
        XCTAssertEqual(diagnostic["edge_tcp_connect_address_family"] as? String, "fqdn_unresolved")
        XCTAssertEqual(diagnostic["runtime_copy_endpoint_passthrough_decision"] as? String, "no_flow_matched_edge_port")
        XCTAssertEqual(diagnostic["edge_port_flow_reentry_observed"] as? Bool, false)
    }

    func testM1208ProviderRuntimeDiagnosticPreservesAcceptedFallbackSnapshotBeforeLiveCopyProgressAfterLaterDeniedFlow() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("dsse-provider-runtime-diagnostic-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        addTeardownBlock {
            try? FileManager.default.removeItem(at: directory)
        }

        let diagnosticURL = directory.appendingPathComponent("network_extension_runtime_diagnostic.json")
        let writer = DsseProviderRuntimeDiagnosticWriter(
            diagnosticURL: diagnosticURL,
            now: { Date(timeIntervalSince1970: 1_801_440_000) }
        )

        try writer.recordHandleNewFlow(
            decisionCategory: "accepted",
            extractionStatus: "ok",
            extractionReason: "extracted_tcp_host_port",
            providerDecisionAction: "tunnel",
            providerDecisionReason: "matched_network_extension_rule",
            singleRuleLabFallbackGate: "applied",
            flowAuthorityHostGate: "hostname",
            flowAuthorityPortGate: "positive",
            singleRuleLabFallbackPortGate: "matched",
            providerLoadedRulesGeneratedAt: "not_observed"
        )
        try writer.recordHandleNewFlow(
            decisionCategory: "deny_closed",
            extractionStatus: "denied",
            extractionReason: "invalid_flow_authority",
            providerDecisionAction: "deny",
            providerDecisionReason: "invalid_flow_authority",
            singleRuleLabFallbackGate: "destination_port_mismatch",
            flowAuthorityHostGate: "empty_or_missing",
            flowAuthorityPortGate: "zero_or_missing",
            singleRuleLabFallbackPortGate: "authority_port_zero_or_missing",
            providerLoadedRulesGeneratedAt: "not_observed"
        )

        let diagnostic = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: diagnosticURL)) as? [String: Any])
        XCTAssertEqual(diagnostic["handle_new_flow_decision_category"] as? String, "accepted")
        XCTAssertEqual(diagnostic["handle_new_flow_extraction_status"] as? String, "ok")
        XCTAssertEqual(diagnostic["handle_new_flow_extraction_reason"] as? String, "extracted_tcp_host_port")
        XCTAssertEqual(diagnostic["provider_decision_action"] as? String, "tunnel")
        XCTAssertEqual(diagnostic["provider_decision_reason"] as? String, "matched_network_extension_rule")
        XCTAssertEqual(diagnostic["single_rule_lab_fallback_gate"] as? String, "applied")
        XCTAssertEqual(diagnostic["flow_authority_host_gate"] as? String, "hostname")
        XCTAssertEqual(diagnostic["flow_authority_port_gate"] as? String, "positive")
        XCTAssertEqual(diagnostic["single_rule_lab_fallback_port_gate"] as? String, "matched")
        XCTAssertEqual(diagnostic["live_copy_status"] as? String, "not_observed")
        XCTAssertEqual(diagnostic["live_copy_started"] as? Bool, false)
        XCTAssertEqual(diagnostic["recommended_next_dev_action"] as? String, "inspect_provider_runtime_next_gate")
    }

    func testM1202ProviderRuntimeDiagnosticPreservesEdgePortPassthroughDecisionAfterLaterNonEdgeFlow() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("dsse-provider-runtime-diagnostic-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        addTeardownBlock {
            try? FileManager.default.removeItem(at: directory)
        }

        let diagnosticURL = directory.appendingPathComponent("network_extension_runtime_diagnostic.json")
        let writer = DsseProviderRuntimeDiagnosticWriter(
            diagnosticURL: diagnosticURL,
            now: { Date(timeIntervalSince1970: 1_801_440_000) }
        )

        try writer.recordRuntimeCopyEndpointPassthroughDecision(
            decisionCategory: "no_flow_matched_edge_port",
            edgePortFlowReentryObserved: false
        )
        try writer.recordRuntimeCopyEndpointPassthroughDecision(
            decisionCategory: "port_matched_host_mismatch",
            edgePortFlowReentryObserved: true
        )
        try writer.recordRuntimeCopyEndpointPassthroughDecision(
            decisionCategory: "no_flow_matched_edge_port",
            edgePortFlowReentryObserved: false
        )

        let mismatchDiagnostic = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: diagnosticURL)) as? [String: Any])
        XCTAssertEqual(mismatchDiagnostic["runtime_copy_endpoint_passthrough_decision"] as? String, "port_matched_host_mismatch")
        XCTAssertEqual(mismatchDiagnostic["edge_port_flow_reentry_observed"] as? Bool, true)
        XCTAssertEqual(mismatchDiagnostic["runtime_copy_endpoint_pass_through_observed"] as? Bool, false)

        try writer.recordRuntimeCopyEndpointPassthroughDecision(
            decisionCategory: "matched_passed_through",
            edgePortFlowReentryObserved: true
        )
        try writer.recordRuntimeCopyEndpointPassthroughDecision(
            decisionCategory: "no_flow_matched_edge_port",
            edgePortFlowReentryObserved: false
        )

        let matchedDiagnostic = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: diagnosticURL)) as? [String: Any])
        XCTAssertEqual(matchedDiagnostic["runtime_copy_endpoint_passthrough_decision"] as? String, "matched_passed_through")
        XCTAssertEqual(matchedDiagnostic["edge_port_flow_reentry_observed"] as? Bool, true)
        XCTAssertEqual(matchedDiagnostic["runtime_copy_endpoint_pass_through_observed"] as? Bool, true)
        let snapshot = writer.section16RuntimeCopyEvidenceSnapshot()
        XCTAssertEqual(snapshot.runtimeCopyEndpointPassthroughDecision, "matched_passed_through")
        XCTAssertEqual(snapshot.edgePortFlowReentryObserved, true)
    }

    private func startedLifecycleManager(rules: String = rulesFixture, expectedRuleCount: Int = 1) throws -> ProviderLifecycleManager {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("dsse-handle-new-flow-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        addTeardownBlock {
            try? FileManager.default.removeItem(at: directory)
        }

        let rulesURL = directory.appendingPathComponent("network_extension_steering_rules.json")
        let agentConfigURL = directory.appendingPathComponent("agent_config.json")
        try rules.write(to: rulesURL, atomically: true, encoding: .utf8)
        try #"{"network_extension_rules_ref":"network_extension_steering_rules.json"}"#
            .write(to: agentConfigURL, atomically: true, encoding: .utf8)

        let manager = ProviderLifecycleManager()
        let state = manager.start(agentConfigPath: agentConfigURL.path)
        XCTAssertEqual(state.status, .running)
        XCTAssertTrue(state.rulesLoaded)
        XCTAssertEqual(state.ruleCount, expectedRuleCount)
        return manager
    }

    private func assertRuntimeCopyNotStarted(
        _ report: DsseHandleNewFlowContractReport,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        XCTAssertFalse(report.networkExtensionFlowOpened, file: file, line: line)
        XCTAssertFalse(report.edgeTunnelOpenStarted, file: file, line: line)
        XCTAssertFalse(report.tcpPayloadCopyStarted, file: file, line: line)
        XCTAssertFalse(report.flowPayloadReadStarted, file: file, line: line)
        XCTAssertFalse(report.flowPayloadWriteStarted, file: file, line: line)
    }

    private func assertMetadataOnlyPolicyAuditEvidence(
        _ evidence: DssePolicyDrivenHandleNewFlowAuditEvidence,
        forbiddenFragments: [String],
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws {
        XCTAssertEqual(evidence.auditMetadataOnlyGate, "ok", file: file, line: line)
        XCTAssertEqual(evidence.secretLeakGate, "ok", file: file, line: line)
        XCTAssertEqual(evidence.runtimeOverclaimGate, "ok", file: file, line: line)
        XCTAssertEqual(evidence.flowCopyOverclaimGate, "ok", file: file, line: line)
        XCTAssertFalse(evidence.realEdgeConnectorProductClaimed, file: file, line: line)
        XCTAssertFalse(evidence.flowTunneledClaimed, file: file, line: line)
        XCTAssertFalse(evidence.flowDeniedClaimed, file: file, line: line)
        XCTAssertFalse(evidence.ransomwareProtectionActiveClaimed, file: file, line: line)
        XCTAssertFalse(evidence.realTLSInterceptionClaimed, file: file, line: line)
        XCTAssertFalse(evidence.certificateIssuanceClaimed, file: file, line: line)
        XCTAssertFalse(evidence.productionPrivateAppEnforcementClaimed, file: file, line: line)
        XCTAssertFalse(evidence.productionDefaultDenyEnforcementClaimed, file: file, line: line)
        XCTAssertFalse(evidence.rawLogsIncluded, file: file, line: line)
        XCTAssertFalse(evidence.rawCommandOutputIncluded, file: file, line: line)
        XCTAssertFalse(evidence.rawNEFlowIncluded, file: file, line: line)
        XCTAssertFalse(evidence.hostUserPayloadIncluded, file: file, line: line)
        XCTAssertFalse(evidence.destinationIPIncluded, file: file, line: line)
        XCTAssertFalse(evidence.credentialsIncluded, file: file, line: line)
        XCTAssertFalse(evidence.packetCaptureIncluded, file: file, line: line)
        XCTAssertFalse(evidence.appleIdentifierIncluded, file: file, line: line)
        XCTAssertTrue(evidence.noSecretAttestation, file: file, line: line)
        XCTAssertTrue(
            evidence.nonsecretAuditEventCategories.contains("policy_decision_evaluated"),
            file: file,
            line: line
        )
        XCTAssertTrue(
            evidence.nonsecretAuditEventCategories.contains("metadata_only_audit_emitted"),
            file: file,
            line: line
        )

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        let rawEvidence = try XCTUnwrap(String(data: try encoder.encode(evidence), encoding: .utf8), file: file, line: line)
        forbiddenFragments.forEach { fragment in
            XCTAssertFalse(rawEvidence.contains(fragment), "evidence leaked \(fragment)", file: file, line: line)
        }
    }
}

private let rulesFixture = """
{
  "schema_version": "network_extension_steering_rules.v1",
  "tenant_id": "tenant_lab_001",
  "version": "2026.06.02.test",
  "source_protected_app_map": "protected_app_map_phase2_flow_copy_lab.json",
  "generated_at": "2026-06-02T23:30:00Z",
  "default_action": "deny",
  "rules": [
    {
      "application_id": "app_dummy_postgres",
      "fqdn": "dummy-postgres.local",
      "destination_port": 5432,
      "service_family": "database",
      "steering_mode": "network_extension",
      "action": "tunnel",
      "connector_group_id": "cg_lab_001"
    }
  ]
}
"""

private let p2OperatorConfigRulesFixture = """
{
  "schema_version": "network_extension_steering_rules.v1",
  "tenant_id": "tenant_p2_operator_config",
  "version": "p2-operator-config-port-fallback-test",
  "source_protected_app_map": "protected_app_map_operator_config.json",
  "generated_at": "2026-06-10T08:45:00Z",
  "default_action": "deny",
  "rules": [
    {
      "application_id": "p2_real_postgres_app_ref",
      "fqdn": "postgres.p2.dev.example.internal",
      "destination_port": 5432,
      "service_family": "database",
      "steering_mode": "network_extension",
      "action": "tunnel",
      "connector_group_id": "p2_real_connector_group_ref"
    },
    {
      "application_id": "p2_real_rdp_app_ref",
      "fqdn": "rdp.p2.dev.example.internal",
      "destination_port": 3389,
      "service_family": "rdp",
      "steering_mode": "network_extension",
      "action": "tunnel",
      "connector_group_id": "p2_real_connector_group_ref"
    },
    {
      "application_id": "p2_real_ssh_app_ref",
      "fqdn": "ssh.p2.dev.example.internal",
      "destination_port": 22,
      "service_family": "ssh",
      "steering_mode": "network_extension",
      "action": "tunnel",
      "connector_group_id": "p2_real_connector_group_ref"
    },
    {
      "application_id": "p2_real_web_app_ref",
      "fqdn": "web.p2.dev.example.internal",
      "destination_port": 443,
      "service_family": "https",
      "steering_mode": "network_extension",
      "action": "tunnel",
      "connector_group_id": "p2_real_connector_group_ref"
    }
  ]
}
"""

private let phase4ProtectionRulesFixture = """
{
  "schema_version": "network_extension_steering_rules.v1",
  "tenant_id": "tenant_lab_001",
  "version": "2026.06.04.",
  "source_protected_app_map": "protected_app_map_phase2_flow_copy_lab.json",
  "generated_at": "2026-06-04T20:08:00Z",
  "default_action": "deny",
  "rules": [
    {
      "application_id": "app_dummy_postgres",
      "fqdn": "dummy-postgres.local",
      "destination_port": 5432,
      "service_family": "database",
      "steering_mode": "network_extension",
      "action": "tunnel",
      "connector_group_id": "cg_lab_001"
    },
    {
      "application_id": "app_file_share_admin",
      "fqdn": "dummy-smb-admin-share.local",
      "destination_port": 445,
      "service_family": "lateral_movement_file_share",
      "steering_mode": "network_extension",
      "action": "deny",
      "protection_mode": "ac09_ransomware_lateral_movement",
      "protection_reason_codes": [
        "ransomware_protection_mode_active",
        "risk_signal_lateral_movement_protocol_anomaly"
      ]
    }
  ]
}
"""

private final class MockProviderTCPFlowCopyIO: DsseProviderTCPFlowCopyIO, @unchecked Sendable {
    let upstreamPayload: Data
    let onRead: (@Sendable () -> Void)?
    var opened = false
    var readCount = 0
    var writtenPayloads: [Data] = []
    var closedRead = false
    var closedWrite = false

    init(upstreamPayload: Data, onRead: (@Sendable () -> Void)? = nil) {
        self.upstreamPayload = upstreamPayload
        self.onRead = onRead
    }

    func openForCopy(completionHandler: @escaping @Sendable (Error?) -> Void) {
        opened = true
        completionHandler(nil)
    }

    func readDataForCopy(completionHandler: @escaping @Sendable (Data?, Error?) -> Void) {
        let index = readCount
        readCount += 1
        onRead?()
        guard index == 0 else {
            completionHandler(Data(), nil)
            return
        }
        completionHandler(upstreamPayload, nil)
    }

    func writeDataForCopy(_ data: Data, completionHandler: @escaping @Sendable (Error?) -> Void) {
        writtenPayloads.append(data)
        completionHandler(nil)
    }

    func closeReadForCopy(error: Error?) {
        closedRead = true
    }

    func closeWriteForCopy(error: Error?) {
        closedWrite = true
    }
}

private final class MultiReadProviderTCPFlowCopyIO: DsseProviderTCPFlowCopyIO, @unchecked Sendable {
    let upstreamPayloads: [Data]
    var opened = false
    var readCount = 0
    var writtenPayloads: [Data] = []
    var closedRead = false
    var closedWrite = false

    init(upstreamPayloads: [Data]) {
        self.upstreamPayloads = upstreamPayloads
    }

    func openForCopy(completionHandler: @escaping @Sendable (Error?) -> Void) {
        opened = true
        completionHandler(nil)
    }

    func readDataForCopy(completionHandler: @escaping @Sendable (Data?, Error?) -> Void) {
        let index = readCount
        readCount += 1
        guard index < upstreamPayloads.count else {
            completionHandler(Data(), nil)
            return
        }
        completionHandler(upstreamPayloads[index], nil)
    }

    func writeDataForCopy(_ data: Data, completionHandler: @escaping @Sendable (Error?) -> Void) {
        writtenPayloads.append(data)
        completionHandler(nil)
    }

    func closeReadForCopy(error: Error?) {
        closedRead = true
    }

    func closeWriteForCopy(error: Error?) {
        closedWrite = true
    }
}

private final class HangingAfterPayloadsProviderTCPFlowCopyIO: DsseProviderTCPFlowCopyIO, @unchecked Sendable {
    let upstreamPayloads: [Data]
    var opened = false
    var readCount = 0
    var writtenPayloads: [Data] = []
    var closedRead = false
    var closedWrite = false

    init(upstreamPayloads: [Data]) {
        self.upstreamPayloads = upstreamPayloads
    }

    func openForCopy(completionHandler: @escaping @Sendable (Error?) -> Void) {
        opened = true
        completionHandler(nil)
    }

    func readDataForCopy(completionHandler: @escaping @Sendable (Data?, Error?) -> Void) {
        let index = readCount
        readCount += 1
        guard index < upstreamPayloads.count else {
            return
        }
        completionHandler(upstreamPayloads[index], nil)
    }

    func writeDataForCopy(_ data: Data, completionHandler: @escaping @Sendable (Error?) -> Void) {
        writtenPayloads.append(data)
        completionHandler(nil)
    }

    func closeReadForCopy(error: Error?) {
        closedRead = true
    }

    func closeWriteForCopy(error: Error?) {
        closedWrite = true
    }
}

private final class HangingOpenProviderTCPFlowCopyIO: DsseProviderTCPFlowCopyIO, @unchecked Sendable {
    let upstreamPayload: Data
    var openAttempted = false
    var readCount = 0
    var writtenPayloads: [Data] = []
    var closedRead = false
    var closedWrite = false

    init(upstreamPayload: Data) {
        self.upstreamPayload = upstreamPayload
    }

    func openForCopy(completionHandler: @escaping @Sendable (Error?) -> Void) {
        openAttempted = true
    }

    func readDataForCopy(completionHandler: @escaping @Sendable (Data?, Error?) -> Void) {
        readCount += 1
        completionHandler(upstreamPayload, nil)
    }

    func writeDataForCopy(_ data: Data, completionHandler: @escaping @Sendable (Error?) -> Void) {
        writtenPayloads.append(data)
        completionHandler(nil)
    }

    func closeReadForCopy(error: Error?) {
        closedRead = true
    }

    func closeWriteForCopy(error: Error?) {
        closedWrite = true
    }
}

private final class FailingWriteProviderTCPFlowCopyIO: DsseProviderTCPFlowCopyIO, @unchecked Sendable {
    let upstreamPayload: Data
    let writeError: Error
    var opened = false
    var readCount = 0
    var writtenPayloads: [Data] = []
    var closedRead = false
    var closedWrite = false

    init(
        upstreamPayload: Data,
        writeError: Error = DsseLocalRuntimeCopyDriverError.flowWriteFailed
    ) {
        self.upstreamPayload = upstreamPayload
        self.writeError = writeError
    }

    func openForCopy(completionHandler: @escaping @Sendable (Error?) -> Void) {
        opened = true
        completionHandler(nil)
    }

    func readDataForCopy(completionHandler: @escaping @Sendable (Data?, Error?) -> Void) {
        readCount += 1
        completionHandler(upstreamPayload, nil)
    }

    func writeDataForCopy(_ data: Data, completionHandler: @escaping @Sendable (Error?) -> Void) {
        writtenPayloads.append(data)
        completionHandler(writeError)
    }

    func closeReadForCopy(error: Error?) {
        closedRead = true
    }

    func closeWriteForCopy(error: Error?) {
        closedWrite = true
    }
}

private final class HangingWriteProviderTCPFlowCopyIO: DsseProviderTCPFlowCopyIO, @unchecked Sendable {
    let upstreamPayload: Data
    var opened = false
    var readCount = 0
    var writtenPayloads: [Data] = []
    var closedRead = false
    var closedWrite = false

    init(upstreamPayload: Data) {
        self.upstreamPayload = upstreamPayload
    }

    func openForCopy(completionHandler: @escaping @Sendable (Error?) -> Void) {
        opened = true
        completionHandler(nil)
    }

    func readDataForCopy(completionHandler: @escaping @Sendable (Data?, Error?) -> Void) {
        readCount += 1
        completionHandler(upstreamPayload, nil)
    }

    func writeDataForCopy(_ data: Data, completionHandler: @escaping @Sendable (Error?) -> Void) {
        writtenPayloads.append(data)
    }

    func closeReadForCopy(error: Error?) {
        closedRead = true
    }

    func closeWriteForCopy(error: Error?) {
        closedWrite = true
    }
}

private final class RecordingRuntimeCopyTransport: DsseLocalRuntimeCopyTransport, @unchecked Sendable {
    let downstreamPayload: Data
    var seenPayloads: [Data] = []
    var seenMetadata: [DsseLocalRuntimeCopyMetadata] = []

    init(downstreamPayload: Data) {
        self.downstreamPayload = downstreamPayload
    }

    func roundTrip(
        _ payload: Data,
        metadata: DsseLocalRuntimeCopyMetadata
    ) throws -> Data {
        seenPayloads.append(payload)
        seenMetadata.append(metadata)
        return downstreamPayload
    }
}

private final class RecordingSessionRuntimeCopyTransport: DsseSessionLocalRuntimeCopyTransport, @unchecked Sendable {
    let downstreamPayloads: [Data]
    let sessionClosedResponses: [Bool]
    let onClose: (@Sendable () -> Void)?
    var seenOperations: [DsseLocalRuntimeCopySessionOperation] = []
    var seenPayloads: [Data] = []
    var seenMetadata: [DsseLocalRuntimeCopyMetadata] = []
    var closeCount = 0

    init(
        downstreamPayloads: [Data],
        sessionClosedResponses: [Bool] = [],
        onClose: (@Sendable () -> Void)? = nil
    ) {
        self.downstreamPayloads = downstreamPayloads
        self.sessionClosedResponses = sessionClosedResponses
        self.onClose = onClose
    }

    func roundTrip(
        _ payload: Data,
        metadata: DsseLocalRuntimeCopyMetadata
    ) throws -> Data {
        throw DsseLocalRuntimeCopyDriverError.edgeTransportRequestFailed
    }

    func exchangeSession(
        _ payload: Data,
        operation: DsseLocalRuntimeCopySessionOperation,
        metadata: DsseLocalRuntimeCopyMetadata,
        progressHandler: (@Sendable (DsseLiveRuntimeCopyProgress) -> Void)?
    ) throws -> DsseLocalRuntimeCopySessionExchangeResult {
        seenOperations.append(operation)
        seenPayloads.append(payload)
        seenMetadata.append(metadata)
        progressHandler?(.edgeRoundTripRequestSent)
        progressHandler?(.edgeRoundTripResponseBodyReceived)
        let index = seenPayloads.count - 1
        return DsseLocalRuntimeCopySessionExchangeResult(
            downstreamPayload: downstreamPayloads[index],
            sessionClosed: index < sessionClosedResponses.count ? sessionClosedResponses[index] : false
        )
    }

    func closeSession(
        metadata: DsseLocalRuntimeCopyMetadata,
        progressHandler: (@Sendable (DsseLiveRuntimeCopyProgress) -> Void)?
    ) throws {
        closeCount += 1
        onClose?()
    }
}

private final class BlockedRuntimeCopyTransport: DsseLocalRuntimeCopyTransport, @unchecked Sendable {
    // Keep the exchange incomplete until the timeout assertions finish, even if
    // a loaded test runner takes longer than an arbitrary sleep to resume them.
    let release = DispatchSemaphore(value: 0)
    private let lock = NSLock()
    let downstreamPayload: Data
    private var payloads: [Data] = []
    var seenPayloads: [Data] {
        lock.lock(); defer { lock.unlock() }
        return payloads
    }

    init(downstreamPayload: Data) {
        self.downstreamPayload = downstreamPayload
    }

    func roundTrip(
        _ payload: Data,
        metadata: DsseLocalRuntimeCopyMetadata
    ) throws -> Data {
        lock.lock(); payloads.append(payload); lock.unlock()
        release.wait()
        return downstreamPayload
    }
}

private final class RecordingEdgeRuntimeCopyHTTPClient: DsseEdgeRuntimeCopyHTTPClient, @unchecked Sendable {
    let response: [String: String]
    let echoRequestID: Bool
    let statusCode: Int
    var requests: [URLRequest] = []

    init(response: [String: String], echoRequestID: Bool = false, statusCode: Int = 200) {
        self.response = response
        self.echoRequestID = echoRequestID
        self.statusCode = statusCode
    }

    func perform(_ request: URLRequest) throws -> (Data, Int) {
        requests.append(request)
        var response = response
        if echoRequestID,
           let body = request.httpBody,
           let json = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
           let requestID = json["request_id"] as? String {
            response["request_id"] = requestID
        }
        return (try JSONSerialization.data(withJSONObject: response), statusCode)
    }
}

private final class HangingURLProtocol: URLProtocol {
    override class func canInit(with request: URLRequest) -> Bool {
        true
    }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest {
        request
    }

    override func startLoading() {}

    override func stopLoading() {}
}

private final class RuntimeCopyResultBox: @unchecked Sendable {
    var result: Result<DsseLocalRuntimeCopyResult, Error>?
}

private final class RuntimeCopyProgressBox: @unchecked Sendable {
    private let lock = NSLock()
    private var events: [DsseLiveRuntimeCopyProgress] = []

    var values: [DsseLiveRuntimeCopyProgress] {
        lock.lock()
        defer { lock.unlock() }
        return events
    }

    func append(_ progress: DsseLiveRuntimeCopyProgress) {
        lock.lock()
        defer { lock.unlock() }
        events.append(progress)
    }
}

private final class ManualRuntimeCopyClock: @unchecked Sendable {
    private let lock = NSLock()
    private var current: Date

    init(now: Date) {
        self.current = now
    }

    var now: Date {
        lock.lock()
        defer { lock.unlock() }
        return current
    }

    func advance(by interval: TimeInterval) {
        lock.lock()
        defer { lock.unlock() }
        current = current.addingTimeInterval(interval)
    }
}

// MARK: - a destination named as never-steered is never steered, whichever half the client hands over

extension HandleNewFlowTakeoverTests {

    /// ★★★ MEASURED BEFORE THIS EXISTED (2026-08-30, a real Mac, a real browser). The passthrough list was
    /// matched against the flow's remote host, and a browser resolves the name itself and connects to the
    /// result — `headless_shell … remote_host_kind=ipv4_literal`, `com.apple.curl … remote_host_kind=ipv4_literal`.
    /// So a deployment that named its own Console here was steered anyway in every browser, into the Edge that
    /// is exactly what cannot reach it, and the decision said nothing because it only spoke when it matched.
    func testADestinationNamedForPassthroughIsAlsoMatchedByTheAddressItResolvesTo() {
        let domains = ["console.example.test"]
        let addresses: Set<String> = ["203.0.113.10", "2001:db8::10"]

        // The client that hands over a name — matched as before.
        XCTAssertEqual(DsseAppProxyProvider.transparentPassthroughDomainDecision(
            input: ProviderFlowAuthorityInput(transport: .tcp, remoteHost: "console.example.test", remotePort: 443),
            domains: domains, addresses: addresses
        ), DsseTransparentPassthroughDecision(category: "matched_transparent_passthrough_domain", shouldPassThrough: true))

        // The client that hands over an address — which is what browsers do, and what used to be steered.
        for literal in ["203.0.113.10", "2001:db8::10", "2001:DB8::10"] {
            XCTAssertEqual(DsseAppProxyProvider.transparentPassthroughDomainDecision(
                input: ProviderFlowAuthorityInput(transport: .tcp, remoteHost: literal, remotePort: 443),
                domains: domains, addresses: addresses
            ), DsseTransparentPassthroughDecision(category: "matched_transparent_passthrough_address", shouldPassThrough: true),
            "\(literal) is the destination the deployment named; a browser dials it as an address")
        }

        // An address the deployment never named is steered, which is the whole point of steering. (An IPv4
        // literal passes the domain normaliser, so it falls out of the NAME comparison as not_matched — the
        // very reading that hid this: a destination nobody authored and a destination the client asked for by
        // address were the same answer.)
        XCTAssertEqual(DsseAppProxyProvider.transparentPassthroughDomainDecision(
            input: ProviderFlowAuthorityInput(transport: .tcp, remoteHost: "198.51.100.7", remotePort: 443),
            domains: domains, addresses: addresses
        ), DsseTransparentPassthroughDecision(category: "not_matched", shouldPassThrough: false))

        // And with nothing resolved, an address cannot match by accident.
        XCTAssertEqual(DsseAppProxyProvider.transparentPassthroughDomainDecision(
            input: ProviderFlowAuthorityInput(transport: .tcp, remoteHost: "203.0.113.10", remotePort: 443),
            domains: domains, addresses: []
        ), DsseTransparentPassthroughDecision(category: "not_matched", shouldPassThrough: false))
    }

    /// The resolver half: a name the device can actually resolve produces the address a client would dial.
    /// localhost is used because it resolves on every machine this ever runs on, including a build box with no
    /// network — a test that needs the internet to pass is a test that fails for reasons it is not about.
    func testTheNamesAreResolvedIntoTheAddressesAClientWillDial() {
        let resolved = DsseAppProxyProvider.addressesFor(domains: ["localhost"])
        XCTAssertTrue(resolved.contains("127.0.0.1") || resolved.contains("::1"),
                      "localhost resolved to \(resolved), which contains neither loopback address")
        // A name nothing can resolve contributes nothing, and must not throw or hang the caller.
        XCTAssertTrue(DsseAppProxyProvider.addressesFor(
            domains: ["nothing.invalid.example.test.invalid"]).isEmpty)
        XCTAssertTrue(DsseAppProxyProvider.addressesFor(domains: []).isEmpty)
    }
}

// MARK: - the rank has to be on the list the FIRST choice is made from

extension HandleNewFlowTakeoverTests {

    /// ★★★ MEASURED BEFORE THIS EXISTED (2026-08-30, a real Mac, both directions). The provider read the
    /// preference and printed it — `region_priority configured nagoya=1,fukuoka=2` — and then connected to
    /// fukuoka. The rank was attached only inside the endpoint poller's callback, which runs every 60 seconds
    /// and only after a signed list arrives; the controller's FIRST evaluate happens immediately against the
    /// seed built from the install profile, which carried no rank. Latency chose, and `sticky` kept it there.
    /// The one moment a preference can decide anything is the one moment it was not applied.
    ///
    /// This asserts the selector's behaviour directly: given a seed that carries the rank, the region ranked 1
    /// is chosen even when the other answers faster.
    func testASeedThatCarriesTheRankDecidesTheFirstChoice() {
        let ranked = [
            DsseRegionEndpoint(region: "nagoya", endpoint: "https://n.example", priority: 1),
            DsseRegionEndpoint(region: "fukuoka", endpoint: "https://f.example", priority: 2),
        ]
        let selector = DsseRegionSelector(allowed: ranked, home: "")
        // fukuoka answers in 1ms, nagoya in 200ms: latency alone would pick fukuoka, and did on the real Mac.
        let health: [String: DsseRegionHealth] = [
            "nagoya": DsseRegionHealth(reachable: true, admitted: true, rttMillis: 200),
            "fukuoka": DsseRegionHealth(reachable: true, admitted: true, rttMillis: 1),
        ]
        let decision = selector.evaluate { ep in health[ep.region] ?? DsseRegionHealth(reachable: false, admitted: false, rttMillis: 0) }
        XCTAssertEqual(decision.current?.region, "nagoya",
                       "the region ranked 1 must win over the faster one; got \(decision.current?.region ?? "-")")

        // And the other direction in the same test, because a selector that always returns the first entry
        // would pass the assertion above and mean nothing.
        let reversed = [
            DsseRegionEndpoint(region: "nagoya", endpoint: "https://n.example", priority: 2),
            DsseRegionEndpoint(region: "fukuoka", endpoint: "https://f.example", priority: 1),
        ]
        let selector2 = DsseRegionSelector(allowed: reversed, home: "")
        let decision2 = selector2.evaluate { ep in health[ep.region] ?? DsseRegionHealth(reachable: false, admitted: false, rttMillis: 0) }
        XCTAssertEqual(decision2.current?.region, "fukuoka",
                       "reversing the rank must reverse the choice; got \(decision2.current?.region ?? "-")")
    }

    /// ★ AND AN UNRANKED SEED STILL RANKS BY LATENCY, which is the behaviour every fleet has today and which
    /// this change must not take away from a deployment that states no preference.
    func testAnUnrankedSeedStillPicksTheNearest() {
        let unranked = [
            DsseRegionEndpoint(region: "nagoya", endpoint: "https://n.example"),
            DsseRegionEndpoint(region: "fukuoka", endpoint: "https://f.example"),
        ]
        let selector = DsseRegionSelector(allowed: unranked, home: "")
        let health: [String: DsseRegionHealth] = [
            "nagoya": DsseRegionHealth(reachable: true, admitted: true, rttMillis: 200),
            "fukuoka": DsseRegionHealth(reachable: true, admitted: true, rttMillis: 1),
        ]
        let decision = selector.evaluate { ep in health[ep.region] ?? DsseRegionHealth(reachable: false, admitted: false, rttMillis: 0) }
        XCTAssertEqual(decision.current?.region, "fukuoka", "with no preference the nearest region wins")
    }

    /// ★ AND THE PROVIDER ACTUALLY PUTS IT THERE. The selector honouring a rank is worth nothing if the seed
    /// handed to it never carries one — which is precisely the state this was measured in.
    func testTheProviderRanksTheSeedItBuilds() throws {
        // Read the way the other source-level assertions in this suite read: from #filePath, so the test does
        // not depend on a working directory.
        let url = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Sources/DsseAppProxyProviderSkeleton/DsseAppProxyProvider.swift")
        let source = try String(contentsOf: url, encoding: .utf8)
        XCTAssertTrue(source.contains("DsseInstallProfileApplication.regionSeed(profile: installProfile).map(rank)"),
                      "the provider builds its seed without applying the rank, so the first choice — the only "
                      + "one a preference can decide — is made by latency alone")
    }
}
