import Foundation
import XCTest
@testable import DsseNetworkExtensionContract

final class ProviderLifecycleRulesReloadRegressionTests: XCTestCase {
    private func rules(port: Int, version: String) -> String {
        """
        {
          "schema_version": "network_extension_steering_rules.v1",
          "tenant_id": "tenant-a",
          "version": "\(version)",
          "source_protected_app_map": "operator-map",
          "generated_at": "2026-10-23T00:00:00Z",
          "default_action": "deny",
          "rules": [{
            "application_id": "app",
            "fqdn": "private.example.test",
            "destination_port": \(port),
            "service_family": "tcp",
            "steering_mode": "network_extension",
            "action": "tunnel"
          }]
        }
        """
    }

    func testAtomicRulesReplacementWithSameModificationDateReloads() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("dsse-rules-stamp-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let config = dir.appendingPathComponent("agent_config.json")
        let ruleFile = dir.appendingPathComponent("rules.json")
        try Data(#"{"network_extension_rules_ref":"rules.json"}"#.utf8).write(to: config)
        let fixedDate = Date(timeIntervalSince1970: 1_800_000_000)
        try Data(rules(port: 18081, version: "old").utf8).write(to: ruleFile, options: .atomic)
        try FileManager.default.setAttributes([.modificationDate: fixedDate], ofItemAtPath: ruleFile.path)

        let manager = ProviderLifecycleManager()
        XCTAssertEqual(manager.start(agentConfigPath: config.path).status, .running)
        XCTAssertEqual(manager.decide(ProviderFlowRequest(host: "private.example.test", port: 18081)).providerAction,
                       .openTunnel)

        try Data(rules(port: 18082, version: "new").utf8).write(to: ruleFile, options: .atomic)
        try FileManager.default.setAttributes([.modificationDate: fixedDate], ofItemAtPath: ruleFile.path)

        XCTAssertEqual(manager.reloadIfStale(), "reloaded")
        XCTAssertEqual(manager.decide(ProviderFlowRequest(host: "private.example.test", port: 18081)).providerAction,
                       .deny)
        XCTAssertEqual(manager.decide(ProviderFlowRequest(host: "private.example.test", port: 18082)).providerAction,
                       .openTunnel)
    }
}
