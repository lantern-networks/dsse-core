@testable import DsseAppProxyProviderSkeleton
import Foundation
import XCTest

final class PolicyDenyTakeoverTests: XCTestCase {
    func testPolicyDenialIsNotReturnedToTransparentProxyAsPassthrough() throws {
        // NETransparentProxyProvider treats handleNewFlow == false as direct OS egress. The pure policy
        // report's acceptFlow == false means deny, so it must never be returned as the provider result.
        let source = try String(contentsOfFile:
            "Sources/DsseAppProxyProviderSkeleton/DsseAppProxyProvider.swift", encoding: .utf8)
        let methodStart = try XCTUnwrap(source.range(of: "public override func handleNewFlow("))
        let methodEnd = try XCTUnwrap(source.range(of: "public var currentLifecycleState", range: methodStart.upperBound..<source.endIndex))
        let body = String(source[methodStart.lowerBound..<methodEnd.lowerBound])
        XCTAssertFalse(body.contains("return report.acceptFlow"),
                       "a policy denial would escape the transparent proxy and egress directly")
        let deniedBranch = try XCTUnwrap(body.range(of: "let auditEvidence = Self.policyDrivenHandleNewFlowAuditEvidence(report: report)"))
        let deniedTail = String(body[deniedBranch.lowerBound...])
        XCTAssertTrue(deniedTail.contains("Self.closeFlowWithoutCopy(flow)"),
                      "the rejected flow must be closed while it is retained by the provider")
        XCTAssertTrue(deniedTail.contains("return true"),
                      "the provider must retain a rejected flow rather than release it to direct egress")
    }
}
