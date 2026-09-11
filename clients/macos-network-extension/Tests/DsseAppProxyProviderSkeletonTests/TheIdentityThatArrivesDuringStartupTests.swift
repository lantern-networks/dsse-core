import XCTest
@testable import DsseAppProxyProviderSkeleton
import DsseNetworkExtensionContract

/// ★★★ MEASURED ON A REAL MAC, 2026-08-29 18:15. A Mac installed the documented way (profile + package +
/// token) started its provider, armed five identity-dependent subsystems while it still had no certificate,
/// and enrolled successfully 0.4 seconds later. Nothing re-read the identity. For the next half hour the
/// machine steered every flow into a URLSession that App Transport Security will not let near the
/// deployment's private CA (959 × `NSURLErrorDomain code=-1200`), lost all TCP, and reported itself to the
/// Edge as a device that was never there.
///
/// The rule and the call site are both asserted, because either one alone is satisfied by the broken build:
/// the old code would have passed a rule-only test, and a call site can be deleted without touching the rule.
final class TheIdentityThatArrivesDuringStartupTests: XCTestCase {
    func testAnIdentityThatArrivesDuringStartupRequiresRearming() {
        XCTAssertTrue(DsseStartupArming.mustRearmIdentityDependentSubsystems(after: .arrivedDuringStartup),
                      "a device that enrolled during start keeps the answers it computed before it had a certificate")
        XCTAssertFalse(DsseStartupArming.mustRearmIdentityDependentSubsystems(after: .alreadyPresent),
                       "a restart of an already-enrolled device would arm every subsystem twice")
    }

    /// The call site: startProxy must arm the identity-dependent subsystems AGAIN after the enrolment gate,
    /// and must re-select the runtime-copy transport — the one that decides whether a steered flow can reach
    /// the Edge at all. Read from the source because there is no way to start an NEAppProxyProvider in a test
    /// process, and a comment is not a check.
    func testStartProxyRearmsAfterTheEnrolmentGate() throws {
        let source = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()   // DsseAppProxyProviderSkeletonTests
            .deletingLastPathComponent()   // Tests
            .deletingLastPathComponent()   // package root
            .appendingPathComponent("Sources/DsseAppProxyProviderSkeleton/DsseAppProxyProvider.swift")
        let text = try String(contentsOf: source, encoding: .utf8)
        guard let startProxy = text.range(of: "public override func startProxy("),
              let gate = text.range(of: "resolveDeviceIdentityForStartup(agentConfigPath:", range: startProxy.upperBound..<text.endIndex) else {
            return XCTFail("startProxy no longer calls resolveDeviceIdentityForStartup — this guard is measuring nothing")
        }
        let afterGate = text[gate.upperBound...]
        // Bound the search to the remainder of startProxy so a call in some later method cannot satisfy it.
        let body = afterGate.prefix(4_000)
        XCTAssertTrue(body.contains("armIdentityDependentSubsystems(agentConfigPath:"),
                      "startProxy does not arm the identity-dependent subsystems after the enrolment gate: a device "
                      + "that enrols at first start runs with no heartbeat, no policy poller, no region failover, and "
                      + "a runtime-copy transport that cannot verify the deployment's CA")
        XCTAssertTrue(body.contains("runtimeCopyTransport = Self.runtimeCopyTransport("),
                      "startProxy does not re-select the runtime-copy transport after enrolment: every steered flow "
                      + "would keep riding the URLSession fallback that black-holed this Mac")
    }
}
