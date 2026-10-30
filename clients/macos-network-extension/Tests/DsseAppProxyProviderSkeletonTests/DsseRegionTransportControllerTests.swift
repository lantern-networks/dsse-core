import XCTest
@testable import DsseAppProxyProviderSkeleton
@testable import DsseNetworkExtensionContract

final class DsseRegionTransportControllerTests: XCTestCase {
    let tok = DsseRegionEndpoint(region: "jp-tokyo", endpoint: "https://tok:443")
    let osa = DsseRegionEndpoint(region: "jp-osaka", endpoint: "https://osa:443")

    func up(_ ms: Int) -> DsseRegionHealth { DsseRegionHealth(reachable: true, admitted: true, rttMillis: ms) }
    func down() -> DsseRegionHealth { DsseRegionHealth(reachable: false, admitted: false, rttMillis: 0) }

    func testConnectedRegionDoesNotUnblockOldTransportWhenRebuildFailsAndRetries() {
        let next = DsseRegionEndpoint(region: "jp-osaka", endpoint: "https://osa:443")
        var appliedEndpoint = "https://tok:443"
        var ready = true
        var blocked = false
        var activations = 0
        var canBuild = false
        func transition(changed: Bool) -> Bool {
            DsseAppProxyProvider.activateConnectedRegion(
                current: next, changed: changed, appliedEndpoint: appliedEndpoint,
                transportReady: ready,
                block: { blocked = true; ready = false; return true },
                build: { _ in canBuild ? 1 : nil },
                activate: { _, endpoint, _ in
                    appliedEndpoint = endpoint
                    ready = true
                    blocked = false
                    activations += 1
                    return true
                },
                unblock: { blocked = false; return true })
        }

        XCTAssertFalse(transition(changed: true))
        XCTAssertTrue(blocked)
        XCTAssertFalse(ready)
        XCTAssertEqual(appliedEndpoint, "https://tok:443")
        // The controller reports unchanged on the next probe. A failed rebuild must still retry.
        canBuild = true
        XCTAssertTrue(transition(changed: false))
        XCTAssertFalse(blocked)
        XCTAssertTrue(ready)
        XCTAssertEqual(appliedEndpoint, next.endpoint)
        XCTAssertEqual(activations, 1)
    }

    func testConnectedRegionRejectsPlaintextEndpointBeforeBuildingTransport() {
        var built = false
        var blocked = false
        let insecure = DsseRegionEndpoint(region: "jp-osaka", endpoint: "http://osa:443")
        let activated = DsseAppProxyProvider.activateConnectedRegion(
            current: insecure, changed: true, appliedEndpoint: "https://tok:443",
            transportReady: true,
            block: { blocked = true; return true },
            build: { _ -> Int? in built = true; return 1 },
            activate: { _, _, _ in XCTFail("plaintext endpoint activated"); return true },
            unblock: { XCTFail("old transport unblocked"); return true })
        XCTAssertFalse(activated)
        XCTAssertTrue(blocked)
        XCTAssertFalse(built)
    }

    func testStoppedControllerCannotBuildOrPublishAStaleRegion() {
        let next = DsseRegionEndpoint(region: "jp-osaka", endpoint: "https://osa:443")
        var built = false
        let activated = DsseAppProxyProvider.activateConnectedRegion(
            current: next, changed: true, appliedEndpoint: "https://tok:443",
            transportReady: true,
            block: { false }, // provider epoch changed during stopProxy
            build: { _ -> Int? in built = true; return 1 },
            activate: { _, _, _ in XCTFail("stale region published"); return true },
            unblock: { XCTFail("stale region unblocked"); return true })
        XCTAssertFalse(activated)
        XCTAssertFalse(built)
    }

    func testTelemetryDoesNotReportDisarmedWhenAdmissionOrTransportBlocksDirectEgress() {
        XCTAssertEqual(DsseAppProxyProvider.regionSteerPosture(blocked: true, admissionDenied: true,
                                                                transportReady: true, failOpenArmed: true), "dark")
        XCTAssertEqual(DsseAppProxyProvider.regionSteerPosture(blocked: true, admissionDenied: false,
                                                                transportReady: false, failOpenArmed: true), "dark")
        XCTAssertEqual(DsseAppProxyProvider.regionSteerPosture(blocked: true, admissionDenied: false,
                                                                transportReady: true, failOpenArmed: true), "disarmed")
    }

    func testControllerRebuildsOnDoorChangeWithinRegion() {
        let a = DsseRegionEndpoint(region: "kiri", endpoint: "https://a.example")
        let b = DsseRegionEndpoint(region: "kiri", endpoint: "https://b.example")
        let selector = DsseRegionSelector(allowed: [a, b], home: "kiri")
        selector.setUnhealthyStrikes(1)
        var health = [a.endpoint: up(1), b.endpoint: up(2)]
        var changes: [Bool] = []
        let controller = DsseRegionTransportController(selector: selector,
            probe: { health[$0.endpoint] ?? self.down() }, onDecision: { _, changed in changes.append(changed) })
        XCTAssertEqual(controller.evaluateOnce().current, a)
        health[a.endpoint] = down()
        XCTAssertEqual(controller.evaluateOnce().current, b)
        XCTAssertEqual(changes, [true, true])
    }

    // The controller orchestrates probe -> select -> decision, flags a region change for the provider to rebuild
    // the transport, and reaches fail-closed when no allowed region is healthy.
    func testControllerDrivesFailoverAndFailClosed() {
        let selector = DsseRegionSelector(allowed: [tok, osa], home: "jp-tokyo")
        selector.setUnhealthyStrikes(1)
        var health: [String: DsseRegionHealth] = ["jp-tokyo": up(50), "jp-osaka": up(10)]
        var changes: [Bool] = []
        let controller = DsseRegionTransportController(
            selector: selector,
            probe: { health[$0.region] ?? DsseRegionHealth(reachable: false, admitted: false, rttMillis: 0) },
            onDecision: { _, changed in changes.append(changed) })

        // Round 1: land on osaka (nearest) — a region change.
        var d = controller.evaluateOnce()
        XCTAssertEqual(d.current?.region, "jp-osaka")
        XCTAssertTrue(changes.last!)

        // Round 2: unchanged — sticky, no region change.
        d = controller.evaluateOnce()
        XCTAssertEqual(d.current?.region, "jp-osaka")
        XCTAssertFalse(changes.last!)

        // Round 3: osaka dies -> failover to tokyo (region change).
        health["jp-osaka"] = down()
        d = controller.evaluateOnce()
        XCTAssertEqual(d.current?.region, "jp-tokyo")
        XCTAssertTrue(changes.last!)

        // Round 4: both down -> fail closed (deny).
        health["jp-tokyo"] = down()
        d = controller.evaluateOnce()
        XCTAssertEqual(d.state, .failClosed)
        XCTAssertNil(d.current)
    }

    // updateList feeds a freshly-verified residency-filtered list into the selector (residency shrink path).
    func testUpdateListAppliesResidencyShrink() {
        let selector = DsseRegionSelector(allowed: [tok, osa], home: "jp-tokyo")
        selector.setUnhealthyStrikes(1)
        let health: [String: DsseRegionHealth] = ["jp-osaka": up(10), "jp-tokyo": up(50)]
        let controller = DsseRegionTransportController(
            selector: selector,
            probe: { health[$0.region] ?? DsseRegionHealth(reachable: false, admitted: false, rttMillis: 0) },
            onDecision: { _, _ in })
        XCTAssertEqual(controller.evaluateOnce().current?.region, "jp-osaka")

        // Shrink the allowed set to tokyo only; the selector drops osaka even though it probes nearest.
        selector.updateList(allowed: [tok], home: "jp-tokyo")
        XCTAssertEqual(controller.evaluateOnce().current?.region, "jp-tokyo")
    }
}
