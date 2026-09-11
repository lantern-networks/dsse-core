import XCTest
@testable import DsseAppProxyProviderSkeleton
@testable import DsseNetworkExtensionContract

final class DsseRegionTransportControllerTests: XCTestCase {
    let tok = DsseRegionEndpoint(region: "jp-tokyo", endpoint: "https://tok:443")
    let osa = DsseRegionEndpoint(region: "jp-osaka", endpoint: "https://osa:443")

    func up(_ ms: Int) -> DsseRegionHealth { DsseRegionHealth(reachable: true, admitted: true, rttMillis: ms) }
    func down() -> DsseRegionHealth { DsseRegionHealth(reachable: false, admitted: false, rttMillis: 0) }

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
