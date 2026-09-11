import XCTest
@testable import DsseNetworkExtensionContract

final class DsseRegionFailoverTests: XCTestCase {
    let tok = DsseRegionEndpoint(region: "jp-tokyo", endpoint: "https://tok:443")
    let osa = DsseRegionEndpoint(region: "jp-osaka", endpoint: "https://osa:443")
    let ish = DsseRegionEndpoint(region: "jp-ishikari", endpoint: "https://ish:443")

    func up(_ ms: Int) -> DsseRegionHealth { DsseRegionHealth(reachable: true, admitted: true, rttMillis: ms) }
    func down() -> DsseRegionHealth { DsseRegionHealth(reachable: false, admitted: false, rttMillis: 0) }
    func deniedAdmit() -> DsseRegionHealth { DsseRegionHealth(reachable: true, admitted: false, rttMillis: 5) }

    func probe(_ m: [String: DsseRegionHealth]) -> (DsseRegionEndpoint) -> DsseRegionHealth {
        { ep in m[ep.region] ?? DsseRegionHealth(reachable: false, admitted: false, rttMillis: 0) }
    }

    // Nearest-healthy among allowed: home=tokyo but osaka nearer -> land on osaka, not the home anchor.
    func testNearestHealthyAmongAllowedNotHome() {
        let s = DsseRegionSelector(allowed: [tok, osa, ish], home: "jp-tokyo")
        let d = s.evaluate(probe: probe(["jp-tokyo": up(50), "jp-osaka": up(10), "jp-ishikari": down()]))
        XCTAssertEqual(d.state, .connected)
        XCTAssertEqual(d.current?.region, "jp-osaka")
        XCTAssertEqual(d.failoverSet.map { $0.region }, ["jp-tokyo"])
    }

    // Empty home from a list refresh preserves the client's configured anchor; a non-empty server home overrides.
    // home=osaka (NOT list[0]) so the tiebreak is distinguishable from list order. Parity with the Go engine.
    func testUpdateListEmptyHomePreservesConfiguredAnchor() {
        let s = DsseRegionSelector(allowed: [tok, osa, ish], home: "jp-osaka")
        s.updateList(allowed: [tok, osa, ish], home: "") // server has no opinion -> keep osaka
        let d = s.evaluate(probe: probe(["jp-tokyo": up(10), "jp-osaka": up(10), "jp-ishikari": up(10)]))
        XCTAssertEqual(d.current?.region, "jp-osaka") // tie -> preserved home anchor, not list-order tokyo
        let s2 = DsseRegionSelector(allowed: [tok, osa, ish], home: "jp-osaka")
        s2.updateList(allowed: [tok, osa, ish], home: "jp-ishikari") // server home overrides
        let d2 = s2.evaluate(probe: probe(["jp-tokyo": up(10), "jp-osaka": up(10), "jp-ishikari": up(10)]))
        XCTAssertEqual(d2.current?.region, "jp-ishikari")
    }

    // In-boundary failover: the current region dies -> reconnect to the next healthy ALLOWED region.
    func testInBoundaryFailover() {
        let s = DsseRegionSelector(allowed: [tok, osa, ish], home: "jp-tokyo")
        s.setUnhealthyStrikes(1)
        XCTAssertEqual(s.evaluate(probe: probe(["jp-tokyo": up(50), "jp-osaka": up(10), "jp-ishikari": up(80)])).current?.region, "jp-osaka")
        let d = s.evaluate(probe: probe(["jp-tokyo": up(50), "jp-osaka": down(), "jp-ishikari": up(80)]))
        XCTAssertEqual(d.state, .connected)
        XCTAssertEqual(d.current?.region, "jp-tokyo") // 50 < ishikari 80
    }

    // Fail closed when no in-boundary peer is healthy: deny, never reach outside the boundary.
    func testFailClosedWhenNoHealthyAllowed() {
        let s = DsseRegionSelector(allowed: [tok, osa, ish], home: "jp-tokyo")
        let d = s.evaluate(probe: probe(["jp-tokyo": down(), "jp-osaka": down(), "jp-ishikari": down()]))
        XCTAssertEqual(d.state, .failClosed)
        XCTAssertNil(d.current)
    }

    // Residency shrink: a refresh removing the current region drops it; re-select within the new set only.
    func testResidencyShrinkDropsOutOfBoundaryCurrent() {
        let s = DsseRegionSelector(allowed: [tok, osa, ish], home: "jp-tokyo")
        s.setUnhealthyStrikes(1)
        _ = s.evaluate(probe: probe(["jp-osaka": up(10), "jp-tokyo": up(50)]))
        XCTAssertEqual(s.currentRegion, "jp-osaka")
        s.updateList(allowed: [tok, ish], home: "jp-tokyo") // osaka now out of boundary
        XCTAssertEqual(s.currentRegion, "")
        let d = s.evaluate(probe: probe(["jp-osaka": up(1), "jp-tokyo": up(50), "jp-ishikari": up(80)]))
        XCTAssertEqual(d.current?.region, "jp-tokyo") // osaka excluded despite being healthy/nearest
    }

    // Revocation is not evaded by failover: reachable-but-admission-denied -> surface deny, don't hunt.
    func testAdmissionDeniedSurfacesDenyNotFailover() {
        let s = DsseRegionSelector(allowed: [tok, osa, ish], home: "jp-tokyo")
        let d = s.evaluate(probe: probe(["jp-tokyo": deniedAdmit(), "jp-osaka": deniedAdmit(), "jp-ishikari": deniedAdmit()]))
        XCTAssertEqual(d.state, .denied)
        XCTAssertNil(d.current)
    }

    // No flap: a healthy current region is kept even when another becomes nearer (stickiness).
    func testStickinessNoFlap() {
        let s = DsseRegionSelector(allowed: [tok, osa, ish], home: "jp-tokyo")
        _ = s.evaluate(probe: probe(["jp-tokyo": up(50)]))
        XCTAssertEqual(s.currentRegion, "jp-tokyo")
        let d = s.evaluate(probe: probe(["jp-tokyo": up(50), "jp-osaka": up(10)]))
        XCTAssertEqual(d.current?.region, "jp-tokyo") // must NOT flap to nearer osaka
    }

    // Hysteresis: a degraded current region is tolerated for N-1 rounds, failing over on the Nth.
    func testHysteresisToleratesTransientThenFailsOver() {
        let s = DsseRegionSelector(allowed: [tok, osa], home: "jp-tokyo")
        s.setUnhealthyStrikes(3)
        _ = s.evaluate(probe: probe(["jp-tokyo": up(50)]))
        let downTok = probe(["jp-tokyo": down(), "jp-osaka": up(10)])
        for _ in 1...2 {
            let d = s.evaluate(probe: downTok)
            XCTAssertEqual(d.state, .connected)
            XCTAssertEqual(d.current?.region, "jp-tokyo") // within hysteresis
        }
        let d = s.evaluate(probe: downTok)
        XCTAssertEqual(d.current?.region, "jp-osaka") // 3rd strike -> failover
    }

    // Observability of the accepted-risk hysteresis window (WONT-FIX #14): an admission-deny on the
    // ALREADY-CONNECTED current region is tolerated for unhealthyStrike-1 rounds. State stays .connected
    // (failover behavior UNCHANGED) but the hold is annotated so the agent can surface the delayed revocation.
    // Byte-parity with the Go regionfailover engine's TestHysteresisHoldAnnotatesAdmissionDenied.
    func testHysteresisHoldAnnotatesAdmissionDenied() {
        let s = DsseRegionSelector(allowed: [tok, osa, ish], home: "jp-tokyo") // default unhealthyStrikes = 3
        XCTAssertEqual(s.evaluate(probe: probe(["jp-tokyo": up(50)])).current?.region, "jp-tokyo")
        // Tokyo (current) now admission-DENIED, no other region healthy. Strike 1 of 3: still .connected, annotated.
        var d = s.evaluate(probe: probe(["jp-tokyo": deniedAdmit()]))
        XCTAssertEqual(d.state, .connected)          // behavior unchanged during hysteresis
        XCTAssertEqual(d.current?.region, "jp-tokyo")
        XCTAssertTrue(d.held)
        XCTAssertTrue(d.heldAdmissionDenied)         // revoked, not merely unreachable
        XCTAssertEqual(d.heldRoundsRemaining, 2)     // strike 1 of 3
        // Strike 2 of 3: still held, one round left.
        d = s.evaluate(probe: probe(["jp-tokyo": deniedAdmit()]))
        XCTAssertEqual(d.state, .connected)
        XCTAssertTrue(d.held)
        XCTAssertEqual(d.heldRoundsRemaining, 1)
        // Strike 3 reaches the threshold: the deny now takes effect.
        d = s.evaluate(probe: probe(["jp-tokyo": deniedAdmit()]))
        XCTAssertEqual(d.state, .denied)
        XCTAssertFalse(d.held) // a resolved deny is not a hold
    }

    // An UNREACHABLE hold is annotated but NOT flagged as an admission-deny (benign transient blip).
    func testHysteresisHoldUnreachableNotAdmissionDenied() {
        let s = DsseRegionSelector(allowed: [tok, osa, ish], home: "jp-tokyo")
        XCTAssertEqual(s.evaluate(probe: probe(["jp-tokyo": up(50)])).current?.region, "jp-tokyo")
        let d = s.evaluate(probe: probe(["jp-tokyo": down()]))
        XCTAssertEqual(d.state, .connected)
        XCTAssertTrue(d.held)
        XCTAssertFalse(d.heldAdmissionDenied)
    }

    // A persistent admission-deny on the CURRENT region must NOT fail over to a peer that still admits this
    // (revoked) device — revocation may not have propagated there yet. Byte-parity with the Go engine's
    // TestCurrentRegionAdmissionDenyDeniesNotFailoverToAdmittingPeer.
    func testCurrentRegionAdmissionDenyDeniesNotFailoverToAdmittingPeer() {
        let s = DsseRegionSelector(allowed: [tok, osa, ish], home: "jp-tokyo")
        s.setUnhealthyStrikes(1)       // reach the threshold immediately
        s.setDenyOnAdmissionDeny(true) // endpoint-agent semantics: !admitted = revoked device
        XCTAssertEqual(s.evaluate(probe: probe(["jp-tokyo": up(50)])).current?.region, "jp-tokyo")
        // Tokyo denies (revoked here); osaka still admits (revocation not propagated). Must deny, not fail over.
        let d = s.evaluate(probe: probe(["jp-tokyo": deniedAdmit(), "jp-osaka": up(10), "jp-ishikari": down()]))
        XCTAssertEqual(d.state, .denied)
        XCTAssertNil(d.current)
    }

    // DEFAULT (deny-on-admission-deny OFF): the same engine drives the Edge CP-endpoint selector, where
    // !admitted means "not the CP leader" — a reachable-but-not-leader current region MUST fail over. Parity
    // with the Go engine's TestCurrentRegionNotAdmittedFailsOverWhenDenyOptionOff.
    func testCurrentRegionNotAdmittedFailsOverWhenDenyOptionOff() {
        let s = DsseRegionSelector(allowed: [tok, osa, ish], home: "jp-tokyo")
        s.setUnhealthyStrikes(1) // deny option left OFF (default) — CP-endpoint-selector semantics
        XCTAssertEqual(s.evaluate(probe: probe(["jp-tokyo": up(50)])).current?.region, "jp-tokyo")
        let d = s.evaluate(probe: probe(["jp-tokyo": deniedAdmit(), "jp-osaka": up(10), "jp-ishikari": down()]))
        XCTAssertEqual(d.state, .connected)
        XCTAssertEqual(d.current?.region, "jp-osaka") // follow leadership / fail over
    }

    // Instant revoke (opt-in): a current-region admission-deny denies IMMEDIATELY (no hold). Byte-parity with
    // the Go engine's TestInstantRevokeOnAdmissionDenyDeniesAtStrikeOne.
    func testInstantRevokeOnAdmissionDenyDeniesAtStrikeOne() {
        let s = DsseRegionSelector(allowed: [tok, osa, ish], home: "jp-tokyo")
        s.setInstantRevokeOnAdmissionDeny(true)
        XCTAssertEqual(s.evaluate(probe: probe(["jp-tokyo": up(50)])).current?.region, "jp-tokyo")
        let d = s.evaluate(probe: probe(["jp-tokyo": deniedAdmit()]))
        XCTAssertEqual(d.state, .denied)
        XCTAssertFalse(d.held)
    }

    // STICKY deny: once the current region admission-denies, the deny holds every round — a revoked device must
    // never reconnect to a peer that still admits it. Byte-parity with the Go TestAdmissionDenyIsSticky...
    func testAdmissionDenyIsStickyNoReconnectToAdmittingPeer() {
        let s = DsseRegionSelector(allowed: [tok, osa, ish], home: "jp-tokyo")
        s.setInstantRevokeOnAdmissionDeny(true)
        XCTAssertEqual(s.evaluate(probe: probe(["jp-tokyo": up(50)])).current?.region, "jp-tokyo")
        let revoked = probe(["jp-tokyo": deniedAdmit(), "jp-osaka": up(10), "jp-ishikari": up(80)])
        for round in 1...5 {
            let d = s.evaluate(probe: revoked)
            XCTAssertEqual(d.state, .denied, "round \(round): must stay denied, not reconnect to admitting osaka")
        }
        // Recovery: tokyo admits again -> reconnect.
        let d = s.evaluate(probe: probe(["jp-tokyo": up(50), "jp-osaka": up(10)]))
        XCTAssertEqual(d.state, .connected)
        XCTAssertEqual(d.current?.region, "jp-tokyo")
    }

    // Instant revoke is specific to admission denials: an UNREACHABLE current region still gets hysteresis.
    func testInstantRevokeStillHoldsOnUnreachable() {
        let s = DsseRegionSelector(allowed: [tok, osa], home: "jp-tokyo")
        s.setInstantRevokeOnAdmissionDeny(true)
        s.setUnhealthyStrikes(3)
        XCTAssertEqual(s.evaluate(probe: probe(["jp-tokyo": up(50)])).current?.region, "jp-tokyo")
        let d = s.evaluate(probe: probe(["jp-tokyo": down()]))
        XCTAssertEqual(d.state, .connected)
        XCTAssertTrue(d.held)
        XCTAssertFalse(d.heldAdmissionDenied)
    }

    // Contrast: even with deny-on-admission-deny ON, an UNREACHABLE current region still fails over normally
    // (the deny rule is admission-specific; health failover is unaffected). Parity with the Go twin.
    func testCurrentRegionUnreachableStillFailsOver() {
        let s = DsseRegionSelector(allowed: [tok, osa, ish], home: "jp-tokyo")
        s.setUnhealthyStrikes(1)
        s.setDenyOnAdmissionDeny(true)
        XCTAssertEqual(s.evaluate(probe: probe(["jp-tokyo": up(50)])).current?.region, "jp-tokyo")
        let d = s.evaluate(probe: probe(["jp-tokyo": down(), "jp-osaka": up(10), "jp-ishikari": down()]))
        XCTAssertEqual(d.state, .connected)
        XCTAssertEqual(d.current?.region, "jp-osaka")
    }

    // Recovery: after fail-closed, return to connected when an allowed region recovers.
    func testRecoversFromFailClosed() {
        let s = DsseRegionSelector(allowed: [tok, osa], home: "jp-tokyo")
        XCTAssertEqual(s.evaluate(probe: probe([:])).state, .failClosed)
        let d = s.evaluate(probe: probe(["jp-osaka": up(10)]))
        XCTAssertEqual(d.state, .connected)
        XCTAssertEqual(d.current?.region, "jp-osaka")
    }
}

// MARK: - Operator priority (2026-08-10)
//
// The requirement: multi-region must have a configurable order, and an RTT tolerance band is not a substitute
// because tens of milliseconds is not noise to an application — it is several TLS round trips and every
// serialized request after them. Mirrors regionfailover/priority_test.go so the two engines cannot drift.

final class DsseRegionPriorityTests: XCTestCase {
    private func up(_ ms: Int) -> DsseRegionHealth {
        DsseRegionHealth(reachable: true, admitted: true, rttMillis: ms)
    }
    private func down() -> DsseRegionHealth {
        DsseRegionHealth(reachable: false, admitted: false, rttMillis: Int.max)
    }
    private func probe(_ m: [String: DsseRegionHealth]) -> (DsseRegionEndpoint) -> DsseRegionHealth {
        { m[$0.region] ?? DsseRegionHealth(reachable: false, admitted: false, rttMillis: Int.max) }
    }

    // A preferred region that is MEASURABLY SLOWER still wins. The 70ms gap makes this impossible to pass by
    // accidental tie.
    func testPriorityBeatsAFasterRegion() {
        let tokP1 = DsseRegionEndpoint(region: "jp-tokyo", endpoint: "https://tok:443", priority: 1)
        let osaP2 = DsseRegionEndpoint(region: "jp-osaka", endpoint: "https://osa:443", priority: 2)
        let s = DsseRegionSelector(allowed: [tokP1, osaP2], home: "")
        let d = s.evaluate(probe: probe(["jp-tokyo": up(80), "jp-osaka": up(10)]))
        XCTAssertEqual(d.current?.region, "jp-tokyo", "priority 1 must win over a region 70ms nearer")
    }

    // Within one tier, nearest still wins — that is what tiers are for.
    func testNearestDecidesWithinOneTier() {
        let a = DsseRegionEndpoint(region: "jp-tokyo", endpoint: "https://tok:443", priority: 1)
        let b = DsseRegionEndpoint(region: "jp-osaka", endpoint: "https://osa:443", priority: 1)
        let s = DsseRegionSelector(allowed: [a, b], home: "jp-tokyo")
        let d = s.evaluate(probe: probe(["jp-tokyo": up(50), "jp-osaka": up(10)]))
        XCTAssertEqual(d.current?.region, "jp-osaka", "inside one tier the nearest wins, even over the home anchor")
    }

    // Preference is not reachability: an unhealthy first choice falls to the next TIER, not to the fastest.
    func testFailsOverToTheNextTier() {
        let p1 = DsseRegionEndpoint(region: "jp-tokyo", endpoint: "https://tok:443", priority: 1)
        let p2 = DsseRegionEndpoint(region: "jp-osaka", endpoint: "https://osa:443", priority: 2)
        let p3 = DsseRegionEndpoint(region: "jp-ishikari", endpoint: "https://ish:443", priority: 3)
        let s = DsseRegionSelector(allowed: [p1, p2, p3], home: "")
        let d = s.evaluate(probe: probe(["jp-tokyo": down(), "jp-osaka": up(90), "jp-ishikari": up(5)]))
        XCTAssertEqual(d.current?.region, "jp-osaka", "the next priority tier, not the fastest survivor")
    }

    // Backward compatibility: with nothing configured every region ties and nearest-RTT decides as before, so
    // the change cannot silently re-home an existing fleet.
    func testNoPrioritiesKeepsNearestBehaviour() {
        let t = DsseRegionEndpoint(region: "jp-tokyo", endpoint: "https://tok:443")
        let o = DsseRegionEndpoint(region: "jp-osaka", endpoint: "https://osa:443")
        let s = DsseRegionSelector(allowed: [t, o], home: "jp-tokyo")
        let d = s.evaluate(probe: probe(["jp-tokyo": up(50), "jp-osaka": up(10)]))
        XCTAssertEqual(d.current?.region, "jp-osaka", "with no priorities the nearest healthy region still wins")
    }
}

// MARK: - Fail-back happens on RESTART, not while running (2026-08-10)
//
// Mirrors regionfailover/failback_test.go so the two engines cannot drift on a decision this load-bearing:
// without a restart re-home, one transient blip moves a device permanently and a fleet drifts onto whichever
// regions happened to be up during past blips, never returning, with everything reporting healthy.
final class DsseRegionFailbackTests: XCTestCase {
    private func up(_ ms: Int) -> DsseRegionHealth { DsseRegionHealth(reachable: true, admitted: true, rttMillis: ms) }
    private func down() -> DsseRegionHealth { DsseRegionHealth(reachable: false, admitted: false, rttMillis: Int.max) }
    private func probe(_ m: [String: DsseRegionHealth]) -> (DsseRegionEndpoint) -> DsseRegionHealth {
        { m[$0.region] ?? DsseRegionHealth(reachable: false, admitted: false, rttMillis: Int.max) }
    }

    func testRestartIsTheFailBackEvent() {
        let p1 = DsseRegionEndpoint(region: "jp-tokyo", endpoint: "https://tok:443", priority: 1)
        let p2 = DsseRegionEndpoint(region: "jp-osaka", endpoint: "https://osa:443", priority: 2)
        let outage = probe(["jp-tokyo": down(), "jp-osaka": up(10)])
        let recovered = probe(["jp-tokyo": up(5), "jp-osaka": up(10)])

        let running = DsseRegionSelector(allowed: [p1, p2], home: "")
        running.setUnhealthyStrikes(1)
        _ = running.evaluate(probe: outage)
        XCTAssertEqual(running.evaluate(probe: outage).current?.region, "jp-osaka")

        var last = running.evaluate(probe: recovered)
        for _ in 0..<50 { last = running.evaluate(probe: recovered) }
        XCTAssertEqual(last.current?.region, "jp-osaka",
                       "a running agent must not fail back on its own — the whole fleet would return in the "
                       + "same probe round, at the region least able to absorb it")

        let restarted = DsseRegionSelector(allowed: [p1, p2], home: "")
        XCTAssertEqual(restarted.evaluate(probe: recovered).current?.region, "jp-tokyo",
                       "restart is the ONLY fail-back path; if it stops working the fleet never returns")
    }

    // Restarting DURING an outage takes the next priority. Priority is preference, never reachability.
    func testRestartDuringAnOutageTakesTheNextPriority() {
        let p1 = DsseRegionEndpoint(region: "jp-tokyo", endpoint: "https://tok:443", priority: 1)
        let p2 = DsseRegionEndpoint(region: "jp-osaka", endpoint: "https://osa:443", priority: 2)
        let s = DsseRegionSelector(allowed: [p1, p2], home: "")
        let d = s.evaluate(probe: probe(["jp-tokyo": down(), "jp-osaka": up(10)]))
        XCTAssertEqual(d.current?.region, "jp-osaka")
    }
}

// MARK: - the fetch that fails has to say what failed

extension DsseRegionFailoverTests {

    /// ★★★ EIGHT HOURS OF ONE SENTENCE (2026-08-30). This device could not fetch the signed region list for as
    /// long as it had been running — no RECOVERED line in the whole day — so region failover ran on the install
    /// profile's seed the entire time, including two measured outage windows, and the rank the poller attaches
    /// was never applied because the callback that attaches it never ran. The only report was, every minute:
    ///
    ///     region-endpoint fetch FAILED (190 consecutive): transport: A TLS error caused the secure connection
    ///     to fail. — the device keeps its previous state, so nothing looks broken from here
    ///
    /// A rejected client certificate, a pinning failure, a certificate that does not carry the name, and a host
    /// that is simply unreachable all produce exactly that sentence. It cannot be acted on, and the line even
    /// ends by saying nothing looks broken.
    ///
    /// Asserted at the source, in the style this suite already uses for reporting contracts: the behaviour is
    /// exercised against a real deployment, and what a unit test can hold is that the branch still names the
    /// domain, the code and the address.
    func testTheTransportFailureNamesItsCauseAndItsAddress() throws {
        let url = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Sources/DsseAppProxyProviderSkeleton/DsseRegionEndpointPoller.swift")
        let source = try String(contentsOf: url, encoding: .utf8)
        for needed in ["domain=\\(ns.domain)", "code=\\(ns.code)", "host=\\(self.url.host"] {
            XCTAssertTrue(source.contains(needed),
                          "the region-endpoint fetch reports a transport failure without \(needed): a rejected "
                          + "client certificate, a pinning failure and an unreachable host then read identically, "
                          + "and the device says so once a minute for as long as it runs")
        }
    }
    // ★★★ RESTART IS THE FAIL-BACK EVENT, AND ON THIS ENGINE NOTHING WAS CHECKING IT (2026-08-31, found by
    // measuring a real failover and then comparing the two engines' test lists).
    //
    // The Go engine pins this with TestRestartIsTheFailBackEvent and TestANewSelectorRemembersNoRegion. The
    // Swift engine — the one every Mac in the fleet actually runs — mirrored eighteen of its siblings and not
    // these two. So the property the whole design rests on was pinned on the platform that was not running
    // here, and the comment in the Go engine says exactly what its loss looks like:
    //
    //	"If a future change remembers it — an obvious-looking optimisation — fail-back disappears silently and
    //	 the fleet drifts to whichever regions happened to be up during past blips, with everything reporting
    //	 healthy."
    //
    // Measured on this Mac today: nagoya was blackholed, the device moved to fukuoka in 29 seconds, nagoya
    // came back, and the device stayed on fukuoka for six minutes with failover_set=[nagoya] — seeing the
    // recovery and declining to move. That is the behaviour these two tests protect.
    func testARunningAgentDoesNotFailBackButOffersTheRecoveredRegion() {
        let nagP1 = DsseRegionEndpoint(region: "nagoya", endpoint: "https://nag:443", priority: 1)
        let fukP2 = DsseRegionEndpoint(region: "fukuoka", endpoint: "https://fuk:443", priority: 2)
        let s = DsseRegionSelector(allowed: [nagP1, fukP2], home: "")
        s.setUnhealthyStrikes(1)

        let outage = probe(["nagoya": down(), "fukuoka": up(10)])
        _ = s.evaluate(probe: outage)
        XCTAssertEqual(s.evaluate(probe: outage).current?.region, "fukuoka",
                       "it must leave a priority-1 region that is down")

        // The preferred region comes back and stays back. A running agent deliberately does not return: a whole
        // fleet moving in one probe round is a reconnect storm aimed at the region that just recovered.
        let recovered = probe(["nagoya": up(5), "fukuoka": up(10)])
        var last: DsseRegionDecision?
        for _ in 0..<50 { last = s.evaluate(probe: recovered) }
        XCTAssertEqual(last?.current?.region, "fukuoka",
                       "a running agent must NOT fail back on its own (herd avoidance). If in-run fail-back "
                       + "was added deliberately — with a stability hold-down, a per-device stagger and a "
                       + "back-off on repeated returns — change this test on purpose, and say so.")
        // ...but the recovered region is offered, so the state is visible rather than forgotten.
        XCTAssertEqual(last?.failoverSet.first?.region, "nagoya",
                       "the recovered higher-priority region must appear as the preferred alternative")
    }

    // The other half, and the property the one above rests on: a NEW selector has no memory, so its first
    // evaluation ranks by priority. If anything ever persists the chosen region across a restart, fail-back
    // disappears and nothing else in this suite would notice.
    func testANewSelectorRemembersNoRegion() {
        let nagP1 = DsseRegionEndpoint(region: "nagoya", endpoint: "https://nag:443", priority: 1)
        let fukP2 = DsseRegionEndpoint(region: "fukuoka", endpoint: "https://fuk:443", priority: 2)
        let healthy = probe(["nagoya": up(5), "fukuoka": up(10)])

        let ranAndMoved = DsseRegionSelector(allowed: [nagP1, fukP2], home: "")
        ranAndMoved.setUnhealthyStrikes(1)
        _ = ranAndMoved.evaluate(probe: probe(["nagoya": down(), "fukuoka": up(10)]))
        _ = ranAndMoved.evaluate(probe: probe(["nagoya": down(), "fukuoka": up(10)]))
        XCTAssertEqual(ranAndMoved.evaluate(probe: healthy).current?.region, "fukuoka",
                       "precondition: this selector is sitting on the lower-priority region")

        let restarted = DsseRegionSelector(allowed: [nagP1, fukP2], home: "")
        XCTAssertEqual(restarted.evaluate(probe: healthy).current?.region, "nagoya",
                       "a fresh selector must home on priority 1. If it does not, restarting an agent no "
                       + "longer re-homes it, and the fleet drifts onto whichever regions were up during past "
                       + "blips while every device reports healthy.")
    }
}
