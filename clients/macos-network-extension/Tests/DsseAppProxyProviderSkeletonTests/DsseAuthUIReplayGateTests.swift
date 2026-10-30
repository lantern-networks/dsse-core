import XCTest
@testable import DsseAppProxyProviderSkeleton

final class DsseAuthUIReplayGateTests: XCTestCase {
    func testPeriodicReadRecoversMissedNotificationExactlyOnce() {
        var gate = DsseAuthUIReplayGate()
        // No notification was delivered. The next periodic read sees the file.
        XCTAssertTrue(gate.admit(id: "first", result: nil, uptime: 100))
        for now in stride(from: 102.0, through: 500.0, by: 2) {
            XCTAssertFalse(gate.admit(id: "first", result: nil, uptime: now))
        }
        XCTAssertTrue(gate.admit(id: "second", result: nil, uptime: 502))
        XCTAssertTrue(gate.admit(id: "first", result: "resumed", uptime: 503))
        XCTAssertFalse(gate.admit(id: "first", result: "resumed", uptime: 504))
        XCTAssertFalse(gate.admit(id: "first", result: "not_resumed", uptime: 505))
        XCTAssertFalse(gate.admit(id: "first", result: nil, uptime: 506))
    }

    func testResultBeforeRequestDoesNotReopenBrowser() {
        var gate = DsseAuthUIReplayGate()
        XCTAssertTrue(gate.admit(id: "finished", result: "not_resumed", uptime: 100))
        XCTAssertFalse(gate.admit(id: "finished", result: nil, uptime: 101))
    }

    func testBoundDoesNotEvictLiveRequestsAndDuplicateReadsDoNotExtendRetention() {
        var gate = DsseAuthUIReplayGate(limit: 2)
        XCTAssertTrue(gate.admit(id: "one", result: nil, uptime: 100))
        XCTAssertTrue(gate.admit(id: "two", result: nil, uptime: 101))
        XCTAssertFalse(gate.admit(id: "flood", result: nil, uptime: 102))
        XCTAssertFalse(gate.admit(id: "one", result: nil, uptime: 999))
        // The original first-seen time, not the latest replay, releases a slot.
        XCTAssertTrue(gate.admit(id: "new", result: nil, uptime: 1000))
        XCTAssertFalse(gate.admit(id: "two", result: nil, uptime: 1000))
    }

    func testMalformedEventsAreRejected() {
        var gate = DsseAuthUIReplayGate()
        XCTAssertFalse(gate.admit(id: "", result: nil, uptime: 1))
        XCTAssertFalse(gate.admit(id: "x", result: "browser_opened", uptime: 1))
        XCTAssertFalse(gate.admit(id: "x", result: nil, uptime: .nan))
        XCTAssertFalse(gate.admit(id: "x", result: nil, uptime: -1))
        XCTAssertTrue(gate.admit(id: "x", result: nil, uptime: 1))
    }
}
