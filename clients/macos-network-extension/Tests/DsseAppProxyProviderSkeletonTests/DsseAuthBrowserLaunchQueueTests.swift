import XCTest
@testable import DsseAppProxyProviderSkeleton

final class DsseAuthBrowserLaunchQueueTests: XCTestCase {
    func testNewRevocationChallengeOpensWithinTwoMinutesOfPreviousLogin() {
        var queue = DsseAuthBrowserLaunchQueue()
        XCTAssertTrue(queue.enqueue(id: "initial", uptime: 100))
        XCTAssertEqual(queue.next(uptime: 100), "initial")
        // Do not depend on receiving the previous mux completion event.
        XCTAssertTrue(queue.enqueue(id: "revoked", uptime: 176))
        XCTAssertEqual(queue.next(uptime: 176), "revoked")
        XCTAssertNil(queue.next(uptime: 178))
    }

    func testBurstIsDeferredInOrderAndDuplicatesDoNotReopen() {
        var queue = DsseAuthBrowserLaunchQueue()
        for id in ["one", "two", "three"] { XCTAssertTrue(queue.enqueue(id: id, uptime: 100)) }
        XCTAssertEqual(queue.next(uptime: 100), "one")
        XCTAssertFalse(queue.enqueue(id: "one", uptime: 101))
        XCTAssertNil(queue.next(uptime: 101.999))
        XCTAssertEqual(queue.next(uptime: 102), "two")
        XCTAssertEqual(queue.next(uptime: 104), "three")
        XCTAssertNil(queue.next(uptime: 106))
    }

    func testManualAttemptOrResultCancelsQueuedAutomaticOpening() {
        var queue = DsseAuthBrowserLaunchQueue()
        XCTAssertTrue(queue.enqueue(id: "manual", uptime: 100))
        queue.markAttempted(id: "manual", uptime: 100)
        XCTAssertNil(queue.next(uptime: 102))
        XCTAssertTrue(queue.enqueue(id: "already-resumed", uptime: 103))
        queue.remove(id: "already-resumed")
        XCTAssertNil(queue.next(uptime: 104))
    }

    func testExpiryDoesNotRenewOnDuplicateOrAfterFailedOpening() {
        var queue = DsseAuthBrowserLaunchQueue()
        XCTAssertTrue(queue.enqueue(id: "blocker", uptime: 0))
        XCTAssertTrue(queue.enqueue(id: "waiting", uptime: 0))
        XCTAssertEqual(queue.next(uptime: 119), "blocker")
        XCTAssertFalse(queue.enqueue(id: "waiting", uptime: 119.5))
        XCTAssertNil(queue.next(uptime: 121))
    }

    func testBoundAndMalformedMonotonicTimes() {
        var queue = DsseAuthBrowserLaunchQueue()
        XCTAssertFalse(queue.enqueue(id: "", uptime: 1))
        XCTAssertFalse(queue.enqueue(id: "invalid", uptime: .nan))
        XCTAssertFalse(queue.enqueue(id: "invalid", uptime: -1))
        for i in 0..<32 { XCTAssertTrue(queue.enqueue(id: String(i), uptime: 100)) }
        XCTAssertFalse(queue.enqueue(id: "overflow", uptime: 101))
        XCTAssertEqual(queue.next(uptime: 100), "0")
        XCTAssertNil(queue.next(uptime: .infinity))
        XCTAssertNil(queue.next(uptime: 99))
        XCTAssertNil(queue.next(uptime: 221))
        XCTAssertTrue(queue.enqueue(id: "fresh", uptime: 222))
        XCTAssertEqual(queue.next(uptime: 222), "fresh")
    }
}
