@testable import DsseAppProxyProviderSkeleton
import Foundation
import XCTest

// Regression test for the active idle reaper that prevents connection leaks. Even when the browser closes a flow,
// if the OS does not deliver EOF to the provider's pending read, finish() never runs and the tunnel connection lingers (leaks).
// The reaper tears down a flow with no bytes in either direction for the threshold, ensuring
// NE->Edge connections do not accumulate without bound (no leak).
final class DsseRuntimeCopyTunnelIdleReapTests: XCTestCase {

    func testIdleFlowWithNoActivityIsReaped() {
        let requestID = "req-idle-reap"
        let liveGuard = DsseLiveRuntimeCopyGuard()
        XCTAssertNoThrow(try liveGuard.open(metadata: DsseLocalRuntimeCopyMetadata(
            tenantID: "tenant_lab_001",
            requestID: requestID,
            applicationID: "app.test"
        )))

        // Simulate a zero-activity flow whose read/receive never calls back (browser died / EOF not delivered).
        let flow = ParkingMockFlow()
        let tunnel = ParkingMockTunnel()
        let done = XCTestExpectation(description: "reaped")
        let resultBox = DsseUnsafeBox<Result<DsseLocalRuntimeCopyResult, Error>>()

        let loop = DsseLiveRuntimeCopyTunnelLoop(
            flow: flow,
            requestID: requestID,
            tunnel: tunnel,
            liveGuard: liveGuard,
            emitProgress: { _ in },
            makeSuccessResult: { _, _ in
                XCTFail("idle flow must not succeed")
                return DsseRuntimeCopyTunnelIdleReapTests.dummyResult()
            },
            closeGuardAndFlow: { _ in liveGuard.close(requestID: requestID) },
            completionHandler: { result in
                resultBox.value = result
                done.fulfill()
            },
            idleReapThreshold: 0.4 // reap after 0.4s of no activity
        )
        loop.run()
        // The reaper runs at max(5, threshold/2); for threshold<10 the interval floors at 5s, so
        // keep the threshold small and allow generous wait time to hit it reliably and quickly.
        wait(for: [done], timeout: 12)

        guard let result = resultBox.value else { return XCTFail("no completion (idle flow not reaped = leak)") }
        switch result {
        case .success:
            XCTFail("idle flow must be reaped as failure, not success")
        case .failure(let error):
            XCTAssertEqual(error as? DsseLocalRuntimeCopyDriverError, .runtimeCopyIdleTimeoutExceeded)
        }
        // After reaping, tunnel.close() has been called (the NE->Edge connection is released).
        XCTAssertTrue(tunnel.wasClosed, "reaping must call tunnel.close() (connection release)")
    }

    // Verify that with the reaper disabled (threshold<=0) nothing is reaped (stays parked = never completes).
    func testReaperDisabledKeepsFlowOpen() {
        let requestID = "req-idle-reap-disabled"
        let liveGuard = DsseLiveRuntimeCopyGuard()
        try? liveGuard.open(metadata: DsseLocalRuntimeCopyMetadata(
            tenantID: "t", requestID: requestID, applicationID: "a"))
        let flow = ParkingMockFlow()
        let tunnel = ParkingMockTunnel()
        let done = XCTestExpectation(description: "should-not-complete")
        done.isInverted = true
        let loop = DsseLiveRuntimeCopyTunnelLoop(
            flow: flow, requestID: requestID, tunnel: tunnel, liveGuard: liveGuard,
            emitProgress: { _ in },
            makeSuccessResult: { _, _ in DsseRuntimeCopyTunnelIdleReapTests.dummyResult() },
            closeGuardAndFlow: { _ in liveGuard.close(requestID: requestID) },
            completionHandler: { _ in done.fulfill() },
            idleReapThreshold: 0 // disabled
        )
        loop.run()
        wait(for: [done], timeout: 1.5) // verify it does not complete
    }

    // The interactive-East-West classifier decides which flows are EXEMPT from the idle reaper (so an ssh/rdp
    // session idle at a prompt is not cut at ~120s). Browsing (80/443) must stay reapable; nil/unknown too.
    func testInteractiveEastWestPortClassifier() {
        for p in [22, 3389, 445, 139, 5985, 5986, 135, 5900, 1433, 3306, 5432, 1521, 27017] {
            XCTAssertTrue(dsseIsInteractiveEastWestPort(p), "port \(p) must be interactive East-West (idle-reap exempt)")
        }
        for p in [80, 443, 8443, 8080, 53, 123, 993] {
            XCTAssertFalse(dsseIsInteractiveEastWestPort(p), "port \(p) must NOT be exempt (stays reapable)")
        }
        XCTAssertFalse(dsseIsInteractiveEastWestPort(nil), "nil port must not be exempt")
    }

    func testAuthenticationWaitSurvivesIdleThresholdThenReturnsToNormalCleanup() {
        let liveGuard = DsseLiveRuntimeCopyGuard()
        let flow = ParkingMockFlow()
        let tunnel = AuthenticationParkingTunnel()
        let done = XCTestExpectation(description: "normal cleanup after authentication")
        let loop = DsseLiveRuntimeCopyTunnelLoop(
            flow: flow, requestID: "auth-wait", tunnel: tunnel, liveGuard: liveGuard,
            emitProgress: { _ in },
            makeSuccessResult: { _, _ in Self.dummyResult() },
            closeGuardAndFlow: { _ in },
            completionHandler: { _ in done.fulfill() },
            idleReapThreshold: 0.01
        )
        Thread.sleep(forTimeInterval: 0.03)
        loop.reapIfIdle()
        XCTAssertFalse(tunnel.wasClosed, "a held authentication flow is not an idle keep-alive")
        tunnel.finishAuthentication()
        loop.reapIfIdle()
        XCTAssertFalse(tunnel.wasClosed, "resumption gets a fresh ordinary idle budget")
        Thread.sleep(forTimeInterval: 0.03)
        loop.reapIfIdle()
        wait(for: [done], timeout: 1)
        XCTAssertTrue(tunnel.wasClosed, "authentication must not permanently disable leak cleanup")
    }

    func testHalfClosedRequestRemainsOpenDuringAuthenticationAndDrainsResponse() {
        let tunnel = AuthenticationDrainTunnel()
        let flow = HalfClosedAuthenticationFlow()
        let done = XCTestExpectation(description: "held half-closed request resumes")
        let resultBox = DsseUnsafeBox<Result<DsseLocalRuntimeCopyResult, Error>>()
        let loop = DsseLiveRuntimeCopyTunnelLoop(
            flow: flow, requestID: "auth-half-close", tunnel: tunnel,
            liveGuard: DsseLiveRuntimeCopyGuard(), emitProgress: { _ in },
            makeSuccessResult: { _, _ in Self.dummyResult() },
            closeGuardAndFlow: { _ in },
            completionHandler: { result in resultBox.value = result; done.fulfill() },
            idleReapThreshold: 0.01
        )
        loop.run()
        // Cross both the ordinary idle poll and the five-second EOF drain grace.
        Thread.sleep(forTimeInterval: 6)
        XCTAssertFalse(tunnel.wasClosed, "send-side EOF is not cancellation of a pending authentication")
        tunnel.resumeWithResponse(Data("authenticated response".utf8))
        wait(for: [done], timeout: 2)
        XCTAssertEqual(flow.received, Data("authenticated response".utf8))
        guard case .success = resultBox.value else { return XCTFail("held response must drain successfully") }
    }

    func testAuthenticationWindowIsMonotonicBoundedAndCannotBeRenewed() {
        var window = DsseMuxAuthenticationWait()
        XCTAssertFalse(window.isPending(at: 10))
        window.begin(at: 10)
        XCTAssertTrue(window.isPending(at: 40), "30 seconds without bytes must allow human authentication")
        window.begin(at: 100)
        XCTAssertTrue(window.isPending(at: 129.99))
        XCTAssertFalse(window.isPending(at: 130), "repeated STEPUP cannot extend the 120-second bound")
        XCTAssertFalse(window.isPending(at: 9), "clock regression must not create an unbounded window")
        window.begin(at: 131)
        XCTAssertFalse(window.isPending(at: 131))
    }

    func testApplicationDataOrClosePermanentlyEndsAuthenticationWindow() {
        var window = DsseMuxAuthenticationWait()
        window.begin(at: 10)
        window.end()
        XCTAssertFalse(window.isPending(at: 11))
        window.begin(at: 12)
        XCTAssertFalse(window.isPending(at: 13), "completed flow cannot acquire another exemption")
    }

    private static func dummyResult() -> DsseLocalRuntimeCopyResult {
        DsseLocalRuntimeCopyResult(
            status: "t", implementation: "t", bytesUp: 0, bytesDown: 0,
            registryCleanupGate: "t", tenantMetadataCleanupGate: "t", auditMetadataOnlyGate: "t",
            connectionRegistryRuntimeConnected: true, byteCapRuntimeEnforced: true,
            idleTimeoutRuntimeEnforced: true, boundedBackpressureRuntimeEnforced: true,
            flowReadHalfCloseRuntimeEnforced: true, flowWriteHalfCloseRuntimeEnforced: true,
            networkExtensionFlowOpened: true, edgeTunnelOpenStarted: true, tcpPayloadCopyStarted: true,
            flowPayloadReadStarted: true, flowPayloadWriteStarted: true)
    }
}

// Mock that parks read/receive forever = a zero-activity flow. write/send are treated as successful.
private final class ParkingMockFlow: DsseProviderTCPFlowCopyIO, @unchecked Sendable {
    func openForCopy(completionHandler: @escaping @Sendable (Error?) -> Void) { completionHandler(nil) }
    func readDataForCopy(completionHandler: @escaping @Sendable (Data?, Error?) -> Void) { /* park */ }
    func writeDataForCopy(_ data: Data, completionHandler: @escaping @Sendable (Error?) -> Void) { completionHandler(nil) }
    func closeReadForCopy(error: Error?) {}
    func closeWriteForCopy(error: Error?) {}
}

private final class ParkingMockTunnel: DsseRuntimeCopyTunnelStream, @unchecked Sendable {
    private let lock = NSLock()
    private var closed = false
    var wasClosed: Bool { lock.lock(); defer { lock.unlock() }; return closed }
    func send(_ data: Data, completion: @escaping @Sendable (Error?) -> Void) { completion(nil) }
    func receive(completion: @escaping @Sendable (Data?, Error?) -> Void) { /* park */ }
    func close() { lock.lock(); closed = true; lock.unlock() }
}

private final class AuthenticationParkingTunnel: DsseRuntimeCopyTunnelStream, @unchecked Sendable {
    private let lock = NSLock()
    private var waiting = true
    private var closed = false
    var authenticationWaitPending: Bool { lock.lock(); defer { lock.unlock() }; return waiting && !closed }
    var wasClosed: Bool { lock.lock(); defer { lock.unlock() }; return closed }
    func finishAuthentication() { lock.lock(); waiting = false; lock.unlock() }
    func send(_ data: Data, completion: @escaping @Sendable (Error?) -> Void) { completion(nil) }
    func receive(completion: @escaping @Sendable (Data?, Error?) -> Void) {}
    func close() { lock.lock(); closed = true; lock.unlock() }
}

private final class AuthenticationDrainTunnel: DsseRuntimeCopyTunnelStream, @unchecked Sendable {
    private let lock = NSLock()
    private var waiting = true
    private var closed = false
    private var response: Data?
    private var receiver: (@Sendable (Data?, Error?) -> Void)?
    var authenticationWaitPending: Bool { lock.lock(); defer { lock.unlock() }; return waiting && !closed }
    var wasClosed: Bool { lock.lock(); defer { lock.unlock() }; return closed }
    func send(_ data: Data, completion: @escaping @Sendable (Error?) -> Void) { completion(nil) }
    func receive(completion: @escaping @Sendable (Data?, Error?) -> Void) {
        lock.lock()
        if waiting { receiver = completion; lock.unlock(); return }
        let data = response; response = nil
        lock.unlock()
        completion(data, nil)
    }
    func resumeWithResponse(_ data: Data) {
        lock.lock(); waiting = false
        let callback = receiver; receiver = nil
        if callback == nil { response = data }
        lock.unlock()
        callback?(data, nil)
    }
    func close() {
        lock.lock(); closed = true
        let callback = receiver; receiver = nil
        lock.unlock()
        callback?(nil, nil)
    }
}

private final class HalfClosedAuthenticationFlow: DsseProviderTCPFlowCopyIO, @unchecked Sendable {
    private let lock = NSLock()
    private var response = Data()
    var received: Data { lock.lock(); defer { lock.unlock() }; return response }
    func openForCopy(completionHandler: @escaping @Sendable (Error?) -> Void) { completionHandler(nil) }
    func readDataForCopy(completionHandler: @escaping @Sendable (Data?, Error?) -> Void) { completionHandler(nil, nil) }
    func writeDataForCopy(_ data: Data, completionHandler: @escaping @Sendable (Error?) -> Void) {
        lock.lock(); response.append(data); lock.unlock(); completionHandler(nil)
    }
    func closeReadForCopy(error: Error?) {}
    func closeWriteForCopy(error: Error?) {}
}
