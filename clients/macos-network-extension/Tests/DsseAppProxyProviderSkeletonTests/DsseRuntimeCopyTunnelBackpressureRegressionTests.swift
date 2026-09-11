@testable import DsseAppProxyProviderSkeleton
import Foundation
import XCTest

// Regression guard: the full-duplex tunnel copy loop (DsseLiveRuntimeCopyTunnelLoop) calls
// enqueueDownstreamBytes (+1) and dequeueDownstream (-1) as a pair for each downstream chunk.
// A missing dequeue (the root cause) makes queuedDownstreamChunks grow monotonically, and
// once it exceeds backpressureQueueCapacity (default 16) it throws runtimeCopyBackpressureOverflowClosed
// and force-closes the flow. This test streams 40 downstream chunks (well over 16) and
// asserts it runs to completion (no mid-stream backpressure close).
//
// Removing the dequeue makes this test fail (chunk 17 of 40 becomes .failure).
final class DsseRuntimeCopyTunnelBackpressureRegressionTests: XCTestCase {

    func testDownstreamChunksBeyondBackpressureCapacityDoNotCloseFlow() {
        let downstreamChunkCount = 40 // well over backpressureQueueCapacity (16)
        let capacity = DsseLiveRuntimeCopyGuardConfiguration.defaults.backpressureQueueCapacity
        XCTAssertLessThan(capacity, downstreamChunkCount, "test premise: delivered chunk count exceeds capacity")

        let requestID = "req-backpressure-regression"
        let liveGuard = DsseLiveRuntimeCopyGuard()
        XCTAssertNoThrow(try liveGuard.open(metadata: DsseLocalRuntimeCopyMetadata(
            tenantID: "tenant_lab_001",
            requestID: requestID,
            applicationID: "app.test"
        )))

        let flow = BackpressureMockFlow()
        let tunnel = BackpressureMockTunnel(downstreamChunks: downstreamChunkCount)

        let done = XCTestExpectation(description: "copy loop completed")
        let resultBox = DsseUnsafeBox<Result<DsseLocalRuntimeCopyResult, Error>>()

        let loop = DsseLiveRuntimeCopyTunnelLoop(
            flow: flow,
            requestID: requestID,
            tunnel: tunnel,
            liveGuard: liveGuard,
            emitProgress: { _ in },
            makeSuccessResult: { up, down in Self.makeResult(up: up, down: down) },
            closeGuardAndFlow: { _ in liveGuard.close(requestID: requestID) },
            completionHandler: { result in
                resultBox.value = result
                done.fulfill()
            }
        )
        loop.run()
        wait(for: [done], timeout: 5)

        guard let result = resultBox.value else { return XCTFail("no completion") }
        switch result {
        case .success(let r):
            // All 40 chunks stream downstream successfully. bytesDown is 40 * chunkSize.
            XCTAssertEqual(r.bytesDown, downstreamChunkCount * BackpressureMockTunnel.chunkSize)
        case .failure(let error):
            if let driverError = error as? DsseLocalRuntimeCopyDriverError,
               driverError == .runtimeCopyBackpressureOverflowClosed {
                XCTFail("backpressure dequeue-leak regression: flow closed after >16 chunks")
            } else {
                XCTFail("unexpected failure: \(error)")
            }
        }
    }

    static func makeResult(up: Int, down: Int) -> DsseLocalRuntimeCopyResult {
        DsseLocalRuntimeCopyResult(
            status: "completed",
            implementation: "test",
            bytesUp: up,
            bytesDown: down,
            registryCleanupGate: "test",
            tenantMetadataCleanupGate: "test",
            auditMetadataOnlyGate: "test",
            connectionRegistryRuntimeConnected: true,
            byteCapRuntimeEnforced: true,
            idleTimeoutRuntimeEnforced: true,
            boundedBackpressureRuntimeEnforced: true,
            flowReadHalfCloseRuntimeEnforced: true,
            flowWriteHalfCloseRuntimeEnforced: true,
            networkExtensionFlowOpened: true,
            edgeTunnelOpenStarted: true,
            tcpPayloadCopyStarted: true,
            flowPayloadReadStarted: true,
            flowPayloadWriteStarted: true
        )
    }
}

// Upstream: return one chunk, then park subsequent reads (no callback). Keeps pumpUpstream alive while
// the downstream EOF (finishOnEOF) makes up>0 && down>0 -> success.
private final class BackpressureMockFlow: DsseProviderTCPFlowCopyIO, @unchecked Sendable {
    private var upstreamDelivered = false
    private let lock = NSLock()

    func openForCopy(completionHandler: @escaping @Sendable (Error?) -> Void) { completionHandler(nil) }

    func readDataForCopy(completionHandler: @escaping @Sendable (Data?, Error?) -> Void) {
        lock.lock(); let first = !upstreamDelivered; upstreamDelivered = true; lock.unlock()
        if first {
            completionHandler(Data("upstream".utf8), nil)
        }
        // Do not call back from the second read on (park). The downstream EOF completes it successfully.
    }

    func writeDataForCopy(_ data: Data, completionHandler: @escaping @Sendable (Error?) -> Void) {
        completionHandler(nil) // immediate success (write completion triggers dequeue)
    }

    func closeReadForCopy(error: Error?) {}
    func closeWriteForCopy(error: Error?) {}
}

// Downstream: return downstreamChunks fixed chunks of chunkSize, then empty Data (EOF).
private final class BackpressureMockTunnel: DsseRuntimeCopyTunnelStream, @unchecked Sendable {
    static let chunkSize = 1024
    private let total: Int
    private var delivered = 0
    private let lock = NSLock()

    init(downstreamChunks: Int) { self.total = downstreamChunks }

    func send(_ data: Data, completion: @escaping @Sendable (Error?) -> Void) { completion(nil) }

    func receive(completion: @escaping @Sendable (Data?, Error?) -> Void) {
        lock.lock()
        let n = delivered
        if delivered < total { delivered += 1 }
        lock.unlock()
        if n < total {
            completion(Data(repeating: 0x78, count: Self.chunkSize), nil)
        } else {
            completion(Data(), nil) // EOF (empty) -> finishOnEOF
        }
    }

    func close() {}
}

// A flow where the SERVER speaks first and the client never sends anything is legitimate — an SSH banner, an
// SMTP greeting, a port that answers and closes. It used to be reported as emptyUpstreamPayload, i.e. a
// failure, even though the response had been delivered to the app in full.
//
// This was found while root-causing an intermittent failure in the test above rather than dismissing it as
// flaky: the same rule also made a concurrency race visible, because a downstream EOF arriving before the
// upstream read callback had added its bytes saw up == 0 and failed a flow that had worked.
final class DsseRuntimeCopyServerSpeaksFirstTests: XCTestCase {

    func testAFlowWithNoUpstreamBytesButRealDownstreamBytesSucceeds() {
        let requestID = "req-server-speaks-first"
        let liveGuard = DsseLiveRuntimeCopyGuard()
        XCTAssertNoThrow(try liveGuard.open(metadata: DsseLocalRuntimeCopyMetadata(
            tenantID: "tenant_lab_001", requestID: requestID, applicationID: "app.test")))

        let done = XCTestExpectation(description: "copy loop completed")
        let resultBox = DsseUnsafeBox<Result<DsseLocalRuntimeCopyResult, Error>>()
        let loop = DsseLiveRuntimeCopyTunnelLoop(
            flow: SilentClientMockFlow(),
            requestID: requestID,
            tunnel: BackpressureMockTunnel(downstreamChunks: 3),
            liveGuard: liveGuard,
            emitProgress: { _ in },
            makeSuccessResult: { up, down in
                DsseRuntimeCopyTunnelBackpressureRegressionTests.makeResult(up: up, down: down)
            },
            closeGuardAndFlow: { _ in liveGuard.close(requestID: requestID) },
            completionHandler: { result in resultBox.value = result; done.fulfill() })
        loop.run()
        wait(for: [done], timeout: 5)

        switch resultBox.value {
        case .success(let r):
            XCTAssertEqual(r.bytesUp, 0, "the client sent nothing, by construction")
            XCTAssertEqual(r.bytesDown, 3 * BackpressureMockTunnel.chunkSize,
                           "the response was delivered in full")
        case .failure(let error):
            XCTFail("a server-speaks-first flow was reported as a failure (\(error)) even though the response " +
                    "reached the app — an SSH banner or SMTP greeting would be treated as a broken flow")
        case .none:
            XCTFail("no completion")
        }
    }
}

// A client that never sends: the flow's read parks forever, exactly as it would while a user sits at an SSH
// banner without typing.
private final class SilentClientMockFlow: DsseProviderTCPFlowCopyIO, @unchecked Sendable {
    func openForCopy(completionHandler: @escaping @Sendable (Error?) -> Void) { completionHandler(nil) }
    func readDataForCopy(completionHandler: @escaping @Sendable (Data?, Error?) -> Void) { /* parked */ }
    func writeDataForCopy(_ data: Data, completionHandler: @escaping @Sendable (Error?) -> Void) {
        completionHandler(nil)
    }
    func closeReadForCopy(error: Error?) {}
    func closeWriteForCopy(error: Error?) {}
}
