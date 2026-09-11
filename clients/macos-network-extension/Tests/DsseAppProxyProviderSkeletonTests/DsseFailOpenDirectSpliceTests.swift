import XCTest
import Network
@testable import DsseAppProxyProviderSkeleton

// Integration test for the fail-open direct splice: stand up a loopback TCP echo server, splice a mock flow to
// it, push bytes through the flow, and assert they come back written to the flow. This proves the splice actually
// carries traffic bidirectionally to a direct destination — the load-bearing behaviour of fail-open.
final class DsseFailOpenDirectSpliceTests: XCTestCase {

    func testSpliceCarriesBytesBidirectionallyToADirectDestination() throws {
        let echo = LoopbackEchoServer()
        let port = try echo.start()
        defer { echo.stop() }

        let flow = MockCopyFlow(upstream: [Data("hello-direct".utf8)])
        guard let splice = DsseFailOpenDirectSplice(flow: flow, host: "127.0.0.1", port: Int(port), requestID: "test") else {
            return XCTFail("splice should construct for a valid 127.0.0.1:port destination")
        }

        let ready = expectation(description: "spliced")
        let failed = expectation(description: "not failed"); failed.isInverted = true
        splice.start(onReady: { ready.fulfill() }, onFailed: { _ in failed.fulfill() })
        wait(for: [ready], timeout: 5)

        // The echo server returns what the flow sent upstream; the splice writes it back to the flow's downstream.
        let got = flow.waitForDownstream(atLeast: "hello-direct".utf8.count, timeout: 5)
        XCTAssertEqual(String(data: got, encoding: .utf8), "hello-direct", "the flow's bytes must round-trip through the direct connection")
        wait(for: [failed], timeout: 0.1)
    }

    // The driver constructs a splice as a local and returns — it does NOT retain it. This reproduces exactly that:
    // drop the only strong reference immediately after start(), and assert the splice still drives the connection.
    // Without the internal self-retain the splice deallocates here and the flow silently connect-times-out (the
    // 2026-07-18 on-device failure: onFailed fired with self already nil, egress dead).
    func testSpliceKeepsRunningAfterTheCallerDropsItsReference() throws {
        let echo = LoopbackEchoServer()
        let port = try echo.start()
        defer { echo.stop() }

        let flow = MockCopyFlow(upstream: [Data("orphaned-splice".utf8)])
        let ready = expectation(description: "spliced")
        let failed = expectation(description: "not failed"); failed.isInverted = true

        // Construct, start, then release the local — nothing on the stack retains the splice from here on.
        do {
            guard let splice = DsseFailOpenDirectSplice(flow: flow, host: "127.0.0.1", port: Int(port), requestID: "orphan") else {
                return XCTFail("splice should construct")
            }
            splice.start(onReady: { ready.fulfill() }, onFailed: { _ in failed.fulfill() })
        }

        wait(for: [ready], timeout: 5)
        let got = flow.waitForDownstream(atLeast: "orphaned-splice".utf8.count, timeout: 5)
        XCTAssertEqual(String(data: got, encoding: .utf8), "orphaned-splice", "an un-retained splice must still carry traffic")
        wait(for: [failed], timeout: 0.1)
    }

    func testSpliceConstructionRejectsAnInvalidDestination() {
        let flow = MockCopyFlow(upstream: [])
        XCTAssertNil(DsseFailOpenDirectSplice(flow: flow, host: "", port: 443, requestID: "t"), "empty host -> nil")
        XCTAssertNil(DsseFailOpenDirectSplice(flow: flow, host: "h", port: 0, requestID: "t"), "port 0 -> nil")
        XCTAssertNil(DsseFailOpenDirectSplice(flow: flow, host: "h", port: 70_000, requestID: "t"), "port > 65535 -> nil")
    }

    func testSpliceFailsWhenTheDirectDestinationIsUnreachable() throws {
        // A closed port on loopback: the direct connect must fail, and onFailed (not onReady) fires.
        let flow = MockCopyFlow(upstream: [Data("x".utf8)])
        guard let splice = DsseFailOpenDirectSplice(flow: flow, host: "127.0.0.1", port: 1, requestID: "t") else {
            return XCTFail("splice should construct")
        }
        let failed = expectation(description: "failed")
        let ready = expectation(description: "not ready"); ready.isInverted = true
        splice.start(onReady: { ready.fulfill() }, onFailed: { _ in failed.fulfill() })
        wait(for: [failed, ready], timeout: 13) // connectTimeout is 10s; ready must NOT fire
    }
}

// MockCopyFlow feeds a queue of upstream chunks and captures downstream writes, implementing the copy IO the
// splice drives.
final class MockCopyFlow: DsseProviderTCPFlowCopyIO, @unchecked Sendable {
    private let lock = NSLock()
    private var upstream: [Data]
    private var downstream = Data()
    private var readClosed = false

    init(upstream: [Data]) { self.upstream = upstream }

    func openForCopy(completionHandler: @escaping @Sendable (Error?) -> Void) { completionHandler(nil) }

    func readDataForCopy(completionHandler: @escaping @Sendable (Data?, Error?) -> Void) {
        lock.lock()
        if let next = upstream.first {
            upstream.removeFirst()
            lock.unlock()
            completionHandler(next, nil)
        } else {
            lock.unlock()
            // No more upstream: signal EOF (empty) so the splice half-closes toward the connection.
            completionHandler(Data(), nil)
        }
    }

    func writeDataForCopy(_ data: Data, completionHandler: @escaping @Sendable (Error?) -> Void) {
        lock.lock(); downstream.append(data); lock.unlock()
        completionHandler(nil)
    }

    func closeReadForCopy(error: Error?) { lock.lock(); readClosed = true; lock.unlock() }
    func closeWriteForCopy(error: Error?) {}

    func waitForDownstream(atLeast count: Int, timeout: TimeInterval) -> Data {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            lock.lock(); let n = downstream.count; let snapshot = downstream; lock.unlock()
            if n >= count { return snapshot }
            usleep(20_000)
        }
        lock.lock(); let snapshot = downstream; lock.unlock()
        return snapshot
    }
}

// LoopbackEchoServer accepts one connection and echoes everything it receives.
final class LoopbackEchoServer: @unchecked Sendable {
    private var listener: NWListener?
    private let queue = DispatchQueue(label: "dsse.test.echo")

    func start() throws -> UInt16 {
        let l = try NWListener(using: .tcp)
        listener = l
        l.newConnectionHandler = { conn in
            conn.start(queue: self.queue)
            self.echo(conn)
        }
        let ready = DispatchSemaphore(value: 0)
        l.stateUpdateHandler = { state in if case .ready = state { ready.signal() } }
        l.start(queue: queue)
        _ = ready.wait(timeout: .now() + 5)
        guard let port = l.port?.rawValue else { throw NSError(domain: "echo", code: 1) }
        return port
    }

    private func echo(_ conn: NWConnection) {
        conn.receive(minimumIncompleteLength: 1, maximumLength: 65_536) { data, _, isComplete, error in
            if let data, !data.isEmpty {
                conn.send(content: data, completion: .contentProcessed { _ in })
            }
            if isComplete || error != nil { conn.cancel(); return }
            self.echo(conn)
        }
    }

    func stop() { listener?.cancel() }
}
