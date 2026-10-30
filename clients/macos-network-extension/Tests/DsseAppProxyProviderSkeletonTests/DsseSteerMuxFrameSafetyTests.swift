import Foundation
import Network
import XCTest
@testable import DsseAppProxyProviderSkeleton

final class DsseSteerMuxFrameSafetyTests: XCTestCase {
    private var listener: NWListener?

    override func tearDown() {
        listener?.cancel()
        listener = nil
        super.tearDown()
    }

    func testWireLengthMatchesExistingEdgeProtocolBound() {
        XCTAssertTrue(DsseMuxFrameSafety.acceptsFrameLength(0))
        XCTAssertTrue(DsseMuxFrameSafety.acceptsFrameLength(1 << 20))
        XCTAssertFalse(DsseMuxFrameSafety.acceptsFrameLength((1 << 20) + 1))
        XCTAssertFalse(DsseMuxFrameSafety.acceptsFrameLength(Int(UInt32.max)))
    }

    func testSlowFlowCannotGrowItsInboundBufferWithoutBound() {
        XCTAssertTrue(DsseMuxFrameSafety.acceptsInbound(buffered: 0, incoming: 1 << 20))
        XCTAssertTrue(DsseMuxFrameSafety.acceptsInbound(buffered: (1 << 20) - 1, incoming: 1 << 20))
        XCTAssertFalse(DsseMuxFrameSafety.acceptsInbound(buffered: 1 << 20, incoming: 1))
        XCTAssertFalse(DsseMuxFrameSafety.acceptsInbound(buffered: 0, incoming: (1 << 20) + 1))
    }

    func testOversizedPeerFrameClosesTheLocalMuxBeforeReadingItsBody() throws {
        let queue = DispatchQueue(label: "test.mux-oversized-frame")
        let listener = try NWListener(using: .tcp, on: .any)
        self.listener = listener
        listener.newConnectionHandler = { connection in
            connection.start(queue: queue)
            connection.receive(minimumIncompleteLength: 1, maximumLength: 4096) { _, _, _, _ in
                var response = Data("HTTP/1.1 200 Connection Established\r\n\r\n".utf8)
                response.append(contentsOf: [0, 0, 0, 1, 1]) // flow 1, DATA
                var oversized = UInt32((1 << 20) + 1).bigEndian
                withUnsafeBytes(of: &oversized) { response.append(contentsOf: $0) }
                connection.send(content: response, completion: .contentProcessed { _ in })
            }
        }
        let ready = expectation(description: "local listener ready")
        listener.stateUpdateHandler = { state in
            if case .ready = state { ready.fulfill() }
        }
        listener.start(queue: queue)
        wait(for: [ready], timeout: 5)
        guard let port = listener.port?.rawValue else { return XCTFail("no local port") }

        let opened = expectation(description: "mux handshake completed")
        let muxBox = MuxBox()
        DsseSteerMux.open(edgeHost: "127.0.0.1", edgePort: Int(port), tlsSecurity: nil) { result in
            if case .success(let mux) = result { muxBox.value = mux }
            opened.fulfill()
        }
        wait(for: [opened], timeout: 5)
        guard let mux = muxBox.value else { return XCTFail("local handshake failed") }
        defer { mux.shutdown() }
        let deadline = Date().addingTimeInterval(2)
        while mux.isHealthy && Date() < deadline { Thread.sleep(forTimeInterval: 0.01) }
        XCTAssertFalse(mux.isHealthy, "oversized frame header left a live mux waiting for its impossible body")
    }

    func testHandshakeDoesNotFindSuccessInA502ReasonPhrase() throws {
        let queue = DispatchQueue(label: "test.mux-false-200")
        let listener = try NWListener(using: .tcp, on: .any)
        self.listener = listener
        listener.newConnectionHandler = { connection in
            connection.start(queue: queue)
            connection.receive(minimumIncompleteLength: 1, maximumLength: 4096) { _, _, _, _ in
                connection.send(content: Data("HTTP/1.1 502 Retry after 200 seconds\r\n\r\n".utf8),
                                completion: .contentProcessed { _ in })
            }
        }
        let ready = expectation(description: "local listener ready")
        listener.stateUpdateHandler = { state in
            if case .ready = state { ready.fulfill() }
        }
        listener.start(queue: queue)
        wait(for: [ready], timeout: 5)
        guard let port = listener.port?.rawValue else { return XCTFail("no local port") }

        let completed = expectation(description: "mux handshake rejected")
        let resultBox = MuxResultBox()
        DsseSteerMux.open(edgeHost: "127.0.0.1", edgePort: Int(port), tlsSecurity: nil) { result in
            switch result {
            case .success(let mux): resultBox.mux = mux
            case .failure: resultBox.refused = true
            }
            completed.fulfill()
        }
        wait(for: [completed], timeout: 5)
        defer { resultBox.mux?.shutdown() }
        XCTAssertTrue(resultBox.refused, "HTTP 502 reason phrase was accepted as a 200 status")
    }
}

private final class MuxBox: @unchecked Sendable {
    var value: DsseSteerMux?
}

private final class MuxResultBox: @unchecked Sendable {
    var mux: DsseSteerMux?
    var refused = false
}
