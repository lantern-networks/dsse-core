@testable import DsseAppProxyProviderSkeleton
import Foundation
import Network
import XCTest

final class DsseRuntimeCopyTunnelTests: XCTestCase {
    private var listener: NWListener?

    override func tearDown() {
        listener?.cancel()
        listener = nil
        super.tearDown()
    }

    // Minimal Edge tunnel stand-in: read the HTTP handshake, reply
    // "200 Connection Established", then echo all subsequent bytes (full-duplex).
    private func startEchoTunnelListener() throws -> Int {
        let queue = DispatchQueue(label: "test.echo-tunnel")
        let listener = try NWListener(using: .tcp, on: .any)
        self.listener = listener
        listener.newConnectionHandler = { conn in
            conn.start(queue: queue)
            func echo() {
                conn.receive(minimumIncompleteLength: 1, maximumLength: 65536) { data, _, isComplete, _ in
                    if let data, !data.isEmpty {
                        conn.send(content: data, completion: .contentProcessed { _ in
                            if !isComplete { echo() }
                        })
                    } else if !isComplete {
                        echo()
                    }
                }
            }
            func readHandshake(_ acc: Data) {
                conn.receive(minimumIncompleteLength: 1, maximumLength: 4096) { data, _, _, _ in
                    var next = acc
                    if let data { next.append(data) }
                    if next.range(of: Data("\r\n\r\n".utf8)) != nil {
                        conn.send(content: Data("HTTP/1.1 200 Connection Established\r\n\r\n".utf8), completion: .contentProcessed { _ in
                            echo()
                        })
                    } else {
                        readHandshake(next)
                    }
                }
            }
            readHandshake(Data())
        }
        let ready = XCTestExpectation(description: "listener ready")
        listener.stateUpdateHandler = { state in
            if case .ready = state { ready.fulfill() }
        }
        listener.start(queue: queue)
        wait(for: [ready], timeout: 5)
        guard let port = listener.port?.rawValue else {
            throw DsseRuntimeCopyTunnelError.invalidEdgeAuthority
        }
        return Int(port)
    }

    func testTunnelHandshakeAndFullDuplexEcho() throws {
        let port = try startEchoTunnelListener()

        let opened = XCTestExpectation(description: "tunnel opened")
        let openedTunnel = DsseUnsafeBox<DsseRuntimeCopyTunnel>()
        DsseRuntimeCopyTunnel.open(
            edgeHost: "127.0.0.1",
            edgePort: port,
            tunnelPath: DsseRuntimeCopyTunnel.tunnelEndpointPath,
            tenantID: "tenant_lab_001",
            destinationHost: "dummy.local",
            destinationPort: 443
        ) { result in
            switch result {
            case .success(let tunnel):
                openedTunnel.value = tunnel
                opened.fulfill()
            case .failure(let error):
                XCTFail("tunnel open failed: \(error)")
            }
        }
        wait(for: [opened], timeout: 5)
        guard let tunnel = openedTunnel.value else { return XCTFail("no tunnel") }
        defer { tunnel.close() }

        for payload in ["hello", "world", "dsse"] {
            XCTAssertNil(sendSync(tunnel, Data(payload.utf8)), "send error for \(payload)")
            var received = Data()
            while received.count < payload.utf8.count {
                guard let chunk = receiveSync(tunnel), !chunk.isEmpty else {
                    return XCTFail("tunnel closed before echo of \(payload)")
                }
                received.append(chunk)
            }
            XCTAssertEqual(String(data: received, encoding: .utf8), payload)
        }
    }

    private func sendSync(_ tunnel: DsseRuntimeCopyTunnelStream, _ data: Data) -> Error? {
        let sem = DispatchSemaphore(value: 0)
        let box = DsseUnsafeBox<Error>()
        tunnel.send(data) { error in box.value = error; sem.signal() }
        _ = sem.wait(timeout: .now() + 5)
        return box.value
    }

    private func receiveSync(_ tunnel: DsseRuntimeCopyTunnelStream) -> Data? {
        let sem = DispatchSemaphore(value: 0)
        let box = DsseUnsafeBox<Data>()
        tunnel.receive { data, _ in box.value = data; sem.signal() }
        _ = sem.wait(timeout: .now() + 5)
        return box.value
    }
}

final class DsseUnsafeBox<T>: @unchecked Sendable {
    var value: T?
}
