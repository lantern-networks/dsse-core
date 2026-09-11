import Foundation
import Security
import XCTest
@testable import DsseAppProxyProviderSkeleton

final class DsseArtifactDownloadTests: XCTestCase {
    func testLivePinnedMTLSDownloadAndRefusals() throws {
        guard let path = ProcessInfo.processInfo.environment["DSSE_ARTIFACT_TLS_FIXTURE"] else {
            throw XCTSkip("set DSSE_ARTIFACT_TLS_FIXTURE to the private local TLS fixture directory")
        }
        let root = URL(fileURLWithPath: path)
        let portText = try String(contentsOf: root.appendingPathComponent("port"), encoding: .utf8)
        let port = try XCTUnwrap(Int(portText.trimmingCharacters(in: .whitespacesAndNewlines)))
        let ca = try XCTUnwrap(SecCertificateCreateWithData(nil, Data(contentsOf: root.appendingPathComponent("ca.der")) as CFData))
        let otherCA = try XCTUnwrap(SecCertificateCreateWithData(nil, Data(contentsOf: root.appendingPathComponent("other.der")) as CFData))
        let identity = try XCTUnwrap(DsseTransportSecurityFactory.clientIdentity(
            fromP12Data: Data(contentsOf: root.appendingPathComponent("client.p12")), passphrase: "fixture-only"))
        DsseLiveClientIdentity.setProvider { nil }
        DsseLiveTrustAnchors.setProvider { [] }
        DsseLiveTransportServerName.setProvider { "tenant.artifact.invalid" }
        defer { DsseLiveTransportServerName.setProvider { "" } }
        let security = DsseTransportSecurity(host: "127.0.0.1", port: port, mtlsRequired: true,
                                             pinnedCACertificates: [ca], clientIdentity: identity)
        var req = URLRequest(url: URL(string: "https://127.0.0.1:\(port)/artifact")!)
        req.httpMethod = "GET"
        req.timeoutInterval = 5
        let (file, response) = try DsseArtifactDownloadTransport.receive(req, security: security)
        defer { try? FileManager.default.removeItem(at: file) }
        XCTAssertEqual(response.statusCode, 200)
        XCTAssertEqual(response.value(forHTTPHeaderField: "X-Dsse-Agent-Update-Version"), "0.3.0+fixture")
        XCTAssertEqual(try Data(contentsOf: file), Data(repeating: 0xa5, count: 8 * 1024 * 1024))

        DsseLiveTransportServerName.setProvider { "wrong.artifact.invalid" }
        XCTAssertThrowsError(try DsseArtifactDownloadTransport.receive(req, security: security))
        DsseLiveTransportServerName.setProvider { "tenant.artifact.invalid" }
        let wrongTrust = DsseTransportSecurity(host: "127.0.0.1", port: port, mtlsRequired: true,
            pinnedCACertificates: [otherCA], clientIdentity: identity)
        XCTAssertThrowsError(try DsseArtifactDownloadTransport.receive(req, security: wrongTrust))
        let anonymous = DsseTransportSecurity(host: "127.0.0.1", port: port, mtlsRequired: true,
            pinnedCACertificates: [ca], clientIdentity: nil)
        XCTAssertThrowsError(try DsseArtifactDownloadTransport.receive(req, security: anonymous))
        req.url = URL(string: "https://127.0.0.1:\(port)/truncated")!
        XCTAssertThrowsError(try DsseArtifactDownloadTransport.receive(req, security: security))
    }

    func testLargeContentLengthStreamsWithoutRetainingPackage() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appendingPathComponent("artifact")
        FileManager.default.createFile(atPath: url.path, contents: nil)
        let file = try FileHandle(forWritingTo: url)
        defer { try? file.close() }
        let chunk = Data(repeating: 0xa5, count: 65_536)
        let size = chunk.count * 128
        let decoder = DsseArtifactHTTPDecoder { try file.write(contentsOf: $0) }
        try decoder.append(Data("HTTP/1.1 200 OK\r\nContent-Length: \(size)\r\nX-Dsse-Agent-Update-Version: 0.3.0+test\r\n\r\n".utf8))
        for _ in 0..<128 {
            try decoder.append(chunk)
            XCTAssertEqual(decoder.bufferedBytes, 0)
        }
        try decoder.endOfStream()
        try file.synchronize()
        XCTAssertTrue(decoder.complete)
        XCTAssertEqual(decoder.written, size)
        XCTAssertEqual(decoder.headers["x-dsse-agent-update-version"], "0.3.0+test")
        XCTAssertEqual(try Data(contentsOf: url), Data(repeating: 0xa5, count: size))
    }

    func testChunkedAcrossEveryByteBoundary() throws {
        let raw = Data("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3;extension=x\r\nabc\r\n2\r\nde\r\n0\r\nX-End: yes\r\n\r\n".utf8)
        for width in 1...raw.count {
            var body = Data()
            let decoder = DsseArtifactHTTPDecoder { body.append($0) }
            for start in stride(from: 0, to: raw.count, by: width) {
                try decoder.append(raw.subdata(in: start..<min(start + width, raw.count)))
            }
            try decoder.endOfStream()
            XCTAssertEqual(body, Data("abcde".utf8), "width=\(width)")
            XCTAssertTrue(decoder.complete)
        }
    }

    func testTruncationAndAmbiguousFramingAreRejected() {
        for raw in [
            "HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nshort",
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nlong",
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\nok",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 2\r\n\r\nok",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nab",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabcXX0\r\n\r\n",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nextra",
            "HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 9999999999999999999999999\r\n\r\n",
        ] {
            XCTAssertThrowsError(try {
                let decoder = DsseArtifactHTTPDecoder { _ in }
                try decoder.append(Data(raw.utf8))
                try decoder.endOfStream()
            }(), raw)
        }
    }

    func testCloseDelimitedAndBodyLimit() throws {
        var body = Data()
        let decoder = DsseArtifactHTTPDecoder(maximumBody: 4) { body.append($0) }
        try decoder.append(Data("HTTP/1.1 404 Not Found\r\n\r\nnone".utf8))
        XCTAssertFalse(decoder.complete)
        try decoder.endOfStream()
        XCTAssertTrue(decoder.complete)
        XCTAssertEqual(decoder.status, 404)
        XCTAssertEqual(body, Data("none".utf8))
        let limited = DsseArtifactHTTPDecoder(maximumBody: 4) { _ in }
        XCTAssertThrowsError(try limited.append(Data("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n".utf8)))
        let chunked = DsseArtifactHTTPDecoder(maximumBody: 4) { _ in }
        XCTAssertThrowsError(try chunked.append(Data("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\n".utf8)))
        let unbounded = DsseArtifactHTTPDecoder(maximumBody: 4) { _ in }
        XCTAssertThrowsError(try unbounded.append(Data("HTTP/1.1 200 OK\r\n\r\n12345".utf8)))
    }

    func testSinkFailureDoesNotCompleteDownload() throws {
        let decoder = DsseArtifactHTTPDecoder { _ in throw CocoaError(.fileWriteOutOfSpace) }
        XCTAssertThrowsError(try decoder.append(Data("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc".utf8)))
        XCTAssertFalse(decoder.complete)
        XCTAssertEqual(decoder.written, 0)
    }
}
