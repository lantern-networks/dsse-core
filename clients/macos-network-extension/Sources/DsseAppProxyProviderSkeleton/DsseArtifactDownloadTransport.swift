import Foundation
import Network

/// Package downloads use explicit tenant SNI and the tunnel's pinned mTLS identity.
/// The response is decoded into a private temporary file, never a package-sized Data buffer.
final class DsseArtifactDownloadTransport: @unchecked Sendable {
    typealias Completion = @Sendable (URL?, URLResponse?, Error?) -> Void
    private let lock = NSLock()
    private var security: DsseTransportSecurity
    private let worker = DispatchQueue(label: "dsse.artifact-download")

    init(security: DsseTransportSecurity) { self.security = security }

    func selectEndpoint(_ endpoint: URL) {
        guard endpoint.scheme == "https", let host = endpoint.host, !host.isEmpty,
              endpoint.user == nil, endpoint.password == nil,
              (1...65535).contains(endpoint.port ?? 443) else { return }
        lock.lock()
        security = DsseTransportSecurity(host: host, port: endpoint.port ?? 443,
            mtlsRequired: security.mtlsRequired, pinnedCACertificates: security.pinnedCACertificates,
            clientIdentity: security.clientIdentity)
        lock.unlock()
    }

    func download(_ request: URLRequest, completion: @escaping Completion) {
        worker.async { [self] in
            lock.lock()
            let snapshot = security
            lock.unlock()
            do {
                let result = try Self.receive(request, security: snapshot)
                // The completion may atomically move this file into staging. Otherwise only this
                // temporary file is removed; an existing staged package is never touched on failure.
                defer { try? FileManager.default.removeItem(at: result.0) }
                completion(result.0, result.1, nil)
            } catch { completion(nil, nil, error) }
        }
    }

    static func receive(_ request: URLRequest, security: DsseTransportSecurity) throws -> (URL, HTTPURLResponse) {
        guard request.httpMethod == "GET", let url = request.url,
              let parts = URLComponents(url: url, resolvingAgainstBaseURL: false),
              (1...65535).contains(security.port),
              let port = NWEndpoint.Port(rawValue: UInt16(security.port)) else {
            throw DsseSingleRequestError.badEndpoint("invalid artifact request")
        }
        let path = parts.percentEncodedPath + (parts.percentEncodedQuery.map { "?" + $0 } ?? "")
        let name = security.controlServerName ?? security.host
        guard !path.contains("\r"), !path.contains("\n"), !name.contains("\r"), !name.contains("\n") else {
            throw DsseSingleRequestError.badEndpoint("invalid artifact authority or path")
        }
        let temporary = FileManager.default.temporaryDirectory.appendingPathComponent("dsse-artifact-" + UUID().uuidString)
        guard FileManager.default.createFile(atPath: temporary.path, contents: nil,
                                             attributes: [.posixPermissions: 0o600]) else {
            throw DsseSingleRequestError.unusable("cannot create artifact temporary file")
        }
        var keep = false
        defer { if !keep { try? FileManager.default.removeItem(at: temporary) } }
        let file = try FileHandle(forWritingTo: temporary)
        defer { try? file.close() }
        let decoder = DsseArtifactHTTPDecoder { try file.write(contentsOf: $0) }
        let connection = NWConnection(host: NWEndpoint.Host(security.host), port: port,
            using: DsseTransportTLS.makeTunnelParameters(security: security,
                                                        serverNameOverride: security.controlServerName))
        let queue = DispatchQueue(label: "dsse.artifact-connection")
        final class Outcome: @unchecked Sendable {
            var finished = false
            var failure: Error?
            let done = DispatchSemaphore(value: 0)
            func finish(_ error: Error?) {
                guard !finished else { return }
                finished = true
                failure = error
                done.signal()
            }
        }
        let outcome = Outcome() // All state below is confined to queue.
        let bytes = Data("GET \(path) HTTP/1.1\r\nHost: \(name)\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n".utf8)
        connection.stateUpdateHandler = { state in
            guard !outcome.finished else { return }
            switch state {
            case .ready:
                connection.send(content: bytes, completion: .contentProcessed { error in
                    if let error { outcome.finish(error); return }
                    @Sendable func readMore() {
                        connection.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) { data, _, eof, error in
                            guard !outcome.finished else { return }
                            do {
                                if let error { throw error }
                                if let data { try decoder.append(data) }
                                if eof { try decoder.endOfStream() }
                                if decoder.complete { outcome.finish(nil); return }
                                readMore()
                            } catch { outcome.finish(error) }
                        }
                    }
                    readMore()
                })
            case .failed(let error), .waiting(let error): outcome.finish(error)
            case .cancelled: outcome.finish(DsseSingleRequestError.transport("artifact connection cancelled"))
            default: break
            }
        }
        connection.start(queue: queue)
        let timedOut = outcome.done.wait(timeout: .now() + request.timeoutInterval) == .timedOut
        // Drain callbacks before closing/removing the file, including on timeout.
        let failure: Error? = queue.sync {
            if timedOut { outcome.finish(DsseSingleRequestError.transport("artifact download timed out")) }
            connection.cancel()
            return outcome.failure
        }
        if let failure { throw failure }
        guard decoder.complete, let response = HTTPURLResponse(url: url, statusCode: decoder.status,
            httpVersion: "HTTP/1.1", headerFields: decoder.headers) else {
            throw DsseSingleRequestError.unusable("incomplete artifact response")
        }
        try file.synchronize()
        keep = true
        return (temporary, response)
    }
}

/// Incremental HTTP/1 response framing. Rejects ambiguous lengths and truncated chunks.
/// Only headers/chunk framing are buffered; body pieces go straight to the sink.
final class DsseArtifactHTTPDecoder: @unchecked Sendable {
    private let sink: (Data) throws -> Void
    private let maximumBody: Int
    private var buffer = Data()
    private var remaining: Int?
    private var chunkRemaining: Int?
    private var chunked = false
    private var chunkCRLF = false
    private var trailers = false
    private var trailerBytes = 0
    private(set) var status = 0
    private(set) var headers: [String: String] = [:]
    private(set) var complete = false
    private(set) var written = 0
    var bufferedBytes: Int { buffer.count }

    init(maximumBody: Int = 2 * 1024 * 1024 * 1024, sink: @escaping (Data) throws -> Void) {
        self.maximumBody = maximumBody
        self.sink = sink
    }

    private func reject(_ reason: String) -> DsseSingleRequestError { .unusable("artifact: " + reason) }

    func append(_ data: Data) throws {
        if complete {
            guard data.isEmpty else { throw reject("bytes after response") }
            return
        }
        buffer.append(data)
        if status == 0 {
            guard let end = buffer.range(of: Data("\r\n\r\n".utf8)) else {
                if buffer.count > 65_536 { throw reject("oversized headers") }
                return
            }
            guard end.lowerBound - buffer.startIndex <= 65_536,
                  let text = String(data: buffer[..<end.lowerBound], encoding: .utf8) else {
                throw reject("invalid headers")
            }
            let lines = text.components(separatedBy: "\r\n")
            let first = lines[0].split(separator: " ")
            guard first.count >= 2, ["HTTP/1.0", "HTTP/1.1"].contains(String(first[0])),
                  let code = Int(first[1]), (200...599).contains(code) else { throw reject("invalid status") }
            status = code
            for line in lines.dropFirst() {
                guard let colon = line.firstIndex(of: ":"), colon != line.startIndex,
                      !line.hasPrefix(" "), !line.hasPrefix("\t") else { throw reject("malformed header") }
                let key = line[..<colon].lowercased()
                let value = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
                if headers[key] != nil && ["content-length", "transfer-encoding"].contains(key) {
                    throw reject("duplicate framing header")
                }
                headers[key] = value
            }
            if let encoding = headers["content-encoding"], encoding.lowercased() != "identity" {
                throw reject("unsupported content encoding")
            }
            if let transfer = headers["transfer-encoding"] {
                guard transfer.lowercased() == "chunked", headers["content-length"] == nil else {
                    throw reject("ambiguous transfer framing")
                }
                chunked = true
            } else if let length = headers["content-length"] {
                guard !length.isEmpty, length.utf8.allSatisfy({ (48...57).contains($0) }),
                      let count = Int(length), count <= maximumBody else { throw reject("invalid content length") }
                remaining = count
            }
            buffer = Data(buffer[end.upperBound...])
            if status == 204 || status == 304 { remaining = 0; chunked = false }
        }
        if !chunked {
            if let remaining, buffer.count > remaining { throw reject("body exceeds content length") }
            let count = buffer.count
            try write(buffer)
            buffer.removeAll(keepingCapacity: true)
            if remaining != nil { remaining! -= count; complete = remaining == 0 }
            return
        }
        while true {
            if trailers {
                guard let line = try takeLine() else { return }
                trailerBytes += line.utf8.count + 2
                guard trailerBytes <= 65_536 else { throw reject("oversized trailers") }
                if line.isEmpty {
                    guard buffer.isEmpty else { throw reject("bytes after chunks") }
                    complete = true
                    return
                }
                guard line.contains(":") else { throw reject("invalid trailer") }
            } else if chunkCRLF {
                guard buffer.count >= 2 else { return }
                guard buffer.prefix(2) == Data("\r\n".utf8) else { throw reject("missing chunk terminator") }
                buffer = Data(buffer.dropFirst(2))
                chunkCRLF = false
            } else if let count = chunkRemaining {
                let take = min(count, buffer.count)
                if take == 0 { return }
                try write(Data(buffer.prefix(take)))
                buffer = Data(buffer.dropFirst(take))
                chunkRemaining = count - take
                if chunkRemaining == 0 { chunkRemaining = nil; chunkCRLF = true }
            } else {
                guard let line = try takeLine() else { return }
                let size = line.split(separator: ";", omittingEmptySubsequences: false)[0]
                guard !size.isEmpty, size.utf8.allSatisfy({ (48...57).contains($0) || (65...70).contains($0) || (97...102).contains($0) }),
                      let count = Int(size, radix: 16), count <= maximumBody - written else { throw reject("invalid chunk size") }
                if count == 0 { trailers = true } else { chunkRemaining = count }
            }
        }
    }

    private func takeLine() throws -> String? {
        guard let end = buffer.range(of: Data("\r\n".utf8)) else {
            if buffer.count > 8192 { throw reject("oversized chunk line") }
            return nil
        }
        guard end.lowerBound - buffer.startIndex <= 8192,
              let line = String(data: buffer[..<end.lowerBound], encoding: .utf8) else { throw reject("invalid chunk line") }
        buffer = Data(buffer[end.upperBound...])
        return line
    }

    private func write(_ data: Data) throws {
        guard data.count <= maximumBody - written else { throw reject("body exceeds download limit") }
        try sink(data)
        written += data.count
    }

    func endOfStream() throws {
        guard status != 0 else { throw reject("missing response headers") }
        if chunked || remaining != nil {
            guard complete else { throw reject("truncated body") }
        } else { complete = true }
    }
}
