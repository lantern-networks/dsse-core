import Foundation
import Network
import Security

/// One HTTPS request over NWConnection, for the case URLSession cannot serve: sending a TLS server name that
/// differs from the address dialled.
///
/// ★★★ WHY THIS EXISTS (the enrolment fold, 2026-08-19). An agent must reach an Edge on ONE port. The expired-certificate
/// renewal path is a second listener today because it has to accept a certificate that has already expired, and
/// the main transport must never be relaxed that way. The Edge now serves that path on the main port for a
/// NAME it announces — but a renewal request went out over URLSession, which sends the URL's host as the server
/// name and offers no way to send another. Dialling the main port without the name reaches the ordinary
/// listener, which demands a valid certificate: exactly what a recovering device does not have.
///
/// So this is deliberately small and deliberately not a general HTTP client. One request, one response,
/// Connection: close, no redirects, no reuse. It exists to carry a JSON POST whose whole security rests on the
/// TLS layer built by makeTunnelParameters — the same identity, the same pinned anchors, the same fail-closed
/// verify block as every other connection this agent makes.
public enum DsseSingleRequestOverNW {
    public struct Response {
        public let status: Int
        public let body: Data
    }

    /// post sends one request and returns the response, or throws.
    ///
    /// serverName is what goes in the ClientHello and in the Host header. When nil the address is used, which
    /// is what every other caller wants and is why this parameter is explicit rather than inferred.
    public static func post(host: String, port: Int, serverName: String?, path: String, body: Data,
                            security: DsseTransportSecurity, timeout: TimeInterval,
                            presentClientIdentity: Bool = true) throws -> Response {
        try request(method: "POST", host: host, port: port, serverName: serverName, path: path,
                    body: body, security: security, timeout: timeout,
                    presentClientIdentity: presentClientIdentity)
    }

    /// get sends one GET and returns the response, or throws.
    ///
    /// ★ ADDED 2026-08-22, and the reason is the same one that put this file here. The agent-policy poller —
    /// which both FETCHES this device's policy and REPORTS what it is enforcing — went over URLSession, which
    /// sends the URL's host as the server name and offers no way to send another. So the one channel every
    /// readiness gate is measured from was dialling this Edge WITHOUT its organization's name, landing on the
    /// deployment-wide certificate while the tunnel beside it was served the organization's own. The moment
    /// that organization's shared anchor was withdrawn — which is the last step of roadmap D, and the thing
    /// the fold exists to make safe — this device stopped being able to report at all, and said nothing.
    public static func get(host: String, port: Int, serverName: String?, path: String,
                           security: DsseTransportSecurity, timeout: TimeInterval,
                           identityOverride: SecIdentity? = nil) throws -> Response {
        try request(method: "GET", host: host, port: port, serverName: serverName, path: path,
                    body: Data(), security: security, timeout: timeout, identityOverride: identityOverride)
    }

    public static func request(method: String, host: String, port: Int, serverName: String?, path: String,
                               body: Data, security: DsseTransportSecurity, timeout: TimeInterval,
                               identityOverride: SecIdentity? = nil,
                               presentClientIdentity: Bool = true) throws -> Response {
        guard let nwPort = NWEndpoint.Port(rawValue: UInt16(port)) else {
            throw DsseSingleRequestError.badEndpoint("port \(port)")
        }
        let parameters = DsseTransportTLS.makeTunnelParameters(security: security, serverNameOverride: serverName,
                                                              identityOverride: identityOverride,
                                                              presentClientIdentity: presentClientIdentity)
        let connection = NWConnection(host: NWEndpoint.Host(host), port: nwPort, using: parameters)
        let queue = DispatchQueue(label: "dsse.single-request")

        let hostHeader = serverName ?? host
        // Built by hand rather than from a multi-line literal: a stray newline in a request line is a protocol
        // error that surfaces as an unexplained hang, and this path runs on a device that is already locked out.
        // A GET carries no body and must not announce a Content-Type it does not have; everything else about
        // the request — the TLS beneath it above all — is identical, because two ways of building this
        // connection would be two security postures.
        var head = "\(method) \(path) HTTP/1.1\r\nHost: \(hostHeader)\r\n"
        if !body.isEmpty {
            head += "Content-Type: application/json\r\nContent-Length: \(body.count)\r\n"
        }
        head += "Connection: close\r\n\r\n"
        var requestBytes = Data(head.utf8)
        requestBytes.append(body)
        let request = requestBytes

        // A small box, because the completion handlers run on the connection's queue and Swift concurrency is
        // right to refuse shared mutable captures. The semaphore is what the caller waits on.
        final class Outcome: @unchecked Sendable {
            let lock = NSLock()
            var received = Data()
            var failure: Error?
            let done = DispatchSemaphore(value: 0)
            var finished = false
            func append(_ d: Data) { lock.lock(); received.append(d); lock.unlock() }
            func finish(_ error: Error?) {
                lock.lock()
                if !finished {
                    finished = true
                    if failure == nil { failure = error }
                    lock.unlock()
                    done.signal()
                    return
                }
                lock.unlock()
            }
        }
        let outcome = Outcome()

        connection.stateUpdateHandler = { state in
            switch state {
            case .ready:
                connection.send(content: request, completion: .contentProcessed { sendError in
                    if let sendError {
                        outcome.finish(DsseSingleRequestError.transport("send: \(sendError)"))
                        return
                    }
                    func readMore() {
                        connection.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) { chunk, _, isComplete, receiveError in
                            if let chunk, !chunk.isEmpty { outcome.append(chunk) }
                            if let receiveError {
                                outcome.finish(DsseSingleRequestError.transport("receive: \(receiveError)"))
                                return
                            }
                            // Connection: close, so the server closing IS the end of the body. Reading to
                            // completion rather than trusting a length keeps this small and correct for a
                            // chunked answer too.
                            if isComplete { outcome.finish(nil); return }
                            readMore()
                        }
                    }
                    readMore()
                })
            case .failed(let error):
                outcome.finish(DsseSingleRequestError.transport("connection failed: \(error)"))
            case .waiting(let error):
                // ★★ A REJECTED HANDSHAKE ARRIVES HERE, NOT IN .failed (2026-08-19, measured against the live
                // Edge). NWConnection treats "cannot proceed right now" as something to RETRY, so a refusal —
                // the pin saying no, or the Edge refusing an anonymous caller on the recovery path — left this
                // waiting until the timeout and reported "timed out after 15s". That is the wrong sentence
                // twice over: it hides the reason, and it costs a locked-out device the full timeout on every
                // attempt while telling its operator nothing.
                //
                // There is nothing to retry for a one-shot request whose failure is a decision, so this is
                // terminal and it carries the reason.
                outcome.finish(DsseSingleRequestError.transport("refused: \(error)"))
            case .cancelled:
                outcome.finish(DsseSingleRequestError.transport("connection cancelled"))
            default:
                break
            }
        }
        connection.start(queue: queue)
        if outcome.done.wait(timeout: .now() + timeout) == .timedOut {
            connection.cancel()
            throw DsseSingleRequestError.transport("timed out after \(Int(timeout))s")
        }
        connection.cancel()
        if let failure = outcome.failure { throw failure }
        return try parse(outcome.received)
    }

    /// parse splits the status line and the body. Deliberately strict: an answer this cannot read is reported
    /// as unusable rather than guessed at, because the caller is about to install a certificate from it.
    static func parse(_ raw: Data) throws -> Response {
        guard let separator = raw.range(of: Data("\r\n\r\n".utf8)) else {
            throw DsseSingleRequestError.unusable("no header/body separator in \(raw.count) bytes")
        }
        let headerData = raw.subdata(in: raw.startIndex..<separator.lowerBound)
        let body = raw.subdata(in: separator.upperBound..<raw.endIndex)
        guard let headerText = String(data: headerData, encoding: .utf8),
              let statusLine = headerText.split(separator: "\r\n", omittingEmptySubsequences: false).first else {
            throw DsseSingleRequestError.unusable("unreadable headers")
        }
        let parts = statusLine.split(separator: " ")
        guard parts.count >= 2, let status = Int(parts[1]) else {
            throw DsseSingleRequestError.unusable("no status in \"\(statusLine)\"")
        }
        // Chunked bodies: the Edge answers these with Content-Length, but a proxy in between may not, and a
        // silently-truncated JSON body would surface as "response carried no cert_pem" — a message that sends
        // the reader to the server. Decoded here so the failure names the real thing.
        if headerText.lowercased().contains("transfer-encoding: chunked") {
            return Response(status: status, body: try dechunk(body))
        }
        return Response(status: status, body: body)
    }

    static func dechunk(_ body: Data) throws -> Data {
        var out = Data()
        var rest = body
        while true {
            guard let lineEnd = rest.range(of: Data("\r\n".utf8)) else { break }
            let sizeText = String(data: rest.subdata(in: rest.startIndex..<lineEnd.lowerBound), encoding: .utf8) ?? ""
            let size = Int(sizeText.split(separator: ";").first.map(String.init) ?? "", radix: 16) ?? -1
            if size < 0 { throw DsseSingleRequestError.unusable("bad chunk size \"\(sizeText)\"") }
            if size == 0 { break }
            let chunkStart = lineEnd.upperBound
            let chunkEnd = rest.index(chunkStart, offsetBy: size, limitedBy: rest.endIndex) ?? rest.endIndex
            out.append(rest.subdata(in: chunkStart..<chunkEnd))
            let afterChunk = rest.index(chunkEnd, offsetBy: 2, limitedBy: rest.endIndex) ?? rest.endIndex
            rest = rest.subdata(in: afterChunk..<rest.endIndex)
        }
        return out
    }
}

public enum DsseSingleRequestError: Error, CustomStringConvertible {
    case badEndpoint(String)
    case transport(String)
    case unusable(String)

    public var description: String {
        switch self {
        case .badEndpoint(let s): return "endpoint unusable: \(s)"
        case .transport(let s): return "transport: \(s)"
        case .unusable(let s): return "response unusable: \(s)"
        }
    }
}
