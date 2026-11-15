import Foundation
import Network
import Darwin

//  W4 (NE side, DNS): the user-space DNS proxy. The endpoint's system resolver is pointed at this
// local listener; each DNS query is forwarded to the Edge over the (T) ENCRYPTED tunnel via
// POST /steer/dns-query (pinned + mTLS), and only the Edge resolves it. So the queried domain never
// appears in plaintext on the endpoint / local network (the DNS form of steer-all). Mirrors the Windows
// agent's steer_dns.go (). NEAppProxyUDPFlow can't read per-datagram ports at handleNewFlow, so
// DNS is handled here in user space rather than in the NE flow path.

public final class DsseDNSTunnelProxy: @unchecked Sendable {
    private let session: URLSession
    private let dnsURL: URL
    private let queue = DispatchQueue(label: "dsse.dns-tunnel-proxy")
    private var fd: Int32 = -1
    private var source: DispatchSourceRead?

    // dnsTunnelURL composes the /steer/dns-query URL from the transport host/port + path.
    public static func dnsTunnelURL(security: DsseTransportSecurity, dnsOverTunnelPath: String) -> URL? {
        var path = dnsOverTunnelPath.trimmingCharacters(in: .whitespacesAndNewlines)
        if path.isEmpty { path = "/steer/dns-query" }
        if !path.hasPrefix("/") { path = "/" + path }
        return URL(string: "https://\(security.dialHost):\(security.port)\(path)")
    }

    public init?(security: DsseTransportSecurity, dnsOverTunnelPath: String = "/steer/dns-query") {
        guard let url = Self.dnsTunnelURL(security: security, dnsOverTunnelPath: dnsOverTunnelPath) else { return nil }
        self.session = DsseTransportTLS.makePinnedURLSession(security: security, channel: "dns-over-tunnel")
        self.dnsURL = url
    }

    // Test/seam initializer: inject the session + URL directly.
    public init(session: URLSession, dnsURL: URL) {
        self.session = session
        self.dnsURL = dnsURL
    }

    // forwardQuery POSTs a raw DNS query (application/dns-message) to the Edge over the (T) tunnel and
    // returns the raw DNS response, or nil on failure (the caller drops the datagram — fail closed).
    public func forwardQuery(_ query: Data, completion: @escaping @Sendable (Data?) -> Void) {
        forwardQuery(query) { response, _ in completion(response) }
    }

    // forwardQuery with the reason a query went unanswered: "http_<status>", "error_<domain>_<code>" or "empty".
    // Non-secret by construction: a status code or an error domain and code, never a URL, name or body.
    public func forwardQuery(_ query: Data, outcome: @escaping @Sendable (Data?, String) -> Void) {
        var req = URLRequest(url: dnsURL)
        req.httpMethod = "POST"
        req.setValue("application/dns-message", forHTTPHeaderField: "content-type")
        req.httpBody = query
        session.dataTask(with: req) { data, resp, error in
            if let error {
                let ns = error as NSError
                outcome(nil, "error_\(ns.domain)_\(ns.code)")
                return
            }
            guard let http = resp as? HTTPURLResponse else {
                outcome(nil, "no_http_response")
                return
            }
            guard http.statusCode == 200 else {
                outcome(nil, "http_\(http.statusCode)")
                return
            }
            guard let data, !data.isEmpty else {
                outcome(nil, "empty")
                return
            }
            outcome(data, "ok")
        }.resume()
    }

    // start binds a UDP socket (DNS) on listenHost:listenPort and serves until stop(). Point the system
    // resolver here (e.g. 127.0.0.1) so all DNS rides the tunnel. Uses a plain POSIX UDP socket
    // (recvfrom -> forward over the tunnel -> sendto) — the classic, reliable DNS-proxy pattern.
    public func start(listenHost: String = "127.0.0.1", listenPort: UInt16 = 53) throws {
        let s = socket(AF_INET, SOCK_DGRAM, 0)
        guard s >= 0 else { throw NSError(domain: "DsseDNSTunnelProxy", code: Int(errno), userInfo: [NSLocalizedDescriptionKey: "socket"]) }
        var on: Int32 = 1
        setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, socklen_t(MemoryLayout<Int32>.size))
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = listenPort.bigEndian
        addr.sin_addr.s_addr = inet_addr(listenHost)
        let bound = withUnsafePointer(to: &addr) { p in
            p.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(s, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
        guard bound == 0 else { let e = errno; close(s); throw NSError(domain: "DsseDNSTunnelProxy", code: Int(e), userInfo: [NSLocalizedDescriptionKey: "bind"]) }
        fd = s
        let src = DispatchSource.makeReadSource(fileDescriptor: s, queue: queue)
        src.setEventHandler { [weak self] in self?.readOne() }
        source = src
        src.resume()
    }

    public func stop() {
        source?.cancel()
        source = nil
        if fd >= 0 { close(fd); fd = -1 }
    }

    private func readOne() {
        var buf = [UInt8](repeating: 0, count: 4096)
        var from = sockaddr_storage()
        var fromLen = socklen_t(MemoryLayout<sockaddr_storage>.size)
        let n = withUnsafeMutablePointer(to: &from) { fp in
            fp.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                recvfrom(fd, &buf, buf.count, 0, sa, &fromLen)
            }
        }
        guard n > 0 else { return }
        let query = Data(buf[0..<n])
        // Copy the client address bytes so the async completion can reply with sendto (sockaddr is not Sendable).
        let addrData = withUnsafePointer(to: &from) { Data(bytes: $0, count: Int(fromLen)) }
        let sock = fd
        forwardQuery(query) { resp in
            guard let resp, sock >= 0 else { return }
            addrData.withUnsafeBytes { (ab: UnsafeRawBufferPointer) in
                guard let sa = ab.bindMemory(to: sockaddr.self).baseAddress else { return }
                _ = resp.withUnsafeBytes { rb in
                    sendto(sock, rb.baseAddress, resp.count, 0, sa, socklen_t(addrData.count))
                }
            }
        }
    }
}

/// DNS queries to the Edge over NWConnection, built by makeTunnelParameters like the device's tunnel: the same
/// identity, the same pinned anchors, the organization's transport name in the ClientHello.
///
/// Not URLSession. On macOS a URLSession over TLS 1.3 never surfaces the Edge's request for the device's
/// certificate, completes the handshake presenting none, and the Edge refuses it — measured on the first Mac
/// to run the DNS proxy: every query failed NSURLErrorDomain -1200 and the Edge counted none.
///
/// And not a connection per query. A Mac asks for names in bursts — at start-up, on a network change, when a
/// browser opens — and a TLS handshake per name starved itself: 80 lookups at once, almost none answered
/// within their five seconds, on a Mac whose Edge answered each in 12 ms. Queries share a few connections that
/// stay open; each carries one request at a time and the next waits its turn.
public final class DsseDNSOverNWForwarder: @unchecked Sendable {
    private let channels: [DsseDNSKeptConnection]
    private let lock = NSLock()
    private var next = 0

    public init(security: DsseTransportSecurity, dnsOverTunnelPath: String = "/steer/dns-query", timeout: TimeInterval = 5,
                connections: Int = 4) {
        var p = dnsOverTunnelPath.trimmingCharacters(in: .whitespacesAndNewlines)
        if p.isEmpty { p = "/steer/dns-query" }
        if !p.hasPrefix("/") { p = "/" + p }
        channels = (0..<max(1, connections)).map { _ in
            DsseDNSKeptConnection(security: security, path: p, timeout: timeout)
        }
    }

    /// outcome receives the answer, or nil and a non-secret reason: "http_<status>", "error_<what>" or "empty".
    public func forwardQuery(_ query: Data, outcome: @escaping @Sendable (Data?, String) -> Void) {
        lock.lock()
        let channel = channels[next % channels.count]
        next = (next + 1) % channels.count
        lock.unlock()
        channel.submit(query, outcome: outcome)
    }

    public func close() {
        for c in channels { c.close() }
    }
}

/// One kept-open HTTP/1.1 connection to the Edge carrying DNS queries one after another.
final class DsseDNSKeptConnection: @unchecked Sendable {
    private struct Job {
        let query: Data
        let outcome: @Sendable (Data?, String) -> Void
        var attempts = 0
    }

    private let security: DsseTransportSecurity
    private let path: String
    private let timeout: TimeInterval
    private let queue = DispatchQueue(label: "dsse.dns-kept-connection")
    private var connection: NWConnection?
    private var ready = false
    private var carried = 0              // requests answered on the current connection
    private var pending: [Job] = []
    private var busy = false
    private var generation = 0
    private var buffer = Data()
    private var connectWaiter: ((Bool) -> Void)?

    init(security: DsseTransportSecurity, path: String, timeout: TimeInterval) {
        self.security = security
        self.path = path
        self.timeout = timeout
    }

    func submit(_ query: Data, outcome: @escaping @Sendable (Data?, String) -> Void) {
        queue.async {
            self.pending.append(Job(query: query, outcome: outcome))
            self.pump()
        }
    }

    func close() {
        queue.async { self.drop() }
    }

    private func pump() {
        guard !busy, !pending.isEmpty else { return }
        busy = true
        generation += 1
        let gen = generation
        queue.asyncAfter(deadline: .now() + timeout) { [weak self] in
            guard let self, self.busy, self.generation == gen else { return }
            self.finish(nil, "error_timed_out_after_\(Int(self.timeout))s", retryable: false)
        }
        connect(gen) { [weak self] ok in
            guard let self, self.busy, self.generation == gen else { return }
            guard ok else { self.finish(nil, "error_connect", retryable: false); return }
            self.send(gen)
        }
    }

    private func answerConnect(_ ok: Bool) {
        let waiter = connectWaiter
        connectWaiter = nil
        waiter?(ok)
    }

    private func connect(_ gen: Int, _ done: @escaping (Bool) -> Void) {
        if let connection, ready, connection.state == .ready { done(true); return }
        drop()
        guard security.port > 0, security.port <= Int(UInt16.max), let port = NWEndpoint.Port(rawValue: UInt16(security.port)) else {
            done(false); return
        }
        connectWaiter = done
        let parameters = DsseTransportTLS.makeTunnelParameters(security: security, serverNameOverride: security.controlServerName)
        let c = NWConnection(host: NWEndpoint.Host(security.host), port: port, using: parameters)
        connection = c
        c.stateUpdateHandler = { [weak self, weak c] state in
            guard let self, let c, self.connection === c else { return }
            switch state {
            case .ready:
                self.ready = true
                self.answerConnect(true)
            case .failed, .cancelled, .waiting:
                self.ready = false
                self.connection = nil
                c.cancel()
                if self.connectWaiter != nil { self.answerConnect(false) }
                else if self.busy { self.finish(nil, "error_connection_lost", retryable: self.buffer.isEmpty) }
            default:
                break
            }
        }
        c.start(queue: queue)
    }

    private func send(_ gen: Int) {
        guard let c = connection, let job = pending.first else { finish(nil, "error_connect", retryable: false); return }
        let hostHeader = security.controlServerName ?? security.host
        var request = Data(("POST \(path) HTTP/1.1\r\nHost: \(hostHeader)\r\nContent-Type: application/dns-message\r\n"
            + "Content-Length: \(job.query.count)\r\n\r\n").utf8)
        request.append(job.query)
        buffer = Data()
        c.send(content: request, completion: .contentProcessed { [weak self] error in
            guard let self, self.busy, self.generation == gen else { return }
            if error != nil { self.finish(nil, "error_send", retryable: true); return }
            self.receive(c, gen)
        })
    }

    private func receive(_ c: NWConnection, _ gen: Int) {
        c.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, isComplete, error in
            guard let self, self.busy, self.generation == gen else { return }
            if let data, !data.isEmpty { self.buffer.append(data) }
            switch Self.parse(self.buffer) {
            case .answer(let status, let body, let keepAlive):
                if !keepAlive { self.drop() }
                if status != 200 { self.finish(nil, "http_\(status)", retryable: false) }
                else if body.isEmpty { self.finish(nil, "empty", retryable: false) }
                else { self.finish(body, "ok", retryable: false) }
            case .malformed:
                self.finish(nil, "error_response_unusable", retryable: false)
            case .incomplete:
                if error != nil || isComplete { self.finish(nil, "error_connection_closed", retryable: self.buffer.isEmpty) }
                else { self.receive(c, gen) }
            }
        }
    }

    /// retryable: the failure came from the connection, before any byte of an answer. A connection the Edge
    /// closed while it sat idle fails exactly this way on its next use, so the query is sent once more on a
    /// fresh one instead of being answered SERVFAIL for the Edge's housekeeping.
    private func finish(_ answer: Data?, _ reason: String, retryable: Bool) {
        guard busy, !pending.isEmpty else { return }
        generation += 1
        busy = false
        if answer == nil {
            let reused = carried > 0
            drop()
            if retryable, reused, pending[0].attempts == 0 {
                pending[0].attempts = 1
                pump()
                return
            }
        } else {
            carried += 1
        }
        let job = pending.removeFirst()
        job.outcome(answer, reason)
        pump()
    }

    private func drop() {
        ready = false
        carried = 0
        connectWaiter = nil
        if let c = connection {
            connection = nil
            c.stateUpdateHandler = nil
            c.cancel()
        }
    }

    enum Parsed: Equatable {
        case incomplete
        case malformed
        case answer(status: Int, body: Data, keepAlive: Bool)
    }

    /// One HTTP/1.1 response with a Content-Length, as the Edge writes a DNS answer. Anything else is malformed:
    /// this is not a general HTTP client, and guessing where a response ends would hand one query another's answer.
    static func parse(_ raw: Data) -> Parsed {
        guard let headEnd = raw.range(of: Data("\r\n\r\n".utf8)) else {
            return raw.count > 16384 ? .malformed : .incomplete
        }
        guard let head = String(data: raw[raw.startIndex..<headEnd.lowerBound], encoding: .utf8) else { return .malformed }
        let lines = head.components(separatedBy: "\r\n")
        let statusParts = lines[0].split(separator: " ")
        guard statusParts.count >= 2, statusParts[0].hasPrefix("HTTP/1."), let status = Int(statusParts[1]) else { return .malformed }
        var length: Int?
        var keepAlive = true
        for line in lines.dropFirst() {
            guard let colon = line.firstIndex(of: ":") else { continue }
            let name = line[line.startIndex..<colon].trimmingCharacters(in: .whitespaces).lowercased()
            let value = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            if name == "content-length" { length = Int(value) }
            if name == "connection", value.lowercased() == "close" { keepAlive = false }
            if name == "transfer-encoding" { return .malformed }
        }
        guard let length, length >= 0, length <= 65535 + 1024 else { return .malformed }
        let bodyStart = headEnd.upperBound
        let have = raw.endIndex - bodyStart
        if have < length { return .incomplete }
        if have > length { return .malformed }
        return .answer(status: status, body: Data(raw[bodyStart..<raw.endIndex]), keepAlive: keepAlive)
    }
}
