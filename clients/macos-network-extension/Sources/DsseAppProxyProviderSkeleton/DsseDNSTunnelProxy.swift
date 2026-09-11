import Foundation
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
        var req = URLRequest(url: dnsURL)
        req.httpMethod = "POST"
        req.setValue("application/dns-message", forHTTPHeaderField: "content-type")
        req.httpBody = query
        session.dataTask(with: req) { data, resp, _ in
            guard let http = resp as? HTTPURLResponse, http.statusCode == 200, let data, !data.isEmpty else {
                completion(nil)
                return
            }
            completion(data)
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
