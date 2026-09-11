import Foundation

/// Small control messages use the same explicit SNI and mTLS identity as the data tunnel.
/// File downloads keep their streaming transport; do not send package bytes through this buffer.
final class DsseControlRequestTransport: @unchecked Sendable {
    typealias Completion = @Sendable (Data?, URLResponse?, Error?) -> Void
    typealias Request = @Sendable (URLRequest, DsseTransportSecurity, String?) throws -> DsseSingleRequestOverNW.Response
    private let lock = NSLock()
    private var security: DsseTransportSecurity
    private let request: Request
    private let queue = DispatchQueue(label: "dsse.control-request", attributes: .concurrent)

    init(security: DsseTransportSecurity, request: @escaping Request = { req, security, name in
        guard let url = req.url, let parts = URLComponents(url: url, resolvingAgainstBaseURL: false) else {
            throw DsseSingleRequestError.badEndpoint("missing control URL")
        }
        let path = parts.percentEncodedPath + (parts.percentEncodedQuery.map { "?" + $0 } ?? "")
        return try DsseSingleRequestOverNW.request(method: req.httpMethod ?? "GET", host: security.host,
            port: security.port, serverName: name, path: path, body: req.httpBody ?? Data(),
            security: security, timeout: req.timeoutInterval)
    }) {
        self.security = security
        self.request = request
    }

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

    func send(_ req: URLRequest, completion: @escaping Completion) {
        queue.async { [self] in
            lock.lock()
            let snapshot = security
            lock.unlock()
            do {
                let result = try request(req, snapshot, snapshot.controlServerName)
                guard let url = req.url, let response = HTTPURLResponse(url: url, statusCode: result.status,
                    httpVersion: "HTTP/1.1", headerFields: nil) else {
                    throw DsseSingleRequestError.unusable("invalid control response")
                }
                completion(result.body, response, nil)
            } catch {
                // No fallback to a DNS-derived SNI or a less strict trust policy on failure.
                completion(nil, nil, error)
            }
        }
    }
}
