import Foundation
import Security

// The half-duplex runtime-copy transport, dialled the way everything else on this device dials.
//
// ★★★ THE LAST URLSession ON THE STEERING PATH, AND IT COST A DARK MACHINE (2026-08-29, measured on a real
// Mac). Every steered flow failed with edgeTransportRequestFailed and the box carried nothing that was not
// excluded. The tunnel and the enrolment bootstrap had already been moved off URLSession, each for its own
// measured reason, and this one was left:
//
//   * App Transport Security judges by the SYSTEM trust store, not by the URLSession delegate. A deployment's
//     private transport CA is not in it, so the request is refused (-9802) BEFORE the pinning code that would
//     have accepted the certificate ever runs. That is exactly what the enrolment dial hit hours earlier.
//   * URLSession takes the TLS server name from the URL's host and offers no way to send another. On a folded
//     port the Edge picks which organization's certificate to serve BY that name, so a device dialling the
//     deployment-wide address is served the deployment-wide certificate while the tunnel beside it is served
//     its organization's — the defect that was already fixed for the agent-policy poller.
//
// Neither problem is visible in a test, and neither is visible on a lab Edge that happens to serve one
// certificate to everybody. Both are structural, and DsseSingleRequestOverNW is the answer this codebase has
// already arrived at twice: dial by address, prove by name, pin against what the profile provisioned.
public final class DsseNWRuntimeCopyHTTPClient: DsseInstrumentedEdgeRuntimeCopyHTTPClient, @unchecked Sendable {
    private let security: DsseTransportSecurity
    /// The name this organization's devices are told to send. Empty means "whatever the address is", which is
    /// the single-organization case and dials exactly as it always did.
    private let serverName: String?
    private let timeout: TimeInterval

    public init(transportSecurity: DsseTransportSecurity, serverName: String?, timeout: TimeInterval = 30) {
        self.security = transportSecurity
        let trimmed = serverName?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() ?? ""
        self.serverName = trimmed.isEmpty ? nil : trimmed
        self.timeout = timeout
    }

    public func perform(_ request: URLRequest) throws -> (Data, Int) {
        try perform(request, connectFamilyFallback: "unknown", progressHandler: nil)
    }

    public func perform(
        _ request: URLRequest,
        connectFamilyFallback: String,
        progressHandler: (@Sendable (DsseLiveRuntimeCopyProgress) -> Void)?
    ) throws -> (Data, Int) {
        guard let url = request.url, let host = url.host else {
            throw DsseLocalRuntimeCopyDriverError.invalidEdgeTransportConfiguration
        }
        let port = url.port ?? (url.scheme?.lowercased() == "http" ? 80 : 443)
        var path = url.path.isEmpty ? "/" : url.path
        if let q = url.query, !q.isEmpty { path += "?" + q }
        progressHandler?(.edgeRoundTripStarted)
        do {
            let response = try DsseSingleRequestOverNW.request(
                method: request.httpMethod ?? "POST", host: host, port: port,
                serverName: serverName ?? DsseLiveTransportServerName.current(),
                path: path, body: request.httpBody ?? Data(),
                security: security, timeout: timeout)
            progressHandler?(.edgeRoundTripRequestSent)
            progressHandler?(.edgeRoundTripCompleted)
            return (response.body, response.status)
        } catch {
            // Named, for the same reason every other failure on this path is: a device that steers and cannot
            // deliver is fail-closed by accident, and the operator's only way in is this line.
            // ★★ AND IT SAYS WHAT THE ERROR SAID (2026-08-29). Bridging a Swift enum to NSError and printing
            // localizedDescription discards the associated value — every failure on this path read
            // "DsseSingleRequestError error 1 / The operation couldn't be completed", which is the same line
            // for a refused connection, a timeout and an unparseable response. DsseSingleRequestError already
            // spells out which one it is; this asks it rather than Foundation.
            let nsError = error as NSError
            let reason = (error as? DsseSingleRequestError)?.description ?? nsError.localizedDescription
            dsseRuntimeLog("edge_round_trip_failed transport=nw url=\(host)\(path) " +
                           "server_name=\(serverName ?? DsseLiveTransportServerName.current()) " +
                           "domain=\(nsError.domain) code=\(nsError.code) reason=\(reason)")
            throw DsseLocalRuntimeCopyDriverError.edgeTransportRequestFailed
        }
    }
}
