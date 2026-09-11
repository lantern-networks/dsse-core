import Foundation

// DsseRegionEndpointPoller — the NE pulls the Edge's SIGNED region-endpoint list over the (T) mTLS transport it
// already uses, verifies it against the MDM-provisioned pinned key, and feeds the verified allowed-region
// endpoints to the region selector. It mirrors DsseAgentPolicyPoller exactly (same fetch/verify/cache discipline)
// but carries the region list instead of the steer-exclusion set.
//
// Fail-safe: a fetch/verify failure does NOT clear the current list (a transient Edge outage must never widen or
// drop the allowed set). Fail-closed: an unverifiable list is never applied. The agent always fetches from its
// CURRENT region's transport; on the first run the list is seeded from the MDM enrollment config.
public final class DsseRegionEndpointPoller: @unchecked Sendable {
    private let session: URLSession
    private let url: URL
    private let pinnedPublicKeyHex: String
    // acceptedKeys returns the adopted signing-key set (a CALLBACK, not a snapshot, because the set changes as
    // the device adopts bundles while the poller runs). Verifying against pin + adopted is what lets the region
    // list survive a signing-key rotation — the exact gap that left this poller Ed25519-only and single-key.
    private let acceptedKeys: () -> [String]
    private let cachePath: String?
    private let transportLock = NSLock()
    private var transport: DsseTransportSecurity?
    // Kept injectable so tests exercise the production request and verification path.
    var requestOverNW: (DsseTransportSecurity, String?, String) throws -> DsseSingleRequestOverNW.Response = { security, name, path in
        try DsseSingleRequestOverNW.get(host: security.host, port: security.port,
            serverName: name, path: path, security: security, timeout: 15)
    }
    private let queue = DispatchQueue(label: "dsse.region-endpoint-poller")
    private static let logLabel = "region-endpoint fetch"
    // --- fail-loud ------------------------------------------------------------------------------------------
    //
    // These fetches used to fail SILENTLY: one guard collapsed transport errors, non-200s, empty bodies and
    // signature-verification failures into `completion(nil)`, and the caller kept its previous state. That is
    // the right fail-SAFE behaviour and it was the wrong observability. On 2026-08-03 the Edge's policy-signing
    // key moved into the HSM and this device's pin was still the retired one, so EVERY verification failed —
    // for four days, with no region list and no admin exclusions, and not one line anywhere saying so. It was
    // found by noticing the Console showed a synthetic region name, not by any signal from the device.
    //
    // Logged on TRANSITION plus every tenth repeat: a poll loop that says nothing is how this hid, and one that
    // says the same thing every 30 seconds is how the next person learns to ignore it.
    private let failureLock = NSLock()
    private var consecutiveFailures = 0
    // Also recorded, not just logged: a log line proves the failure was ANNOUNCED, this proves it was
    // classified. Tests assert on it because asserting on os_log output would test the logger, not the poller.
    private var lastFailure: String?

    /// The reason the most recent fetch failed, or nil when the last fetch succeeded.
    var lastFailureReason: String? {
        failureLock.lock(); defer { failureLock.unlock() }
        return lastFailure
    }

    private func noteFetchOutcome(failure reason: String?) {
        failureLock.lock()
        defer { failureLock.unlock() }
        guard let reason else {
            if consecutiveFailures > 0 {
                dsseRuntimeLog("\(Self.logLabel) RECOVERED after \(consecutiveFailures) consecutive failure(s)")
                consecutiveFailures = 0
            }
            lastFailure = nil
            return
        }
        consecutiveFailures += 1
        lastFailure = reason
        if consecutiveFailures == 1 || consecutiveFailures % 10 == 0 {
            dsseRuntimeLog("\(Self.logLabel) FAILED (\(consecutiveFailures) consecutive): \(reason) — the device keeps its previous state, so nothing looks broken from here")
        }
    }

    private var timer: DispatchSourceTimer?
    private var onUpdate: ((DsseVerifiedRegionEndpoints) -> Void)?

    public static func regionEndpointsURL(security: DsseTransportSecurity, path: String = "/steer/region-endpoints") -> URL? {
        var p = path.trimmingCharacters(in: .whitespacesAndNewlines)
        if p.isEmpty { p = "/steer/region-endpoints" }
        if !p.hasPrefix("/") { p = "/" + p }
        return URL(string: "https://\(security.dialHost):\(security.port)\(p)")
    }

    public init?(security: DsseTransportSecurity, pinnedPublicKeyHex: String, cachePath: String?,
                 acceptedKeys: @escaping () -> [String] = { [] }) {
        let keyHex = pinnedPublicKeyHex.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !keyHex.isEmpty, let url = Self.regionEndpointsURL(security: security) else { return nil }
        self.session = DsseTransportTLS.makePinnedURLSession(security: security, channel: "region-endpoints")
        self.url = url
        self.pinnedPublicKeyHex = keyHex
        self.acceptedKeys = acceptedKeys
        self.cachePath = cachePath
        self.transport = security
    }

    // Test/seam initializer.
    public init(session: URLSession, url: URL, pinnedPublicKeyHex: String, cachePath: String? = nil,
                acceptedKeys: @escaping () -> [String] = { [] }) {
        self.session = session
        self.url = url
        self.pinnedPublicKeyHex = pinnedPublicKeyHex.trimmingCharacters(in: .whitespacesAndNewlines)
        self.acceptedKeys = acceptedKeys
        self.cachePath = cachePath
        self.transport = nil
    }

    /// Called only with the region selected from the verified list or signed install profile.
    /// Move the address while preserving all pinned anchors and the client identity.
    @discardableResult
    public func selectEndpoint(_ endpoint: URL) -> Bool {
        guard endpoint.scheme == "https", let host = endpoint.host, !host.isEmpty,
              endpoint.user == nil, endpoint.password == nil,
              (1...65535).contains(endpoint.port ?? 443) else { return false }
        transportLock.lock(); defer { transportLock.unlock() }
        guard let current = transport else { return false }
        transport = DsseTransportSecurity(host: host, port: endpoint.port ?? 443,
            mtlsRequired: current.mtlsRequired, pinnedCACertificates: current.pinnedCACertificates,
            clientIdentity: current.clientIdentity)
        return true
    }

    public func fetchVerifiedRegionEndpoints(completion: @escaping @Sendable (DsseVerifiedRegionEndpoints?) -> Void) {
        transportLock.lock()
        let currentTransport = transport
        transportLock.unlock()
        if let security = currentTransport {
            // URLSession cannot send tenant SNI independently of the dial address.
            // Read the adopted name for every request, including after rotation.
            let name = DsseLiveTransportServerName.current()
            do {
                let answer = try requestOverNW(security, name.isEmpty ? nil : name, url.path)
                completion(verifyResponse(status: answer.status, body: answer.body))
            } catch {
                noteFetchOutcome(failure: "transport (\(security.host):\(security.port), named \(name)): \(error.localizedDescription)")
                completion(nil)
            }
            return
        }
        var req = URLRequest(url: url)
        req.httpMethod = "GET"
        req.timeoutInterval = 15
        session.dataTask(with: req) { [weak self] data, resp, err in
            guard let self else { completion(nil); return }
            if let err {
                // ★★★ THE SENTENCE HAS TO NAME WHAT WENT WRONG (2026-08-30, after eight hours of it).
                // "transport: A TLS error caused the secure connection to fail." was the whole report, every
                // minute, for as long as this device had been running — and it cannot be acted on: a rejected
                // client certificate, a pinning failure, a name the certificate does not carry and an
                // unreachable host all say exactly that. The signed region list never arrived, region failover
                // ran on the install profile's seed the entire time, and the only other sign was this same
                // line ending in "nothing looks broken from here".
                //
                // The domain and code are what separate those cases, and the host is what says WHICH address
                // this device could not reach — a deployment has more than one.
                // ★ AND THE ERROR UNDERNEATH, which is the one that names the TLS alert. NSURLErrorDomain
                // -1200 is "the secure connection failed" and nothing more; the underlying NSOSStatusErrorDomain
                // code is the difference between a protocol-version refusal, a handshake failure and a peer
                // certificate the other side would not accept. Chasing this without it cost an afternoon.
                let ns = err as NSError
                let under = (ns.userInfo[NSUnderlyingErrorKey] as? NSError).map {
                    " under=\($0.domain)/\($0.code)"
                } ?? ""
                self.noteFetchOutcome(failure: "transport: \(err.localizedDescription) "
                    + "[domain=\(ns.domain) code=\(ns.code)\(under) host=\(self.url.host ?? "?"):\(self.url.port ?? 443)]")
                completion(nil); return
            }
            guard let http = resp as? HTTPURLResponse else {
                self.noteFetchOutcome(failure: "no HTTP response"); completion(nil); return
            }
            completion(self.verifyResponse(status: http.statusCode, body: data ?? Data()))
        }.resume()
    }

    private func verifyResponse(status: Int, body: Data) -> DsseVerifiedRegionEndpoints? {
        guard status == 200 else {
            noteFetchOutcome(failure: "HTTP \(status)"); return nil
        }
        guard !body.isEmpty else {
            noteFetchOutcome(failure: "empty body"); return nil
        }
        guard let verified = DsseSignedRegionEndpoints.verifiedRegionEndpoints(
                  envelopeData: body, pinnedPublicKeyHex: pinnedPublicKeyHex,
                  alsoAccept: acceptedKeys()) else {
            noteFetchOutcome(failure: "signature NOT verified against pin \(pinnedPublicKeyHex.prefix(12))… (+\(acceptedKeys().count) adopted key(s)) — the Edge is signing with a key this device does not accept")
            return nil
        }
        noteFetchOutcome(failure: nil)
        writeCache(body)
        return verified
    }

    public func start(interval: TimeInterval, onUpdate: @escaping (DsseVerifiedRegionEndpoints) -> Void) {
        self.onUpdate = onUpdate
        queue.async { [weak self] in
            guard let self else { return }
            self.pollOnce()
            let t = DispatchSource.makeTimerSource(queue: self.queue)
            t.schedule(deadline: .now() + interval, repeating: interval)
            t.setEventHandler { [weak self] in self?.pollOnce() }
            t.resume()
            self.timer = t
        }
    }

    public func stop() {
        queue.async { [weak self] in
            self?.timer?.cancel()
            self?.timer = nil
            self?.onUpdate = nil
        }
    }

    private func pollOnce() {
        fetchVerifiedRegionEndpoints { [weak self] verified in
            guard let self, let verified else { return } // fail-safe: keep the current list on error
            self.queue.async { self.onUpdate?(verified) }
        }
    }

    private func writeCache(_ data: Data) {
        guard let cachePath, !cachePath.isEmpty else { return }
        try? data.write(to: URL(fileURLWithPath: cachePath), options: .atomic)
    }
}
