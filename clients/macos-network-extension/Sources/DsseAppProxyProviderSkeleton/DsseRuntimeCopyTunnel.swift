import Foundation
import Network
import os

// TEMP flow diagnostics: query with `log show --predicate 'subsystem == "dsse.ne.flowdiag"' --info`.
// Records which leg of a flow copy fails (flow_read / tunnel_send / tunnel_receive / flow_write / idle_reap)
// plus byte counts, to pin down the Amazon-Haul intermittent flow reset. Remove once diagnosed.
let dsseFlowDiagLogger = Logger(subsystem: "dsse.ne.flowdiag", category: "flow")

// Full-duplex runtime-copy tunnel client (NE side).
//
// The session/round-trip transports are half-duplex HTTP exchanges (write the
// upstream chunk, then block reading the downstream behind polling waits), which
// serializes real TLS+HTTP and makes browser SPAs stall. This opens a raw TCP
// connection to the Edge runtime-copy tunnel endpoint, performs a one-shot
// HTTP/1.1 upgrade handshake ("200 Connection Established"), then exposes the
// connection as an opaque bidirectional byte stream so the driver can copy the
// flow's bytes in both directions concurrently.
//

public enum DsseRuntimeCopyTunnelError: Error, Equatable {
    case invalidEdgeAuthority
    case handshakeFailed(String)
    case connectionFailed(String)
    case closed
}

public protocol DsseRuntimeCopyTunnelStream: AnyObject, Sendable {
    func send(_ data: Data, completion: @escaping @Sendable (Error?) -> Void)
    func receive(completion: @escaping @Sendable (Data?, Error?) -> Void)
    func close()
}

// Opens the tunnel for a flow given its routing metadata.
public protocol DsseTunnelLocalRuntimeCopyTransport: DsseLocalRuntimeCopyTransport {
    var runtimeCopyTunnelEnabled: Bool { get }
    func openTunnel(
        metadata: DsseLocalRuntimeCopyMetadata,
        completion: @escaping @Sendable (Result<DsseRuntimeCopyTunnelStream, Error>) -> Void
    )
}

public final class DsseRuntimeCopyTunnel: DsseRuntimeCopyTunnelStream, @unchecked Sendable {
    public static let tunnelEndpointPath = "/network-extension/runtime-copy/tunnel"
    public static let tenantHeader = "X-Dsse-Ne-Tunnel-Tenant"
    public static let hostHeader = "X-Dsse-Ne-Tunnel-Host"
    public static let portHeader = "X-Dsse-Ne-Tunnel-Port"
    // Match the Windows WFP steer agent's edge protocol so Edge<->NE and Edge<->WFP are IDENTICAL.
    public static let connectAuthorityHeader = "x-dsse-connect-authority"
    // Shared concurrent queue for ALL tunnels (see open()): avoids ~80 per-flow serial queues exhausting GCD.
    static let sharedQueue = DispatchQueue(label: "dsse.runtime-copy-tunnel.shared", qos: .userInitiated, attributes: .concurrent)

    private let connection: NWConnection
    private let queue: DispatchQueue
    private let lock = NSLock()
    private var pendingDownstream = Data()
    private var closed = false

    private init(connection: NWConnection, queue: DispatchQueue) {
        self.connection = connection
        self.queue = queue
    }

    // Connects to the Edge tunnel endpoint and completes once the
    // "200 Connection Established" handshake succeeds.
    public static func open(
        edgeHost: String,
        edgePort: Int,
        tunnelPath: String,
        tenantID: String,
        destinationHost: String,
        destinationPort: Int,
        tlsSecurity: DsseTransportSecurity? = nil,
        completion: @escaping @Sendable (Result<DsseRuntimeCopyTunnel, Error>) -> Void
    ) {
        let trimmedHost = edgeHost.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedHost.isEmpty, edgePort > 0, edgePort <= 65535,
              let port = NWEndpoint.Port(rawValue: UInt16(edgePort)) else {
            completion(.failure(DsseRuntimeCopyTunnelError.invalidEdgeAuthority))
            return
        }
        // ONE shared CONCURRENT queue for every tunnel (not a per-flow serial queue): a heavy page opens ~80
        // flows at once, and ~80 distinct serial DispatchQueues each holding a thread while their NWConnection
        // callback blocks exhausts GCD's thread pool -> some flows' pumps stall -> the interception handshake
        // stalls (partial ClientHello). Go's WFP agent uses goroutines (no such limit). A single concurrent
        // queue lets GCD schedule all flows without one-thread-per-flow. Per-flow ordering is preserved because
        // each pump step runs in the completion of the previous (and shared state is lock-guarded).
        let queue = DsseRuntimeCopyTunnel.sharedQueue
        //  W4: when the (T) transport contract is present, dial over TLS (server-cert pinned, +mTLS
        // device identity). Default (nil security) keeps the legacy plaintext TCP dial unchanged.
        // TCP_NODELAY: disable Nagle / delayed ACK. The tunnel exchanges smallish chunks, so
        // with Nagle on each chunk takes ~40-190ms extra latency and per-flow throughput
        // drops to a few hundred KB/s (a real Google sign-in JS bundle fails to load and crashes).
        let parameters: NWParameters
        if let tlsSecurity {
            parameters = DsseTransportTLS.makeTunnelParameters(security: tlsSecurity)
        } else {
            let tcpOptions = NWProtocolTCP.Options()
            tcpOptions.noDelay = true
            parameters = NWParameters(tls: nil, tcp: tcpOptions)
        }
        let connection = NWConnection(host: NWEndpoint.Host(trimmedHost), port: port, using: parameters)
        let tunnel = DsseRuntimeCopyTunnel(connection: connection, queue: queue)

        let request = Self.handshakeRequest(
            tunnelPath: tunnelPath,
            edgeHost: trimmedHost,
            tenantID: tenantID,
            destinationHost: destinationHost,
            destinationPort: destinationPort
        )
        let completed = DsseAtomicFlag()
        connection.stateUpdateHandler = { state in
            switch state {
            case .ready:
                connection.send(content: request, completion: .contentProcessed { error in
                    if let error {
                        if completed.set() { completion(.failure(DsseRuntimeCopyTunnelError.connectionFailed("\(error)"))) }
                        connection.cancel()
                        return
                    }
                    tunnel.readHandshakeResponse(accumulated: Data()) { result in
                        guard completed.set() else { return }
                        switch result {
                        case .success:
                            completion(.success(tunnel))
                        case .failure(let err):
                            connection.cancel()
                            completion(.failure(err))
                        }
                    }
                })
            case .failed(let error):
                if completed.set() { completion(.failure(DsseRuntimeCopyTunnelError.connectionFailed("\(error)"))) }
                connection.cancel()
            case .cancelled:
                if completed.set() { completion(.failure(DsseRuntimeCopyTunnelError.closed)) }
            default:
                break
            }
        }
        connection.start(queue: queue)
    }

    private static func handshakeRequest(
        tunnelPath: String,
        edgeHost: String,
        tenantID: String,
        destinationHost: String,
        destinationPort: Int
    ) -> Data {
        // Identical wire protocol to the Windows WFP steer agent: CONNECT /steer + x-dsse-connect-authority.
        _ = tunnelPath
        _ = tenantID
        // IPv6 literals MUST be bracketed in an authority (host:port) or the Edge cannot separate the address
        // from the port (2001:db8::1:443 is ambiguous). Windows gets this free via netip.AddrPort.String();
        // without it every IPv6 destination (Google/Gmail, CloudFront/Amazon) fails tunnel_open with non-200
        // while IPv4 sites (Yahoo) work.
        let authority: String
        if destinationHost.contains(":") && !destinationHost.hasPrefix("[") {
            authority = "[\(destinationHost)]:\(destinationPort)"
        } else {
            authority = "\(destinationHost):\(destinationPort)"
        }
        let lines = [
            "CONNECT /steer HTTP/1.1",
            "Host: \(edgeHost)",
            "\(connectAuthorityHeader): \(authority)",
            "",
            ""
        ]
        return Data(lines.joined(separator: "\r\n").utf8)
    }

    // Reads the HTTP response headers, verifies a 2xx status, and buffers any
    // bytes that arrive after the header terminator as the first tunnel payload.
    private func readHandshakeResponse(
        accumulated: Data,
        completion: @escaping @Sendable (Result<Void, Error>) -> Void
    ) {
        let terminator = Data("\r\n\r\n".utf8)
        if let range = accumulated.range(of: terminator) {
            let header = accumulated.subdata(in: accumulated.startIndex..<range.lowerBound)
            let leftover = accumulated.subdata(in: range.upperBound..<accumulated.endIndex)
            guard let statusLine = String(data: header, encoding: .utf8)?
                .split(separator: "\r\n", omittingEmptySubsequences: true).first,
                  statusLine.contains(" 200 ") || statusLine.hasSuffix(" 200") else {
                let firstLine = String(data: header, encoding: .utf8)?
                    .split(separator: "\r\n", omittingEmptySubsequences: true).first.map(String.init) ?? "unparseable"
                dsseRuntimeLog("runtime_copy_tunnel handshake_failed reason=non_200_status status_line=\(firstLine)")
                completion(.failure(DsseRuntimeCopyTunnelError.handshakeFailed("non_200_status")))
                return
            }
            if !leftover.isEmpty {
                lock.lock(); pendingDownstream.append(leftover); lock.unlock()
            }
            completion(.success(()))
            return
        }
        if accumulated.count > 16 * 1024 {
            dsseRuntimeLog("runtime_copy_tunnel handshake_failed reason=header_too_large")
            completion(.failure(DsseRuntimeCopyTunnelError.handshakeFailed("header_too_large")))
            return
        }
        connection.receive(minimumIncompleteLength: 1, maximumLength: 8 * 1024) { [weak self] data, _, isComplete, error in
            guard let self else { return }
            if let error {
                dsseRuntimeLog("runtime_copy_tunnel handshake_failed reason=transport_error error=\(error)")
                completion(.failure(DsseRuntimeCopyTunnelError.handshakeFailed("\(error)")))
                return
            }
            var next = accumulated
            if let data, !data.isEmpty { next.append(data) }
            if isComplete && next.range(of: terminator) == nil {
                dsseRuntimeLog("runtime_copy_tunnel handshake_failed reason=closed_before_headers bytes_seen=\(next.count)")
                completion(.failure(DsseRuntimeCopyTunnelError.handshakeFailed("closed_before_headers")))
                return
            }
            self.readHandshakeResponse(accumulated: next, completion: completion)
        }
    }

    public func send(_ data: Data, completion: @escaping @Sendable (Error?) -> Void) {
        connection.send(content: data, completion: .contentProcessed { error in
            completion(error)
        })
    }

    public func receive(completion: @escaping @Sendable (Data?, Error?) -> Void) {
        lock.lock()
        if !pendingDownstream.isEmpty {
            let buffered = pendingDownstream
            pendingDownstream.removeAll(keepingCapacity: false)
            lock.unlock()
            completion(buffered, nil)
            return
        }
        lock.unlock()
        connection.receive(minimumIncompleteLength: 1, maximumLength: 1024 * 1024) { data, _, isComplete, error in
            if let error {
                completion(nil, error)
                return
            }
            if let data, !data.isEmpty {
                completion(data, nil)
                return
            }
            if isComplete {
                completion(nil, nil) // EOF
                return
            }
            completion(Data(), nil)
        }
    }

    public func close() {
        lock.lock()
        if closed { lock.unlock(); return }
        closed = true
        lock.unlock()
        connection.cancel()
    }
}

final class DsseAtomicFlag: @unchecked Sendable {
    private let lock = NSLock()
    private var value = false
    // Returns true exactly once (the first caller); false afterwards.
    func set() -> Bool {
        lock.lock(); defer { lock.unlock() }
        if value { return false }
        value = true
        return true
    }
}

// Full-duplex copy loop: pumps the flow's bytes to the tunnel and the tunnel's
// bytes to the flow in two independent callback chains, with no per-exchange
// synchronization. Either side reaching EOF (Connection: close / TLS close_notify)
// completes the copy; any error fails it. This replaces the half-duplex session
// exchange loop for real browser traffic.
final class DsseLiveRuntimeCopyTunnelLoop: @unchecked Sendable {
    private let flow: any DsseProviderTCPFlowCopyIO
    private let requestID: String
    private let tunnel: any DsseRuntimeCopyTunnelStream
    private let liveGuard: DsseLiveRuntimeCopyGuard
    private let emitProgress: @Sendable (DsseLiveRuntimeCopyProgress) -> Void
    private let makeSuccessResult: @Sendable (Int, Int) -> DsseLocalRuntimeCopyResult
    private let closeGuardAndFlow: @Sendable (Error?) -> Void
    private let completionHandler: @Sendable (Result<DsseLocalRuntimeCopyResult, Error>) -> Void

    private let lock = NSLock()
    private var bytesUp = 0
    private var bytesDown = 0
    private var finished = false
    // Half-close bookkeeping. The browser→Edge (upstream) direction reaching EOF means the browser finished
    // SENDING its request — NOT that the flow is over: the Edge→browser (downstream) direction may still be
    // delivering the response the Edge already produced. Tearing the whole flow down on upstream EOF sent a mux
    // CLOSE that dropped the Edge's in-flight HTTP/2 responses (e.g. amazon.co.jp/haul プチプラ getAsins →
    // net::ERR_FAILED → skeleton). So upstream EOF now HALF-closes (stop reading upstream, keep downstream), and
    // the flow finishes only when downstream EOFs, either side errors, or the idle reaper fires. This is the
    // NE-side mirror of the Edge's bufferedPipeConn.CloseWrite fix.
    private var upstreamEOF = false
    private var downstreamEOF = false


    // Active idle reaper to prevent connection leaks. Even when the browser closes a flow, the OS may not
    // deliver EOF to the provider's pending read; in that case finish() never runs and the NE->Edge tunnel
    // connection lingers (leaks) -> the NE hits its concurrent-connection limit and errors. A flow with no
    // bytes in either direction for idleReapThreshold is actively torn down to keep the limit.
    private var lastActivityAt = Date()
    private let idleReapThreshold: TimeInterval
    private let idleReapQueue = DispatchQueue(label: "dsse.tunnel-idle-reaper")
    private var idleTimer: DispatchSourceTimer?

    // Default 120s (override with DSSE_NE_FLOW_IDLE_REAP_SECONDS, <=0 disables). SSE/long-poll
    // heartbeats are usually <120s so false reaps are unlikely. Shorter = a tighter leak bound.
    static var defaultIdleReapThreshold: TimeInterval {
        if let raw = ProcessInfo.processInfo.environment["DSSE_NE_FLOW_IDLE_REAP_SECONDS"],
           let parsed = TimeInterval(raw) {
            return parsed
        }
        return 120
    }

    // LOAD-AWARE idle reaping (the robustness cure): each live flow parks a dedicated pump thread; a browser's
    // pooled keep-alive connections accumulate idle-but-not-reaped flows -> thread/scheduler pressure that
    // starves new-flow opens (docs/ne_tunnel_robustness_rootcause.md). So when the concurrent-flow count is high
    // we reap idle flows MUCH sooner (bounding the accumulation), and at normal load we keep the full 120s window
    // (don't break keep-alive reuse or SSE heartbeats). An early reap is safe: finishIdleReap() closes cleanly
    // (FIN), so the browser just reopens. Overridable for tests/tuning.
    static var highLoadFlowWatermark: Int {
        if let raw = ProcessInfo.processInfo.environment["DSSE_NE_HIGH_LOAD_FLOW_WATERMARK"], let n = Int(raw) { return n }
        return 128
    }
    static var highLoadIdleReapThreshold: TimeInterval {
        if let raw = ProcessInfo.processInfo.environment["DSSE_NE_HIGH_LOAD_IDLE_REAP_SECONDS"], let n = TimeInterval(raw) { return n }
        return 20
    }

    // Grace after the upstream (request) direction half-closes, for the downstream (response) direction to drain
    // the Edge's in-flight response before the flow is torn down. Bounds a half-closed flow's linger (and its one
    // remaining pump thread) to this instead of the 120 s idle reaper. Override with DSSE_NE_UPSTREAM_EOF_DRAIN_SECONDS.
    static var upstreamEOFDrainGrace: TimeInterval {
        if let raw = ProcessInfo.processInfo.environment["DSSE_NE_UPSTREAM_EOF_DRAIN_SECONDS"],
           let parsed = TimeInterval(raw), parsed >= 0 {
            return parsed
        }
        return 5
    }

    init(
        flow: any DsseProviderTCPFlowCopyIO,
        requestID: String,
        tunnel: any DsseRuntimeCopyTunnelStream,
        liveGuard: DsseLiveRuntimeCopyGuard,
        emitProgress: @escaping @Sendable (DsseLiveRuntimeCopyProgress) -> Void,
        makeSuccessResult: @escaping @Sendable (Int, Int) -> DsseLocalRuntimeCopyResult,
        closeGuardAndFlow: @escaping @Sendable (Error?) -> Void,
        completionHandler: @escaping @Sendable (Result<DsseLocalRuntimeCopyResult, Error>) -> Void,
        idleReapThreshold: TimeInterval = DsseLiveRuntimeCopyTunnelLoop.defaultIdleReapThreshold
    ) {
        self.flow = flow
        self.requestID = requestID
        self.tunnel = tunnel
        self.liveGuard = liveGuard
        self.emitProgress = emitProgress
        self.makeSuccessResult = makeSuccessResult
        self.closeGuardAndFlow = closeGuardAndFlow
        self.completionHandler = completionHandler
        self.idleReapThreshold = idleReapThreshold
    }

    func run() {
        emitProgress(.liveCopyStarted)
        startIdleReaper()
        // Full-duplex like the Windows WFP agent's two io.Copy goroutines: a DEDICATED thread per direction
        // running a BLOCKING read->write loop, instead of an async callback pump that stalls under a browser's
        // concurrent-flow burst (the async NWConnection/flow callbacks contend on GCD and the TLS handshake's
        // ServerHello<->Finished exchange doesn't complete). Each thread mostly blocks (cheap); the callbacks it
        // waits on run on GCD, a different execution context, so the blocking waits never deadlock the callbacks.
        let upThread = Thread { [self] in self.copyUpstream() }
        upThread.stackSize = 512 * 1024
        upThread.name = "dsse.copy.up"
        upThread.start()
        let downThread = Thread { [self] in self.copyDownstream() }
        downThread.stackSize = 512 * 1024
        downThread.name = "dsse.copy.down"
        downThread.start()
    }

    private func touchActivity() {
        lock.lock()
        lastActivityAt = Date()
        lock.unlock()
    }

    private func startIdleReaper() {
        guard idleReapThreshold > 0 else { return }
        // Poll often enough to honor the SHORT (high-load) threshold, not just the full window.
        let interval = max(5.0, min(idleReapThreshold, Self.highLoadIdleReapThreshold) / 2)
        let timer = DispatchSource.makeTimerSource(queue: idleReapQueue)
        timer.schedule(deadline: .now() + interval, repeating: interval)
        timer.setEventHandler { [weak self] in self?.reapIfIdle() }
        lock.lock()
        idleTimer = timer
        lock.unlock()
        timer.resume()
    }

    private func reapIfIdle() {
        lock.lock()
        if finished {
            lock.unlock()
            return
        }
        let idleFor = Date().timeIntervalSince(lastActivityAt)
        lock.unlock()
        // Load-aware: under a high concurrent-flow count reap idle flows sooner to bound the per-idle-flow thread
        // accumulation; at normal load keep the full window so keep-alive reuse / SSE heartbeats are not broken.
        var threshold = idleReapThreshold
        if liveGuard.activeCount >= Self.highLoadFlowWatermark {
            threshold = min(idleReapThreshold, Self.highLoadIdleReapThreshold)
        }
        if idleFor >= threshold {
            // No bytes in either direction for the (load-aware) threshold. This catches BOTH a genuinely dead/stuck flow
            // (the OS abandoned it) AND a still-live keep-alive connection sitting idle in the browser's pool.
            // We cannot tell them apart at the TCP layer, so reap CLEANLY (FIN) — exactly how an HTTP server
            // recycles an idle keep-alive connection: the browser drops it from its pool and opens a fresh one
            // for the next request. The old error-close (RST) made the browser's NEXT reused request fail
            // "flow is not connected" (ERR_FAILED) — worst on POSTs, which browsers do not retry. See
            // docs/ne_tunnel_robustness_rootcause.md.
            dsseFlowDiagLogger.error("leg=idle_reap fail req=\(self.requestID, privacy: .public) up=\(self.bytesUp) down=\(self.bytesDown) idleFor=\(Int(idleFor))s")
            finishReason("idle_reap:\(Int(idleFor))s")
            finishIdleReap()
        }
    }

    // Idle-reap teardown that closes the flow CLEANLY (nil error = FIN) so a reused keep-alive connection
    // degrades to a graceful reopen instead of an ERR_FAILED. Still reports the idle-timeout result so the
    // driver's metrics/logging are unchanged. Mirrors finish() but forces the clean close regardless of result.
    private func finishIdleReap() {
        lock.lock()
        if finished {
            lock.unlock()
            return
        }
        finished = true
        lock.unlock()
        cancelIdleReaper()
        tunnel.close()
        closeGuardAndFlow(nil)
        completionHandler(.failure(DsseLocalRuntimeCopyDriverError.runtimeCopyIdleTimeoutExceeded))
    }

    private func cancelIdleReaper() {
        lock.lock()
        let timer = idleTimer
        idleTimer = nil
        lock.unlock()
        timer?.cancel()
    }

    // After the upstream half-closes, close the flow once the downstream has been IDLE for the grace window —
    // i.e. the Edge's in-flight response has drained. Activity-based (not a fixed deadline) so a slow or large
    // still-delivering response is NOT truncated; it keeps rescheduling while bytes flow. A no-op once finished
    // (downstream EOF / error / idle reaper got there first). SSE/long-poll never reach here (upstream stays open).
    private func scheduleUpstreamEOFDrainFinish() {
        let grace = max(1.0, DsseLiveRuntimeCopyTunnelLoop.upstreamEOFDrainGrace)
        idleReapQueue.asyncAfter(deadline: .now() + grace) { [weak self] in
            guard let self, !self.isFinished else { return }
            self.lock.lock()
            let idleFor = Date().timeIntervalSince(self.lastActivityAt)
            self.lock.unlock()
            if idleFor >= grace {
                Self.neDiag("grace_finish req=\(self.requestID) idleFor=\(Int(idleFor))")
                self.finishOnEOF()
            } else {
                self.scheduleUpstreamEOFDrainFinish()
            }
        }
    }

    // The upstream (browser->Edge / request) direction ended — by clean EOF (browser finished sending) OR a
    // flow read error (browser reset/closed its send side; or an abandon after the flow already finished). Either
    // way this is NOT a reason to tear down the flow: the Edge may still be delivering the in-flight response on
    // the downstream. HALF-CLOSE — stop reading upstream, keep downstream alive, and let the downstream EOF/error
    // or the bounded post-EOF drain finish the flow. CRITICAL for HTTP/2 over the mux: if the NE instead sent a
    // mux CLOSE here, the Edge's h2 server would see read-EOF and CANCEL the in-flight upstream forwards (still
    // waiting on the origin) before their responses were produced -> getAsins/acp responses dropped -> amazon
    // Haul プチプラ skeleton. So the NE must NEVER close the flow just because the request direction ended.
    private func handleUpstreamEnd(_ reason: String) {
        lock.lock()
        upstreamEOF = true
        let downAlreadyDone = downstreamEOF
        lock.unlock()
        // Acknowledge the app's send-side half-close by closing ONLY the read side (nil error = clean). Apple's
        // NEAppProxyTCPFlow needs this to settle into a proper half-open state; without it the flow was reported
        // "not connected" on the very next write, so the pending HTTP/2 response could not be delivered and the
        // browser's read side was reset ("Error 2 reading from socket") -> abandoned stream -> Haul skeleton.
        // We do NOT closeWrite — the response direction must stay open.
        flow.closeReadForCopy(error: nil)
        Self.neDiag("up_end req=\(requestID) reason=\(reason) up=\(bytesUp) down=\(bytesDown) downDone=\(downAlreadyDone)")
        if downAlreadyDone {
            finishOnEOF()
        } else {
            scheduleUpstreamEOFDrainFinish()
        }
    }

    // copyUpstream: browser flow -> Edge tunnel, a blocking read->send loop (io.Copy).
    private func copyUpstream() {
        while true {
            let (data, readError) = blockingFlowRead()
            if let readError {
                dsseFlowDiagLogger.error("leg=flow_read fail req=\(self.requestID, privacy: .public) up=\(self.bytesUp) down=\(self.bytesDown) err=\(String(describing: readError), privacy: .public)")
                handleUpstreamEnd("readerr:\(readError)")
                return
            }
            guard let data, !data.isEmpty else {
                // Clean EOF: the browser half-closed its send side (done sending requests) but keeps its RECEIVE
                // side open for the pending HTTP/2 responses. HALF-CLOSE, do NOT tear the flow down — acknowledge
                // the read-close and let copyDownstream keep delivering; the flow finishes on downstream EOF /
                // write error / the bounded post-EOF drain.
                //
                // KNOWN macOS PLATFORM LIMITATION (measured, not fixable here): once the app half-closes its send
                // side, NEAppProxyTCPFlow's WRITE side dies a few KB later ("flow is not connected") EVEN THOUGH
                // the browser's receive is still open — verified that neither keeping readData armed NOR
                // closeReadWithError(nil) (Apple's documented half-open ack) keeps it writable. Windows/WFP uses a
                // real socket (half-open works) so it never hit this. So the LAST in-flight stream on a connection
                // whose response arrives AFTER this half-close is dropped. The residual Amazon Haul skeleton is
                // therefore latency-driven: the browser-mimic egress TTFB to amazon is ~1.2 s (full TLS handshake
                // per upstream connection, no session resumption — fidelity #14), so responses land after the
                // half-close. The real lever left is cutting that egress latency (TLS resumption / connection
                // reuse), NOT the flow pump. We still keep the flow alive here so responses that DO arrive before
                // the write dies are delivered (took the common case from ~always-skeleton to mostly-rendered).
                lock.lock()
                let already = upstreamEOF
                upstreamEOF = true
                lock.unlock()
                if !already {
                    flow.closeReadForCopy(error: nil)
                    Self.neDiag("up_eof req=\(requestID) up=\(bytesUp) down=\(bytesDown)")
                    scheduleUpstreamEOFDrainFinish()
                }
                return
            }
            do {
                try liveGuard.recordUpstreamBytes(requestID: requestID, count: data.count)
            } catch {
                finishReason("up_guard:\(error)")
                finish(.failure(error))
                return
            }
            touchActivity()
            lock.lock(); bytesUp += data.count; lock.unlock()
            emitProgress(.upstreamReadCompleted(bytes: data.count))
            if let sendError = blockingTunnelSend(data) {
                dsseFlowDiagLogger.error("leg=tunnel_send fail req=\(self.requestID, privacy: .public) up=\(self.bytesUp) down=\(self.bytesDown) err=\(String(describing: sendError), privacy: .public)")
                finishReason("up_senderr:\(sendError)")
                finish(.failure(sendError))
                return
            }
        }
    }

    // copyDownstream: Edge tunnel -> browser flow, a blocking receive->write loop (io.Copy). Writes to the flow
    // are serial by construction (one at a time in this loop), which NEAppProxyTCPFlow requires.
    private func copyDownstream() {
        while true {
            let (data, receiveError) = blockingTunnelReceive()
            if let receiveError {
                dsseFlowDiagLogger.error("leg=tunnel_receive fail req=\(self.requestID, privacy: .public) up=\(self.bytesUp) down=\(self.bytesDown) err=\(String(describing: receiveError), privacy: .public)")
                finishReason("down_recverr:\(receiveError)")
                finish(.failure(receiveError))
                return
            }
            guard let data, !data.isEmpty else {
                // Downstream (response) EOF is the natural end of the flow: the Edge closed the tunnel after the
                // response completed. Finish now (this also tears down a flow whose upstream already half-closed).
                lock.lock(); downstreamEOF = true; lock.unlock()
                Self.neDiag("down_eof req=\(requestID) up=\(bytesUp) down=\(bytesDown)")
                finishOnEOF()
                return
            }
            touchActivity()
            lock.lock(); bytesDown += data.count; lock.unlock()
            emitProgress(.downstreamWriteStarted)
            if let writeError = blockingFlowWrite(data) {
                dsseFlowDiagLogger.error("leg=flow_write fail req=\(self.requestID, privacy: .public) up=\(self.bytesUp) down=\(self.bytesDown) err=\(String(describing: writeError), privacy: .public)")
                finishReason("down_writeerr:\(writeError)")
                finish(.failure(writeError))
                return
            }
            emitProgress(.downstreamWriteCompleted)
        }
    }

    // Blocking wrappers over the async flow/tunnel APIs. The completion runs on GCD (a different thread than the
    // dedicated copy thread that waits here), so there is no self-deadlock. Results land in a Sendable box (not a
    // captured var) to satisfy strict-concurrency; the semaphore gives the happens-before for the read.
    private final class ResultBox<T>: @unchecked Sendable {
        var value: T
        init(_ v: T) { value = v }
    }

    private var isFinished: Bool {
        lock.lock(); defer { lock.unlock() }; return finished
    }

    // Wait for the callback, but wake every few seconds to ABANDON the wait once the loop has finished. Without
    // this, a pending flow read / tunnel receive that the OS never completes (e.g. NEAppProxyTCPFlow does not
    // fire a pending readData completion when the flow is closed — see the idle-reaper note) parks this dedicated
    // thread forever = one leaked thread per flow that degrades the whole process over a browsing session.
    // Returns false when abandoned (loop finished); the outstanding callback is harmless (it signals a semaphore
    // no one waits on and fills a box no one reads).
    private func awaitOrAbandon(_ sem: DispatchSemaphore) -> Bool {
        while sem.wait(timeout: .now() + 3) == .timedOut {
            if isFinished { return false }
        }
        return true
    }

    private func blockingFlowRead() -> (Data?, Error?) {
        let sem = DispatchSemaphore(value: 0)
        let box = ResultBox<(Data?, Error?)>((nil, nil))
        flow.readDataForCopy { data, err in box.value = (data, err); sem.signal() }
        guard awaitOrAbandon(sem) else { return (nil, DsseLocalRuntimeCopyDriverError.runtimeCopyIdleTimeoutExceeded) }
        return box.value
    }

    private func blockingFlowWrite(_ data: Data) -> Error? {
        let sem = DispatchSemaphore(value: 0)
        let box = ResultBox<Error?>(nil)
        flow.writeDataForCopy(data) { err in box.value = err; sem.signal() }
        guard awaitOrAbandon(sem) else { return DsseLocalRuntimeCopyDriverError.runtimeCopyIdleTimeoutExceeded }
        return box.value
    }

    private func blockingTunnelSend(_ data: Data) -> Error? {
        let sem = DispatchSemaphore(value: 0)
        let box = ResultBox<Error?>(nil)
        tunnel.send(data) { err in box.value = err; sem.signal() }
        guard awaitOrAbandon(sem) else { return DsseLocalRuntimeCopyDriverError.runtimeCopyIdleTimeoutExceeded }
        return box.value
    }

    private func blockingTunnelReceive() -> (Data?, Error?) {
        let sem = DispatchSemaphore(value: 0)
        let box = ResultBox<(Data?, Error?)>((nil, nil))
        tunnel.receive { data, err in box.value = (data, err); sem.signal() }
        guard awaitOrAbandon(sem) else { return (nil, DsseLocalRuntimeCopyDriverError.runtimeCopyIdleTimeoutExceeded) }
        return box.value
    }

    private func finishOnEOF() {
        lock.lock()
        let up = bytesUp
        let down = bytesDown
        lock.unlock()
        // DOWNSTREAM BYTES ARE PROOF THE FLOW WORKED, even with nothing upstream.
        //
        // This used to require up > 0 as well, and that is wrong twice over. It is wrong for SERVER-SPEAKS-FIRST
        // protocols — an SSH banner, an SMTP greeting, a port that answers and immediately closes — where a
        // client legitimately sends nothing before the server responds and ends the flow. And it is a race in
        // every other case: the upstream and downstream legs run concurrently, so a downstream EOF that arrives
        // before the upstream read callback has added its bytes sees up == 0 and reports a failure for a flow
        // that is about to be, or already was, entirely successful. That race is what made
        // DsseRuntimeCopyTunnelBackpressureRegressionTests intermittently fail with emptyUpstreamPayload.
        //
        // What the check was really guarding is "the copy loop moved nothing at all", and that is still caught:
        // down == 0 && up == 0 falls through to the failure below.
        if down > 0 {
            finish(.success(makeSuccessResult(up, down)))
        } else if up == 0 {
            dsseFlowDiagLogger.error("leg=eof_empty_up req=\(self.requestID, privacy: .public) up=\(up) down=\(down)")
            finish(.failure(DsseLocalRuntimeCopyDriverError.emptyUpstreamPayload))
        } else {
            dsseFlowDiagLogger.error("leg=eof_empty_down req=\(self.requestID, privacy: .public) up=\(up) down=\(down)")
            finish(.failure(DsseLocalRuntimeCopyDriverError.emptyDownstreamPayload))
        }
    }

    // Flow teardown-reason tracing. No-op by default; flip neDiagEnabled to append reasons to
    // /tmp/dsse_ne_teardown.log (used while diagnosing the macOS half-open write issue; os_log from the system
    // extension is not surfaced, so a world-readable file is the only way to read the reasons back).
    static let neDiagEnabled = false
    static func neDiag(_ line: @autoclosure () -> String) {
        guard neDiagEnabled else { return }
        let path = "/tmp/dsse_ne_teardown.log"
        guard let data = (line() + "\n").data(using: .utf8) else { return }
        if let fh = FileHandle(forWritingAtPath: path) {
            defer { try? fh.close() }
            _ = try? fh.seekToEnd()
            try? fh.write(contentsOf: data)
        } else {
            try? data.write(to: URL(fileURLWithPath: path))
            try? FileManager.default.setAttributes([.posixPermissions: 0o666], ofItemAtPath: path)
        }
    }

    private func finishReason(_ reason: @autoclosure () -> String) {
        guard Self.neDiagEnabled else { return }
        lock.lock(); let u = bytesUp; let d = bytesDown; lock.unlock()
        Self.neDiag("finish req=\(requestID) reason=\(reason()) up=\(u) down=\(d)")
    }

    private func finish(_ result: Result<DsseLocalRuntimeCopyResult, Error>) {
        lock.lock()
        if finished {
            lock.unlock()
            return
        }
        finished = true
        lock.unlock()
        cancelIdleReaper()
        tunnel.close()
        switch result {
        case .success:
            closeGuardAndFlow(nil)
        case .failure(let error):
            closeGuardAndFlow(error)
        }
        completionHandler(result)
    }
}
