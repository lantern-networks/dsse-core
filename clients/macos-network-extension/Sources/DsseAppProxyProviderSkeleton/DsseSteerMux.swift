import Foundation
import Network
import os

// Tunnel multiplexing (NE side). One mTLS transport connection to the Edge carries MANY browser flows via
// custom framing, instead of one CONNECT /steer NWConnection per flow. A heavy page opens ~80 flows at once;
// ~80 concurrent NWConnections overwhelm Network.framework's callback delivery and stall interception
// handshakes mid-ServerHello. Collapsing to ONE connection (a single receive loop, a single TLS context)
// removes that limit — the flows are unchanged, only their carriage is. Wire protocol matches steer_mux.go:
//   [flowID uint32 BE][type uint8][length uint32 BE][payload...]   OPEN=0 (authority) / DATA=1 / CLOSE=2

private let dsseMuxLogger = Logger(subsystem: "dsse.ne.flowdiag", category: "mux")

// The Edge and Windows peer already enforce this wire-format bound. It prevents a
// malformed length header or a stalled flow from retaining unbounded process memory.
enum DsseMuxFrameSafety {
    static let maxPayload = 1 << 20
    static let flowBufferCap = 1 << 20

    static func acceptsFrameLength(_ length: Int) -> Bool {
        length >= 0 && length <= maxPayload
    }

    static func acceptsInbound(buffered: Int, incoming: Int) -> Bool {
        buffered < flowBufferCap && acceptsFrameLength(incoming)
    }
}

enum DsseMuxFrameType: UInt8 {
    case open = 0
    case data = 1
    case close = 2
    case stepUp = 3  // Edge->NE: payload = a step-up portal URL to open OOB in a browser (native flow can't 302)
    case warn = 4    // Edge->NE: payload = JSON {message,destination,service}. NON-HOLDING learning-lifecycle Warn
                     // notice — the flow is allowed; surface a passive "monitored; auth soon required" message only.
    case authResult = 5 // Edge->NE: authenticated mux result for this held flow; not a browser callback verdict.
    case authQuery = 6  // NE->Edge: requery a final result after a lost mux notification.
}

// A held flow has one non-renewable authentication window. Use monotonic time:
// wall-clock changes and repeated STEPUP frames must not keep a flow alive forever.
struct DsseMuxAuthenticationWait {
    private var beganAt: TimeInterval?
    private var ended = false

    mutating func begin(at uptime: TimeInterval) {
        guard beganAt == nil, !ended else { return }
        beganAt = uptime
    }

    mutating func end() { ended = true }

    func isPending(at uptime: TimeInterval) -> Bool {
        guard !ended, let beganAt, uptime >= beganAt else { return false }
        return uptime - beganAt < 120 // Same upper bound as the Edge/Portal request.
    }
}

// Per-flow stream over the shared mux. Conforms to DsseRuntimeCopyTunnelStream so the existing full-duplex
// pump drives it UNCHANGED (send/receive/close) — it just talks frames on the shared connection.
public final class DsseMuxFlowStream: DsseRuntimeCopyTunnelStream, @unchecked Sendable {
    let flowID: UInt32
 let authOwner: DsseAuthOwner?
    private weak var mux: DsseSteerMux?
    private let lock = NSLock()
    private var inbound = Data()
    private var pendingReceive: (@Sendable (Data?, Error?) -> Void)?
    private var eof = false
    private var failure: Error?
    private var closed = false
    private var authenticationWait = DsseMuxAuthenticationWait()

    init(flowID: UInt32, mux: DsseSteerMux, authOwner: DsseAuthOwner?) {
 self.authOwner = authOwner
        self.flowID = flowID
        self.mux = mux
    }

    public var authenticationWaitPending: Bool {
        lock.lock(); defer { lock.unlock() }
        return !closed && !eof && failure == nil &&
            authenticationWait.isPending(at: ProcessInfo.processInfo.systemUptime)
    }

    func beginAuthenticationWait() {
        lock.lock(); defer { lock.unlock() }
        guard !closed, !eof, failure == nil else { return }
        authenticationWait.begin(at: ProcessInfo.processInfo.systemUptime)
    }

    public func send(_ data: Data, completion: @escaping @Sendable (Error?) -> Void) {
        guard let mux else { completion(DsseRuntimeCopyTunnelError.closed); return }
        mux.sendFrame(flowID: flowID, type: .data, payload: data, completion: completion)
    }

    public func receive(completion: @escaping @Sendable (Data?, Error?) -> Void) {
        lock.lock()
        if !inbound.isEmpty {
            let d = inbound
            inbound = Data()
            lock.unlock()
            completion(d, nil)
            return
        }
        if let failure {
            lock.unlock()
            completion(nil, failure)
            return
        }
        if eof {
            lock.unlock()
            completion(nil, nil) // nil, nil = clean EOF
            return
        }
        pendingReceive = completion
        lock.unlock()
    }

    public func close() {
        lock.lock()
        let alreadyClosed = closed
        closed = true
        authenticationWait.end()
        // CRITICAL: fire any receive the pump is blocked on. The copy pump's downstream thread parks in
        // `receive(completion:)` (pendingReceive set); unlike a real NWConnection, closing this virtual stream
        // cancels nothing, so without this the completion never fires and the thread blocks forever — a thread
        // leak per closed flow that degrades the whole process over a browsing session (the "it shouldn't break
        // this easily" symptom). Deliver a clean EOF so blockingTunnelReceive returns and the thread exits.
        let p = pendingReceive
        pendingReceive = nil
        eof = true
        lock.unlock()
        if !alreadyClosed {
            mux?.closeFlow(flowID: flowID)
        }
        p?(nil, nil)
    }

    // ---- called by the mux demux loop ----
    func deliverInbound(_ data: Data) -> Bool {
        lock.lock()
        if closed || eof || failure != nil {
            lock.unlock()
            return true
        }
        if !data.isEmpty { authenticationWait.end() }
        if let p = pendingReceive {
            pendingReceive = nil
            lock.unlock()
            p(data, nil)
            return true
        }
        if !DsseMuxFrameSafety.acceptsInbound(buffered: inbound.count, incoming: data.count) {
            failure = DsseRuntimeCopyTunnelError.connectionFailed("mux flow inbound overflow")
            closed = true
            lock.unlock()
            return false
        }
        inbound.append(data)
        lock.unlock()
        return true
    }

    func deliverEOF() {
        lock.lock()
        authenticationWait.end()
        eof = true
        if let p = pendingReceive {
            pendingReceive = nil
            lock.unlock()
            p(nil, nil)
            return
        }
        lock.unlock()
    }

    func deliverFailure(_ error: Error) {
        lock.lock()
        authenticationWait.end()
        if failure == nil { failure = error }
        if let p = pendingReceive {
            pendingReceive = nil
            lock.unlock()
            p(nil, error)
            return
        }
        lock.unlock()
    }
}

public final class DsseSteerMux: @unchecked Sendable {
    private static let queryLeaderLock = NSLock()
    nonisolated(unsafe) private static var queryLeader: DsseSteerMux? // guarded by queryLeaderLock
    private let connection: NWConnection
    private let queue: DispatchQueue
    private let stateLock = NSLock()
    private var flows: [UInt32: DsseMuxFlowStream] = [:]
    private var nextFlowID: UInt32 = 1
    private var readBuffer = Data()
    private var readOffset = 0 // consumed prefix of readBuffer (serial-queue-confined, no lock)
    private let muxHeaderLen = 9 // flowID(4) + type(1) + length(4)
    private var torndown = false

    private init(connection: NWConnection, queue: DispatchQueue) {
        self.connection = connection
        self.queue = queue
    }

    // Opens ONE mux transport connection: mTLS dial + `CONNECT /steer-mux` + 200, then starts the demux loop.
    public static func open(
        edgeHost: String,
        edgePort: Int,
        tlsSecurity: DsseTransportSecurity?,
        completion: @escaping @Sendable (Result<DsseSteerMux, Error>) -> Void
    ) {
        let trimmed = edgeHost.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, edgePort > 0, edgePort <= 65535,
              let port = NWEndpoint.Port(rawValue: UInt16(edgePort)) else {
            completion(.failure(DsseRuntimeCopyTunnelError.invalidEdgeAuthority))
            return
        }
        let queue = DispatchQueue(label: "dsse.steer-mux", qos: .userInitiated)
        let parameters: NWParameters
        if let tlsSecurity {
            parameters = DsseTransportTLS.makeTunnelParameters(security: tlsSecurity)
        } else {
            let tcp = NWProtocolTCP.Options()
            tcp.noDelay = true
            parameters = NWParameters(tls: nil, tcp: tcp)
        }
        let connection = NWConnection(host: NWEndpoint.Host(trimmed), port: port, using: parameters)
        let mux = DsseSteerMux(connection: connection, queue: queue)
        // Report basic device posture (disk encryption + firewall) on the CONNECT — per connection ≈ per device,
        // the right granularity. Best-effort; omits any signal it could not read.
        let posture = DsseDevicePosture.collect().connectHeaderLines()
        let request = Data("CONNECT /steer-mux HTTP/1.1\r\nHost: \(trimmed)\r\n\(posture)\r\n".utf8)
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
                    mux.readHandshakeResponse(accumulated: Data()) { result in
                        guard completed.set() else { return }
                        switch result {
                        case .success:
                            mux.startReadLoop()
                            mux.scheduleAuthRequery()
                            completion(.success(mux))
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
            case .waiting(let error):
                // The Edge is unreachable right now — the usual case is it is RESTARTING (connection refused).
                // NWConnection would sit in .waiting retrying indefinitely, so if we ignore it the open never
                // completes: the pool's muxOpeningCount never clears and every flow parks forever = the wedge
                // that used to require an agent restart. Fail fast instead; the caller retries on the next flow,
                // and once the Edge is back the next open reaches .ready on its own (auto-recovery, no restart).
                if completed.set() {
                    connection.cancel()
                    completion(.failure(DsseRuntimeCopyTunnelError.connectionFailed("waiting: \(error)")))
                }
            default:
                break
            }
        }
        connection.start(queue: queue)
        // Backstop: if the connection never reaches .ready and never surfaces .failed/.waiting (a silent stall
        // in .preparing), still fail the open so muxOpeningCount is released and flows retry — never hang the pool.
        queue.asyncAfter(deadline: .now() + 8) {
            if completed.set() {
                connection.cancel()
                completion(.failure(DsseRuntimeCopyTunnelError.connectionFailed("open timeout")))
            }
        }
    }

    private func readHandshakeResponse(accumulated: Data, completion: @escaping @Sendable (Result<Void, Error>) -> Void) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) { [self] data, _, isComplete, error in
            if let error {
                completion(.failure(DsseRuntimeCopyTunnelError.connectionFailed("\(error)")))
                return
            }
            var acc = accumulated
            if let data { acc.append(data) }
            if isComplete {
                completion(.failure(DsseRuntimeCopyTunnelError.handshakeFailed("mux_handshake_closed")))
                return
            }
            guard let headerEnd = acc.range(of: Data("\r\n\r\n".utf8)) else {
                if acc.count > 64 * 1024 {
                    completion(.failure(DsseRuntimeCopyTunnelError.handshakeFailed("mux_header_too_large")))
                    return
                }
                readHandshakeResponse(accumulated: acc, completion: completion)
                return
            }
            guard headerEnd.lowerBound <= 64 * 1024 else {
                completion(.failure(DsseRuntimeCopyTunnelError.handshakeFailed("mux_header_too_large")))
                return
            }
            let head = Data(acc[..<headerEnd.lowerBound])
            guard DsseRuntimeCopyTunnel.handshakeStatusCode(head) == 200 else {
                completion(.failure(DsseRuntimeCopyTunnelError.handshakeFailed("mux_non_200")))
                return
            }
            // Any bytes past the header terminator are the first mux frames — seed the demux buffer.
            let leftover = acc[headerEnd.upperBound...]
            if !leftover.isEmpty {
                stateLock.lock(); readBuffer.append(leftover); stateLock.unlock()
            }
            completion(.success(()))
        }
    }

    // Registers a new flow, sends OPEN(authority), returns the per-flow stream.
    public func openFlow(authority: String, authOwner: DsseAuthOwner? = nil) -> DsseMuxFlowStream {
        stateLock.lock()
        let id = nextFlowID
        nextFlowID &+= 1
        let flow = DsseMuxFlowStream(flowID: id, mux: self, authOwner: authOwner)
        flows[id] = flow
        stateLock.unlock()
        sendFrame(flowID: id, type: .open, payload: Data((authOwner?.appendingIdentity(to: authority) ?? authority).utf8), completion: { _ in })
        return flow
    }

    func closeFlow(flowID: UInt32) {
        stateLock.lock()
        flows[flowID] = nil
        stateLock.unlock()
        sendFrame(flowID: flowID, type: .close, payload: Data(), completion: { _ in })
    }

    private func lookup(_ flowID: UInt32) -> DsseMuxFlowStream? {
        stateLock.lock(); defer { stateLock.unlock() }
        return flows[flowID]
    }

    private func removeFlow(_ flowID: UInt32) {
        stateLock.lock()
        flows[flowID] = nil
        stateLock.unlock()
    }

    func sendFrame(flowID: UInt32, type: DsseMuxFrameType, payload: Data, completion: @escaping @Sendable (Error?) -> Void) {
        guard DsseMuxFrameSafety.acceptsFrameLength(payload.count) else {
            completion(DsseRuntimeCopyTunnelError.connectionFailed("mux frame too large"))
            return
        }
        var frame = Data(capacity: 9 + payload.count)
        var fid = flowID.bigEndian
        withUnsafeBytes(of: &fid) { frame.append(contentsOf: $0) }
        frame.append(type.rawValue)
        var len = UInt32(payload.count).bigEndian
        withUnsafeBytes(of: &len) { frame.append(contentsOf: $0) }
        frame.append(payload)
        // NO lock: NWConnection.send already delivers sends in order, and each call sends ONE whole frame
        // (header+payload) atomically, so frames never interleave. Holding a lock across the async completion
        // would serialize ALL flows' writes to one in-flight send and collapse throughput / risk deadlock.
        connection.send(content: frame, completion: .contentProcessed { error in
            completion(error.map { DsseRuntimeCopyTunnelError.connectionFailed("\($0)") })
        })
    }

    private func startReadLoop() {
        if parseFrames() { readMore() } // drain any leftover seeded during the handshake
    }

    private func scheduleAuthRequery() {
        guard isHealthy else { return }
        Self.queryLeaderLock.lock()
        if Self.queryLeader == nil || Self.queryLeader?.isHealthy == false { Self.queryLeader = self }
        let leader = Self.queryLeader === self
        Self.queryLeaderLock.unlock()
        if leader {
            DispatchQueue.global(qos: .utility).async { [self] in
                for query in DsseAuthHandoff.resultQueries() {
                    guard isHealthy else { return }
                    let fields = ["request_id": query.id, "os_principal": query.principal, "os_session": query.session]
                    guard let payload = try? JSONSerialization.data(withJSONObject: fields), payload.count <= 256 else { continue }
                    sendFrame(flowID: 0, type: .authQuery, payload: payload, completion: { _ in })
                }
            }
        }
        queue.asyncAfter(deadline: .now() + 15) { [self] in scheduleAuthRequery() }
    }

    private func readMore() {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 1 << 20) { [self] data, _, isComplete, error in
            if let data, !data.isEmpty {
                stateLock.lock(); readBuffer.append(data); stateLock.unlock()
                if !parseFrames() { return }
            }
            if let error {
                teardown(DsseRuntimeCopyTunnelError.connectionFailed("\(error)"))
                return
            }
            if isComplete {
                teardown(DsseRuntimeCopyTunnelError.closed)
                return
            }
            readMore()
        }
    }

    // Parses whole frames out of readBuffer using a read OFFSET, then compacts ONCE. readBuffer/readOffset are
    // touched only on the mux serial queue (readMore's callback + the handshake seed) so they need no lock; the
    // flows map does (pump threads touch it). CRITICAL: the previous version did `readBuffer.removeFirst(total)`
    // per frame — O(n) each, so a large download (e.g. 2.4 MB) made the single receive loop O(n^2). That slow
    // drain backpressured the one shared tunnel, the Edge held its per-frame write lock, and small latency-
    // sensitive frames (a new flow's ServerHello, getAsins, passkey/gapi) stalled behind it (down=1563/0) → the
    // browser timed out → heavy pages skeletoned. Offset + single compaction keeps the drain O(n).
    private func parseFrames() -> Bool {
        var batch: [(UInt32, UInt8, Data)] = []
        var oversizedFrame = false
        if !readBuffer.isEmpty {
            readBuffer.withUnsafeBytes { (raw: UnsafeRawBufferPointer) in
                let count = raw.count
                while count - readOffset >= muxHeaderLen {
                    let fid = UInt32(bigEndian: raw.loadUnaligned(fromByteOffset: readOffset, as: UInt32.self))
                    let rawType = raw.load(fromByteOffset: readOffset + 4, as: UInt8.self)
                    let len = Int(UInt32(bigEndian: raw.loadUnaligned(fromByteOffset: readOffset + 5, as: UInt32.self)))
                    if !DsseMuxFrameSafety.acceptsFrameLength(len) {
                        oversizedFrame = true
                        break
                    }
                    if count - readOffset < muxHeaderLen + len { break }
                    let payload = len > 0 ? Data(bytes: raw.baseAddress! + readOffset + muxHeaderLen, count: len) : Data()
                    batch.append((fid, rawType, payload))
                    readOffset += muxHeaderLen + len
                }
            }
            if readOffset > 0 {
                // Rebuild readBuffer as a FRESH, zero-based Data from the unconsumed tail. Front-removal on a Data
                // (removeFirst/removeAll/replaceSubrange) advances its START INDEX — the value stays a slice over
                // the original storage — and across edge churn that index drift eventually makes removeAll/
                // replaceSubrange trap (EXC_BREAKPOINT on the dsse.steer-mux queue), crashing the provider so it
                // never recovers. Copying the (small) leftover tail into a fresh Data re-bases the indices and
                // keeps the drain O(n). Never front-mutate readBuffer in place.
                if readOffset >= readBuffer.count {
                    readBuffer = Data()
                } else {
                    readBuffer = Data(readBuffer.dropFirst(readOffset))
                }
                readOffset = 0
            }
        }
        if oversizedFrame {
            teardown(DsseRuntimeCopyTunnelError.connectionFailed("mux frame too large"))
            return false
        }
        for (fid, rawType, payload) in batch {
            guard let type = DsseMuxFrameType(rawValue: rawType) else { continue }
            switch type {
            case .data:
                if let flow = lookup(fid), !flow.deliverInbound(payload) {
                    closeFlow(flowID: fid)
                }
            case .close:
                if let flow = lookup(fid) { flow.deliverEOF() }
                removeFlow(fid)
            case .open:
                break // Edge never initiates OPEN
            case .stepUp:
                if let flow = lookup(fid), let url = String(data: payload, encoding: .utf8),
                   DsseAuthHandoff.enqueue(url: url, owner: flow.authOwner) {
                    flow.beginAuthenticationWait()
                    // The bounded worker validates and notifies off the mux reader.
                } else {
                    dsseMuxLogger.error("mux stepup: no trusted Portal or originating user session")
                }
            case .warn:
                // NON-HOLDING Warn-stage notice (S3). The flow is ALREADY allowed/forwarded; this only informs the
                // user. Keep it in the same originating OS session as STEPUP; the GUI reads a protected
                // root-owned record after the payload-free Darwin notification.
                if let flow = lookup(fid), DsseAuthHandoff.enqueueWarn(payload: payload, owner: flow.authOwner) {
                    dsseMuxLogger.info("mux warn: handed monitored-notice to the agent app for flow \(fid)")
                } else {
                    dsseMuxLogger.error("mux warn: no validated notice or originating user session")
                }
            case .authResult:
                if fid == 0, DsseAuthHandoff.enqueueQueriedResult(payload: payload) {
                    // The protected request file supplies the originating login.
                } else if let flow = lookup(fid), DsseAuthHandoff.enqueueResult(payload: payload, owner: flow.authOwner) {
                    // The root-owned, session-specific handoff delivers a bounded
                    // result to the originating user's GUI, not to another login.
                } else {
                    dsseMuxLogger.error("mux auth result: no matching request in originating session")
                }
            case .authQuery:
                break // Edge never queries the endpoint.
            }
        }
        return true
    }

    private func teardown(_ error: Error) {
        stateLock.lock()
        if torndown { stateLock.unlock(); return }
        torndown = true
        let all = Array(flows.values)
        flows.removeAll()
        stateLock.unlock()
        Self.queryLeaderLock.lock()
        if Self.queryLeader === self { Self.queryLeader = nil }
        Self.queryLeaderLock.unlock()
        for f in all { f.deliverFailure(error) }
        connection.cancel()
        dsseMuxLogger.error("mux torn down: \(String(describing: error), privacy: .public)")
    }

    public var isHealthy: Bool {
        stateLock.lock(); defer { stateLock.unlock() }
        return !torndown
    }

    // Number of flows currently open on this connection. The adaptive pool uses it to load-balance new flows
    // onto the least-loaded connection and to decide when to grow/shrink the pool.
    public var activeFlowCount: Int {
        stateLock.lock(); defer { stateLock.unlock() }
        return flows.count
    }

    // Closes this whole mux connection (pool shrink of an idle slot). Any flows still on it fail (the browser
    // retries onto a fresh flow). Idempotent.
    public func shutdown() {
        teardown(DsseRuntimeCopyTunnelError.closed)
    }
}
