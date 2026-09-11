import DsseNetworkExtensionContract
import Foundation
import Network
import OSLog

// DsseFailOpenDirectSplice — the load-bearing half of the fail-open design.
//
// When a flow the NE has ALREADY taken over fails to be carried to the Edge (the tunnel/mTLS open fails — e.g. an
// expired device cert, the 2026-07-17 outage), the driver cannot just decline it: the flow is open and owned by
// the NE. Under fail-open it hands the still-open flow here, and this opens a DIRECT NWConnection to the flow's
// real destination and splices the two together, so the developer's own traffic keeps flowing instead of the
// whole machine bricking.
//
// It triggers on the CARRY FAILURE itself, not on a prediction of Edge health — so it covers failure modes no one
// enumerated in advance — "ANY reason" — which is exactly what the reverted health-prediction probe could not.
// PRODUCTION never reaches here: the driver only constructs this when fail-open is enabled, which is lab/PoC only.
private let dsseFailOpenSpliceLogger = Logger(subsystem: DsseRuntimeLogSubsystem.name, category: "failopen")

enum DsseFailOpenDirectError: Error, Equatable, Sendable {
    case connectTimeout
}

final class DsseFailOpenDirectSplice: @unchecked Sendable {
    static let fellOpenStatus = "fell_open_direct"

    // fellOpenResult reports "this flow fell open to a direct connection" to the driver's completion, so the
    // provider logs a fell-open (not a failure). Byte counts are not tracked on this exceptional path.
    static func fellOpenResult() -> DsseLocalRuntimeCopyResult {
        DsseLocalRuntimeCopyResult(
            status: fellOpenStatus,
            implementation: "fail_open_direct_nwconnection",
            bytesUp: 0,
            bytesDown: 0,
            registryCleanupGate: "not_applicable",
            tenantMetadataCleanupGate: "not_applicable",
            auditMetadataOnlyGate: "not_applicable",
            connectionRegistryRuntimeConnected: false,
            byteCapRuntimeEnforced: false,
            idleTimeoutRuntimeEnforced: false,
            boundedBackpressureRuntimeEnforced: false,
            flowReadHalfCloseRuntimeEnforced: false,
            flowWriteHalfCloseRuntimeEnforced: false,
            networkExtensionFlowOpened: true,
            edgeTunnelOpenStarted: true,
            tcpPayloadCopyStarted: false,
            flowPayloadReadStarted: false,
            flowPayloadWriteStarted: false
        )
    }

    private let flow: any DsseProviderTCPFlowCopyIO
    private let connection: NWConnection
    private let queue: DispatchQueue
    private let requestID: String
    private let maxReceive = 65_536

    // Establishment deadline: NWConnection retries a refused/unreachable destination via .waiting rather than
    // .failed, so without this a direct-fallback to a dead destination would hang the flow forever. If the direct
    // connection is not .ready within this window, give up and close (nothing — not the Edge, not direct — works).
    private let connectTimeout: TimeInterval = 10

    private let lock = NSLock()
    private var closed = false
    // Half-close bookkeeping: the splice is done only when BOTH directions have hit EOF.
    private var upDone = false   // flow -> connection: the app closed its write half
    private var downDone = false // connection -> flow: the peer closed its write half

    // The driver constructs a splice as a local and returns, so nothing on the call stack retains it. Every
    // internal continuation ([weak self] on the connection handler, the connect-timeout, both pumps) is weak so
    // as not to leak, which means WITHOUT this the splice deallocates the instant start() returns — the connection
    // never gets driven and the flow silently connect-times-out (observed on device 2026-07-18: onFailed fired with
    // self already nil, zero `spliced`/`connect_failed` logs). Retain self for the splice's lifetime; release in
    // closeBoth, the single terminal for every completion path.
    private var selfRetain: DsseFailOpenDirectSplice?

    // Returns nil when the destination cannot be turned into an endpoint (nothing to fall open to).
    init?(flow: any DsseProviderTCPFlowCopyIO, host: String, port: Int, requestID: String) {
        let trimmedHost = host.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedHost.isEmpty, port > 0, port <= 65_535, let nwPort = NWEndpoint.Port(rawValue: UInt16(port)) else {
            return nil
        }
        self.flow = flow
        self.connection = NWConnection(host: NWEndpoint.Host(trimmedHost), port: nwPort, using: .tcp)
        self.queue = DispatchQueue(label: "dsse.failopen.direct.\(requestID)")
        self.requestID = requestID
    }

    // start opens the direct connection. onReady fires once the splice is established (the flow is now carried
    // direct); onFailed fires if the DIRECT connection also fails (truly nothing works — the flow is closed).
    // Exactly one of onReady/onFailed fires, at most once.
    func start(onReady: @escaping @Sendable () -> Void, onFailed: @escaping @Sendable (Error) -> Void) {
        lock.lock(); selfRetain = self; lock.unlock() // stay alive until closeBoth, or the splice is never driven
        let readyOnce = DsseOnce()
        let giveUp: @Sendable (Error) -> Void = { [weak self] error in
            readyOnce.run {
                if let self {
                    dsseFailOpenSpliceLogger.error("fail_open_direct connect_failed req=\(self.requestID, privacy: .public) err=\(String(describing: error), privacy: .public)")
                    self.closeBoth(error)
                }
                onFailed(error)
            }
        }
        connection.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                readyOnce.run {
                    dsseFailOpenSpliceLogger.notice("fail_open_direct spliced req=\(self.requestID, privacy: .public)")
                    onReady()
                    self.pumpFlowToConnection()
                    self.pumpConnectionToFlow()
                }
            case .failed(let error):
                giveUp(error)
            case .cancelled:
                self.closeBoth(nil)
            default:
                break
            }
        }
        // Fail if not established within connectTimeout — a refused/unreachable destination sits in .waiting and
        // retries forever, which would hang the flow.
        queue.asyncAfter(deadline: .now() + connectTimeout) {
            giveUp(DsseFailOpenDirectError.connectTimeout)
        }
        connection.start(queue: queue)
    }

    // flow -> connection: read from the app flow, send to the direct connection. Empty read = the app closed its
    // write half (EOF); signal it to the connection and stop this pump.
    private func pumpFlowToConnection() {
        flow.readDataForCopy { [weak self] data, error in
            guard let self else { return }
            if error != nil {
                self.closeBoth(error)
                return
            }
            guard let data, !data.isEmpty else {
                self.connection.send(content: nil, contentContext: .finalMessage, isComplete: true, completion: .contentProcessed { _ in })
                self.markUpDone()
                return
            }
            self.connection.send(content: data, completion: .contentProcessed { [weak self] sendError in
                guard let self else { return }
                if sendError != nil {
                    self.closeBoth(sendError)
                    return
                }
                self.pumpFlowToConnection()
            })
        }
    }

    // connection -> flow: receive from the direct connection, write to the app flow. isComplete = the peer closed
    // its write half; close the flow's write half and stop this pump.
    private func pumpConnectionToFlow() {
        connection.receive(minimumIncompleteLength: 1, maximumLength: maxReceive) { [weak self] data, _, isComplete, error in
            guard let self else { return }
            if let data, !data.isEmpty {
                self.flow.writeDataForCopy(data) { [weak self] writeError in
                    guard let self else { return }
                    if writeError != nil {
                        self.closeBoth(writeError)
                        return
                    }
                    if isComplete {
                        self.flow.closeWriteForCopy(error: nil)
                        self.markDownDone()
                        return
                    }
                    self.pumpConnectionToFlow()
                }
                return
            }
            if isComplete {
                self.flow.closeWriteForCopy(error: nil)
                self.markDownDone()
                return
            }
            if error != nil {
                self.closeBoth(error)
                return
            }
            self.pumpConnectionToFlow()
        }
    }

    // markUpDone / markDownDone record a clean half-close; when BOTH directions have EOF'd the splice is finished
    // and closeBoth releases it. A half-close on one side alone leaves the other pumping (request/response, etc.).
    private func markUpDone() {
        lock.lock(); upDone = true; let both = downDone; lock.unlock()
        if both { closeBoth(nil) }
    }

    private func markDownDone() {
        lock.lock(); downDone = true; let both = upDone; lock.unlock()
        if both { closeBoth(nil) }
    }

    // closeBoth tears down both ends, idempotently, and releases the self-retain so the splice can deallocate.
    private func closeBoth(_ error: Error?) {
        lock.lock()
        if closed { lock.unlock(); return }
        closed = true
        lock.unlock()
        flow.closeReadForCopy(error: error)
        flow.closeWriteForCopy(error: error)
        connection.stateUpdateHandler = nil
        connection.cancel()
        lock.lock(); selfRetain = nil; lock.unlock()
    }
}

// DsseOnce runs a block at most once (thread-safe). Used to make onReady/onFailed mutually exclusive.
final class DsseOnce: @unchecked Sendable {
    private let lock = NSLock()
    private var done = false
    func run(_ block: () -> Void) {
        guard tryRun() else { return }
        block()
    }

    // tryRun claims the single-run slot without a block: returns true exactly once, false thereafter. Used to
    // make an openTunnel timeout, its .failure, and its .success mutually exclusive.
    func tryRun() -> Bool {
        lock.lock(); defer { lock.unlock() }
        if done { return false }
        done = true
        return true
    }
}
