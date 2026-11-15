import Foundation
import Network
import NetworkExtension
import os.log

// The Mac's DNS, answered by the Edge.
//
// Every DNS query the Mac makes — whichever resolver the system was configured with — is handed to this provider
// and sent to the Edge's /steer/dns-query over the same pinned, mutually authenticated transport the device's
// flows use. The Edge answers it the way it answers the Windows agent's DNS: names an organization registered
// on a Site are resolved on that Site through its connector, and address answers live at most five minutes.
//
// Without it the Mac asked its local resolvers directly. Names that only a Site can resolve did not resolve at
// all, the queried names left the device in plain text, and the Edge never learned which name an address came
// from.
//
// A query the Edge does not answer is answered SERVFAIL here, at once. It is not sent to the local resolver
// instead: that would put the device's DNS back on the local network whenever the Edge is unreachable.

private let dnsProxyLogger = Logger(subsystem: "jp.co.lantern-networks.dsse.agent", category: "dns-proxy")

private func dnsProxyLog(_ message: String) {
    dnsProxyLogger.notice("\(message, privacy: .public)")
}

open class DsseDNSProxyProvider: NEDNSProxyProvider, @unchecked Sendable {
    private let lock = NSLock()
    private var forwarder: DsseDNSOverNWForwarder?
    private var forwarderBuiltAt = Date.distantPast
    private let agentConfigPath = DsseAppProxyProvider.productionAgentConfigPath

    /// How long one resolution of the device's transport (identity, pins, Edge address) is used before it is read
    /// again. A renewed device certificate reaches the DNS path within this time.
    static let forwarderLifetime: TimeInterval = 300

    open override func startProxy(options: [String: Any]? = nil, completionHandler: @escaping (Error?) -> Void) {
        let ready = currentForwarder(now: Date()) != nil
        dnsProxyLog("dns_proxy_started transport_ready=\(ready)")
        completionHandler(nil)
    }

    open override func stopProxy(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        lock.lock(); let old = forwarder; forwarder = nil; lock.unlock()
        old?.close()
        dnsProxyLog("dns_proxy_stopped reason=\(reason.rawValue)")
        completionHandler()
    }

    open override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        // Refusing a flow here closes it; it is not handed to the Mac's resolvers. The app enables this provider
        // only on macOS 15 and later, where it can carry every query it is given.
        guard #available(macOS 15.0, *) else {
            return false
        }
        let source = flow.metaData.sourceAppSigningIdentifier
        noteOnce(&firstFlowNoted, "dns_proxy_first_query source=\(source.isEmpty ? "unknown" : source)")
        if let udp = flow as? NEAppProxyUDPFlow {
            udp.open(withLocalFlowEndpoint: nil) { [weak self] error in
                guard let self else { return }
                if let error {
                    dnsProxyLog("dns_proxy_udp_open_failed \(Self.nonsecret(error))")
                    return
                }
                self.relayDatagrams(udp)
            }
            return true
        }
        if let tcp = flow as? NEAppProxyTCPFlow {
            tcp.open(withLocalFlowEndpoint: nil) { [weak self] error in
                guard let self else { return }
                if let error {
                    dnsProxyLog("dns_proxy_tcp_open_failed \(Self.nonsecret(error))")
                    return
                }
                self.relayStream(tcp, pending: Data())
            }
            return true
        }
        return false
    }

    // MARK: - UDP

    @available(macOS 15.0, *)
    private func relayDatagrams(_ flow: NEAppProxyUDPFlow) {
        flow.readDatagrams { [weak self] datagrams, error in
            guard let self else { return }
            if error != nil || datagrams == nil || datagrams?.isEmpty == true {
                flow.closeReadWithError(nil)
                flow.closeWriteWithError(nil)
                return
            }
            for (query, endpoint) in datagrams ?? [] {
                self.answer(query) { response in
                    flow.writeDatagrams([(response, endpoint)]) { _ in }
                }
            }
            self.relayDatagrams(flow)
        }
    }

    // MARK: - TCP (RFC 1035 4.2.2: each message is preceded by its two-byte length)

    @available(macOS 15.0, *)
    private func relayStream(_ flow: NEAppProxyTCPFlow, pending: Data) {
        flow.readData { [weak self] data, error in
            guard let self else { return }
            guard error == nil, let data, !data.isEmpty else {
                flow.closeReadWithError(nil)
                flow.closeWriteWithError(nil)
                return
            }
            var buffer = pending + data
            for query in Self.takeFramedMessages(&buffer) {
                self.answer(query) { response in
                    flow.write(Self.framed(response)) { _ in }
                }
            }
            self.relayStream(flow, pending: buffer)
        }
    }

    // MARK: - Answering

    private func answer(_ query: Data, reply: @escaping @Sendable (Data) -> Void) {
        guard let forwarder = currentForwarder(now: Date()) else {
            if let failure = Self.serverFailure(for: query) { reply(failure) }
            return
        }
        forwarder.forwardQuery(query) { [weak self] response, outcome in
            if let response, Self.isResponse(response, to: query) {
                self?.noteAnswered()
                reply(response)
                return
            }
            self?.noteUnanswered(outcome == "ok" ? "not_a_response_to_the_query" : outcome)
            self?.discardForwarder()
            if let failure = Self.serverFailure(for: query) { reply(failure) }
        }
    }

    private func currentForwarder(now: Date) -> DsseDNSOverNWForwarder? {
        lock.lock()
        defer { lock.unlock() }
        if let forwarder, now.timeIntervalSince(forwarderBuiltAt) < Self.forwarderLifetime {
            return forwarder
        }
        let path = agentConfigPath
        let configDir = URL(fileURLWithPath: path).deletingLastPathComponent()
        let contract = (try? Data(contentsOf: URL(fileURLWithPath: path)))
            .flatMap { DsseAppProxyProvider.transportContract(agentConfigPath: path, data: $0) }
        guard let security = DsseTransportSecurityResolver.resolve(contract: contract, configDirectory: configDir, agentConfigPath: path),
              security.clientIdentity != nil else {
            forwarder = nil
            return nil
        }
        let dnsPath = contract?.dnsOverTunnelPath ?? "/steer/dns-query"
        forwarder?.close()
        forwarder = DsseDNSOverNWForwarder(security: security, dnsOverTunnelPath: dnsPath)
        forwarderBuiltAt = now
        return forwarder
    }

    private var firstFlowNoted = false
    private var answeredNoted = false
    private var unanswered = 0

    private func noteOnce(_ flag: inout Bool, _ message: String) {
        lock.lock()
        let first = !flag
        flag = true
        lock.unlock()
        if first { dnsProxyLog(message) }
    }

    private func noteAnswered() {
        noteOnce(&answeredNoted, "dns_proxy_first_answer_from_the_edge")
    }

    // The first few failures and then every hundredth: enough to say why, without a line per query.
    private func noteUnanswered(_ reason: String) {
        lock.lock()
        unanswered += 1
        let n = unanswered
        lock.unlock()
        if n <= 5 || n % 100 == 0 {
            dnsProxyLog("dns_proxy_edge_did_not_answer reason=\(reason) count=\(n) — answered SERVFAIL")
        }
    }

    private func discardForwarder() {
        lock.lock(); forwarderBuiltAt = .distantPast; lock.unlock()
    }

    private static func nonsecret(_ error: Error) -> String {
        let ns = error as NSError
        return "domain=\(ns.domain) code=\(ns.code)"
    }

    // MARK: - Message helpers (pure; tested)

    /// The response carries the query's ID and is marked as a response.
    static func isResponse(_ response: Data, to query: Data) -> Bool {
        guard response.count >= 12, query.count >= 12 else { return false }
        let r = [UInt8](response.prefix(3)), q = [UInt8](query.prefix(2))
        return r[0] == q[0] && r[1] == q[1] && (r[2] & 0x80) != 0
    }

    /// SERVFAIL for query: its header and question, marked as a response, nothing else.
    static func serverFailure(for query: Data) -> Data? {
        let bytes = [UInt8](query)
        guard bytes.count >= 12 else { return nil }
        let questions = Int(bytes[4]) << 8 | Int(bytes[5])
        var offset = 12
        for _ in 0..<questions {
            while true {
                guard offset < bytes.count else { return nil }
                let length = Int(bytes[offset])
                if length == 0 { offset += 1; break }
                if length & 0xC0 == 0xC0 { offset += 2; break }
                offset += 1 + length
            }
            offset += 4
            guard offset <= bytes.count else { return nil }
        }
        var out = Array(bytes[0..<offset])
        out[2] = 0x80 | (bytes[2] & 0x79)   // QR, the query's opcode and RD; AA and TC clear
        out[3] = 0x80 | 0x02                 // RA, RCODE=SERVFAIL
        out[6] = 0; out[7] = 0; out[8] = 0; out[9] = 0; out[10] = 0; out[11] = 0
        return Data(out)
    }

    static func framed(_ message: Data) -> Data {
        var out = Data([UInt8(message.count >> 8 & 0xFF), UInt8(message.count & 0xFF)])
        out.append(message)
        return out
    }

    /// Removes every complete length-prefixed message from the front of buffer and returns them in order.
    static func takeFramedMessages(_ buffer: inout Data) -> [Data] {
        var messages: [Data] = []
        var bytes = [UInt8](buffer)
        while bytes.count >= 2 {
            let length = Int(bytes[0]) << 8 | Int(bytes[1])
            guard bytes.count >= 2 + length else { break }
            messages.append(Data(bytes[2..<(2 + length)]))
            bytes.removeFirst(2 + length)
        }
        buffer = Data(bytes)
        return messages
    }
}

extension NEAppProxyUDPFlow: @unchecked @retroactive Sendable {}
