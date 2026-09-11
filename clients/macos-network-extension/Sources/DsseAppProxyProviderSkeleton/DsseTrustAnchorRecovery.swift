import Foundation
import Network
import Security

// Self-healing for the case the whole PKI effort exists to remove: this device's anchors no longer validate the
// Edge, so the tunnel cannot open, and everything that would repair it is distributed over that tunnel.
//
// Cross-signing is what should stop this happening at all — a rotation keeps the old anchor working for the
// overlap. This is what a device does when it happens anyway: a shutdown longer than the overlap, an unplanned
// key revocation, or a rotation performed without publishing the cross-certificate.
//
// It is deliberately a PERIODIC CHECK rather than a reaction to a failed handshake. Wiring it to a handshake
// error would only cover devices that are already running and trying; a device that BOOTS holding a stale anchor
// never gets a meaningful failure to react to, and that is exactly the returning-from-leave case. Checking
// "can I still verify the Edge?" on a timer covers both, and costs one probe when the answer is yes.
//
// Nothing here trusts the network. The probe decides only WHETHER to look; the bundle it then fetches is
// verified against a key pinned in this device's configuration, and rejected unless its serial advances past the
// highest already accepted.

public enum DsseTrustAnchorRecoveryOutcome: Sendable, Equatable {
    /// The current anchors still validate the Edge. Nothing was fetched.
    case anchorsStillValid
    /// The anchors did not validate and a newer signed bundle replaced them.
    case adopted(serial: Int64, anchors: Int)
    /// The anchors did not validate and no usable bundle could be obtained. The device stays as it was.
    case unrecovered(reason: String)
    /// The anchors still validated the Edge AND a newer signed distribution was adopted anyway. This is the
    /// ordinary path for a healthy device: adoption cannot be reserved for devices that are already broken,
    /// or an overlap-then-retire rotation can never reach the overlap.
    case adoptedWhileHealthy(serial: Int64, anchors: Int)
    /// A newer distribution was offered and REFUSED because this device could not verify the Edge with it.
    /// Adopting would have cut the device off, and it is the device — not the Edge — that can tell.
    case refusedWouldStrandSelf(serial: Int64, reason: String)
}

public enum DsseTrustAnchorRecovery {

    /// probeAnchorsValidateEdge answers "do the anchors I hold still validate this Edge?" by FETCHING the chain
    /// the Edge serves and evaluating it locally, anchors-only.
    ///
    /// Reading the answer out of a TLS client error instead does not work here, and the live lab proved it: the
    /// transport port requires a client certificate, so a probe without one fails the handshake for a reason
    /// that is indistinguishable from an untrusted chain — every healthy device would conclude its anchors were
    /// stale. Separating "can I read the chain" from "does it verify" removes that confusion entirely, and needs
    /// no device identity to ask the question.
    ///
    /// nil means UNDETERMINED — the Edge could not be reached. An unreachable Edge and an untrusted one must
    /// never be conflated: treating lost signal as stale anchors would have a fleet re-fetching trust material
    /// every time the network blips.
    public static func probeAnchorsValidateEdge(host: String, port: Int, anchors: [SecCertificate],
                                                serverName: String = DsseLiveTransportServerName.current(),
                                                timeout: TimeInterval = 10) -> Bool? {
        // Holding NO anchors is decided without asking the network: a device with nothing to verify against
        // cannot verify anything, whether or not the Edge answers. Probing first would report "undetermined" for
        // an unreachable Edge and leave a device that has lost its anchor file waiting for a human.
        guard !anchors.isEmpty else { return false }
        // The name the transport sends, from the same place the handshake reads it — see servedChain. Asking a
        // different door than the tunnel uses is how this probe came to refuse a distribution the tunnel accepts.
        let name = serverName.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard let chain = servedChain(host: host, port: port, serverName: name, timeout: timeout) else {
            return nil
        }
        return chainValidates(chain, anchors: anchors, hostname: name.isEmpty ? host : name)
    }

    /// servedChain returns the certificate chain the Edge presents, WITHOUT validating it. Reading the chain is
    /// not trusting it — every use of it below is an explicit evaluation against pinned anchors.
    ///
    /// ★★★ IT MUST KNOCK ON THE DOOR THE TRANSPORT USES (2026-08-20, measured on the lab the moment roadmap D
    /// finished on the other platform).
    ///
    /// The Edge chooses which organization's certificate to present from the TLS server name, because a server
    /// has to choose before the client certificate arrives. This read went through URLSession at
    /// https://<address>:<port>/healthz, so it sent no name — and got the deployment-wide certificate signed by
    /// the SHARED authority. That was invisible while every bundle still carried the shared anchor. The instant
    /// the last step of roadmap D took the shared anchor out of one organization's bundle, this probe could no
    /// longer verify what it was reading, concluded the device could not verify the Edge, and REFUSED a
    /// distribution the device's own transport accepts without trouble.
    ///
    /// Safe, in that it fails towards "stay where you are" — and it means macOS can never finish the rotation
    /// this whole mechanism exists to perform. The Windows agent sent the name from the start and reached the
    /// end state first.
    ///
    /// So the name goes on the probe, from the same place the handshake reads it, and the certificate is then
    /// evaluated against that name rather than against an address it was never issued for.
    public static func servedChain(host: String, port: Int, serverName: String,
                                   timeout: TimeInterval = 10) -> [SecCertificate]? {
        let name = serverName.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if name.isEmpty {
            // No name announced: the deployment serves one certificate to everybody and this is unchanged.
            return servedChainWithoutServerName(host: host, port: port, timeout: timeout)
        }
        let captured = ChainBox()
        let options = NWProtocolTLS.Options()
        sec_protocol_options_set_min_tls_protocol_version(options.securityProtocolOptions, .TLSv12)
        sec_protocol_options_set_tls_server_name(options.securityProtocolOptions, name)
        sec_protocol_options_set_verify_block(options.securityProtocolOptions, { _, secTrustRef, complete in
            let trust = sec_trust_copy_ref(secTrustRef).takeRetainedValue()
            if let certs = SecTrustCopyCertificateChain(trust) as? [SecCertificate] {
                captured.set(certs)
            }
            // Reading is not trusting. The handshake is refused here on purpose: the caller evaluates the chain
            // against pinned anchors, and nothing this probe touches is allowed to carry traffic.
            complete(false)
        }, DispatchQueue(label: "jp.co.lantern-networks.dsse.trustprobe"))

        guard let nwPort = NWEndpoint.Port(rawValue: UInt16(truncatingIfNeeded: port)) else { return nil }
        let connection = NWConnection(host: NWEndpoint.Host(host), port: nwPort,
                                      using: NWParameters(tls: options))
        let done = DispatchSemaphore(value: 0)
        connection.stateUpdateHandler = { state in
            switch state {
            case .ready, .failed, .cancelled:
                done.signal()
            default:
                break
            }
        }
        connection.start(queue: DispatchQueue(label: "jp.co.lantern-networks.dsse.trustprobe.conn"))
        _ = done.wait(timeout: .now() + timeout)
        connection.cancel()
        let chain = captured.value()
        return chain.isEmpty ? nil : chain
    }

    /// probeServerName picks the name to knock with: the one the distribution being CONSIDERED announces, and
    /// the one this device is currently sending only when that distribution announces none.
    ///
    /// ★ THE ORDER IS THE POINT. A distribution that changes an organization's name carries the new one, and
    /// the certificate the Edge presents under it changes at the same moment. Probing with the name this device
    /// still holds would evaluate the new certificate against the old name and refuse a distribution that is
    /// correct — the same shape as probing with no name at all, which is the defect this function was extracted
    /// from: the Edge chooses which certificate to present from the name, so asking without one asks about a
    /// different certificate than the tunnel will meet.
    public static func probeServerName(offeredByBundle: String, liveOnThisDevice: String) -> String {
        let offered = offeredByBundle.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if !offered.isEmpty {
            return offered
        }
        return liveOnThisDevice.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    }

    /// ChainBox carries the chain out of the verify block, which runs on its own queue.
    private final class ChainBox: @unchecked Sendable {
        private let lock = NSLock()
        private var certs: [SecCertificate] = []
        func set(_ c: [SecCertificate]) { lock.lock(); certs = c; lock.unlock() }
        func value() -> [SecCertificate] { lock.lock(); defer { lock.unlock() }; return certs }
    }

    /// ★ PRIVATE, AND NAMED FOR WHAT IT DOES (2026-08-20, suggested from the Windows side after the same trap
    /// was measured there). Their agent never hit it because probe and dial take the name from ONE function, so
    /// asking a different door than the tunnel uses cannot happen by omission. The reachable API here now
    /// requires the caller to say which name it is asking about; this is the deliberate no-name case, for a
    /// deployment that serves one certificate to everybody.
    private static func servedChainWithoutServerName(host: String, port: Int,
                                                     timeout: TimeInterval = 10) -> [SecCertificate]? {
        let delegate = ChainCaptureDelegate()
        let session = URLSession(configuration: .ephemeral, delegate: delegate, delegateQueue: nil)
        defer { session.finishTasksAndInvalidate() }
        var request = URLRequest(url: URL(string: "https://\(host):\(port)/healthz")!)
        request.timeoutInterval = timeout
        let done = DispatchSemaphore(value: 0)
        session.dataTask(with: request) { _, _, _ in done.signal() }.resume()
        _ = done.wait(timeout: .now() + timeout + 5)
        let chain = delegate.chain
        return chain.isEmpty ? nil : chain
    }

    /// chainValidates evaluates a served chain against ONLY the given anchors — the same anchors-only rule the
    /// transport applies, so the probe cannot pass where the real handshake would fail.
    public static func chainValidates(_ chain: [SecCertificate], anchors: [SecCertificate], hostname: String) -> Bool {
        guard let leaf = chain.first, !anchors.isEmpty else { return false }
        var trust: SecTrust?
        let policy = SecPolicyCreateSSL(true, hostname as CFString)
        guard SecTrustCreateWithCertificates(chain as CFArray, policy, &trust) == errSecSuccess, let trust else {
            return false
        }
        _ = leaf
        guard SecTrustSetAnchorCertificates(trust, anchors as CFArray) == errSecSuccess,
              SecTrustSetAnchorCertificatesOnly(trust, true) == errSecSuccess else {
            return false
        }
        return SecTrustEvaluateWithError(trust, nil)
    }

    private final class ChainCaptureDelegate: NSObject, URLSessionDelegate {
        var chain: [SecCertificate] = []
        func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
            guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
                  let trust = challenge.protectionSpace.serverTrust else {
                completionHandler(.performDefaultHandling, nil)
                return
            }
            if let certs = SecTrustCopyCertificateChain(trust) as? [SecCertificate] {
                chain = certs
            }
            // Reading the chain is the whole purpose; the connection itself is then abandoned.
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }

    /// recoverIfNeeded runs the whole check: probe, and only on a trust failure fetch, verify and adopt.
    ///
    /// `fetchBundle` is injected so the decision logic can be tested without a network; production passes
    /// `fetchOverUnverifiedChannel`.
    public static func recoverIfNeeded(host: String, port: Int, bundleURL: URL,
                                       configDirectory: URL, pinnedPublicKeyHex: String,
                                       currentAnchors: [SecCertificate],
                                       fetchBundle: (URL) -> Data?,
                                       log: (String) -> Void = { _ in }) -> DsseTrustAnchorRecoveryOutcome {
        switch probeAnchorsValidateEdge(host: host, port: port, anchors: currentAnchors) {
        case .some(true):
            // Healthy — but "healthy" is not "current". A distribution the fleet has moved on to is adopted
            // here, in the ordinary case, rather than only as a rescue: a device that is only ever updated
            // once it breaks can never be brought onto a new CA BEFORE the old one is retired, which is the
            // whole mechanism an overlap-then-retire rotation depends on (2026-08-01: the reference Mac sat on
            // distribution 2 while the Edge served 3, and no amount of waiting would have moved it).
            return adoptNewerIfOffered(host: host, port: port, bundleURL: bundleURL,
                                       configDirectory: configDirectory, pinnedPublicKeyHex: pinnedPublicKeyHex,
                                       fetchBundle: fetchBundle, log: log)
        case .none:
            // Could not tell — the Edge was unreachable. Say so rather than acting on it.
            return .unrecovered(reason: "edge unreachable; anchor validity undetermined")
        case .some(false):
            break
        }
        log("trust_anchor_recovery anchors no longer validate the Edge — fetching the signed trust bundle")

        guard let data = fetchBundle(bundleURL) else {
            return .unrecovered(reason: "trust bundle could not be fetched")
        }
        let lastSerial = DsseAdoptedTrustAnchorStore.lastAcceptedSerial(configDirectory: configDirectory)
        guard let bundle = DsseSignedTrustBundle.verified(
                envelopeData: data, pinnedPublicKeyHex: pinnedPublicKeyHex, lastAcceptedSerial: lastSerial,
                alsoAccept: DsseAdoptedTrustAnchorStore.acceptedAgentPolicyKeys(configDirectory: configDirectory)) else {
            // Includes the replay case: a bundle at or below the accepted serial is refused, so an attacker who
            // can serve this device anything cannot walk it back onto a withdrawn CA.
            return .unrecovered(reason: "trust bundle failed verification (signature, schema, or serial)")
        }
        do {
            let adopted = try DsseAdoptedTrustAnchorStore.install(bundle, configDirectory: configDirectory)
            log("trust_anchor_recovery ADOPTED serial=\(adopted.serial) anchors=\(adopted.fingerprints.count)")
            return .adopted(serial: adopted.serial, anchors: adopted.fingerprints.count)
        } catch {
            return .unrecovered(reason: "adopting the verified bundle failed: \(error)")
        }
    }

    /// adoptNewerIfOffered takes a newer signed distribution on a device that is currently FINE. It is the
    /// routine half of the mechanism; recoverIfNeeded is the emergency half.
    ///
    /// The check that matters is the last one: a new anchor set is only installed once this device has
    /// confirmed it can still verify the Edge with it. The Edge cannot make that judgement — it does not know
    /// what any device holds — so a distribution that would strand this machine is refused here, loudly,
    /// leaving it on anchors that work.
    static func adoptNewerIfOffered(host: String, port: Int, bundleURL: URL,
                                    configDirectory: URL, pinnedPublicKeyHex: String,
                                    fetchBundle: (URL) -> Data?,
                                    log: (String) -> Void = { _ in }) -> DsseTrustAnchorRecoveryOutcome {
        let lastSerial = DsseAdoptedTrustAnchorStore.lastAcceptedSerial(configDirectory: configDirectory)
        guard let data = fetchBundle(bundleURL) else {
            // Not an error worth acting on: the device is healthy and stays as it is.
            return .anchorsStillValid
        }
        guard let bundle = DsseSignedTrustBundle.verified(
                envelopeData: data, pinnedPublicKeyHex: pinnedPublicKeyHex, lastAcceptedSerial: lastSerial,
                alsoAccept: DsseAdoptedTrustAnchorStore.acceptedAgentPolicyKeys(configDirectory: configDirectory)) else {
            // Nothing newer on offer is the common case and is silent; a bundle at or below the accepted
            // serial is refused by the same rule that blocks a rollback onto a withdrawn CA.
            return .anchorsStillValid
        }
        let offered = DsseTransportSecurityFactory.certificates(fromPEM: bundle.anchorsPEM)
        guard !offered.isEmpty else {
            log("trust_anchor_adoption serial=\(bundle.serial) NOT adopted: the bundle carried no usable anchor")
            return .anchorsStillValid
        }
        // ★ The name this organization is announced, and the one its certificate is issued for. Taken from the
        // bundle just verified rather than from the running transport, so a device adopting a distribution that
        // CHANGES the name evaluates against the new one — the announcement and the certificate move together.
        let probeName = probeServerName(offeredByBundle: bundle.transportServerName,
                                        liveOnThisDevice: DsseLiveTransportServerName.current())
        // ★★★ DO NOT JUDGE BEFORE THIS DEVICE CAN BE ASKED ITS NAME (2026-09-06, measured on a lab that then
        // had a live deployment changed on the strength of the line this produced).
        //
        // The organization's door is chosen by SNI. With no name the probe is served the deployment-wide
        // certificate, the organization's own anchors correctly fail to validate it, and this refused — a
        // minute later, with the provider installed, it adopted the SAME serial and the SAME anchors. Read as
        // written, the first line says a device is permanently refusing a distribution. It was read that way.
        //
        // Not knowing the name yet is the same class of answer as not being able to read the served chain:
        // this device could not judge, so it says so and keeps what it has. A deployment that genuinely serves
        // one certificate to everybody is unaffected — its provider IS installed and answers "", and probing
        // without a name is right there.
        if probeName.isEmpty && !DsseLiveTransportServerName.hasBeenAsked() {
            log("trust_anchor_adoption serial=\(bundle.serial) NOT JUDGED YET: this device has not been asked " +
                "which name it presents, and its organization's door is chosen by that name — re-judged on the " +
                "next tick, keeping the current anchors until then")
            return .anchorsStillValid
        }
        guard let chain = servedChain(host: host, port: port, serverName: probeName), !chain.isEmpty else {
            log("trust_anchor_adoption serial=\(bundle.serial) NOT adopted: the served chain could not be read")
            return .anchorsStillValid
        }
        guard chainValidates(chain, anchors: offered, hostname: probeName.isEmpty ? host : probeName) else {
            log("trust_anchor_adoption REFUSED serial=\(bundle.serial) anchors=\(offered.count) " +
                "name=\(probeName.isEmpty ? "(none sent)" : probeName) — this device cannot verify the Edge " +
                "with them; staying on the current anchors. THIS IS RE-JUDGED EVERY TICK and adopting later " +
                "is the ordinary outcome — do not read one of these lines as a permanent refusal")
            return .refusedWouldStrandSelf(serial: bundle.serial,
                                           reason: "the offered anchors do not validate the served chain")
        }
        do {
            let adopted = try DsseAdoptedTrustAnchorStore.install(bundle, configDirectory: configDirectory)
            log("trust_anchor_adoption ADOPTED serial=\(adopted.serial) anchors=\(adopted.fingerprints.count) " +
                "(device was healthy; verified against the served chain first)")
            return .adoptedWhileHealthy(serial: adopted.serial, anchors: adopted.fingerprints.count)
        } catch {
            log("trust_anchor_adoption serial=\(bundle.serial) NOT adopted: \(error)")
            return .anchorsStillValid
        }
    }

    /// fetchOverUnverifiedChannel gets the bundle WITHOUT validating the server certificate.
    ///
    /// That is not a weakening: this runs precisely when the device cannot validate the Edge, and the document's
    /// authenticity comes from its signature. Validating here would make the fallback unusable in the only
    /// situation it exists for. Nothing read from this response is used before it verifies.
    public static func fetchOverUnverifiedChannel(_ url: URL, timeout: TimeInterval = 15) -> Data? {
        let delegate = UnverifiedChannelDelegate()
        let session = URLSession(configuration: .ephemeral, delegate: delegate, delegateQueue: nil)
        defer { session.finishTasksAndInvalidate() }
        var out: Data?
        let done = DispatchSemaphore(value: 0)
        var request = URLRequest(url: url)
        request.timeoutInterval = timeout
        session.dataTask(with: request) { data, response, _ in
            defer { done.signal() }
            guard let http = response as? HTTPURLResponse, http.statusCode == 200 else { return }
            out = data
        }.resume()
        _ = done.wait(timeout: .now() + timeout + 5)
        return out
    }

    private final class UnverifiedChannelDelegate: NSObject, URLSessionDelegate {
        func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
            guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
                  let trust = challenge.protectionSpace.serverTrust else {
                completionHandler(.performDefaultHandling, nil)
                return
            }
            completionHandler(.useCredential, URLCredential(trust: trust))
        }
    }
}
