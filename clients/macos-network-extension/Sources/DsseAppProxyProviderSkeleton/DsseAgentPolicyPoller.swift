import Foundation

// DsseAgentPolicyPoller — the PRODUCTION mechanism for admin-managed signed steer exclusions on the
// endpoint. The NE itself PULLS the Edge's signed steer-exclusion policy over the (T) mTLS transport it
// already uses for steering, VERIFIES it against the pinned Ed25519 key (provisioned by MDM in the
// root-owned agent_config — NOT by any human/shell command), applies the result live, and caches the
// verified envelope for restart/offline resilience.
//
// This replaces the lab `activate_signed_steer_exclusions.sh` scaffold: there is NO client-side command
// work in production — config changes in the admin console propagate to the device automatically on the
// next poll. Mirrors the Windows agent's exclusionSync (cmd/windivert-steer/steer_exclusion_sync.go).
//
// Fail-safe: a fetch/verify failure does NOT clear the current set (a transient Edge outage must never
// drop exclusions and start steering an excluded app). Fail-closed: an unverifiable policy is never applied.
public final class DsseAgentPolicyPoller: @unchecked Sendable {
    private let session: URLSession
    // ★★★ THE NAME THIS CHANNEL DIALS WITH (2026-08-22, measured — the day this device stopped reporting).
    //
    // URLSession sends the URL's host as the TLS server name and offers no way to send another, so this
    // poller — the ONE channel every readiness gate in the product is measured from — reached the Edge
    // WITHOUT its organization's name and was served the deployment-wide certificate, while the tunnel
    // beside it was served the organization's own. That is invisible until the shared anchor is withdrawn,
    // which is the last step of roadmap D; then this device is locked out of reporting and nothing else
    // changes, so it keeps browsing and looks healthy.
    //
    // When both a transport and a name are available the request goes over DsseSingleRequestOverNW instead,
    // which was written for exactly this and builds its TLS with makeTunnelParameters — same identity, same
    // live anchors, same fail-closed verify block. Without them the URLSession path is used unchanged, which
    // is what every injected-session test does.
    private let namedTransport: DsseTransportSecurity?
    private let serverName: () -> String
    private let url: URL
    private let pinnedPublicKeyHex: String
    /// Additional policy-signing keys this device has adopted from a verified trust bundle. Resolved fresh on
    /// every poll rather than captured once: adopting a bundle is what puts a key here, and a poller holding
    /// the set it was born with would never see the key that arrives afterwards — the same start-up-capture
    /// mistake that hid an anchor rotation and a certificate renewal earlier in this project.
    private let acceptedKeys: () -> [String]
    private let cachePath: String?
    private let queue = DispatchQueue(label: "dsse.agent-policy-poller")
    private static let logLabel = "agent-policy fetch"
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
                // ★ THE OTHER HALF OF THE PAIR, IN THE SAME PLACE. The fetch and the report share one channel,
                // one identity and one name. Read side by side, "the fetch works and the report does not" and
                // "nothing on this channel works" are different faults with different fixes; read apart, both
                // look like a device that has gone quiet. Written on transition only, so a working device
                // writes nothing here.
                DsseAgentReportJournal.record("policy fetch RECOVERED after \(consecutiveFailures) consecutive failure(s)")
                consecutiveFailures = 0
            }
            lastFailure = nil
            return
        }
        consecutiveFailures += 1
        lastFailure = reason
        if consecutiveFailures == 1 || consecutiveFailures % 10 == 0 {
            dsseRuntimeLog("\(Self.logLabel) FAILED (\(consecutiveFailures) consecutive): \(reason) — the device keeps its previous state, so nothing looks broken from here")
            DsseAgentReportJournal.record("policy fetch FAILED (\(consecutiveFailures) consecutive): \(reason) "
                + "— the device keeps its previous state, so nothing looks broken from here")
        }
    }

    private var timer: DispatchSourceTimer?
    // Non-Sendable on purpose: the consumer (the NE provider) captures itself to swap its lock-protected
    // exclusion policy. The poller is @unchecked Sendable and only ever calls this on its own queue.
    private var onUpdate: (([String]?) -> Void)?

    // agentPolicyURL composes the signed-policy URL from the (T) transport host/port.
    public static func agentPolicyURL(security: DsseTransportSecurity, path: String = "/steer/agent-policy") -> URL? {
        var p = path.trimmingCharacters(in: .whitespacesAndNewlines)
        if p.isEmpty { p = "/steer/agent-policy" }
        if !p.hasPrefix("/") { p = "/" + p }
        return URL(string: "https://\(security.dialHost):\(security.port)\(p)")
    }

    // Production initializer: build the pinned (T) URLSession from the transport security. Returns nil ONLY
    // when the URL can't be composed from the transport.
    //
    // An empty pin used to return nil here, and that quietly defeated the reporting gate above it: the caller
    // had already stopped requiring a pin, but this refused to construct, so the caller's guard failed anyway
    // and blamed the transport in its log. A poller with no pin is a legitimate object — it reports, and it
    // verifies nothing (fetchVerifiedExclusions still yields nil, because an empty pin cannot verify anything).
    public init?(security: DsseTransportSecurity, pinnedPublicKeyHex: String, cachePath: String?,
                 acceptedKeys: @escaping () -> [String] = { [] }) {
        let keyHex = pinnedPublicKeyHex.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let url = Self.agentPolicyURL(security: security) else { return nil }
        self.session = DsseTransportTLS.makePinnedURLSession(security: security, channel: "agent-policy")
        self.url = url
        self.pinnedPublicKeyHex = keyHex
        self.acceptedKeys = acceptedKeys
        self.cachePath = cachePath
        self.namedTransport = security
        // Read per request, never captured: the name arrives in a trust bundle after start-up, exactly like
        // the anchors, and a value captured here would be the one this device was born with.
        self.serverName = { DsseLiveTransportServerName.current() }
    }

    // Test/seam initializer: inject the session + URL directly.
    public init(session: URLSession, url: URL, pinnedPublicKeyHex: String, cachePath: String? = nil,
                acceptedKeys: @escaping () -> [String] = { [] }) {
        self.session = session
        self.url = url
        self.pinnedPublicKeyHex = pinnedPublicKeyHex.trimmingCharacters(in: .whitespacesAndNewlines)
        self.acceptedKeys = acceptedKeys
        self.cachePath = cachePath
        self.namedTransport = nil
        self.serverName = { "" }
    }


    /// namedRoute answers whether this poller can reach the Edge under its organization's transport name, and
    /// with what. Nil means "dial by address over URLSession", which is what an injected-session test does and
    /// what a deployment with no per-organization transport authority does.
    private func namedRoute() -> (security: DsseTransportSecurity, name: String)? {
        let name = serverName().trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard let transport = namedTransport, !name.isEmpty else { return nil }
        return (transport, name)
    }

    /// transportServerNameSent is what this channel ACTUALLY put in its ClientHello — the organization's name
    /// when the folded route is in use, and NOTHING when this poller is still dialling by address.
    ///
    /// ★ Empty is a silence, not a claim, and it is the correct answer here. A device reaching this Edge by
    /// address is served the deployment-wide certificate, so the shared anchor may not be withdrawn from its
    /// organization yet — and the Edge's gate reads exactly this field to decide that. Reporting the name this
    /// device HOLDS instead of the one it SENDS would open that gate and lock the device out, which is the
    /// failure this field was added after.
    func transportServerNameSent() -> String {
        namedRoute()?.name ?? ""
    }

    // fetchVerifiedExclusions GETs the signed policy over (T), verifies it against the pinned key, and
    // returns the verified server-issued exclusion set (or nil on any network/verify failure). On success
    // it also writes the raw verified envelope to the cache path (best-effort) for restart/offline use.
    public func fetchVerifiedExclusions(completion: @escaping @Sendable ([String]?) -> Void) {
        if let route = namedRoute() {
            let path = url.path.isEmpty ? "/" : url.path
            do {
                let answer = try DsseSingleRequestOverNW.get(
                    host: route.security.host, port: route.security.port, serverName: route.name,
                    path: path, security: route.security, timeout: 15)
                guard answer.status == 200 else {
                    noteFetchOutcome(failure: "HTTP \(answer.status)"); completion(nil); return
                }
                guard !answer.body.isEmpty else {
                    noteFetchOutcome(failure: "empty body"); completion(nil); return
                }
                guard let excluded = DsseSignedAgentPolicy.verifiedServerExclusions(
                          envelopeData: answer.body, pinnedPublicKeyHex: pinnedPublicKeyHex,
                          alsoAccept: acceptedKeys()) else {
                    noteFetchOutcome(failure: "signature NOT verified against pin \(pinnedPublicKeyHex.prefix(12))… (+\(acceptedKeys().count) adopted key(s)) — admin exclusions authored for this device are NOT being applied")
                    completion(nil); return
                }
                noteFetchOutcome(failure: nil)
                writeCache(answer.body)
                completion(excluded)
            } catch {
                noteFetchOutcome(failure: "transport (named \(route.name)): \(error.localizedDescription)")
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
                self.noteFetchOutcome(failure: "transport: \(err.localizedDescription)")
                completion(nil); return
            }
            guard let http = resp as? HTTPURLResponse else {
                self.noteFetchOutcome(failure: "no HTTP response"); completion(nil); return
            }
            guard http.statusCode == 200 else {
                self.noteFetchOutcome(failure: "HTTP \(http.statusCode)"); completion(nil); return
            }
            guard let data, !data.isEmpty else {
                self.noteFetchOutcome(failure: "empty body"); completion(nil); return
            }
            guard let excluded = DsseSignedAgentPolicy.verifiedServerExclusions(
                      envelopeData: data, pinnedPublicKeyHex: self.pinnedPublicKeyHex,
                      alsoAccept: self.acceptedKeys()) else {
                self.noteFetchOutcome(failure: "signature NOT verified against pin \(self.pinnedPublicKeyHex.prefix(12))… (+\(self.acceptedKeys().count) adopted key(s)) — admin exclusions authored for this device are NOT being applied")
                completion(nil); return
            }
            self.noteFetchOutcome(failure: nil)
            self.writeCache(data)
            completion(excluded)
        }.resume()
    }

    // reportEffective POSTs the device's MERGED effective steer-exclusion set (the floor + scaffold + verified
    // server overlay) back to the Edge over the same pinned (T) transport, so an admin console can observe what
    // the device ACTUALLY excludes — including the hardcoded self-exclusion the server never issued. This is
    // REVERSE telemetry only: additive, best-effort, fail-safe. It NEVER changes steering/enforcement. The Edge
    // keys the report to the cert-proven device identity (the (T) mTLS client cert), so NO device id is sent.
    // Network/HTTP errors are ignored (success = HTTP 204); there is no retry and it never blocks.
    // Phase 1a device steer-state: the same report also carries the device's LIVE steering state so the admin
    // console can show it (posture / fail-open / region-failover), matching the Windows agent's Phase 1a fields.
    // The wire keys + posture vocabulary MUST match the edge parser (normalizeReportedPosture / POST
    // /steer/agent-policy/effective) exactly, or the edge drops the field to NULL. Defaults keep it a no-op for
    // any caller that doesn't yet source the state.
    // pinnedCAFingerprints is the SHA-256 of every transport CA this device pins. It is the readiness signal
    // for a CA rotation: an operator must know which devices already hold the incoming CA before switching to
    // it, because a device that missed the changeover cannot recover on its own — it can no longer verify the
    // Edge, and the new CA would have arrived over the tunnel it can no longer establish. Empty simply omits
    // the field, and the Edge then counts this device as SILENT rather than ready, which is the safe reading.
    /// Attaches the recovery name this device holds, normalised the way the Edge compares it, and attaches
    /// NOTHING when it holds none — a device that says nothing is counted as "not yet", and an empty string
    /// would be a claim rather than a silence.
    static func attachRecoverySNI(_ body: inout [String: Any], held: String, resolvedTarget: String = "") {
        let name = held.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if !name.isEmpty {
            body["renewal_recovery_sni_sent"] = name
        }
        // ★ AND WHERE THIS DEVICE WOULD ACTUALLY DIAL. Reported from win-dev-1 on 2026-08-20: holding the name
        // and resolving a destination were two different pieces of code there, so it reported the name and
        // would still have dialled the port that had just been closed. The Edge closes that port on this
        // field now, not on the name.
        let target = resolvedTarget.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if !target.isEmpty {
            body["renewal_recovery_target"] = target
        }
    }

    /// attachTransportServerName attaches the name this device SENDS on the reporting channel, and attaches
    /// NOTHING when it sends none. Same shape as attachRecoverySNI beside it, and the same reason: an empty
    /// string is a claim, and the Edge must be able to tell "dialling by address" from "did not report".
    static func attachTransportServerName(_ body: inout [String: Any], sent: String) {
        let name = sent.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if !name.isEmpty {
            body["transport_server_name_sent"] = name
        }
    }

    public func reportEffective(_ ids: [String], serverCount: Int, ignored: [String] = [],
                                posture: String = "", failOpenConfigured: Bool = false,
                                regionFailoverEnabled: Bool = false, activeRegion: String = "",
                                pinnedCAFingerprints: [String] = [],
                                adoptedTrustSerial: Int64 = 0,
                                renewalRecoverySNIHeld: String = "",
                                renewalRecoveryTargetResolved: String = "",
                                interceptionRootSHA256: [String] = [],
                                interceptionRootPin: String = "",
                                trustRefusals: [DsseTrustRefusal] = [],
                                fallbackClientCertPEM: String = "",
                                agentPolicyPublicKeys: [String] = [],
                                onRefusalsAccepted: (([DsseTrustRefusal]) -> Void)? = nil) {
        // Derive the sibling /effective endpoint from the agent-policy URL, keeping scheme/host/port. The
        // agent-policy URL is …/steer/agent-policy, so this yields the fixed contract …/steer/agent-policy/effective.
        let reportURL = url.appendingPathComponent("effective")
        var body: [String: Any] = [
            "platform": "macos",
            "effective_app_signing_ids": ids.sorted(),
            "server_app_signing_id_count": serverCount,
            // What this device received and deliberately did not apply. Reported so the console states the
            // device's own reason instead of inferring one from the AppID's shape — an inference that drifts
            // the moment the agent's parser changes. Empty is a valid answer, not a missing one.
            "ignored_app_signing_ids": ignored.sorted(),
            "posture": posture,                                   // steering|disarmed|dark|stopped|error (edge enum)
            "fail_open_configured": failOpenConfigured,
            "region_failover_enabled": regionFailoverEnabled,
            "active_region": activeRegion,
            "server_initiated_rule_count": 0,                     // no inbound-runtime rule count on this path (matches Windows)
        ]
        // ★ DEVICE POSTURE ON THIS CHANNEL, and the reason is a measured gap rather than symmetry with Windows.
        //
        // Disk encryption and application firewall were reported ONLY as headers on the steer-mux CONNECT, so a
        // device reported them as a side effect of CARRYING TRAFFIC. Measured on the reference Edge, 2026-08-10:
        // mac-dev-1 had NO device-runtime record at all while win-dev-1 had a full one — and the Console
        // therefore said the NE reports neither signal. The collector was fine (fdesetup and socketfilterfw both
        // answer exactly what the parser expects on this machine); the channel was the problem.
        //
        // This report already goes out every 15 s over the (T) transport, keyed to the cert-proven identity, on
        // a device that may be enrolled and alive without steering anything at that moment. Posture belongs on
        // it for the same reason presence does: a fleet view that only sees the machines currently carrying
        // traffic is a fleet view that quietly under-reports exactly the devices an operator is looking for.
        //
        // Collected here rather than passed in, so no caller can forget to supply it and turn a compliant
        // machine into an unreported one. nil stays absent: a signal that could not be read is never guessed.
        let devicePosture = DsseDevicePosture.collect()
        if let enc = devicePosture.encryption {
            body["disk_encryption_enabled"] = enc
        }
        if let fw = devicePosture.firewall {
            body["firewall_enabled"] = fw
        }
        body["posture_source"] = "macos_collector"
        body["device_os"] = DsseDevicePosture.osDescription()
        if !pinnedCAFingerprints.isEmpty {
            body["pinned_transport_ca_sha256"] = pinnedCAFingerprints
        }
        // ★ WHICH INTERCEPTION ROOT THIS AGENT IS PINNED TO — a different fact from the ones it HOLDS, and the
        // one that decides whether an authority may stop being announced.
        //
        // The Edge keeps the outgoing root announced during a replacement so devices pinned to it keep working,
        // and ends that overlap by withdrawing it. "Every device holds the new root" does not make that safe:
        // an agent pinned to the old one stands aside the moment the Edge stops naming it, whatever else is in
        // its trust store. Without this field the Edge cannot tell who has moved, and its choices are to block
        // every withdrawal forever or to guess.
        //
        // Empty is omitted, and the Edge reads a device that says nothing as UNKNOWN rather than as moved —
        // which is the safe direction and the one that keeps this field honest while agents are still being
        // upgraded to send it.
        if !interceptionRootPin.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            body["interception_root_pin_sha256"] = interceptionRootPin.lowercased()
        }
        // WHICH distribution these anchors came from. Fingerprints alone let a device look ready while it is
        // still verifying against an older set: the Edge can compare what it distributes with what a device
        // holds, but not with what that device is actually USING, and those came apart on 2026-08-01.
        if adoptedTrustSerial > 0 {
            body["adopted_trust_serial"] = adoptedTrustSerial
        }
        // ★ THE RECOVERY NAME THIS DEVICE HOLDS — the fact that decides whether the dedicated recovery port
        // may be closed. Windows shipped this field first; this agent did not send it, so the question had no
        // answer from half the fleet and the port could not honestly be retired.
        //
        // Omitted when empty, and the Edge reads a device that says nothing as NOT YET rather than as ready.
        // The devices that need the recovery path are the ones that were switched off when the name was
        // announced, so silence is the one reading that must never open the gate.
        DsseAgentPolicyPoller.attachRecoverySNI(&body, held: renewalRecoverySNIHeld,
                                                resolvedTarget: renewalRecoveryTargetResolved)
        // ★★★ THE NAME THIS DEVICE ACTUALLY SENDS ON THIS CHANNEL — never reported by this agent until now.
        //
        // Windows has shipped it since 0.2.10. macOS had no parameter and no body key, so every Edge-side
        // measurement that turns on it — the enrolment fold, a transport-name rename, and the withdrawal of an
        // organization's shared anchor — read this device as SILENT for ever. Two implementations happened to
        // arrive at the Edge with the field empty at the same time, which read as the Edge dropping it; it was
        // not, and half of it was simply never sent.
        //
        // Resolved from the route this request is taking, not from what the device holds — same rule as the
        // recovery target beside it, and for the same reason: holding a name and dialling it were two
        // different pieces of code, and they disagreed.
        DsseAgentPolicyPoller.attachTransportServerName(&body, sent: transportServerNameSent())
        // Which of the interception roots the Edge advertised were actually found in this machine's trust
        // store. Omitted entirely when none were found, so the Edge can tell "looked and found nothing" from
        // "this agent does not report" — reading those the same way leads to opposite mistakes.
        if !interceptionRootSHA256.isEmpty {
            body["pinned_interception_root_sha256"] = interceptionRootSHA256
        }
        // The credential this device would FALL BACK to — the certificate only, never key material. The Edge's
        // retire gate reads it: a CA that issues a fleet's bootstrap credentials must not be retired while a
        // device can still fall back to one (2026-08-02). Omitted when unknown; the Edge then simply applies
        // no additional constraint, exactly as before this field existed.
        if !fallbackClientCertPEM.isEmpty {
            body["fallback_client_cert_pem"] = fallbackClientCertPEM
        }
        // The policy-signing keys this device would accept — its pin PLUS any key adopted from a trust bundle.
        // This is what lets the Edge see, before switching the config-signing key, that this device has taken
        // the next key; signing to a key it does not hold would freeze it. The EFFECTIVE set, not the adopted
        // part alone, because the question is "would this device verify a policy signed by key X", which the
        // adopted subset cannot answer without also knowing the pin. Omitted when only the pin is configured.
        if !agentPolicyPublicKeys.isEmpty {
            body["agent_policy_public_keys"] = agentPolicyPublicKeys
        }
        // What this device REFUSED, late by necessity: a refusal cannot travel over the connection it caused
        // to fail, so it is carried on the first one that works. Without it, a fleet that declined a
        // certificate is indistinguishable from a fleet that is switched off (2026-07-31).
        if !trustRefusals.isEmpty {
            let encoder = JSONEncoder()
            encoder.dateEncodingStrategy = .iso8601
            if let blob = try? encoder.encode(trustRefusals),
               let asJSON = try? JSONSerialization.jsonObject(with: blob) {
                body["trust_refusals"] = asJSON
            }
        }
        guard let payload = try? JSONSerialization.data(withJSONObject: body) else { return }
        if let route = namedRoute() {
            let path = reportURL.path.isEmpty ? "/" : reportURL.path
            do {
                let answer = try DsseSingleRequestOverNW.post(
                    host: route.security.host, port: route.security.port, serverName: route.name,
                    path: path, body: payload, security: route.security, timeout: 10)
                // ★★★ AND IT SAYS WHETHER IT LANDED (2026-08-22). This was fire-and-forget on both paths: the
                // closure below decided only whether to clear the refusal journal and threw the outcome away
                // otherwise. So this device logged "reporting it anyway so the Edge does not lose sight of
                // this device" once a minute for over two hours while not one report reached the Edge, and
                // nothing on the device said so. A report nobody confirms is a report nobody can miss.
                if (200...299).contains(answer.status) {
                    if !trustRefusals.isEmpty { onRefusalsAccepted?(trustRefusals) }
                    DsseAgentReportJournal.record("report LANDED name=\(route.name) host=\(route.security.host) "
                        + "port=\(route.security.port) path=\(path) status=\(answer.status)")
                } else {
                    dsseRuntimeLog("agent_report ★ REFUSED by the Edge status=\(answer.status) name=\(route.name) "
                        + "— this device is not being observed, and every readiness gate reads it as silent")
                    DsseAgentReportJournal.record("report REFUSED by the Edge name=\(route.name) "
                        + "host=\(route.security.host) port=\(route.security.port) path=\(path) "
                        + "status=\(answer.status) — every readiness gate reads this device as silent")
                }
            } catch {
                dsseRuntimeLog("agent_report ★ DID NOT REACH the Edge name=\(route.name): "
                    + "\(error.localizedDescription) — this device is not being observed, and every readiness "
                    + "gate reads it as silent")
                DsseAgentReportJournal.record("report DID NOT REACH the Edge name=\(route.name) "
                    + "host=\(route.security.host) port=\(route.security.port) path=\(path) "
                    + "reason=\(error.localizedDescription) — every readiness gate reads this device as silent")
            }
            return
        }
        var req = URLRequest(url: reportURL)
        req.httpMethod = "POST"
        req.timeoutInterval = 10
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = payload
        session.dataTask(with: req) { _, response, error in
            // Best-effort reverse telemetry: the applied-exclusions half is never retried. The REFUSALS half
            // is different — it is the only copy — so it is dropped only once the Edge has actually taken it.
            // Anything else (no response, an error, a non-2xx) keeps it for the next poll.
            let http = response as? HTTPURLResponse
            let landed = error == nil && (http.map { (200...299).contains($0.statusCode) } ?? false)
            if !landed {
                // Said out loud on this path too — see the named route above. The whole cost of this outage
                // was that the device believed it had reported.
                dsseRuntimeLog("agent_report ★ DID NOT REACH the Edge by address: "
                    + "\(error?.localizedDescription ?? "HTTP \(http?.statusCode ?? -1)") — this device is not "
                    + "being observed, and every readiness gate reads it as silent")
                DsseAgentReportJournal.record("report DID NOT REACH the Edge by address url=\(reportURL.absoluteString) "
                    + "reason=\(error?.localizedDescription ?? "HTTP \(http?.statusCode ?? -1)") "
                    + "— every readiness gate reads this device as silent")
                return
            }
            DsseAgentReportJournal.record("report LANDED by address url=\(reportURL.absoluteString) "
                + "status=\(http?.statusCode ?? -1)")
            guard !trustRefusals.isEmpty else { return }
            onRefusalsAccepted?(trustRefusals)
        }.resume()
    }

    // start fetches immediately, then every interval, delivering the result of each poll to onUpdate: the
    // verified set, or nil when nothing verified this tick (network error, non-200, bad signature, no pin).
    //
    // onUpdate fires on EVERY tick, including the nil ones. It used to fire only on success, which made the
    // caller's periodic reverse-telemetry report a hostage of policy verification: a device whose pin no
    // longer matched the Edge's signing key stopped reporting entirely, so it aged out of the fleet view and
    // became indistinguishable from a device that was switched off — the failure found on mac-dev-1,
    // 2026-08-05. Verification decides what is APPLIED; it must not decide whether the device SPEAKS.
    //
    // nil still means "keep the last applied set" — fail-safe is unchanged. It is the caller's job to apply
    // only on non-nil and to report on both.
    public func start(interval: TimeInterval, onUpdate: @escaping ([String]?) -> Void) {
        // Set synchronously (start is called once at startProxy, before the first poll fires) so the
        // @Sendable dispatch closures below capture only `self` (the @unchecked Sendable poller), never the
        // non-Sendable onUpdate parameter.
        self.onUpdate = onUpdate
        // ★ SAID ONCE, SO AN EMPTY JOURNAL MEANS SOMETHING. Without this line a journal with no entries reads
        // the same for a device that never armed this channel and a device that armed it and failed every
        // attempt — and those two have opposite causes.
        let namedRouteAnswer = namedTransport == nil
            ? "no — reports go by address, without this organization's name"
            : "yes"
        DsseAgentReportJournal.record("report channel ARMED interval=\(Int(interval))s "
            + "url=\(url.absoluteString) named_route=\(namedRouteAnswer)")
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
        fetchVerifiedExclusions { [weak self] excluded in
            guard let self else { return }
            // excluded == nil is delivered too. The caller keeps its current set (fail-safe) and still
            // reports; see start(interval:onUpdate:).
            self.queue.async { self.onUpdate?(excluded) }
        }
    }

    private func writeCache(_ data: Data) {
        guard let cachePath, !cachePath.isEmpty else { return }
        try? data.write(to: URL(fileURLWithPath: cachePath), options: .atomic)
    }
}
