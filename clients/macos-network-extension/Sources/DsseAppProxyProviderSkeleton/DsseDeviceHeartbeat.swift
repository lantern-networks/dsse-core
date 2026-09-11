import Foundation
import Security

// Endpoint liveness for macOS: a periodic authenticated heartbeat to the Edge over the same (T) mTLS
// transport the data path uses, so stopping the agent is VISIBLE.
//
// Why this exists (2026-08-05). The Windows agent has had this since W-2; macOS never did. The whole outbound
// surface of this extension was the data path plus /steer/agent-policy, /steer/dns-query and
// /steer/region-endpoints — nothing that says "I am still here". The Edge's device liveness for a Mac was
// therefore a SIDE EFFECT of steering: the steer-mux CONNECT handler stamps last_seen, so the device looked
// alive only while it happened to be carrying traffic. mac-dev-1's last_seen sat at 2026-07-25 while the box
// was steering all day.
//
// The consequence is the one that matters: with no purpose-built signal, killing the extension is
// indistinguishable from closing the laptop. An agent that can be switched off without the control plane
// noticing is the gap the agent-disablement threat model is about, and macOS had no coverage.
//
// Two deliberate departures from the Windows agent:
//
//   * NO POSTURE IN THE HEARTBEAT. The Edge re-derives device trust from any posture block it receives
//     (DerivePostureTrustLevel), against a policy whose defaults require disk encryption, firewall AND screen
//     lock. This collector reads the first two and cannot read screen lock, so attaching posture here would
//     drop this Mac from `managed` to `noncompliant` the moment liveness was switched on — which is exactly
//     what happened to win-dev-1, whose heartbeat carries only enforcement_agent_healthy and which has been
//     noncompliant ever since. A heartbeat is a liveness signal; it must not quietly re-decide trust with a
//     signal set it knows is incomplete. Posture keeps arriving on the CONNECT headers, where it is complete
//     enough to mean something. Trust changes on evidence, and absence of a field is not evidence.
//
//   * NO SELF-REGISTRATION. Windows registers itself when the Edge answers 404. Enrollment is the control
//     plane's to grant; an agent that can enroll itself on a 404 is an agent that can walk into a tenant. A
//     404 is reported loudly and retried on the next tick instead.
//
// Gated on the (T) transport and NOT on the agent-policy pin, for the same reason reporting is
// (DsseAgentReportingGate): the Edge needs to know WHICH device is speaking, and nothing else.
public enum DsseDeviceHeartbeat {

    // The agent version this build actually is, from the bundle Info.plist: "<short>+<build>", e.g.
    // "0.1.0+20260805164016" — the redeploy stamps CFBundleVersion with a UTC build timestamp.
    //
    // Not a hardcoded product name. The Windows agent reports the literal "wfp-steer" for agent_version, which
    // is a steering-backend name, so nobody can read a fleet's version distribution off the Console — the gap
    // written up as step 0 of docs/agent_auto_update_design.ja.md. Reporting a real version here is that step,
    // for this platform.
    public static func agentVersion(bundle: Bundle = .main) -> String {
        let short = (bundle.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String) ?? ""
        let build = (bundle.object(forInfoDictionaryKey: "CFBundleVersion") as? String) ?? ""
        switch (short.isEmpty, build.isEmpty) {
        case (false, false): return "\(short)+\(build)"
        case (false, true):  return short
        case (true, false):  return build
        case (true, true):   return "unknown"
        }
    }

    // The device identity, taken from the CN of the (T) client certificate. The Edge derives the identity from
    // the VERIFIED client cert and ignores what the body claims, so this is only what the body says about
    // itself — and taking it from the same certificate keeps the two from disagreeing.
    public static func deviceIdentity(from identity: SecIdentity?) -> String? {
        guard let identity else { return nil }
        var certificate: SecCertificate?
        guard SecIdentityCopyCertificate(identity, &certificate) == errSecSuccess, let certificate else { return nil }
        var cn: CFString?
        guard SecCertificateCopyCommonName(certificate, &cn) == errSecSuccess, let cn else { return nil }
        let name = (cn as String).trimmingCharacters(in: .whitespacesAndNewlines)
        return name.isEmpty ? nil : name
    }

    // The heartbeat body. Pure, so the wire shape is testable without a device or an Edge.
    //
    // `posture` is absent by design — see the note at the top of this file. The Edge's store keeps the trust
    // level derived from the last REAL posture report when a heartbeat carries none, which is the behaviour
    // this relies on.
    public static func body(deviceID: String, tenantID: String, agentVersion: String, now: Date) -> [String: Any] {
        var out: [String: Any] = [
            "id": deviceID,
            "status": "active",
            "agent_version": agentVersion,
            "timestamp": ISO8601DateFormatter().string(from: now),
        ]
        // Sent only when configured. An empty tenant_id is accepted by the Edge as "no claim"; sending an empty
        // string instead of omitting it would be a claim about a tenant, and the store compares it.
        if !tenantID.isEmpty { out["tenant_id"] = tenantID }
        return out
    }
}

// The sender: one timer, one POST per tick, never blocking and never able to take steering down.
public final class DsseDeviceHeartbeatSender: @unchecked Sendable {
    private let session: URLSession
    private var controlTransport: DsseControlRequestTransport?
    // The update-outcome sender, nil when this device cannot address the route. See DsseUpdateReports.swift.
    private let reports: DsseUpdateReportSender?
    private let url: URL
    private let deviceID: String
    private let tenantID: String
    private let agentVersion: String
    private let queue = DispatchQueue(label: "dsse.device-heartbeat")
    private var timer: DispatchSourceTimer?
    // Reported once per transition rather than every tick, so a persistent failure is visible in the log
    // without burying everything else in it.
    private var consecutiveFailures = 0
    private var lastOutcome: String = ""

    public static func heartbeatURL(security: DsseTransportSecurity, deviceID: String) -> URL? {
        guard !deviceID.isEmpty,
              let encoded = deviceID.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) else { return nil }
        return URL(string: "https://\(security.dialHost):\(security.port)/devices/\(encoded)/heartbeat")
    }

    // Returns nil when the device cannot identify itself — no (T) client certificate, or a certificate with no
    // CN. That is the one state in which silence is correct, and the caller says so out loud.
    public init?(security: DsseTransportSecurity, tenantID: String, agentVersion: String) {
        guard let deviceID = DsseDeviceHeartbeat.deviceIdentity(from: security.clientIdentity),
              let url = Self.heartbeatURL(security: security, deviceID: deviceID) else { return nil }
        self.session = DsseTransportTLS.makePinnedURLSession(security: security, channel: "heartbeat")
        let transport = DsseControlRequestTransport(security: security)
        self.controlTransport = transport
        // ★ THE UPDATER CANNOT SEND ITS OWN OUTCOMES, so this does. Same pinned session, same identity, and it
        // runs only after a beat has succeeded — see DsseUpdateReports.swift for why the two are split.
        if let reportURL = DsseUpdateReportStore.url(security: security.dialHost, port: security.port,
                                                    deviceID: deviceID) {
            self.reports = DsseUpdateReportSender(
                session: DsseTransportTLS.makePinnedURLSession(security: security, channel: "heartbeat"),
                url: reportURL, deviceID: deviceID, tenantID: tenantID, controlTransport: transport)
        } else {
            self.reports = nil
        }
        self.url = url
        self.deviceID = deviceID
        self.tenantID = tenantID
        self.agentVersion = agentVersion
    }

    // Test/seam initializer: inject the session + URL directly.
    public init(session: URLSession, url: URL, deviceID: String, tenantID: String, agentVersion: String,
                reports: DsseUpdateReportSender? = nil) {
        self.reports = reports
        self.session = session
        self.url = url
        self.deviceID = deviceID
        self.tenantID = tenantID
        self.agentVersion = agentVersion
    }

    public var identity: String { deviceID }

    // start beats immediately, then every interval. Beating at once matters: a device that has just started
    // enforcing must not look dark for a whole interval.
    public func start(interval: TimeInterval) {
        queue.async { [weak self] in
            guard let self else { return }
            self.beat()
            let t = DispatchSource.makeTimerSource(queue: self.queue)
            t.schedule(deadline: .now() + interval, repeating: interval)
            t.setEventHandler { [weak self] in self?.beat() }
            t.resume()
            self.timer = t
        }
    }

    public func stop() {
        // Clear the marker on a CLEAN stop. Not what makes the reader correct — a killed extension never gets
        // here, which is why the reader pairs the value with the heartbeat rather than with the file existing —
        // but a deliberately stopped agent should not leave a version string that reads as current.
        DsseRuntimeMarker.clear()
        queue.async { [weak self] in
            self?.timer?.cancel()
            self?.timer = nil
        }
    }


    public func selectEndpoint(_ endpoint: URL) { controlTransport?.selectEndpoint(endpoint) }

    private func beat() {
        // ★ Refresh the local runtime marker on the SAME tick as the remote heartbeat, deliberately.
        //
        // The marker is how a second process on this machine learns which agent code is executing, and the rule
        // it has to satisfy is that a version counts only alongside an independent liveness signal — a value
        // that outlives its writer is a memory, and a reader that trusts one credits a dead extension with
        // running a version. Riding the beat that already exists means the timestamp cannot drift away from
        // the thing it is evidence of: if this process stops, both stop together.
        DsseRuntimeMarker.write(version: agentVersion, deviceIdentity: deviceID, tenantID: tenantID)
        guard let payload = try? JSONSerialization.data(withJSONObject: DsseDeviceHeartbeat.body(
            deviceID: deviceID, tenantID: tenantID, agentVersion: agentVersion, now: Date())) else { return }
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.timeoutInterval = 10
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = payload
        let completion: DsseControlRequestTransport.Completion = { [weak self] _, response, error in
            guard let self else { return }
            let outcome: String
            if let error {
                outcome = "send_failed=\(DsseDeviceHeartbeatSender.nonsecretErrorDetail(error))"
            } else if let http = response as? HTTPURLResponse {
                switch http.statusCode {
                case 200, 202:
                    outcome = "ok"
                    // The beat has just proved the route and the certificate. Anything dsse-updater queued
                    // goes now, in order.
                    self.reports?.drain()
                case 404:
                    // The Edge does not know this device. Deliberately NOT self-registered: enrollment is the
                    // control plane's to grant. Loud, because from the Edge this device is simply absent.
                    outcome = "device_unknown_to_edge=404 (enrollment is required; this agent will not self-register)"
                default:
                    outcome = "unexpected_status=\(http.statusCode)"
                }
            } else {
                outcome = "no_response"
            }
            self.queue.async {
                // ★★★ A FAILURE MUST NEVER BE DEDUPLICATED INTO SILENCE (2026-08-30, measured).
                //
                // This logged only when the outcome CHANGED. On this Mac the first beat after every start
                // failed, said so once, and then said nothing for the rest of the day — because it kept
                // failing in exactly the same way. An operator reading the log sees one line at start-up and
                // silence after it, which is what a channel that RECOVERED looks like. It had not recovered:
                // the device was dark to the Edge for eight hours and its own log was the reason nobody knew.
                //
                // Successes still collapse — a line every fifteen seconds about a working channel is how a
                // log stops being read. Failures do not, and they carry how long this has been going on, so
                // the difference between a blip and a dark device is on the line itself.
                let ok = outcome == "ok"
                if ok {
                    if self.consecutiveFailures > 0 {
                        dsseRuntimeLog("device_heartbeat device=\(self.deviceID) ok — reporting again after "
                            + "\(self.consecutiveFailures) failed beat(s)")
                    } else if outcome != self.lastOutcome {
                        dsseRuntimeLog("device_heartbeat device=\(self.deviceID) \(outcome)")
                    }
                    self.consecutiveFailures = 0
                } else {
                    self.consecutiveFailures += 1
                    dsseRuntimeLog("device_heartbeat device=\(self.deviceID) \(outcome) "
                        + "consecutive=\(self.consecutiveFailures) — the Edge has not heard from this device "
                        + "since this started, whatever the rest of this log looks like")
                }
                self.lastOutcome = outcome
            }
        }
        if let controlTransport { controlTransport.send(req, completion: completion) }
        else { session.dataTask(with: req, completionHandler: completion).resume() }
    }

    // Errors reach the log, so they carry a code rather than a message that might quote a URL or a host.
    static func nonsecretErrorDetail(_ error: Error) -> String {
        // ★ THE ERROR UNDERNEATH IS THE ONE THAT NAMES THE FAULT (2026-08-30). "NSURLErrorDomain/-1200" is
        // "the secure connection failed" and nothing more — it reads the same for a protocol-version refusal,
        // a handshake failure, and a peer that would not accept what was offered. This device reported exactly
        // that, every fifteen seconds, all day, while the tunnel beside it carried traffic. Neither domain nor
        // code is a secret: they are numbers Apple publishes.
        let ns = error as NSError
        guard let under = ns.userInfo[NSUnderlyingErrorKey] as? NSError else {
            return "\(ns.domain)/\(ns.code)"
        }
        return "\(ns.domain)/\(ns.code) under=\(under.domain)/\(under.code)"
    }
}
