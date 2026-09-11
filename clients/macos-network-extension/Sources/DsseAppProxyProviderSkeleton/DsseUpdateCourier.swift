import Foundation

// DsseUpdateCourier — the NE carries the two update documents to disk, and deliberately does nothing else
// with them.
//
// The updater that acts on them holds no network identity: it reads a signed envelope from
// /Library/Application Support/Dsse and verifies it against keys it pins itself. That design rests on the
// SIGNATURE being the trust boundary rather than the channel, which is what makes it safe for the file to be
// written by something else. This is that something else — the same split the Windows agent already runs.
//
// ★ THE ENVELOPES ARE WRITTEN UNOPENED. This file does not verify a signature, and that is a decision rather
// than an omission: the updater verifies, and an agent that pre-approved the same bytes would be a second
// opinion the updater would then have to either trust — making this process part of the trust boundary for no
// gain — or ignore, making the check pointless. One verifier, at the point of use.
//
// What it DOES check is that the body is an envelope of the expected TYPE. That is not a trust judgement; it
// is refusing to hand the updater something that would make it raise a security alarm about a captive-portal
// error page. A manifest that fails verification means, by the updater's own design, "look tonight".
//
// ★ AND NOTHING HERE DELETES. The Windows side got this wrong first and corrected it, and the reasoning
// transfers exactly: on the Edge a manifest is a file in a directory, so "withdrawn", "never published" and
// "the operator pointed at the wrong path" are all the same 404. Clearing on it would let one misconfiguration
// disarm the update path across a fleet, in the direction that looks healthy. For the PLAN it is worse — an
// absent plan falls back to an unfrozen default, so a courier that deleted on a transient failure would lift
// an operator's halt.
public final class DsseUpdateCourier: @unchecked Sendable {
    /// Where the updater looks. Both paths are a contract with clients/macos/updateplatform.
    public static let manifestPath = "/Library/Application Support/Dsse/update-manifest.json"
    public static let planPath = "/Library/Application Support/Dsse/update-plan.json"
    /// Where the updater looks for the package itself. A contract with clients/macos/updateplatform's
    /// StagedRoot()/StagedPath(version).
    public static let stagedRoot = "/Library/Application Support/Dsse/staged"

    private let session: URLSession
    private var controlTransport: DsseControlRequestTransport?
    private var artifactTransport: DsseArtifactDownloadTransport?
    private let baseURL: URL
    private let arch: String
    private let queue = DispatchQueue(label: "dsse.update-courier")
    private var timer: DispatchSourceTimer?

    /// - Parameters:
    ///   - session: the (T) mTLS session the NE already uses; the Edge keys the answer to the cert-proven
    ///     device identity, so no device id is sent and a device cannot ask about another one.
    ///   - baseURL: the Edge base, e.g. https://host:18543
    public init(session: URLSession, baseURL: URL, arch: String = DsseUpdateCourier.currentArch) {
        self.session = session
        self.baseURL = baseURL
        self.arch = arch
    }

    /// Production initializer: the pinned (T) session and the Edge base, from the same transport contract the
    /// policy poller resolves. Gated on the transport and NOT on a pin, the same split the reverse-telemetry
    /// report already uses — this process verifies nothing, so a pin would gate the wrong thing.
    public convenience init?(security: DsseTransportSecurity) {
        guard let base = URL(string: "https://\(security.dialHost):\(security.port)") else { return nil }
        self.init(session: DsseTransportTLS.makePinnedURLSession(security: security, channel: "agent-update"), baseURL: base)
        self.controlTransport = DsseControlRequestTransport(security: security)
        self.artifactTransport = DsseArtifactDownloadTransport(security: security)
    }

    /// currentArch is what this BINARY is, not what the machine could run.
    ///
    /// A Rosetta-translated x86_64 build asking for arm64 would be handed a package it cannot install, and the
    /// refusal would arrive at the updater as a platform mismatch rather than as the deployment mistake it is.
    public static var currentArch: String {
        #if arch(arm64)
        return "arm64"
        #else
        return "amd64"
        #endif
    }

    public func selectEndpoint(_ endpoint: URL) {
        controlTransport?.selectEndpoint(endpoint)
        artifactTransport?.selectEndpoint(endpoint)
    }

    public func start(interval: TimeInterval = 900) {
        queue.async { [weak self] in
            guard let self else { return }
            self.refresh()
            let t = DispatchSource.makeTimerSource(queue: self.queue)
            t.schedule(deadline: .now() + interval, repeating: interval)
            t.setEventHandler { [weak self] in self?.refresh() }
            t.resume()
            self.timer = t
        }
    }

    public func stop() {
        queue.async { [weak self] in
            self?.timer?.cancel()
            self?.timer = nil
        }
    }

    /// refresh fetches both documents once. Public so a test — and an operator debugging a device — can drive
    /// one pass without waiting for the timer.
    public func refresh() {
        fetch(path: "/steer/agent-update-manifest",
              expectedType: DsseUpdateManifest.envelopeType,
              destination: Self.manifestPath,
              label: "update-manifest")
        fetchArtifact()
        // Only the PLAN may arrive unsigned: that is the form an Edge with no agent-policy signer serves.
        // The manifest never may — it is the document that says which code to run.
        fetch(path: "/steer/agent-update-plan",
              expectedType: DsseRolloutPlan.envelopeType,
              destination: Self.planPath,
              label: "update-plan",
              unsignedSchema: DsseRolloutPlan.schemaVersion)
    }

    /// fetchArtifact brings the release package inside the tunnel.
    ///
    /// ★★ WHY THE AGENT CARRIES IT (2026-08-13, operator decision). The updater used to fetch this itself over
    /// plain https from an endpoint that was deliberately anonymous. The integrity argument for that held — the
    /// digest is in the signed manifest and the updater checks it at staging and again immediately before the
    /// installer runs — but two things did not. Anyone who could reach the endpoint could retrieve the fleet's
    /// CURRENT build, so "is this fleet mid-rollout of something with public weaknesses" was not private; and the
    /// (T) listener refuses to start without mandatory mTLS, so an anonymous route could never live on it, which
    /// on 443-only corporate egress meant a second global address per customer.
    ///
    /// The reason the updater holds no network identity is untouched: it still only reads a file. THIS process
    /// already has the TLS stack and the device key, and always did.
    ///
    /// ★ AND IT IS WRITTEN WHERE THE UPDATER ALREADY LOOKS. updateplatform.Stage returns immediately when the
    /// staged file's DIGEST already matches, so a couriered package needs no new code over there and no new
    /// trust: the same verification runs on the same bytes, twice, as before.
    /// alreadyStaged reports that the package this device's manifest names is on disk at the expected size, so
    /// there is nothing to fetch.
    ///
    /// ★★ WITHOUT IT THE FLEET PAYS FOR ITS OWN IDLENESS (2026-08-13, found by win-dev-1 while writing the
    /// Windows twin). This courier runs on the manifest's refresh interval, so a device that is already up to
    /// date pulled the whole package — tens of megabytes — every fifteen minutes, for ever, off the Edge's
    /// uplink. The first version of this file had no such check, and nothing about it would have looked wrong
    /// in a log.
    ///
    /// The manifest on disk is read as a HINT ONLY: it names a version and a size, which decide whether to do
    /// WORK. It decides nothing about what may be installed — the updater hashes the staged bytes against the
    /// manifest it verifies, twice, and a lying manifest here can at most cause an unnecessary download or a
    /// skipped one that the updater's own digest check then refuses.
    static func alreadyStaged() -> Bool {
        guard let raw = FileManager.default.contents(atPath: manifestPath),
              let env = try? JSONDecoder().decode(DsseSignedAgentPolicyEnvelope.self, from: raw),
              let payload = Data(base64Encoded: env.payloadB64),
              let object = (try? JSONSerialization.jsonObject(with: payload)) as? [String: Any],
              let version = object["version"] as? String,
              let name = stagedFileName(forVersion: version) else { return false }
        // A size of zero, or an absent one, means "cannot tell" — and cannot-tell must not skip the fetch.
        let declared = (object["artifact_size"] as? NSNumber)?.int64Value ?? 0
        guard declared > 0 else { return false }
        let attrs = try? FileManager.default.attributesOfItem(atPath: stagedRoot + "/" + name)
        guard let onDisk = (attrs?[.size] as? NSNumber)?.int64Value else { return false }
        return onDisk == declared
    }

    private func fetchArtifact() {
        // Nothing to do is the ordinary state of a fleet, and it must cost nothing.
        if Self.alreadyStaged() {
            return
        }
        guard var comps = URLComponents(url: baseURL.appendingPathComponent("/steer/agent-update-artifact"),
                                        resolvingAgainstBaseURL: false) else { return }
        comps.queryItems = [URLQueryItem(name: "platform", value: "darwin"), URLQueryItem(name: "arch", value: arch)]
        guard let url = comps.url else { return }

        var req = URLRequest(url: url)
        req.httpMethod = "GET"
        // Longer than the documents: this is a package, not a few kilobytes, and a laptop on a hotel network is
        // the ordinary case rather than the exception.
        req.timeoutInterval = 900

        let completion: DsseArtifactDownloadTransport.Completion = { tempURL, response, error in
            if let error {
                dsseRuntimeLog("artifact courier: fetch failed (\(error.localizedDescription)); the updater will "
                    + "try again on its next pass")
                return
            }
            guard let http = response as? HTTPURLResponse, let tempURL else { return }
            switch http.statusCode {
            case 200:
                break
            case 404:
                return // nothing published for this device: the normal state, and not a reason to log
            case 401:
                dsseRuntimeLog("artifact courier: the edge refused this device's identity (HTTP 401) — release "
                    + "bytes are served inside the tunnel and this session did not present a usable certificate")
                return
            default:
                dsseRuntimeLog("artifact courier: edge returned HTTP \(http.statusCode)")
                return
            }
            // ★ THE VERSION COMES FROM THE EDGE'S OWN HEADER, not from parsing the manifest here. This process
            // verifies nothing and should decide nothing; the header only chooses a FILENAME, and the updater
            // then verifies the digest of whatever is at that name against the manifest it trusts. A wrong
            // header produces a file the updater ignores, not a package it installs.
            let version = (http.value(forHTTPHeaderField: "X-Dsse-Agent-Update-Version") ?? "").trimmingCharacters(
                in: .whitespacesAndNewlines)
            guard let name = Self.stagedFileName(forVersion: version) else {
                dsseRuntimeLog("artifact courier: the edge named the version \(version.isEmpty ? "(absent)" : version)"
                    + ", which is not one this device will write to disk")
                return
            }
            do {
                try FileManager.default.createDirectory(atPath: Self.stagedRoot, withIntermediateDirectories: true)
                let dst = URL(fileURLWithPath: Self.stagedRoot + "/" + name)
                // ★ REPLACED, NEVER DELETED-THEN-MOVED, and the guard in this package's own tests is what
                // insisted on it. That rule was written for the DOCUMENTS — deleting a plan lifts a freeze,
                // because an absent plan falls back to an unfrozen default — and it does not transfer to a
                // package, which the updater simply re-fetches. It is still the right call here for a different
                // reason: delete-then-move leaves a window in which the staged path holds nothing or half a
                // file, and the updater hashes whatever it finds there. replaceItemAt has no such window.
                if FileManager.default.fileExists(atPath: dst.path) {
                    _ = try FileManager.default.replaceItemAt(dst, withItemAt: tempURL)
                } else {
                    try FileManager.default.moveItem(at: tempURL, to: dst)
                }
                dsseRuntimeLog("artifact courier: staged \(name) for the updater")
            } catch {
                dsseRuntimeLog("artifact courier: could not stage the package: \(error.localizedDescription)")
            }
        }
        if let artifactTransport {
            artifactTransport.download(req, completion: completion)
        } else {
            session.downloadTask(with: req, completionHandler: completion).resume()
        }
    }

    /// stagedFileName mirrors rollbackstore.FileNameFor: a version arrives from the network and must never
    /// become a path. Anything outside this alphabet, or reaching for a parent directory, is refused rather
    /// than sanitised — a name that had to be repaired is a name nobody meant.
    static func stagedFileName(forVersion version: String) -> String? {
        guard !version.isEmpty, version.count <= 128 else { return nil }
        guard let first = version.first, first != ".", first != "-" else { return nil }
        let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.+-_")
        guard version.unicodeScalars.allSatisfy({ allowed.contains($0) }) else { return nil }
        // ★ THE PREFIX IS PART OF THE CONTRACT, not decoration: rollbackstore.fileNameWithSuffix produces
        // "dsse-agent-<version>.pkg" and updateplatform.StagedPath asks it for exactly that name. A file under
        // any other name is one the updater never looks at, so it would download a package every pass and
        // install nothing — the silent shape this repo keeps finding.
        return "dsse-agent-" + version + ".pkg"
    }

    private func fetch(path: String, expectedType: String, destination: String, label: String,
                       unsignedSchema: String? = nil) {
        guard var comps = URLComponents(url: baseURL.appendingPathComponent(path), resolvingAgainstBaseURL: false) else {
            return
        }
        // Both REQUIRED by the Edge, which answers 400 rather than guessing — a default there would hand a
        // device the wrong build's manifest. They are device-declared and that is safe: they only select which
        // document is served, and the manifest carries the platform it is for, so a device that lies receives
        // something its own verifier then refuses.
        comps.queryItems = [URLQueryItem(name: "platform", value: "darwin"), URLQueryItem(name: "arch", value: arch)]
        guard let url = comps.url else { return }

        var req = URLRequest(url: url)
        req.httpMethod = "GET"
        req.timeoutInterval = 30

        let completion: DsseControlRequestTransport.Completion = { data, response, error in
            if let error {
                // Keeps what is on disk. A laptop off the network is the common cause and it recovers by itself.
                dsseRuntimeLog("\(label) courier: fetch failed (\(error.localizedDescription)); keeping what is on disk")
                return
            }
            guard let http = response as? HTTPURLResponse else { return }
            switch http.statusCode {
            case 200:
                break
            case 404:
                // The NORMAL state for most devices most of the time. Quiet, and explicitly not a reason to
                // touch what is on disk — see the note on deletion above.
                return
            case 400:
                // This agent always sends both parameters, so a 400 means the contract moved. Named rather than
                // folded into the generic branch: it will not fix itself with retries.
                dsseRuntimeLog("\(label) courier: the Edge rejected platform/arch as malformed (HTTP 400) — the "
                    + "endpoint contract has changed and this agent needs updating by another path")
                return
            default:
                dsseRuntimeLog("\(label) courier: Edge returned HTTP \(http.statusCode); keeping what is on disk")
                return
            }
            guard let data, !data.isEmpty else { return }
            // Bounded: an envelope is a few kilobytes. A wrong endpoint returning something enormous must not
            // reach the disk of a machine whose network this product is responsible for.
            guard data.count <= 1_048_576 else {
                dsseRuntimeLog("\(label) courier: response exceeds 1 MiB; refusing it")
                return
            }
            // ★ AN UNSIGNED BODY IS THE FORM THIS ENDPOINT STILL SERVES, AND ONLY macOS REFUSED IT
            // (2026-08-13, twenty-ninth review). An Edge with no agent-policy signer serves the rollout plan as
            // a bare JSON object. Windows accepts that (unsignedSchema) and macOS decoded a
            // non-optional envelope, so the plan never reached disk and LoadRollout read "no plan on this
            // device" — which is deliberately NOT a freeze. So an operator halting a bad release stopped the
            // Windows machines and not the Macs, while the Console showed the whole fleet halted. A halt that
            // reaches half a fleet is worse than one that reaches none, because it looks like it worked.
            //
            // The distinction Windows draws is kept exactly: NO type is the unsigned form and is legitimate; a
            // DIFFERENT type is a routing mistake, and on this document a routing mistake would halt the fleet.
            let env = try? JSONDecoder().decode(DsseSignedAgentPolicyEnvelope.self, from: data)
            if let env {
                guard env.type == expectedType else {
                    dsseRuntimeLog("\(label) courier: envelope type \(env.type) is not \(expectedType); keeping "
                        + "what is on disk")
                    return
                }
            } else if let unsignedSchema {
                // ★★ WHAT THE UNSIGNED FORM MUST CALL ITSELF, NOT WHETHER ONE IS ALLOWED (2026-08-13, from the
                // reported from the Windows side). This was a Bool, and the schema it implied was baked into the check — so
                // the day a SECOND endpoint gains an unsigned form, setting that flag would either re-create the
                // hole or silently demand the rollout plan's schema of a different document. A string cannot be
                // set without saying what the body has to name itself, which makes the dangerous state
                // inexpressible rather than merely discouraged. Their fix removed a field; this matches it.
                if !Self.namesItself(data, schema: unsignedSchema) {
                // ★★ "IT PARSED AS JSON" WAS NOT A CHECK (2026-08-13, thirtieth review #13). The unsigned form is
                // a ROLLOUT PLAN served as a bare object by an Edge with no agent-policy signer. Accepting any
                // JSON meant a proxy's error page, or an envelope whose signature field was missing, was written
                // over a plan this device had verified — and on a signed deployment the updater then answers
                // ErrPlanUnverifiable, which is a FREEZE. One mis-routed response stops updates on this platform.
                //
                // So the unsigned form has to identify itself the way the signed one does: by carrying the
                // plan's schema. A document that is neither an envelope of the right type nor a plan is a wrong
                // response, whatever it parses as.
                    dsseRuntimeLog("\(label) courier: the response is neither a signed envelope nor a document "
                        + "calling itself \(unsignedSchema); keeping what is on disk")
                    return
                }
            } else {
                dsseRuntimeLog("\(label) courier: the response is not a signed envelope; keeping what is on disk")
                return
            }
            // The bytes are written through byte-for-byte: re-serialising the decoded envelope could change
            // them, and what the updater verifies must be exactly what the Edge signed.
            if Self.writeAtomically(data, to: destination) {
                // An unsigned plan has no signing key to name, and saying so is the point: the updater then
                // reads it under the rule that a device pinning no key accepts it unverified and says so.
                let provenance = env.map { "signing key \($0.signingKeyID)" } ?? "UNSIGNED (this edge has no agent-policy signer)"
                dsseRuntimeLog("\(label) courier: wrote \(data.count) bytes to \(destination) (\(provenance))")
            }
        }
        if let controlTransport {
            controlTransport.send(req, completion: completion)
        } else {
            session.dataTask(with: req, completionHandler: completion).resume()
        }
    }

    /// namesItself reports whether the body is a bare JSON document declaring the schema this endpoint's
    /// unsigned form is expected to carry.
    ///
    /// Only the schema marker is read. Nothing here validates the plan — the updater does that, against its own
    /// keys — and a courier that started judging content would be a second opinion at the wrong layer. What it
    /// refuses is a document that never claimed to be a plan at all.
    static func namesItself(_ data: Data, schema expected: String) -> Bool {
        guard let object = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else { return false }
        guard let schema = object["schema_version"] as? String else { return false }
        return schema == expected
    }

    /// writeAtomically puts bytes on disk in a way the updater can never catch half-written.
    ///
    /// The updater re-reads these files on every pass, on its own schedule, with no lock and no coordination
    /// with this process. A torn read of the manifest is not a retry — it is ErrManifestRejected, which by the
    /// updater's design means "a release is broken or artefacts are being substituted, look tonight". Torn
    /// writes here manufacture security alarms.
    static func writeAtomically(_ data: Data, to path: String) -> Bool {
        let url = URL(fileURLWithPath: path)
        do {
            try FileManager.default.createDirectory(at: url.deletingLastPathComponent(),
                                                    withIntermediateDirectories: true)
            // .atomic writes a temporary file in the same directory and renames — the same dance the Windows
            // courier does by hand, and for the same reason: a rename across volumes is not atomic.
            try data.write(to: url, options: .atomic)
            return true
        } catch {
            dsseRuntimeLog("update courier: could not write \(path): \(error.localizedDescription)")
            return false
        }
    }
}

/// DsseRolloutPlan is the plan document's type constant on this platform. The plan itself is consumed by the
/// updater, not by the extension — the extension only needs to recognise the envelope well enough to refuse a
/// proxy error page, so this is deliberately just the type.
public enum DsseRolloutPlan {
    /// Must match agentupdate.RolloutPlanEnvelopeType. The plan has its own type rather than borrowing the
    /// steer-policy one, so a document carrying a FREEZE cannot be confused with an exclusion policy signed by
    /// the same key.
    public static let envelopeType = "dsse_agent_update_plan.v1"

    /// Must match agentupdate.RolloutPlanSchema. It identifies the UNSIGNED form — the bare plan an Edge with no
    /// agent-policy signer serves — which otherwise has nothing to distinguish it from any other JSON a wrong
    /// endpoint might return.
    public static let schemaVersion = "dsse.agent-update-plan.v1"
}
