import Foundation

// DsseUpdateReports.swift — the extension sends what the UPDATER could not.
//
// ★ WHY THE TWO ARE SPLIT (2026-08-12). dsse-updater runs as root and launches `installer -pkg`; it
// deliberately holds no network identity, because giving the process most likely to be replaced mid-execution
// the certificate that proves this machine's identity is not a trade worth making. So it writes each terminal
// outcome to a directory beside its journal, and this extension — which already holds that certificate and
// already beats on a timer — sends them.
//
// ★ AND WHY IT MATTERS AT ALL. Until this existed the ingest route (`POST /devices/{id}/agent-updates`) had no
// caller on either platform. The first real update on this hardware, six failure modes and a verified rollback
// were all invisible to the control plane: the fleet view read `total: 0` whether a fleet had updated cleanly
// or the updater had never run. "Nothing to report" and "nothing is reporting" rendered identically.
//
// ★ AND WHY IT DOES NOT PARSE MUCH. The report is written by Go and read here; every field is optional except
// the timestamp and the status, and an unreadable file is DISCARDED rather than retried forever. One lost event
// said out loud is better than a queue that never drains again because of one bad byte.

public struct DsseUpdateReport: Sendable {
    public let fileURL: URL
    public let id: String
    public let status: String
    public let targetVersion: String
    public let runningVersion: String
    public let fromVersion: String
    public let kind: String
    public let reason: String
    public let at: String
    public let droppedBefore: Int
    /// The digest of a document that would not verify. A refusal of one has no version to name it by.
    public let rejectedDigest: String
    /// What this endpoint IS. The control plane cannot tell which release applies to a device without it.
    public let platform: String
    /// The architecture the device RUNS ON, a separate fact from the platform. Without it the Edge guessed a
    /// constant per OS (macOS meant arm64), so an Intel Mac was compared against a release it cannot run.
    public let arch: String

    init?(fileURL: URL, json: [String: Any]) {
        guard let status = json["status"] as? String, !status.isEmpty,
              let at = json["at"] as? String, !at.isEmpty else { return nil }
        self.fileURL = fileURL
        self.status = status
        self.at = at
        self.id = json["id"] as? String ?? ""
        self.targetVersion = json["target_version"] as? String ?? ""
        self.runningVersion = json["running_version"] as? String ?? ""
        self.fromVersion = json["from_version"] as? String ?? ""
        self.kind = json["kind"] as? String ?? "update"
        self.reason = json["reason"] as? String ?? ""
        self.droppedBefore = json["dropped_before"] as? Int ?? 0
        self.rejectedDigest = json["rejected_digest"] as? String ?? ""
        self.platform = json["platform"] as? String ?? ""
        self.arch = json["arch"] as? String ?? ""
    }
}

public enum DsseUpdateReportStore {
    /// Where dsse-updater leaves them. Must stay in step with agentupdate.ReportsDir on the Go side.
    public static let directory = URL(fileURLWithPath: "/Library/Application Support/Dsse/update/reports")

    /// Reports waiting to be sent, OLDEST FIRST.
    ///
    /// Order is the point: "failed, then installed" and "installed, then failed" are different stories about
    /// the same device, and the file names are timestamp-prefixed so sorting them is sorting by when they
    /// happened. `dropped.json` is bookkeeping, not a report.
    public static func pending(in dir: URL = directory) -> [URL] {
        let names = (try? FileManager.default.contentsOfDirectory(atPath: dir.path)) ?? []
        return names
            .filter { $0.hasSuffix(".json") && !$0.hasPrefix(".") && $0 != "dropped.json" }
            .sorted()
            .map { dir.appendingPathComponent($0) }
    }

    /// How many outcomes this device threw away to stay inside its cap, as the Go side's ledger records it.
    ///
    /// ★ THE LEDGER IS A SEPARATE FILE, and the first version of this reader simply filtered it out — so macOS
    /// never told the Edge about discarded outcomes at all, while its test asserted a `dropped_before` field
    /// that the real producer does not put inside a report. The test was consuming its own fixture.
    public static func droppedCount(in dir: URL = directory) -> Int {
        guard let data = try? Data(contentsOf: dir.appendingPathComponent("dropped.json")),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let n = obj["dropped"] as? Int else { return 0 }
        return n
    }

    /// Claims the ledger by RENAMING it, and returns the count.
    ///
    /// ★ CLEARING BY DELETION LOST DROPS (2026-08-12, seventh review). The sender read the count, spent a
    /// network round trip, and then removed the whole file — so any drop the Go updater recorded in between
    /// vanished with it. Claiming by rename means the producer's next addition starts a NEW ledger, and this
    /// claim is either discarded (delivered) or put back (not).
    public static func claimDropped(in dir: URL = directory) -> (count: Int, claim: URL?) {
        // The whole recover-and-rename pair is held, so a producer cannot add between them.
        withLedgerLock(in: dir) { claimDroppedLocked(in: dir) }
    }

    private static func claimDroppedLocked(in dir: URL) -> (count: Int, claim: URL?) {
        // ★ RENAME FIRST, THEN READ THE CLAIM (2026-08-12, eighth review). Reading the count and renaming were
        // two operations, so a drop recorded between them made the returned number disagree with the file
        // actually taken. And an orphaned claim from a previous crash was DELETED here, which lost its count
        // permanently — it is folded back into the ledger instead.
        let claim = dir.appendingPathComponent("dropped.json.claimed")
        recoverClaim(claim, in: dir)
        do {
            try FileManager.default.moveItem(at: dir.appendingPathComponent("dropped.json"), to: claim)
        } catch {
            return (0, nil) // nothing recorded, or someone else holds the claim
        }
        let n = count(in: claim)
        guard n > 0 else {
            try? FileManager.default.removeItem(at: claim)
            return (0, nil)
        }
        return (n, claim)
    }

    /// Folds a claim left behind by a crash back into the ledger, rather than discarding it.
    ///
    /// Called with the ledger lock already held (from claimDroppedLocked), so it adds WITHOUT taking it again.
    static func recoverClaim(_ claim: URL, in dir: URL) {
        let n = count(in: claim)
        guard n > 0 else {
            try? FileManager.default.removeItem(at: claim)
            return
        }
        let total = droppedCount(in: dir) + n
        if let data = try? JSONSerialization.data(withJSONObject: ["dropped": total]) {
            try? data.write(to: dir.appendingPathComponent("dropped.json"))
        }
        try? FileManager.default.removeItem(at: claim)
    }

    static func count(in file: URL) -> Int {
        guard let data = try? Data(contentsOf: file),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let n = obj["dropped"] as? Int else { return 0 }
        return n
    }

    /// ★ THE UPDATER AND THIS SENDER ARE DIFFERENT PROCESSES (2026-08-12, ninth review). Adding to the ledger
    /// is a read-modify-write, and the Go updater's prune adds to the same file — so a restore here and a prune
    /// there could each overwrite the other's increment. The Go side takes a flock on `dropped.lock`; this
    /// takes the same one, on the same file, so the two actually exclude each other.
    ///
    /// Best-effort: failing to take it does not skip the update — a ledger that under-counts is better than one
    /// that stops counting — but it is the only path here that proceeds without exclusion.
    static func withLedgerLock<T>(in dir: URL, _ body: () -> T) -> T {
        let path = dir.appendingPathComponent("dropped.lock").path
        let fd = open(path, O_CREAT | O_RDWR, 0o600)
        guard fd >= 0 else { return body() }
        defer { close(fd) }
        guard flock(fd, LOCK_EX) == 0 else { return body() }
        defer { flock(fd, LOCK_UN) }
        return body()
    }

    static func add(_ n: Int, in dir: URL) {
        withLedgerLock(in: dir) {
            let total = droppedCount(in: dir) + n
            if let data = try? JSONSerialization.data(withJSONObject: ["dropped": total]) {
                try? data.write(to: dir.appendingPathComponent("dropped.json"))
            }
        }
    }

    /// Discards a delivered claim, or ADDS it back to whatever has accumulated since. Adding rather than
    /// overwriting: those are different drops and both happened.
    public static func releaseDropped(_ claim: URL?, delivered: Bool, in dir: URL = directory) {
        guard let claim else { return }
        defer { try? FileManager.default.removeItem(at: claim) }
        if delivered { return }
        let n = count(in: claim)
        guard n > 0 else { return }
        add(n, in: dir)
    }

    /// Reads one, or nil when it cannot be parsed — in which case it is removed, because a file nothing can
    /// read would otherwise block every report behind it forever.
    public static func read(_ url: URL) -> DsseUpdateReport? {
        guard let data = try? Data(contentsOf: url),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let report = DsseUpdateReport(fileURL: url, json: obj) else {
            try? FileManager.default.removeItem(at: url)
            dsseRuntimeLog("agent_update_report DISCARDED unreadable=\(url.lastPathComponent) — that update "
                + "outcome will never appear in the fleet view")
            return nil
        }
        return report
    }

    /// The ingest route's body. device_id and tenant_id come from the SENDER's verified identity, never from
    /// the report: the updater records what it could read locally, and the authoritative answer is the
    /// certificate the Edge checked.
    /// Maps a device-side status to one the Edge's schema accepts.
    ///
    /// ★ THE SCHEMA IS A CHECK CONSTRAINT. `agent_update_events` allows
    /// available|downloaded|installing|installed|failed|rolled_back. `rolled_back` therefore goes out AS
    /// ITSELF — rewriting it to `installed`, as the first version of this file did, counted every rollback as a
    /// successful update and inflated the rollout success rate with the events that most contradict it.
    /// A REFUSAL has no value of its own there, so it goes as `failed` (true from the fleet's point of view:
    /// this device is not on the target) with `refused: true` in the metadata.
    static func edgeStatus(_ status: String) -> String {
        status == "refused" ? "failed" : status
    }

    public static func body(for report: DsseUpdateReport, deviceID: String, tenantID: String,
                            droppedBefore: Int = 0) -> [String: Any] {
        let status = edgeStatus(report.status)
        var meta: [String: Any] = [
            "platform": report.platform,
            "kind": report.kind,
            "reported_by": "dsse-network-extension",
        ]
        // Empty on a report written by an updater that predates the field; the Edge falls back to its guess
        // rather than treating "" as an architecture.
        if !report.arch.isEmpty { meta["arch"] = report.arch }
        if !report.fromVersion.isEmpty { meta["from_version"] = report.fromVersion }
        if report.status == "rolled_back" { meta["rolled_back"] = true }
        if report.status == "refused" { meta["refused"] = true }
        // ★ THE ONLY THING THAT IDENTIFIES A REFUSAL OF AN UNVERIFIABLE DOCUMENT. Without it the fleet sees "no
        // version, generic signature error" and cannot tell a second substituted document from a repeat.
        if !report.rejectedDigest.isEmpty { meta["rejected_manifest_sha256"] = report.rejectedDigest }
        // ★ SAID OUT LOUD. A device offline long enough to overflow its outbox must not come back with a tidy
        // history that silently begins in the middle. The count comes from the Go side's LEDGER
        // (dropped.json), not from inside a report — the reports it counts are exactly the ones that are gone.
        let dropped = max(report.droppedBefore, droppedBefore)
        if dropped > 0 { meta["dropped_before"] = dropped }
        var body: [String: Any] = [
            // ★ THE ID GOES ON THE WIRE. The stored report has a stable one; without it every RETRY — a lost
            // response, or a crash between "accepted" and "removed" — becomes a NEW event at the Edge, counted
            // twice in the success rate and audited twice.
            "id": report.id,
            "device_id": deviceID,
            "tenant_id": tenantID,
            "current_agent_version": report.runningVersion,
            "target_agent_version": report.targetVersion,
            "update_status": status,
            // NOT "dsse": the Edge CHECKs update_source IN ('mdm','control_plane','manual'), so that value
            // would be rejected at insert. The release came from the control plane.
            "update_source": "control_plane",
            "timestamp": report.at,
            "metadata": meta,
        ]
        if !report.reason.isEmpty { body["failure_reason"] = report.reason }
        return body
    }

    public static func url(security host: String, port: Int, deviceID: String) -> URL? {
        guard !deviceID.isEmpty,
              let encoded = deviceID.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) else { return nil }
        return URL(string: "https://\(host):\(port)/devices/\(encoded)/agent-updates")
    }
}

/// Sends queued update outcomes over the same pinned (T) session the heartbeat uses.
///
/// ONE AT A TIME, IN ORDER, and it stops at the first refusal: a drain that skipped ahead would reorder this
/// device's history in the fleet view, and one that deleted on error would lose the outcome entirely.
// @unchecked Sendable, like the heartbeat sender beside it and for the same reason: every field is set once at
// construction and never mutated, and the drain is a self-chaining sequence of URLSession callbacks with no
// shared state between them.
public final class DsseUpdateReportSender: @unchecked Sendable {
    private let session: URLSession
    private let controlTransport: DsseControlRequestTransport?
    private let url: URL
    private let deviceID: String
    private let tenantID: String
    private let directory: URL
    // ★ ONE DRAIN AT A TIME (2026-08-12, sixth review). The heartbeat fires every 15 seconds and each success
    // called drain(); a drain walks up to 200 files ASYNCHRONOUSLY, so several could be in flight over the
    // same directory, POST the same file concurrently, and produce duplicate events at the Edge — under
    // ordinary operation, not under a failure. The flag is guarded by a serial queue, and a request arriving
    // while one is running is dropped rather than queued: the next beat is 15 seconds away and the outbox is
    // still there.
    private let gate = DispatchQueue(label: "dsse.update-reports.gate")
    private var draining = false

    public init(session: URLSession, url: URL, deviceID: String, tenantID: String,
                directory: URL = DsseUpdateReportStore.directory) {
        self.session = session
        self.controlTransport = nil
        self.url = url
        self.deviceID = deviceID
        self.tenantID = tenantID
        self.directory = directory
    }

    init(session: URLSession, url: URL, deviceID: String, tenantID: String,
         directory: URL = DsseUpdateReportStore.directory, controlTransport: DsseControlRequestTransport) {
        self.session = session
        self.controlTransport = controlTransport
        self.url = url
        self.deviceID = deviceID
        self.tenantID = tenantID
        self.directory = directory
    }

    /// Called after a heartbeat has SUCCEEDED, which is why there is no backoff: the beat has just proved the
    /// route and the certificate, so a failure here is about this request rather than about being offline.
    public func drain(completion: (@Sendable () -> Void)? = nil) {
        let start: Bool = gate.sync {
            if draining { return false }
            draining = true
            return true
        }
        guard start else {
            completion?()
            return
        }
        let finish: @Sendable () -> Void = { [weak self] in
            self?.gate.sync { self?.draining = false }
            completion?()
        }
        let queued = DsseUpdateReportStore.pending(in: directory)
        guard !queued.isEmpty else {
            finish()
            return
        }
        let (dropped, claim) = DsseUpdateReportStore.claimDropped(in: directory)
        let dir = directory
        let release: @Sendable (Bool) -> Void = { delivered in
            DsseUpdateReportStore.releaseDropped(claim, delivered: delivered, in: dir)
        }
        send(remaining: queued, sent: 0, dropped: dropped, release: release, completion: finish)
    }

    private func send(remaining: [URL], sent: Int, dropped: Int, release: @escaping @Sendable (Bool) -> Void,
                      completion: (@Sendable () -> Void)?) {
        guard let next = remaining.first else {
            release(false) // nothing left to carry it; anything still claimed goes back
            if sent > 0 {
                dsseRuntimeLog("agent_update_report delivered=\(sent) device=\(deviceID)")
            }
            completion?()
            return
        }
        guard let report = DsseUpdateReportStore.read(next) else {
            // Unreadable and already removed: carry on rather than stall the queue behind it.
            send(remaining: Array(remaining.dropFirst()), sent: sent, dropped: dropped, release: release,
                 completion: completion)
            return
        }
        guard let payload = try? JSONSerialization.data(withJSONObject: DsseUpdateReportStore.body(
            for: report, deviceID: deviceID, tenantID: tenantID, droppedBefore: dropped)) else {
            try? FileManager.default.removeItem(at: next)
            send(remaining: Array(remaining.dropFirst()), sent: sent, dropped: dropped, release: release,
                 completion: completion)
            return
        }
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.timeoutInterval = 15
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = payload
        let completionHandler: DsseControlRequestTransport.Completion = { [weak self] _, response, error in
            guard let self else { return }
            if error != nil {
                dsseRuntimeLog("agent_update_report send_failed pending=\(remaining.count) (kept, in order)")
                release(false)
                completion?()
                return
            }
            let code = (response as? HTTPURLResponse)?.statusCode ?? 0
            guard code == 200 || code == 202 else {
                dsseRuntimeLog("agent_update_report refused status=\(code) pending=\(remaining.count) "
                    + "(kept, in order)")
                release(false)
                completion?()
                return
            }
            // Delivered. Remove it and continue; a file that cannot be removed stops the drain rather than
            // being sent again on every beat.
            do {
                try FileManager.default.removeItem(at: next)
            } catch {
                dsseRuntimeLog("agent_update_report delivered but NOT removed — stopping so it is not sent "
                    + "repeatedly: \(next.lastPathComponent)")
                release(dropped > 0) // the count DID reach the Edge on this request
                completion?()
                return
            }
            // The claim is discarded only once a report CARRYING the count has been accepted.
            if dropped > 0 { release(true) }
            self.send(remaining: Array(remaining.dropFirst()), sent: sent + 1, dropped: 0, release: release,
                      completion: completion)
        }
        if let controlTransport { controlTransport.send(req, completion: completionHandler) }
        else { session.dataTask(with: req, completionHandler: completionHandler).resume() }
    }
}
