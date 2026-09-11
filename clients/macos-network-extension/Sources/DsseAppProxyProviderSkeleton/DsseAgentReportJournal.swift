import Foundation

// DsseAgentReportJournal — what this device tried to tell the Edge, and what came back, written where a
// person can read it with `cat`.
//
// ★★★ WHY A FILE AND NOT THE LOG. The report on the /effective channel is the single fact every readiness
// gate in the product is computed from: whether a device may adopt a new anchor, whether a shared anchor may
// be withdrawn, whether a recovery port may be retired. When it stops arriving, the Edge sees exactly what it
// sees for a device that was switched off — so the question "did this device send it" can only be answered on
// the device. It was asked, and could not be answered: the provider's os_log/NSLog output did not reach the
// unified log store under any predicate that was tried, twice, seven weeks apart. A diagnosis that depends on
// a channel already measured to be empty is not a diagnosis.
//
// The failure text this journal carries was already written and already correct — "DID NOT REACH the Edge …
// this device is not being observed, and every readiness gate reads it as silent". Nothing was missing except
// somewhere to read it.
//
// Bounded by construction, and deliberately not the general runtime log: one line per report attempt, at most
// once a minute, never on a per-flow path. The per-flow evidence writers on this agent once dirtied ~34 GB a
// day and destabilised the provider; that is the reason this takes the outcome only and nothing that scales
// with traffic.
//
// Non-secret by construction: names, statuses and reasons. Never key material, never a certificate body.
public enum DsseAgentReportJournal {
    public static let defaultPath = "/Library/Application Support/Dsse/agent_reports.log"

    /// Where the journal is written. A test points it somewhere writable; nothing else ever sets it.
    nonisolated(unsafe) public static var path = defaultPath

    // Kept small enough to read in a terminal and large enough to hold a night: a line is ~120 bytes and
    // arrives once a minute, so this is a little over two days.
    static let maximumBytes = 384 * 1024
    static let keepBytesWhenTrimming = 192 * 1024

    /// Append one outcome line. Best-effort: a journal that cannot be written must never affect reporting.
    public static func record(_ line: String, path: String = DsseAgentReportJournal.path) {
        let stamp = ISO8601DateFormatter().string(from: Date())
        let entry = "\(stamp) \(line)\n"
        guard let payload = entry.data(using: .utf8) else { return }
        let url = URL(fileURLWithPath: path)
        let fm = FileManager.default
        try? fm.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        if let handle = try? FileHandle(forWritingTo: url) {
            defer { try? handle.close() }
            _ = try? handle.seekToEnd()
            try? handle.write(contentsOf: payload)
        } else {
            try? payload.write(to: url, options: .atomic)
        }
        trimIfOversized(path: path)
    }

    // Drops whole lines from the front, so what remains is still a journal and not a file that begins
    // mid-sentence.
    static func trimIfOversized(path: String) {
        let url = URL(fileURLWithPath: path)
        guard let size = (try? FileManager.default.attributesOfItem(atPath: path)[.size]) as? Int,
              size > maximumBytes,
              let blob = try? Data(contentsOf: url) else { return }
        let tail = blob.suffix(keepBytesWhenTrimming)
        guard let newlineIndex = tail.firstIndex(of: UInt8(ascii: "\n")) else {
            try? tail.write(to: url, options: .atomic)
            return
        }
        let whole = tail[tail.index(after: newlineIndex)...]
        try? Data(whole).write(to: url, options: .atomic)
    }
}
