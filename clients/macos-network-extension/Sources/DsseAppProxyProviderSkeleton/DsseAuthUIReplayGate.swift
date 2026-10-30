import Foundation

// Darwin notifications are wakeups, not the durable request. A periodic reader
// can recover a missed wakeup without opening an already delivered request again
// or renewing its original 120-second UI lifetime.
public struct DsseAuthUIReplayGate: Sendable {
    private struct Entry: Sendable {
        let firstSeen: TimeInterval
        var result: String?
    }
    private var entries: [String: Entry] = [:]
    private let limit: Int
    public init(limit: Int = 128) { self.limit = max(1, limit) }

    public mutating func admit(id: String, result: String?, uptime: TimeInterval) -> Bool {
        guard !id.isEmpty, uptime.isFinite, uptime >= 0,
              result == nil || result == "resumed" || result == "not_resumed" else { return false }
        entries = entries.filter { uptime >= $0.value.firstSeen && uptime - $0.value.firstSeen < 900 }
        if var previous = entries[id] {
            guard previous.result == nil, let result else { return false }
            previous.result = result
            entries[id] = previous
            return true
        }
        // Never evict a live entry to admit a new request: doing so could reopen
        // an older pending request on the next periodic read.
        guard entries.count < limit else { return false }
        entries[id] = Entry(firstSeen: uptime, result: result)
        return true
    }
}
