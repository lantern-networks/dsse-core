import Foundation

// Only signature/origin/session-validated requests may enter this queue. It
// schedules presentation, never authorization. Distinct requests are deferred,
// not discarded by a session-wide cooldown; duplicates never reopen a tab.
public struct DsseAuthBrowserLaunchQueue: Sendable {
    private struct Entry: Sendable {
        let id: String
        let received: TimeInterval
        var attempted = false
    }
    private var entries: [Entry] = []
    private var lastAttempt: TimeInterval?
    public init() {}

    public mutating func enqueue(id: String, uptime: TimeInterval) -> Bool {
        guard valid(uptime), !id.isEmpty else { return false }
        prune(uptime)
        guard entries.count < 32, !entries.contains(where: { $0.id == id }) else { return false }
        entries.append(Entry(id: id, received: uptime))
        return true
    }

    public mutating func next(uptime: TimeInterval) -> String? {
        guard valid(uptime) else { return nil }
        prune(uptime)
        if let lastAttempt, uptime < lastAttempt || uptime - lastAttempt < 2 { return nil }
        guard let index = entries.firstIndex(where: { !$0.attempted }) else { return nil }
        entries[index].attempted = true
        lastAttempt = uptime
        return entries[index].id
    }

    // Explicit user selection must not be followed by a duplicate automatic tab.
    // A failed OS browser launch is also an attempt; retries remain user driven.
    public mutating func markAttempted(id: String, uptime: TimeInterval) {
        guard valid(uptime), let index = entries.firstIndex(where: { $0.id == id }) else { return }
        entries[index].attempted = true
        lastAttempt = uptime
    }

    public mutating func remove(id: String) {
        entries.removeAll { $0.id == id }
    }

    private func valid(_ uptime: TimeInterval) -> Bool { uptime.isFinite && uptime >= 0 }
    private mutating func prune(_ uptime: TimeInterval) {
        entries.removeAll { uptime < $0.received || uptime - $0.received >= 120 }
    }
}
