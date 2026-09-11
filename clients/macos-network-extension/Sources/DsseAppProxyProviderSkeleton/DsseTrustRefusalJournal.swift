import CryptoKit
import Foundation
import Security

/// Why a device declined to trust its Edge, kept until someone can be told.
///
/// A device that refuses the Edge's certificate cannot report that it refused: the report travels over the
/// connection it just declined to make. That is the whole reason the 2026-07-31 outage was unexplainable for
/// 47 minutes — from the Edge and the Console, a fleet refusing a certificate and a fleet switched off look
/// exactly alike, and the one signal that would have separated them existed only in each device's own log.
///
/// So refusals are written down locally and shipped on the next connection that DOES succeed. That is late by
/// definition, and late is the only option available; the alternative is never. What arrives is not "the fleet
/// is down" — nothing can carry that — but "here is what I refused, and why", from each device as it returns.
///
/// Nothing here is secret: a fingerprint and an OS error string about a certificate the Edge served publicly.
public struct DsseTrustRefusal: Codable, Sendable, Equatable {
    /// SHA-256 of the leaf the Edge presented. The operator correlates this with what they replaced.
    public let servedSHA256: String
    /// The verifier's own words. Not classified into a code — the reason a device gives is the evidence, and
    /// mapping it to an enum here would discard the part nobody anticipated.
    public let reason: String
    public let firstAt: Date
    public var lastAt: Date
    /// How many handshakes this covers. A device retries hard; one line per attempt would say nothing more.
    public var count: Int

    enum CodingKeys: String, CodingKey {
        case servedSHA256 = "served_sha256"
        case reason
        case firstAt = "first_at"
        case lastAt = "last_at"
        case count
    }
}

public enum DsseTrustRefusalJournal {
    public static let fileName = "trust_refusals.json"
    /// Bounded so a device refusing everything for a week cannot fill its own disk. Distinct (certificate,
    /// reason) pairs, not attempts — the count field absorbs repetition, and in practice a device refusing
    /// its Edge produces one pair, not thirty.
    static let maxEntries = 32
    static let maxReasonLength = 300

    private static let lock = NSLock()

    private static func url(configDirectory: URL) -> URL {
        configDirectory.appendingPathComponent(fileName)
    }

    /// record folds a refusal into the journal, merging with an existing (certificate, reason) pair.
    /// Best-effort throughout: a journal that cannot be written must never break a handshake path further.
    public static func record(servedChain: [SecCertificate], reason: String, configDirectory: URL,
                              now: Date = Date()) {
        let fingerprint = servedChain.first.map { certificate -> String in
            let der = SecCertificateCopyData(certificate) as Data
            return SHA256.hash(data: der).map { String(format: "%02x", $0) }.joined()
        } ?? ""
        let trimmed = String(reason.prefix(maxReasonLength))

        lock.lock()
        defer { lock.unlock() }
        var entries = loadLocked(configDirectory: configDirectory)
        if let index = entries.firstIndex(where: { $0.servedSHA256 == fingerprint && $0.reason == trimmed }) {
            entries[index].lastAt = now
            entries[index].count += 1
        } else {
            entries.append(DsseTrustRefusal(servedSHA256: fingerprint, reason: trimmed,
                                            firstAt: now, lastAt: now, count: 1))
            // Oldest first out. A device that has been refusing for a while has already said the important
            // thing in its earliest entries, but the newest tell an operator what is happening NOW.
            if entries.count > maxEntries {
                entries.removeFirst(entries.count - maxEntries)
            }
        }
        saveLocked(entries, configDirectory: configDirectory)
    }

    /// pending returns what has not been reported yet.
    public static func pending(configDirectory: URL) -> [DsseTrustRefusal] {
        lock.lock()
        defer { lock.unlock() }
        return loadLocked(configDirectory: configDirectory)
    }

    /// clear drops entries only after they have been ACCEPTED by the Edge. Clearing on send would lose exactly
    /// the reports that matter, since the send is happening over a connection that has only just come back.
    public static func clear(_ reported: [DsseTrustRefusal], configDirectory: URL) {
        guard !reported.isEmpty else { return }
        lock.lock()
        defer { lock.unlock() }
        let sent = Set(reported.map { $0.servedSHA256 + "\u{1}" + $0.reason + "\u{1}" + String($0.count) })
        // A refusal that recurred while the report was in flight has a higher count and is deliberately kept.
        let remaining = loadLocked(configDirectory: configDirectory).filter {
            !sent.contains($0.servedSHA256 + "\u{1}" + $0.reason + "\u{1}" + String($0.count))
        }
        saveLocked(remaining, configDirectory: configDirectory)
    }

    private static func loadLocked(configDirectory: URL) -> [DsseTrustRefusal] {
        guard let data = try? Data(contentsOf: url(configDirectory: configDirectory)) else { return [] }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return (try? decoder.decode([DsseTrustRefusal].self, from: data)) ?? []
    }

    private static func saveLocked(_ entries: [DsseTrustRefusal], configDirectory: URL) {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        guard let data = try? encoder.encode(entries) else { return }
        try? data.write(to: url(configDirectory: configDirectory), options: .atomic)
    }
}
