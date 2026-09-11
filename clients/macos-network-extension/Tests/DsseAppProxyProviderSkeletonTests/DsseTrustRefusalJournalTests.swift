import XCTest
@testable import DsseAppProxyProviderSkeleton

// The journal exists because a refusal cannot travel over the connection it caused to fail. Its one subtle
// rule is that an entry is dropped only once the Edge has ACCEPTED it — this is the only copy.
final class DsseTrustRefusalJournalTests: XCTestCase {
    private func tempDir() throws -> URL {
        let dir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("dsse-refusals-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    func testRepeatedRefusalsFoldIntoOneEntryWithACount() throws {
        let dir = try tempDir()
        for _ in 0..<5 {
            DsseTrustRefusalJournal.record(servedChain: [], reason: "certificate is not trusted",
                                           configDirectory: dir)
        }
        let pending = DsseTrustRefusalJournal.pending(configDirectory: dir)
        XCTAssertEqual(pending.count, 1, "a device retries hard; one line per attempt says nothing more")
        XCTAssertEqual(pending.first?.count, 5)
    }

    func testADifferentReasonIsADifferentEntry() throws {
        let dir = try tempDir()
        DsseTrustRefusalJournal.record(servedChain: [], reason: "certificate is not trusted", configDirectory: dir)
        DsseTrustRefusalJournal.record(servedChain: [], reason: "certificate has expired", configDirectory: dir)
        XCTAssertEqual(DsseTrustRefusalJournal.pending(configDirectory: dir).count, 2)
    }

    // The rule that matters: clearing on SEND would lose exactly the reports worth having, because the send
    // happens over a connection that has only just come back.
    func testAnEntrySurvivesUntilItIsAccepted() throws {
        let dir = try tempDir()
        DsseTrustRefusalJournal.record(servedChain: [], reason: "certificate is not trusted", configDirectory: dir)
        let sent = DsseTrustRefusalJournal.pending(configDirectory: dir)

        // Not accepted: nothing is cleared.
        DsseTrustRefusalJournal.clear([], configDirectory: dir)
        XCTAssertEqual(DsseTrustRefusalJournal.pending(configDirectory: dir).count, 1)

        // Accepted: it goes.
        DsseTrustRefusalJournal.clear(sent, configDirectory: dir)
        XCTAssertTrue(DsseTrustRefusalJournal.pending(configDirectory: dir).isEmpty)
    }

    // A refusal that recurred while the report was in flight must NOT be dropped by that report's acknowledgement.
    func testARefusalThatRecurredDuringTheReportIsKept() throws {
        let dir = try tempDir()
        DsseTrustRefusalJournal.record(servedChain: [], reason: "certificate is not trusted", configDirectory: dir)
        let inFlight = DsseTrustRefusalJournal.pending(configDirectory: dir)

        DsseTrustRefusalJournal.record(servedChain: [], reason: "certificate is not trusted", configDirectory: dir)
        DsseTrustRefusalJournal.clear(inFlight, configDirectory: dir)

        let remaining = DsseTrustRefusalJournal.pending(configDirectory: dir)
        XCTAssertEqual(remaining.count, 1, "the newer state of a still-failing device must not be acknowledged away")
        XCTAssertEqual(remaining.first?.count, 2)
    }

    func testTheJournalIsBounded() throws {
        let dir = try tempDir()
        for i in 0..<(DsseTrustRefusalJournal.maxEntries + 10) {
            DsseTrustRefusalJournal.record(servedChain: [], reason: "reason \(i)", configDirectory: dir)
        }
        XCTAssertEqual(DsseTrustRefusalJournal.pending(configDirectory: dir).count,
                       DsseTrustRefusalJournal.maxEntries)
    }
}
