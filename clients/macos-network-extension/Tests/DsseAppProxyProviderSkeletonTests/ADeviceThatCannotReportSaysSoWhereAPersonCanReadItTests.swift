import XCTest
@testable import DsseAppProxyProviderSkeleton

/// ★★★ THE REPORT NOBODY COULD ASK ABOUT (2026-09-06, measured on a three-region lab).
///
/// The Edge received zero reports on /steer/agent-policy/effective in three hours while resolving the same
/// device's organization from its certificate on every flow — so the Console read both enrolled devices as
/// `never_reported_anything`, and the gate that withdraws an organization's shared anchor had no denominator.
/// The agent already wrote the right sentence when a report failed. It was written to a log that could not be
/// read: the provider's os_log and NSLog output reached the unified log store under no predicate that was
/// tried, twice, seven weeks apart.
///
/// So the question "did this device send it" had no answer on either side, and the only remaining PKI
/// violation stayed open behind a measurement that could not be taken.
///
/// These tests are on the CALL SITE, not on the journal: a journal that is never written from the reporting
/// path is exactly the failure being fixed, and a test of `record` alone would pass with the poller silent.
final class ADeviceThatCannotReportSaysSoWhereAPersonCanReadItTests: XCTestCase {
    private var journal = ""
    private var directory = ""

    override func setUp() {
        super.setUp()
        directory = NSTemporaryDirectory() + "dsse-report-journal-" + UUID().uuidString
        journal = directory + "/agent_reports.log"
        DsseAgentReportJournal.path = journal
    }

    override func tearDown() {
        DsseAgentReportJournal.path = DsseAgentReportJournal.defaultPath
        try? FileManager.default.removeItem(atPath: directory)
        super.tearDown()
    }

    private func journalText(waitingUpTo seconds: TimeInterval) -> String {
        let deadline = Date().addingTimeInterval(seconds)
        while Date() < deadline {
            if let text = try? String(contentsOfFile: journal, encoding: .utf8), !text.isEmpty { return text }
            RunLoop.current.run(until: Date().addingTimeInterval(0.05))
        }
        return (try? String(contentsOfFile: journal, encoding: .utf8)) ?? ""
    }

    /// Port 1 on loopback refuses immediately: the report cannot land, which is the case the journal exists for.
    func testAReportThatDoesNotReachTheEdgeIsRecordedOnTheDevice() throws {
        let url = try XCTUnwrap(URL(string: "http://127.0.0.1:1/steer/agent-policy"))
        let poller = DsseAgentPolicyPoller(session: .shared, url: url, pinnedPublicKeyHex: "aa")
        poller.reportEffective([], serverCount: 0)

        let text = journalText(waitingUpTo: 10)
        XCTAssertTrue(text.contains("DID NOT REACH"),
                      "a device that failed to report must say so somewhere a person can read without the " +
                      "unified log — got: \(text)")
        XCTAssertTrue(text.contains("readiness gate"),
                      "and it must say what the failure COSTS, so the line is actionable rather than noted")
        XCTAssertTrue(text.contains("127.0.0.1:1"),
                      "including where it tried, so 'sent to the wrong door' is distinguishable from 'sent " +
                      "nowhere' — got: \(text)")
    }

    /// An empty journal must not be ambiguous between "this device never armed the channel" and "it armed the
    /// channel and every attempt failed". Those have opposite causes and opposite fixes.
    func testArmingTheChannelIsRecordedSoAnEmptyJournalMeansSomething() throws {
        let url = try XCTUnwrap(URL(string: "http://127.0.0.1:1/steer/agent-policy"))
        let poller = DsseAgentPolicyPoller(session: .shared, url: url, pinnedPublicKeyHex: "aa")
        poller.start(interval: 3600) { _ in }
        defer { poller.stop() }

        let text = journalText(waitingUpTo: 10)
        XCTAssertTrue(text.contains("ARMED"), "got: \(text)")
        XCTAssertTrue(text.contains("named_route=no"),
                      "a poller dialling by address is served the deployment-wide certificate, and the " +
                      "journal must say which route was used — got: \(text)")
    }

    /// The journal is written once a minute for the life of a device. It must not be the thing that fills a
    /// disk, and trimming must leave a file that still begins at a line boundary.
    func testTheJournalIsBoundedAndStillReadableAfterTrimming() throws {
        try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true)
        let line = String(repeating: "x", count: 512)
        for _ in 0..<1200 { DsseAgentReportJournal.record(line) }

        let size = try XCTUnwrap((try FileManager.default.attributesOfItem(atPath: journal)[.size]) as? Int)
        XCTAssertLessThanOrEqual(size, DsseAgentReportJournal.maximumBytes,
                                 "an unbounded journal on a per-minute path is a disk-filling defect, and this " +
                                 "agent has had one")
        let text = try String(contentsOfFile: journal, encoding: .utf8)
        let first = try XCTUnwrap(text.split(separator: "\n").first)
        XCTAssertTrue(first.hasPrefix("20"),
                      "trimming drops whole lines, so what remains is a journal and not a file beginning " +
                      "mid-sentence — got: \(first.prefix(40))")
    }
}
