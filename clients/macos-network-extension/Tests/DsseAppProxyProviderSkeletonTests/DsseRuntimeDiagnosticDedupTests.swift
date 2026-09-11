import XCTest
@testable import DsseAppProxyProviderSkeleton

// Regression for the NE provider "disk writes" resource bug (~34 GB/day at negligible traffic): the phase-2
// verification diagnostic writers were wired into the live per-flow hot path and re-wrote a single shared
// (last-writer-wins) file on every progress sub-event / every flow. The fix makes the writer ONE-SHOT: it captures
// the verification snapshot up to the terminal "completed" state, then permanently seals — no serialize, no disk
// write, ever again. Uses the REAL clock so a per-call createdAt cannot mask a rewrite.
final class DsseRuntimeDiagnosticDedupTests: XCTestCase {
    private func makeWriter() throws -> (DsseProviderRuntimeDiagnosticWriter, URL) {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("dsse-diag-seal-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: dir) }
        let url = dir.appendingPathComponent("network_extension_runtime_diagnostic.json")
        return (DsseProviderRuntimeDiagnosticWriter(diagnosticURL: url), url)
    }

    private func modificationDate(_ url: URL) throws -> Date {
        try XCTUnwrap(FileManager.default.attributesOfItem(atPath: url.path)[.modificationDate] as? Date)
    }

    func testWriterSealsAtTerminalAndNeverWritesAgain() throws {
        let (writer, url) = try makeWriter()

        // Before the terminal state, genuine state changes DO persist.
        try writer.recordStartProxyRunning()
        let m0 = try modificationDate(url)
        try writer.recordTransparentNetworkSettingsApplied()
        let m1 = try modificationDate(url)
        XCTAssertNotEqual(m0, m1, "a real state change before the terminal snapshot must be written")

        // Reach the terminal "completed" snapshot — this seals the writer.
        try writer.recordLiveCopyProgress(.liveCopyStarted)
        try writer.recordLiveCopyCompleted()
        let mSealed = try modificationDate(url)

        // The live flood: hundreds of post-terminal progress events + further state changes. Pre-fix each re-wrote
        // the whole shared file; now the writer is sealed and must touch the disk ZERO more times. APFS mtime is
        // nanosecond-resolution, so a single rewrite would move it.
        for _ in 0..<500 {
            try writer.recordLiveCopyProgress(.edgeRoundTripResponseBodyReceived)
            try writer.recordLiveCopyProgress(.liveCopyStarted)
        }
        try writer.recordProviderRulesReloadGate("reloaded_on_change")
        try writer.recordStartProxyRunning()
        let mAfter = try modificationDate(url)
        XCTAssertEqual(mSealed, mAfter,
                       "once the terminal snapshot is captured the writer must never write again (one-shot)")
    }
}
