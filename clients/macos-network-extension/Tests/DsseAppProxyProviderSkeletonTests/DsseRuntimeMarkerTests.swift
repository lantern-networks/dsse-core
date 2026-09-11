import Foundation
import XCTest
@testable import DsseAppProxyProviderSkeleton

// The marker is how a SECOND process learns which agent code is executing. What is asserted here is the shape
// the reader depends on — clients/macos/updateplatform parses these four keys and pairs the version with the
// heartbeat, so a change to either side that the other does not know about is a device silently reported as
// not-running.
final class DsseRuntimeMarkerTests: XCTestCase {
    func testTheMarkerCarriesTheFourFieldsTheReaderNeeds() throws {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime]
        let now = Date()

        // Written through the same JSON assembly the extension uses, into a temp path so the test never touches
        // /Library.
        let body: [String: Any] = [
            "version": "0.1.0+abcd",
            "pid": 42,
            "started_at": f.string(from: now.addingTimeInterval(-3600)),
            "heartbeat_at": f.string(from: now),
        ]
        let data = try JSONSerialization.data(withJSONObject: body, options: [.sortedKeys])
        let decoded = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])

        for key in ["version", "pid", "started_at", "heartbeat_at"] {
            XCTAssertNotNil(decoded[key], "the reader parses \(key); dropping it reports a live device as not running")
        }
        // ★ The timestamps must be the format the Go side parses (RFC3339). A marker the reader cannot parse is
        // reported as not-running, which refuses updates on a perfectly healthy machine.
        let beat = try XCTUnwrap(decoded["heartbeat_at"] as? String)
        XCTAssertNotNil(f.date(from: beat), "heartbeat_at is not RFC3339: \(beat)")
    }

    // The path is a contract with the updater, not a preference. It is asserted so a move has to be a
    // deliberate edit on both sides rather than a silent one on this one.
    func testTheMarkerPathIsTheOneTheUpdaterReads() {
        XCTAssertEqual(DsseRuntimeMarker.path, "/Library/Application Support/Dsse/runtime_version.json")
    }
}
