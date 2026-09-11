import XCTest
@testable import DsseAppProxyProviderSkeleton

// Both defects here were found by the Windows session reviewing the first version of this loader, and both are
// the silent kind: the device keeps working, the log looks healthy, and the preference an operator wrote is
// simply not in effect.
final class DsseRegionPriorityConfigTests: XCTestCase {
    private func load(_ json: String) -> (table: [String: Int], logs: [String]) {
        var logs: [String] = []
        let t = DsseRegionPriorityAgentConfig.load(agentConfig: Data(json.utf8)) { logs.append($0) }
        return (t, logs)
    }

    func testConfiguredPriorityIsRead() {
        let (t, _) = load(#"{"network_extension_region_priority":{"jp-tokyo":1,"jp-osaka":2}}"#)
        XCTAssertEqual(t, ["jp-tokyo": 1, "jp-osaka": 2])
    }

    // Not configured is the ordinary case and must stay quiet — a warning every machine prints is a warning
    // nobody reads.
    func testAbsentIsSilent() {
        let (t, logs) = load(#"{"transport":{"host":"x"}}"#)
        XCTAssertTrue(t.isEmpty)
        XCTAssertTrue(logs.isEmpty, "an unconfigured device must not log about region priority: \(logs)")
    }

    // ★ DEFECT 1. `try?` on the whole config object turned any decode failure into an empty map, so a
    // configured-but-broken machine produced output byte-identical to an unconfigured one — and then homed on
    // jitter, the state this feature exists to end.
    func testMalformedIsLoudRatherThanIndistinguishableFromUnconfigured() {
        let (t, logs) = load(#"{"network_extension_region_priority":"jp-tokyo=1"}"#)
        XCTAssertTrue(t.isEmpty)
        XCTAssertTrue(logs.contains { $0.contains("CONFIGURED BUT UNUSABLE") },
                      "a present-but-unusable preference must not be silent: \(logs)")
    }

    // ...including when the breakage is in an UNRELATED key. The old code decoded the whole object, so a typo
    // anywhere un-ranked the device.
    func testAnUnrelatedBrokenKeyDoesNotUnrankTheDevice() {
        let (t, _) = load(#"{"network_extension_region_priority":{"jp-tokyo":1},"some_other_key":{"a":[1,2}}"#)
        // The file is not valid JSON at all, so nothing is readable — but the point is the OPPOSITE case below.
        XCTAssertTrue(t.isEmpty)
        let (t2, _) = load(#"{"network_extension_region_priority":{"jp-tokyo":1},"network_extension_observe_only_passthrough_all":"not-a-bool"}"#)
        XCTAssertEqual(t2, ["jp-tokyo": 1],
                       "a wrong type in an unrelated key must not silently discard the region preference")
    }

    // ★ DEFECT 2. Zero-based is the ordinary instinct for "first", but 0 means unspecified and ranks LAST — so
    // `tokyo: 0` delivered the precise inverse of the intent, on every device, with a healthy log.
    func testZeroIsRejectedByNameBecauseItInvertsTheIntent() {
        let (t, logs) = load(#"{"network_extension_region_priority":{"jp-tokyo":0,"jp-osaka":2}}"#)
        XCTAssertEqual(t, ["jp-osaka": 2], "0 must not be accepted as a priority")
        XCTAssertTrue(logs.contains { $0.contains("REJECTED") && $0.contains("1 is the HIGHEST") },
                      "rejecting 0 must say why, naming 1 as highest: \(logs)")
    }

    func testNegativeAndNonIntegerAreRejected() {
        let (t, logs) = load(#"{"network_extension_region_priority":{"a":-1,"b":"2","c":3}}"#)
        XCTAssertEqual(t, ["c": 3])
        XCTAssertTrue(logs.contains { $0.contains("REJECTED") })
    }
}
