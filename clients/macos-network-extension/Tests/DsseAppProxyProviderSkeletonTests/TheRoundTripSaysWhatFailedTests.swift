import XCTest
@testable import DsseAppProxyProviderSkeleton

/// ★★ 2026-08-29: every failed round trip on the NW path logged `code=1 reason=The operation couldn't be
/// completed. (DsseSingleRequestError error 1.)` — the same line for a refused connection, a timeout and an
/// unreadable response, because bridging the enum to NSError drops the associated value. The operator's only
/// way into a device that steers and cannot deliver is that line.
final class TheRoundTripSaysWhatFailedTests: XCTestCase {
    func testEachFailureNamesItself() {
        XCTAssertEqual(DsseSingleRequestError.transport("connection failed: refused").description,
                       "transport: connection failed: refused")
        XCTAssertEqual(DsseSingleRequestError.badEndpoint("port 0").description, "endpoint unusable: port 0")
        XCTAssertEqual(DsseSingleRequestError.unusable("no status in \"\"").description,
                       "response unusable: no status in \"\"")
    }

    /// What the old line did, so the difference is visible rather than asserted from memory.
    func testFoundationsDescriptionSaysNothingUseful() {
        let bridged = DsseSingleRequestError.transport("connection failed: refused") as NSError
        XCTAssertFalse(bridged.localizedDescription.contains("refused"),
                       "if Foundation now carries the reason, this log no longer needs its own formatting")
    }

    func testTheCallSiteAsksTheErrorAndNotFoundation() throws {
        let source = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Sources/DsseAppProxyProviderSkeleton/DsseRuntimeCopyOverNW.swift")
        let text = try String(contentsOf: source, encoding: .utf8)
        XCTAssertTrue(text.contains("(error as? DsseSingleRequestError)?.description"),
                      "edge_round_trip_failed is back to printing Foundation's generic description, which is "
                      + "the same string for every distinct failure on this path")
    }
}

/// ★★★ 2026-08-30: the formatter that exists to stop numbers reaching an operator did not know the one error
/// type every request to the Edge now produces. A failed enrolment — the path with nothing else to look at,
/// because the device has no identity at all — logged
///
///	enrolment_error=request_failed detail=domain=…DsseSingleRequestError code=1
///
/// which is the same line for a refused connection, a timeout, a bad port and an unreadable response.
final class EveryRequestErrorNamesItselfTests: XCTestCase {
    func testTheFormatterKnowsTheTypeEveryEdgeRequestProduces() {
        let detail = providerNonsecretErrorDetail(DsseSingleRequestError.transport("connection failed: refused"))
        XCTAssertTrue(detail.contains("refused"),
                      "the reason was dropped on the way to the operator: \(detail)")
        XCTAssertTrue(detail.contains("transport:"), "the failure does not say which kind it was: \(detail)")
    }

    func testTheOtherKindsAreDistinguishable() {
        let a = providerNonsecretErrorDetail(DsseSingleRequestError.transport("timed out after 15s"))
        let b = providerNonsecretErrorDetail(DsseSingleRequestError.unusable("no status in \"\""))
        XCTAssertNotEqual(a, b, "a timeout and an unreadable response produce the same line")
    }
}
