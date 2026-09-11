import XCTest
@testable import DsseAppProxyProviderSkeleton

/// Every runtime-copy failure must reach the log as a name, not a number.
///
/// ★★★ TWICE IN ONE DAY (2026-08-29). An enrolment failure logged `code=1` and was read as the second case of
/// its enum; it was requestFailed, because Swift numbers payload-carrying cases first. Hours later a device
/// that steered and delivered nothing logged `live_copy_failed=… code=20`, and the same counting exercise
/// started again. A number that has to be decoded by reading source is not a diagnostic.
final class DsseRuntimeCopyErrorsNameThemselvesTests: XCTestCase {
    func testEveryCaseNamesItself() {
        let all: [DsseLocalRuntimeCopyDriverError] = [
            .missingTenantScope, .missingRequestID, .missingApplicationScope, .emptyUpstreamPayload,
            .emptyDownstreamPayload, .flowOpenFailed, .flowReadFailed, .flowWriteFailed, .flowOpenTimeout,
            .tunnelOpenTimeout, .flowReadTimeout, .edgeRoundTripTimeout, .flowWriteTimeout,
            .duplicateRuntimeCopyRequestID, .runtimeCopyConcurrentCapExceeded, .runtimeCopyByteCapExceeded,
            .runtimeCopyIdleTimeoutExceeded, .runtimeCopyBackpressureOverflowClosed,
            .runtimeTransportDeviceValidationPending, .invalidEdgeTransportConfiguration,
            .edgeTransportRequestFailed, .edgeTransportStatusFailed, .edgeTransportDecodeFailed,
            .edgeTransportRequestIDMismatch,
        ]
        var seen = Set<String>()
        for e in all {
            guard let named = providerNonsecretRuntimeCopyErrorDetail(e) else {
                return XCTFail("\(e) reached the log as a bare number")
            }
            XCTAssertTrue(named.hasPrefix("runtime_copy_error="), named)
            XCTAssertTrue(seen.insert(named).inserted, "two cases share the name \(named)")
        }
        XCTAssertEqual(seen.count, all.count)
    }

    func testTheFailureThisWasFoundOnIsNamed() {
        // The one a device that steers and cannot deliver writes on every flow.
        XCTAssertEqual(providerNonsecretRuntimeCopyErrorDetail(DsseLocalRuntimeCopyDriverError.edgeTransportRequestFailed),
                       "runtime_copy_error=edge_transport_request_failed")
    }

    func testAnUnrelatedErrorIsLeftAlone() {
        XCTAssertNil(providerNonsecretRuntimeCopyErrorDetail(
            NSError(domain: "somewhere.else", code: 20)))
    }
}
