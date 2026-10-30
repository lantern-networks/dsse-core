import XCTest
@testable import DsseAppProxyProviderSkeleton

final class DssePerformanceLimitsTests: XCTestCase {
    func testAbsentResourceQuotasDoNotCutHighCountLargeOrQuietFlows() throws {
        let limits = try DssePerformanceLimits.decode(Data("{}".utf8))
        XCTAssertEqual(limits.maxConcurrentConnections,0)
        XCTAssertEqual(limits.maxBytesPerFlow,0)
        XCTAssertEqual(limits.idleTimeoutSeconds,0)
        XCTAssertEqual(limits.maxSessionExchangesPerFlow,0)
        XCTAssertEqual(DsseLocalRuntimeCopyDriver.defaultMaxSessionExchangeCount,0)
        let config = DsseLiveRuntimeCopyGuardConfiguration()
        let guardState = DsseLiveRuntimeCopyGuard(configuration:config)
        for i in 0..<2_048 {
            let metadata=DsseLocalRuntimeCopyMetadata(tenantID:"tenant",requestID:"held-\(i)",applicationID:"app")
            try guardState.open(metadata:metadata)
        }
        XCTAssertEqual(guardState.activeCount,2_048)
        try guardState.recordUpstreamBytes(requestID:"held-0",count:2_147_483_648)
        XCTAssertTrue(guardState.isActive(requestID:"held-0"))
        for i in 0..<2_048 { guardState.close(requestID:"held-\(i)") }
        XCTAssertEqual(guardState.activeCount,0)
    }

    func testOperatorConfigurationIsNotClampedToOldQuotas() throws {
        let data=Data(#"{"max_concurrent_connections":100000,"max_bytes_per_flow":8589934592,"idle_timeout_seconds":86400}"#.utf8)
        let limits=try DssePerformanceLimits.decode(data)
        XCTAssertEqual(limits.maxConcurrentConnections,100_000)
        XCTAssertEqual(limits.maxBytesPerFlow,8_589_934_592)
        XCTAssertEqual(limits.idleTimeoutSeconds,86_400)
        for invalid in [#"{"max_concurrent_connections":-1}"#,#"{"max_bytes_per_flow":true}"#,#"{"idle_timeout_seconds":1.5}"#,#"{"misspelled_limit":1}"#] {
            XCTAssertThrowsError(try DssePerformanceLimits.decode(Data(invalid.utf8)))
        }
    }
}
