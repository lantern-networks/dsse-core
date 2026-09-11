import XCTest
@testable import DsseAppProxyProviderSkeleton

// Where a device recovers from, when its certificate has already expired, must not depend on a value that only
// arrives over the tunnel it can no longer open. The transport URL is written at provisioning time and is
// always present; the recovery endpoint is published in a fleet snapshot and may not be. Resolving the host
// from the transport closes that gap — a config carrying only a port is enough.
final class DsseRecoveryEndpointResolutionTests: XCTestCase {
    private func contract(recovery: String?, transport: String? = "https://203.0.113.10:18543") -> DsseTransportContract {
        let json = """
        {
          "transport_tls_url": \(transport.map { "\"\($0)\"" } ?? "null"),
          "renewal_recovery_endpoint": \(recovery.map { "\"\($0)\"" } ?? "null")
        }
        """
        return try! JSONDecoder().decode(DsseTransportContract.self, from: Data(json.utf8))
    }

    func testFullHostPortIsUsedAsGiven() {
        let got = DsseCertificateRenewalScheduler.resolvedRecoveryEndpoint(contract: contract(recovery: "10.0.0.5:18545"))
        XCTAssertEqual(got, "10.0.0.5:18545", "an explicit endpoint must win — it may deliberately differ from the transport host")
    }

    func testPortOnlyTakesTheHostFromTheTransport() {
        XCTAssertEqual(
            DsseCertificateRenewalScheduler.resolvedRecoveryEndpoint(contract: contract(recovery: ":18545")),
            "203.0.113.10:18545",
            "a fleet config naming only the port must resolve against the Edge the device already reaches")
        XCTAssertEqual(
            DsseCertificateRenewalScheduler.resolvedRecoveryEndpoint(contract: contract(recovery: "18545")),
            "203.0.113.10:18545",
            "the leading colon must be optional; both spellings mean the same thing")
    }

    func testIPv6TransportHostStaysBracketed() {
        let got = DsseCertificateRenewalScheduler.resolvedRecoveryEndpoint(
            contract: contract(recovery: ":18545", transport: "https://[2001:db8::1]:18543"))
        XCTAssertEqual(got, "[2001:db8::1]:18545",
                       "an unbracketed IPv6 literal would be re-split at the wrong colon and point somewhere else")
    }

    func testAbsentRecoveryEndpointStaysAbsent() {
        XCTAssertNil(DsseCertificateRenewalScheduler.resolvedRecoveryEndpoint(contract: contract(recovery: nil)),
                     "silence must not be invented into an address; the device reports it cannot self-recover")
        XCTAssertNil(DsseCertificateRenewalScheduler.resolvedRecoveryEndpoint(contract: contract(recovery: "   ")))
    }

    func testPortOnlyWithoutATransportURLCannotResolve() {
        XCTAssertNil(
            DsseCertificateRenewalScheduler.resolvedRecoveryEndpoint(contract: contract(recovery: ":18545", transport: nil)),
            "with no transport URL there is no host to borrow, and guessing one would send credentials somewhere unverified")
    }

    func testNonNumericPortIsRejected() {
        XCTAssertNil(DsseCertificateRenewalScheduler.resolvedRecoveryEndpoint(contract: contract(recovery: "recovery-host")),
                     "a bare hostname is not a port; treating it as one would produce a bogus endpoint")
    }
}
