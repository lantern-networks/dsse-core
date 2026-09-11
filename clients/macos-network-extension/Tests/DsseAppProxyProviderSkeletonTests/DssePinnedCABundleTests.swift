import XCTest
import Security
@testable import DsseAppProxyProviderSkeleton

// Rotating the transport CA is the one change that can cut a fleet off with no way back: the device pins the
// CA, so once it is replaced the device cannot verify the Edge — and it cannot fetch the new CA, because
// fetching happens over the tunnel it can no longer establish.
//
// The standard answer is an overlap: publish the next CA, wait until every device has it, then start signing
// with it. That requires trusting TWO CAs at once. macOS could pin exactly one, because the parser stopped at
// the first END CERTIFICATE, while the Windows client has always accepted a bundle. The two endpoints
// disagreed about something that decides whether a CA rotation is routine or an outage.
final class DssePinnedCABundleTests: XCTestCase {

    // Two DIFFERENT CA certificates in one file — the outgoing one and the incoming one, exactly what an
    // operator's configuration looks like during a rotation overlap.
    static let bundlePEM = """
        -----BEGIN CERTIFICATE-----
        MIIBFzCBvgIJAI3EZk4GrRQXMAoGCCqGSM49BAMCMBQxEjAQBgNVBAMMCW1hYy1k
        ZXYtMTAeFw0yNjA3MjgwMzU3MDRaFw00NjA3MjMwMzU3MDRaMBQxEjAQBgNVBAMM
        CW1hYy1kZXYtMTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABFuNcmeJVwYB0zkS
        JZhIjS5A/5C2OQDdxApa//W3TIXXgOlJHhXoG4xUsxzZqyhWHSDr4pWrtQTVGahQ
        TDUrbm4wCgYIKoZIzj0EAwIDSAAwRQIgUP5uGa6EFnuw4YwSeMlBvCAK6fyZVNZh
        usi9XfhGyZ4CIQC0f/6l3MCymBRqsO+QH5JYDej+8dhjsQbh5OWy3oomSg==
        -----END CERTIFICATE-----
        -----BEGIN CERTIFICATE-----
        MIIBKDCBzgIJAN84uXoGuXxjMAoGCCqGSM49BAMCMBwxGjAYBgNVBAMMEW5leHQg
        dHJhbnNwb3J0IENBMB4XDTI2MDcyODA4NTUxM1oXDTQ2MDcyMzA4NTUxM1owHDEa
        MBgGA1UEAwwRbmV4dCB0cmFuc3BvcnQgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMB
        BwNCAASNvWlzzBB6JPhjEYk6Ergq1pF6mDl0MbTmdtMuPRYRqtUvev48HeE8e2VH
        cOs+69hu5W0VEccJSrK5+p1BOVbNMAoGCCqGSM49BAMCA0kAMEYCIQCEiMFXGGsS
        xctifoFSPzF9yb6AuCqhMvjXlazAtfwW6wIhAMBTlRdTSxpAv/XiKgQpQJCk5l1k
        VPFXbKGx3PXsn8je
        -----END CERTIFICATE-----
        """

    // THE regression. The old parser returned one certificate no matter how many the file held, so an
    // operator's carefully prepared overlap silently collapsed back to a single pin.
    func testEveryCertificateInABundleIsPinned() {
        let pinned = DsseTransportSecurityFactory.certificates(fromPEM: Self.bundlePEM)
        XCTAssertEqual(pinned.count, 2,
                       "only \(pinned.count) CA(s) parsed from a two-certificate bundle — an overlap cannot " +
                       "exist, so rotating the transport CA cuts off every device at the moment of changeover")
        // And they must be the two DIFFERENT CAs, not the same one twice.
        let subjects = Set(pinned.map { SecCertificateCopySubjectSummary($0) as String? ?? "" })
        XCTAssertEqual(subjects.count, 2, "the bundle collapsed to a single distinct CA: \(subjects)")
    }

    func testASingleCertificateStillParses() {
        let one = DsseTransportSecurityFactory.certificates(fromPEM: Self.bundlePEM
            .components(separatedBy: "-----END CERTIFICATE-----").first! + "-----END CERTIFICATE-----")
        XCTAssertEqual(one.count, 1)
    }

    // A damaged entry must not take the rest of the file with it. Losing the remainder is how an overlap
    // quietly becomes a single pin again — the failure this whole change exists to prevent.
    func testAMalformedEntryDoesNotDiscardTheRestOfTheBundle() {
        let damaged = """
            -----BEGIN CERTIFICATE-----
            this is not base64 at all
            -----END CERTIFICATE-----
            """ + "\n" + Self.bundlePEM
        let pinned = DsseTransportSecurityFactory.certificates(fromPEM: damaged)
        XCTAssertEqual(pinned.count, 2, "a malformed entry discarded the valid CAs that followed it")
    }

    func testNoCertificatesYieldsAnEmptyListRatherThanAFalsePin() {
        XCTAssertTrue(DsseTransportSecurityFactory.certificates(fromPEM: "nothing here").isEmpty)
    }

    // The security value must carry all of them, since that is what becomes the anchor set.
    func testTransportSecurityCarriesEveryPinnedCA() {
        let pinned = DsseTransportSecurityFactory.certificates(fromPEM: Self.bundlePEM)
        let security = DsseTransportSecurity(host: "edge.example.com", port: 18543, mtlsRequired: true,
                                             pinnedCACertificates: pinned, clientIdentity: nil)
        XCTAssertEqual(security.pinnedCACertificates.count, 2)
        XCTAssertNotNil(security.pinnedCACertificate, "the single-certificate accessor must still work")
    }
}

// The readiness signal an operator needs before rotating the transport CA: which CAs does this device pin?
// Reporting only the first would make a device that HAS picked up the incoming CA look as though it had not,
// and the operator would keep waiting for a fleet that is already ready.
extension DssePinnedCABundleTests {

    func testFingerprintsCoverEveryPinnedCA() {
        let pinned = DsseTransportSecurityFactory.certificates(fromPEM: Self.bundlePEM)
        let security = DsseTransportSecurity(host: "edge.example.com", port: 18543, mtlsRequired: true,
                                             pinnedCACertificates: pinned, clientIdentity: nil)
        let fingerprints = security.pinnedCAFingerprints

        XCTAssertEqual(fingerprints.count, 2,
                       "a device mid-rotation pins two CAs; reporting \(fingerprints.count) would make it look " +
                       "unready when it is ready")
        XCTAssertNotEqual(fingerprints[0], fingerprints[1], "the two CAs produced the same fingerprint")
        for fp in fingerprints {
            XCTAssertEqual(fp.count, 64, "not a SHA-256 hex digest: \(fp)")
            XCTAssertEqual(fp, fp.lowercased(), "fingerprints must be lower-case hex so the Edge can match them")
        }
    }

    func testNoPinnedCAsReportsNothingRatherThanAPlaceholder() {
        let security = DsseTransportSecurity(host: "edge.example.com", port: 18543, mtlsRequired: true,
                                             pinnedCACertificates: [], clientIdentity: nil)
        XCTAssertTrue(security.pinnedCAFingerprints.isEmpty,
                      "an empty list must stay empty — the Edge counts a device reporting nothing as SILENT, " +
                      "which is the safe reading, whereas a placeholder would be matched against a real CA")
    }
}
