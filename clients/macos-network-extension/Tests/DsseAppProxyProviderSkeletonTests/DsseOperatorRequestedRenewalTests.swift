import XCTest
@testable import DsseAppProxyProviderSkeleton

// An operator can declare that certificates issued before some moment are stale, and the agent renews on its
// next check rather than at two thirds of its certificate's life.
//
// The rule it supplements is right almost always: two thirds of life leaves the final third as retry budget,
// so a broken renewal path is an alert rather than an outage. It is wrong after the issuing CA changes. A
// certificate signed by a superseded CA is stale the day the CA is replaced, however much validity remains —
// and the extreme case is real: a ten-year certificate whose two-thirds point is in 2033, which keeps the old
// CA alive for seven years because something still depends on it.
final class DsseOperatorRequestedRenewalTests: XCTestCase {

    private func date(_ iso: String) -> Date {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime]
        return f.date(from: iso)!
    }

    // Without a cutoff, nothing changes: the two-thirds rule alone decides.
    func testWithoutACutoffTheOrdinaryScheduleApplies() {
        let notBefore = date("2026-07-01T00:00:00Z")
        let notAfter = date("2026-08-30T00:00:00Z") // 60 days
        XCTAssertFalse(DsseCertificateRenewal.renewalDue(
            notBefore: notBefore, notAfter: notAfter, renewIfIssuedBefore: nil,
            now: date("2026-07-20T00:00:00Z")), "20 days into a 60-day certificate is not yet two thirds")
        XCTAssertTrue(DsseCertificateRenewal.renewalDue(
            notBefore: notBefore, notAfter: notAfter, renewIfIssuedBefore: nil,
            now: date("2026-08-15T00:00:00Z")), "past two thirds, renewal is due")
    }

    // The case this exists for: a certificate with years of validity left, issued before the cutoff.
    func testACertificateOlderThanTheCutoffRenewsHoweverLongItHasLeft() {
        let notBefore = date("2026-07-17T00:00:00Z")
        let notAfter = date("2036-07-14T00:00:00Z") // ten years — two thirds lands in 2033
        let now = date("2026-07-31T00:00:00Z")

        XCTAssertFalse(DsseCertificateRenewal.renewalDue(notBefore: notBefore, notAfter: notAfter, now: now),
                       "precondition: the ordinary rule would wait until 2033")
        XCTAssertTrue(DsseCertificateRenewal.renewalDue(
            notBefore: notBefore, notAfter: notAfter,
            renewIfIssuedBefore: date("2026-07-31T00:00:00Z"), now: now),
            "a certificate issued before the cutoff is stale regardless of how much validity it has left")
    }

    // Idempotence, which is why this is a declaration rather than a command. Once the agent has renewed, its
    // certificate was issued AFTER the cutoff and the instruction stops applying — no acknowledgements, no
    // per-device state, and no way to renew twice off one request.
    func testACertificateIssuedAfterTheCutoffIsNotRenewedAgain() {
        let cutoff = date("2026-07-31T00:00:00Z")
        let renewed = date("2026-07-31T00:05:00Z") // issued five minutes after the cutoff
        XCTAssertFalse(DsseCertificateRenewal.renewalDue(
            notBefore: renewed, notAfter: date("2026-09-29T00:00:00Z"),
            renewIfIssuedBefore: cutoff, now: date("2026-08-01T00:00:00Z")),
            "the freshly issued certificate must not match the cutoff that produced it")
    }

    // The cutoff must come from a SIGNED policy. This value can make a fleet replace its credentials, so
    // accepting it unverified would hand that to whoever can answer on the network.
    func testAnUnsignedOrTamperedPolicyYieldsNoCutoff() {
        let notSigned = Data(#"{"renew_certificates_issued_before":"2026-07-31T00:00:00Z"}"#.utf8)
        XCTAssertNil(DsseSignedAgentPolicy.verifiedRenewCertificatesIssuedBefore(
            envelopeData: notSigned, pinnedPublicKeyHex: String(repeating: "ab", count: 32)),
            "a bare payload is not a signed policy")
        XCTAssertNil(DsseSignedAgentPolicy.verifiedRenewCertificatesIssuedBefore(
            envelopeData: Data("not json".utf8), pinnedPublicKeyHex: String(repeating: "ab", count: 32)),
            "garbage must read as no instruction, never as renew-now")
    }
}
