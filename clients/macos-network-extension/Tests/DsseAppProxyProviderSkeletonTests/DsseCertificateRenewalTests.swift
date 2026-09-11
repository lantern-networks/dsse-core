import XCTest
import Security
@testable import DsseAppProxyProviderSkeleton

// Tests for automated device-certificate renewal.
//
// The CSR encoder is hand-rolled DER, which is the kind of code that passes any test written by the same
// person who wrote the encoder. These tests therefore check it against something independent: the DER is
// dumped to a file that the live-Edge check (deploy/reference/verify-enroll-renew) and openssl can parse, and
// the timing rule is checked against the same table as the Go implementation it must mirror.
final class DsseCertificateRenewalTests: XCTestCase {

    // The renewal window must match renewalDue() in cmd/edge/enroll_renew_endpoint.go exactly. If the client
    // renewed later than the server expects, the retry budget the server's design depends on would not exist.
    func testRenewalOpensAtTwoThirdsOfLifeLeavingRetryBudget() {
        let notBefore = Date(timeIntervalSince1970: 1_767_225_600) // 2026-01-01T00:00:00Z
        let day = 24.0 * 3600.0
        let notAfter = notBefore.addingTimeInterval(60 * day)

        let cases: [(String, Date, Bool)] = [
            ("fresh", notBefore, false),
            ("halfway", notBefore.addingTimeInterval(30 * day), false),
            ("just before two thirds", notBefore.addingTimeInterval(40 * day - 60), false),
            ("at two thirds", notBefore.addingTimeInterval(40 * day), true),
            ("day 50 — 10 days of retries left", notBefore.addingTimeInterval(50 * day), true),
            ("expired", notAfter.addingTimeInterval(3600), true),
        ]
        for (name, now, want) in cases {
            XCTAssertEqual(DsseCertificateRenewal.renewalDue(notBefore: notBefore, notAfter: notAfter, now: now),
                           want, "renewalDue at \(name)")
        }
    }

    // "We cannot tell when this expires" must not mean "renew now". Treating an unreadable window as due would
    // turn one malformed certificate into a device renewing on every single check.
    func testDegenerateValidityWindowIsNotDue() {
        let now = Date()
        XCTAssertFalse(DsseCertificateRenewal.renewalDue(notBefore: now, notAfter: now, now: now),
                       "a zero-length window must not be due")
        XCTAssertFalse(DsseCertificateRenewal.renewalDue(notBefore: now,
                                                         notAfter: now.addingTimeInterval(-3600), now: now),
                       "an inverted window must not be due")
    }

    // The CSR has to be structurally sound before anything else is worth testing. Checked here at the level a
    // parser cares about — outer tag, declared length matching the real length — with the real proof being that
    // the live Edge signs it.
    func testCertificateSigningRequestIsWellFormedDER() throws {
        let (key, tag) = try DsseCertificateRenewal.generateDeviceKey()
        addTeardownBlock { DsseCertificateRenewal.deleteKey(tag: tag) }
        let pem = try DsseCertificateRenewal.certificateSigningRequestPEM(privateKey: key, commonName: "mac-dev-1")

        XCTAssertTrue(pem.hasPrefix("-----BEGIN CERTIFICATE REQUEST-----"))
        XCTAssertTrue(pem.hasSuffix("-----END CERTIFICATE REQUEST-----\n"))

        let base64 = pem.split(separator: "\n").filter { !$0.contains("-----") }.joined()
        let der = try XCTUnwrap(Data(base64Encoded: base64), "the CSR body is not valid base64")

        XCTAssertEqual(der.first, 0x30, "a CertificationRequest must be a SEQUENCE")
        let (declared, headerLength) = try XCTUnwrap(Self.derLength(der, at: 1), "unreadable outer length")
        XCTAssertEqual(declared + 1 + headerLength, der.count,
                       "the declared DER length does not match the encoded bytes — long-form length encoding is wrong")

        // The subject common name must be in there. Not authority — the Edge overrides it — but a CSR whose
        // subject silently vanished would be a real encoder bug.
        XCTAssertTrue(der.range(of: Data("mac-dev-1".utf8)) != nil, "the CSR does not carry the common name")

        // Written out so it can be parsed by openssl / the live check rather than only by my own reader.
        let out = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("dsse-renewal-csr.pem")
        try? pem.write(to: out, atomically: true, encoding: .utf8)
    }

    // Long-form lengths are where naive DER encoders break: everything works while structures stay under 128
    // bytes, and a CSR is always larger.
    func testLongFormLengthEncoding() {
        XCTAssertEqual(Array(DER.length(0)), [0x00])
        XCTAssertEqual(Array(DER.length(127)), [0x7F], "127 is the last short-form length")
        XCTAssertEqual(Array(DER.length(128)), [0x81, 0x80], "128 must switch to long form")
        XCTAssertEqual(Array(DER.length(255)), [0x81, 0xFF])
        XCTAssertEqual(Array(DER.length(256)), [0x82, 0x01, 0x00])
    }

    // A BIT STRING's leading byte is the unused-bit count. Dropping it does not shorten the value, it shifts
    // the whole thing, and the signature silently stops verifying.
    func testBitStringCarriesTheUnusedBitCount() {
        let encoded = DER.bitString(Data([0xAB, 0xCD]))
        XCTAssertEqual(Array(encoded), [0x03, 0x03, 0x00, 0xAB, 0xCD])
    }

    // MARK: - Response validation
    //
    // These are the checks that stand between a bad response and a device that can no longer connect.

    func testCanonicalizedRenewalCertificateKeepsTheSameDeviceIdentity() throws {
        let directory = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        addTeardownBlock { try? FileManager.default.removeItem(at: directory) }
        let (key, tag) = try DsseCertificateRenewal.generateDeviceKey()
        addTeardownBlock { DsseCertificateRenewal.deleteKey(tag: tag) }
        let csr = try DsseCertificateRenewal.certificateSigningRequestPEM(privateKey: key, commonName: "shinnomac-mini")
        try csr.write(to: directory.appendingPathComponent("device.csr"), atomically: true, encoding: .utf8)
        func openssl(_ arguments: [String]) throws {
            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
            process.arguments = arguments
            process.currentDirectoryURL = directory
            process.standardOutput = FileHandle.nullDevice
            process.standardError = FileHandle.nullDevice
            try process.run()
            process.waitUntilExit()
            XCTAssertEqual(process.terminationStatus, 0, "fixture certificate generation failed")
        }
        try openssl(["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                     "-subj", "/CN=RenewalFixtureCA", "-keyout", "ca-key.pem", "-out", "ca.pem", "-days", "2"])
        try openssl(["x509", "-req", "-in", "device.csr", "-CA", "ca.pem", "-CAkey", "ca-key.pem",
                     "-set_serial", "11", "-days", "1", "-out", "device.pem"])
        let pem = try String(contentsOf: directory.appendingPathComponent("device.pem"), encoding: .utf8)
        let ca = try String(contentsOf: directory.appendingPathComponent("ca.pem"), encoding: .utf8)
        for expected in ["shinnomac-mini", "ShinnoMac-mini", " SHINNOMAC-MINI "] {
            let renewed = try DsseCertificateRenewal.validate(certificatePEM: pem, caPEM: ca,
                privateKey: key, privateKeyTag: tag, expectedCommonName: expected)
            XCTAssertEqual(renewed.commonName, "shinnomac-mini")
        }
        for other in ["another-mac", "shinnomac-mini-2", "", "  "] {
            XCTAssertThrowsError(try DsseCertificateRenewal.validate(certificatePEM: pem, caPEM: ca,
                privateKey: key, expectedCommonName: other)) { error in
                guard case DsseCertificateRenewalError.responseUnusable(let reason) = error else {
                    return XCTFail("unexpected refusal: \(error)")
                }
                XCTAssertTrue(reason.contains("issued certificate names"))
            }
        }
    }

    // The most dangerous response to accept: a valid, well-signed certificate for somebody else's key. It
    // installs perfectly and then fails at the next handshake, by which point the working identity is gone.
    func testCertificateForADifferentKeyIsRejected() throws {
        let (ourKey, ourTag) = try DsseCertificateRenewal.generateDeviceKey()
        addTeardownBlock { DsseCertificateRenewal.deleteKey(tag: ourTag) }
        let somebodyElsesCertificate = Self.otherPartysCertificatePEM

        XCTAssertThrowsError(
            try DsseCertificateRenewal.validate(certificatePEM: somebodyElsesCertificate, caPEM: "",
                                                privateKey: ourKey, expectedCommonName: "mac-dev-1")
        ) { error in
            guard case DsseCertificateRenewalError.responseUnusable(let why) = error else {
                return XCTFail("expected responseUnusable, got \(error)")
            }
            XCTAssertTrue(why.contains("DIFFERENT key"), "wrong rejection reason: \(why)")
        }
    }

    func testUnparseableCertificateIsRejected() throws {
        let (key, tag) = try DsseCertificateRenewal.generateDeviceKey()
        addTeardownBlock { DsseCertificateRenewal.deleteKey(tag: tag) }
        XCTAssertThrowsError(
            try DsseCertificateRenewal.validate(certificatePEM: "-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----",
                                                caPEM: "", privateKey: key,
                                                expectedCommonName: "mac-dev-1"))
    }

    // MARK: - Helpers

    // derLength reads a definite-length header, returning (length, bytes consumed by the length field).
    static func derLength(_ data: Data, at index: Int) -> (Int, Int)? {
        guard index < data.count else { return nil }
        let first = data[data.startIndex + index]
        if first < 0x80 { return (Int(first), 1) }
        let count = Int(first & 0x7F)
        guard count > 0, index + count < data.count else { return nil }
        var value = 0
        for offset in 1...count {
            value = (value << 8) | Int(data[data.startIndex + index + offset])
        }
        return (value, 1 + count)
    }

    // A real P-256 certificate for a key nobody in this test holds. CN=mac-dev-1, valid to 2046.
    //
    // Fixed rather than generated at run time on purpose. The first version of this test shelled out to
    // openssl, and macOS ships LibreSSL, which silently ignored -pkeyopt ec_paramgen_curve and emitted a
    // certificate whose key Security.framework would not load at all. The test then "failed" for a reason that
    // had nothing to do with the code under test. A constant cannot drift with whatever openssl is on the box.
    static let otherPartysCertificatePEM = """
        -----BEGIN CERTIFICATE-----
        MIIBFzCBvgIJAI3EZk4GrRQXMAoGCCqGSM49BAMCMBQxEjAQBgNVBAMMCW1hYy1k
        ZXYtMTAeFw0yNjA3MjgwMzU3MDRaFw00NjA3MjMwMzU3MDRaMBQxEjAQBgNVBAMM
        CW1hYy1kZXYtMTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABFuNcmeJVwYB0zkS
        JZhIjS5A/5C2OQDdxApa//W3TIXXgOlJHhXoG4xUsxzZqyhWHSDr4pWrtQTVGahQ
        TDUrbm4wCgYIKoZIzj0EAwIDSAAwRQIgUP5uGa6EFnuw4YwSeMlBvCAK6fyZVNZh
        usi9XfhGyZ4CIQC0f/6l3MCymBRqsO+QH5JYDej+8dhjsQbh5OWy3oomSg==
        -----END CERTIFICATE-----
        """
}

// The check interval must fit inside the retry budget, which is a third of the certificate's life. A FIXED
// interval is wrong for short-lived certificates in the worst possible way: nothing errors, nothing logs, and
// the certificate simply expires unchecked.
extension DsseCertificateRenewalTests {

    func testCheckIntervalFitsInsideTheRetryBudget() {
        let notBefore = Date(timeIntervalSince1970: 1_767_225_600)
        let lifetimes: [(String, TimeInterval)] = [
            ("60-day — what /enroll issues today", 60 * 24 * 3600),
            ("24-hour", 24 * 3600),
            ("1-hour", 3600),
            ("5-minute", 300),
        ]
        for (name, life) in lifetimes {
            let interval = DsseCertificateRenewalScheduler.checkInterval(
                notBefore: notBefore, notAfter: notBefore.addingTimeInterval(life))
            let budget = life / 3

            XCTAssertLessThanOrEqual(interval, budget,
                "\(name): a \(Int(interval))s interval exceeds the \(Int(budget))s retry budget — with a fixed " +
                "6h interval a 1-hour certificate got ZERO checks before expiring")
            XCTAssertGreaterThanOrEqual(budget / interval, 2,
                "\(name): only \(Int(budget / interval)) attempt(s) inside the retry budget — one transient " +
                "failure would consume the whole margin")
            XCTAssertLessThanOrEqual(interval, DsseCertificateRenewalScheduler.maxCheckInterval)
            XCTAssertGreaterThanOrEqual(interval, DsseCertificateRenewalScheduler.minCheckInterval)
        }
    }

    func testCheckIntervalIsCappedForLongLivedCertificates() {
        let notBefore = Date(timeIntervalSince1970: 1_767_225_600)
        XCTAssertEqual(
            DsseCertificateRenewalScheduler.checkInterval(
                notBefore: notBefore, notAfter: notBefore.addingTimeInterval(10 * 365 * 24 * 3600)),
            DsseCertificateRenewalScheduler.maxCheckInterval,
            "a 10-year certificate must not push the interval past the cap")
    }

    func testCheckIntervalHandlesDegenerateWindows() {
        let now = Date()
        for (notBefore, notAfter) in [(now, now), (now, now.addingTimeInterval(-3600))] {
            XCTAssertEqual(DsseCertificateRenewalScheduler.checkInterval(notBefore: notBefore, notAfter: notAfter),
                           DsseCertificateRenewalScheduler.maxCheckInterval,
                           "a window we cannot read must fall back to the default, not to something nonsensical")
        }
    }
}
