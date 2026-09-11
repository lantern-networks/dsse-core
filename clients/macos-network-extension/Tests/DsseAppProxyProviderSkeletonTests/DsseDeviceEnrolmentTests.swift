import XCTest
import CryptoKit
import Security
@testable import DsseAppProxyProviderSkeleton

final class DsseDeviceEnrolmentTests: XCTestCase {
    private func write(_ json: String) throws -> String {
        let path = NSTemporaryDirectory() + "dsse-enrol-\(UUID().uuidString).json"
        try json.write(toFile: path, atomically: true, encoding: .utf8)
        addTeardownBlock { try? FileManager.default.removeItem(atPath: path) }
        return path
    }

    func testReadsTheEnrolmentBlockFromTheInstallConfig() throws {
        let path = try write("""
        {
          "client_identity_common_name": "ignored-when-block-names-one",
          "enrolment": {
            "enrol_url": "https://edge.example:8443/enroll",
            "device_id": "laptop-01",
            "enrolment_token": "s3cr3t",
            "tenant": "tenant_a",
            "device_ca_pin_sha256": "AABBCC"
          }
        }
        """)
        let config = try XCTUnwrap(DsseDeviceEnrolment.readConfig(at: path))
        XCTAssertEqual(config.deviceID, "laptop-01")
        XCTAssertEqual(config.token, "s3cr3t")
        XCTAssertEqual(config.enrolURL, "https://edge.example:8443/enroll")
        XCTAssertTrue(config.isPresent)
        XCTAssertTrue(config.hasPinnedBootstrap)
    }

    // A machine that already holds an identity has no enrolment block, and one whose token was erased after use
    // has no token. Neither is an error at this layer — the caller decides what to say.
    func testAConfigWithoutATokenIsNotAnEnrolmentConfig() throws {
        let path = try write("""
        {"enrolment": {"enrol_url": "https://edge.example:8443/enroll", "device_id": "laptop-01"}}
        """)
        XCTAssertNil(DsseDeviceEnrolment.readConfig(at: path))
        XCTAssertNil(DsseDeviceEnrolment.readConfig(at: "/nonexistent/agent_config.json"))
    }

    // Enrolment is the trust bootstrap. With nothing to verify the channel or the issuing CA against, a MITM
    // could hand this machine an identity from a CA of their choosing — so it must refuse rather than proceed.
    func testEnrolRefusesAnUnpinnedBootstrap() {
        let config = DsseEnrolmentConfig(enrolURL: "https://edge.example:8443/enroll",
                                         deviceID: "laptop-01", token: "s3cr3t")
        XCTAssertFalse(config.hasPinnedBootstrap)
        XCTAssertThrowsError(try DsseDeviceEnrolment.enrol(config: config)) { error in
            XCTAssertEqual(error as? DsseDeviceEnrolmentError, .unpinnedTransport)
        }
    }

    func testEitherPinSatisfiesTheBootstrapRequirement() {
        let byCA = DsseEnrolmentConfig(enrolURL: "https://e:8443/enroll", deviceID: "d", token: "t",
                                       enrolCAPEM: "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----")
        let byPin = DsseEnrolmentConfig(enrolURL: "https://e:8443/enroll", deviceID: "d", token: "t",
                                        deviceCAPinSHA256: "aabb")
        XCTAssertTrue(byCA.hasPinnedBootstrap)
        XCTAssertTrue(byPin.hasPinnedBootstrap)
    }

    func testEnrolRefusesAnIncompleteConfig() {
        let noToken = DsseEnrolmentConfig(enrolURL: "https://e:8443/enroll", deviceID: "d", token: "",
                                          deviceCAPinSHA256: "aabb")
        XCTAssertThrowsError(try DsseDeviceEnrolment.enrol(config: noToken)) { error in
            guard case .notConfigured = (error as? DsseDeviceEnrolmentError) else {
                return XCTFail("expected notConfigured, got \(error)")
            }
        }
    }

    // The token is one-time on the server, so leaving it cannot enrol a second machine — but it is a credential
    // sitting in a file for no remaining purpose, and an operator reading that file later cannot tell whether it
    // is live. Erasing it also records that it WAS spent, which is the thing they actually want to know.
    func testTheSpentTokenIsErasedFromTheConfig() throws {
        let path = try write("""
        {"enrolment": {"enrol_url": "https://e:8443/enroll", "device_id": "d", "enrolment_token": "s3cr3t"}}
        """)
        XCTAssertTrue(DsseDeviceEnrolment.eraseSpentToken(at: path))

        let raw = try String(contentsOfFile: path, encoding: .utf8)
        XCTAssertFalse(raw.contains("s3cr3t"), "the spent token is still in the config file")
        XCTAssertTrue(raw.contains("enrolment_token_spent"))
        // The rest of the config must survive: erasing a credential must not wipe the machine's configuration.
        XCTAssertTrue(raw.contains("enrol_url"))
        XCTAssertTrue(raw.contains("\"device_id\""))
        XCTAssertNil(DsseDeviceEnrolment.readConfig(at: path), "an erased token leaves nothing to enrol with")
    }

    func testErasingIsIdempotentAndSafeOnAConfigWithNoToken() throws {
        let path = try write(#"{"enrolment": {"enrol_url": "https://e:8443/enroll", "device_id": "d"}}"#)
        XCTAssertFalse(DsseDeviceEnrolment.eraseSpentToken(at: path))
        XCTAssertFalse(DsseDeviceEnrolment.eraseSpentToken(at: "/nonexistent/agent_config.json"))
    }

    // The pin is compared as lower-case hex of the DER, which is the same shape the Windows agent uses, so one
    // install profile can carry one pin for both platforms. An unparseable ca_pem yields "" and therefore fails
    // the comparison rather than passing it.
    func testTheCAFingerprintIsEmptyWhenThePEMCarriesNoCertificate() {
        XCTAssertEqual(DsseDeviceEnrolment.deviceCAFingerprint(caPEM: ""), "")
        XCTAssertEqual(DsseDeviceEnrolment.deviceCAFingerprint(caPEM: "not a certificate"), "")
    }

    // The pin covers the FIRST certificate in ca_pem, and it must be a stable function of the DER — the
    // fingerprint an admin copies out of the Console has to be the one the device computes.
    func testTheCAFingerprintIsTheDERDigestOfTheFirstCertificate() throws {
        let anchors = DsseSignedTrustBundle.parseAnchors(DsseTestAnchors.twoCABundlePEM)
        try XCTSkipIf(anchors.count < 2, "the embedded bundle did not parse as two CAs")
        let der = SecCertificateCopyData(anchors[0]) as Data
        let expected = SHA256.hash(data: der).map { String(format: "%02x", $0) }.joined()

        let got = DsseDeviceEnrolment.deviceCAFingerprint(caPEM: DsseTestAnchors.twoCABundlePEM)
        XCTAssertEqual(got, expected)
        XCTAssertEqual(got.count, 64)

        // A DIFFERENT CA must not satisfy the same pin, or cross-checking the issuer would be decorative.
        let otherDER = SecCertificateCopyData(anchors[1]) as Data
        let other = SHA256.hash(data: otherDER).map { String(format: "%02x", $0) }.joined()
        XCTAssertNotEqual(got, other)
    }
}
