import XCTest
@testable import DsseAppProxyProviderSkeleton

// Enrols against a RUNNING Edge with a real admin-issued token, so it is deployment-specific and takes its inputs
// from the environment. It SKIPS when they are absent: this lives in the public OSS package, where nobody else has
// this lab, and a test that fails everywhere but one machine is worse than no test at all.
//
//   DSSE_LAB_ENROL_URL        POST /enroll on the Edge under test
//   DSSE_LAB_ENROL_TOKEN      an UNSPENT admin-issued enrolment token (one-time — each run needs a fresh one)
//   DSSE_LAB_ENROL_CA         path to the PEM the enrol endpoint's TLS is verified against
//   DSSE_LAB_ENROL_DEVICE_ID  a throwaway device name; remove it from the Enrolled Inventory afterwards
final class DsseDeviceEnrolmentLiveTests: XCTestCase {
    private func env(_ key: String) -> String? {
        guard let v = ProcessInfo.processInfo.environment[key]?
            .trimmingCharacters(in: .whitespacesAndNewlines), !v.isEmpty else { return nil }
        return v
    }

    private func liveConfig() throws -> DsseEnrolmentConfig {
        guard let url = env("DSSE_LAB_ENROL_URL"),
              let token = env("DSSE_LAB_ENROL_TOKEN"),
              let deviceID = env("DSSE_LAB_ENROL_DEVICE_ID"),
              let caPath = env("DSSE_LAB_ENROL_CA"),
              let caPEM = try? String(contentsOfFile: caPath, encoding: .utf8) else {
            throw XCTSkip("set DSSE_LAB_ENROL_URL/TOKEN/DEVICE_ID/CA to run the live enrolment")
        }
        return DsseEnrolmentConfig(enrolURL: url, deviceID: deviceID, token: token, enrolCAPEM: caPEM)
    }

    // The whole Day-0 path in one go: this machine generates its own key, asks for a certificate with a token it
    // was handed, and gets one it can actually use. Everything the renewal path validates is validated here too —
    // same key, right name, not already due for renewal — because an unusable certificate at enrolment bricks the
    // endpoint before it has ever worked.
    func testAFreshMachineEnrolsWithAnAdminIssuedToken() throws {
        let config = try liveConfig()
        // The key lands in the keychain on success. Leaving it is how device identities accumulate (#23), and
        // this one belongs to a throwaway name that will be removed from the ledger.
        var tag = ""
        defer { if !tag.isEmpty { DsseCertificateRenewal.deleteKey(tag: tag) } }

        let identity = try DsseDeviceEnrolment.enrol(config: config)
        tag = identity.privateKeyTag

        XCTAssertEqual(identity.commonName, config.deviceID,
                       "the Edge assigns the identity; a different name means it enrolled something else")
        XCTAssertFalse(identity.certificatePEM.isEmpty)
        XCTAssertFalse(identity.caPEM.isEmpty, "without the CA the device cannot verify anything it is issued")
        XCTAssertGreaterThan(identity.notAfter, Date(), "an already-expired certificate is not an enrolment")
    }

    // The same token a second time. On the server it is already spent, so this is the property that stops a copied
    // installer config from enrolling a fleet — and it has to hold against the real endpoint, not just the store.
    func testTheSameTokenCannotEnrolATwiceMachine() throws {
        let config = try liveConfig()
        var firstTag = ""
        defer { if !firstTag.isEmpty { DsseCertificateRenewal.deleteKey(tag: firstTag) } }

        let first = try DsseDeviceEnrolment.enrol(config: config)
        firstTag = first.privateKeyTag

        let second = DsseEnrolmentConfig(enrolURL: config.enrolURL, deviceID: config.deviceID + "-copy",
                                         token: config.token, enrolCAPEM: config.enrolCAPEM)
        XCTAssertThrowsError(try DsseDeviceEnrolment.enrol(config: second)) { error in
            guard case .serverRefused(let status, _) = (error as? DsseDeviceEnrolmentError) else {
                return XCTFail("expected a server refusal, got \(error)")
            }
            XCTAssertEqual(status, 403)
        }
    }

    // A pin that does not match the CA the Edge actually issues from must stop the enrolment, or cross-checking
    // the issuer would be decorative — and an impersonated endpoint could hand this machine an identity from a CA
    // of its choosing.
    func testAWrongDeviceCAPinRefusesTheIssuedIdentity() throws {
        let live = try liveConfig()
        let config = DsseEnrolmentConfig(enrolURL: live.enrolURL, deviceID: live.deviceID, token: live.token,
                                         enrolCAPEM: live.enrolCAPEM,
                                         deviceCAPinSHA256: String(repeating: "ab", count: 32))
        XCTAssertThrowsError(try DsseDeviceEnrolment.enrol(config: config)) { error in
            guard case .caPinMismatch = (error as? DsseDeviceEnrolmentError) else {
                return XCTFail("expected a CA pin mismatch, got \(error)")
            }
        }
    }
}
