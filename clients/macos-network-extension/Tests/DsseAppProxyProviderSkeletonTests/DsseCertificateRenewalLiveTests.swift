import XCTest
import Security
@testable import DsseAppProxyProviderSkeleton

// End-to-end renewal against a REAL Edge and the REAL keychain. No stubs.
//
// Everything the unit tests cover is arithmetic and encoding. What decides whether renewal is safe to ship is
// the part they cannot reach: does the Edge accept a CSR this code built, does the keychain actually form an
// identity from the key and certificate we stored, and does that identity complete an mTLS handshake? A mock
// keychain would answer yes to all three and prove nothing.
//
// OFF by default — it needs the reference lab and real device key material, so it cannot run on an ordinary
// checkout or in CI. Enable it explicitly:
//
//   DSSE_LIVE_RENEWAL_EDGE=203.0.113.10:18543 \
//   DSSE_LIVE_RENEWAL_CA=/path/to/transport.pem \
//   DSSE_LIVE_RENEWAL_P12=/path/to/win-device.p12 \
//   DSSE_LIVE_RENEWAL_P12_PASS=labtest \
//   DSSE_LIVE_RENEWAL_CN=win-dev-1 \
//   swift test --filter DsseCertificateRenewalLiveTests
//
// It installs under its own keychain labels and deletes them afterwards, so it cannot disturb a real device
// identity on the machine running it.
final class DsseCertificateRenewalLiveTests: XCTestCase {

    struct LiveConfig {
        let security: DsseTransportSecurity
        let commonName: String
    }

    // Every certificate these tests cause to be stored, kept as a REFERENCE so the final sweep removes exactly
    // those and nothing else — and so it does not depend on a keychain search that does not reliably see items
    // this process just added.
    nonisolated(unsafe) static var installedCertificates: [SecCertificate] = []

    override class func tearDown() {
        // By reference, never by a fresh lookup: a certificate this process stored is not reliably returned by
        // a later enumeration here, so a fingerprint-based sweep silently leaves it behind.
        for certificate in installedCertificates {
            DsseRenewedIdentityStore.remove(certificate: certificate)
        }
        installedCertificates.removeAll()
        super.tearDown()
    }

    // Each run gets its own throwaway config directory, so the pointer file it writes cannot be mistaken for
    // a real device's. Keychain material is removed by fingerprint in teardown.
    func makeScratchConfigDirectory() throws -> URL {
        let dir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("dsse-renewal-live-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: dir) }
        return dir
    }

    func liveConfig() throws -> LiveConfig? {
        let env = ProcessInfo.processInfo.environment
        guard let endpoint = env["DSSE_LIVE_RENEWAL_EDGE"],
              let caPath = env["DSSE_LIVE_RENEWAL_CA"],
              let p12Path = env["DSSE_LIVE_RENEWAL_P12"] else {
            return nil
        }
        let parts = endpoint.split(separator: ":")
        guard parts.count == 2, let port = Int(parts[1]) else {
            XCTFail("DSSE_LIVE_RENEWAL_EDGE must be host:port")
            return nil
        }
        let caPEM = try String(contentsOfFile: caPath, encoding: .utf8)
        let pinned = try XCTUnwrap(DsseTransportSecurityFactory.certificate(fromPEM: caPEM),
                                   "the pinned CA at \(caPath) could not be parsed")
        let p12 = try Data(contentsOf: URL(fileURLWithPath: p12Path))
        let identity = try XCTUnwrap(
            DsseTransportSecurityFactory.clientIdentity(fromP12Data: p12,
                                                        passphrase: env["DSSE_LIVE_RENEWAL_P12_PASS"] ?? ""),
            "the device identity at \(p12Path) could not be loaded")
        return LiveConfig(
            security: DsseTransportSecurity(host: String(parts[0]), port: port, mtlsRequired: true,
                                            pinnedCACertificate: pinned, clientIdentity: identity),
            commonName: env["DSSE_LIVE_RENEWAL_CN"] ?? "win-dev-1")
    }

    // The whole chain, in one run: generate a key, build a CSR, have the Edge sign it, validate the response,
    // store it in the keychain, and prove the stored identity can complete an mTLS handshake.
    func testRenewalRoundTripAgainstRealEdgeAndKeychain() throws {
        guard let live = try liveConfig() else {
            throw XCTSkip("live renewal check not configured — set DSSE_LIVE_RENEWAL_* to run it")
        }
        let configDirectory = try makeScratchConfigDirectory()
        let renewed = try DsseCertificateRenewal.renew(security: live.security,
                                                       commonName: live.commonName)
        let fingerprint = DsseRenewedIdentityStore.sha256Hex(
            SecCertificateCopyData(renewed.certificate) as Data)
        let keyTag = renewed.privateKeyTag
        Self.installedCertificates.append(renewed.certificate)
        let renewedCertificate = renewed.certificate
        addTeardownBlock {
            DsseRenewedIdentityStore.remove(certificate: renewedCertificate)
            DsseCertificateRenewal.deleteKey(tag: keyTag)
        }

        // The Edge takes the identity from the verified certificate, so this must come back as the device that
        // asked, whatever the CSR said.
        XCTAssertEqual(renewed.commonName, live.commonName)
        XCTAssertGreaterThan(renewed.notAfter, Date(), "the issued certificate is already expired")

        // Install it and prove it on the wire. The probe is a real request over mTLS with the NEW identity —
        // the step that makes this prove-then-swap rather than write-then-hope.
        var probed = false
        let installed = try DsseRenewedIdentityStore.install(
            renewed,
            configDirectory: configDirectory,
            probe: { candidate in
                probed = true
                return Self.handshakeSucceeds(with: candidate, like: live.security)
            })
        XCTAssertTrue(probed, "install must not promote an identity it never probed")

        var installedCertificate: SecCertificate?
        XCTAssertEqual(SecIdentityCopyCertificate(installed, &installedCertificate), errSecSuccess)
        XCTAssertEqual(SecCertificateCopyData(try XCTUnwrap(installedCertificate)) as Data,
                       SecCertificateCopyData(renewed.certificate) as Data,
                       "the keychain formed an identity around a different certificate")

        // And it is findable the way the transport will find it: through the pointer file, not a label.
        let pointer = try XCTUnwrap(DsseRenewedIdentityStore.readPointer(configDirectory: configDirectory),
                                    "no pointer file was written, so nothing puts the new identity in force")
        XCTAssertEqual(pointer.certificateSHA256, fingerprint)
        XCTAssertEqual(pointer.commonName, live.commonName)

        let looked = try XCTUnwrap(
            DsseRenewedIdentityStore.currentIdentity(configDirectory: configDirectory),
            "the installed identity is not resolvable from the pointer — the transport would not find it")
        var lookedCertificate: SecCertificate?
        XCTAssertEqual(SecIdentityCopyCertificate(looked, &lookedCertificate), errSecSuccess)
        XCTAssertEqual(SecCertificateCopyData(try XCTUnwrap(lookedCertificate)) as Data,
                       SecCertificateCopyData(renewed.certificate) as Data)
    }

    // A probe that says no must leave nothing behind. This is the safety property the whole design rests on:
    // a renewal that cannot be proven must cost nothing rather than break the device.
    func testRejectedProbeRollsBackAndLeavesNothingInstalled() throws {
        guard let live = try liveConfig() else {
            throw XCTSkip("live renewal check not configured — set DSSE_LIVE_RENEWAL_* to run it")
        }
        let configDirectory = try makeScratchConfigDirectory()
        let renewed = try DsseCertificateRenewal.renew(security: live.security,
                                                       commonName: live.commonName)
        let fingerprint = DsseRenewedIdentityStore.sha256Hex(
            SecCertificateCopyData(renewed.certificate) as Data)
        let keyTag = renewed.privateKeyTag
        Self.installedCertificates.append(renewed.certificate)
        let renewedCertificate = renewed.certificate
        addTeardownBlock {
            DsseRenewedIdentityStore.remove(certificate: renewedCertificate)
            DsseCertificateRenewal.deleteKey(tag: keyTag)
        }

        XCTAssertThrowsError(
            try DsseRenewedIdentityStore.install(renewed, configDirectory: configDirectory,
                                                 probe: { _ in false })
        ) { error in
            guard case DsseRenewedIdentityStoreError.probeRejectedNewIdentity = error else {
                return XCTFail("expected probeRejectedNewIdentity, got \(error)")
            }
        }

        XCTAssertNil(DsseRenewedIdentityStore.readPointer(configDirectory: configDirectory),
                     "a rejected identity was put in force — this is the bricking case")
        XCTAssertNil(DsseRenewedIdentityStore.identity(certificateSHA256: fingerprint),
                     "rejected material was left behind in the keychain")
    }

    // handshakeSucceeds does a real mTLS request with the candidate identity, pinned to the same CA. Renewal
    // hits /enroll/renew; the probe deliberately does not, so a candidate is not proven by the one endpoint
    // guaranteed to be lenient about it.
    static func handshakeSucceeds(with candidate: SecIdentity, like security: DsseTransportSecurity) -> Bool {
        let probeSecurity = DsseTransportSecurity(host: security.host, port: security.port,
                                                  mtlsRequired: true,
                                                  pinnedCACertificate: security.pinnedCACertificate,
                                                  clientIdentity: candidate)
        var request = URLRequest(url: URL(string: "https://\(security.host):\(security.port)/healthz")!)
        request.timeoutInterval = 15
        let session = DsseTransportTLS.makePinnedURLSession(security: probeSecurity)
        let (_, status, failure) = DsseCertificateRenewal.synchronousData(for: request, session: session,
                                                                         timeout: 15)
        // Any HTTP answer proves the mTLS handshake completed, which is what is being tested. A transport
        // error means the certificate was refused at the TLS layer — exactly what must block promotion.
        return failure == nil && status > 0
    }
}
