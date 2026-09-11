import XCTest
import CryptoKit
@testable import DsseAppProxyProviderSkeleton

/// ★★★ MEASURED ON A REAL MAC, 2026-08-29. This Mac was installed for hikari.lab with a fresh profile, a
/// fresh deployment anchor and a fresh enrolment — and dialled every door asking for
/// `44paeqjensoua35pt4xyvkln6m.dsse.invalid`, a name belonging to a deployment that no longer exists. The
/// adopted-anchor store is authoritative (its set REPLACES the provisioned one, which is what makes a
/// withdrawal possible), and it recorded no deployment, so a re-install onto a different deployment carried
/// the old one's anchors and announced name straight through. The Edge answered exactly as designed:
///
///	transport_server_name: a device asked for "44paeq….dsse.invalid", which this node does not serve
///	door=agent-plane http: TLS handshake error: remote error: tls: unknown certificate
final class AnchorsAdoptedForAnotherDeploymentTests: XCTestCase {
    private func writePointer(_ dir: URL, tenant: String?, serial: Int64 = 5603) throws {
        var body: [String: Any] = ["serial": serial, "fingerprints": [], "adopted_at": "2026-08-25T05:37:00Z",
                                   "transport_server_name": "44paeqjensoua35pt4xyvkln6m.dsse.invalid"]
        if let tenant { body["tenant_id"] = tenant }
        try JSONSerialization.data(withJSONObject: body)
            .write(to: dir.appendingPathComponent(DsseAdoptedTrustAnchorStore.pointerFileName))
    }


    /// A profile signed by a key, and that key written where the OPERATOR places it. Both are needed: a
    /// profile alone proves nothing, which is the property this device's whole install lane rests on.
    private func installProfile(_ dir: URL, tenant: String,
                                name: String = "j32kxkri2wajxrllj2kiqmfghe.hikari.lab") throws {
        let key = Curve25519.Signing.PrivateKey()
        let payload = try JSONSerialization.data(withJSONObject: [
            "kind": "dsse_install_profile.v1",
            "version": 1,
            "tenant_id": tenant,
            "transport_url": "https://agents.tokyo.hikari.lab",
            "organization": ["tenant_id": tenant, "transport_server_name": name],
        ])
        let sig = try key.signature(for: payload)
        let env: [String: Any] = [
            "type": "dsse_install_profile.v1",
            "version": "1",
            "signing_key_id": "test",
            "created_at": "2026-08-29T00:00:00Z",
            "payload_sha256": SHA256.hash(data: payload).map { String(format: "%02x", $0) }.joined(),
            "payload_b64": payload.base64EncodedString(),
            "signature": "ed25519:" + sig.base64EncodedString()
                .replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_")
                .replacingOccurrences(of: "=", with: ""),
        ]
        try JSONSerialization.data(withJSONObject: env)
            .write(to: dir.appendingPathComponent("install_profile.json"))
        let hex = key.publicKey.rawRepresentation.map { String(format: "%02x", $0) }.joined()
        try Data((hex + "\n").utf8).write(to: dir.appendingPathComponent("profile_signing_key.txt"))
    }

    /// ★ THE MEASURED CASE. Installed for one deployment, carrying another's adopted material.
    func testMaterialAdoptedForAnotherDeploymentIsDiscarded() throws {
        let dir = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        try installProfile(dir, tenant: "tenant_j32kxkri2wajxrllj2kiqmfghe")
        try writePointer(dir, tenant: "tenant_44paeqjensoua35pt4xyvkln6m")
        XCTAssertEqual(DsseAdoptedTenantScope.tenantInForce(configDirectory: dir),
                       "tenant_j32kxkri2wajxrllj2kiqmfghe",
                       "the profile the operator installed does not say which deployment this device is for")
        XCTAssertEqual(DsseAdoptedTrustAnchorStore.advertisedTransportServerName(configDirectory: dir), "",
                       "this device would still ask for the previous deployment's name and be refused at "
                       + "every door of the one it is installed for")
        XCTAssertNil(DsseAdoptedTrustAnchorStore.currentAnchors(configDirectory: dir),
                     "another deployment's anchors are still REPLACING the ones the installer placed")
    }

    /// And its own deployment's material is kept — the check must not discard the anchors of a device that
    /// adopted a rotation correctly, which is the entire purpose of this store.
    func testItsOwnDeploymentsMaterialIsKept() throws {
        let dir = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        try installProfile(dir, tenant: "tenant_j32kxkri2wajxrllj2kiqmfghe")
        // ★ Deliberately a name the profile does not serve: within ONE deployment that is a RENAME, and the
        // tenant settles it. Discarding here would roll the replay guard back to 0 — letting a withdrawn CA be
        // adopted again — over a name the profile itself corrects.
        try writePointer(dir, tenant: "tenant_j32kxkri2wajxrllj2kiqmfghe")
        XCTAssertEqual(DsseAdoptedTrustAnchorStore.lastAcceptedSerial(configDirectory: dir), 5603,
                       "a device that adopted its OWN deployment's rotation had it discarded — the replay "
                       + "guard is back to 0 and a withdrawn CA becomes acceptable again")
    }


    /// ★★★ THE MACHINE THAT ACTUALLY HAD THE PROBLEM. Its pointer was written on 2026-08-24, long before any
    /// tenant was recorded on one — as was every pointer in the fleet on the day this was found. A check that
    /// only reads the tenant leaves exactly the devices it was written for untouched: the first build of this
    /// fix was installed on that Mac and it went on sending 44paeq….dsse.invalid.
    func testAnUnstampedPointerNamingAnotherDeploymentsNameIsDiscarded() throws {
        let dir = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        try installProfile(dir, tenant: "tenant_j32kxkri2wajxrllj2kiqmfghe")
        try writePointer(dir, tenant: nil)   // exactly what was on the Mac
        XCTAssertEqual(DsseAdoptedTrustAnchorStore.advertisedTransportServerName(configDirectory: dir), "",
                       "the device still asks for the previous deployment's name, which is the whole defect")
        XCTAssertEqual(DsseAdoptedTrustAnchorStore.lastAcceptedSerial(configDirectory: dir), 0)
    }

    /// And an unstamped pointer naming THIS deployment's name is kept — a device that adopted a rotation
    /// before the tenant was recorded must not lose it.
    func testAnUnstampedPointerNamingThisDeploymentIsKept() throws {
        let dir = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        try installProfile(dir, tenant: "tenant_j32kxkri2wajxrllj2kiqmfghe", name: "the-same.hikari.lab")
        var body: [String: Any] = ["serial": 5603, "fingerprints": [], "adopted_at": "2026-08-25T05:37:00Z",
                                   "transport_server_name": "the-same.hikari.lab"]
        try JSONSerialization.data(withJSONObject: body)
            .write(to: dir.appendingPathComponent(DsseAdoptedTrustAnchorStore.pointerFileName))
        body = [:]
        XCTAssertEqual(DsseAdoptedTrustAnchorStore.lastAcceptedSerial(configDirectory: dir), 5603,
                       "a device that adopted its own deployment's rotation had it discarded")
    }

    /// With no profile there is nothing to compare against, so the adopted material stands — a fleet on a
    /// pre-profile deployment must not have its anchors discarded by a check it cannot answer.
    func testWithNoProfileTheAdoptedMaterialStands() throws {
        let dir = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        try writePointer(dir, tenant: "tenant_someone_else")
        XCTAssertNil(DsseAdoptedTenantScope.tenantInForce(configDirectory: dir),
                     "a device with no verifiable profile answered which deployment it belongs to")
        XCTAssertEqual(DsseAdoptedTrustAnchorStore.lastAcceptedSerial(configDirectory: dir), 5603,
                       "the replay guard was rolled back to 0 by a check that could not be made — an old "
                       + "bundle, and a withdrawn CA with it, would become acceptable again")
        XCTAssertEqual(DsseAdoptedTrustAnchorStore.advertisedTransportServerName(configDirectory: dir),
                       "44paeqjensoua35pt4xyvkln6m.dsse.invalid")
    }

    /// A pointer that never recorded a deployment (every pointer written before today) also stands. The check
    /// is "adopted for someone ELSE", not "cannot prove it was adopted for us".
    func testAPointerFromBeforeThisFieldExistedStands() throws {
        let dir = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        try writePointer(dir, tenant: nil)
        XCTAssertEqual(DsseAdoptedTrustAnchorStore.lastAcceptedSerial(configDirectory: dir), 5603)
    }

    /// The rule itself, stated where it can be read without a profile on disk.
    func testTheStoreRecordsWhichDeploymentItAdoptedFor() throws {
        let source = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Sources/DsseAppProxyProviderSkeleton/DsseAdoptedTrustAnchorStore.swift")
        let text = try String(contentsOf: source, encoding: .utf8)
        XCTAssertTrue(text.contains("case tenantID = \"tenant_id\""),
                      "the adopted pointer no longer records which deployment it was adopted for, so a device "
                      + "re-installed onto another deployment keeps the previous one's anchors and name")
        XCTAssertTrue(text.contains("adopted_anchors DISCARDED"),
                      "nothing discards adopted material belonging to another deployment")
    }
}
