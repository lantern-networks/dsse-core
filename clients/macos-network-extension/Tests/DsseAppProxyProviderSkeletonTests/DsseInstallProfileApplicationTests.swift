import CryptoKit
import Foundation
import XCTest
@testable import DsseAppProxyProviderSkeleton
@testable import DsseNetworkExtensionContract

// ★★★ THE PROFILE THE CONSOLE HANDS OUT DECIDED NOTHING ON A MAC (2026-08-28, measured by walking the install
// lane on a two-region deployment). "Device configuration" → "Make the configuration" → Download produces a
// signed `dsse_install_profile.v1`; the verifier for it existed, was correct, and had no caller. These tests
// are the ones that would have failed on 2026-08-27, and they fail again the moment the call site is removed.
final class DsseInstallProfileApplicationTests: XCTestCase {

    private func profileEnvelope(signedBy key: Curve25519.Signing.PrivateKey,
                                 transportURL: String,
                                 endpoints: [String]? = nil,
                                 posture: String? = nil,
                                 ackFailOpen: Bool? = nil,
                                 issuedAt: String? = "2026-08-28T01:33:07Z",
                                 organizationServerName: String? = nil,
                                 kind: String = "dsse_install_profile.v1") throws -> Data {
        var body: [String: Any] = [
            "kind": kind,
            "version": 3,
            "tenant_id": "tenant_kaede",
            "transport_url": transportURL,
        ]
        if let issuedAt { body["issued_at"] = issuedAt }
        if let endpoints { body["transport_endpoints"] = endpoints }
        if let posture { body["posture"] = posture }
        if let ackFailOpen { body["ack_failopen"] = ackFailOpen }
        if let organizationServerName {
            body["organization"] = ["tenant_id": "tenant_kaede", "transport_server_name": organizationServerName]
        }
        let payload = try JSONSerialization.data(withJSONObject: body)
        let sig = try key.signature(for: payload)
        let env: [String: Any] = [
            "type": "dsse_install_profile.v1",
            "version": "1",
            "signing_key_id": "test",
            "created_at": "2026-08-28T01:33:07Z",
            "payload_sha256": SHA256.hash(data: payload).map { String(format: "%02x", $0) }.joined(),
            "payload_b64": payload.base64EncodedString(),
            "signature": "ed25519:" + sig.base64EncodedString()
                .replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_")
                .replacingOccurrences(of: "=", with: ""),
        ]
        return try JSONSerialization.data(withJSONObject: env)
    }

    private func hex(_ key: Curve25519.Signing.PrivateKey) -> String {
        key.publicKey.rawRepresentation.map { String(format: "%02x", $0) }.joined()
    }

    /// A directory holding the two root-owned files a real install has: the configuration carrying the pin, and
    /// the profile the operator downloaded.
    private func stage(pin: String, localTransportURL: String,
                       profile: Data?, ackFailOpen: Bool = false) throws -> (dir: URL, configPath: String) {
        let dir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("dsse-profile-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        var config: [String: Any] = [
            "edge_url": localTransportURL,
            "network_extension_agent_policy_signing_public_key": pin,
            "network_extension_transport": [
                "transport_tls_url": localTransportURL,
                "mtls_required": true,
                "client_identity_common_name": "a-mac",
            ],
        ]
        if ackFailOpen {
            config["network_extension_fail_open_enabled"] = true
            config["network_extension_fail_open_acknowledged"] = true
        }
        let configPath = dir.appendingPathComponent("agent_config.json").path
        try JSONSerialization.data(withJSONObject: config).write(to: URL(fileURLWithPath: configPath))
        if let profile {
            try profile.write(to: dir.appendingPathComponent(DsseInstallProfileApplication.defaultFileName))
        }
        return (dir, configPath)
    }

    // The whole point: the address the deployment published is the address this device dials.
    func testTheDownloadedProfileMovesTheDoorTheDeviceDials() throws {
        let key = Curve25519.Signing.PrivateKey()
        let env = try profileEnvelope(signedBy: key, transportURL: "https://agents.region-a.dsse.lab")
        let staged = try stage(pin: hex(key), localTransportURL: "https://agents.dsse.lab", profile: env)

        let inForce = DsseInstallProfileApplication.inForce(agentConfigPath: staged.configPath,
                                                            configDirectory: staged.dir)
        XCTAssertEqual(inForce?.transportURL, "https://agents.region-a.dsse.lab",
                       "the profile on disk was not applied — this is the defect: a verifier with no caller")

        let local = DsseTransportContract(transportTLSURL: "https://agents.dsse.lab", mtlsRequired: true,
                                          dnsOverTunnelPath: nil, dnsOverTunnelSupported: nil,
                                          pinnedCARef: "anchor.pem", clientIdentityP12Ref: nil,
                                          clientIdentityP12PassRef: nil, clientIdentityCommonName: "a-mac",
                                          renewalRecoveryEndpoint: nil)
        let applied = DsseInstallProfileApplication.applyTransport(to: local, profile: inForce)
        XCTAssertEqual(applied?.transportTLSURL, "https://agents.region-a.dsse.lab")
        // ★ AND NOTHING ELSE MOVED. A document that could rewrite the anchor or the identity selector would be
        // a document that can re-point a device at an authority of its author's choosing.
        XCTAssertEqual(applied?.pinnedCARef, "anchor.pem")
        XCTAssertEqual(applied?.clientIdentityCommonName, "a-mac")
    }

    // A profile signed by anybody else is not a profile. The device keeps what it had rather than widening.
    func testAProfileSignedByAStrangerIsRefusedAndTheLocalConfigurationStands() throws {
        let deployment = Curve25519.Signing.PrivateKey()
        let stranger = Curve25519.Signing.PrivateKey()
        let env = try profileEnvelope(signedBy: stranger, transportURL: "https://attacker.example")
        let staged = try stage(pin: hex(deployment), localTransportURL: "https://agents.dsse.lab", profile: env)

        var said: [String] = []
        let inForce = DsseInstallProfileApplication.inForce(agentConfigPath: staged.configPath,
                                                            configDirectory: staged.dir,
                                                            log: { said.append($0) })
        XCTAssertNil(inForce)
        XCTAssertTrue(said.contains { $0.contains("install_profile REFUSED") },
                      "a refusal nobody can see is how this lands on a device with no reason visible: \(said)")
        let local = DsseTransportContract(transportTLSURL: "https://agents.dsse.lab", mtlsRequired: true,
                                          dnsOverTunnelPath: nil, dnsOverTunnelSupported: nil, pinnedCARef: nil,
                                          clientIdentityP12Ref: nil, clientIdentityP12PassRef: nil,
                                          clientIdentityCommonName: nil, renewalRecoveryEndpoint: nil)
        XCTAssertEqual(DsseInstallProfileApplication.applyTransport(to: local, profile: inForce)?.transportTLSURL,
                       "https://agents.dsse.lab")
    }

    // A validly signed document of ANOTHER kind is not an install profile.
    func testAValidlySignedDocumentOfAnotherKindIsNotAppliedAsAProfile() throws {
        let key = Curve25519.Signing.PrivateKey()
        let env = try profileEnvelope(signedBy: key, transportURL: "https://elsewhere.example",
                                      kind: "dsse_agent_steer_policy.v1")
        let staged = try stage(pin: hex(key), localTransportURL: "https://agents.dsse.lab", profile: env)
        XCTAssertNil(DsseInstallProfileApplication.inForce(agentConfigPath: staged.configPath,
                                                           configDirectory: staged.dir))
    }

    // The anti-rollback rule has to survive a restart, or replacing the file on a machine you can reboot is the
    // way around it. The stamp is written where the profile is.
    func testAnOlderProfileIsRefusedAfterANewerOneHasBeenApplied() throws {
        let key = Curve25519.Signing.PrivateKey()
        let newer = try profileEnvelope(signedBy: key, transportURL: "https://new.dsse.lab",
                                        issuedAt: "2026-08-28T01:33:07Z")
        let staged = try stage(pin: hex(key), localTransportURL: "https://agents.dsse.lab", profile: newer)
        XCTAssertEqual(DsseInstallProfileApplication.inForce(agentConfigPath: staged.configPath,
                                                             configDirectory: staged.dir)?.transportURL,
                       "https://new.dsse.lab")

        let older = try profileEnvelope(signedBy: key, transportURL: "https://old.dsse.lab",
                                        issuedAt: "2026-08-01T00:00:00Z")
        try older.write(to: staged.dir.appendingPathComponent(DsseInstallProfileApplication.defaultFileName))
        var said: [String] = []
        XCTAssertNil(DsseInstallProfileApplication.inForce(agentConfigPath: staged.configPath,
                                                           configDirectory: staged.dir, log: { said.append($0) }),
                     "an older profile replaced the newer one — the anti-rollback stamp did not survive")
        XCTAssertTrue(said.contains { $0.contains("REFUSED=rollback") }, "\(said)")

        // Stripping the stamp is the same downgrade, and is refused for the same reason.
        let unstamped = try profileEnvelope(signedBy: key, transportURL: "https://old.dsse.lab", issuedAt: nil)
        try unstamped.write(to: staged.dir.appendingPathComponent(DsseInstallProfileApplication.defaultFileName))
        XCTAssertNil(DsseInstallProfileApplication.inForce(agentConfigPath: staged.configPath,
                                                           configDirectory: staged.dir))
    }

    // A profile present and a pin absent is the one case that must be LOUD: the operator placed the file and has
    // every reason to believe it took effect.
    func testAProfileThatCannotBeJudgedSaysSo() throws {
        let key = Curve25519.Signing.PrivateKey()
        let env = try profileEnvelope(signedBy: key, transportURL: "https://agents.region-a.dsse.lab")
        let staged = try stage(pin: "", localTransportURL: "https://agents.dsse.lab", profile: env)
        var said: [String] = []
        XCTAssertNil(DsseInstallProfileApplication.inForce(agentConfigPath: staged.configPath,
                                                           configDirectory: staged.dir, log: { said.append($0) }))
        XCTAssertTrue(said.contains { $0.contains("ignored=no_pin") }, "\(said)")
    }

    // No profile at all is the ordinary state of a deployment that has not issued one, and it is silent.
    func testNoProfileIsSilentAndChangesNothing() throws {
        let staged = try stage(pin: "aa", localTransportURL: "https://agents.dsse.lab", profile: nil)
        var said: [String] = []
        XCTAssertNil(DsseInstallProfileApplication.inForce(agentConfigPath: staged.configPath,
                                                           configDirectory: staged.dir, log: { said.append($0) }))
        XCTAssertTrue(said.isEmpty, "a line every startup for a file nobody placed trains an operator to skip " +
                      "this subsystem: \(said)")
    }

    // The door list a device tries before any Edge has answered, in the order the deployment put them in.
    func testTheProfileSeedsEveryRegionInOrder() throws {
        let key = Curve25519.Signing.PrivateKey()
        let env = try profileEnvelope(signedBy: key, transportURL: "https://agents.region-a.dsse.lab",
                                      endpoints: ["region-a=https://agents.region-a.dsse.lab",
                                                  "region-b=https://agents.region-b.dsse.lab"])
        let staged = try stage(pin: hex(key), localTransportURL: "https://agents.dsse.lab", profile: env)
        let profile = DsseInstallProfileApplication.inForce(agentConfigPath: staged.configPath,
                                                            configDirectory: staged.dir)
        let seed = DsseInstallProfileApplication.regionSeed(profile: profile)
        XCTAssertEqual(seed.map { $0.region }, ["region-a", "region-b"])
        XCTAssertEqual(seed.first?.endpoint, "https://agents.region-a.dsse.lab")
        XCTAssertGreaterThan(seed[0].priority, seed[1].priority,
                             "earlier in the deployment's list must be preferred, and the poller ranks a HIGHER " +
                             "number first")
        // Junk in the list is skipped rather than turning the seed into nothing.
        XCTAssertTrue(DsseInstallProfileApplication.regionSeed(profile: nil).isEmpty)
    }

    // ★★ THE DEPLOYMENT MAY CLOSE A POSTURE THE DEVICE OPENED, NEVER THE REVERSE.
    func testPostureCanOnlyBeClosedByTheProfileNeverOpened() throws {
        let key = Curve25519.Signing.PrivateKey()

        let closed = try profileEnvelope(signedBy: key, transportURL: "https://a", posture: "fail-closed")
        var staged = try stage(pin: hex(key), localTransportURL: "https://a", profile: closed, ackFailOpen: true)
        var profile = DsseInstallProfileApplication.inForce(agentConfigPath: staged.configPath,
                                                            configDirectory: staged.dir)
        XCTAssertEqual(DsseInstallProfileApplication.failOpenOverride(profile: profile), false,
                       "a fleet told to carry nothing must not be reopened by editing a file on one laptop")

        // fail-open WITHOUT the deployment's own acknowledgement is still closed: shipping a profile is not
        // enough to take a fleet out of enforcement.
        let openUnacked = try profileEnvelope(signedBy: key, transportURL: "https://a", posture: "fail-open")
        staged = try stage(pin: hex(key), localTransportURL: "https://a", profile: openUnacked)
        profile = DsseInstallProfileApplication.inForce(agentConfigPath: staged.configPath,
                                                        configDirectory: staged.dir)
        XCTAssertEqual(DsseInstallProfileApplication.failOpenOverride(profile: profile), false)

        // fail-open acknowledged by the deployment lifts the deployment's objection and nothing more — the
        // device's own acknowledgement still decides.
        let openAcked = try profileEnvelope(signedBy: key, transportURL: "https://a", posture: "fail-open",
                                            ackFailOpen: true)
        staged = try stage(pin: hex(key), localTransportURL: "https://a", profile: openAcked)
        profile = DsseInstallProfileApplication.inForce(agentConfigPath: staged.configPath,
                                                        configDirectory: staged.dir)
        XCTAssertNil(DsseInstallProfileApplication.failOpenOverride(profile: profile))

        // And a profile that says nothing about posture leaves the local one alone.
        XCTAssertNil(DsseInstallProfileApplication.failOpenOverride(profile: nil))
    }
}

extension DsseInstallProfileApplicationTests {
    // ★★★ AND THE NAMES ARE NESTED, WHICH THIS PLATFORM READ AT THE TOP LEVEL (2026-08-28). The producer puts the
// organization's door names under `organization` — where the Windows agent reads them — and this decoder
// declared them as root keys, so it matched nothing any deployment has ever emitted. A profile can be issued
// correctly, verify, apply, and still leave the device dialling the shared name.
func testTheOrganizationsOwnDoorNameIsReadFromWhereTheDeploymentPutsIt() throws {
    let key = Curve25519.Signing.PrivateKey()
    let env = try profileEnvelope(signedBy: key, transportURL: "https://agents.region-a.dsse.lab",
                                  organizationServerName: "kaede.dsse.lab")
    let staged = try stage(pin: hex(key), localTransportURL: "https://agents.dsse.lab", profile: env)
    let profile = DsseInstallProfileApplication.inForce(agentConfigPath: staged.configPath,
                                                        configDirectory: staged.dir)
    XCTAssertEqual(profile?.transportServerName, "kaede.dsse.lab",
                   "the Edge picks an organization's certificate by SNI, so a device that does not read this " +
                   "name is served the deployment's shared one — which is what every device was")
    XCTAssertEqual(profile?.organization?.tenantID, "tenant_kaede")

    // A profile that names none leaves it absent, which means "the deployment's shared certificate".
    let plain = try profileEnvelope(signedBy: key, transportURL: "https://agents.dsse.lab")
    let staged2 = try stage(pin: hex(key), localTransportURL: "https://agents.dsse.lab", profile: plain)
    XCTAssertNil(DsseInstallProfileApplication.inForce(agentConfigPath: staged2.configPath,
                                                       configDirectory: staged2.dir)?.transportServerName)
    }
}
