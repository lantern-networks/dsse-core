import XCTest
import DsseNetworkExtensionContract
@testable import DsseAppProxyProviderSkeleton

final class DsseEnrolmentGateTests: XCTestCase {
    // The ordinary case, and the one that must not regress: a machine with an identity is untouched by any of
    // this. The gate exists for machines without one.
    func testADeviceWithAnIdentityProceeds() {
        XCTAssertEqual(DsseEnrolmentGate.decide(hasIdentity: true, hasEnrolmentToken: false, wasEnrolledBefore: false),
                       .proceed)
        XCTAssertEqual(DsseEnrolmentGate.decide(hasIdentity: true, hasEnrolmentToken: true, wasEnrolledBefore: true),
                       .proceed)
    }

    func testAFreshMachineWithATokenEnrolsFirst() {
        XCTAssertEqual(DsseEnrolmentGate.decide(hasIdentity: false, hasEnrolmentToken: true, wasEnrolledBefore: false),
                       .enrolFirst)
    }

    // The failure this gate was written for. Without it, a machine with no certificate takes over the network
    // path and is then rejected at every handshake: no traffic, no explanation, from an agent that never had
    // anything to protect. Standing aside bypasses no policy — there is none on a machine nobody approved.
    func testAMachineThatWasNeverEnrolledStandsAside() {
        XCTAssertEqual(DsseEnrolmentGate.decide(hasIdentity: false, hasEnrolmentToken: false, wasEnrolledBefore: false),
                       .standAsideNotEnrolled)
    }

    // A machine that HAS held an identity and lost it is a different event — a revocation, a wiped keychain, a
    // failed rotation — and this gate must not reinterpret it as "never enrolled" and quietly stand down. That
    // would turn losing a credential into losing enforcement, which is the wrong direction for exactly the
    // devices an operator cares most about.
    func testAPreviouslyEnrolledMachineIsNotTreatedAsFresh() {
        XCTAssertEqual(DsseEnrolmentGate.decide(hasIdentity: false, hasEnrolmentToken: false, wasEnrolledBefore: true),
                       .proceedPreviouslyEnrolled)
    }

    // A token wins over the previously-enrolled path: an operator who deliberately placed a fresh token on a
    // machine is asking for a re-enrolment, and honouring that is how a wiped or re-imaged device recovers
    // without hand-work.
    func testATokenOnAPreviouslyEnrolledMachineReEnrols() {
        XCTAssertEqual(DsseEnrolmentGate.decide(hasIdentity: false, hasEnrolmentToken: true, wasEnrolledBefore: true),
                       .enrolFirst)
    }

    // The message is what someone actually reads at 2am. "Not enrolled" alone sends them hunting for a cause
    // that is really a missing step, so it has to name the step and where the traffic went.
    func testTheOperatorMessageSaysWhatIsWrongAndWhatToDo() {
        let message = DsseEnrolmentGate.notEnrolledOperatorMessage
        XCTAssertTrue(message.contains("NOT being steered"), "it must be unambiguous that traffic is unprotected")
        XCTAssertTrue(message.contains("enrolment_token"), "it must name the config key to set")
        XCTAssertTrue(message.contains("Console"), "it must say where the token comes from")
    }
}

// ★★★ MEASURED ON A REAL MAC, 2026-09-04. A device holding `tenant_default`'s certificate was given the four
// artefacts of a NEW organization. The certificate handshook perfectly — same deployment, same Edge — so the
// gate proceeded, the device never enrolled into the organization it had been given, and every flow was
// inspected under the DEPLOYMENT's interception CA while the organization's own authority sat loaded and
// unused on the Edge. Both sides reported success.
extension DsseEnrolmentGateTests {
    func testAnIdentityFromAnotherOrganizationEnrolsAgainEvenThoughItWorksHere() {
        let decision = DsseEnrolmentGate.decide(hasIdentity: true,
                                                hasEnrolmentToken: true,
                                                wasEnrolledBefore: true,
                                                identityWorksHere: true,
                                                identityBelongsToThisOrganization: false)
        XCTAssertEqual(decision, DsseEnrolmentGateDecision.enrolFirst,
                       "a certificate issued by another organization's device CA completes the handshake; only the issuer says it is the wrong one")
    }

    // nil is "could not be asked" — an issuer that is not in the keychain is a different fault, and refusing
    // on it would strand a device that is otherwise correct.
    func testAnUnaskableOrganizationQuestionDoesNotForceEnrolment() {
        XCTAssertEqual(DsseEnrolmentGate.decide(hasIdentity: true, hasEnrolmentToken: true,
                                                wasEnrolledBefore: true, identityWorksHere: true,
                                                identityBelongsToThisOrganization: nil),
                       DsseEnrolmentGateDecision.proceed)
    }

    func testAnIdentityFromThisOrganizationStillProceeds() {
        XCTAssertEqual(DsseEnrolmentGate.decide(hasIdentity: true, hasEnrolmentToken: true,
                                                wasEnrolledBefore: true, identityWorksHere: true,
                                                identityBelongsToThisOrganization: true),
                       DsseEnrolmentGateDecision.proceed)
    }
}

// The pointer is what lets a device answer "which organization is this identity for". An unstamped pointer —
// which is every pointer that exists today — must decode as unknown, not as wrong.
final class DsseDeviceIdentityPointerTenantTests: XCTestCase {
    func testAnUnstampedPointerDecodesAsUnknownOrganization() throws {
        let legacy = """
        {"certificate_sha256":"aa","private_key_tag":"tag","common_name":"mac-1",
         "not_after":760000000,"installed_at":750000000}
        """.data(using: .utf8)!
        let decoder = JSONDecoder()
        let pointer = try decoder.decode(DsseDeviceIdentityPointer.self, from: legacy)
        XCTAssertNil(pointer.tenantID, "a pointer written before the field existed must read as unknown")
        XCTAssertEqual(pointer.commonName, "mac-1")
    }

    func testAStampedPointerRoundTrips() throws {
        let pointer = DsseDeviceIdentityPointer(certificateSHA256: "aa", privateKeyTag: "tag",
                                                commonName: "mac-1", notAfter: Date(), installedAt: Date(),
                                                tenantID: "tenant_yomogi")
        let data = try JSONEncoder().encode(pointer)
        XCTAssertTrue(String(data: data, encoding: .utf8)!.contains("\"tenant_id\":\"tenant_yomogi\""))
        XCTAssertEqual(try JSONDecoder().decode(DsseDeviceIdentityPointer.self, from: data).tenantID, "tenant_yomogi")
    }
}

// The deployment states this device's organization in the signed steering document, computed from the
// certificate the device presented. It is the ONLY source that answers for a device enrolled before the
// identity pointer carried an organization — which is every device that exists today.
final class DsseDeploymentStatedTenantTests: XCTestCase {
    func testAnUnverifiedDocumentIsNotAnAnswer() {
        let unsigned = #"{"type":"dsse_agent_steer_policy.v1","payload_b64":"e30=","signature":"ed25519:AAAA"}"#
            .data(using: .utf8)!
        XCTAssertNil(DsseSignedAgentPolicy.verifiedDeploymentTenant(envelopeData: unsigned,
                                                                   pinnedPublicKeyHex: String(repeating: "ab", count: 32)),
                     "a document that does not verify must answer nothing — otherwise anyone on the network chooses this device's organization")
    }

    func testAnAbsentFileIsNotAnAnswer() {
        XCTAssertNil(DsseSignedAgentPolicy.verifiedDeploymentTenant(signedPath: "/nonexistent/steer.json",
                                                                    pinnedPublicKeyHex: String(repeating: "ab", count: 32)))
    }

    func testAnEmptyPathIsNotAnAnswer() {
        XCTAssertNil(DsseSignedAgentPolicy.verifiedDeploymentTenant(signedPath: "   ", pinnedPublicKeyHex: ""))
    }
}

// ★★★ The signed steering document was fetched and verified every minute and written NOWHERE, because the key
// naming its location was never set by anything that installs a device. Every reader of it — the interception
// roots the deployment says it signs under, the renewal cutoff, this device's organization — silently read
// nothing, and each had a fallback, so each looked like a working feature answering "none".
final class DsseAgentPolicySignedPathTests: XCTestCase {
    func testAnAbsentKeyStillNamesAPlaceInsideTheConfigDirectory() throws {
        let cfg = try JSONDecoder().decode(DsseSelfExclusionAgentConfig.self,
                                           from: #"{"network_extension_self_exclusion_enabled":true}"#.data(using: .utf8)!)
        let dir = URL(fileURLWithPath: "/Library/Application Support/Dsse")
        let path = cfg.resolvedAgentPolicySignedPath(configDirectory: dir)
        XCTAssertFalse(path.isEmpty, "with no key configured the document must still have somewhere to live")
        XCTAssertTrue(path.hasPrefix(dir.path), "it belongs beside the rest of this device's state, got \(path)")
    }

    func testAConfiguredPathStillWins() throws {
        let cfg = try JSONDecoder().decode(DsseSelfExclusionAgentConfig.self,
                                           from: #"{"network_extension_agent_policy_signed_path":"/opt/somewhere/steer.json"}"#
                                               .data(using: .utf8)!)
        XCTAssertEqual(cfg.resolvedAgentPolicySignedPath(configDirectory: URL(fileURLWithPath: "/tmp")),
                       "/opt/somewhere/steer.json")
    }

    func testABlankConfiguredPathIsNotAPath() throws {
        let cfg = try JSONDecoder().decode(DsseSelfExclusionAgentConfig.self,
                                           from: #"{"network_extension_agent_policy_signed_path":"   "}"#.data(using: .utf8)!)
        XCTAssertTrue(cfg.resolvedAgentPolicySignedPath(configDirectory: URL(fileURLWithPath: "/tmp")).hasPrefix("/tmp"))
    }
}

final class DsseReinstallEnrolmentRegressionTests: XCTestCase {
    func testSpentTokenAndOfflineSameTenantIdentityDoNotTriggerRegistration() {
        XCTAssertEqual(DsseEnrolmentGate.decide(hasIdentity: true, hasEnrolmentToken: true,
            wasEnrolledBefore: true, identityWorksHere: false, identityBelongsToThisOrganization: true), .proceed)
    }

    func testFailedMigrationOfManagedDeviceKeepsEnforcement() {
        XCTAssertEqual(DsseEnrolmentGate.decide(hasIdentity: true, hasEnrolmentToken: true,
            wasEnrolledBefore: true, identityWorksHere: true, identityBelongsToThisOrganization: false), .enrolFirst)
        XCTAssertEqual(DsseStartupArming.afterEnrolmentFailure(wasEnrolledBefore: true), .enforcementBlocked)
        XCTAssertFalse(DsseStartupArming.mustRearmIdentityDependentSubsystems(after: .enforcementBlocked))
        XCTAssertNil(DsseStartupArming.afterEnrolmentFailure(wasEnrolledBefore: false))
    }
}
