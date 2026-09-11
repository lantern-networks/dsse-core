import XCTest

@testable import DsseAppProxyProviderSkeleton

final class DsseInterceptionRootPinTests: XCTestCase {

    /// The case the pin exists for: the Edge signs under an authority this agent was not installed with. It is
    /// dangerous precisely when it SUCCEEDS — a root the machine happens to hold for some other reason means
    /// interception under the wrong authority that the browser is perfectly happy with.
    func testAnEdgeSigningUnderAnotherAuthorityIsAMismatch() {
        let decision = DsseInterceptionRootPin.decide(pinned: "aa11", announced: ["bb22", "cc33"])

        guard case let .mismatch(pinned, announced) = decision else {
            return XCTFail("expected a mismatch, got \(decision)")
        }
        XCTAssertEqual(pinned, "aa11")
        XCTAssertEqual(announced, ["bb22", "cc33"])
        // The message has to name both sides and a way out, or an operator hunts for a cause that is really a
        // rotation that did not reach this machine.
        let message = DsseInterceptionRootPin.mismatchOperatorMessage(pinned: pinned, announced: announced)
        XCTAssertTrue(message.contains("aa11"))
        XCTAssertTrue(message.contains("bb22"))
        XCTAssertTrue(message.contains("tenant-install-bundle"))
    }

    /// ★ AN OVERLAP IS A MATCH. An authority is replaced by announcing old and new together while devices move
    /// across. Demanding equality would make every rotation an outage on every device that had not yet been
    /// re-configured — which is the surest way to have this check turned off.
    func testAnOverlapDuringAReplacementStillSatisfiesThePin() {
        XCTAssertEqual(DsseInterceptionRootPin.decide(pinned: "old", announced: ["new", "old"]), .satisfied)
    }

    /// ★ ABSENCE IS NOT A VERDICT, TWICE OVER.
    ///
    /// No pin: every configuration already in the field predates the field, and treating that as a failure
    /// would strand the entire installed base — the same mistake the macOS installer gate made twice.
    ///
    /// The Edge naming nothing: unknown, not wrong. A device that concluded "wrong" from silence would stand
    /// aside every time a policy failed to arrive.
    func testAbsenceIsNeverAMismatch() {
        XCTAssertEqual(DsseInterceptionRootPin.decide(pinned: nil, announced: ["bb22"]), .noPin)
        XCTAssertEqual(DsseInterceptionRootPin.decide(pinned: "   ", announced: ["bb22"]), .noPin)
        XCTAssertEqual(DsseInterceptionRootPin.decide(pinned: "aa11", announced: []), .edgeNamedNoRoot)
        XCTAssertEqual(DsseInterceptionRootPin.decide(pinned: "aa11", announced: ["  ", ""]), .edgeNamedNoRoot)
    }

    /// Fingerprints are compared the way every other boundary in this product compares them: trimmed and
    /// case-insensitively. A capital letter arriving from one tool and not another is not a security event.
    func testComparisonIgnoresCaseAndSurroundingSpace() {
        XCTAssertEqual(DsseInterceptionRootPin.decide(pinned: " AA11 ", announced: ["aa11"]), .satisfied)
        XCTAssertEqual(DsseInterceptionRootPin.decide(pinned: "aa11", announced: [" Aa11"]), .satisfied)
    }
}

extension DsseInterceptionRootPinTests {

    private func writeConfig(_ json: String) -> String {
        let path = NSTemporaryDirectory() + "/agent_config_\(UUID().uuidString).json"
        try? json.data(using: .utf8)?.write(to: URL(fileURLWithPath: path))
        return path
    }

    /// The pin is read from the configuration the agent was INSTALLED with, which is where the Edge writes it.
    func testThePinIsReadFromTheInstallConfiguration() {
        let path = writeConfig("""
        {"edge_url":"https://edge.invalid",
         "trusted_ca_bundle":{"tenant_id":"tenant_northwind","interception_root_sha256":"aa11","enforce":true}}
        """)

        let pin = DsseAppProxyProvider.installedInterceptionRootPin(agentConfigPath: path)

        XCTAssertEqual(pin.fingerprint, "aa11")
        XCTAssertEqual(pin.tenant, "tenant_northwind")
        XCTAssertTrue(pin.enforce)
    }

    /// ★ ENFORCEMENT IS OFF UNLESS THE CONFIGURATION SAYS OTHERWISE. Arming a fail-closed check by default
    /// would stand aside on every machine whose configuration predates the field — the entire installed base —
    /// and a security control that takes the fleet offline on the day it ships is one that gets removed.
    func testEnforcementIsOffByDefaultAndAbsentBundleIsNotAPin() {
        let armedByOmission = writeConfig("""
        {"trusted_ca_bundle":{"tenant_id":"t","interception_root_sha256":"aa11"}}
        """)
        XCTAssertFalse(DsseAppProxyProvider.installedInterceptionRootPin(agentConfigPath: armedByOmission).enforce)

        let noBundle = writeConfig(#"{"edge_url":"https://edge.invalid"}"#)
        let pin = DsseAppProxyProvider.installedInterceptionRootPin(agentConfigPath: noBundle)
        XCTAssertNil(pin.fingerprint)
        XCTAssertFalse(pin.enforce)

        // A configuration that is not there at all, or is not JSON, is also not a pin — an agent must not
        // stand aside because a file could not be read.
        XCTAssertNil(DsseAppProxyProvider.installedInterceptionRootPin(agentConfigPath: "/nonexistent").fingerprint)
        XCTAssertNil(DsseAppProxyProvider.installedInterceptionRootPin(agentConfigPath: writeConfig("not json")).fingerprint)
    }
}

extension DsseInterceptionRootPinTests {

    /// ★ THE LOG TOKEN MUST BE GREPPABLE (2026-08-16). The first live verification of this control reported
    /// that nothing had happened while the control was working perfectly: the enum's default description is
    /// `mismatch(pinned: "…", announced: ["…"])`, the check matched `decision=[^ ]*`, and the spaces inside
    /// the value hid every mismatch line — so the script fell back to the PREVIOUS phase's verdict and called
    /// it the current one. An operator's grep fails identically.
    func testEveryDecisionLogsAsOneSpacelessToken() {
        let decisions: [DsseInterceptionRootPinDecision] = [
            .noPin, .edgeNamedNoRoot, .satisfied, .mismatch(pinned: "aa11", announced: ["bb22", "cc33"]),
        ]
        var seen = Set<String>()
        for decision in decisions {
            let token = decision.logToken
            XCTAssertFalse(token.contains(" "), "\(token) would break the grep that reads this line")
            XCTAssertFalse(token.isEmpty)
            XCTAssertTrue(seen.insert(token).inserted, "two decisions log as \(token) — indistinguishable in the log")
        }
    }
}

extension DsseInterceptionRootPinTests {

    /// ★ THE AGENT MUST REPORT ITS PIN, OR THE EDGE CANNOT END A REPLACEMENT (2026-08-16). The Edge keeps the
    /// outgoing authority announced while devices move across, and withdraws it to finish. "Every device holds
    /// the new root" does not make that safe — an agent pinned to the old one stands aside the moment the Edge
    /// stops naming it, whatever else is in its trust store. Without this field the Edge can only block every
    /// withdrawal forever or guess, and it is the same value the startup gate enforces on, read from the same
    /// configuration, so the two can never disagree.
    func testTheReportedPinIsTheSameValueTheGateEnforcesOn() {
        let path = writeConfig("""
        {"trusted_ca_bundle":{"tenant_id":"tenant_northwind","interception_root_sha256":"AA11","enforce":true}}
        """)

        let pin = DsseAppProxyProvider.installedInterceptionRootPin(agentConfigPath: path)
        let decision = DsseInterceptionRootPin.decide(pinned: pin.fingerprint, announced: ["aa11"])

        XCTAssertEqual(pin.fingerprint, "AA11")
        // Reported lowercased, compared case-insensitively: one value, two readers, no third normalisation.
        XCTAssertEqual(decision, .satisfied)
    }
}
