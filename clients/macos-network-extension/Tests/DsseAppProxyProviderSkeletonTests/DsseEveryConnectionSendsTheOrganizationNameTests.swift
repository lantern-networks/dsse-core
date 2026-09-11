import XCTest
@testable import DsseAppProxyProviderSkeleton

/// ★★★ EVERY CONNECTION THIS AGENT MAKES TO ITS EDGE SENDS ITS ORGANIZATION'S NAME (2026-08-22).
///
/// Three channels broke the same way in one day — the agent-policy fetch, the report it carries, and the
/// certificate renewal. Each dialled the Edge BY ADDRESS and was served the deployment-wide certificate,
/// while the tunnel beside them sent the organization's name and was served its own. Invisible until the
/// organization's devices stop holding the shared anchor, which is the last step of roadmap D — and then:
///
///	certificate_renewal FAILED identity=mac-dev-1 error=requestFailed("cancelled")
///
/// retried every six hours, for ever. No device could renew, so no device could ever move onto its own
/// organization's device-identity authority, which is the entire point of that tier.
///
/// The name is read at DIAL time from what this device last adopted, never captured, because it arrives in a
/// trust bundle after start-up.
final class DsseEveryConnectionSendsTheOrganizationNameTests: XCTestCase {
    override func tearDown() {
        DsseLiveTransportServerName.setProvider { "" }
        super.tearDown()
    }

    func testTheAnnouncedNameIsUsedWhenTheCallerGivesNone() {
        DsseLiveTransportServerName.setProvider { "lab.dsse.invalid" }
        XCTAssertEqual(DsseLiveTransportServerName.current(), "lab.dsse.invalid",
                       "the provider is the source every dial reads; without it this test measures nothing")

        // The renewal's own resolution: caller's name wins, else the announced one, else none.
        XCTAssertEqual(resolvedDialName(callerGave: nil), "lab.dsse.invalid",
                       "an ordinary renewal must dial by the organization's name, not by address")
        XCTAssertEqual(resolvedDialName(callerGave: "recovery.lab.dsse.invalid"), "recovery.lab.dsse.invalid",
                       "the recovery path selects a DIFFERENT name on the Edge and must keep its own")
        XCTAssertEqual(resolvedDialName(callerGave: "   "), "lab.dsse.invalid",
                       "whitespace is not a name")

        DsseLiveTransportServerName.setProvider { "" }
        XCTAssertNil(resolvedDialName(callerGave: nil),
                     "a deployment with no per-organization name dials by address exactly as before")
    }

    /// Mirrors the resolution in DsseCertificateRenewal.renew. Kept beside the test rather than reaching into
    /// the function, because what is being pinned down is the RULE: caller, then announced, then nothing.
    private func resolvedDialName(callerGave: String?) -> String? {
        (callerGave?.trimmingCharacters(in: .whitespacesAndNewlines)).flatMap { $0.isEmpty ? nil : $0 }
            ?? { let n = DsseLiveTransportServerName.current(); return n.isEmpty ? nil : n }()
    }
}
