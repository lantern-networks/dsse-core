import XCTest
@testable import DsseAppProxyProviderSkeleton

/// ★★★ ONE LINE, READ AS PERMANENT, CHANGED A LIVE DEPLOYMENT (2026-09-06).
///
///     20:24:11  trust_anchor_adoption REFUSED serial=5 anchors=3
///     20:25:11  trust_anchor_adoption ADOPTED serial=5 anchors=3
///
/// Same serial, same anchors, one minute apart. The first probe ran before this device had been asked which
/// name it presents; the organization's door is chosen by that name, so the probe was served the
/// deployment-wide certificate and the organization's own anchors correctly failed against it.
final class ARefusalThatTheNextTickReversesTests: XCTestCase {
    func testNotHavingBeenAskedIsADifferentAnswerFromHavingNoName() {
        // Whatever earlier tests in this process installed, the question is answerable and must be answered
        // by the provider rather than by the empty string it returns.
        DsseLiveTransportServerName.setProvider { "" }
        XCTAssertTrue(DsseLiveTransportServerName.hasBeenAsked(),
                      "a deployment that serves one certificate to everybody answers \"\" and IS asked; " +
                      "treating it as unasked would stop it ever adopting a rotation")
        XCTAssertEqual(DsseLiveTransportServerName.current(), "")

        DsseLiveTransportServerName.setProvider { "enrol.example.invalid" }
        XCTAssertEqual(DsseLiveTransportServerName.current(), "enrol.example.invalid")
    }

    /// The bundle's own name still wins, so a distribution that RENAMES the organization is judged against the
    /// new name — the announcement and the certificate move together.
    func testTheBundlesNameOutranksTheDevicesLiveOne() {
        XCTAssertEqual(
            DsseTrustAnchorRecovery.probeServerName(offeredByBundle: "  ENROL.New.Invalid ",
                                                    liveOnThisDevice: "enrol.old.invalid"),
            "enrol.new.invalid")
        XCTAssertEqual(
            DsseTrustAnchorRecovery.probeServerName(offeredByBundle: "   ",
                                                    liveOnThisDevice: "ENROL.Old.Invalid"),
            "enrol.old.invalid",
            "a bundle that names nothing leaves the device on the name it already presents")
    }
}
