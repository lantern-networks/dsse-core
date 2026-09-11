import XCTest
@testable import DsseAppProxyProviderSkeleton

/// ★★★ THE PROBE HAS TO KNOCK ON THE DOOR THE TUNNEL USES (2026-08-20, measured on the lab).
///
/// The Edge chooses which organization's certificate to present from the TLS server name — it has to choose
/// before the client certificate arrives. The adoption probe read the served chain over URLSession at
/// `https://<address>:<port>/healthz`, so it sent no name and met the deployment-wide certificate signed by the
/// SHARED authority.
///
/// That was invisible for as long as every bundle still carried the shared anchor. The instant the last step of
/// roadmap D took it out of one organization's bundle, the probe could no longer verify what it was reading,
/// concluded this device could not verify the Edge, and REFUSED a distribution the device's own transport
/// accepts. It fails towards "stay where you are", so nothing broke — and macOS could never have finished the
/// rotation. The Windows agent sent the name from the start and reached the end state first.
final class DsseProbeServerNameTests: XCTestCase {

    func testTheNameComesFromTheDistributionBeingConsidered() {
        // A distribution that changes the name carries the new one, and the certificate the Edge presents under
        // it changes at the same moment. Probing with the name this device still holds would evaluate the new
        // certificate against the old name and refuse something correct.
        XCTAssertEqual(
            DsseTrustAnchorRecovery.probeServerName(offeredByBundle: "New.DSSE.Invalid",
                                                    liveOnThisDevice: "old.dsse.invalid"),
            "new.dsse.invalid",
            "the probe used the name this device already holds instead of the one being offered")
    }

    func testItFallsBackToWhatThisDeviceSendsToday() {
        XCTAssertEqual(
            DsseTrustAnchorRecovery.probeServerName(offeredByBundle: "  ",
                                                    liveOnThisDevice: "lab.dsse.invalid"),
            "lab.dsse.invalid",
            "a distribution that announces no name left the probe with nothing, so it would go back to asking " +
            "about the deployment-wide certificate")
    }

    func testNoNameAnywhereIsStillNoName() {
        // The deployment that serves one certificate to everybody: unchanged behaviour, and never an invented
        // name — the rule DsseLiveTransportServerName states for the handshake applies here too.
        XCTAssertEqual(
            DsseTrustAnchorRecovery.probeServerName(offeredByBundle: "", liveOnThisDevice: ""), "")
    }
}
