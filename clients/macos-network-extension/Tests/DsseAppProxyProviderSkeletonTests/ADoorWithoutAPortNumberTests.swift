import XCTest
@testable import DsseAppProxyProviderSkeleton

/// ★★★ MEASURED ON A REAL MAC, 2026-08-29. The deployment's signed profile names the door it wants devices to
/// use as `https://agents.tokyo.hikari.lab` — no port, because the agent plane is folded onto 443. The (T)
/// transport resolver refused that string, so a device whose configuration was correct in every field ran with
/// no transport at all: dark to the Edge, no policy poller, no region failover, and every steered flow on a
/// URLSession that App Transport Security will not let near the deployment's private CA.
final class ADoorWithoutAPortNumberTests: XCTestCase {
    func testTheDoorTheProfileActuallyNamesResolves() throws {
        let hp = try XCTUnwrap(
            DsseTransportSecurityFactory.hostPort(fromTransportURL: "https://agents.tokyo.hikari.lab"),
            "the door a deployment's profile names — https with no port — did not resolve, which is the whole "
            + "(T) transport gone on every profile-installed device")
        XCTAssertEqual(hp.host, "agents.tokyo.hikari.lab")
        XCTAssertEqual(hp.port, 443, "https means 443 unless something says otherwise")
    }

    func testAnExplicitPortStillWins() throws {
        let hp = try XCTUnwrap(DsseTransportSecurityFactory.hostPort(fromTransportURL: "https://edge.example:8443"))
        XCTAssertEqual(hp.port, 8443)
    }

    func testWhatIsStillRefused() {
        XCTAssertNil(DsseTransportSecurityFactory.hostPort(fromTransportURL: "http://agents.example"),
                     "a plaintext door was accepted for a transport that must be TLS")
        XCTAssertNil(DsseTransportSecurityFactory.hostPort(fromTransportURL: "https://"),
                     "a URL with no host resolved to something")
        XCTAssertNil(DsseTransportSecurityFactory.hostPort(fromTransportURL: "https://edge.example:0"),
                     "an explicitly invalid port was defaulted away instead of refused")
    }
}
