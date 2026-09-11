import XCTest
@testable import DsseAppProxyProviderSkeleton

/// ★★★ THE DEVICE CALLS ITS EDGE BY NAME (2026-08-22).
///
/// Ten channels in this agent built a URL from the Edge's ADDRESS. URLSession sends the URL's host as the TLS
/// server name and offers no way to send another, so every one of them was served the deployment-wide
/// certificate while the tunnel beside them sent the organization's name and was served its own. Harmless
/// until the shared anchor leaves that organization's bundle — the last step of roadmap D — and then every one
/// of them is refused, permanently, including the renewal that is the only way a device can move onto its own
/// organization's device-identity authority.
///
/// Fixing them one at a time is not the answer. This is: one decision, read by every channel.
final class DsseDialHostTests: XCTestCase {
    override func tearDown() {
        DsseDialHostDecision.setResolver { _ in false }
        DsseLiveTransportServerName.setProvider { "" }
        DsseDialHostDecision.setClock { Date() }
        DsseDialHostDecision.forget()
        super.tearDown()
    }

    /// ★★★ A "NO" MUST EXPIRE (2026-09-05, measured on a Mac that was steering under interception). The
    /// decision was cached permanently in both directions, and the extension comes up before the tunnel it
    /// will resolve the name through — so the ordinary startup answer, "cannot resolve", condemned every
    /// channel of that process to dial by address for its whole life. On a device whose organization has its
    /// own transport authority the shared anchor is gone, so dialling by address is not a fallback: the Edge
    /// recorded that device refusing its certificate, over and over, while the device never re-asked.
    func testANegativeAnswerIsReconsideredAndAPositiveOneIsNot() {
        let s = security(host: "203.0.113.10")
        DsseLiveTransportServerName.setProvider { "kaede.example.invalid" }

        var clock = Date()
        DsseDialHostDecision.setClock { clock }

        // Second zero: the name does not resolve yet, so the address is used — the safe answer.
        var resolvable = false
        DsseDialHostDecision.setResolver { _ in resolvable }
        DsseDialHostDecision.setClock { clock }
        XCTAssertEqual(s.dialHost, "203.0.113.10")

        // The name starts resolving. Within the lifetime of the negative answer nothing re-asks — that is the
        // cache doing its job, and it is why this is not a DNS lookup in front of every flow.
        resolvable = true
        XCTAssertEqual(s.dialHost, "203.0.113.10", "a fresh negative answer is believed")

        // Past it, the device asks again and moves onto its organization's name.
        clock = clock.addingTimeInterval(DsseDialHostDecision.negativeAnswerLifetime + 1)
        XCTAssertEqual(s.dialHost, "kaede.example.invalid",
                       "a stale negative answer must be reconsidered, or a startup race lasts for ever")

        // A positive answer is final: the name resolved, and re-asking buys nothing.
        resolvable = false
        clock = clock.addingTimeInterval(3600)
        XCTAssertEqual(s.dialHost, "kaede.example.invalid", "a yes is not re-litigated")
    }

    private func security(host: String) -> DsseTransportSecurity {
        DsseTransportSecurity(host: host, port: 18543, mtlsRequired: true,
                              pinnedCACertificates: [], clientIdentity: nil)
    }

    func testTheNameIsUsedWhenItResolvesAndTheAddressWhenItDoesNot() {
        let s = security(host: "203.0.113.10")

        // No organization name at all: a deployment that has none dials the address exactly as before.
        DsseLiveTransportServerName.setProvider { "" }
        DsseDialHostDecision.setResolver { _ in true }
        XCTAssertEqual(s.dialHost, "203.0.113.10", "with no announced name there is nothing to dial by")

        // A name that resolves: every channel now sends it, and each is served its organization's certificate.
        DsseLiveTransportServerName.setProvider { "lab.dsse.invalid" }
        DsseDialHostDecision.setResolver { $0 == "lab.dsse.invalid" }
        XCTAssertEqual(s.dialHost, "lab.dsse.invalid")

        // ★ AND IT FALLS BACK. Answering "yes" for a name this device cannot resolve takes it off the network
        // in the name of correctness; answering "no" costs only being served the shared certificate, which is
        // where it was yesterday. The doubt resolves towards the address.
        DsseDialHostDecision.setResolver { _ in false }
        XCTAssertEqual(s.dialHost, "203.0.113.10",
                       "a name that does not resolve must never be dialled — that is a fleet-wide outage")
    }

    func testTheResolverIsAskedOncePerName() {
        var asked = 0
        DsseLiveTransportServerName.setProvider { "lab.dsse.invalid" }
        DsseDialHostDecision.setResolver { _ in asked += 1; return true }
        let s = security(host: "203.0.113.10")
        for _ in 0..<25 { _ = s.dialHost }
        XCTAssertEqual(asked, 1, "every connection asks dialHost; a resolver call per connection would put a " +
                       "DNS lookup in front of all of this agent's control traffic")
    }
}
