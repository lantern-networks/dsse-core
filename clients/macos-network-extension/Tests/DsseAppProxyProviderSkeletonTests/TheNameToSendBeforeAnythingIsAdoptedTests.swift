import XCTest
@testable import DsseAppProxyProviderSkeleton

/// ★★★ THE CYCLE A NEW DEVICE COULD NOT LEAVE (2026-08-30, measured on a Mac joining a new deployment).
///
/// The name a device sends as its organization's own is read from the bundle it last ADOPTED. Adopting one
/// needs an identity; getting an identity needs an enrolment; and the enrolment's probe dials by that name.
/// So a device that has never adopted anything dialled the DEPLOYMENT-wide name:
///
///	enrolment probe host=agents.tokyo.hikari.lab:443/healthz result=REFUSED
///	  reason=A TLS error caused the secure connection to fail.
///
/// — served the deployment-wide certificate, on a device that now pins its ORGANISATION's transport authority
/// because the profile gave it one. Every new device of every organization begins in that state.
///
/// The profile has carried organization.transport_server_name all along. Nothing read it.
final class TheNameToSendBeforeAnythingIsAdoptedTests: XCTestCase {
    func testTheProfileSuppliesTheNameWhenNothingHasBeenAdopted() throws {
        let source = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Sources/DsseAppProxyProviderSkeleton/DsseAppProxyProvider.swift")
        let text = try String(contentsOf: source, encoding: .utf8)
        guard let i = text.range(of: "DsseLiveTransportServerName.setProvider") else {
            return XCTFail("nothing supplies the name this device sends")
        }
        let block = text[i.upperBound...].prefix(2_000)
        XCTAssertTrue(block.contains("profile?.transportServerName"),
                      "a device that has never adopted a bundle still has no organization name to send, so its "
                      + "first enrolment dials the deployment-wide door and is served a certificate its "
                      + "organization's pinned authority cannot verify")
        // ★ And the adopted bundle must still win: it is signed, it is how a rename reaches a device, and a
        // profile that has been superseded must not pull the name back.
        XCTAssertTrue(block.contains("if !adopted.isEmpty { return adopted }"),
                      "the profile now outranks what this device adopted, so a rename delivered by bundle would "
                      + "be undone by the profile it was installed with")
    }
}
