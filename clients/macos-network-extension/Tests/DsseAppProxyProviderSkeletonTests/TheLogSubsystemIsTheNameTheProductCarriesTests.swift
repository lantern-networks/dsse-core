import XCTest
@testable import DsseNetworkExtensionContract

/// ★★★ A PREDICATE NO SHIPPED PRODUCT MATCHES.
///
/// The subsystem was a literal placeholder in five files while every build set its own bundle id. An operator
/// forming the predicate from the product's bundle id matched nothing; a developer following the source
/// matched nothing either. "I checked the logs and there was nothing" is the most repeated wrong conclusion
/// in this project's history, and this is why.
final class TheLogSubsystemIsTheNameTheProductCarriesTests: XCTestCase {
    func testTheContainerAppLogsUnderItsOwnBundleID() {
        XCTAssertEqual(DsseRuntimeLogSubsystem.resolve(bundleIdentifier: "jp.co.example.dsse.agent"),
                       "jp.co.example.dsse.agent")
    }

    func testTheSystemExtensionLogsUnderTheContainersName() {
        XCTAssertEqual(
            DsseRuntimeLogSubsystem.resolve(bundleIdentifier: "jp.co.example.dsse.agent.networkextension"),
            "jp.co.example.dsse.agent",
            "one predicate must show the agent and its provider interleaved — that is the order the two have " +
            "to be read in, and splitting them is how an activation failure was read as a datapath failure")
    }

    func testAProcessWithNoBundleIdentifierStillLogsSomewhereNamed() {
        XCTAssertEqual(DsseRuntimeLogSubsystem.resolve(bundleIdentifier: nil), "example.dsse.agent")
        XCTAssertEqual(DsseRuntimeLogSubsystem.resolve(bundleIdentifier: "   "), "example.dsse.agent",
                       "a blank id is not a name; falling through to one keeps the lines findable rather " +
                       "than emitting them under the empty string")
        XCTAssertEqual(DsseRuntimeLogSubsystem.resolve(bundleIdentifier: ".networkextension"),
                       "example.dsse.agent")
    }
}
