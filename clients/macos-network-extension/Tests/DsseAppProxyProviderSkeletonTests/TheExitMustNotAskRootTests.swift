import XCTest
import DsseNetworkExtensionContract

/// The shipped uninstaller's first and most important step — remove the transparent proxy configuration —
/// was run as root, and root cannot see it. See DsseNetworkConfigurationScope for what was measured.
final class TheExitMustNotAskRootTests: XCTestCase {
    private let app = "/Applications/LanternDsseAgent.app/Contents/MacOS/LanternDsseAgent"

    func testRootIsRefusedAndToldHowToRunIt() throws {
        let refusal = try XCTUnwrap(
            DsseNetworkConfigurationScope.refusalWhenNotTheConsoleUser(
                effectiveUID: 0, command: "--uninstall", appExecutablePath: app, consoleUID: 501),
            "root was allowed to answer 'is there a configuration?' — an empty answer then deletes the app "
            + "while the configuration stays behind")
        XCTAssertTrue(refusal.contains("launchctl asuser 501"),
                      "the refusal does not print the command that works: \(refusal)")
        XCTAssertTrue(refusal.contains("--uninstall"), "the refusal does not name the command it refused")
    }

    func testTheConsoleUserIsNotRefused() {
        XCTAssertNil(DsseNetworkConfigurationScope.refusalWhenNotTheConsoleUser(
            effectiveUID: 501, command: "--disable", appExecutablePath: app, consoleUID: 501),
            "the user who owns the configuration was refused, which leaves no way to remove it at all")
    }

    func testWithNobodyAtTheConsoleTheRefusalStillNamesAWayForward() throws {
        let refusal = try XCTUnwrap(DsseNetworkConfigurationScope.refusalWhenNotTheConsoleUser(
            effectiveUID: 0, command: "--uninstall", appExecutablePath: app,
            consoleUID: DsseNetworkConfigurationScope.consoleUID(statOwnerOfDevConsole: 0)))
        XCTAssertTrue(refusal.contains("log in as the console user"),
                      "with nobody logged in the operator is told nothing actionable: \(refusal)")
    }
}
