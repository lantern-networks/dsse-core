import Foundation
import XCTest

final class DsseUninstallFailureExitTests: XCTestCase {
    func testDeactivationFailureKeepsContainingAppInstalled() throws {
        let package = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let app = try String(contentsOf: package.appendingPathComponent("Sources/DsseAgentAppExecutable/main.swift"), encoding: .utf8)
        let failure = try XCTUnwrap(app.range(of: "func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error)"))
        let failureBody = app[failure.lowerBound..<app.endIndex].prefix(900)
        XCTAssertTrue(failureBody.contains("exit(4)"), "failed deactivation must give the uninstaller a nonzero exit")
        XCTAssertFalse(failureBody.contains("NSApplication.shared.terminate(nil)"), "failed deactivation must not look successful")

        let packageScript = try String(contentsOf: package.appendingPathComponent("packaging/build_macos_ne_pkg.sh"), encoding: .utf8)
        XCTAssertTrue(packageScript.contains("if ! launchctl asuser "))
        XCTAssertTrue(packageScript.contains("--uninstall; then"))
        XCTAssertTrue(packageScript.contains("exit 1\n\tfi\n\tsleep 8"), "failed app command must stop before deleting the app")
    }

    func testDisableFailureReturnsNonzero() throws {
        let package = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let app = try String(contentsOf: package.appendingPathComponent("Sources/DsseAgentAppExecutable/main.swift"), encoding: .utf8)
        let disable = try XCTUnwrap(app.range(of: "} else if CommandLine.arguments.contains(\"--disable\")"))
        let disableBody = app[disable.lowerBound..<app.endIndex].prefix(500)
        XCTAssertTrue(disableBody.contains("if error != nil { exit(5) }"), "failed preference save must not report a successful disable")
    }
}
