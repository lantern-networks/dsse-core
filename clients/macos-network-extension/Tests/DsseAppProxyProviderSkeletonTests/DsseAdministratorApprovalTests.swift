import XCTest
import DsseNetworkExtensionContract

final class DsseAdministratorApprovalTests: XCTestCase {
    private let now = Date(timeIntervalSince1970: 1_800_000_000)
    private func file(uid: UInt32 = 0, mode: UInt16 = 0o644, regular: Bool = true, age: TimeInterval = 5) -> DsseAdministratorApproval.FileFacts {
        .init(ownerUID: uid, mode: mode, isRegularFile: regular, isDirectory: !regular, modified: now.addingTimeInterval(-age))
    }
    private var folder: DsseAdministratorApproval.FileFacts { .init(ownerUID: 0, mode: 0o755, isRegularFile: false, isDirectory: true, modified: now) }

    func testRootsFreshApprovalIsAccepted() {
        XCTAssertTrue(DsseAdministratorApproval.rootApproved(file: file(), folder: folder, now: now))
    }

    func testNothingAnUnprivilegedPersonCanMakeIsAccepted() {
        XCTAssertFalse(DsseAdministratorApproval.rootApproved(file: nil, folder: folder, now: now), "no approval")
        XCTAssertFalse(DsseAdministratorApproval.rootApproved(file: file(uid: 501), folder: folder, now: now), "their own file")
        XCTAssertFalse(DsseAdministratorApproval.rootApproved(file: file(mode: 0o666), folder: folder, now: now), "a file anyone may rewrite")
        XCTAssertFalse(DsseAdministratorApproval.rootApproved(file: file(regular: false), folder: folder, now: now), "not a file")
        let theirFolder = DsseAdministratorApproval.FileFacts(ownerUID: 501, mode: 0o755, isRegularFile: false, isDirectory: true, modified: now)
        XCTAssertFalse(DsseAdministratorApproval.rootApproved(file: file(), folder: theirFolder, now: now), "a folder they own")
        let openFolder = DsseAdministratorApproval.FileFacts(ownerUID: 0, mode: 0o777, isRegularFile: false, isDirectory: true, modified: now)
        XCTAssertFalse(DsseAdministratorApproval.rootApproved(file: file(), folder: openFolder, now: now), "a folder anyone may write")
    }

    func testAnOldApprovalIsNotAStandingPermission() {
        XCTAssertFalse(DsseAdministratorApproval.rootApproved(file: file(age: 121), folder: folder, now: now))
        XCTAssertTrue(DsseAdministratorApproval.rootApproved(file: file(age: 119), folder: folder, now: now))
        XCTAssertFalse(DsseAdministratorApproval.rootApproved(file: file(age: -600), folder: folder, now: now), "dated in the future")
    }

    func testEachCommandHasItsOwnApproval() {
        XCTAssertEqual(DsseAdministratorApproval.path(forCommand: "--disable"), "/Library/Application Support/Dsse/admin-approval/disable")
        XCTAssertNotEqual(DsseAdministratorApproval.path(forCommand: "--disable"), DsseAdministratorApproval.path(forCommand: "--uninstall"))
    }
}
