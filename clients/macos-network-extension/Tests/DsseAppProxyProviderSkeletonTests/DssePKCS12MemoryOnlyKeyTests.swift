import XCTest
import Security
@testable import DsseAppProxyProviderSkeleton

// The p12 import asks for a MEMORY-ONLY import by literal string, because the named constant
// (kSecImportToMemoryOnly) is macOS 15+ and gating on it would leave exactly the older fleet with the defect:
// a file-delivered bootstrap identity persisted into a keychain, bound by ACL to the code that imported it, and
// therefore unusable after any rebrand, re-sign or team change.
//
// A literal is a guess until something checks it. This is that check.
final class DssePKCS12MemoryOnlyKeyTests: XCTestCase {
    func testTheLiteralMatchesTheFrameworkConstant() throws {
        guard #available(macOS 15.0, *) else {
            throw XCTSkip("kSecImportToMemoryOnly is macOS 15+; the literal cannot be compared here")
        }
        XCTAssertEqual(kSecImportToMemoryOnly as String, "memory",
                       "the p12 import passes this key as a literal so pre-15 systems also get a memory-only "
                       + "import — if Security.framework spells it differently, the import silently persists "
                       + "into a keychain again and the ACL defect returns")
    }
}
