import Foundation
import XCTest
@testable import DsseAppProxyProviderSkeleton

final class DsseAuthHandoffTests: XCTestCase {
    func testMuxOutcomeIsStrictlyBoundedAndHasNoIdentityFields() {
        let id = String(repeating: "A", count: 32)
        let valid = Data("{\"request_id\":\"\(id)\",\"result\":\"resumed\"}".utf8)
        XCTAssertEqual(DsseAuthHandoff.validatedResult(valid)?.id, id)
        XCTAssertEqual(DsseAuthHandoff.validatedResult(valid)?.result, "resumed")
        for payload in [
            "{\"request_id\":\"x\",\"result\":\"resumed\"}",
            "{\"request_id\":\"\(id)\",\"result\":\"approved\"}",
            "{\"request_id\":\"\(id)\",\"result\":\"resumed\",\"user\":\"other\"}",
            String(repeating: "x", count: 257)
        ] {
            XCTAssertNil(DsseAuthHandoff.validatedResult(Data(payload.utf8)))
        }
    }

    func testOnlyExactPortalAndLiveRequestCanLaunch() {
        let now = Date(timeIntervalSince1970: 2_000_000_000)
        let query = "portal_origin=https%3A%2F%2Fportal.example%3A443&request_id=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&issued_at=2000000000&expires_at=2000000120&requirements_sig=x&device_sig=x"
        let raw = "https://portal.example/clientless/auth/start?" + query
        let origins = ["https://portal.example:443"]
        XCTAssertNotNil(DsseAuthHandoff.validatedURL(raw, origins: origins, now: now))
        XCTAssertNotNil(DsseAuthHandoff.validatedURL(raw + "&grant_ttl=300", origins: origins, now: now))
        XCTAssertNotNil(DsseAuthHandoff.validatedStartURL(raw, origins: origins, observedUptime: 1000, now: now, uptime: 1000))
        XCTAssertNotNil(DsseAuthHandoff.validatedStartURL(raw, origins: origins, observedUptime: 1000, now: now.addingTimeInterval(119), uptime: 1119))
        XCTAssertNil(DsseAuthHandoff.validatedStartURL(raw, origins: origins, observedUptime: 1000, now: now.addingTimeInterval(120), uptime: 1120))
        XCTAssertNil(DsseAuthHandoff.validatedStartURL(raw, origins: origins, observedUptime: 1000, now: now, uptime: 999))
        // A device clock can be ahead of the Portal. The server owns the exact
        // deadline; the local UI bounds its prompt by monotonic receipt time.
        XCTAssertNotNil(DsseAuthHandoff.validatedStartURL(raw, origins: origins, observedUptime: 1000,
                                                          now: now.addingTimeInterval(299), uptime: 1001))
        for bad in [raw + "#fragment", raw + "&request_id=other", raw.replacingOccurrences(of: "https:", with: "http:"), raw.replacingOccurrences(of: "portal.example", with: "portal.example.attacker.test"), raw.replacingOccurrences(of: "portal.example", with: "user@portal.example")] {
            XCTAssertNil(DsseAuthHandoff.validatedURL(bad, origins: origins, now: now))
        }
        XCTAssertNotNil(DsseAuthHandoff.validatedURL(raw, origins: origins, now: now.addingTimeInterval(-299)))
        XCTAssertNotNil(DsseAuthHandoff.validatedURL(raw, origins: origins, now: now.addingTimeInterval(299)))
        XCTAssertNil(DsseAuthHandoff.validatedURL(raw, origins: [], now: now))
        XCTAssertNil(DsseAuthHandoff.validatedURL(raw, origins: origins, now: now.addingTimeInterval(420)))
    }

    func testHandoffWorkIsBoundedAndDoesNotBlockCaller() {
        let queue = DsseAuthWorkQueue(limit: 1)
        let release = DispatchSemaphore(value: 0)
        let entered = expectation(description: "worker entered")
        let finished = expectation(description: "worker exited")
        XCTAssertTrue(queue.submit {
            entered.fulfill()
            _ = release.wait(timeout: .now() + 3)
            finished.fulfill()
        })
        wait(for: [entered], timeout: 1)
        XCTAssertFalse(queue.submit { XCTFail("exceeded queue limit") })
        release.signal()
        wait(for: [finished], timeout: 1)
    }

    func testLoginIdentityMetadataAndLaunchBinding() {
        let principal = "macos:11111111-2222-3333-4444-555555555555"
        let session = String(repeating: "a", count: 64)
        let owner = DsseAuthOwner(uid: 501, session: 42, principal: principal, loginSession: session)
        XCTAssertEqual(owner.appendingIdentity(to: "app:22"), "app:22\0op=" + principal + " ls=" + session)
        XCTAssertTrue(owner.matchesIdentity(in: ["os_principal": principal, "os_session": session]))
        XCTAssertTrue(owner.matchesIdentity(in: [:])) // mixed-version legacy Portal
        XCTAssertFalse(owner.matchesIdentity(in: ["os_principal": principal]))
        XCTAssertFalse(owner.matchesIdentity(in: ["os_principal": principal, "os_session": String(repeating: "b", count: 64)]))
        XCTAssertFalse(DsseAuthOwner(uid: 501, session: 42).matchesIdentity(in: ["os_principal": principal, "os_session": session]))
    }

    func testKernelAuditTokenBindsUserAndLoginSession() {
        var words: [UInt32] = [501, 501, 20, 501, 20, 1234, 42, 1]
        let token = words.withUnsafeBytes { Data($0) }
        let owner = DsseAuthOwner.fromAuditToken(token)
        XCTAssertEqual(owner?.uid, 501)
        XCTAssertEqual(owner?.session, 42)
        XCTAssertTrue(owner?.principal?.hasPrefix("macos:") == true)
        XCTAssertEqual(owner?.loginSession?.count, 64)
        words[5] = 9876 // a different process in the same login
        XCTAssertEqual(owner?.loginSession, DsseAuthOwner.fromAuditToken(words.withUnsafeBytes { Data($0) })?.loginSession)
        words[6] = 43
        XCTAssertNotEqual(owner, DsseAuthOwner.fromAuditToken(words.withUnsafeBytes { Data($0) }))
        words[1] = 0
        XCTAssertNil(DsseAuthOwner.fromAuditToken(words.withUnsafeBytes { Data($0) }))
        XCTAssertNil(DsseAuthOwner.fromAuditToken(Data()))
    }

    func testWarnNoticeNeedsOriginatingSessionAndBoundedPayload() {
        let owner = DsseAuthOwner(uid: 501, session: 42,
                                  principal: "macos:11111111-2222-3333-4444-555555555555")
        let payload = Data(#"{"message":"monitored","destination":"10.20.0.10","service":"ssh"}"#.utf8)
        XCTAssertNil(DsseAuthHandoff.validatedWarnPayload(payload, owner: nil))
        guard let notice = DsseAuthHandoff.validatedWarnPayload(payload, owner: owner) else {
            XCTFail("valid session-bound notice rejected")
            return
        }
        XCTAssertEqual(notice.destination, "10.20.0.10")
        XCTAssertTrue(DsseAuthHandoff.warnVisible(notice, to: owner, now: notice.created))
        XCTAssertFalse(DsseAuthHandoff.warnVisible(notice,
            to: DsseAuthOwner(uid: 502, session: 42, principal: owner.principal), now: notice.created))
        XCTAssertFalse(DsseAuthHandoff.warnVisible(notice,
            to: DsseAuthOwner(uid: 501, session: 43, principal: owner.principal), now: notice.created))
        XCTAssertFalse(DsseAuthHandoff.warnVisible(notice, to: owner, now: notice.created + 601))
        XCTAssertNil(DsseAuthHandoff.validatedWarnPayload(Data(#"{"message":"x","destination":"a\nnewline","service":"ssh"}"#.utf8), owner: owner))
        XCTAssertNil(DsseAuthHandoff.validatedWarnPayload(Data(repeating: 65, count: 4097), owner: owner))
    }
}
