import XCTest
@testable import DsseAppProxyProviderSkeleton

final class DsseDNSProxyMessageTests: XCTestCase {
    // A query for wiki.example (A, IN) with ID 0xbeef, RD set, and one EDNS OPT record in the additional section.
    private let query = Data([
        0xbe, 0xef, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x04, 0x77, 0x69, 0x6b, 0x69, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x00,
        0x00, 0x01, 0x00, 0x01,
        0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ])

    func testAQueryTheEdgeDidNotAnswerIsAnsweredServfailAtOnce() throws {
        let failure = try XCTUnwrap(DsseDNSProxyProvider.serverFailure(for: query))
        let b = [UInt8](failure)
        XCTAssertEqual(Array(b[0...1]), [0xbe, 0xef], "the query's ID")
        XCTAssertEqual(b[2] & 0x80, 0x80, "marked as a response")
        XCTAssertEqual(b[2] & 0x01, 0x01, "RD carried over")
        XCTAssertEqual(b[3] & 0x0f, 2, "SERVFAIL")
        XCTAssertEqual(Array(b[4...5]), [0x00, 0x01], "the one question")
        XCTAssertEqual(Array(b[6...11]), [0, 0, 0, 0, 0, 0], "no answers, authorities or additional records")
        XCTAssertEqual(b.count, 30, "header and question only")
        XCTAssertTrue(DsseDNSProxyProvider.isResponse(failure, to: query))
    }

    func testATruncatedQueryGetsNoAnswerRatherThanAMadeUpOne() {
        XCTAssertNil(DsseDNSProxyProvider.serverFailure(for: query.prefix(20)))
        XCTAssertNil(DsseDNSProxyProvider.serverFailure(for: Data([0x00, 0x01])))
    }

    func testOnlyAResponseToThisQueryIsPassedBack() {
        var other = [UInt8](query); other[2] |= 0x80
        XCTAssertTrue(DsseDNSProxyProvider.isResponse(Data(other), to: query))
        other[1] = 0x00
        XCTAssertFalse(DsseDNSProxyProvider.isResponse(Data(other), to: query), "another ID")
        XCTAssertFalse(DsseDNSProxyProvider.isResponse(query, to: query), "a query is not a response")
    }

    func testTCPMessagesAreTakenWholeAndInOrder() {
        let a = Data([1, 2, 3]), b = Data([4, 5])
        var buffer = DsseDNSProxyProvider.framed(a) + DsseDNSProxyProvider.framed(b) + Data([0x00, 0x05, 9])
        let messages = DsseDNSProxyProvider.takeFramedMessages(&buffer)
        XCTAssertEqual(messages, [a, b])
        XCTAssertEqual(buffer, Data([0x00, 0x05, 9]), "an incomplete message waits for the rest")
        buffer.append(contentsOf: [8, 7, 6, 5])
        XCTAssertEqual(DsseDNSProxyProvider.takeFramedMessages(&buffer), [Data([9, 8, 7, 6, 5])])
        XCTAssertTrue(buffer.isEmpty)
    }
}

final class DsseDNSKeptConnectionResponseTests: XCTestCase {
    private func response(_ head: String, _ body: [UInt8]) -> Data {
        var d = Data(head.utf8); d.append(contentsOf: body); return d
    }

    func testAnAnswerIsTakenWholeAndTheConnectionKept() {
        let raw = response("HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: 3\r\n\r\n", [1, 2, 3])
        XCTAssertEqual(DsseDNSKeptConnection.parse(raw), .answer(status: 200, body: Data([1, 2, 3]), keepAlive: true))
        XCTAssertEqual(DsseDNSKeptConnection.parse(raw.prefix(raw.count - 1)), .incomplete, "a body still arriving")
        XCTAssertEqual(DsseDNSKeptConnection.parse(raw.prefix(20)), .incomplete, "headers still arriving")
    }

    func testARefusalAndAClosingConnectionAreRead() {
        let refused = response("HTTP/1.1 401 Unauthorized\r\ncontent-length: 2\r\nConnection: close\r\n\r\n", [0x6e, 0x6f])
        XCTAssertEqual(DsseDNSKeptConnection.parse(refused), .answer(status: 401, body: Data([0x6e, 0x6f]), keepAlive: false))
    }

    func testAResponseWhoseEndCannotBeKnownIsNotGuessedAt() {
        XCTAssertEqual(DsseDNSKeptConnection.parse(response("HTTP/1.1 200 OK\r\n\r\n", [1])), .malformed, "no length")
        XCTAssertEqual(DsseDNSKeptConnection.parse(response("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n", [])), .malformed)
        XCTAssertEqual(DsseDNSKeptConnection.parse(response("HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n", [1, 2])), .malformed,
                       "bytes beyond the answer would belong to another query")
        XCTAssertEqual(DsseDNSKeptConnection.parse(response("garbage\r\n\r\n", [])), .malformed)
    }
}
