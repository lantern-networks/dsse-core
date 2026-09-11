import XCTest
@testable import DsseAppProxyProviderSkeleton

/// ★★ THIS PARSER RUNS ON A DEVICE THAT IS ALREADY LOCKED OUT, so every way it can be wrong costs that device
/// its only way back. The renewal request moved to NWConnection because the expired-certificate path is
/// selected on the Edge by a TLS server name and URLSession cannot send one that differs from the address
/// (the enrolment fold) — which means this code now owns the HTTP framing that URLSession used to own.
///
/// Asserted here rather than end to end because reproducing the real case needs a certificate that has already
/// expired. What can be tested exactly is the framing, and the framing is where a small mistake reads as
/// "the server sent nothing usable".
final class DsseSingleRequestParseTests: XCTestCase {
    func testAPlainResponseIsSplitAtTheHeaderBoundary() throws {
        let raw = Data("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 17\r\n\r\n{\"cert_pem\":\"x\"}".utf8)
        let r = try DsseSingleRequestOverNW.parse(raw)
        XCTAssertEqual(r.status, 200)
        XCTAssertEqual(String(data: r.body, encoding: .utf8), "{\"cert_pem\":\"x\"}")
    }

    func testARefusalKeepsItsStatusAndBody() throws {
        let raw = Data("HTTP/1.1 403 Forbidden\r\nContent-Length: 29\r\n\r\n{\"error\":\"identity revoked\"}".utf8)
        let r = try DsseSingleRequestOverNW.parse(raw)
        XCTAssertEqual(r.status, 403, "the caller distinguishes refused from unreachable, and only the status can")
        XCTAssertTrue(String(data: r.body, encoding: .utf8)!.contains("revoked"))
    }

    func testAChunkedBodyIsDecodedRatherThanHandedOnTruncated() throws {
        let raw = Data("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n5\r\nworld\r\n0\r\n\r\n".utf8)
        let r = try DsseSingleRequestOverNW.parse(raw)
        XCTAssertEqual(String(data: r.body, encoding: .utf8), "helloworld",
                       "a chunked answer handed on raw would reach the caller as JSON it cannot decode, and the "
                       + "message would send the reader to the server rather than here")
    }

    func testAnAnswerWithNoHeaderBoundaryIsRefusedRatherThanGuessedAt() {
        XCTAssertThrowsError(try DsseSingleRequestOverNW.parse(Data("HTTP/1.1 200 OK".utf8)),
                             "half an answer must not be read as a whole one: the caller is about to install a "
                             + "certificate out of this body")
    }

    func testAStatusLineWithoutACodeIsRefused() {
        XCTAssertThrowsError(try DsseSingleRequestOverNW.parse(Data("GARBAGE\r\n\r\nbody".utf8)))
    }
}
