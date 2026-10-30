import Foundation
import CoreFoundation
import Darwin

// Resource quotas are authored by the host administrator, not inferred from a
// signed application's destination or from the number of flows currently open.
// No file / a zero value imposes no connection-count, byte, or idle quota.
public struct DssePerformanceLimits: Equatable, Sendable {
    public let maxConcurrentConnections: Int
    public let maxBytesPerFlow: Int
    public let maxSessionExchangesPerFlow: Int
    public let idleTimeoutSeconds: TimeInterval
    public static let path = "/Library/Application Support/Dsse/performance-limits.json"
    public static let current: DssePerformanceLimits = {
        do { return try loadRootConfiguration() }
        catch { preconditionFailure("Invalid administrator performance-limits.json: \(error)") }
    }()

    public static func decode(_ data: Data) throws -> DssePerformanceLimits {
        guard let values = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(values.keys).isSubset(of: ["max_concurrent_connections", "max_bytes_per_flow", "idle_timeout_seconds", "max_session_exchanges_per_flow"]) else {
            throw NSError(domain: "DssePerformanceLimits", code: 1)
        }
        func count(_ key: String) throws -> Int {
            guard let value = values[key] else { return 0 }
            guard let number = value as? NSNumber,
                  CFGetTypeID(number) != CFBooleanGetTypeID(),
                  let n = Int(number.stringValue), n >= 0 else {
                throw NSError(domain: "DssePerformanceLimits", code: 2)
            }
            return n
        }
        return try DssePerformanceLimits(maxConcurrentConnections: count("max_concurrent_connections"), maxBytesPerFlow: count("max_bytes_per_flow"), maxSessionExchangesPerFlow: count("max_session_exchanges_per_flow"), idleTimeoutSeconds: TimeInterval(count("idle_timeout_seconds")))
    }

    private static func loadRootConfiguration() throws -> DssePerformanceLimits {
        let fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        if fd < 0 {
            if errno == ENOENT { return try decode(Data("{}".utf8)) }
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
        }
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_uid == 0,
              info.st_mode & S_IFMT == S_IFREG, info.st_mode & 0o022 == 0,
              info.st_size <= 65_536 else { throw NSError(domain: "DssePerformanceLimits", code: 3) }
        return try decode(handle.readToEnd() ?? Data())
    }
}
