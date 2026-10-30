import Darwin
import Foundation
import CryptoKit

@_silgen_name("mbr_uid_to_uuid")
private func dsseUIDToUUID(_ uid: uid_t, _ uuid: UnsafeMutableRawPointer) -> Int32

public struct DsseAuthOwner: Codable, Equatable, Sendable {
    public let uid: UInt32
    public let session: UInt32
    public let principal: String?
    public let loginSession: String?
    private static let agentEpoch = UUID().uuidString
    public init(uid: UInt32, session: UInt32, principal: String? = nil, loginSession: String? = nil) {
        self.uid = uid; self.session = session; self.principal = principal; self.loginSession = loginSession
    }
    public func appendingIdentity(to authority: String) -> String {
        guard let principal, let loginSession else { return authority }
        return authority + (authority.contains("\0") ? " " : "\0") + "op=" + principal + " ls=" + loginSession
    }

    public func matchesIdentity(in values: [String: String]) -> Bool {
        // Old Portals omit identity metadata until fleet activation.
        if values["os_principal"] == nil && values["os_session"] == nil { return true }
        guard let principal, let loginSession else { return false }
        return values["os_principal"] == principal && values["os_session"] == loginSession
    }

    public static func fromAuditToken(_ data: Data?) -> DsseAuthOwner? {
        guard let data, data.count == 32 else { return nil }
        let uid = data.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: 4, as: UInt32.self) }
        let session = data.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: 24, as: UInt32.self) }
        guard uid >= 501, session != 0, session != UInt32.max else { return nil }
        var uuid = UUID().uuid
        guard dsseUIDToUUID(uid, &uuid) == 0 else { return nil }
        let principal = "macos:" + UUID(uuid: uuid).uuidString.lowercased()
        let material = "\(agentEpoch)|\(principal)|\(session)"
        let login = SHA256.hash(data: Data(material.utf8)).map { String(format: "%02x", $0) }.joined()
        return DsseAuthOwner(uid: uid, session: session, principal: principal, loginSession: login)
    }

    public static func current() -> DsseAuthOwner? {
        var token = audit_token_t()
        var count = mach_msg_type_number_t(MemoryLayout<audit_token_t>.size / MemoryLayout<integer_t>.size)
        let result = withUnsafeMutablePointer(to: &token) { ptr in
            ptr.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                task_info(mach_task_self_, task_flavor_t(TASK_AUDIT_TOKEN), $0, &count)
            }
        }
        guard result == KERN_SUCCESS else { return nil }
        return withUnsafeBytes(of: token) { fromAuditToken(Data($0)) }
    }
}

// The shared mux reader must never perform file/ACL/profile work synchronously.
// One worker and a fixed admission bound also limit memory under notification floods.
final class DsseAuthWorkQueue: @unchecked Sendable {
    private let queue = DispatchQueue(label: "jp.co.lantern-networks.dsse.auth-handoff")
    private let slots: DispatchSemaphore
    init(limit: Int = 32) { slots = DispatchSemaphore(value: limit) }
    func submit(_ work: @escaping @Sendable () -> Void) -> Bool {
        guard slots.wait(timeout: .now()) == .success else { return false }
        queue.async { [self] in
            defer { slots.signal() }
            work()
        }
        return true
    }
}

// Root-owned, session-specific files; ACLs grant only the originating user read
// access. Darwin notifications contain no URL and merely prompt a re-read.
public enum DsseAuthHandoff {
    private static let lock = NSLock()
    private static let workQueue = DsseAuthWorkQueue()
    // Informational WARN notices must not consume the authentication handoff queue.
    private static let warnWorkQueue = DsseAuthWorkQueue(limit: 8)

    public static func enqueue(url: String, owner: DsseAuthOwner?) -> Bool {
        guard url.utf8.count <= 16384, let owner else { return false }
        return workQueue.submit {
            if publish(url: url, owner: owner) {
                CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(),
                    CFNotificationName("jp.co.lantern-networks.dsse.stepup" as CFString), nil, nil, true)
            } else {
                NSLog("DSSE authentication handoff refused: invalid request or unavailable session handoff")
            }
        }
    }
    public static func enqueueResult(payload: Data, owner: DsseAuthOwner?) -> Bool {
        guard let owner, let outcome = validatedResult(payload) else { return false }
        return workQueue.submit {
            if publishResult(id: outcome.id, result: outcome.result, owner: owner) {
                CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(),
                    CFNotificationName("jp.co.lantern-networks.dsse.stepup" as CFString), nil, nil, true)
            }
        }
    }
    public static func enqueueQueriedResult(payload: Data) -> Bool {
        guard let outcome = validatedResult(payload) else { return false }
        return workQueue.submit {
            guard geteuid() == 0, let rootFD = protectedFD(directory, directory: true) else { return }
            close(rootFD)
            var matched: DsseAuthOwner?
            for folder in (try? FileManager.default.contentsOfDirectory(atPath: directory)) ?? [] {
                guard let fd = protectedFD(directory + "/" + folder, directory: true) else { continue }
                close(fd)
                let path = directory + "/" + folder + "/" + outcome.id + ".json"
                guard let data = rootData(path, max: 20000),
                      let request = try? JSONDecoder().decode(Request.self, from: data),
                      request.id == outcome.id, sessionDirectory(request.owner) == directory + "/" + folder,
                      request.result == nil, validatedURL(request.url, origins: trustedOrigins()) != nil else { continue }
                if matched != nil { return } // Request IDs must remain unique across sessions.
                matched = request.owner
            }
            if publishResult(id: outcome.id, result: outcome.result, owner: matched) {
                CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(),
                    CFNotificationName("jp.co.lantern-networks.dsse.stepup" as CFString), nil, nil, true)
            }
        }
    }

    public struct ResultQuery: Sendable {
        public let id: String
        public let principal: String
        public let session: String
    }

    // Root NE work only; never called on the shared mux reader queue.
    public static func resultQueries() -> [ResultQuery] {
        guard geteuid() == 0, let rootFD = protectedFD(directory, directory: true) else { return [] }
        close(rootFD)
        var queries: [ResultQuery] = []
        for folder in (try? FileManager.default.contentsOfDirectory(atPath: directory)) ?? [] {
            guard queries.count < 256, let fd = protectedFD(directory + "/" + folder, directory: true) else { continue }
            close(fd)
            for name in (try? FileManager.default.contentsOfDirectory(atPath: directory + "/" + folder)) ?? [] {
                guard queries.count < 256, name.hasSuffix(".json"),
                      let data = rootData(directory + "/" + folder + "/" + name, max: 20000),
                      let request = try? JSONDecoder().decode(Request.self, from: data),
                      request.result == nil, request.id + ".json" == name,
                      sessionDirectory(request.owner) == directory + "/" + folder,
                      let principal = request.owner.principal, let session = request.owner.loginSession,
                      validatedURL(request.url, origins: trustedOrigins()) != nil else { continue }
                queries.append(ResultQuery(id: request.id, principal: principal, session: session))
            }
        }
        return queries
    }
    public static func validatedResult(_ payload: Data) -> (id: String, result: String)? {
        guard payload.count <= 256,
              let fields = (try? JSONSerialization.jsonObject(with: payload)) as? [String: String],
              fields.count == 2, let id = fields["request_id"], let result = fields["result"],
              id.utf8.count == 32,
              id.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-" || $0 == "_") }),
              result == "resumed" || result == "not_resumed" else { return nil }
        return (id, result)
    }
    private static let base = "/Library/Application Support/Dsse"
    private static let directory = base + "/auth-requests"
    private static let warnDirectory = base + "/warn-notices"
    public struct Request: Codable, Sendable {
        public let owner: DsseAuthOwner
        public let url: String
        public let id: String
        public let expires: Int64
        public let result: String?
        public init(owner: DsseAuthOwner, url: String, id: String, expires: Int64, result: String? = nil) {
            self.owner = owner; self.url = url; self.id = id; self.expires = expires; self.result = result
        }
    }

    public static func validatedURL(_ raw: String, origins: [String], now: Date = Date()) -> URL? {
        guard raw.utf8.count <= 16384,
              !raw.unicodeScalars.contains(where: { $0.value < 33 || $0.value == 127 || "\"'`\\".unicodeScalars.contains($0) }),
              let u = URLComponents(string: raw), u.scheme == "https", u.user == nil, u.password == nil,
              u.fragment == nil, u.percentEncodedPath == "/clientless/auth/start", let host = u.host,
              !host.contains("%"), !host.contains("*") else { return nil }
        let trusted = origins.contains { rawOrigin in
            guard let o = URLComponents(string: rawOrigin), o.scheme == "https", o.user == nil, o.password == nil,
                  o.query == nil, o.fragment == nil, o.path.isEmpty || o.path == "/" else { return false }
            return o.host?.lowercased() == host.lowercased() && (o.port ?? 443) == (u.port ?? 443)
        }
        guard trusted else { return nil }
        var values: [String: String] = [:]
        for item in u.queryItems ?? [] {
            guard values[item.name] == nil, let value = item.value else { return nil }
            values[item.name] = value
        }
        guard let boundOrigin = values["portal_origin"], let bound = URLComponents(string: boundOrigin),
              bound.scheme == "https", bound.host?.lowercased() == host.lowercased(), (bound.port ?? 443) == (u.port ?? 443),
              bound.user == nil, bound.password == nil, bound.query == nil, bound.fragment == nil, bound.path.isEmpty,
              let id = values["request_id"], id.utf8.count == 32,
              id.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-" || $0 == "_") }),
              let issued = Int64(values["issued_at"] ?? ""), let expires = Int64(values["expires_at"] ?? ""),
              issued > 0, issued <= Int64(now.timeIntervalSince1970) + 300,
              issued <= Int64.max - 120, expires == issued + 120, expires > Int64(now.timeIntervalSince1970) - 300,
              !(values["requirements_sig"] ?? "").isEmpty, !(values["device_sig"] ?? "").isEmpty else { return nil }
        return u.url
    }

    // Keep a prompt for at most the Portal's 120-second request lifetime from
    // receipt. Use monotonic time: comparing expires_at directly to the device
    // clock would undo the clock-skew allowance in validatedURL. The Portal is
    // authoritative and may still reject a request that arrived late.
    public static func validatedStartURL(_ raw: String, origins: [String], observedUptime: TimeInterval,
                                         now: Date = Date(), uptime: TimeInterval = ProcessInfo.processInfo.systemUptime) -> URL? {
        guard uptime >= observedUptime, uptime - observedUptime < 120 else { return nil }
        return validatedURL(raw, origins: origins, now: now)
    }

    private static func protectedFD(_ path: String, directory: Bool = false) -> Int32? {
        let fd = open(path, O_RDONLY | O_NOFOLLOW | (directory ? O_DIRECTORY : 0))
        guard fd >= 0 else { return nil }
        var st = stat()
        guard fstat(fd, &st) == 0, st.st_uid == 0, (st.st_mode & 0o022) == 0,
              directory ? (st.st_mode & S_IFMT) == S_IFDIR : (st.st_mode & S_IFMT) == S_IFREG else { close(fd); return nil }
        return fd
    }

    private static func rootData(_ path: String, max: Int = 2_000_000) -> Data? {
        guard let fd = protectedFD(path) else { return nil }
        let file = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        guard let data = try? file.read(upToCount: max + 1), data.count <= max else { return nil }
        return data
    }

    public static func trustedOrigins() -> [String] {
        guard let fd = protectedFD(base, directory: true) else { return [] }
        close(fd)
        // The installer deliberately keeps agent_config.json root-only. Read its
        // separately provisioned PUBLIC verification key and signed profile,
        // both root-owned and user-readable; never loosen the private file.
        guard let keyData = rootData(base + "/profile_signing_key.txt", max: 1024),
              let pin = String(data: keyData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines),
              let data = rootData(base + "/install_profile.json"),
              let profile = DsseSignedInstallProfile.verifiedProfile(envelopeData: data, pinnedPublicKeyHex: pin) else { return [] }
        return profile.deployment?.stepUpPortalOrigins ?? []
    }

    private static func grantRead(_ fd: Int32, uid: UInt32, directory: Bool) -> Bool {
        var uuid = UUID().uuid
        guard dsseUIDToUUID(uid, &uuid) == 0 else { return false }
        var acl = acl_init(1)
        defer { if let acl { _ = acl_free(UnsafeMutableRawPointer(acl)) } }
        var entry: acl_entry_t?
        guard acl_create_entry(&acl, &entry) == 0, let entry,
              acl_set_tag_type(entry, ACL_EXTENDED_ALLOW) == 0,
              acl_set_qualifier(entry, &uuid) == 0 else { return false }
        var permissions: acl_permset_t?
        guard acl_get_permset(entry, &permissions) == 0, let permissions else { return false }
        for permission in [ACL_READ_DATA, ACL_READ_ATTRIBUTES, ACL_READ_EXTATTRIBUTES, ACL_READ_SECURITY] {
            guard acl_add_perm(permissions, permission) == 0 else { return false }
        }
        if directory && acl_add_perm(permissions, ACL_SEARCH) != 0 { return false }
        guard let acl else { return false }
        return acl_set_fd_np(fd, acl, ACL_TYPE_EXTENDED) == 0
    }

    private static func sessionDirectory(_ owner: DsseAuthOwner) -> String {
        directory + "/\(owner.uid)-\(owner.session)"
    }

    public static func publish(url raw: String, owner: DsseAuthOwner?) -> Bool {
        guard geteuid() == 0, let owner,
              let url = validatedURL(raw, origins: trustedOrigins()),
              let components = URLComponents(url: url, resolvingAgainstBaseURL: false) else { return false }
        let values = Dictionary(uniqueKeysWithValues: (components.queryItems ?? []).map { ($0.name, $0.value ?? "") })
        guard owner.matchesIdentity(in: values),
              let id = values["request_id"], let expires = Int64(values["expires_at"] ?? "") else { return false }
        lock.lock(); defer { lock.unlock() }
        guard let baseFD = protectedFD(base, directory: true) else { return false }; close(baseFD)
        if mkdir(directory, 0o755) != 0 && errno != EEXIST { return false }
        guard let rootFD = protectedFD(directory, directory: true) else { return false }; close(rootFD)
        let folder = sessionDirectory(owner)
        if mkdir(folder, 0o700) != 0 && errno != EEXIST { return false }
        guard let folderFD = protectedFD(folder, directory: true) else { return false }
        defer { close(folderFD) }
        guard grantRead(folderFD, uid: owner.uid, directory: true) else { return false }
        let files = (try? FileManager.default.contentsOfDirectory(atPath: folder)) ?? []
        var count = 0
        for name in files where name.hasSuffix(".json") {
            if let data = rootData(folder + "/" + name, max: 20000),
               let request = try? JSONDecoder().decode(Request.self, from: data), request.expires <= Int64(Date().timeIntervalSince1970) - 300 {
                _ = unlink((folder + "/" + name))
            } else { count += 1 }
        }
        guard count < 32, let data = try? JSONEncoder().encode(Request(owner: owner, url: raw, id: id, expires: expires)) else { return false }
        let path = folder + "/" + id + ".json"
        let fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
        if fd < 0 { return errno == EEXIST }
        let file = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        do { try file.write(contentsOf: data) } catch { _ = unlink(path); return false }
        guard grantRead(fd, uid: owner.uid, directory: false) else { _ = unlink(path); return false }
        return true
    }

    // Called only by the root NE after an AUTH_RESULT frame on the authenticated
    // mux. Never create a result record from an unsolicited frame: its request
    // must already exist in this exact OS session's protected handoff folder.
    public static func publishResult(id: String, result: String, owner: DsseAuthOwner?) -> Bool {
        guard geteuid() == 0, let owner, result == "resumed" || result == "not_resumed",
              id.utf8.count == 32,
              id.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-" || $0 == "_") }) else { return false }
        lock.lock(); defer { lock.unlock() }
        let folder = sessionDirectory(owner)
        guard let folderFD = protectedFD(folder, directory: true) else { return false }
        defer { close(folderFD) }
        let path = folder + "/" + id + ".json"
        guard let data = rootData(path, max: 20000),
              let request = try? JSONDecoder().decode(Request.self, from: data),
              request.id == id, request.owner == owner,
              validatedURL(request.url, origins: trustedOrigins()) != nil else { return false }
        if let previous = request.result { return previous == result }
        let updated = Request(owner: owner, url: request.url, id: id, expires: request.expires, result: result)
        guard let encoded = try? JSONEncoder().encode(updated) else { return false }
        let temporary = folder + "/." + id + ".result-" + UUID().uuidString
        let fd = open(temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
        guard fd >= 0 else { return false }
        let file = FileHandle(fileDescriptor: fd, closeOnDealloc: false)
        defer { close(fd) }
        do { try file.write(contentsOf: encoded) } catch { _ = unlink(temporary); return false }
        guard grantRead(fd, uid: owner.uid, directory: false), fsync(fd) == 0,
              rename(temporary, path) == 0 else { _ = unlink(temporary); return false }
        return true
    }

    public static func pending() -> [Request] {
        guard let owner = DsseAuthOwner.current(), owner.uid == getuid(),
              let rootFD = protectedFD(directory, directory: true) else { return [] }
        close(rootFD)
        let folder = sessionDirectory(owner)
        guard let fd = protectedFD(folder, directory: true) else { return [] }; close(fd)
        let origins = trustedOrigins()
        return ((try? FileManager.default.contentsOfDirectory(atPath: folder)) ?? []).prefix(32).compactMap { name in
            guard name.hasSuffix(".json"), let data = rootData(folder + "/" + name, max: 20000),
                  let request = try? JSONDecoder().decode(Request.self, from: data), request.owner.uid == owner.uid, request.owner.session == owner.session, request.owner.principal == owner.principal,
                  validatedURL(request.url, origins: origins) != nil else { return nil }
            return request
        }
    }

    // A WARN belongs to the OS login that originated its flow. In particular, a
    // missing audit-token owner must never turn it into a machine-wide notice.
    public struct WarnNotice: Codable, Equatable, Sendable {
        public let owner: DsseAuthOwner
        public let destination: String
        public let service: String
        public let created: Int64
    }

    public static func validatedWarnPayload(_ payload: Data, owner: DsseAuthOwner?) -> WarnNotice? {
        guard let owner, payload.count <= 4096,
              let fields = (try? JSONSerialization.jsonObject(with: payload)) as? [String: String],
              fields.count == 3, fields["message"] != nil,
              let destination = fields["destination"], let service = fields["service"],
              !destination.isEmpty, destination.utf8.count <= 255, service.utf8.count <= 128,
              !destination.unicodeScalars.contains(where: { $0.value < 32 || $0.value == 127 }),
              !service.unicodeScalars.contains(where: { $0.value < 32 || $0.value == 127 }) else { return nil }
        return WarnNotice(owner: owner, destination: destination, service: service,
                          created: Int64(Date().timeIntervalSince1970))
    }

    public static func enqueueWarn(payload: Data, owner: DsseAuthOwner?) -> Bool {
        guard let notice = validatedWarnPayload(payload, owner: owner) else { return false }
        return warnWorkQueue.submit {
            if publishWarn(notice) {
                CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(),
                    CFNotificationName("jp.co.lantern-networks.dsse.warn" as CFString), nil, nil, true)
            }
        }
    }

    private static func warnSessionDirectory(_ owner: DsseAuthOwner) -> String {
        warnDirectory + "/\(owner.uid)-\(owner.session)"
    }

    private static func publishWarn(_ notice: WarnNotice) -> Bool {
        guard geteuid() == 0 else { return false }
        lock.lock(); defer { lock.unlock() }
        guard let baseFD = protectedFD(base, directory: true) else { return false }; close(baseFD)
        if mkdir(warnDirectory, 0o755) != 0 && errno != EEXIST { return false }
        guard let rootFD = protectedFD(warnDirectory, directory: true) else { return false }; close(rootFD)
        let folder = warnSessionDirectory(notice.owner)
        if mkdir(folder, 0o700) != 0 && errno != EEXIST { return false }
        guard let folderFD = protectedFD(folder, directory: true) else { return false }
        defer { close(folderFD) }
        guard grantRead(folderFD, uid: notice.owner.uid, directory: true) else { return false }
        let now = Int64(Date().timeIntervalSince1970)
        var count = 0
        for name in (try? FileManager.default.contentsOfDirectory(atPath: folder)) ?? [] where name.hasSuffix(".json") {
            let path = folder + "/" + name
            if let data = rootData(path, max: 2048),
               let old = try? JSONDecoder().decode(WarnNotice.self, from: data),
               old.created < now - 600 {
                _ = unlink(path)
            } else {
                count += 1
            }
        }
        guard count < 32, let data = try? JSONEncoder().encode(notice), data.count <= 2048 else { return false }
        let path = folder + "/" + UUID().uuidString.lowercased() + ".json"
        let fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
        guard fd >= 0 else { return false }
        defer { close(fd) }
        do { try FileHandle(fileDescriptor: fd, closeOnDealloc: false).write(contentsOf: data) }
        catch { _ = unlink(path); return false }
        guard grantRead(fd, uid: notice.owner.uid, directory: false), fsync(fd) == 0 else {
            _ = unlink(path)
            return false
        }
        return true
    }

    static func warnVisible(_ notice: WarnNotice, to owner: DsseAuthOwner, now: Int64) -> Bool {
        notice.owner.uid == owner.uid && notice.owner.session == owner.session &&
            notice.owner.principal == owner.principal &&
            notice.created <= now + 300 && notice.created >= now - 600
    }

    public static func pendingWarn() -> [WarnNotice] {
        guard let owner = DsseAuthOwner.current(), owner.uid == getuid(),
              let rootFD = protectedFD(warnDirectory, directory: true) else { return [] }
        close(rootFD)
        let folder = warnSessionDirectory(owner)
        guard let fd = protectedFD(folder, directory: true) else { return [] }; close(fd)
        let now = Int64(Date().timeIntervalSince1970)
        return ((try? FileManager.default.contentsOfDirectory(atPath: folder)) ?? []).prefix(32).compactMap { name in
            guard name.hasSuffix(".json"), let data = rootData(folder + "/" + name, max: 2048),
                  let notice = try? JSONDecoder().decode(WarnNotice.self, from: data),
                  warnVisible(notice, to: owner, now: now) else { return nil }
            return notice
        }
    }
}
