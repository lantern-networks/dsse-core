import Foundation

/// Who may turn this device's steering off.
///
/// Turning steering off, or removing it, takes the device out from under its organization's policy. A person
/// logged in without administrator rights could do both with one unprivileged command. Either now needs an
/// administrator: an administrator's authentication in the system's own dialog, or — for the uninstaller and
/// the steering switch, which already run as root — an approval root left on disk moments ago.
///
/// The approval is a file because the command that acts must run as the console user (root is shown an empty
/// Network Extension preference list), so it cannot simply be root. A file only root can create, in a directory
/// only root can write, a few seconds old, says that root asked for exactly this command just now.
public enum DsseAdministratorApproval {
    public static let directory = "/Library/Application Support/Dsse/admin-approval"
    public static let lifetime: TimeInterval = 120

    public struct FileFacts: Equatable, Sendable {
        public let ownerUID: UInt32
        public let mode: UInt16
        public let isRegularFile: Bool
        public let isDirectory: Bool
        public let modified: Date
        public init(ownerUID: UInt32, mode: UInt16, isRegularFile: Bool, isDirectory: Bool, modified: Date) {
            self.ownerUID = ownerUID; self.mode = mode; self.isRegularFile = isRegularFile
            self.isDirectory = isDirectory; self.modified = modified
        }
    }

    public static func path(forCommand command: String) -> String {
        directory + "/" + command.trimmingCharacters(in: CharacterSet(charactersIn: "-"))
    }

    /// True when root approved `command` within the last `lifetime`. `file` and `folder` are what lstat says
    /// about the approval and the directory holding it; nil when either is absent.
    public static func rootApproved(file: FileFacts?, folder: FileFacts?, now: Date) -> Bool {
        guard let file, let folder else { return false }
        guard folder.isDirectory, folder.ownerUID == 0, folder.mode & 0o022 == 0 else { return false }
        guard file.isRegularFile, file.ownerUID == 0, file.mode & 0o022 == 0 else { return false }
        let age = now.timeIntervalSince(file.modified)
        return age >= -5 && age <= lifetime
    }

    public static func facts(atPath path: String) -> FileFacts? {
        var st = stat()
        guard lstat(path, &st) == 0 else { return nil }
        let kind = st.st_mode & S_IFMT
        return FileFacts(ownerUID: st.st_uid, mode: UInt16(st.st_mode & 0o7777),
                         isRegularFile: kind == S_IFREG, isDirectory: kind == S_IFDIR,
                         modified: Date(timeIntervalSince1970: TimeInterval(st.st_mtimespec.tv_sec)))
    }

    public static func rootApproved(command: String, now: Date = Date()) -> Bool {
        rootApproved(file: facts(atPath: path(forCommand: command)), folder: facts(atPath: directory), now: now)
    }
}
