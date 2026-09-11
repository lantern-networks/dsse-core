import Foundation

/// Who may manage this device's transparent-proxy configuration.
///
/// ★★★ MEASURED ON A REAL MAC, 2026-08-29 18:48. The shipped uninstaller runs
/// `/Applications/<app>.app/Contents/MacOS/<app> --uninstall` as root, because it must be root to delete the
/// app and boot out the daemon. Run as root, `NETransparentProxyManager.loadAllFromPreferences` returns an
/// EMPTY set — the configuration belongs to the console user's preference scope — so the app logged
///
///     no managed Dsse transparent proxy configuration present; nothing to disable
///     disable completed error=none
///
/// and reported success. The identical code path serves `--uninstall`, where "nothing to remove" is followed
/// by deactivating the extension and deleting the app. That is precisely the state the uninstaller's own
/// header warns is unrecoverable: a transparent proxy configuration that captures traffic, whose provider can
/// never load, and whose only remover has just been deleted. The same machine, run as the console user,
/// found the configuration immediately and stopped it (`disabled and saved`), and the network came back.
///
/// So the rule is not "prefer the console user". An empty answer to root is INDISTINGUISHABLE from an absent
/// configuration, and a caller that acts on it destroys the machine. Refuse instead.
public enum DsseNetworkConfigurationScope {
    /// Non-nil when this process may not be trusted to answer "is there a configuration?" — with the message
    /// an operator needs. `command` is the flag being served, so the refusal can print the right command.
    public static func refusalWhenNotTheConsoleUser(effectiveUID: uid_t, command: String,
                                                    appExecutablePath: String,
                                                    consoleUID: uid_t?) -> String? {
        guard effectiveUID == 0 else { return nil }
        let asUser: String
        if let consoleUID, consoleUID != 0 {
            asUser = "launchctl asuser \(consoleUID) sudo -u '#\(consoleUID)' \"\(appExecutablePath)\" \(command)"
        } else {
            asUser = "log in as the console user and run: \"\(appExecutablePath)\" \(command)"
        }
        return "\(command) REFUSED: this process is root, and the transparent-proxy configuration lives in the "
            + "console user's Network Extension preferences. Root is shown an EMPTY list, which is "
            + "indistinguishable from having no configuration at all — acting on that answer deactivates the "
            + "extension and deletes the app while the configuration stays behind, capturing traffic with no "
            + "provider to carry it and nothing left that can remove it. Run it as the console user:\n  "
            + asUser
    }

    /// The console user's uid, or nil when nobody is logged in at the window server.
    public static func consoleUID(statOwnerOfDevConsole owner: uid_t?) -> uid_t? {
        guard let owner, owner != 0 else { return nil }
        return owner
    }
}
