import AppKit
import Foundation
import OSLog
import UserNotifications

private let stepUpUILogger = Logger(subsystem: "jp.co.lantern-networks.dsse.agent", category: "stepup-ui")
private func DsseAgentLog(_ message: String) { stepUpUILogger.notice("\(message, privacy: .public)") }

// StepUpStatusController owns the menu-bar status item + the native notification for the OOB East-West step-up
// ceremony (task #7). It replaces the "surprise browser tab": the NE provider (root, no window server) fires a
// Darwin notification when an internal hop is held for authentication; instead of the agent SILENTLY opening a
// browser, it now surfaces a native macOS notification ("Authentication required for <dest>") and a menu-bar
// indicator, and opens the Edge step-up portal only when the user clicks either. The menu-bar item is ALWAYS
// present (accessory app = no dock icon), so there is a reliable entry point even if notification permission is
// denied — and if it is denied we fall back to auto-open so the ceremony never strands.
final class StepUpStatusController: NSObject, UNUserNotificationCenterDelegate, @unchecked Sendable {
    static let shared = StepUpStatusController()

    private var statusItem: NSStatusItem?
    private let statusLine = NSMenuItem(title: "アクセス: 待機中", action: nil, keyEquivalent: "")
    private let openItem = NSMenuItem(title: "認証ウィンドウを開く", action: #selector(openPortal), keyEquivalent: "")
    private var pendingURL: URL?
    private var notificationsAuthorized = false
    private let categoryID = "dsse.stepup"
    private let actionID = "dsse.stepup.open"
    private let idleSymbol = "lock.shield"
    private let armedSymbol = "lock.shield.fill"

    // install builds the menu-bar item and requests notification authorization. Must run on the main thread.
    func install() {
        let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        if let button = item.button {
            button.image = NSImage(systemSymbolName: idleSymbol, accessibilityDescription: "Lantern DSSE")
            button.image?.isTemplate = true
        }
        let menu = NSMenu()
        statusLine.isEnabled = false
        menu.addItem(statusLine)
        menu.addItem(.separator())
        openItem.target = self
        openItem.isEnabled = false
        menu.addItem(openItem)
        menu.addItem(.separator())
        menu.addItem(NSMenuItem(title: "Lantern DSSE エージェントを終了", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q"))
        item.menu = menu
        statusItem = item

        let center = UNUserNotificationCenter.current()
        center.delegate = self
        let open = UNNotificationAction(identifier: actionID, title: "認証して接続", options: [.foreground])
        center.setNotificationCategories([UNNotificationCategory(identifier: categoryID, actions: [open], intentIdentifiers: [], options: [])])
        center.requestAuthorization(options: [.alert, .sound]) { granted, _ in
            DispatchQueue.main.async { self.notificationsAuthorized = granted }
        }
    }

    // presentStepUp is called from the step-up Darwin observer. It surfaces the notification + menu-bar indicator
    // and does NOT auto-open — unless notifications are unauthorized, in which case it opens the portal so the
    // ceremony is never stuck behind an invisible prompt.
    func presentStepUp(url: URL) {
        DispatchQueue.main.async {
            self.pendingURL = url
            let dest = Self.destination(from: url)
            self.statusLine.title = "認証が必要: \(dest)"
            self.openItem.isEnabled = true
            self.setSymbol(self.armedSymbol)

            let content = UNMutableNotificationContent()
            content.title = "Lantern DSSE — 認証が必要です"
            content.body = "\(dest) へ接続するには認証してください"
            content.categoryIdentifier = self.categoryID
            content.sound = .default
            UNUserNotificationCenter.current().add(
                UNNotificationRequest(identifier: "dsse.stepup", content: content, trigger: nil))

            if !self.notificationsAuthorized {
                DsseAgentLog("stepup: notifications not authorized — falling back to auto-open")
                self.openPortal()
            }
        }
    }

    // announcedWarnResources coalesces Warn-stage notices so the same internal resource is not re-announced over
    // and over in one agent session (the user asked not to be nagged). Main-thread-confined (presentWarnNotice
    // dispatches to main), so it needs no lock. Keyed by "service|destination".
    private var announcedWarnResources: Set<String> = []

    // presentWarnNotice surfaces a PASSIVE "this internal connection is monitored; authentication will soon be
    // required" banner for a Warn-staged East-West hop (S3, learning lifecycle). It is informational only — no
    // action button, no sound, nothing opened or held (the flow was already allowed). Announced at most once per
    // resource per session. json is the Edge WARN payload {message, destination, service}.
    func presentWarnNotice(json: String) {
        DispatchQueue.main.async {
            guard let data = json.data(using: .utf8),
                  let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: String] else { return }
            let dest = obj["destination"] ?? "内部リソース"
            let service = obj["service"] ?? ""
            let key = service + "|" + dest
            if self.announcedWarnResources.contains(key) { return } // already announced this session — don't nag
            self.announcedWarnResources.insert(key)

            let where_ = service.isEmpty ? dest : "\(dest) (\(service))"
            let content = UNMutableNotificationContent()
            content.title = "Lantern DSSE — このアクセスは監視されています"
            content.body = "\(where_) への接続は監視されています。まもなく認証が必要になります。"
            // Passive: no category/action and no sound — a quiet heads-up, never an interruption or a hold.
            UNUserNotificationCenter.current().add(
                UNNotificationRequest(identifier: "dsse.warn." + key, content: content, trigger: nil))
            DsseAgentLog("warn: announced monitored notice for \(key)")
        }
    }

    @objc private func openPortal() {
        guard let url = pendingURL else { return }
        DsseAgentLog("stepup: opening branded OOB auth window for host=\(Self.destination(from: url))")
        // Task #7 UX: open the Lantern DSSE-branded app-owned window (WKWebView hosting the real IdP) instead of
        // handing the URL to the system browser (the old "surprise browser tab").
        StepUpAuthWindow.shared.present(url: url)
        statusLine.title = "アクセス: 認証中…"
        openItem.isEnabled = false
        // Revert the indicator after the Edge park window; a fresh step-up re-arms it.
        DispatchQueue.main.asyncAfter(deadline: .now() + 10) {
            if !self.openItem.isEnabled {
                self.setSymbol(self.idleSymbol)
                self.statusLine.title = "アクセス: 待機中"
            }
        }
    }

    private func setSymbol(_ name: String) {
        statusItem?.button?.image = NSImage(systemSymbolName: name, accessibilityDescription: "Lantern DSSE")
        statusItem?.button?.image?.isTemplate = true
    }

    // The portal URL carries the real destination in return_to (url.host is the Edge, not the internal hop).
    private static func destination(from url: URL) -> String {
        if let comps = URLComponents(url: url, resolvingAgainstBaseURL: false),
           let rt = comps.queryItems?.first(where: { $0.name == "return_to" })?.value, !rt.isEmpty {
            return rt
        }
        return url.host ?? "internal resource"
    }

    // Show the banner even when the agent is frontmost.
    func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification,
                                withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) {
        completionHandler([.banner, .sound])
    }

    // A tap (default action) or the explicit "Verify & connect" action opens the portal.
    func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse,
                                withCompletionHandler completionHandler: @escaping () -> Void) {
        DispatchQueue.main.async { self.openPortal() }
        completionHandler()
    }
}
