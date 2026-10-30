import DsseAppProxyProviderSkeleton
import AppKit
import Foundation
import OSLog
import UserNotifications

private let stepUpUILogger = Logger(subsystem: "jp.co.lantern-networks.dsse.agent", category: "stepup-ui")
private func DsseAgentLog(_ message: String) { stepUpUILogger.notice("\(message, privacy: .public)") }

// Native status and notification surface for external-browser authentication.
// Only validated, session-bound requests reach this controller. Browser launch
// is never interpreted as authentication success.
final class StepUpStatusController: NSObject, UNUserNotificationCenterDelegate, @unchecked Sendable {
    static let shared = StepUpStatusController()

    private var statusItem: NSStatusItem?
    private let statusLine = NSMenuItem(title: "アクセス: 待機中", action: nil, keyEquivalent: "")
    private let openItem = NSMenuItem(title: "ブラウザで認証する", action: #selector(openPortal), keyEquivalent: "")
    private var pendingURL: URL?
    private var openedRequests: [String: Date] = [:]
    private var requests: [String: URL] = [:]
    private var requestUptimes: [String: TimeInterval] = [:]
    private var completedResults: [String: Date] = [:]
    private var browserLaunchQueue = DsseAuthBrowserLaunchQueue()
    private var browserLaunchTimer: Timer?
    private var expiryTimer: Timer?
    private let requestsMenu = NSMenu()

    private var notificationsAuthorized = false
    private let categoryID = "dsse.stepup"
    private let actionID = "dsse.stepup.open"
    private let idleSymbol = "lock.shield"
    private let armedSymbol = "lock.shield.fill"

    // install builds the menu-bar item and requests notification authorization. Must run on the main thread.
    @MainActor func install() {
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
        let waiting = NSMenuItem(title: "認証要求一覧", action: nil, keyEquivalent: "")
        waiting.submenu = requestsMenu
        menu.addItem(waiting)
        menu.addItem(.separator())
        menu.addItem(NSMenuItem(title: "Lantern DSSE エージェントを終了", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q"))
        item.menu = menu
        statusItem = item

        expiryTimer?.invalidate()
        expiryTimer = Timer.scheduledTimer(withTimeInterval: 15, repeats: true) { [weak self] _ in
            DispatchQueue.main.async { self?.expireRequests() }
        }
        browserLaunchTimer?.invalidate()
        browserLaunchTimer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in
            DispatchQueue.main.async { self?.openNextAutomaticPortal() }
        }

        let center = UNUserNotificationCenter.current()
        center.delegate = self
        let open = UNNotificationAction(identifier: actionID, title: "認証して接続", options: [.foreground])
        center.setNotificationCategories([UNNotificationCategory(identifier: categoryID, actions: [open], intentIdentifiers: [], options: [])])
        center.requestAuthorization(options: [.alert, .sound]) { granted, _ in
            DispatchQueue.main.async { self.notificationsAuthorized = granted }
        }
    }

    // Open each distinct live request once, spacing bursts by two seconds.
    // A previous login must not silently suppress a new revocation challenge.
    func presentStepUp(url: URL) {
        DispatchQueue.main.async {
            DsseAgentLog("auth_handoff_received")
            self.expireRequests()
            let uptime = ProcessInfo.processInfo.systemUptime
            guard DsseAuthHandoff.validatedStartURL(url.absoluteString, origins: DsseAuthHandoff.trustedOrigins(), observedUptime: uptime, uptime: uptime) != nil else { return }
            let now = Date()
            self.openedRequests = self.openedRequests.filter { now.timeIntervalSince($0.value) < 120 }
            self.completedResults = self.completedResults.filter { now.timeIntervalSince($0.value) < 900 }
            let id = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems?.first(where: { $0.name == "request_id" })?.value ?? ""
            guard !id.isEmpty, self.completedResults[id] == nil, self.openedRequests[id] == nil, self.openedRequests.count < 32 else { return }
            self.openedRequests[id] = now
            self.requests = self.requests.filter { self.openedRequests[$0.key] != nil }
            self.requests[id] = url
            self.requestUptimes[id] = uptime
            _ = self.browserLaunchQueue.enqueue(id: id, uptime: uptime)
            self.refreshRequestsMenu()
            if self.pendingURL == nil { self.pendingURL = url }
            let dest = Self.destination(from: url)
            self.statusLine.title = "認証が必要: \(dest)"
            self.openItem.isEnabled = true
            self.setSymbol(self.armedSymbol)

            let content = UNMutableNotificationContent()
            content.title = "Lantern DSSE — 認証が必要です"
            content.body = "\(dest) へ接続するには認証してください"
            content.categoryIdentifier = self.categoryID
            content.sound = .default
            content.userInfo = ["request_id": id]
            UNUserNotificationCenter.current().add(
                UNNotificationRequest(identifier: "dsse.stepup", content: content, trigger: nil))

            self.openNextAutomaticPortal()
        }
    }

    // A result is delivered by the authenticated mux after this flow's current
    // policy check. It never comes from the browser and reveals no IdP identity.
    func presentAuthResult(id: String, result: String) {
        DispatchQueue.main.async {
            let now = Date()
            self.completedResults = self.completedResults.filter { now.timeIntervalSince($0.value) < 900 }
            guard (result == "resumed" || result == "not_resumed"),
                  self.completedResults[id] == nil else { return }
            self.completedResults[id] = now
            self.browserLaunchQueue.remove(id: id)
            self.requests.removeValue(forKey: id)
            self.requestUptimes.removeValue(forKey: id)
            self.openedRequests.removeValue(forKey: id)
            if let pending = self.pendingURL,
               URLComponents(url: pending, resolvingAgainstBaseURL: false)?.queryItems?.first(where: { $0.name == "request_id" })?.value == id {
                self.pendingURL = nil
            }
            if self.pendingURL == nil { self.pendingURL = self.requests.sorted(by: { $0.key < $1.key }).first?.value }
            self.refreshRequestsMenu()
            self.openItem.isEnabled = self.pendingURL != nil
            self.statusLine.title = result == "resumed" ? "通信を再開しました" : "通信を再開できませんでした。元のアプリから再接続してください"
            self.setSymbol(result == "resumed" ? self.idleSymbol : self.armedSymbol)
            let content = UNMutableNotificationContent()
            content.title = result == "resumed" ? "Lantern DSSE — 通信を再開しました" : "Lantern DSSE — 接続を再試行してください"
            content.body = result == "resumed" ? "認証後の確認が完了しました。" : "この通信は再開されませんでした。元のアプリからもう一度接続してください。"
            UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: "dsse.stepup.result." + id, content: content, trigger: nil))
        }
    }

    @MainActor private func refreshRequestsMenu() {
        requestsMenu.removeAllItems()
        for (requestID, requestURL) in requests.sorted(by: { $0.key < $1.key }) {
            let item = NSMenuItem(title: Self.destination(from: requestURL), action: #selector(openSelectedPortal(_:)), keyEquivalent: "")
            item.target = self
            item.representedObject = requestID
            requestsMenu.addItem(item)
        }
    }

    @MainActor private func openNextAutomaticPortal() {
        guard let id = browserLaunchQueue.next(uptime: ProcessInfo.processInfo.systemUptime),
              let url = requests[id] else { return }
        pendingURL = url
        openPortal() // Revalidates origin, signature, session and original expiry.
    }

    @MainActor private func expireRequests() {
        let origins = DsseAuthHandoff.trustedOrigins()
        let uptime = ProcessInfo.processInfo.systemUptime
        let before = requests.count
        let previousIDs = Set(requests.keys)
        requests = requests.filter { id, url in
            guard let observedUptime = requestUptimes[id] else { return false }
            return DsseAuthHandoff.validatedStartURL(url.absoluteString, origins: origins,
                                                     observedUptime: observedUptime, uptime: uptime) != nil
        }
        guard requests.count != before else { return }
        for id in previousIDs.subtracting(requests.keys) { browserLaunchQueue.remove(id: id) }
        requestUptimes = requestUptimes.filter { requests[$0.key] != nil }
        openedRequests = openedRequests.filter { requests[$0.key] != nil }
        if let pendingURL,
           let id = URLComponents(url: pendingURL, resolvingAgainstBaseURL: false)?.queryItems?.first(where: { $0.name == "request_id" })?.value,
           requests[id] == nil {
            self.pendingURL = nil
        }
        if pendingURL == nil { pendingURL = requests.sorted(by: { $0.key < $1.key }).first?.value }
        openItem.isEnabled = pendingURL != nil
        refreshRequestsMenu()
        if requests.isEmpty {
            statusLine.title = "認証要求の期限が切れました。元のアプリから再接続してください"
            setSymbol(armedSymbol)
        }
    }

    @MainActor @objc private func openSelectedPortal(_ sender: NSMenuItem) {
        guard let id = sender.representedObject as? String, let url = requests[id] else { return }
        pendingURL = url
        openPortal()
    }

    // announcedWarnResources coalesces Warn-stage notices so the same internal resource is not re-announced over
    // and over in one agent session (the user asked not to be nagged). Main-thread-confined (presentWarnNotice
    // dispatches to main), so it needs no lock. Keyed by "service|destination".
    private var announcedWarnResources: Set<String> = []

    // presentWarnNotice surfaces a PASSIVE "this internal connection is monitored; authentication will soon be
    // required" banner for a Warn-staged East-West hop (S3, learning lifecycle). It is informational only — no
    // action button, no sound, nothing opened or held (the flow was already allowed). Announced at most once per
    // resource per session. The caller has already read a protected, session-bound handoff record.
    func presentWarnNotice(destination: String, service: String) {
        DispatchQueue.main.async {
            let key = service + "|" + destination
            if self.announcedWarnResources.contains(key) { return } // already announced this session — don't nag
            self.announcedWarnResources.insert(key)

            let where_ = service.isEmpty ? destination : "\(destination) (\(service))"
            let content = UNMutableNotificationContent()
            content.title = "Lantern DSSE — このアクセスは監視されています"
            content.body = "\(where_) への接続は監視されています。まもなく認証が必要になります。"
            // Passive: no category/action and no sound — a quiet heads-up, never an interruption or a hold.
            UNUserNotificationCenter.current().add(
                UNNotificationRequest(identifier: "dsse.warn." + key, content: content, trigger: nil))
            DsseAgentLog("warn: announced monitored notice")
        }
    }

    @MainActor @objc private func openPortal() {
        guard let url = pendingURL else { return }
        let id = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems?.first(where: { $0.name == "request_id" })?.value ?? ""
        guard let observedUptime = requestUptimes[id],
              DsseAuthHandoff.validatedStartURL(url.absoluteString, origins: DsseAuthHandoff.trustedOrigins(),
                                                observedUptime: observedUptime) != nil else {
            expireRequests()
            statusLine.title = pendingURL == nil
                ? "認証要求の期限が切れました。元のアプリから再接続してください"
                : "認証要求の期限が切れました。別の要求を選んでください"
            return
        }
        browserLaunchQueue.markAttempted(id: id, uptime: ProcessInfo.processInfo.systemUptime)
        if NSWorkspace.shared.open(url) {
            DsseAgentLog("auth_browser_open_succeeded")
            statusLine.title = "認証中: ブラウザで完了してください"
        } else {
            DsseAgentLog("auth_browser_open_failed")
            statusLine.title = "ブラウザを開けませんでした。再試行してください"
        }
        // Opening a browser is not proof of authentication. Keep the manual retry
        // available and never mark the connection successful based on a timer.
        openItem.isEnabled = true
    }

    @MainActor private func setSymbol(_ name: String) {
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
        let id = response.notification.request.content.userInfo["request_id"] as? String
        DispatchQueue.main.async {
            guard let id, let url = self.requests[id] else { return }
            self.pendingURL = url
            self.openPortal()
        }
        completionHandler()
    }
}
