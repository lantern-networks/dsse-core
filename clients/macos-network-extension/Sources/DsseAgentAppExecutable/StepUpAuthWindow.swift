import AppKit
import Foundation
import OSLog
import WebKit

private let stepUpWindowLogger = Logger(subsystem: "jp.co.lantern-networks.dsse.agent", category: "stepup-window")
private func DsseAuthWindowLog(_ message: String) { stepUpWindowLogger.notice("\(message, privacy: .public)") }

// StepUpAuthWindow is the Lantern DSSE-branded, app-owned OOB authentication window for the East-West step-up
// ceremony (task #7 UX iteration). It replaces the "surprise browser tab": instead of handing the portal URL to
// the system browser, the resident agent opens THIS window — a WKWebView hosting the REAL IdP login page (the
// Edge clientless broker → the tenant IdP). The credentials / passkey are entered on the genuine IdP origin
// (the window is only the container), which is what keeps the flow phishing-resistant — the client never sees or
// posts the user's secret. The window auto-closes when the ceremony reaches the Edge "Access approved" callback
// page; the held connection then auto-releases on the Edge (task #5), so no client re-run is needed.
//
// Passkey nuance (phishing_resistant / acr=phishing_resistant): a PLATFORM passkey (Touch ID) inside a WKWebView
// requires the app to carry an `associated-domains` entitlement (`webcredentials:<RP>`) authorized by the
// provisioning profile + an apple-app-site-association served by the RP host. Until that is provisioned, this
// window still hosts the IdP fine for the PASSWORD ceremony (no entitlement needed); the passkey leg is the
// separately-gated follow-up.
final class StepUpAuthWindow: NSObject, WKNavigationDelegate, NSWindowDelegate, @unchecked Sendable {
    static let shared = StepUpAuthWindow()

    private var window: NSWindow?
    private var webView: WKWebView?
    private let statusLabel = NSTextField(labelWithString: "")
    private var completed = false

    // ★★★ THIS USED TO BE A LIST OF HOSTNAMES, AND IT SHIPPED (2026-09-03).
    //
    //     private let labTrustedHosts: Set<String> = ["203.0.113.10", "kc.dsse.lab"]
    //
    // For those two hosts the challenge handler returned .useCredential with whatever certificate was
    // presented — no verification of any kind. It was written as "lab-only, tightly scoped", and it was
    // compiled into the signed product: 203.0.113.10 is a private address common enough that somebody will
    // eventually run something there, and a bypass keyed on a hostname trusts whoever answers to it.
    //
    // The deployment knows which authority serves its own step-up portal, and says so in the profile. This
    // reads that one certificate and evaluates the server trust AGAINST IT — a real evaluation, not an
    // acceptance — and only for the host the portal is on. Everything else keeps default handling, so a
    // publicly-trusted portal (the production case, where the operator supplied the certificate) needs
    // nothing here at all.
    private lazy var portalAnchor: SecCertificate? = Self.loadPortalAnchor()
    private var portalHost: String?

    // present opens (or re-uses) the branded window and loads the portal URL. Main-thread only.
    func present(url: URL) {
        DispatchQueue.main.async { self.show(url: url) }
    }

    // loadPortalAnchor reads the authority this deployment named for its own step-up portal, from the profile
    // the agent applied. Absent means the portal is on something the system already trusts — the production
    // case, where the operator supplied the certificate — and then there is nothing for this window to add.
    private static func loadPortalAnchor() -> SecCertificate? {
        let path = "/Library/Application Support/Dsse/install_profile.json"
        guard let data = FileManager.default.contents(atPath: path),
              let envelope = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let b64 = envelope["payload_b64"] as? String,
              let payload = Data(base64Encoded: b64),
              let body = try? JSONSerialization.jsonObject(with: payload) as? [String: Any],
              let deployment = body["deployment"] as? [String: Any],
              let pem = deployment["step_up_portal_anchor_pem"] as? String,
              !pem.isEmpty else { return nil }
        // One certificate, PEM. Take the first block and nothing else: a file with two in it is a question
        // this window should not be answering by picking one.
        let lines = pem.split(separator: "\n", omittingEmptySubsequences: true)
        var b64Body = ""
        var inside = false
        for line in lines {
            if line.hasPrefix("-----BEGIN") { inside = true; continue }
            if line.hasPrefix("-----END") { break }
            if inside { b64Body += line.trimmingCharacters(in: .whitespaces) }
        }
        guard let der = Data(base64Encoded: b64Body),
              let cert = SecCertificateCreateWithData(nil, der as CFData) else { return nil }
        DsseAuthWindowLog("stepup: this deployment names an authority for its step-up portal; it is the only " +
                          "one this window will accept for the portal's host")
        return cert
    }

    private func show(url: URL) {
        completed = false
        // The host the portal is on, recorded from the URL the Edge issued — so the anchor above is used for
        // that host and for nothing else.
        portalHost = url.host
        if window == nil { buildWindow() }
        let dest = Self.destination(from: url)
        statusLabel.stringValue = "接続先 \(dest) を認証しています…"
        webView?.load(URLRequest(url: url))
        NSApp.activate(ignoringOtherApps: true)
        window?.makeKeyAndOrderFront(nil)
        DsseAuthWindowLog("stepup-window: presenting OOB auth window for dest=\(dest)")
    }

    // brandMark loads the symbol the packaging placed in the bundle. nil when there is no bundle resource —
    // a development `swift run`, or a build whose icon step did not produce one.
    //
    // ★ isValid IS CHECKED, because NSImage(contentsOf:) returns an object for a file it could not decode and
    // that object draws nothing. This deployment has already shipped a brand PNG with no opaque pixels in it;
    // an undrawable image and a missing one must reach the same branch here, and whether the FILE is sound is
    // settled where it is built — see verify_macos_ne_packaging.sh.
    private static func brandMark() -> NSImage? {
        guard let url = Bundle.main.url(forResource: "lantern-symbol", withExtension: "png"),
              let image = NSImage(contentsOf: url), image.isValid, image.size.width > 0 else {
            return nil
        }
        return image
    }

    private func buildWindow() {
        let width: CGFloat = 540, height: CGFloat = 760
        let headerH: CGFloat = 60, footerH: CGFloat = 30
        let win = NSWindow(contentRect: NSRect(x: 0, y: 0, width: width, height: height),
                           styleMask: [.titled, .closable, .miniaturizable],
                           backing: .buffered, defer: false)
        win.title = "Lantern DSSE 認証"
        win.isReleasedWhenClosed = false
        win.delegate = self
        win.center()

        let content = win.contentView!
        content.autoresizesSubviews = true

        // Brand header (dark bar + mark + wordmark).
        let header = NSView(frame: NSRect(x: 0, y: height - headerH, width: width, height: headerH))
        header.autoresizingMask = [.width, .minYMargin]
        header.wantsLayer = true
        header.layer?.backgroundColor = NSColor(calibratedRed: 0.043, green: 0.078, blue: 0.145, alpha: 1).cgColor

        // ★★★ THE MARK, BECAUSE THIS IS THE WINDOW WHERE A PASSWORD IS TYPED (2026-09-07, after Windows put
        // the same one in the same place). A window with no standing on it is indistinguishable from a window
        // somebody else drew, and this one loads a third party's sign-in page into a WKWebView — so before
        // the page arrives, the header is the only thing that says whose window this is.
        //
        // ★ IT IS THE FILE, NOT A DRAWING OF IT. clients/macos-network-extension/brand/lantern-symbol.png is
        // byte-for-byte the one the Windows window carries, copied into Contents/Resources by
        // build_macos_ne_app.sh, so the two windows show the same mark rather than two renderings of it.
        //
        // ★★ AND ITS ABSENCE IS NOT A CRASH AND NOT AN EMPTY BOX. `swift run` has no bundle at all, and a
        // build that failed to produce the icon should still give a usable window: no mark, the wordmark
        // moves back to where it always was, and the ceremony proceeds. brandMarkX is the one number both
        // layouts read, so the two cannot drift apart.
        let mark = Self.brandMark()
        let markSide: CGFloat = 28
        let brandMarkX: CGFloat = mark == nil ? 20 : 20 + markSide + 10
        if let mark {
            let view = NSImageView(frame: NSRect(x: 20, y: (headerH - markSide) / 2, width: markSide, height: markSide))
            view.image = mark
            view.imageScaling = .scaleProportionallyUpOrDown
            // Decorative: the wordmark beside it already carries the name, and a screen reader announcing the
            // logo twice is noise in a window somebody is trying to authenticate in.
            view.setAccessibilityElement(false)
            header.addSubview(view)
        }

        let wordmark = NSTextField(labelWithString: "Lantern DSSE")
        wordmark.font = .systemFont(ofSize: 17, weight: .bold)
        wordmark.textColor = .white
        wordmark.frame = NSRect(x: brandMarkX, y: (headerH - 22) / 2 + 6, width: width - brandMarkX - 20, height: 22)
        wordmark.autoresizingMask = [.width]
        let tagline = NSTextField(labelWithString: "セキュア認証")
        tagline.font = .systemFont(ofSize: 11, weight: .regular)
        tagline.textColor = NSColor(white: 1, alpha: 0.6)
        tagline.frame = NSRect(x: brandMarkX, y: (headerH - 22) / 2 - 8, width: width - brandMarkX - 20, height: 14)
        tagline.autoresizingMask = [.width]
        header.addSubview(wordmark)
        header.addSubview(tagline)

        // Web view (real IdP login) fills the middle.
        let wv = WKWebView(frame: NSRect(x: 0, y: footerH, width: width, height: height - headerH - footerH),
                           configuration: WKWebViewConfiguration())
        wv.autoresizingMask = [.width, .height]
        wv.navigationDelegate = self
        self.webView = wv

        // Status footer.
        statusLabel.frame = NSRect(x: 16, y: 6, width: width - 32, height: 18)
        statusLabel.autoresizingMask = [.width]
        statusLabel.font = .systemFont(ofSize: 11)
        statusLabel.textColor = .secondaryLabelColor
        statusLabel.lineBreakMode = .byTruncatingTail

        content.addSubview(wv)
        content.addSubview(header)
        content.addSubview(statusLabel)
        self.window = win
    }

    // MARK: - WKNavigationDelegate

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        // The ceremony lands on /clientless/auth/callback; success renders the branded "Access approved" page.
        guard let u = webView.url, u.path.contains("/clientless/auth/callback"), !completed else { return }
        // NOTE: webView.title lags didFinish — the property updates via async KVO and at didFinish still holds the
        // PREVIOUS page's title (the IdP page), so reading it here misclassifies a successful ceremony as failed.
        // Read the LIVE document.title from the DOM via JS and poll briefly to ride out the lag.
        evaluateCeremonyOutcome(retriesLeft: 10)
    }

    // evaluateCeremonyOutcome polls the live document.title (approved / denied) after the callback page loads.
    private func evaluateCeremonyOutcome(retriesLeft: Int) {
        webView?.evaluateJavaScript("document.title") { [weak self] result, _ in
            guard let self = self, !self.completed else { return }
            let title = (result as? String) ?? ""
            if title.contains("Access approved") || title.contains("承認") {
                self.completed = true
                self.statusLabel.stringValue = "認証に成功しました — 接続を再開しています"
                DsseAuthWindowLog("stepup-window: ceremony approved; auto-closing")
                DispatchQueue.main.asyncAfter(deadline: .now() + 2.0) { [weak self] in self?.dismiss() }
            } else if title.contains("Access denied") || title.contains("拒否") {
                self.statusLabel.stringValue = "アクセスが拒否されました。要件をご確認ください。"
                DsseAuthWindowLog("stepup-window: ceremony denied (title=\(title))")
            } else if retriesLeft > 0 {
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) { [weak self] in
                    self?.evaluateCeremonyOutcome(retriesLeft: retriesLeft - 1)
                }
            } else {
                self.statusLabel.stringValue = "認証を完了できませんでした。内容をご確認ください。"
                DsseAuthWindowLog("stepup-window: callback reached but outcome undetermined (title=\(title))")
            }
        }
    }

    func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
        statusLabel.stringValue = "読み込みに失敗しました: \(error.localizedDescription)"
        DsseAuthWindowLog("stepup-window: navigation failed: \(error.localizedDescription)")
    }

    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
        statusLabel.stringValue = "接続できませんでした: \(error.localizedDescription)"
        DsseAuthWindowLog("stepup-window: provisional navigation failed: \(error.localizedDescription)")
    }

    func webView(_ webView: WKWebView, didReceive challenge: URLAuthenticationChallenge,
                 completionHandler: @escaping @MainActor @Sendable (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let trust = challenge.protectionSpace.serverTrust,
              let anchor = portalAnchor,
              let host = portalHost,
              challenge.protectionSpace.host == host else {
            completionHandler(.performDefaultHandling, nil)
            return
        }
        // Evaluate, do not accept. The anchor is the only one allowed for this host, and a certificate that
        // does not chain to it is refused exactly as the system would refuse it.
        SecTrustSetAnchorCertificates(trust, [anchor] as CFArray)
        SecTrustSetAnchorCertificatesOnly(trust, true)
        var error: CFError?
        if SecTrustEvaluateWithError(trust, &error) {
            DsseAuthWindowLog("stepup: portal certificate verified against the authority the profile names")
            completionHandler(.useCredential, URLCredential(trust: trust))
            return
        }
        DsseAuthWindowLog("stepup: the portal's certificate does not chain to the authority this deployment " +
                          "named for it — refusing: \(String(describing: error))")
        completionHandler(.cancelAuthenticationChallenge, nil)
    }

    // MARK: - NSWindowDelegate

    func windowWillClose(_ notification: Notification) {
        // Stop any in-flight load / clear the IdP page when the operator closes the window manually.
        webView?.stopLoading()
    }

    private func dismiss() {
        window?.orderOut(nil)
        webView?.load(URLRequest(url: URL(string: "about:blank")!))
    }

    // The portal URL carries the real destination in return_to (url.host is the Edge, not the internal hop).
    private static func destination(from url: URL) -> String {
        if let comps = URLComponents(url: url, resolvingAgainstBaseURL: false),
           let rt = comps.queryItems?.first(where: { $0.name == "return_to" })?.value, !rt.isEmpty {
            return rt
        }
        return url.host ?? "内部リソース"
    }
}
