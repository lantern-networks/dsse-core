import AppKit
import DsseAppProxyProviderSkeleton
import DsseNetworkExtensionContract
import Foundation
@preconcurrency import NetworkExtension
import OSLog
import SystemExtensions

// --version answers the INSTALLER's question: what version does the bundle I have just laid down install?
//
// ★ It exists so that ONE function produces both strings. The installer stashes the rollback package under
// this value and the updater later looks material up under the version the LIVE extension recorded — and both
// come from DsseDeviceHeartbeat.agentVersion(). Two shell expressions reading CFBundleShortVersionString and
// CFBundleVersion in a postinstall script would agree until the day the composition changed, and the symptom
// would be ErrNoMaterial on every device forever: an updater refusing every update while looking correct, on a
// fleet where all the code is present and running.
//
// ★ FIRST, before any other top-level statement. Running the raw binary once crashed here
// (`bundleProxyForCurrentProcess is nil`) because AppKit-touching initializers ran before the check — the
// same trap the Windows agent's --version avoids by sitting immediately after flag.Parse(), ahead of the log
// redirect and the posture banner. A --version that can fail for reasons unrelated to the version is one the
// installer's stash step inherits, and the stash failing silently is a device that refuses every update.
//
// It is deliberately NOT the updater's source of truth. Running the installed binary reports the ON-DISK
// version, which is the right answer for the installer and the wrong one for the gate — they differ on exactly
// the machine the distinction was drawn for, a system extension whose replacement lands on the next
// activation. The gate reads what the running extension wrote; see DsseRuntimeMarker.
if CommandLine.arguments.contains("--version") {
    print(DsseDeviceHeartbeat.agentVersion())
    exit(0)
}


// The system extension's bundle id is the container app's bundle id with the
// ".networkextension" suffix. Deriving it at runtime — instead of hardcoding —
// keeps this OSS-sanitized source (example.dsse.agent) and any downstream build
// with a different container id (e.g. a privately-branded distribution) both
// correct WITHOUT a build-time string substitution. The activation request target
// then always matches the embedded extension's actual Info.plist bundle id, so a
// container/extension id mismatch can no longer silently fail activation (which
// otherwise leaves the proxy unstarted and all traffic un-steered).
private func dsseResolveSystemExtensionBundleID() -> String {
    let fallback = "example.dsse.agent.networkextension"
    guard let containerBundleID = Bundle.main.bundleIdentifier, !containerBundleID.isEmpty else {
        return fallback
    }
    return "\(containerBundleID).networkextension"
}

private let dsseSystemExtensionBundleID = dsseResolveSystemExtensionBundleID()
private let dsseAgentConfigPath = "/Library/Application Support/Dsse/agent_config.json"
private let dsseTransparentProxyManagerDescription = "Dsse Transparent Proxy"
private let activationDiagnosticHoldSeconds = 15
private let runtimeGateRestartPollSeconds = 1
private let runtimeGateRestartMaxPolls = 8
private let activationLogger = Logger(
    subsystem: DsseRuntimeLogSubsystem.name,
    category: "system-extension-activation"
)

private func log(_ message: String) {
    activationLogger.notice("\(message, privacy: .public)")
    NSLog("DsseAgent: %@", message)
    FileHandle.standardError.write(Data("DsseAgent: \(message)\n".utf8))
}

private func scheduleTerminationAfterDiagnosticHold(reason: String) {
    log("holding DsseAgent for \(activationDiagnosticHoldSeconds)s after activation terminal callback: \(reason)")
    DispatchQueue.main.asyncAfter(deadline: .now() + .seconds(activationDiagnosticHoldSeconds)) {
        log("terminating DsseAgent after activation diagnostic hold")
        NSApplication.shared.terminate(nil)
    }
}

private func nonsecretErrorDetail(_ error: Error) -> String {
    let nsError = error as NSError
    return "domain=\(nsError.domain) code=\(nsError.code)"
}

final class DsseNetworkExtensionManagerConfigurator: @unchecked Sendable {
    private var statusObserver: NSObjectProtocol?
    // Phase 2a in-app watchdog. An App Proxy / TransparentProxy provider has NO OS keepalive: if its process
    // dies, macOS does NOT relaunch it, so the tunnel silently stays down and all traffic goes un-steered. Once
    // the tunnel has connected at least once (armed), an UNEXPECTED drop to disconnected/invalid while the config
    // is still enabled means the provider died — re-issue startVPNTunnel to bring it back. This is NOT an
    // on-demand rule (the OS never forces/holds a connection, so it cannot fail-close). The critical guard is in
    // watchdogHandleUnexpectedStop: it reloads preferences and restarts ONLY while isEnabled is still true, so an
    // operator/watchdog `--disable` is never resurrected. Restarts are capped to avoid a crash-loop hot restart.
    private var watchdogArmed = false
    private var watchdogRestartAttempts = 0
    private var lastWatchdogRestart = Date.distantPast

    deinit {
        if let statusObserver {
            NotificationCenter.default.removeObserver(statusObserver)
        }
    }

    func configure(completion: @escaping @Sendable (Error?) -> Void) {
        log("loading NETransparentProxyManager preferences")
        NETransparentProxyManager.loadAllFromPreferences { managers, error in
            if let error {
                log("NETransparentProxyManager load failed: \(nonsecretErrorDetail(error))")
                completion(error)
                return
            }

            let manager = Self.manager(from: managers ?? [])
            let providerProtocol = Self.providerProtocol(from: manager)
            providerProtocol.providerBundleIdentifier = dsseSystemExtensionBundleID
            providerProtocol.serverAddress = dsseTransparentProxyManagerDescription
            providerProtocol.providerConfiguration = [
                "agent_config_path": dsseAgentConfigPath
            ]

            manager.localizedDescription = dsseTransparentProxyManagerDescription
            manager.protocolConfiguration = providerProtocol
            manager.isEnabled = true

            log("saving NETransparentProxyManager preferences with provider bundle \(dsseSystemExtensionBundleID)")
            manager.saveToPreferences { saveError in
                if let saveError {
                    log("NETransparentProxyManager save failed: \(nonsecretErrorDetail(saveError))")
                    completion(saveError)
                    return
                }
                log("NETransparentProxyManager saved and enabled; loading preferences before startVPNTunnel")
                manager.loadFromPreferences { loadError in
                    if let loadError {
                        log("NETransparentProxyManager post-save load failed: \(nonsecretErrorDetail(loadError))")
                        completion(loadError)
                        return
                    }
                    self.startRuntimeGate(manager: manager, completion: completion)
                }
            }
        }
    }

    /// Remove the transparent-proxy configuration ENTIRELY (uninstall), as opposed to `disable` which only
    /// clears `isEnabled` and leaves the configuration in Network settings.
    ///
    /// Uninstall must remove it. A configuration left behind points at an app and a system extension that are
    /// about to be deleted; the machine is then carrying a proxy config whose provider can never load. Windows
    /// has the same hazard and handles it explicitly (`dsse_steer --mode recover` on MSI uninstall), and this
    /// session watched a live Mac lose all connectivity when the NE could not carry traffic — leaving the
    /// config installed at uninstall time is that failure, made permanent.
    func remove(completion: @escaping @Sendable (Error?) -> Void) {
        log("loading NETransparentProxyManager preferences for removal")
        NETransparentProxyManager.loadAllFromPreferences { managers, error in
            if let error {
                log("NETransparentProxyManager remove load failed: \(nonsecretErrorDetail(error))")
                completion(error)
                return
            }
            let matched = (managers ?? []).first { manager in
                guard let providerProtocol = manager.protocolConfiguration as? NETunnelProviderProtocol else {
                    return false
                }
                return providerProtocol.providerBundleIdentifier == dsseSystemExtensionBundleID
            }
            guard let manager = matched else {
                log("no managed Dsse transparent proxy configuration present; nothing to remove")
                completion(nil)
                return
            }
            // Stop first: removing a live tunnel's configuration leaves the provider running against a config
            // that no longer exists.
            switch manager.connection.status {
            case .connected, .connecting, .reasserting:
                log("stopping Dsse transparent proxy tunnel before removal")
                manager.connection.stopVPNTunnel()
            default:
                break
            }
            manager.removeFromPreferences { removeError in
                if let removeError {
                    log("NETransparentProxyManager removeFromPreferences failed: \(nonsecretErrorDetail(removeError))")
                    completion(removeError)
                    return
                }
                log("NETransparentProxyManager configuration REMOVED (traffic returns to the normal path)")
                completion(nil)
            }
        }
    }

    // Emergency disable path used by the connectivity watchdog (and by an operator)
    // to turn the transparent proxy off without the GUI. Reuses this app's
    // NetworkExtension management entitlement. Idempotent: a no-op if no managed
    // configuration is present. NOTE: this only clears isEnabled — for uninstall use `remove` above.
    func disable(completion: @escaping @Sendable (Error?) -> Void) {
        log("loading NETransparentProxyManager preferences for disable")
        NETransparentProxyManager.loadAllFromPreferences { managers, error in
            if let error {
                log("NETransparentProxyManager disable load failed: \(nonsecretErrorDetail(error))")
                completion(error)
                return
            }
            let matched = (managers ?? []).first { manager in
                guard let providerProtocol = manager.protocolConfiguration as? NETunnelProviderProtocol else {
                    return false
                }
                return providerProtocol.providerBundleIdentifier == dsseSystemExtensionBundleID
            }
            guard let manager = matched else {
                log("no managed Dsse transparent proxy configuration present; nothing to disable")
                completion(nil)
                return
            }
            switch manager.connection.status {
            case .connected, .connecting, .reasserting:
                log("stopping Dsse transparent proxy tunnel before disable")
                manager.connection.stopVPNTunnel()
            default:
                break
            }
            manager.isEnabled = false
            manager.saveToPreferences { saveError in
                if let saveError {
                    log("NETransparentProxyManager disable save failed: \(nonsecretErrorDetail(saveError))")
                    completion(saveError)
                    return
                }
                log("NETransparentProxyManager disabled and saved")
                completion(nil)
            }
        }
    }

    private func startRuntimeGate(manager: NETransparentProxyManager, completion: @escaping @Sendable (Error?) -> Void) {
        log("NEVPNStatusDidChange status=\(Self.connectionStatusName(manager.connection.status))")
        statusObserver = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange,
            object: manager.connection,
            queue: .main
        ) { [weak self] _ in
            let status = manager.connection.status
            log("NEVPNStatusDidChange status=\(Self.connectionStatusName(status))")
            guard let self else { return }
            switch status {
            case .connected:
                // Healthy: arm the watchdog and clear the crash-loop counter.
                self.watchdogArmed = true
                self.watchdogRestartAttempts = 0
            case .disconnected, .invalid:
                // Only after a successful connect — never during the initial configure/start sequence.
                if self.watchdogArmed {
                    self.watchdogHandleUnexpectedStop(manager: manager)
                }
            default:
                break
            }
        }

        restartRuntimeGateIfNeeded(manager: manager, completion: completion)
    }

    // Restart the provider after an UNEXPECTED stop, but only if it is still supposed to be running. Reloading
    // preferences first is the critical guard: an operator/watchdog `--disable` (a separate process) sets
    // isEnabled=false in the saved preferences, and we MUST respect that — never resurrect a deliberately
    // disabled tunnel (the on-demand resurrection trap that bricked egress). Restarts are capped per window so a
    // genuinely crash-looping provider backs off instead of hot-restarting forever; region failover + lab
    // fail-open keep the machine usable while the provider comes back.
    private func watchdogHandleUnexpectedStop(manager: NETransparentProxyManager) {
        manager.loadFromPreferences { [weak self] loadError in
            guard let self else { return }
            if let loadError {
                log("watchdog: preference reload failed (\(nonsecretErrorDetail(loadError))); not restarting")
                return
            }
            guard manager.isEnabled else {
                log("watchdog: tunnel stopped and isEnabled=false (intentional disable) — not restarting")
                return
            }
            let now = Date()
            if now.timeIntervalSince(self.lastWatchdogRestart) > 120 {
                self.watchdogRestartAttempts = 0
            }
            guard self.watchdogRestartAttempts < 5 else {
                log("watchdog: restart cap reached in window — backing off (provider crash-looping?)")
                return
            }
            self.watchdogRestartAttempts += 1
            self.lastWatchdogRestart = now
            log("watchdog: provider stopped unexpectedly while enabled — restart attempt \(self.watchdogRestartAttempts) via startVPNTunnel")
            DispatchQueue.main.asyncAfter(deadline: .now() + .seconds(3)) {
                self.submitStartVPNTunnel(manager: manager) { _ in }
            }
        }
    }

    private func restartRuntimeGateIfNeeded(
        manager: NETransparentProxyManager,
        completion: @escaping @Sendable (Error?) -> Void
    ) {
        switch manager.connection.status {
        case .connected, .connecting, .reasserting:
            log("NE runtime gate reload requested; stopping existing tunnel before startVPNTunnel")
            manager.connection.stopVPNTunnel()
            waitForRuntimeGateStop(
                manager: manager,
                remainingPolls: runtimeGateRestartMaxPolls,
                completion: completion
            )
        case .disconnecting:
            log("NE runtime gate already disconnecting; waiting before startVPNTunnel")
            waitForRuntimeGateStop(
                manager: manager,
                remainingPolls: runtimeGateRestartMaxPolls,
                completion: completion
            )
        case .invalid, .disconnected:
            submitStartVPNTunnel(manager: manager, completion: completion)
        @unknown default:
            submitStartVPNTunnel(manager: manager, completion: completion)
        }
    }

    private func waitForRuntimeGateStop(
        manager: NETransparentProxyManager,
        remainingPolls: Int,
        completion: @escaping @Sendable (Error?) -> Void
    ) {
        let status = manager.connection.status
        switch status {
        case .invalid, .disconnected:
            log("NE runtime gate restart proceeding after status=\(Self.connectionStatusName(status))")
            submitStartVPNTunnel(manager: manager, completion: completion)
        default:
            guard remainingPolls > 0 else {
                log("NE runtime gate restart timeout; proceeding with startVPNTunnel after status=\(Self.connectionStatusName(status))")
                submitStartVPNTunnel(manager: manager, completion: completion)
                return
            }
            DispatchQueue.main.asyncAfter(deadline: .now() + .seconds(runtimeGateRestartPollSeconds)) {
                self.waitForRuntimeGateStop(
                    manager: manager,
                    remainingPolls: remainingPolls - 1,
                    completion: completion
                )
            }
        }
    }

    private func submitStartVPNTunnel(
        manager: NETransparentProxyManager,
        completion: @escaping @Sendable (Error?) -> Void
    ) {
        let startOptions: [String: NSObject] = [
            "agent_config_path": dsseAgentConfigPath as NSString
        ]
        log("starting NE runtime gate with startVPNTunnel")
        do {
            try manager.connection.startVPNTunnel(options: startOptions)
            log("startVPNTunnel submitted; waiting for NEVPNStatusDidChange")
            completion(nil)
        } catch {
            log("NETransparentProxyManager startVPNTunnel failed: \(nonsecretErrorDetail(error))")
            completion(error)
        }
    }

    private static func manager(from managers: [NETransparentProxyManager]) -> NETransparentProxyManager {
        managers.first { manager in
            guard let providerProtocol = manager.protocolConfiguration as? NETunnelProviderProtocol else {
                return false
            }
            return providerProtocol.providerBundleIdentifier == dsseSystemExtensionBundleID
        } ?? NETransparentProxyManager()
    }

    private static func providerProtocol(from manager: NETransparentProxyManager) -> NETunnelProviderProtocol {
        if let providerProtocol = manager.protocolConfiguration as? NETunnelProviderProtocol {
            return providerProtocol
        }
        return NETunnelProviderProtocol()
    }

    private static func connectionStatusName(_ status: NEVPNStatus) -> String {
        switch status {
        case .invalid:
            return "invalid"
        case .disconnected:
            return "disconnected"
        case .connecting:
            return "connecting"
        case .connected:
            return "connected"
        case .reasserting:
            return "reasserting"
        case .disconnecting:
            return "disconnecting"
        @unknown default:
            return "unknown"
        }
    }
}

final class DsseSystemExtensionRequestDelegate: NSObject, OSSystemExtensionRequestDelegate {
    private let managerConfigurator = DsseNetworkExtensionManagerConfigurator()
    /// Set for a deactivation (uninstall) request. The completion handler is shared between activation and
    /// deactivation, and its activation path RE-CONFIGURES the NE manager — which on an uninstall would put the
    /// transparent-proxy configuration straight back after we just removed it. This flag keeps them apart.
    private var isUninstalling = false

    func submitActivationRequest() {
        let request = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: dsseSystemExtensionBundleID,
            queue: .main
        )
        request.delegate = self

        log("submitting System Extension activation request for \(dsseSystemExtensionBundleID)")
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    /// Ask the system to unload and remove the embedded System Extension (uninstall).
    ///
    /// Deleting the .app alone does NOT remove an activated system extension — it stays registered and the OS
    /// keeps trying to run a provider whose bundle is gone. Only the containing app can request deactivation,
    /// which is why this has to live here and be invoked BEFORE the app is deleted.
    func submitDeactivationRequest() {
        let request = OSSystemExtensionRequest.deactivationRequest(
            forExtensionWithIdentifier: dsseSystemExtensionBundleID,
            queue: .main
        )
        request.delegate = self
        isUninstalling = true
        log("submitting System Extension DEACTIVATION request for \(dsseSystemExtensionBundleID)")
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        log("System Extension activation is waiting for user approval")
    }

    func request(
        _ request: OSSystemExtensionRequest,
        actionForReplacingExtension existing: OSSystemExtensionProperties,
        withExtension replacement: OSSystemExtensionProperties
    ) -> OSSystemExtensionRequest.ReplacementAction {
        log("replacing existing System Extension \(existing.bundleVersion) with \(replacement.bundleVersion)")
        return .replace
    }

    func request(
        _ request: OSSystemExtensionRequest,
        didFinishWithResult result: OSSystemExtensionRequest.Result
    ) {
        if isUninstalling {
            // Deactivation completed. Do NOT reconfigure the NE manager here — that is the activation path and
            // would reinstate the transparent-proxy configuration we are uninstalling. Just exit.
            log("System Extension DEACTIVATION completed result=\(result.rawValue) willCompleteAfterReboot=\(result == .willCompleteAfterReboot)")
            DispatchQueue.main.asyncAfter(deadline: .now() + .seconds(1)) {
                NSApplication.shared.terminate(nil)
            }
            return
        }
        log("System Extension activation request lifecycle completed with result \(result.rawValue); registration visibility not asserted by callback")
        log("activation result classification rawValue=\(result.rawValue) completed=\(result == .completed) willCompleteAfterReboot=\(result == .willCompleteAfterReboot)")
        configureNetworkExtensionManagerThenStayResident(reason: "activation_completed")
    }

    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        let nsError = error as NSError
        log("System Extension request failed: \(error.localizedDescription)")
        log("failure detail domain=\(nsError.domain) code=\(nsError.code) uninstalling=\(isUninstalling)")
        if isUninstalling {
            // Uninstall must not hang on a failed deactivation — the caller (the uninstaller script) still has
            // to unload the LaunchAgent and delete files, and it reports the residue itself.
            DispatchQueue.main.asyncAfter(deadline: .now() + .seconds(1)) {
                NSApplication.shared.terminate(nil)
            }
            return
        }
        scheduleTerminationAfterDiagnosticHold(reason: "activation_failed")
    }

    private func configureNetworkExtensionManagerThenStayResident(reason: String) {
        managerConfigurator.configure { _ in
            // Do NOT terminate on success. The app stays resident (accessory, no dock icon) so it can observe the
            // provider's step-up Darwin notification and open the browser — the NE provider is root with no
            // window server and cannot. (Re-launch via `open -a` just re-activates this resident instance.)
            log("NE manager configured (\(reason)); staying resident to serve OOB step-up browser hand-off")
        }
    }
}

let app = NSApplication.shared
app.setActivationPolicy(.accessory)

// Menu-bar status item + native notification for the OOB step-up ceremony (task #7). Built now so the menu-bar
// surface exists before any step-up arrives.
StepUpStatusController.shared.install()

// Retained for the whole process lifetime: OSSystemExtensionRequest.delegate is
// weak, and the configurators must outlive their async preference callbacks.
let requestDelegate = DsseSystemExtensionRequestDelegate()
let disableConfigurator = DsseNetworkExtensionManagerConfigurator()

// ★★★ THE EXIT MUST NOT BE RUN AS ROOT, AND MUST SAY SO (2026-08-29, measured on this Mac). The
// transparent-proxy configuration lives in the CONSOLE USER's Network Extension preferences; a root process
// is shown an empty list and cannot tell "there is none" from "I cannot see it". The shipped uninstaller ran
// this binary as root, was told "nothing to disable / error=none", and would then have deactivated the
// extension and deleted the app — stranding a configuration that captures every flow with no provider to
// carry it and no remaining way to remove it. See DsseNetworkConfigurationScope.
for scopedCommand in ["--uninstall", "--disable"] where CommandLine.arguments.contains(scopedCommand) {
    var consoleStat = stat()
    let consoleOwner: uid_t? = stat("/dev/console", &consoleStat) == 0 ? consoleStat.st_uid : nil
    if let refusal = DsseNetworkConfigurationScope.refusalWhenNotTheConsoleUser(
        effectiveUID: geteuid(),
        command: scopedCommand,
        appExecutablePath: CommandLine.arguments.first ?? "/Applications/LanternDsseAgent.app/Contents/MacOS/LanternDsseAgent",
        consoleUID: DsseNetworkConfigurationScope.consoleUID(statOwnerOfDevConsole: consoleOwner)) {
        log(refusal)
        FileHandle.standardError.write(Data((refusal + "\n").utf8))
        exit(2)
    }
}

if CommandLine.arguments.contains("--uninstall") {
    // Full teardown, in this order: REMOVE the transparent-proxy configuration, then ask the system to
    // deactivate the extension. Order matters — only the containing app can do either, so both must happen
    // while the .app still exists. Deleting the app first strands an activated extension and a proxy config
    // whose provider can never load.
    log("DsseAgent --uninstall invoked; removing transparent proxy configuration and deactivating the extension")
    DispatchQueue.main.async {
        disableConfigurator.remove { error in
            log("configuration removal completed error=\(error.map { nonsecretErrorDetail($0) } ?? "none")")
            // ★ DEACTIVATE ONLY IF THE CONFIGURATION IS ACTUALLY GONE. Deactivating after a failed removal is
            // the same stranded state by a different route: the config stays, its provider can never load
            // again, and every flow it captures dies. Leave the extension running and let the operator retry.
            guard error == nil else {
                log("uninstall REFUSING to deactivate the extension: the transparent proxy configuration is "
                    + "still installed, and an extension deactivated under a live configuration takes this "
                    + "machine's network with it. Fix the removal and run the uninstaller again.")
                DispatchQueue.main.asyncAfter(deadline: .now() + .seconds(1)) { exit(3) }
                return
            }
            // Hop to main before touching requestDelegate: this completion is @Sendable / nonisolated, and the
            // delegate (like the OSSystemExtensionRequest queue it uses) is main-actor isolated.
            DispatchQueue.main.async {
                requestDelegate.submitDeactivationRequest()
            }
        }
    }
} else if CommandLine.arguments.contains("--disable") {
    log("DsseAgent --disable invoked; disabling transparent proxy without GUI")
    DispatchQueue.main.async {
        disableConfigurator.disable { error in
            log("disable completed error=\(error.map { nonsecretErrorDetail($0) } ?? "none")")
            DispatchQueue.main.asyncAfter(deadline: .now() + .seconds(2)) {
                NSApplication.shared.terminate(nil)
            }
        }
    }
} else {
    log("DsseAgent launch observed; preparing System Extension activation request")
    DispatchQueue.main.async {
        requestDelegate.submitActivationRequest()
    }
}

// Step-up hand-off: the NE provider (root, no window server) can't open a browser, so on an egress
// authenticate/reauth flow (e.g. tcp/22) it drops the step-up portal URL in /tmp and fires this systemwide
// Darwin notification. The agent app (user GUI session) opens it — the OOB browser step-up the operator expects.
CFNotificationCenterAddObserver(
    CFNotificationCenterGetDarwinNotifyCenter(),
    nil,
    { _, _, _, _, _ in
        guard let raw = try? String(contentsOfFile: "/tmp/dsse_stepup_url", encoding: .utf8) else { return }
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let url = URL(string: trimmed) else { return }
// ★★★ THE PRODUCT'S OWN NAMESPACE, NOT AN AUTHOR'S (2026-09-03, found while checking what publishing
// dsse-core would actually publish). These Darwin notification names carried a personal
// GitHub handle in shipped source, while the logger three lines away already used
// jp.co.lantern-networks.dsse.agent. One product, two namespaces, one of them somebody's.
//
// They are a private contract between the extension and the app in this same package, tied to neither the
// bundle identifier nor the signing identity, so renaming them changes nothing but the name — provided BOTH
// sides move together, which is why they are defined once here and referenced.
        // Task #7: surface a native notification + menu-bar indicator instead of silently opening a browser tab.
        // The controller opens the portal on the user's click (or auto-opens as a fallback if notifications are
        // unauthorized, so the ceremony never strands behind an invisible prompt).
        log("stepup: surfacing notification + menu-bar for host=\(url.host ?? "?")")
        StepUpStatusController.shared.presentStepUp(url: url)
    },
    "jp.co.lantern-networks.dsse.stepup" as CFString,
    nil,
    .deliverImmediately)

// Warn-stage hand-off (S3, learning lifecycle): a Warn-staged East-West rule ALLOWS the flow but the provider
// drops a JSON notice in /tmp and fires this Darwin notification so the agent can surface a PASSIVE "this internal
// connection is monitored; authentication will soon be required" message. Non-holding — nothing is opened or
// blocked. The controller coalesces so the same resource is not re-announced repeatedly in one session.
CFNotificationCenterAddObserver(
    CFNotificationCenterGetDarwinNotifyCenter(),
    nil,
    { _, _, _, _, _ in
        guard let raw = try? String(contentsOfFile: "/tmp/dsse_warn_notice", encoding: .utf8) else { return }
        log("warn: surfacing monitored-notice")
        StepUpStatusController.shared.presentWarnNotice(json: raw)
    },
    "jp.co.lantern-networks.dsse.warn" as CFString,
    nil,
    .deliverImmediately)

app.run()
