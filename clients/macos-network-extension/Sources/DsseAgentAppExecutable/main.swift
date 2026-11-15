import AppKit
import DsseAppProxyProviderSkeleton
import DsseNetworkExtensionContract
import Foundation
import Security
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
private let dsseDNSProxyManagerDescription = "Dsse DNS Proxy"
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
    private var startWasAttempted = false
    private var startRetries = 0
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
                    self.setDNSProxy(enabled: true) { dnsError in
                        // The flows are steered either way; a DNS proxy that could not be saved is logged and
                        // retried at the next launch, and the device's DNS stays where it was meanwhile.
                        log("DNS proxy enable completed error=\(dnsError.map { nonsecretErrorDetail($0) } ?? "none")")
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
        removeDNSProxy { dnsError in
            if let dnsError {
                log("DNS proxy removal failed: \(nonsecretErrorDetail(dnsError))")
                completion(dnsError)
                return
            }
            self.removeTransparentProxy(completion: completion)
        }
    }

    private func removeTransparentProxy(completion: @escaping @Sendable (Error?) -> Void) {
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
        setDNSProxy(enabled: false) { dnsError in
            log("DNS proxy disable completed error=\(dnsError.map { nonsecretErrorDetail($0) } ?? "none")")
            self.disableTransparentProxy { proxyError in
                completion(proxyError ?? dnsError)
            }
        }
    }

    /// Turn steering back on after `--disable`, from the command line, and say whether it came up.
    ///
    /// `--disable` had no opposite. The resident app does nothing when it is opened again, so the only way back
    /// was to quit it and launch it — which nothing on the Mac says.
    ///
    /// It enables the configuration that is already installed and starts it; it installs nothing. The start is
    /// submitted again while the tunnel has not connected, for the same reason the resident app retries one.
    func enable(completion: @escaping @Sendable (Error?) -> Void) {
        NETransparentProxyManager.loadAllFromPreferences { managers, error in
            if let error {
                completion(error)
                return
            }
            let matched = (managers ?? []).first { manager in
                (manager.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == dsseSystemExtensionBundleID
            }
            guard let manager = matched else {
                log("no Dsse transparent proxy configuration is installed; open the app (or install the package) first")
                completion(NSError(domain: "DsseAgent", code: 1))
                return
            }
            manager.isEnabled = true
            manager.saveToPreferences { saveError in
                if let saveError {
                    completion(saveError)
                    return
                }
                manager.loadFromPreferences { loadError in
                    if let loadError {
                        completion(loadError)
                        return
                    }
                    self.setDNSProxy(enabled: true) { dnsError in
                        log("DNS proxy enable completed error=\(dnsError.map { nonsecretErrorDetail($0) } ?? "none")")
                        DispatchQueue.main.async {
                            self.startUntilConnected(manager: manager, attempt: 1, dnsError: dnsError, completion: completion)
                        }
                    }
                }
            }
        }
    }

    private func startUntilConnected(manager: NETransparentProxyManager, attempt: Int, dnsError: Error?,
                                     completion: @escaping @Sendable (Error?) -> Void) {
        switch manager.connection.status {
        case .connected:
            completion(dnsError)
            return
        case .disconnected, .invalid:
            if attempt > 10 {
                log("enable: the tunnel did not connect after \(attempt - 1) attempts")
                completion(NSError(domain: "DsseAgent", code: 2))
                return
            }
            submitStartVPNTunnel(manager: manager) { _ in }
        default:
            break   // connecting / reasserting / disconnecting: wait
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + .seconds(3)) {
            self.startUntilConnected(manager: manager, attempt: attempt + 1, dnsError: dnsError, completion: completion)
        }
    }

    // The Mac's DNS goes to the Edge through the extension's DNS proxy provider while steering is on. It is
    // enabled and disabled with the transparent proxy, and removed with it.
    func setDNSProxy(enabled requested: Bool, completion: @escaping @Sendable (Error?) -> Void) {
        // The provider carries DNS only on macOS 15 and later. A DNS proxy the system hands queries to and the
        // provider cannot carry does not fall back to the Mac's resolvers — the queries are dropped. So on
        // earlier systems it is never enabled, and one an earlier build enabled is turned off.
        var enabled = requested
        if #unavailable(macOS 15.0) {
            if requested { log("DNS proxy: not enabled on this macOS (needs 15 or later); name lookups stay with the Mac's resolvers") }
            enabled = false
        }
        let manager = NEDNSProxyManager.shared()
        manager.loadFromPreferences { loadError in
            if let loadError {
                completion(loadError)
                return
            }
            if !enabled && manager.providerProtocol == nil {
                completion(nil)
                return
            }
            let providerProtocol = (manager.providerProtocol as? NEDNSProxyProviderProtocol) ?? NEDNSProxyProviderProtocol()
            providerProtocol.providerBundleIdentifier = dsseSystemExtensionBundleID
            manager.providerProtocol = providerProtocol
            manager.localizedDescription = dsseDNSProxyManagerDescription
            manager.isEnabled = enabled
            manager.saveToPreferences { saveError in
                completion(saveError)
            }
        }
    }

    private func removeDNSProxy(completion: @escaping @Sendable (Error?) -> Void) {
        let manager = NEDNSProxyManager.shared()
        manager.loadFromPreferences { loadError in
            if let loadError {
                completion(loadError)
                return
            }
            guard manager.providerProtocol != nil else {
                log("no Dsse DNS proxy configuration present; nothing to remove")
                completion(nil)
                return
            }
            manager.removeFromPreferences { removeError in
                if removeError == nil {
                    log("DNS proxy configuration REMOVED (DNS returns to the system resolvers)")
                }
                completion(removeError)
            }
        }
    }

    private func disableTransparentProxy(completion: @escaping @Sendable (Error?) -> Void) {
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
            case .connecting:
                self.startWasAttempted = true
            case .disconnected, .invalid:
                // Only after a successful connect — never during the initial configure/start sequence.
                if self.watchdogArmed {
                    self.watchdogHandleUnexpectedStop(manager: manager)
                } else if self.startWasAttempted {
                    self.retryAStartThatDidNotTake(manager: manager)
                }
            default:
                break
            }
        }

        restartRuntimeGateIfNeeded(manager: manager, completion: completion)
    }

    // ★ A START THAT DID NOT TAKE IS TRIED AGAIN. A tunnel that goes connecting -> disconnected without ever
    // connecting was refused by the system — measured on a real Mac when the start was submitted while the
    // system extension was still coming up (NEAgentErrorDomain 2). Nothing retried it: the app stayed resident,
    // the proxy stayed down, and every connection left the Mac directly with nothing on screen. The watchdog
    // above does not cover it because it arms only after a first connect.
    //
    // Like the watchdog it reloads preferences first and does nothing when isEnabled is false, so a `--disable`
    // is never undone, and it stops after a few attempts.
    private func retryAStartThatDidNotTake(manager: NETransparentProxyManager) {
        guard startRetries < 6 else {
            log("start retry: the tunnel did not start after \(startRetries) attempts — leaving it down; this Mac is NOT steered")
            return
        }
        startRetries += 1
        let attempt = startRetries
        DispatchQueue.main.asyncAfter(deadline: .now() + .seconds(3)) { [weak self] in
            manager.loadFromPreferences { loadError in
                guard let self, loadError == nil, manager.isEnabled, !self.watchdogArmed else { return }
                switch manager.connection.status {
                case .disconnected, .invalid:
                    log("start retry: the tunnel went down before it ever connected — attempt \(attempt) via startVPNTunnel")
                    DispatchQueue.main.async { self.submitStartVPNTunnel(manager: manager) { _ in } }
                default:
                    break
                }
            }
        }
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
    private var activeExtensionIsAlreadyThisOne = false

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
        if existing.bundleVersion == replacement.bundleVersion
            && existing.bundleShortVersion == replacement.bundleShortVersion {
            // Every launch of this app asks for activation. Replacing an extension with itself stops and
            // restarts a healthy provider — a gap in steering on every login — and the start submitted right
            // after it is the one the system refuses. The running extension is already this one.
            log("the active System Extension is already \(existing.bundleShortVersion)/\(existing.bundleVersion); not replacing it")
            activeExtensionIsAlreadyThisOne = true
            return .cancel
        }
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
            // The containing app is the only code that can retry deactivation. Return a failure to the
            // uninstaller so it keeps the app installed instead of stranding the registered extension.
            DispatchQueue.main.asyncAfter(deadline: .now() + .seconds(1)) {
                exit(4)
            }
            return
        }
        if activeExtensionIsAlreadyThisOne {
            // The request was cancelled by this app, above, because there was nothing to replace.
            activeExtensionIsAlreadyThisOne = false
            configureNetworkExtensionManagerThenStayResident(reason: "already_active")
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
for scopedCommand in ["--uninstall", "--disable", "--enable"] where CommandLine.arguments.contains(scopedCommand) {
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

// ★ TURNING STEERING OFF NEEDS AN ADMINISTRATOR. `--disable` and `--uninstall` take this device out from under
// its organization's policy, and both ran for anyone logged in. Now: an approval root left moments ago (the
// uninstaller and the steering switch, which are run with sudo), or an administrator's authentication in the
// system's own dialog. `--enable` needs neither.
private func administratorAuthenticated(prompt: String) -> Bool {
    var ref: AuthorizationRef?
    guard AuthorizationCreate(nil, nil, [], &ref) == errAuthorizationSuccess, let ref else { return false }
    defer { AuthorizationFree(ref, [.destroyRights]) }
    return kAuthorizationRightExecute.withCString { name in
        var item = AuthorizationItem(name: name, valueLength: 0, value: nil, flags: 0)
        return withUnsafeMutablePointer(to: &item) { itemPointer in
            var rights = AuthorizationRights(count: 1, items: itemPointer)
            return prompt.withCString { promptPointer in
                var promptItem = AuthorizationItem(name: kAuthorizationEnvironmentPrompt, valueLength: strlen(promptPointer),
                                                   value: UnsafeMutableRawPointer(mutating: promptPointer), flags: 0)
                return withUnsafeMutablePointer(to: &promptItem) { promptItemPointer in
                    var environment = AuthorizationEnvironment(count: 1, items: promptItemPointer)
                    let flags: AuthorizationFlags = [.interactionAllowed, .extendRights, .destroyRights]
                    return AuthorizationCopyRights(ref, &rights, &environment, flags, nil) == errAuthorizationSuccess
                }
            }
        }
    }
}

for guarded in ["--uninstall", "--disable"] where CommandLine.arguments.contains(guarded) {
    if DsseAdministratorApproval.rootApproved(command: guarded) {
        log("\(guarded): approved by root")
    } else if administratorAuthenticated(prompt: "Lantern DSSE: an administrator must approve turning this Mac's steering off.") {
        log("\(guarded): approved by an administrator's authentication")
    } else {
        let refusal = "\(guarded) REFUSED: turning this Mac's steering off needs an administrator. "
            + "Run it with sudo:  sudo \"/Library/Application Support/Dsse/bin/dsse-steering\" off   "
            + "(or, to remove the agent:  sudo \"/Library/Application Support/Dsse/bin/dsse-uninstall\")"
        log(refusal)
        exit(7)
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
                if error != nil { exit(5) }
                NSApplication.shared.terminate(nil)
            }
        }
    }
} else if CommandLine.arguments.contains("--enable") {
    log("DsseAgent --enable invoked; enabling the installed transparent proxy and DNS proxy")
    DispatchQueue.main.async {
        disableConfigurator.enable { error in
            log("enable completed error=\(error.map { nonsecretErrorDetail($0) } ?? "none")")
            DispatchQueue.main.asyncAfter(deadline: .now() + .seconds(1)) {
                if error != nil { exit(6) }
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
// authenticate/reauth flow, it writes a root-owned, user-readable session record.
// This notification contains no URL; each GUI reads only its own validated records.
private final class AuthHandoffDelivery: @unchecked Sendable {
    private let queue = DispatchQueue(label: "jp.co.lantern-networks.dsse.auth-ui-recovery")
    private let admission = DispatchSemaphore(value: 1)
    private var gate = DsseAuthUIReplayGate()
    func replay() {
        guard admission.wait(timeout: .now()) == .success else { return }
        queue.async { [self] in
            defer { admission.signal() }
            for request in DsseAuthHandoff.pending() {
                guard gate.admit(id: request.id, result: request.result, uptime: ProcessInfo.processInfo.systemUptime) else { continue }
                if let result = request.result {
                    StepUpStatusController.shared.presentAuthResult(id: request.id, result: result)
                } else if let url = URL(string: request.url) {
                    StepUpStatusController.shared.presentStepUp(url: url)
                }
            }
        }
    }
}
private let authHandoffDelivery = AuthHandoffDelivery()
private func replayAuthHandoff() { authHandoffDelivery.replay() }
CFNotificationCenterAddObserver(
    CFNotificationCenterGetDarwinNotifyCenter(),
    nil,
    { _, _, _, _, _ in
        replayAuthHandoff()
    },
    "jp.co.lantern-networks.dsse.stepup" as CFString,
    nil,
    .deliverImmediately)
// Darwin notifications are not queued while the GUI is absent. The root NE's
// session-bound records are the recovery source when the app is relaunched.
replayAuthHandoff()
// Recover a missed notification while the GUI remains running. Protected files,
// signature/origin checks and OS-session binding remain the admission boundary.
let authHandoffCatchUpTimer = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { _ in
    replayAuthHandoff()
    replayWarnHandoff()
}

// Warn-stage hand-off (S3, learning lifecycle): a Warn-staged East-West rule ALLOWS the flow but the provider
// writes a root-owned, originating-login-only notice and fires a payload-free Darwin notification. Non-holding —
// nothing is opened or blocked. The controller coalesces the same resource within this login session.
private func replayWarnHandoff() {
    for notice in DsseAuthHandoff.pendingWarn() {
        StepUpStatusController.shared.presentWarnNotice(destination: notice.destination, service: notice.service)
    }
}
CFNotificationCenterAddObserver(
    CFNotificationCenterGetDarwinNotifyCenter(),
    nil,
    { _, _, _, _, _ in
        replayWarnHandoff()
    },
    "jp.co.lantern-networks.dsse.warn" as CFString,
    nil,
    .deliverImmediately)
replayWarnHandoff()

app.run()
