import Foundation

// DsseDevicePosture — basic macOS device posture the agent reports to the Edge on the steer-mux CONNECT (per
// connection ≈ per device). The basics, per the signal contract: disk encryption (FileVault) + application
// firewall. EDR is deliberately out (not always installed; hard to read; not testable in the lab). Best-effort
// + FAIL-SAFE: a signal we cannot read stays nil and is simply not reported (never a guessed value).
public struct DsseDevicePosture: Sendable {
    public let encryption: Bool?
    public let firewall: Bool?

    public static func collect() -> DsseDevicePosture {
        DsseDevicePosture(encryption: fileVaultEnabled(), firewall: firewallEnabled())
    }

    // As HTTP header lines appended to the CONNECT request. The OS is always reported (reliable via ProcessInfo);
    // posture only reports what it could read.
    public func connectHeaderLines() -> String {
        var lines = "X-Dsse-Device-OS: \(DsseDevicePosture.osDescription())\r\n"
        if let e = encryption { lines += "X-Dsse-Posture-Encryption: \(e ? "on" : "off")\r\n" }
        if let f = firewall { lines += "X-Dsse-Posture-Firewall: \(f ? "on" : "off")\r\n" }
        lines += "X-Dsse-Posture-Source: macos_collector\r\n"
        return lines
    }

    static func osDescription() -> String {
        let v = ProcessInfo.processInfo.operatingSystemVersion
        return "macOS \(v.majorVersion).\(v.minorVersion).\(v.patchVersion)"
    }

    // Application Firewall global state via socketfilterfw ("Firewall is enabled. (State = 1)" / "... disabled.
    // (State = 0)"). The old /Library/Preferences/com.apple.alf.plist no longer exists on current macOS, so read
    // it from the tool (same mechanism as FileVault). nil if the tool cannot be run.
    private static func firewallEnabled() -> Bool? {
        guard let out = runTool("/usr/libexec/ApplicationFirewall/socketfilterfw", ["--getglobalstate"]) else {
            return nil
        }
        if out.contains("State = 1") || out.contains("State = 2") || out.contains("Firewall is enabled") { return true }
        if out.contains("State = 0") || out.contains("Firewall is disabled") { return false }
        return nil
    }

    // FileVault status via `fdesetup status` ("FileVault is On." / "FileVault is Off."). nil if the tool cannot
    // be run (e.g. a sandbox that blocks process spawn) — reported as unknown, never guessed.
    private static func fileVaultEnabled() -> Bool? {
        guard let out = runTool("/usr/bin/fdesetup", ["status"]) else { return nil }
        if out.contains("FileVault is On") { return true }
        if out.contains("FileVault is Off") { return false }
        return nil
    }

    // Run a system tool and return its stdout, or nil on any failure (missing binary, spawn blocked by sandbox,
    // non-UTF8). Bounded: the posture tools return a line or two.
    private static func runTool(_ path: String, _ args: [String]) -> String? {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = args
        let outPipe = Pipe()
        process.standardOutput = outPipe
        process.standardError = Pipe()
        do {
            try process.run()
        } catch {
            return nil
        }
        let data = outPipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return String(data: data, encoding: .utf8)
    }
}
