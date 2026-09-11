import Foundation

// DsseRuntimeMarker — what a SECOND process on this machine can read to learn which agent code is executing.
//
// ★ THE QUESTION IT ANSWERS, and why the obvious answers are wrong. The updater has to know the version of the
// code CURRENTLY EXECUTING, not the version on disk, because the box that holds new bytes and runs old ones is
// the entire reason that distinction exists — here, a system extension whose replacement completes on the next
// activation. Reading the installed bundle's CFBundleShortVersionString answers the wrong question, and it
// answers it confidently on exactly the machines where the two differ.
//
// ★ AND WHY A TIMESTAMP AND NOT JUST A VALUE. The rule the Windows side had to invent is that a version counts
// as running only when it is paired with an INDEPENDENT liveness signal: a value alone outlives the process
// that wrote it, so a crashed agent leaves its last version behind and a reader credits a dead machine with
// running it. Windows pairs a static registry value with the service manager. Here the marker refreshes its
// own heartbeat, which is a stronger signal rather than a weaker substitute — a timestamp that stopped
// advancing cannot be produced by a process that is gone.
//
// Written by the extension, read by the updater (clients/macos/updateplatform). The two agree on this file's
// shape and nothing else; if they ever disagree the updater reports the device as not-running, which refuses
// an update rather than performing one on a wrong assumption.
public enum DsseRuntimeMarker {
    /// Same directory the agent config already lives in, so an operator has one place to look.
    public static let path = "/Library/Application Support/Dsse/runtime_version.json"

    /// write records the running version and refreshes the heartbeat. Called at start and on every heartbeat
    /// tick.
    ///
    /// Best-effort by design: an extension that refused to steer because it could not write a bookkeeping file
    /// would be trading enforcement for observability. The consequence of failure is stated where it lands —
    /// the updater reports this device as unassessable — rather than being silently absorbed here.
    /// ★ deviceIdentity and tenantID are recorded so a SECOND process can check that a document addressed to a
    /// device is addressed to THIS one (2026-08-11, from a review). The rollout plan carries both, the Edge
    /// signs one per device, and the updater — which deliberately holds no network identity — had no way to
    /// tell its own plan from another device's. The extension is the only component here that knows: it reads
    /// the identity from the verified (T) client certificate.
    ///
    /// Empty strings are written rather than omitted keys, so "this build does not record it" and "this device
    /// has no identity" stay distinguishable to the reader.
    public static func write(version: String, deviceIdentity: String = "", tenantID: String = "",
                             now: Date = Date()) {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime]
        let body: [String: Any] = [
            "version": version,
            "pid": ProcessInfo.processInfo.processIdentifier,
            "started_at": f.string(from: startedAt),
            "heartbeat_at": f.string(from: now),
            "device_identity": deviceIdentity,
            "tenant_id": tenantID,
        ]
        guard let data = try? JSONSerialization.data(withJSONObject: body, options: [.sortedKeys]) else { return }

        let url = URL(fileURLWithPath: path)
        try? FileManager.default.createDirectory(at: url.deletingLastPathComponent(),
                                                 withIntermediateDirectories: true)
        // Atomic: the updater reads this file on its own schedule with no coordination, and a torn read is not
        // a retry — it is a device reported as not-running while it is perfectly healthy, which refuses an
        // update for a reason that never existed.
        try? data.write(to: url, options: .atomic)
    }

    /// clear removes the marker on a CLEAN stop.
    ///
    /// It is not what makes the answer correct — a killed extension never reaches it, which is exactly why the
    /// reader pairs the value with the heartbeat rather than trusting the file's existence. Clearing is still
    /// worth doing: it keeps a deliberately stopped agent from leaving a version string that reads as current
    /// to anything looking at the file directly.
    public static func clear() {
        try? FileManager.default.removeItem(atPath: path)
    }

    private static let startedAt = Date()
}
