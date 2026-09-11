import Foundation

/// DsseDialHostDecision answers, once per name, whether this device can resolve its organization's transport
/// name — and says so in the log the first time it decides.
///
/// ★★★ WHY IT IS CACHED AND WHY IT IS SAID (2026-08-22). Every connection this agent makes asks dialHost, so a
/// resolver call per connection would put a DNS lookup in front of every flow's control traffic. And a fleet
/// where half the devices reach their Edge by name and half by address is a fleet where a certificate change
/// breaks an arbitrary subset — so which one a device chose has to be a line somebody can find, not an
/// inference from a failure.
///
/// ★ THE FALLBACK IS THE POINT. Answering "yes" for a name that does not resolve takes the device off the
/// network; answering "no" costs only that this device keeps being served the deployment-wide certificate,
/// which is exactly where it was yesterday. So the doubt resolves towards the address.
/// ★★★ AND A "NO" IS NOT FOREVER (2026-09-05, measured on a Mac steering under interception). The cache above
/// was permanent in both directions, so a name that did not resolve at the instant the provider started — the
/// ordinary case, because the extension comes up before the tunnel it will resolve through — condemned every
/// channel of that process to dial by address. The Edge recorded the consequence and the device never
/// re-asked:
///
///	report channel to agents.singapore.sakura.lab: “Kaede Foods Root CA” certificate is not trusted
///	(recurring, and the anchor measurement said not_holding for that device)
///
/// The note below says the fallback is safe "while this organization's devices still hold the shared anchor".
/// This device does not hold it — its organization has its own transport authority, which is roadmap D's whole
/// point — so for it the fallback is not a fallback. It is a channel that can never complete a handshake.
///
/// A "yes" stays cached: the name resolved, and re-asking buys nothing. A "no" expires, so the device that
/// could not resolve at second zero is not still dialling by address at minute forty. The probe is one
/// getaddrinfo per name per minute at worst, which is not a lookup in front of every flow — the thing the
/// cache exists to prevent.
public enum DsseDialHostDecision {
    /// How long a NEGATIVE answer is believed. Positive answers never expire.
    static let negativeAnswerLifetime: TimeInterval = 60
    private static let lock = NSLock()
    nonisolated(unsafe) private static var decided: [String: Bool] = [:]
    nonisolated(unsafe) private static var decidedAt: [String: Date] = [:]
    /// Test seam: the clock, so a test can age a negative answer without waiting a minute.
    nonisolated(unsafe) private static var now: () -> Date = { Date() }

    /// setClock is for tests only — see negativeAnswerLifetime.
    public static func setClock(_ c: @escaping () -> Date) {
        lock.lock(); defer { lock.unlock() }
        now = c
    }
    /// Test seam: replaced so a test can decide without touching the machine's resolver.
    nonisolated(unsafe) private static var resolver: (String) -> Bool = DsseDialHostDecision.systemResolves

    public static func setResolver(_ r: @escaping (String) -> Bool) {
        lock.lock(); defer { lock.unlock() }
        resolver = r
        decided = [:]
        decidedAt = [:]
    }

    public static func forget() {
        lock.lock(); defer { lock.unlock() }
        decided = [:]
        decidedAt = [:]
    }

    public static func resolves(_ name: String) -> Bool {
        let key = name.lowercased()
        lock.lock()
        if let known = decided[key] {
            // A yes is kept. A no is kept only until it goes stale — see the note at the top.
            if known {
                lock.unlock()
                return true
            }
            if let at = decidedAt[key], now().timeIntervalSince(at) < negativeAnswerLifetime {
                lock.unlock()
                return false
            }
        }
        let probe = resolver
        let previous = decided[key]
        lock.unlock()

        let answer = probe(key)
        lock.lock()
        decided[key] = answer
        decidedAt[key] = now()
        lock.unlock()

        // Only the first decision and any CHANGE are worth a line: a "still no" every minute is the noise the
        // cache exists to avoid, and a flip to yes is the moment every channel on this device starts being
        // served its organization's own certificate.
        if previous != nil && previous == answer {
            return answer
        }
        if answer {
            dsseRuntimeLog("transport_dial_host \(key) resolves — every connection this agent makes will send "
                + "this organization's name, so each one is served that organization's own certificate")
        } else {
            dsseRuntimeLog("transport_dial_host \(key) does NOT resolve on this device — dialling the Edge by "
                + "ADDRESS, which means being served the DEPLOYMENT-WIDE certificate on every channel except "
                + "the tunnel. That works only while this organization's devices still hold the shared anchor")
        }
        return answer
    }

    /// systemResolves asks the machine's resolver, and treats anything other than a usable address as "no".
    /// A name under a reserved suffix (.invalid) can never resolve by design, which is the ordinary answer in
    /// a lab and the reason the fallback exists at all.
    private static func systemResolves(_ name: String) -> Bool {
        var hints = addrinfo(ai_flags: 0, ai_family: AF_UNSPEC, ai_socktype: SOCK_STREAM, ai_protocol: 0,
                             ai_addrlen: 0, ai_canonname: nil, ai_addr: nil, ai_next: nil)
        var result: UnsafeMutablePointer<addrinfo>?
        defer { if let result { freeaddrinfo(result) } }
        guard getaddrinfo(name, nil, &hints, &result) == 0, result != nil else { return false }
        return true
    }
}
