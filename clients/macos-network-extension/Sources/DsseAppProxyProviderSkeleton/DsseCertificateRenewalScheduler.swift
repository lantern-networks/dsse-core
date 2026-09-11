import Foundation
import Security

// DsseCertificateRenewalScheduler — the part that makes renewal actually happen without anyone asking.
//
// The pieces existed before this: DsseCertificateRenewal can obtain a new certificate, and
// DsseRenewedIdentityStore can install one safely. Nothing ran them. A device whose certificate is expiring
// still expired, and the startup log only warned about it — which is exactly the state described in
// recorded as the reason short-lived certificates could not be used for a real
// fleet.
//
// WHAT IT DOES NOT DO, deliberately:
//
//   * It never touches live connections. A renewed identity is picked up when the transport next resolves
//     security, not by tearing down established tunnels. Renewal is a background housekeeping task; making it
//     able to interrupt steering would give a credential-maintenance path the power to cause an outage, which
//     is the thing this whole area is trying to remove.
//   * It never fails the provider. Every error is logged and retried at the next tick. There is a third of the
//     certificate's life of retry budget by design — on a 60-day certificate, 20 days — so a renewal path that
//     is temporarily broken must look like an alert, not like a failure.
//   * It does not renew early. Renewal opens at two thirds of life and not before, so a fleet does not spend
//     issuance on certificates that have most of their validity left.

public final class DsseCertificateRenewalScheduler: @unchecked Sendable {

    private let configDirectory: URL
    private let contract: DsseTransportContract
    private let log: (String) -> Void
    private let queue = DispatchQueue(label: "dsse.certificate-renewal")
    private var timer: DispatchSourceTimer?
    // Pinned agent-policy key and where to fetch the signed trust bundle. Empty pin = anchor self-healing is
    // OFF, which is stated in the log rather than left to be inferred from nothing happening.
    private let agentPolicyPinnedPublicKeyHex: String
    private let trustBundleURL: URL?
    // Called after anchors are adopted. Adoption alone does not heal the device: the transport resolved its
    // anchors when it was built, so a running provider keeps using the broken ones until something rebuilds it.
    // Verified the hard way on-device — the anchors were adopted, and every flow still failed until a restart.
    private let onAnchorsAdopted: (() -> Void)?
    // Where the verified agent policy is cached, so the renewal decision can read the operator's cutoff from
    // the same signed document the steering path already trusts.
    private let agentPolicySignedPath: String?

    public init(configDirectory: URL, contract: DsseTransportContract,
                agentPolicyPinnedPublicKeyHex: String = "", trustBundleURL: URL? = nil,
                agentPolicySignedPath: String? = nil,
                onAnchorsAdopted: (() -> Void)? = nil,
                log: @escaping (String) -> Void) {
        self.configDirectory = configDirectory
        self.contract = contract
        self.agentPolicyPinnedPublicKeyHex = agentPolicyPinnedPublicKeyHex.trimmingCharacters(in: .whitespacesAndNewlines)
        self.trustBundleURL = trustBundleURL
        self.agentPolicySignedPath = agentPolicySignedPath
        self.onAnchorsAdopted = onAnchorsAdopted
        self.log = log
    }

    // operatorRenewCutoff reads "renew anything issued before this" from the SIGNED agent policy the device
    // already caches. Signature-checked, because this value can make a fleet replace its credentials.
    //
    // nil whenever anything is missing or does not verify, which puts the agent back on its ordinary
    // two-thirds-of-life schedule. That is the safe direction: reading a garbled response as "renew now" is how
    // one bad reply becomes a fleet-wide renewal storm.
    private func operatorRenewCutoff() -> Date? {
        guard let path = agentPolicySignedPath?.trimmingCharacters(in: .whitespacesAndNewlines),
              !path.isEmpty, !agentPolicyPinnedPublicKeyHex.isEmpty else {
            return nil
        }
        return DsseSignedAgentPolicy.verifiedRenewCertificatesIssuedBefore(
            signedPath: path, pinnedPublicKeyHex: agentPolicyPinnedPublicKeyHex)
    }

    // Six hours is ample for the 60-day certificates /enroll issues today, whose retry budget is 20 days.
    static let maxCheckInterval: TimeInterval = 6 * 3600
    // Set low deliberately: a check that finds the certificate NOT due is purely local — it reads a certificate
    // already to hand and makes no network request — so frequent checking costs nothing. Only a DUE check talks
    // to the Edge, and there urgency is correct.
    static let minCheckInterval: TimeInterval = 15
    // How many chances a device should get inside its retry budget. Twelve means one transient failure costs a
    // twelfth of the margin rather than most of it.
    static let attemptsPerBudget: Double = 12

    // checkInterval derives how often to look from the certificate's own lifetime.
    //
    // A FIXED interval is wrong, and quietly so. Renewal opens at two thirds of life, leaving the last third as
    // retry budget, and the interval must fit inside that budget. With a 60-day certificate the budget is 20
    // days and six-hourly checks give 80 attempts. With a ONE-HOUR certificate the budget is 20 minutes and
    // six-hourly checks give ZERO — the certificate expires without the device ever looking. Short TTLs are not
    // hypothetical; they are what an operator reaches for when tightening a fleet, and what the lab uses to
    // exercise this path at all. The failure this prevents is the nastiest kind: everything looks configured,
    // nothing logs an error, and the certificate simply expires.
    public static func checkInterval(notBefore: Date, notAfter: Date) -> TimeInterval {
        guard notAfter > notBefore else { return maxCheckInterval }
        let budget = notAfter.timeIntervalSince(notBefore) / 3.0
        return min(maxCheckInterval, max(minCheckInterval, budget / attemptsPerBudget))
    }

    // start runs a first check shortly after startup and then reschedules itself from the certificate in force.
    //
    // Self-rescheduling rather than a fixed repeating timer, because the right cadence depends on the
    // certificate and the certificate changes when renewal succeeds — a 60-day bootstrap certificate replaced
    // by a 24-hour managed one needs the interval to follow it down.
    public func start() {
        scheduleNext(after: 60)
        log("certificate_renewal scheduler started (interval derived from the certificate's own lifetime, max \(Int(Self.maxCheckInterval))s)")
        // Answer the writability question now, not on the day a certificate comes due.
        queue.async { [weak self] in
            self?.probeKeychainWritability()
            self?.probeSecureEnclaveAvailability()
            // Name any leftover identities for this device — superseded, hand-made, or from a renewal that
            // died before it committed. The store reaps the one its pointer superseded; nothing else reaps
            // these, and each is a second credential the Edge still trusts. Report only; see the file.
            if let self {
                DsseDeviceIdentityOrphans.reportOrphans(configDirectory: self.configDirectory, log: self.log)
            }
        }
    }

    // checkSoon brings the next check forward when something has changed that the ordinary cadence would take
    // hours to notice.
    //
    // The cadence is derived from the certificate's own lifetime, which is right for the two-thirds schedule
    // and exactly backwards for an operator's explicit request: a long certificate is checked rarely, and a
    // long certificate is precisely what somebody presses "renew now" about. Measured on the lab — a ten-year
    // certificate yields the six-hour ceiling, so an operator's request would have sat unacted-on for most of
    // a working day while everything reported itself healthy.
    //
    // Idempotent and cheap: a check that finds nothing due reads a certificate already to hand and makes no
    // network request, so waking early costs nothing when the caller was wrong.
    public func checkSoon(reason: String) {
        log("certificate_renewal check_brought_forward reason=\(reason)")
        scheduleNext(after: 1)
    }

    private func scheduleNext(after delay: TimeInterval) {
        timer?.cancel()
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + delay)
        timer.setEventHandler { [weak self] in
            guard let self else { return }
            // Anchors first: renewal cannot complete over a transport this device can no longer verify, so
            // healing the anchor is a precondition for the certificate work below rather than a peer of it.
            self.recoverTrustAnchorsIfNeeded()
            let next = self.checkOnce()
            self.scheduleNext(after: next)
        }
        self.timer = timer
        timer.resume()
    }

    // probeKeychainWritability answers, at startup, the one question renewal cannot answer for itself until the
    // day it matters: can THIS process write to the keychain at all?
    //
    // Everything else about renewal was verified in a user-context process. The provider is a system extension
    // running as root and may use a different keychain with different permissions. Without this, a keychain
    // that refuses writes would stay invisible until a certificate came due — which, for a fleet on 60-day
    // certificates, means finding out during the outage rather than weeks before it.
    //
    // It is deliberately harmless: one throwaway key, created and immediately deleted. No certificate is
    // touched, nothing is installed, and the device identity is not involved. The cost is a few milliseconds
    // once per start; what it buys is that the renewal path's viability is observable BEFORE anything depends
    // on it.
    public func probeKeychainWritability() {
        let tag = "dsse-keychain-writability-probe"
        // Clear any leftover from a previous start that was killed mid-probe, so a stale item cannot make this
        // look like a duplicate failure forever.
        SecItemDelete([kSecClass as String: kSecClassKey,
                       kSecAttrApplicationTag as String: Data(tag.utf8)] as CFDictionary)

        var error: Unmanaged<CFError>?
        let key = SecKeyCreateRandomKey([
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: Data(tag.utf8),
            ],
        ] as CFDictionary, &error)

        guard key != nil else {
            let detail = (error?.takeRetainedValue()).map { String(describing: $0) } ?? "unknown"
            log("certificate_renewal keychain_writable=NO error=\(detail) — automated renewal CANNOT install a " +
                "new certificate on this device; it will keep requesting one and failing. Fix this before " +
                "short-lived certificates are issued to this fleet.")
            return
        }
        // Readable back? Creation reporting success is not the same as the item being retrievable, and the
        // install path depends on retrieval.
        var found: CFTypeRef?
        let readBack = SecItemCopyMatching([
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: Data(tag.utf8),
            kSecReturnRef as String: true,
        ] as CFDictionary, &found)
        let deleted = SecItemDelete([kSecClass as String: kSecClassKey,
                                     kSecAttrApplicationTag as String: Data(tag.utf8)] as CFDictionary)
        if readBack == errSecSuccess {
            log("certificate_renewal keychain_writable=YES (probe key created, read back and removed; delete_status=\(deleted))")
        } else {
            log("certificate_renewal keychain_writable=PARTIAL create=ok read_back_status=\(readBack) — a key " +
                "can be created but not retrieved, so no identity would form and renewal would fail at install")
        }
    }

    // probeSecureEnclaveAvailability answers, in the ONE context where it matters, whether a device key could
    // live in the Secure Enclave.
    //
    // WHY THIS IS INSTRUMENTATION AND NOT A TEST. A device key held in the keychain is protected by an access
    // control list, and on this machine that list was found to permit an ordinary local user to SIGN with the
    // device key — enough to impersonate the device to the Edge, without extracting anything
    // (docs/2026-07-28_macos_device_identity_readable_by_non_root.ja.md). An Enclave-held key removes that
    // class of problem structurally: the key never exists outside the Enclave, and using it requires passing
    // an access control the caller cannot bypass.
    //
    // Whether that is possible HERE cannot be settled from a command-line tool: Secure Enclave key generation
    // requires a properly signed process, and an unsigned probe fails with errSecInteractionNotAllowed —
    // which says nothing about the extension. So the question is asked from inside the extension, where the
    // answer actually applies, and reported once per start.
    //
    // Harmless by construction: one throwaway key, created and immediately deleted. No certificate, no
    // identity, nothing installed.
    public func probeSecureEnclaveAvailability() {
        // The first attempt failed with -34018 (errSecMissingEntitlement) at "failed to add key to keychain",
        // AFTER the Enclave had produced the key — the hardware and the extension context are fine, and what
        // fails is PERSISTING it. The extension's keychain-access-groups is a wildcard ("TEAMID.*"), and an
        // item has to be added to a CONCRETE group, so the likely cause is that no access group was named and
        // the wildcard cannot serve as one. Secure Enclave keys on macOS also live in the data-protection
        // keychain rather than the file-based one.
        //
        // Rather than guess once per deploy, try the plausible combinations in one run and report which — if
        // any — works. Each attempt cleans up after itself; nothing is installed either way.
        let team = "M4U8GSBL6C"
        let attempts: [(String, [String: Any])] = [
            ("plain", [:]),
            ("data-protection keychain", [kSecUseDataProtectionKeychain as String: true]),
            ("access group = extension id", [
                kSecAttrAccessGroup as String: "\(team).jp.co.lantern-networks.dsse.agent.networkextension",
            ]),
            ("access group = extension id + data-protection", [
                kSecAttrAccessGroup as String: "\(team).jp.co.lantern-networks.dsse.agent.networkextension",
                kSecUseDataProtectionKeychain as String: true,
            ]),
            ("access group = app group", [
                kSecAttrAccessGroup as String: "group.jp.co.lantern-networks.dsse.app-group",
                kSecUseDataProtectionKeychain as String: true,
            ]),
        ]

        var succeeded: String?
        for (label, extra) in attempts {
            let tag = "dsse-secure-enclave-probe-\(label.replacingOccurrences(of: " ", with: "-"))"
            var deleteQuery: [String: Any] = [kSecClass as String: kSecClassKey,
                                              kSecAttrApplicationTag as String: Data(tag.utf8)]
            extra.forEach { deleteQuery[$0.key] = $0.value }
            SecItemDelete(deleteQuery as CFDictionary)

            guard let access = SecAccessControlCreateWithFlags(
                nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage], nil) else { continue }
            var privateAttrs: [String: Any] = [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: Data(tag.utf8),
                kSecAttrAccessControl as String: access,
            ]
            extra.forEach { privateAttrs[$0.key] = $0.value }

            var genError: Unmanaged<CFError>?
            let key = SecKeyCreateRandomKey([
                kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                kSecAttrKeySizeInBits as String: 256,
                kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
                kSecPrivateKeyAttrs as String: privateAttrs,
            ] as CFDictionary, &genError)

            guard let key else {
                let detail = (genError?.takeRetainedValue()).map { String(describing: $0) } ?? "unknown"
                log("device_key_secure_enclave attempt=\(label) result=FAILED error=\(detail)")
                continue
            }
            let canSign = SecKeyCreateSignature(key, .ecdsaSignatureMessageX962SHA256,
                                                Data("probe".utf8) as CFData, nil) != nil
            let privateEscapes = (SecKeyCopyExternalRepresentation(key, nil) as Data?) != nil
            SecItemDelete(deleteQuery as CFDictionary)

            if privateEscapes {
                log("device_key_secure_enclave attempt=\(label) result=SUSPECT the private key came out — not Enclave-held")
                continue
            }
            log("device_key_secure_enclave attempt=\(label) result=OK can_sign=\(canSign) private_key_export=refused")
            succeeded = succeeded ?? label
        }

        if let succeeded {
            log("device_key_secure_enclave=AVAILABLE via=\"\(succeeded)\" — a device key can be bound to this " +
                "machine's Enclave, which removes the ability of a local user to sign with it")
        } else {
            log("device_key_secure_enclave=UNAVAILABLE none of the attempted keychain placements worked — device " +
                "keys stay in the keychain, where their access control is what stands between a local user and " +
                "impersonating this device")
        }
    }

    public func stop() {
        timer?.cancel()
        timer = nil
    }

    // checkOnce decides whether renewal is due and, if so, performs it, returning how long to wait before
    // looking again. Safe to call at any time.
    @discardableResult
    public func checkOnce() -> TimeInterval {
        guard let security = DsseTransportSecurityResolver.resolve(contract: contract,
                                                                   configDirectory: configDirectory) else {
            log("certificate_renewal skipped reason=no_transport_security")
            return Self.maxCheckInterval
        }
        guard let identity = security.clientIdentity else {
            // mtls_required with no identity is already fail-closed elsewhere. Renewal cannot help: it
            // authenticates with the certificate being renewed, so there is nothing to authenticate as.
            log("certificate_renewal skipped reason=no_client_identity")
            return Self.maxCheckInterval
        }
        var certificate: SecCertificate?
        guard SecIdentityCopyCertificate(identity, &certificate) == errSecSuccess, let certificate,
              let notBefore = DsseCertificateRenewal.notBefore(of: certificate),
              let notAfter = DsseCertificateRenewal.notAfter(of: certificate) else {
            log("certificate_renewal skipped reason=validity_unreadable")
            return Self.maxCheckInterval
        }
        var cn: CFString?
        SecCertificateCopyCommonName(certificate, &cn)
        guard let commonName = (cn as String?), !commonName.isEmpty else {
            log("certificate_renewal skipped reason=no_common_name")
            return Self.maxCheckInterval
        }

        let daysRemaining = Int(notAfter.timeIntervalSinceNow / 86_400)
        let next = Self.checkInterval(notBefore: notBefore, notAfter: notAfter)

        // ALREADY EXPIRED — the device was switched off across its own expiry (a long holiday). The normal
        // transport CANNOT carry this handshake, so renewing over it is not merely likely to fail, it is
        // impossible. Go to the recovery listener instead. See resolvedRecoveryEndpoint for how the address is
        // found when the fleet config carries only a port.
        if notAfter <= Date() {
            let expiredDays = -daysRemaining
            // ★★ THE NAME IS KNOWN AND CANNOT YET BE SENT, AND THAT IS SAID OUT LOUD. The Edge announces a
            // recovery SNI so this path can share the transport port — but a renewal request goes out over
            // URLSession, which derives the TLS server name from the URL's host and offers no way to send a
            // different one. Dialling the transport port WITHOUT the name would reach the main listener, which
            // requires a valid certificate: the exact thing this device does not have.
            //
            // So the separate port stays in use here until the renewal request moves to NWConnection (which the
            // tunnel already uses and which does let the name be set). Until then this logs the gap rather than
            // pretending the fold has reached this platform — an agent that quietly ignores an announcement is
            // how the Edge comes to believe a fleet has adopted something it has not.
            guard let dial = Self.resolvedRecoveryDial(contract: contract, configDirectory: configDirectory),
                  let hp = DsseTransportSecurityFactory.hostPort(fromTransportURL: "https://" + dial.endpoint) else {
                log("certificate_renewal EXPIRED identity=\(commonName) expired_days=\(expiredDays) and no " +
                    "recovery endpoint is configured — this device cannot renew itself and needs manual re-enrolment")
                return next
            }
            // ★ ONE PORT WHEN THE EDGE HAS ANNOUNCED A NAME FOR IT (the enrolment fold). The request then goes over
            // NWConnection, which can send a server name that differs from the address; URLSession cannot, and
            // that constraint is the whole reason the separate port outlived the design that replaced it.
            let via = dial.serverName.map { "\(dial.endpoint) as \($0) (transport port)" } ?? dial.endpoint
            log("certificate_renewal EXPIRED identity=\(commonName) expired_days=\(expiredDays) — the normal " +
                "transport cannot carry this handshake; recovering via \(via)")
            recover(commonName: commonName, via: hp, serverName: dial.serverName, liveSecurity: security)
            return next
        }

        // An operator can declare that certificates issued before some moment are stale — after replacing the
        // issuing CA, say. Read from the SIGNED agent policy the device already fetches; an unsigned or absent
        // value means no instruction, and the ordinary schedule applies.
        let renewIfIssuedBefore = operatorRenewCutoff()
        guard DsseCertificateRenewal.renewalDue(notBefore: notBefore, notAfter: notAfter,
                                                renewIfIssuedBefore: renewIfIssuedBefore) else {
            log("certificate_renewal not_due identity=\(commonName) days_remaining=\(daysRemaining) next_check=\(Int(next))s")
            return next
        }
        if let cutoff = renewIfIssuedBefore, notBefore < cutoff {
            log("certificate_renewal DUE identity=\(commonName) reason=operator_requested issued=\(notBefore) " +
                "cutoff=\(cutoff) days_remaining=\(daysRemaining) — this certificate predates the cutoff an operator set")
        } else {
            log("certificate_renewal DUE identity=\(commonName) days_remaining=\(daysRemaining) — requesting a new certificate")
        }

        do {
            let renewed = try DsseCertificateRenewal.renew(security: security, commonName: commonName)
            try DsseRenewedIdentityStore.install(renewed, configDirectory: configDirectory,
                                                 probe: { [weak self] candidate in
                                                     self?.handshakeSucceeds(with: candidate, like: security) ?? false
                                                 },
                                                 log: log)
        } catch {
            // Loud but not fatal. With the retry budget this is an alert; only a renewal path that stays
            // broken for weeks becomes an outage, and that is what the day count is for.
            log("certificate_renewal FAILED identity=\(commonName) days_remaining=\(daysRemaining) error=\(error) " +
                "— the existing certificate is still in use and renewal will be retried in \(Int(next))s")
        }
        return next
    }

    // recover renews through the recovery listener and proves the result on the NORMAL transport.
    //
    // The two are deliberately different endpoints. The recovery listener refuses a still-VALID certificate by
    // design, so probing a freshly issued one against it would always fail; and the identity has to be proven
    // where the device actually needs it, which is the (T) transport. Same pinned CA and same SNI for both, so
    // nothing new has to be trusted to reach the recovery port.
    // resolvedRecoveryEndpoint works out WHERE to recover, tolerating a fleet config that names only the port.
    //
    // The recovery listener lives on the same host as the (T) transport and differs only in port — that is the
    // whole reason nothing new has to be trusted to reach it. But the two values reached the device by
    // different routes: the transport URL is written at PROVISIONING time (a device that lacks it cannot reach
    // the Edge at all, so it is always present), whereas the recovery endpoint arrives in a fleet snapshot the
    // Edge publishes. A device provisioned before that field existed, or one that never received a snapshot,
    // therefore has no way to recover — and it only finds out at the moment it is already locked out.
    //
    // So a config may carry the port alone ("18545" or ":18545") and the HOST is taken from the transport URL
    // the device already trusts. That also makes one fleet-wide value correct for every region, instead of a
    // per-Edge address that has to be delivered before it can be useful.
    /// resolvedRecoveryDial answers WHERE to recover and WHAT NAME to send.
    ///
    /// ★★ THE AGENT PLANE IS BEING FOLDED ONTO ONE PORT. When the last adopted bundle names a recovery SNI, the
    /// Edge serves that path on the TRANSPORT port for that name — so the dial is the transport address with
    /// the name attached, and the second port stops being needed by this device. When it names none, this is
    /// exactly what it was: the recovery endpoint from the agent configuration, no name.
    ///
    /// The name comes from the SIGNED bundle and never from a guess: a device that invented one would be asking
    /// an Edge for a path it does not serve, at the moment it is already locked out.
    static func resolvedRecoveryDial(contract: DsseTransportContract,
                                     configDirectory: URL) -> (endpoint: String, serverName: String?)? {
        let sni = DsseAdoptedTrustAnchorStore.advertisedRenewalRecoverySNI(configDirectory: configDirectory)
        if !sni.isEmpty,
           let url = contract.transportTLSURL?.trimmingCharacters(in: .whitespacesAndNewlines),
           let transport = DsseTransportSecurityFactory.hostPort(fromTransportURL: url) {
            let raw6 = transport.host
            let host = (raw6.contains(":") && !raw6.hasPrefix("[")) ? "[\(raw6)]" : raw6
            return ("\(host):\(transport.port)", sni)
        }
        guard let endpoint = resolvedRecoveryEndpoint(contract: contract) else { return nil }
        return (endpoint, nil)
    }

    static func resolvedRecoveryEndpoint(contract: DsseTransportContract) -> String? {
        guard let raw = contract.renewalRecoveryEndpoint?.trimmingCharacters(in: .whitespacesAndNewlines),
              !raw.isEmpty else {
            return nil
        }
        // A full host:port is used as given.
        if let colon = raw.lastIndex(of: ":"), colon != raw.startIndex {
            let host = String(raw[raw.startIndex..<colon])
            if !host.isEmpty && host != "[" {
                return raw
            }
        }
        // Port only, with or without the leading colon.
        let port = raw.hasPrefix(":") ? String(raw.dropFirst()) : raw
        guard !port.isEmpty, port.allSatisfy(\.isNumber),
              let url = contract.transportTLSURL?.trimmingCharacters(in: .whitespacesAndNewlines),
              let transport = DsseTransportSecurityFactory.hostPort(fromTransportURL: url) else {
            return nil
        }
        // An IPv6 literal has to be bracketed or the host:port split below it will misread the address — but the
        // parser may already have bracketed it, and bracketing twice yields an address that resolves to nothing.
        let raw6 = transport.host
        let host = (raw6.contains(":") && !raw6.hasPrefix("[")) ? "[\(raw6)]" : raw6
        return "\(host):\(port)"
    }

    // recoverTrustAnchorsIfNeeded probes whether this device can still verify the Edge and, if not, fetches
    // and adopts the signed trust bundle. Cheap when healthy: one probe, no fetch.
    func recoverTrustAnchorsIfNeeded() {
        guard !agentPolicyPinnedPublicKeyHex.isEmpty else {
            log("trust_anchor_recovery disabled (no pinned agent-policy key in the agent config)")
            return
        }
        guard let url = contract.transportTLSURL?.trimmingCharacters(in: .whitespacesAndNewlines),
              let hp = DsseTransportSecurityFactory.hostPort(fromTransportURL: url) else {
            return
        }
        // Default to the Edge's data listener on the transport host: the bundle is served there, needs no
        // client certificate, and its authenticity comes from the signature rather than the channel.
        // ★★★ SAY WHICH ORGANIZATION IS ASKING (2026-08-20, measured on the lab).
        //
        // This fetch is the last resort: it runs when the device cannot verify the Edge, and its authenticity
        // comes from the signature rather than the channel. It named nobody — and the Edge, hearing no name and
        // seeing no certificate it can verify, answers with THE NODE'S organization's distribution. Measured: a
        // device of tenant_northwind is handed tenant_reference_lab's single anchor, which cannot verify the
        // certificate the Edge presents for northwind.dsse.invalid. It refuses, correctly, and never recovers.
        //
        // So the last resort was alive for one organization and dead for every other, and nothing in a
        // single-organization deployment can show that.
        //
        // The name is what this device already holds and already dials. It is not a credential and proves
        // nothing; it selects, exactly as it does in the handshake.
        // ★★★ A DEVICE THAT HAS ADOPTED NOTHING ASKED FOR NOBODY'S BUNDLE AND WAS GIVEN THE NODE'S
        // (2026-08-29, measured on Windows by the session that walked hikari.lab, and true here identically).
        //
        // advertisedTransportServerName is the name an ADOPTED bundle advertised — empty on a device that has
        // never adopted one, which is every device on its first boot. The Edge answers a nameless request
        // with its OWN organization, as it must. So a brand-new device of one organization adopts the
        // DEPLOYMENT's interception root, logs "ADOPTED", and counts as provisioned — with the wrong
        // authority, while every screen reads green.
        //
        // The name is in the signed install profile, which this device already has and already verifies with
        // the same pin. It selects; it is not a credential and proves nothing, exactly as in the handshake.
        var askedName = DsseAdoptedTrustAnchorStore.advertisedTransportServerName(configDirectory: configDirectory)
        if askedName.isEmpty {
            let profilePath = DsseInstallProfileApplication.profilePath(configured: nil,
                                                                       configDirectory: configDirectory)
            if let profile = DsseSignedInstallProfile.verifiedProfile(signedPath: profilePath,
                                                                     pinnedPublicKeyHex: agentPolicyPinnedPublicKeyHex),
               let stated = profile.transportServerName?.trimmingCharacters(in: .whitespacesAndNewlines),
               !stated.isEmpty {
                askedName = stated
                log("trust_anchor_recovery asking as \(stated) — this device has adopted no bundle yet, so the "
                    + "name comes from the signed install profile. Asking for nobody's bundle is answered with "
                    + "the NODE's organization, and what is adopted there is what this device trusts afterwards")
            }
        }
        // ★★★ THE DOOR IS THE TRANSPORT'S, NOT 8443 (2026-08-26, win-dev-1 letter 112, measured on Windows
        // against a deployment dsse-install generated). Both agents derived this address as
        // "<transport host>:8443" — the Edge's own listening port — and every generated deployment fronts
        // that port on the region doorway instead, so the device dialled a port nothing answers on:
        //
        //   Get "https://…:8443/bootstrap/trust-bundle": connectex: actively refused
        //
        // The box therefore reported interception_root_trust wanted=0 — no roots to look for — while the
        // deployment was decrypting its traffic, which on Windows means every HTTPS request fails the moment
        // steering arms. The Mac derives it the same way and would have failed identically.
        //
        // 8443 dates from when the agent-facing surface was several ports. It is one now — the Edge says so
        // at start-up, "agent-facing ports: 1 … (enrolment, the signed trust bundle and the steering
        // documents)" — and the transport URL is that door's address as seen from outside. So the port comes
        // from the transport, and an explicit trustBundleURL still overrides everything.
        let base = trustBundleURL?.absoluteString
            ?? "https://\(DsseTrustBundleAddress.hostPort(host: hp.host, port: hp.port))/bootstrap/trust-bundle"
        let withName = askedName.isEmpty ? base
            : base + (base.contains("?") ? "&" : "?") + "server_name="
                + (askedName.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? askedName)
        let bundleURL = URL(string: withName)
        guard let bundleURL else { return }

        let anchors = DsseAdoptedTrustAnchorStore.currentAnchors(configDirectory: configDirectory)
            ?? DsseTransportSecurityResolver.resolve(contract: contract, configDirectory: configDirectory)?.pinnedCACertificates
            ?? []
        let outcome = DsseTrustAnchorRecovery.recoverIfNeeded(
            host: hp.host, port: hp.port, bundleURL: bundleURL,
            configDirectory: configDirectory, pinnedPublicKeyHex: agentPolicyPinnedPublicKeyHex,
            currentAnchors: anchors,
            fetchBundle: { DsseTrustAnchorRecovery.fetchOverUnverifiedChannel($0) },
            log: { [weak self] in self?.log($0) })
        switch outcome {
        case .anchorsStillValid:
            // The healthy result is logged too. Staying silent when nothing is wrong reads identically to the
            // feature being off or broken, and this is the one mechanism whose whole job is to rescue a device
            // that cannot talk to anyone — "you cannot tell whether it is armed" is the wrong property for it.
            // At a six-hour tick this is a handful of lines a day.
            let serial = DsseAdoptedTrustAnchorStore.lastAcceptedSerial(configDirectory: configDirectory)
            log("trust_anchor_recovery anchors_valid=yes adopted_serial=\(serial) (no action needed)")
        case .adopted(let serial, let count):
            log("trust_anchor_recovery ADOPTED serial=\(serial) anchors=\(count) — rebuilding the transport")
            onAnchorsAdopted?()
        case .adoptedWhileHealthy(let serial, let count):
            // The ordinary case, and the one that makes a rotation's overlap reachable at all.
            log("trust_anchor_recovery ADOPTED serial=\(serial) anchors=\(count) while healthy — rebuilding the transport")
            onAnchorsAdopted?()
        case .refusedWouldStrandSelf(let serial, let reason):
            // Refusing is correct and must be loud: the fleet has moved to a distribution this device cannot
            // use, and it will keep working on its current anchors until someone looks.
            log("trust_anchor_recovery REFUSED distribution serial=\(serial): \(reason)")
        case .unrecovered(let reason):
            log("trust_anchor_recovery NOT recovered: \(reason)")
        }
    }

    private func recover(commonName: String, via endpoint: (host: String, port: Int),
                         serverName: String? = nil,
                         liveSecurity: DsseTransportSecurity) {
        // EVERY pinned CA, not just the first. Mid-rotation a device legitimately holds a bundle of two, and the
        // Edge may already present the new one; passing only the first would make recovery fail against exactly
        // the certificate the (T) transport accepts — i.e. the recovery path would break during the rotation it
        // exists to survive. Windows already copies the whole pool (certificate_renewal.go recoveryTransport).
        let recoverySecurity = DsseTransportSecurity(
            host: endpoint.host, port: endpoint.port, mtlsRequired: true,
            pinnedCACertificates: liveSecurity.pinnedCACertificates,
            clientIdentity: liveSecurity.clientIdentity)
        do {
            let renewed = try DsseCertificateRenewal.renew(security: recoverySecurity, commonName: commonName,
                                                           serverName: serverName)
            try DsseRenewedIdentityStore.install(renewed, configDirectory: configDirectory,
                                                 probe: { [weak self] candidate in
                                                     self?.handshakeSucceeds(with: candidate, like: liveSecurity) ?? false
                                                 },
                                                 log: log)
            log("certificate_renewal RECOVERED identity=\(commonName) — steering can resume with the new certificate")
        } catch {
            log("certificate_renewal RECOVERY FAILED identity=\(commonName) error=\(error) — the device still " +
                "cannot renew itself; it will retry")
        }
    }

    // handshakeSucceeds proves the candidate identity works before it is put in force.
    //
    // It deliberately does NOT use /enroll/renew: proving a certificate against the one endpoint that just
    // issued it would show little. Any HTTP answer is enough — the question is whether the mTLS handshake
    // completes, not what the endpoint says.
    private func handshakeSucceeds(with candidate: SecIdentity, like security: DsseTransportSecurity) -> Bool {
        let probeSecurity = DsseTransportSecurity(host: security.host, port: security.port,
                                                  mtlsRequired: true,
                                                  pinnedCACertificate: security.pinnedCACertificate,
                                                  clientIdentity: candidate)
        // ★★★ BY NAME, AND WITH THE CANDIDATE (2026-08-22, measured — this probe was failing on the SERVER's
        // certificate and reporting it as "the renewed identity could not complete an mTLS handshake", which
        // is a sentence about the wrong end of the connection).
        //
        // It dialled https://<address>/healthz, so it was served the deployment-wide certificate while every
        // other connection this agent makes sends its organization's name and is served the organization's
        // own. The moment the shared anchor left this organization's bundle — the last step of roadmap D — the
        // probe could never pass, so no renewal could ever be installed, so no device could ever move onto its
        // organization's own device-identity authority. Fourth channel of the same family in one day.
        //
        // And it must present the CANDIDATE. Reading the identity live, which every other connection has to
        // do, would have this prove the certificate already in force and say yes about one it never sent.
        let name = DsseLiveTransportServerName.current()
        do {
            let answer = try DsseSingleRequestOverNW.get(
                host: security.host, port: security.port, serverName: name.isEmpty ? nil : name,
                path: "/healthz", security: probeSecurity, timeout: 15, identityOverride: candidate)
            if !(200...299).contains(answer.status) {
                log("certificate_renewal probe FAILED status=\(answer.status) name=\(name.isEmpty ? "(by address)" : name)")
                return false
            }
            return true
        } catch {
            log("certificate_renewal probe FAILED name=\(name.isEmpty ? "(by address)" : name) " +
                "transport_error=\(error.localizedDescription)")
            return false
        }
    }
}


// DsseTrustBundleAddress builds the address the signed trust bundle is fetched from.
//
// It exists as a named thing rather than an interpolation because the derivation was wrong on both platforms
// at once and the correction has to be visible: the bundle lives on the agent-facing door, and the transport
// URL is that door.
enum DsseTrustBundleAddress {
    static func hostPort(host: String, port: Int) -> String {
        // An IPv6 literal is bracketed exactly once; hand-concatenation reliably gets this wrong.
        let h = host.contains(":") && !host.hasPrefix("[") ? "[\(host)]" : host
        return port > 0 ? "\(h):\(port)" : h
    }
}
