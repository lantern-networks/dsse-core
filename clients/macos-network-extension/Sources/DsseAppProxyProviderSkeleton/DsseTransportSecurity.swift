import CryptoKit
import Foundation
import Network
import Security

//  W4 (NE side): the (T) encrypted-transport contract + TLS parameter builder.
//
// The Edge publishes a `network_extension_transport` block in agent_config.json ():
//   { transport_tls_url, mtls_required, dns_over_tunnel_path, dns_over_tunnel_supported, pinned_ca_ref? }
// telling the NE to dial the Edge over the encrypted (T) tunnel, PIN the transport CA, optionally present
// a device client certificate (mTLS), and send DNS over the tunnel. When the block is absent the NE keeps
// the legacy plaintext dial (additive, non-breaking).
//
// Security posture is FAIL-CLOSED: TLS uses a custom verify block that trusts ONLY the pinned CA; if the
// pinned cert is missing/unparseable or the chain does not validate against it, the handshake is rejected.
// The actual handshake against a real Edge is a real-device verification step.

public struct DsseTransportContract: Decodable, Equatable, Sendable {
    public let transportTLSURL: String?
    public let mtlsRequired: Bool?
    public let dnsOverTunnelPath: String?
    public let dnsOverTunnelSupported: Bool?
    public let pinnedCARef: String?
    // LAB-only device-identity source: when set, the NE loads the mTLS client identity from a PKCS#12 file
    // (resolved relative to the agent-config directory) instead of the keychain. This lets a real device
    // present a device certificate WITHOUT MDM-provisioned keychain enrollment (which is the production
    // path). The passphrase is read from a sidecar file (client_identity_p12_pass_ref) so no secret is
    // persisted in the config itself. In production both fields are absent and the keychain/MDM path is used.
    public let clientIdentityP12Ref: String?
    public let clientIdentityP12PassRef: String?
    // The device name to look the keychain identity up by (production / MDM path). Needed because macOS labels
    // a certificate with its SUBJECT COMMON NAME, so the identity is filed under the device's own name — not
    // under a fixed product string. Without this the lookup has nothing specific to match and fails closed.
    //
    // WRITTEN AT PROVISIONING TIME, not published by the Edge. The Edge's agent config is a fleet-wide
    // snapshot and cannot carry a per-device value; the entity that INSTALLS the identity — the MDM payload or
    // the installer — is the one that knows which device this is, and is where this belongs.
    public let clientIdentityCommonName: String?
    // host:port of the Edge's renewal RECOVERY listener. Used ONLY when this device's certificate has already
    // expired: renewal authenticates with the certificate being renewed, so once it lapses the (T) handshake
    // cannot complete and the device cannot even ask to renew. Absent = no self-recovery after a long
    // shutdown; the device needs manual re-enrolment.
    public let renewalRecoveryEndpoint: String?

    enum CodingKeys: String, CodingKey {
        case transportTLSURL = "transport_tls_url"
        case mtlsRequired = "mtls_required"
        case dnsOverTunnelPath = "dns_over_tunnel_path"
        case dnsOverTunnelSupported = "dns_over_tunnel_supported"
        case pinnedCARef = "pinned_ca_ref"
        case clientIdentityP12Ref = "client_identity_p12_ref"
        case clientIdentityP12PassRef = "client_identity_p12_pass_ref"
        case clientIdentityCommonName = "client_identity_common_name"
        case renewalRecoveryEndpoint = "renewal_recovery_endpoint"
    }

    /// withTransportTLSURL returns this contract with a different door and everything else untouched.
    ///
    /// ★ THE DEPLOYMENT'S SIGNED PROFILE MOVES THE ADDRESS AND NOTHING ELSE. How this device proves itself and
    /// which anchor it pins the Edge against stay whatever it was installed with — see
    /// DsseInstallProfileApplication.applyTransport for why that boundary is where it is.
    public func withTransportTLSURL(_ url: String) -> DsseTransportContract {
        DsseTransportContract(transportTLSURL: url, mtlsRequired: mtlsRequired,
                              dnsOverTunnelPath: dnsOverTunnelPath,
                              dnsOverTunnelSupported: dnsOverTunnelSupported, pinnedCARef: pinnedCARef,
                              clientIdentityP12Ref: clientIdentityP12Ref,
                              clientIdentityP12PassRef: clientIdentityP12PassRef,
                              clientIdentityCommonName: clientIdentityCommonName,
                              renewalRecoveryEndpoint: renewalRecoveryEndpoint)
    }

    // enabled reports whether the (T) transport is configured (a TLS URL is present).
    public var enabled: Bool {
        guard let url = transportTLSURL?.trimmingCharacters(in: .whitespacesAndNewlines) else { return false }
        return !url.isEmpty
    }
}

// Resolved transport security: the pinned CA (public cert) and an optional device client identity, ready
// to build NWParameters. Materialized from the contract + the snapshot dir (pinned CA file) + the keychain.
/// dsseDescribeAnchor states what an anchor IS, in the terms that decide whether it can survive a
/// certificate replacement: its subject, its fingerprint, and whether it is a CA at all. An anchor that is
/// not a CA trusts exactly one certificate and nothing that certificate's issuer ever signs, so every
/// replacement fails against it — and from a count alone that is indistinguishable from a healthy pin.
/// DsseLiveTrustAnchors is the anchor set as it stands NOW, rather than as it stood when a tunnel driver was
/// constructed. Adoption happens while the extension runs, so a set captured at start-up is the one the device
/// was born with — on 2026-08-01 the tunnels were verifying against a single anchor from an older distribution
/// while the device had adopted two, and no replacement of the Edge's certificate could ever satisfy it.
/// The provider is installed once the contract and config directory are known; until then callers fall back to
/// whatever they were given, which is the previous behaviour exactly.
/// DsseTrustRefusalReporting carries the one thing the verify block cannot be handed: where this device keeps
/// its state. The block runs inside a TLS callback with no access to the provider's configuration, and the
/// alternative — threading a directory through every tunnel constructor — would put a reporting concern into
/// the datapath's signature.
public enum DsseTrustRefusalReporting {
    private static let lock = NSLock()
    nonisolated(unsafe) private static var directory: URL?

    public static func setConfigDirectory(_ url: URL) {
        lock.lock(); defer { lock.unlock() }
        directory = url
    }

    public static func configDirectory() -> URL? {
        lock.lock(); defer { lock.unlock() }
        return directory
    }
}

/// DsseLiveClientIdentity is the device identity as it stands NOW. A renewal replaces it while the extension
/// runs, and a connection built from a start-up snapshot would keep presenting the certificate that renewal
/// was meant to retire — which reads, from the Edge, as a device that never renewed.
public enum DsseLiveClientIdentity {
    private static let lock = NSLock()
    nonisolated(unsafe) private static var provider: (() -> SecIdentity?)?

    public static func setProvider(_ p: @escaping () -> SecIdentity?) {
        lock.lock(); defer { lock.unlock() }
        provider = p
    }

    /// nil means "cannot answer", never "no identity" — the caller keeps whatever it was given and stays
    /// fail-closed, exactly as before the provider existed.
    public static func current() -> SecIdentity? {
        lock.lock()
        let p = provider
        lock.unlock()
        return p?()
    }
}

public enum DsseLiveTrustAnchors {
    private static let lock = NSLock()
    nonisolated(unsafe) private static var provider: (() -> [SecCertificate])?

    public static func setProvider(_ p: @escaping () -> [SecCertificate]) {
        lock.lock(); defer { lock.unlock() }
        provider = p
    }

    /// current returns the live anchors, or nil when no provider is installed or it yields nothing. Nil means
    /// "cannot answer" and never means "trust nothing" — the caller keeps its own set and stays fail-closed.
    public static func current() -> [SecCertificate]? {
        lock.lock()
        let p = provider
        lock.unlock()
        guard let p else { return nil }
        let anchors = p()
        return anchors.isEmpty ? nil : anchors
    }
}

/// DsseLiveTransportServerName is the name this device should send as the TLS server name, as it stands NOW.
///
/// ★ ROADMAP D ON THE DEVICE SIDE. Every organization's devices verify the Edge with one shared anchor today,
/// so whoever holds it can impersonate the Edge to any of them. The way out is a certificate per organization,
/// and the only signal that can select one is the name sent in the ClientHello — a server must choose before
/// the client certificate arrives.
///
/// Read at HANDSHAKE time for the same reason the anchors are: a tunnel driver outlives several adoptions, and
/// the value it was built with stops being what this device should send the moment one lands.
///
/// Empty means what it has always meant — dial as before, with no name — and NEVER means "invent one".
public enum DsseLiveTransportServerName {
    private static let lock = NSLock()
    nonisolated(unsafe) private static var provider: (() -> String)?

    public static func setProvider(_ p: @escaping () -> String) {
        lock.lock(); defer { lock.unlock() }
        provider = p
    }

    public static func current() -> String {
        lock.lock()
        let p = provider
        lock.unlock()
        guard let p else { return "" }
        return p().trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    }

    /// ★ WHETHER THIS DEVICE HAS BEEN ASKED YET — which is a different fact from having no name.
    ///
    /// `current()` answers "" in both cases, and one of them is a deployment that serves one certificate to
    /// everybody while the other is the first seconds after start-up, before the provider is installed. Read
    /// as the same thing, a device probes its organization's door WITHOUT the organization's name, is served
    /// the deployment-wide certificate — correctly, the door picks by SNI — and finds that its own anchors do
    /// not validate it. That is not a refusal anybody should act on, and it was written in the same words as
    /// one that is.
    public static func hasBeenAsked() -> Bool {
        lock.lock(); defer { lock.unlock() }
        return provider != nil
    }
}

public func dsseDescribeAnchor(_ certificate: SecCertificate) -> String {
    let der = SecCertificateCopyData(certificate) as Data
    let fp = SHA256.hash(data: der).map { String(format: "%02x", $0) }.joined()
    let subject = (SecCertificateCopySubjectSummary(certificate) as String?) ?? "unknown"
    var isCA = "unknown"
    if let values = SecCertificateCopyValues(certificate, [kSecOIDBasicConstraints] as CFArray, nil) as? [CFString: Any],
       let bc = values[kSecOIDBasicConstraints] as? [CFString: Any],
       let entries = bc[kSecPropertyKeyValue] as? [[CFString: Any]] {
        isCA = "NO"
        for entry in entries {
            guard let label = entry[kSecPropertyKeyLabel] as? String,
                  label.localizedCaseInsensitiveContains("Certificate Authority"),
                  let value = entry[kSecPropertyKeyValue] as? String else { continue }
            isCA = value.localizedCaseInsensitiveContains("yes") ? "yes" : "NO"
        }
    }
    return "subject=\(subject) sha256=\(fp) is_ca=\(isCA)"
}

public struct DsseTransportSecurity: @unchecked Sendable {
    public let host: String
    public let port: Int
    public let mtlsRequired: Bool
    // Every CA this device will accept the Edge under. A LIST, not one certificate, because that is what makes
    // rotating the transport CA survivable — see pinnedCACertificates' note below.
    public let pinnedCACertificates: [SecCertificate]

    // The first pinned CA, for callers that only need one. Kept so existing code reads unchanged.
    public var pinnedCACertificate: SecCertificate? { pinnedCACertificates.first }

    // SHA-256 of every pinned CA, lower-case hex — reported to the Edge so an operator can see which devices
    // already hold the CA they are about to rotate to. A bundle here is the NORMAL mid-rotation state, and
    // reporting only the first would make a device that is ready look as though it were not.
    public var pinnedCAFingerprints: [String] {
        pinnedCACertificates.map { certificate in
            let der = SecCertificateCopyData(certificate) as Data
            return SHA256.hash(data: der).map { String(format: "%02x", $0) }.joined()
        }
    }
    public let clientIdentity: SecIdentity?

    /// dialHost is the host to put in a URL: THIS ORGANIZATION'S ANNOUNCED TRANSPORT NAME when the device can
    /// resolve it, and the address otherwise.
    ///
    /// ★★★ TEN CHANNELS DIALLED BY ADDRESS AND EACH ONE BROKE THE SAME WAY (2026-08-22, measured). URLSession
    /// sends the URL's host as the TLS server name and offers no way to send another, so every connection
    /// built from an address was served the DEPLOYMENT-WIDE certificate while the tunnel beside it sent
    /// lab.dsse.invalid and was served the organization's own. Harmless — until the shared anchor leaves that
    /// organization's bundle, which is the last step of roadmap D and the thing the enrolment fold exists to make
    /// safe. Then every one of those channels is refused, permanently:
    ///
    ///	transport_trust ★ REFUSED the Edge at 203.0.113.10 served=f007c441… — "Lantern DSSE Transport"
    ///	certificate_renewal FAILED error=requestFailed("cancelled")   ... retried in 21600s, for ever
    ///
    /// Four were moved to a name-carrying transport one at a time. That is not the answer, because the other
    /// six will break identically on the day somebody notices. THE ANSWER IS TO GIVE THE DEVICE ITS EDGE AS A
    /// NAME: then URLSession sends it without being asked, and every channel is correct at once.
    ///
    /// ★ AND IT FALLS BACK, because a name that does not resolve would take the fleet off the network in the
    /// name of correctness. A deployment whose organization has no name of its own, or a device that cannot
    /// resolve the one it was given, dials the address exactly as before. The decision is made once and said
    /// out loud, so "which one is this device using" is never a guess.
    /// TLS identity is independent of DNS reachability. Always dial `host` for control requests.
    public var controlServerName: String? {
        let name = DsseLiveTransportServerName.current()
        return name.isEmpty ? nil : name
    }

    public var dialHost: String {
        let name = DsseLiveTransportServerName.current().trimmingCharacters(in: .whitespacesAndNewlines)
        guard !name.isEmpty else { return host }
        return DsseDialHostDecision.resolves(name) ? name : host
    }


    public init(host: String, port: Int, mtlsRequired: Bool, pinnedCACertificates: [SecCertificate],
                clientIdentity: SecIdentity?) {
        self.host = host
        self.port = port
        self.mtlsRequired = mtlsRequired
        self.pinnedCACertificates = pinnedCACertificates
        self.clientIdentity = clientIdentity
    }

    public init(host: String, port: Int, mtlsRequired: Bool, pinnedCACertificate: SecCertificate?, clientIdentity: SecIdentity?) {
        self.host = host
        self.port = port
        self.mtlsRequired = mtlsRequired
        self.pinnedCACertificates = pinnedCACertificate.map { [$0] } ?? []
        self.clientIdentity = clientIdentity
    }

    // clientIdentityNotAfter is the device client certificate's expiry, or nil if there is no identity or the
    // notAfter cannot be read. This exists because resolve() fails closed on a MISSING identity but an EXPIRED
    // one resolves fine (the wire handshake is the first symptom — see the 2026-07-17 outage,
    // the transport health and fail-open design). Reading it lets the provider WARN before the
    // credential fails on the wire. Pure/read-only — it changes no connection behaviour.
    public var clientIdentityNotAfter: Date? {
        DsseTransportSecurityFactory.notAfter(ofClientIdentity: clientIdentity)
    }
}

public enum DsseTransportSecurityError: Error, Equatable {
    case invalidTransportURL
    case pinnedCAMissing
    case pinnedCAUnreadable
    case clientIdentityMissing
}

public enum DsseTransportSecurityFactory {
    // hostPort parses the transport_tls_url into (host, port). Requires https + explicit host + port.
    /// ★★★ A DOOR WITHOUT A PORT NUMBER IS THE ORDINARY CASE NOW (2026-08-29, measured on a real Mac).
    /// This used to REQUIRE an explicit port, and returned nil without one. The deployment's signed profile
    /// names its door as `https://agents.<region>.<zone>` — no port, because the agent plane was folded onto
    /// 443 — so every (T) resolution on a profile-installed device failed at this one guard. What that looked
    /// like on the machine: `no (T) transport contract`, and with it no device heartbeat (the Edge saw a device
    /// that was never there), no agent-policy poller, no region failover, and a runtime-copy transport that
    /// fell back to a plain URLSession whose App Transport Security refuses a private CA — 959 failed round
    /// trips and a Mac with no network, from a configuration that was correct in every field.
    ///
    /// https means 443 unless something says otherwise. That is what every other client on this path already
    /// did — the enrolment dial in the same process reached `agents.tokyo.hikari.lab:443` from the same string.
    public static func hostPort(fromTransportURL raw: String) -> (host: String, port: Int)? {
        guard let comps = URLComponents(string: raw.trimmingCharacters(in: .whitespacesAndNewlines)),
              comps.scheme?.lowercased() == "https",
              let host = comps.host, !host.isEmpty else {
            return nil
        }
        // An explicit port still wins, and an explicitly WRONG one is still refused rather than defaulted.
        if let explicit = comps.port {
            guard explicit > 0, explicit <= 65535 else { return nil }
            return (host, explicit)
        }
        return (host, 443)
    }

    // certificates(fromPEM:) parses EVERY certificate in a PEM bundle.
    //
    // ★ WHY A BUNDLE AND NOT ONE CERTIFICATE. Rotating the transport CA is the one change that can cut a fleet
    // off with no way back: the device pins the CA, so once it is replaced the device cannot verify the Edge,
    // and it cannot fetch the new CA because fetching happens over the tunnel it can no longer establish. The
    // standard answer is an overlap — publish the next CA, wait until every device has it, then start signing
    // with it — and that requires a device to trust TWO CAs at once.
    //
    // The previous parser stopped at the first END CERTIFICATE, so macOS could pin exactly one. That made
    // overlap impossible and turned any CA rotation into an immediate, total outage for every Mac, including
    // ones that were online at the time. The Windows client has always accepted a bundle
    // (x509.CertPool.AppendCertsFromPEM), so the two endpoints disagreed about something this consequential.
    public static func certificates(fromPEM pem: String) -> [SecCertificate] {
        var certificates: [SecCertificate] = []
        var base64 = ""
        var inCert = false
        for line in pem.split(whereSeparator: { $0 == "\n" || $0 == "\r" }) {
            if line.contains("BEGIN CERTIFICATE") { inCert = true; base64 = ""; continue }
            if line.contains("END CERTIFICATE") {
                inCert = false
                if let der = Data(base64Encoded: base64, options: [.ignoreUnknownCharacters]), !der.isEmpty,
                   let cert = SecCertificateCreateWithData(nil, der as CFData) {
                    certificates.append(cert)
                }
                // A malformed block is skipped rather than aborting the file: dropping the REST of a bundle
                // because one entry is bad is how an overlap silently becomes a single pin again.
                continue
            }
            if inCert { base64 += line }
        }
        return certificates
    }

    // certificate(fromPEM:) parses a single PEM CERTIFICATE block into a SecCertificate (the pinned CA).
    public static func certificate(fromPEM pem: String) -> SecCertificate? {
        let lines = pem.split(whereSeparator: { $0 == "\n" || $0 == "\r" })
        var base64 = ""
        var inCert = false
        for line in lines {
            if line.contains("BEGIN CERTIFICATE") { inCert = true; continue }
            if line.contains("END CERTIFICATE") { break }
            if inCert { base64 += line }
        }
        guard let der = Data(base64Encoded: base64, options: [.ignoreUnknownCharacters]), !der.isEmpty else {
            return nil
        }
        return SecCertificateCreateWithData(nil, der as CFData)
    }

    // clientIdentity(fromP12Data:passphrase:) loads a device client SecIdentity (cert + private key) from
    // a PKCS#12 blob. Used by the real-device probe / provisioning where the identity is delivered as a
    // file rather than pre-installed in the keychain. Returns nil on failure (fail closed).
    public static func clientIdentity(fromP12Data data: Data, passphrase: String) -> SecIdentity? {
        // ★ MEMORY ONLY, and this is the fix for a device that could not use its own identity (2026-08-10).
        //
        // On macOS SecPKCS12Import writes into a KEYCHAIN when no destination is given. That turns a
        // file-delivered bootstrap identity into a persistent keychain item — and a keychain item carries an
        // ACL naming the code that created it. Import the same p12 from a build with a different bundle id,
        // team or signing certificate and the call resolves to the item the PREVIOUS build owns, whose key
        // this process may not use. sec_identity_create then returns nil and the connection goes out with no
        // client certificate at all: the Edge answers "client didn't provide a certificate" while the device
        // has just logged the certificate's expiry from the very identity it cannot present.
        //
        // The bootstrap identity arrives as a FILE and is re-read whenever it is needed. It has no reason to be
        // persisted, and persisting it is precisely what binds it to one code identity. kSecImportToMemoryOnly
        // keeps it out of every keychain: no ACL, no collision with what an earlier build left behind, and the
        // key is usable by whoever imported it.
        //
        // Renewal is unaffected — it deliberately writes to the keychain (see DsseRenewedIdentityStore), which
        // is the right place for an identity this device MINTED. What was wrong was persisting one it was GIVEN.
        // macOS 15 named this constant (kSecImportToMemoryOnly); its underlying string is "memory", and the
        // literal is used so a deployment target below 15 gets the memory-only import too — gating on
        // #available would leave exactly the older fleet with the defect.
        //
        // ★ The literal was written as "toMemoryOnly" first, from the constant's NAME. It is "memory".
        // DssePKCS12MemoryOnlyKeyTests compares it against the framework constant for that reason: a guessed
        // string here fails silently by falling back to a keychain import, which is the whole defect returning.
        var options: [String: Any] = [
            kSecImportExportPassphrase as String: passphrase,
            "memory": kCFBooleanTrue as Any,
        ]
        var items: CFArray?
        let status = SecPKCS12Import(data as CFData, options as CFDictionary, &items)
        guard status == errSecSuccess,
              let array = items as? [[String: Any]],
              let first = array.first,
              let identity = first[kSecImportItemIdentity as String] else {
            // Named, because the previous version returned nil for every reason at once and the caller then
            // connected anonymously without anything saying why.
            dsseRuntimeLog("client_identity p12 import FAILED status=\(status) — the device has no usable "
                + "bootstrap identity and cannot present a client certificate")
            return nil
        }
        return (identity as! SecIdentity)
    }

    /// Can THIS process actually present the identity? Presence and usability are different facts, and the
    /// difference is invisible until the handshake: a key whose ACL names another code identity is readable as
    /// a certificate and refused as a signer. sec_identity_create is the same call the TLS options path makes,
    /// so this asks the question in exactly the form that matters.
    public static func clientIdentityIsUsable(_ identity: SecIdentity?) -> Bool {
        guard let identity else { return false }
        return sec_identity_create(identity) != nil
    }

    // notAfter(ofClientIdentity:) reads the identity certificate's validity notAfter, or nil if unavailable.
    // macOS-only (SecCertificateCopyValues); the value is a CFAbsoluteTime (seconds since 2001-01-01 UTC).
    public static func notAfter(ofClientIdentity identity: SecIdentity?) -> Date? {
        guard let identity else { return nil }
        var certificate: SecCertificate?
        guard SecIdentityCopyCertificate(identity, &certificate) == errSecSuccess, let certificate else {
            return nil
        }
        let keys = [kSecOIDX509V1ValidityNotAfter] as CFArray
        guard let values = SecCertificateCopyValues(certificate, keys, nil) as? [CFString: Any],
              let entry = values[kSecOIDX509V1ValidityNotAfter] as? [CFString: Any],
              let seconds = entry[kSecPropertyKeyValue] as? Double else {
            return nil
        }
        return Date(timeIntervalSinceReferenceDate: seconds)
    }

    // clientIdentity(label:) finds the device client SecIdentity (cert + private key) in the keychain.
    //
    // ★ THIS DOES NOT ASK THE KEYCHAIN TO FILTER, ON PURPOSE. Measured on macOS 15: kSecAttrLabel is IGNORED
    // for kSecClassIdentity queries — a query using a label that cannot match anything still returns EVERY
    // identity on the machine. The previous implementation passed kSecAttrLabel and took `result` as the
    // answer, so it returned an ARBITRARY identity: on this development Mac, the first one happens to be an
    // Apple Development signing identity. It has never misbehaved in the lab only because the lab uses the p12
    // path and MDM enrolment is not yet in service — the same shape as /enroll never having been switched on.
    // (docs/2026-07-28_macos_keychain_label_lookup_is_not_a_filter.ja.md)
    //
    // So the filtering happens here, over the attributes the query DOES return. Note what `label` means in
    // practice: macOS sets a certificate's label from its subject common name and ignores any label supplied
    // at add time, so for a device identity this is the DEVICE NAME, not a fixed product string.
    //
    // Ambiguity is resolved deterministically rather than arbitrarily: expired certificates are discarded, and
    // among what is left the most recently issued one wins. Several certificates for one device name is the
    // normal state after a re-issue, and picking the newest is the only choice that converges. A machine with
    // no match gets nil, so the caller fails closed — an mTLS-required Edge rejects the handshake, which is a
    // clear failure instead of a confusing one caused by presenting somebody else's certificate.
    public static func clientIdentity(label: String) -> SecIdentity? {
        let wanted = label.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !wanted.isEmpty else { return nil }

        var result: CFTypeRef?
        let status = SecItemCopyMatching([
            kSecClass as String: kSecClassIdentity,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnAttributes as String: true,
            kSecReturnRef as String: true,
        ] as CFDictionary, &result)
        guard status == errSecSuccess, let rows = result as? [[String: Any]] else { return nil }

        let now = Date()
        var candidates: [(identity: SecIdentity, notBefore: Date)] = []
        for row in rows {
            guard let ref = row[kSecValueRef as String] else { continue }
            let identity = ref as! SecIdentity
            var certificate: SecCertificate?
            guard SecIdentityCopyCertificate(identity, &certificate) == errSecSuccess,
                  let certificate else { continue }

            var cn: CFString?
            SecCertificateCopyCommonName(certificate, &cn)
            let attributeLabel = (row[kSecAttrLabel as String] as? String) ?? ""
            guard attributeLabel == wanted || (cn as String?) == wanted else { continue }

            // An expired certificate is worse than none: it resolves fine and then fails on the wire, which is
            // exactly how the 2026-07-17 outage presented.
            if let notAfter = DsseCertificateRenewal.notAfter(of: certificate), notAfter <= now { continue }
            candidates.append((identity, DsseCertificateRenewal.notBefore(of: certificate) ?? .distantPast))
        }
        guard !candidates.isEmpty else { return nil }
        return candidates.sorted { $0.notBefore > $1.notBefore }.first?.identity
    }
}

public enum DsseTransportSecurityResolver {
    // Default keychain label for the device identity certificate provisioned via MDM ().
    public static let defaultDeviceIdentityLabel = "Dsse Device Identity"

    // fallbackClientCertificatePEM is the certificate of the identity this device would ACTUALLY fall back
    // to if its current renewed identity stopped working: the previous renewed generation when one is held
    // and usable, else the bootstrap. Reported to the Edge as reverse telemetry so the CA that issues the
    // fallback cannot be retired from device trust while falling back remains possible — the report must
    // track the same order resolve() walks, or the gate protects the wrong CA.
    public static func fallbackClientCertificatePEM(contract: DsseTransportContract?, configDirectory: URL,
                                                    keychainLabel: String = defaultDeviceIdentityLabel) -> String? {
        if let previous = DsseRenewedIdentityStore.previousIdentity(configDirectory: configDirectory) {
            var certificate: SecCertificate?
            if SecIdentityCopyCertificate(previous, &certificate) == errSecSuccess, let certificate {
                return pemEncode(SecCertificateCopyData(certificate) as Data)
            }
        }
        return bootstrapClientCertificatePEM(contract: contract, configDirectory: configDirectory,
                                             keychainLabel: keychainLabel)
    }

    // bootstrapClientCertificatePEM is the certificate of the identity this device would FALL BACK to if its
    // renewed identity stopped working — resolve()'s bootstrap branch, skipping the renewed pointer on
    // purpose. Reported to the Edge as reverse telemetry so the CA that issues this fallback cannot be
    // retired from device trust while falling back remains possible: on 2026-08-02 exactly that retirement
    // happened, a pointer move-aside later put the bootstrap on the wire, and every handshake was refused.
    // A certificate only — public material this device presents on every fallback handshake anyway.
    public static func bootstrapClientCertificatePEM(contract: DsseTransportContract?, configDirectory: URL,
                                                     keychainLabel: String = defaultDeviceIdentityLabel) -> String? {
        guard let contract else { return nil }
        var identity: SecIdentity?
        if let p12Ref = contract.clientIdentityP12Ref?.trimmingCharacters(in: .whitespacesAndNewlines), !p12Ref.isEmpty {
            let p12URL = URL(fileURLWithPath: p12Ref, relativeTo: configDirectory)
            guard let p12Data = try? Data(contentsOf: p12URL) else { return nil }
            var passphrase = ""
            if let passRef = contract.clientIdentityP12PassRef?.trimmingCharacters(in: .whitespacesAndNewlines), !passRef.isEmpty {
                let passURL = URL(fileURLWithPath: passRef, relativeTo: configDirectory)
                if let raw = try? String(contentsOf: passURL, encoding: .utf8) {
                    passphrase = raw.trimmingCharacters(in: .whitespacesAndNewlines)
                }
            }
            identity = DsseTransportSecurityFactory.clientIdentity(fromP12Data: p12Data, passphrase: passphrase)
        } else {
            let selector = contract.clientIdentityCommonName?.trimmingCharacters(in: .whitespacesAndNewlines)
            identity = DsseTransportSecurityFactory.clientIdentity(label: (selector?.isEmpty == false) ? selector! : keychainLabel)
        }
        guard let identity else { return nil }
        var certificate: SecCertificate?
        guard SecIdentityCopyCertificate(identity, &certificate) == errSecSuccess, let certificate else { return nil }
        return pemEncode(SecCertificateCopyData(certificate) as Data)
    }

    // pemEncode wraps one DER certificate as PEM — certificate bodies only, never key material.
    static func pemEncode(_ der: Data) -> String {
        let body = der.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
        return "-----BEGIN CERTIFICATE-----\n" + body + "\n-----END CERTIFICATE-----\n"
    }

    // resolve materializes a DsseTransportSecurity from the published contract: parse host/port,
    // load the pinned CA (pinned_ca_ref resolved relative to the agent-config directory), and look up the
    // device client identity in the keychain. Returns nil when the contract is absent/disabled.
    // Fail-closed: a configured-but-unresolvable pin yields nil so the legacy plaintext dial is NOT used
    // silently — callers treat (T)-enabled + nil-security as a hard configuration error.
    // ★★★ AND THIS IS WHERE THE DEPLOYMENT'S SIGNED PROFILE REACHES THE WIRE (2026-08-28). Eight call sites
    // decode the (T) contract out of agent_config.json, and every one of them ends here — so the profile is
    // applied at the one place they share rather than at eight places that can drift. A caller that does not
    // know its agent-config path gets today's behaviour exactly: no path, no profile, local file governs.
    public static func resolve(contract: DsseTransportContract?, configDirectory: URL,
                               keychainLabel: String = defaultDeviceIdentityLabel,
                               agentConfigPath: String? = nil,
                               log: ((String) -> Void)? = nil) -> DsseTransportSecurity? {
        let profile = DsseInstallProfileApplication.inForce(agentConfigPath: agentConfigPath,
                                                            configDirectory: configDirectory, log: log)
        let contract = DsseInstallProfileApplication.applyTransport(to: contract, profile: profile)
        guard let contract, contract.enabled, let url = contract.transportTLSURL,
              let hp = DsseTransportSecurityFactory.hostPort(fromTransportURL: url) else {
            return nil
        }
        var pinnedCAs: [SecCertificate] = []
        // Anchors this device ADOPTED from a signed trust bundle win over the provisioned file. The provisioned
        // anchor is what the device was born with; it stops being current the moment the fleet rotates past it,
        // and a device that was switched off through the rotation has no other way to be told. Replacing rather
        // than adding is what makes a WITHDRAWAL possible — a union could only ever widen what is accepted, so a
        // compromised CA would stay trusted forever. Nothing reaches that store unverified.
        var anchorSource = "none"
        if let adopted = DsseAdoptedTrustAnchorStore.currentAnchors(configDirectory: configDirectory) {
            pinnedCAs = adopted
            anchorSource = "adopted"
        } else if let ref = contract.pinnedCARef?.trimmingCharacters(in: .whitespacesAndNewlines), !ref.isEmpty {
            anchorSource = "provisioned"
            let caURL = URL(fileURLWithPath: ref, relativeTo: configDirectory)
            if let pem = try? String(contentsOf: caURL, encoding: .utf8) {
                // EVERY certificate in the file: an operator preparing a CA rotation appends the next CA here,
                // and both must be accepted until the changeover is complete.
                pinnedCAs = DsseTransportSecurityFactory.certificates(fromPEM: pem)
            }
        }
        // Say what was resolved, every time — not only when a handshake is refused. The set used to VERIFY and
        // the set the device REPORTS are supposed to be the same certificates; on 2026-08-01 the Edge was told
        // two and the tunnel used one, and there was no way to see which was which from either side.
        dsseRuntimeLog("transport_trust anchors_resolved source=\(anchorSource) count=\(pinnedCAs.count) " +
                       "adopted_serial=\(DsseAdoptedTrustAnchorStore.lastAcceptedSerial(configDirectory: configDirectory))")
        for anchor in pinnedCAs {
            dsseRuntimeLog("transport_trust anchor \(dsseDescribeAnchor(anchor))")
        }

        // Device identity: prefer a LAB p12 file when the contract references one (no MDM/keychain needed),
        // otherwise fall back to the production keychain/MDM lookup by label. Fail-closed either way — a
        // missing identity yields nil so an mtls_required Edge rejects the handshake rather than silently
        // connecting without a client cert.
        // A RENEWED identity wins over the bootstrap one. The pointer file names the certificate automated
        // renewal last proved working, so once a device has renewed even once, this is the identity that must
        // be presented — the bootstrap p12 / MDM item is by then the older credential and heading for expiry.
        // Falling back when there is no pointer is what keeps a device that has never renewed working
        // unchanged. (docs/2026-07-28_macos_keychain_label_lookup_is_not_a_filter.ja.md explains why this is a
        // certificate fingerprint and not a keychain label.)
        var identity: SecIdentity? = DsseRenewedIdentityStore.currentIdentity(configDirectory: configDirectory)
        if identity != nil {
            return DsseTransportSecurity(
                host: hp.host, port: hp.port,
                mtlsRequired: contract.mtlsRequired ?? true,
                pinnedCACertificates: pinnedCAs, clientIdentity: identity
            )
        }
        // The PREVIOUS renewed generation before the bootstrap: proven for a whole renewal period and issued
        // by a current CA, where the bootstrap may be years old and chain to a CA the Edge has since retired
        // — the difference that turned a fallback into a refusal on 2026-08-02. previousIdentity logs which
        // tier is carrying the device; the bootstrap below stays as the day-0 floor.
        if let previous = DsseRenewedIdentityStore.previousIdentity(configDirectory: configDirectory) {
            return DsseTransportSecurity(
                host: hp.host, port: hp.port,
                mtlsRequired: contract.mtlsRequired ?? true,
                pinnedCACertificates: pinnedCAs, clientIdentity: previous
            )
        }
        if let p12Ref = contract.clientIdentityP12Ref?.trimmingCharacters(in: .whitespacesAndNewlines), !p12Ref.isEmpty {
            let p12URL = URL(fileURLWithPath: p12Ref, relativeTo: configDirectory)
            if let p12Data = try? Data(contentsOf: p12URL) {
                var passphrase = ""
                if let passRef = contract.clientIdentityP12PassRef?.trimmingCharacters(in: .whitespacesAndNewlines), !passRef.isEmpty {
                    let passURL = URL(fileURLWithPath: passRef, relativeTo: configDirectory)
                    if let raw = try? String(contentsOf: passURL, encoding: .utf8) {
                        passphrase = raw.trimmingCharacters(in: .whitespacesAndNewlines)
                    }
                }
                identity = DsseTransportSecurityFactory.clientIdentity(fromP12Data: p12Data, passphrase: passphrase)
            }
        } else {
            // Prefer the device name the contract publishes; fall back to the legacy label only when it is
            // absent. The fallback is kept so an existing deployment is not broken by this change, but it will
            // match nothing on a normally-provisioned machine and the caller then fails closed — which is the
            // correct outcome, and better than the arbitrary identity it used to return.
            let selector = contract.clientIdentityCommonName?.trimmingCharacters(in: .whitespacesAndNewlines)
            identity = DsseTransportSecurityFactory.clientIdentity(label: (selector?.isEmpty == false) ? selector! : keychainLabel)
        }
        return DsseTransportSecurity(
            host: hp.host, port: hp.port,
            mtlsRequired: contract.mtlsRequired ?? true,
            pinnedCACertificates: pinnedCAs, clientIdentity: identity
        )
    }
}

// DssePinnedURLSessionDelegate pins the (T) transport CA (fail-closed) and presents the device
// client identity (mTLS) for the half-duplex round-trip/session HTTP transports, so they ride the same
// encrypted tunnel as the full-duplex tunnel rather than falling back to plaintext when (T) is enabled.
public final class DssePinnedURLSessionDelegate: NSObject, URLSessionDelegate, URLSessionTaskDelegate, @unchecked Sendable {
    private let security: DsseTransportSecurity
    /// trustProvisionedAlongsideAdopted is set only for the enrolment bootstrap — see the note where it is
    /// read. Everywhere else the adopted set governs alone.
    private let trustProvisionedAlongsideAdopted: Bool
    /// withoutClientIdentity is set only for the enrolment bootstrap — the dial that PRODUCES this device's
    /// first certificate, and which therefore must present none.
    private let withoutClientIdentity: Bool
    /// identityOverride names the ONE certificate this connection may present. See makePinnedURLSession.
    private let identityOverride: SecIdentity?
    /// channel is WHICH of this agent's connections this session carries — "heartbeat", "region-endpoints",
    /// "agent-policy" and so on.
    ///
    /// ★★★ A REFUSAL THAT CANNOT NAME ITSELF COSTS AN HOUR (2026-09-05, measured from the Edge). Nine
    /// components build a pinned URLSession from this factory and the refusal every one of them records read
    ///
    ///	report channel to agents.singapore.sakura.lab: “Kaede Foods Root CA” certificate is not trusted
    ///
    /// — the same sentence whichever component it was, because "report channel" is a literal in one shared
    /// delegate. From the operator's side the record is precise about the host, the certificate and the
    /// reason, and says nothing about WHICH of nine periodic dials is failing; the device's own log was not
    /// readable from the machine either. So the fix that mattered first was not the routing: it was making
    /// the next refusal say where it came from.
    private let channel: String

    public init(security: DsseTransportSecurity, trustProvisionedAlongsideAdopted: Bool = false,
                withoutClientIdentity: Bool = false, identityOverride: SecIdentity? = nil,
                channel: String = "") {
        self.security = security
        self.trustProvisionedAlongsideAdopted = trustProvisionedAlongsideAdopted
        self.withoutClientIdentity = withoutClientIdentity
        self.identityOverride = identityOverride
        self.channel = channel.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// sayItRefused puts a refused handshake somewhere a person will find it: the provider log now, and the
    /// journal that travels to the Edge on the first connection that works. Best-effort — a refusal that
    /// cannot be written down must not make the failure worse.
    /// describe names a client identity the way an operator can match it against the Edge's records: the
    /// certificate's subject and the SHA-256 the deployment reports elsewhere. Not the private key, which is
    /// the part that must never be described.
    private static func describe(identity: SecIdentity) -> String {
        var certificate: SecCertificate?
        guard SecIdentityCopyCertificate(identity, &certificate) == errSecSuccess, let cert = certificate else {
            return "an identity whose certificate could not be read"
        }
        let subject = (SecCertificateCopySubjectSummary(cert) as String?) ?? "?"
        let der = SecCertificateCopyData(cert) as Data
        let sha = SHA256.hash(data: der).map { String(format: "%02x", $0) }.joined()
        return "\(subject) sha256=\(sha.prefix(16))…"
    }

    private static func sayItRefused(chain: [SecCertificate], host: String, reason: String, channel: String) {
        let served = chain.first.map { certificate -> String in
            let der = SecCertificateCopyData(certificate) as Data
            return SHA256.hash(data: der).map { String(format: "%02x", $0) }.joined()
        } ?? "(no certificate)"
        let named = channel.isEmpty ? "an unnamed channel" : channel
        dsseRuntimeLog("transport_trust ★ REFUSED the Edge at \(host) channel=\(named) served=\(served) — \(reason). "
            + "Nothing this agent sends over this channel reaches the Edge while this lasts, INCLUDING the "
            + "reports every readiness gate is measured from")
        if let dir = DsseTrustRefusalReporting.configDirectory() {
            DsseTrustRefusalJournal.record(servedChain: chain,
                                           reason: "\(named) to \(host): \(reason)",
                                           configDirectory: dir)
        }
    }

    // ★★★ SILENCE IS NOT AN ANSWER, AND ON THIS DIAL IT WAS THE ONLY ONE (2026-08-30, measured on a real Mac).
    //
    // Every report this agent sends over URLSession — the heartbeat above all — failed with a bare
    // NSURLErrorDomain -1200, and naming the error underneath it produced kCFErrorDomainCFNetwork/-1200: the
    // same code one layer down, which says nothing. What the log DID show, over eight hours, was that a
    // NSURLAuthenticationMethodClientCertificate challenge was never raised once, while the server-trust
    // challenge was raised every fifteen seconds and always accepted. Measured from the other end with
    // openssl, the Edge does send a CertificateRequest and does name this organization's Device Identity CA.
    //
    // So the device is being asked for a certificate and is never asking us which one to present. That is a
    // fact about CFNetwork's behaviour in this process, and no amount of reading our own code will settle it.
    // These counters and the metrics line below are here to say, on the failing dial itself: which challenges
    // arrived, what TLS version was negotiated, and whether the connection was even reused — the three things
    // that separate "we offered nothing" from "we offered and it was refused".
    private let tallyLock = NSLock()
    private var serverTrustChallenges = 0
    private var clientCertificateChallenges = 0
    private var otherChallenges = 0

    private func countChallenge(_ method: String) {
        tallyLock.lock()
        defer { tallyLock.unlock() }
        switch method {
        case NSURLAuthenticationMethodServerTrust: serverTrustChallenges += 1
        case NSURLAuthenticationMethodClientCertificate: clientCertificateChallenges += 1
        default: otherChallenges += 1
        }
    }

    private func tallyDescription() -> String {
        tallyLock.lock()
        defer { tallyLock.unlock() }
        return "server_trust_challenges=\(serverTrustChallenges) "
            + "client_certificate_challenges=\(clientCertificateChallenges) other_challenges=\(otherChallenges)"
    }

    public func urlSession(_ session: URLSession, task: URLSessionTask,
                           didFinishCollecting metrics: URLSessionTaskMetrics) {
        guard let last = metrics.transactionMetrics.last else { return }
        let host = task.originalRequest?.url?.host ?? "?"
        let tls = Self.tlsVersionName(last.negotiatedTLSProtocolVersion?.rawValue)
        let cipher = last.negotiatedTLSCipherSuite.map { String($0.rawValue) } ?? "-"
        let failed = task.error != nil
        // Only the failures, and the first success after one: a line every fifteen seconds about a channel
        // that works is how a log stops being read.
        guard failed || lastTaskFailed else { return }
        lastTaskFailed = failed
        let why = task.error.map { " error=\(($0 as NSError).domain)/\(($0 as NSError).code)" } ?? ""
        dsseRuntimeLog("transport_trust task_finished host=\(host) failed=\(failed) tls=\(tls) "
            + "cipher=\(cipher) reused=\(last.isReusedConnection) \(tallyDescription())\(why)")
    }

    private static func tlsVersionName(_ raw: UInt16?) -> String {
        guard let raw else { return "none_negotiated" }
        switch raw {
        case 0x0301: return "TLS1.0"
        case 0x0302: return "TLS1.1"
        case 0x0303: return "TLS1.2"
        case 0x0304: return "TLS1.3"
        default: return "0x" + String(raw, radix: 16)
        }
    }

    private var lastTaskFailed = true

    public func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                           completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        // ★★ SAY WHICH CHALLENGE, AND FOR WHERE (2026-08-29). The same bootstrap session succeeds outside the
        // system extension and fails inside it, and the only evidence was CFNetwork's own
        // "System Trust Evaluation yielded status(-9802)" — which is what it logs when THIS method hands the
        // decision back with .performDefaultHandling. Without knowing which challenge arrived, and whether
        // this method was reached at all, the two possibilities are indistinguishable.
        countChallenge(challenge.protectionSpace.authenticationMethod)
        dsseRuntimeLog("transport_trust challenge method=\(challenge.protectionSpace.authenticationMethod) "
            + "host=\(challenge.protectionSpace.host):\(challenge.protectionSpace.port) "
            + "provisioned=\(security.pinnedCACertificates.count) "
            + "live=\(DsseLiveTrustAnchors.current()?.count ?? -1) "
            + "union=\(trustProvisionedAlongsideAdopted) no_identity=\(withoutClientIdentity)")
        switch challenge.protectionSpace.authenticationMethod {
        case NSURLAuthenticationMethodServerTrust:
            // ★★★ AT HANDSHAKE TIME, NOT AT CONSTRUCTION (2026-08-22, measured — this device stopped reporting
            // for over two hours and nothing on either side said so).
            //
            // The tunnel path learned this on 2026-08-01: a connection built from a start-up snapshot keeps
            // verifying against the set the device was BORN with, while adoption moves on. This session — the
            // one the agent-policy poller reports over — was never given the same treatment, so it pinned the
            // anchors captured when the proxy started. The lab withdrew this organization's shared anchor,
            // this channel landed on the certificate that anchor signs, and the refusal became permanent: the
            // anchor came BACK minutes later and this session never re-read it.
            //
            // Live first, the captured set as the fallback — nil from the provider means "cannot answer" and
            // never "trust nothing", exactly as in makeTunnelParameters.
            // ★★★ THE ADOPTED SET DOES NOT SUPERSEDE THE PROVISIONED ONE WHILE THERE IS NO RELATIONSHIP YET
            // (2026-08-29; the Windows side reached the same rule from the other direction and states it more
            // generally: supersession is conditional on coverage).
            //
            // "Adopted beats provisioned" is right for a rotation and wrong for a STRANGER. A device carrying
            // a previous deployment's anchors — a re-provisioned machine, a lab box, anything reused — pins
            // this dial against an authority that has nothing to do with the deployment it is enrolling into,
            // and every attempt fails with a bare TLS error while the log says the anchors were adopted.
            //
            // Enrolment is the one dial where the device has no relationship to preserve: it is presenting a
            // one-time token an operator handed it with the profile, and the profile's anchors are that
            // operator's statement. So for THAT dial both sets are trusted. Everywhere else the live set
            // still wins alone, because withdrawing the shared anchor from an organization's bundle is the
            // whole point of that mechanism and a union would quietly undo it.
            let pinned: [SecCertificate]
            if trustProvisionedAlongsideAdopted {
                var union = security.pinnedCACertificates
                for live in DsseLiveTrustAnchors.current() ?? [] where !union.contains(live) {
                    union.append(live)
                }
                pinned = union
            } else {
                pinned = DsseLiveTrustAnchors.current() ?? security.pinnedCACertificates
            }
            guard let trust = challenge.protectionSpace.serverTrust, !pinned.isEmpty else {
                Self.sayItRefused(chain: [], host: challenge.protectionSpace.host,
                                  reason: "no pinned transport CA is available to verify the Edge against",
                                  channel: channel)
                completionHandler(.cancelAuthenticationChallenge, nil)
                return
            }
            SecTrustSetAnchorCertificates(trust, pinned as CFArray)
            SecTrustSetAnchorCertificatesOnly(trust, true)
            var evalError: CFError?
            if SecTrustEvaluateWithError(trust, &evalError) {
                completionHandler(.useCredential, URLCredential(trust: trust))
            } else {
                // ★★★ AND A REFUSAL THAT SAYS NOTHING IS THE SAME AS NO REFUSAL (2026-08-22). This branch was
                // a bare cancel. The device went on logging "reporting it anyway so the Edge does not lose
                // sight of this device" once a minute while every one of those reports was refused before a
                // byte was sent — so the agent looked healthy, the Edge saw a device that had not spoken
                // since midnight, and the only trace anywhere was a line in the EDGE's log that did not even
                // name which of its three listeners had been dialled.
                var chain: [SecCertificate] = []
                if let served = SecTrustCopyCertificateChain(trust) as? [SecCertificate] { chain = served }
                let why = (evalError as Error?)?.localizedDescription ?? "the served chain did not verify"
                Self.sayItRefused(chain: chain, host: challenge.protectionSpace.host, reason: why, channel: channel)
                completionHandler(.cancelAuthenticationChallenge, nil)
            }
        case NSURLAuthenticationMethodClientCertificate:
            // ★★★ THE DIAL THAT CREATES AN IDENTITY MUST NOT PRESENT ONE (2026-08-29, measured on a Mac
            // carrying identities from previous deployments). makeBootstrapSession says so in its own comment
            // — "No client identity: this is the request that produces one" — and passes nil. This branch
            // then looked the LIVE identity up and presented it anyway, so the device offered a certificate
            // from an authority the Edge has never heard of, the Edge sent a fatal alert, and enrolment
            // failed with -9802: a TLS error that says nothing about whose certificate was refused.
            //
            // Same shape as the anchors one directly above: what the device already had won over what it was
            // being provisioned with, on the one dial where it has no relationship yet.
            if withoutClientIdentity {
                completionHandler(.performDefaultHandling, nil)
                return
            }
            // The identity, live too, and for the same reason: a renewal that never reaches the wire is a
            // renewal the Edge cannot see.
            // ★★★ AND THE PROBE'S CANDIDATE, WHEN IT NAMES ONE (2026-08-30, measured on a real Mac).
            //
            // The hazard is written out above makeTunnelParameters — "reading the identity live … makes the
            // probe test the certificate ALREADY IN USE and report success about a candidate it never sent" —
            // and it was closed on the NW path with identityOverride. This delegate, which is what the
            // enrolment and renewal probe actually uses, kept reading it live.
            //
            // It produced the OTHER direction of the same defect. A Mac moved to a new deployment enrolled,
            // the Edge issued a certificate, and the probe then dialled with the certificate the device was
            // still holding — one from the deployment that had been destroyed the night before. The Edge
            // refused THAT, and a perfectly good new identity was rolled back for it:
            //
            //	enrolment certificate_renewal probe REJECTED the new identity — it was removed and the
            //	  existing certificate remains in force; renewal will be retried
            //
            // for ever, on every start, with the approval spent each time. A false pass and a false fail have
            // the same cause: a probe that does not send what it claims to be testing.
            // ★★★ AND IT SAYS WHICH CERTIFICATE IT SENT (2026-08-30). Every other decision in this file speaks;
            // this one — the one that chooses WHICH identity this device presents, and which the comment above
            // records as having caused both a false pass and a false fail — said nothing at all. So a channel
            // that was refused for presenting the wrong certificate, or for presenting none, produced only
            // "-1200: A TLS error caused the secure connection to fail" at the caller, and the device could
            // not be asked what it had offered. One channel on this Mac failed that way every minute for a
            // whole day while three others on the same host succeeded, and nothing anywhere could tell them
            // apart.
            let chosen = identityOverride ?? DsseLiveClientIdentity.current() ?? security.clientIdentity
            if let identity = chosen {
                let source = identityOverride != nil ? "override"
                    : (DsseLiveClientIdentity.current() != nil ? "live" : "provisioned")
                dsseRuntimeLog("transport_trust client_certificate host=\(challenge.protectionSpace.host):"
                    + "\(challenge.protectionSpace.port) presenting=\(Self.describe(identity: identity)) source=\(source)")
                completionHandler(.useCredential, URLCredential(identity: identity, certificates: nil, persistence: .forSession))
            } else {
                // Not an error here — some names ask for no certificate — but it IS the answer when the peer
                // then closes the connection, so it has to be visible.
                dsseRuntimeLog("transport_trust client_certificate host=\(challenge.protectionSpace.host):"
                    + "\(challenge.protectionSpace.port) presenting=NONE — this device holds no client identity "
                    + "to offer; if the peer requires one it will close the connection and the caller will see "
                    + "only a TLS error")
                completionHandler(.performDefaultHandling, nil)
            }
        default:
            completionHandler(.performDefaultHandling, nil)
        }
    }
}

public enum DsseTransportTLS {
    // makePinnedURLSession builds an ephemeral URLSession that pins the (T) transport CA and presents the
    // device client identity, for the round-trip/session transports over the encrypted tunnel.
    /// identityOverride is for the one caller that must not take the live identity: the probe that proves a
    /// newly issued certificate before anything selects it. Every other caller leaves it nil and keeps the
    /// live identity, which is what they need.
    public static func makePinnedURLSession(security: DsseTransportSecurity,
                                           trustProvisionedAlongsideAdopted: Bool = false,
                                           withoutClientIdentity: Bool = false,
                                           identityOverride: SecIdentity? = nil,
                                           tlsMaximum: tls_protocol_version_t? = nil,
                                           channel: String = "") -> URLSession {
        let configuration = URLSessionConfiguration.ephemeral
        // ★★★ WHY A CALLER WOULD EVER CAP THIS (2026-08-31, measured on a real Mac against a healthy
        // deployment, from both ends).
        //
        // Every report this agent sends over URLSession fails, while the tunnel — same device, same identity,
        // same anchors, built by makeTunnelParameters over NWConnection — carries traffic and polls policy
        // without a complaint. The instruments say why, and they agree:
        //
        //	transport_trust task_finished … tls=TLS1.3 server_trust_challenges=3
        //	                                client_certificate_challenges=0
        //	agent_report ★ REFUSED by the Edge status=401
        //
        // Server trust is asked for and accepted. A client-certificate challenge is NOT RAISED — not once in
        // eight hours of logs — so the delegate is never asked which certificate to present, the handshake
        // completes presenting none, and the Edge answers 401. Measured with openssl from this same Mac, the
        // Edge does send a CertificateRequest and does name this organization's Device Identity CA, so the
        // request to present one is on the wire and CFNetwork is not surfacing it.
        //
        // Capping the maximum version is how a caller TESTS that this is the TLS 1.3 client-certificate path,
        // because TLS 1.2 asks for the certificate during the handshake rather than after it. It is a
        // measurement, not a posture: it is passed by one caller, after failing, and it says so in the log.
        //
        // ★ THE DURABLE FIX IS NOT HERE. If this is what it looks like, these channels belong on the same
        // NWConnection transport the tunnel already uses successfully with this identity, rather than on a
        // URLSession that cannot be told to present one.
        if let tlsMaximum {
            configuration.tlsMaximumSupportedProtocolVersion = tlsMaximum
        }
        return URLSession(configuration: configuration,
                          delegate: DssePinnedURLSessionDelegate(security: security,
                                                                 trustProvisionedAlongsideAdopted: trustProvisionedAlongsideAdopted,
                                                                 withoutClientIdentity: withoutClientIdentity,
                                                                 identityOverride: identityOverride,
                                                                 channel: channel),
                          delegateQueue: nil)
    }

    // makeTunnelParameters builds NWParameters for the (T) tunnel: TCP_NODELAY + TLS that PINS the
    // transport CA (fail-closed verify block) and presents a device client identity when available.
    /// makeTunnelParameters with an explicit server name, for the one caller that must choose it rather than
    /// take the one this organization was announced: the expired-certificate recovery path, which is selected
    /// on the Edge BY that name (the enrolment fold). Everything else — identity, pinning, the fail-closed verify block —
    /// is the same code, because two ways of building this connection would be two security postures.
    public static func makeTunnelParameters(security: DsseTransportSecurity,
                                            serverNameOverride: String?) -> NWParameters {
        makeTunnelParameters(security: security, resolvedServerName: serverNameOverride)
    }

    /// ★★★ THE ONE CALLER THAT MUST NOT TAKE THE LIVE IDENTITY (2026-08-22). The renewal proves a newly issued
    /// certificate on the wire WHILE IT IS STILL INERT — nothing selects it until the pointer names it — and
    /// that is the only safety net between "the Edge issued something" and "this device starts presenting it".
    /// Reading the identity live, which every other connection must do, makes the probe test the certificate
    /// ALREADY IN USE and report success about a candidate it never sent. The probe therefore says which
    /// identity it means, and is the only thing that may.
    public static func makeTunnelParameters(security: DsseTransportSecurity, serverNameOverride: String?,
                                            identityOverride: SecIdentity?,
                                            presentClientIdentity: Bool = true) -> NWParameters {
        makeTunnelParameters(security: security, resolvedServerName: serverNameOverride,
                             identityOverride: identityOverride,
                             presentClientIdentity: presentClientIdentity)
    }

    private static let announcedServerNameLock = NSLock()
    private nonisolated(unsafe) static var lastAnnouncedServerName = ""

    public static func makeTunnelParameters(security: DsseTransportSecurity) -> NWParameters {
        makeTunnelParameters(security: security, resolvedServerName: nil)
    }

    private static func makeTunnelParameters(security: DsseTransportSecurity,
                                             resolvedServerName: String?,
                                             identityOverride: SecIdentity? = nil,
                                             presentClientIdentity: Bool = true) -> NWParameters {
        let tcpOptions = NWProtocolTCP.Options()
        tcpOptions.noDelay = true

        let tlsOptions = NWProtocolTLS.Options()
        let secOptions = tlsOptions.securityProtocolOptions
        sec_protocol_options_set_min_tls_protocol_version(secOptions, .TLSv12)

        // ★ THE NAME THIS ORGANIZATION'S DEVICES ARE TOLD TO SEND (roadmap D). Announced in the signed trust
        // bundle and derived by the Edge from the certificate it actually serves this organization, so it
        // cannot ask for something nobody has. Empty is the ordinary state and dials exactly as before.
        //
        // Setting it also makes the trust evaluation below check the certificate AGAINST that name, which is
        // the point: the certificate is issued for it. Without a name, this device connects to an address and
        // accepts whatever certificate the pinned CA signed for anybody.
        // The caller's name when it gave one (recovery), else the one this organization was announced.
        let announcedServerName = (resolvedServerName?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased())
            ?? DsseLiveTransportServerName.current()
        if !announcedServerName.isEmpty {
            sec_protocol_options_set_tls_server_name(secOptions, announcedServerName)
            // ★ ON CHANGE, NOT ON EVERY DIAL. The region probe now builds its parameters here too, once per
            // region every ten seconds, and a line that repeats twelve times a minute is a line nobody reads.
            // What is worth a log entry is the name CHANGING — an organization being served under a different
            // certificate is exactly the event this line exists to date. This is a SUCCESS being collapsed;
            // failures are never collapsed (see DsseDeviceHeartbeat for what that costs).
            announcedServerNameLock.lock()
            let changed = announcedServerName != lastAnnouncedServerName
            lastAnnouncedServerName = announcedServerName
            announcedServerNameLock.unlock()
            if changed {
                dsseRuntimeLog("transport_server_name sending \(announcedServerName) — this organization is "
                    + "served its own certificate under that name")
            }
        }

        // mTLS: present the device client identity, resolved at HANDSHAKE time.
        //
        // Same defect the anchors had, one field over. A renewal writes a new identity and updates the
        // pointer that names it, but a driver built at start-up keeps handing the old certificate to every
        // connection — so the device believes it has renewed (not_due, 59 days) while the Edge keeps
        // observing the certificate it replaced (58 days). Measured on 2026-08-02: exactly one day apart,
        // which is the renewal that did happen and never reached the wire.
        // ★ A FAILURE HERE USED TO BE SILENCE, and it cost hours on 2026-08-10.
        //
        // This was one `if let` covering both steps: no identity, or an identity `sec_identity_create` refuses,
        // and the block was simply skipped. The connection then went out with NO CLIENT CERTIFICATE — an mTLS
        // Edge answers `tls: client didn't provide a certificate` and the device reports only "a TLS error
        // caused the secure connection to fail". Every layer above believed it had an identity: the provider
        // had logged `client_identity_not_after=… days_remaining=51` from the very certificate that never
        // reached the wire.
        //
        // sec_identity_create returns nil when the private key is not USABLE by this process — which is exactly
        // what happens when the key's ACL names a different code identity (a rebrand, a re-sign, a new team).
        // So the one condition that most needs to be reported was the one turned into a no-op.
        //
        // Now: say which of the two failed, and do not pretend to have an identity. The connection still
        // proceeds — the Edge is the authority on whether an anonymous client is acceptable, and failing the
        // handshake here as well would only replace a clear server-side refusal with a client-side guess — but
        // it can no longer happen without a line naming it.
        // ★★★ AND THERE HAS TO BE A WAY TO SAY "PRESENT NOTHING" (2026-08-30, measured on a real Mac).
        //
        // The enrolment dial passes clientIdentity: nil, with a comment saying exactly why — "this is the
        // request that PRODUCES one, and offering whatever this device happens to hold, including a certificate
        // from a deployment it is no longer part of, is what made the Edge send a fatal alert". That nil was
        // then overwritten one line down by DsseLiveClientIdentity.current(), which is the whole point of this
        // resolution order for every OTHER connection. So the enrolment presented yesterday's certificate:
        //
        //	agent-plane TLS handshake error: x509: certificate signed by unknown authority   (the Edge)
        //	enrolment_error=request_failed … transport: receive: -9831: unknown Cert Authority (the Mac)
        //
        // A device moving to a new deployment could therefore never enrol: the credential that makes it need a
        // new one is the credential it presents while asking. nil could not express this, because nil already
        // means "I have no preference"; withholding is a decision and needs its own word.
        let liveIdentity: SecIdentity? = presentClientIdentity
            ? (identityOverride ?? DsseLiveClientIdentity.current() ?? security.clientIdentity)
            : nil
        if !presentClientIdentity {
            dsseRuntimeLog("client_identity WITHHELD — this connection deliberately presents no client "
                + "certificate. It is the request that produces one, and offering a certificate this "
                + "deployment cannot verify is refused at the handshake before it can be asked for.")
        } else if liveIdentity == nil {
            dsseRuntimeLog("client_identity ABSENT — connecting with NO client certificate. An mTLS Edge will "
                + "refuse this with \"client didn't provide a certificate\".")
        } else if let live = liveIdentity, let secIdentity = sec_identity_create(live) {
            sec_protocol_options_set_local_identity(secOptions, secIdentity)
        } else {
            dsseRuntimeLog("client_identity UNUSABLE — a certificate is present but sec_identity_create refused "
                + "it, which means this process cannot use its PRIVATE KEY (the key's ACL names a different code "
                + "identity — a rebrand, a re-sign or a new team will do it). Connecting with NO client "
                + "certificate; an mTLS Edge will refuse this. The device needs its identity re-provisioned.")
        }

        // Server-cert pinning: trust ONLY the pinned CA. Fail closed if the pin is missing or the chain
        // does not validate against it.
        let fallbackPinned = security.pinnedCACertificates
        sec_protocol_options_set_verify_block(secOptions, { _, secTrust, complete in
            // Read the anchors at HANDSHAKE time. A tunnel driver outlives several adoptions, and the set it
            // was built with stops being what this device trusts the moment one lands.
            let pinned = DsseLiveTrustAnchors.current() ?? fallbackPinned
            guard !pinned.isEmpty else {
                complete(false) // no pin available -> reject (fail closed)
                return
            }
            let trust = sec_trust_copy_ref(secTrust).takeRetainedValue()
            // Anchor evaluation to the pinned CAs only — ALL of them, so a device mid-rotation accepts the
            // Edge under either the outgoing or the incoming CA.
            SecTrustSetAnchorCertificates(trust, pinned as CFArray)
            SecTrustSetAnchorCertificatesOnly(trust, true)
            var error: CFError?
            let ok = SecTrustEvaluateWithError(trust, &error)
            if !ok {
                // Say WHY, once per refusal. A device that silently declines to trust its Edge is
                // indistinguishable from a device that is switched off, which is how a bad certificate
                // replacement becomes an unexplainable outage (2026-07-31).
                let reason = error.map { CFErrorCopyDescription($0) as String } ?? "unknown"
                let served = SecTrustGetCertificateCount(trust)
                dsseRuntimeLog("transport_trust REFUSED chain_length=\(served) anchors=\(pinned.count) reason=\(reason)")
                // WHICH anchors, not just how many. A count cannot distinguish "anchored on the right CA" from
                // "anchored on the certificate the Edge happens to be serving today", and those two states look
                // identical until the certificate is replaced — at which point one of them cuts the fleet off.
                // Three live replacements on 2026-08-01 narrowed it to that question and could not answer it.
                for anchor in pinned {
                    dsseRuntimeLog("transport_trust anchor \(dsseDescribeAnchor(anchor))")
                }
                // Write it down. The Edge cannot be told now — this refusal IS the reason there is no
                // connection to tell it over — so it is kept and shipped when one comes back.
                if let dir = DsseTrustRefusalReporting.configDirectory() {
                    var chain: [SecCertificate] = []
                    if #available(macOS 12.0, *) {
                        chain = (SecTrustCopyCertificateChain(trust) as? [SecCertificate]) ?? []
                    }
                    DsseTrustRefusalJournal.record(servedChain: chain, reason: reason, configDirectory: dir)
                }
            }
            complete(ok)
        }, DispatchQueue(label: "dsse.transport-tls-verify"))

        return NWParameters(tls: tlsOptions, tcp: tcpOptions)
    }
}
