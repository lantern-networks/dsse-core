import Foundation
import Security
import CryptoKit

// Day-0 enrolment: how a Mac that has never had a device certificate gets one.
//
// Until now it did not. The lab's identity was placed on the machine by hand, and the renewal path — which is
// well covered — only works once a certificate already exists, because it authenticates with that certificate.
// So the product could rotate an identity it could not issue. This closes that.
//
// The credential presented here is an ADMIN-ISSUED, ONE-TIME token. It authorises a MACHINE, not a person: an IT
// admin images a batch of laptops before knowing who will use them, so requiring a login at install time fights
// the actual operation. The person is authenticated later, at access, by the IdP. See
// docs/enrolment_authority_design.ja.md.
//
// The private key is generated HERE and never leaves the device. That is why the installer config carries a token
// and not a certificate: shipping a certificate would mean an admin generated this machine's private key, putting
// it outside the machine and foreclosing hardware binding (#13/#31) later.
public enum DsseDeviceEnrolmentError: Error, Equatable {
    case notConfigured(String)
    case unpinnedTransport
    case requestFailed(String)
    case serverRefused(status: Int, message: String)
    case responseUnusable(String)
    case caPinMismatch(expected: String, got: String)
}

// The parts of the install config that drive enrolment. Written by whoever prepares the installer; read once.
public struct DsseEnrolmentConfig: Equatable, Sendable {
    public let enrolURL: String       // https://<edge>:<port>/enroll
    public let deviceID: String       // the name this machine will carry
    public let token: String          // the admin-issued one-time secret
    public let tenant: String         // advisory only — the Edge is authoritative and ignores it
    public let enrolCAPEM: String     // CA to verify the enrol endpoint's TLS against
    /// serverName is the name this device puts in the ClientHello when it enrols, which on a folded transport
    /// port is what SELECTS the enrolment route rather than merely labelling it. Empty means the address is
    /// used, which is what a deployment with no per-organization name wants.
    public var serverName: String = ""
    public let deviceCAPinSHA256: String // SHA-256 of the device CA the response must carry

    public init(enrolURL: String, deviceID: String, token: String, tenant: String = "",
                enrolCAPEM: String = "", deviceCAPinSHA256: String = "", serverName: String = "") {
        self.enrolURL = enrolURL
        self.deviceID = deviceID
        self.token = token
        self.tenant = tenant
        self.enrolCAPEM = enrolCAPEM
        self.deviceCAPinSHA256 = deviceCAPinSHA256
        self.serverName = serverName
    }

    public var isPresent: Bool {
        !enrolURL.trimmed.isEmpty && !deviceID.trimmed.isEmpty && !token.trimmed.isEmpty
    }

    // Enrolment is the trust BOOTSTRAP, so it must not run over a channel this device cannot verify. With neither
    // a CA to pin the enrol endpoint to NOR a device-CA pin to cross-check the response against, the request
    // would fall back to the system root store and anyone who can MITM it could impersonate the control plane —
    // and hand this machine an identity from a CA of their choosing. Require at least one. The Windows agent
    // enforces the same invariant; a device that enrols differently per platform is a device with two trust
    // stories.
    public var hasPinnedBootstrap: Bool {
        !enrolCAPEM.trimmed.isEmpty || !deviceCAPinSHA256.trimmed.isEmpty
    }
}

public enum DsseDeviceEnrolment {
    // Reads the enrolment section of the agent config. Absent is not an error here — a machine that already
    // holds an identity has no enrolment block, and one that never had a token is refused by the caller with a
    // message about the token, not about JSON.
    public static func readConfig(at path: String) -> DsseEnrolmentConfig? {
        guard let data = FileManager.default.contents(atPath: path),
              let root = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else {
            return nil
        }
        let block = (root["enrolment"] as? [String: Any]) ?? root
        let config = DsseEnrolmentConfig(
            enrolURL: (block["enrol_url"] as? String) ?? (block["enroll_url"] as? String) ?? "",
            deviceID: (block["device_id"] as? String) ?? (root["client_identity_common_name"] as? String) ?? "",
            token: (block["enrolment_token"] as? String) ?? (block["enrollment_token"] as? String) ?? "",
            tenant: (block["tenant"] as? String) ?? "",
            enrolCAPEM: (block["enrol_ca_pem"] as? String) ?? (block["enroll_ca_pem"] as? String) ?? "",
            deviceCAPinSHA256: (block["device_ca_pin_sha256"] as? String) ?? "",
            serverName: (block["enrolment_server_name"] as? String)
                ?? (root["network_extension_enrolment_server_name"] as? String) ?? "")
        return config.isPresent ? config : nil
    }

    // Removes the token from the config file once it has been spent.
    //
    // The token is one-time on the server, so leaving it behind cannot enrol a second machine — but it is still a
    // credential sitting in a world-readable-ish file for no remaining purpose, and an operator reading the file
    // months later cannot tell whether it is live. Erase what is no longer needed. Best-effort: a machine that
    // enrolled successfully must not be failed because its config file could not be rewritten.
    @discardableResult
    public static func eraseSpentToken(at path: String) -> Bool {
        guard let data = FileManager.default.contents(atPath: path),
              var root = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else {
            return false
        }
        var changed = false
        for key in ["enrolment_token", "enrollment_token"] {
            if root[key] != nil { root[key] = nil; changed = true }
            if var block = root["enrolment"] as? [String: Any], block[key] != nil {
                block[key] = nil
                block["enrolment_token_spent"] = true
                root["enrolment"] = block
                changed = true
            }
        }
        guard changed,
              let out = try? JSONSerialization.data(withJSONObject: root, options: [.prettyPrinted, .sortedKeys]),
              (try? out.write(to: URL(fileURLWithPath: path), options: .atomic)) != nil else {
            return false
        }
        return true
    }

    // enrol obtains this device's FIRST certificate.
    //
    // It mirrors renewal deliberately — same CSR builder, same validation, same clean-up-the-key-on-every-failure
    // discipline — because the ways an issued certificate can be unusable do not depend on which endpoint issued
    // it. The differences are that there is no client certificate to authenticate with (this is the endpoint that
    // creates one) and that a token is presented instead.
    public static func enrol(config: DsseEnrolmentConfig,
                             session: URLSession? = nil,
                             timeout: TimeInterval = 30) throws -> DsseRenewedIdentity {
        guard config.isPresent else {
            throw DsseDeviceEnrolmentError.notConfigured("enrol_url, device_id and enrolment_token are all required")
        }
        guard config.hasPinnedBootstrap else {
            throw DsseDeviceEnrolmentError.unpinnedTransport
        }
        guard let url = URL(string: config.enrolURL.trimmed) else {
            throw DsseDeviceEnrolmentError.notConfigured("enrol_url is not a URL")
        }

        let (key, tag) = try DsseCertificateRenewal.generateDeviceKey()
        // The key is in the keychain from here, so every exit has to clean it up. #23 taught this the hard way:
        // failed attempts that leave key material behind accumulate device identities nobody prunes.
        var keep = false
        defer { if !keep { DsseCertificateRenewal.deleteKey(tag: tag) } }

        let csrPEM = try DsseCertificateRenewal.certificateSigningRequestPEM(privateKey: key,
                                                                            commonName: config.deviceID.trimmed)
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONSerialization.data(withJSONObject: [
            "device_id": config.deviceID.trimmed,
            "tenant": config.tenant.trimmed,
            "csr_pem": csrPEM,
            "eligibility": ["mode": "token", "token": config.token.trimmed],
        ])
        request.timeoutInterval = timeout

        // ★★★ NOT URLSession, INSIDE A SYSTEM EXTENSION (2026-08-29, measured: the identical session succeeds
        // in an ordinary process on the same machine and fails in the provider).
        //
        // The delegate was reached, approved two provisioned anchors and refused nothing — and CFNetwork
        // logged "System Trust Evaluation yielded status(-9802)" and cancelled anyway. App Transport Security
        // judges by the SYSTEM trust store, and a deployment's own authority is deliberately not in it. The
        // extension declares no ATS exception and should not have to: everything else it sends to the Edge
        // already goes over a pinned NWConnection with this deployment's own verify block.
        //
        // ★ AND THIS FILE'S NEIGHBOUR RECORDS THE SAME DEFECT ONCE BEFORE. DsseSingleRequestOverNW exists
        // because the agent-policy poller went over URLSession, "which sends the URL's host as the server name
        // and offers no way to send another" — so it dialled without its organization's name. Enrolment was
        // the same mistake one file over, and moving it here fixes both halves at once: ATS is not consulted,
        // and the enrolment name the profile states is what goes in the ClientHello.
        let (data, status, transportError) = Self.send(request: request, config: config, timeout: timeout,
                                                       overrideSession: session)
        if let transportError {
            throw DsseDeviceEnrolmentError.requestFailed(transportError)
        }
        let decoded = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] ?? [:]
        guard status == 200 else {
            // The Edge answers every eligibility refusal with one sentence on purpose, so this message says
            // "invalid or missing eligibility token" whether the token was never issued, already spent, expired,
            // or revoked. The operator's answer is in the Edge log, and the admin's answer is the Console's token
            // list. Do not invent a more specific reason here from a status code.
            throw DsseDeviceEnrolmentError.serverRefused(
                status: status, message: (decoded["error"] as? String) ?? "no error message")
        }
        guard let certPEM = decoded["cert_pem"] as? String, !certPEM.isEmpty else {
            throw DsseDeviceEnrolmentError.responseUnusable("response carried no cert_pem")
        }
        let caPEM = (decoded["ca_pem"] as? String) ?? ""

        // Cross-check the issuing CA against the pin from the install profile, when one was given. This is what
        // makes an enrolment over a transport we could not otherwise verify safe: even if the endpoint were
        // impersonated, an identity from the wrong CA is refused here rather than installed.
        if !config.deviceCAPinSHA256.trimmed.isEmpty {
            let expected = config.deviceCAPinSHA256.trimmed.lowercased()
            let got = deviceCAFingerprint(caPEM: caPEM)
            guard got == expected else {
                throw DsseDeviceEnrolmentError.caPinMismatch(expected: expected, got: got)
            }
        }

        let identity = try DsseCertificateRenewal.validate(certificatePEM: certPEM,
                                                          caPEM: caPEM,
                                                          privateKey: key,
                                                          privateKeyTag: tag,
                                                          expectedCommonName: config.deviceID.trimmed)
        keep = true
        return identity
    }

    // send puts the enrolment request on the wire over a pinned NWConnection, presenting the enrolment name
    // when the profile states one. A caller that supplied its own URLSession — the tests — keeps that path.
    static func send(request: URLRequest, config: DsseEnrolmentConfig, timeout: TimeInterval,
                     overrideSession: URLSession?) -> (Data, Int, String?) {
        if let overrideSession {
            return DsseCertificateRenewal.synchronousData(for: request, session: overrideSession, timeout: timeout)
        }
        guard let (host, port) = hostPort(config.enrolURL), let url = URL(string: config.enrolURL.trimmed) else {
            return (Data(), 0, "enrol_url is not a URL")
        }
        let anchors = DsseSignedTrustBundle.parseAnchors(config.enrolCAPEM.trimmed)
        if anchors.isEmpty {
            dsseRuntimeLog("enrolment bootstrap UNPINNED: enrol_ca_pem yielded no certificate authority, so "
                + "this dial cannot verify the endpoint that issues this device's identity")
        }
        // No client identity: this is the request that PRODUCES one, and offering whatever this device happens
        // to hold — including a certificate from a deployment it is no longer part of — is what made the Edge
        // send a fatal alert.
        let security = DsseTransportSecurity(host: host, port: port, mtlsRequired: false,
                                             pinnedCACertificates: anchors, clientIdentity: nil)
        let name = config.serverName.trimmed
        dsseRuntimeLog("enrolment bootstrap dialling \(host):\(port) as "
            + "\(name.isEmpty ? "(the address)" : name) pinned to \(anchors.count) authority(ies)")
        do {
            // presentClientIdentity: false — and it has to be said, because passing clientIdentity: nil above
            // is NOT enough: every connection resolves the device's live identity when the caller expresses no
            // preference, which is right everywhere except here. See the note in makeTunnelParameters.
            let response = try DsseSingleRequestOverNW.post(host: host, port: port,
                                                            serverName: name.isEmpty ? nil : name,
                                                            path: url.path.isEmpty ? "/enroll" : url.path,
                                                            body: request.httpBody ?? Data(),
                                                            security: security, timeout: timeout,
                                                            presentClientIdentity: false)
            return (response.body, response.status, nil)
        } catch {
            return (Data(), 0, providerNonsecretErrorDetail(error))
        }
    }

    // The bootstrap session pins the enrol endpoint to the CA from the install profile when there is one. With
    // only a device-CA pin configured the session falls back to the system trust store and the pin above is what
    // protects the outcome — which is why hasPinnedBootstrap demands at least one of the two.
    static func makeBootstrapSession(config: DsseEnrolmentConfig) -> URLSession {
        // ★★★ IT SAYS WHETHER IT PINNED, ON EVERY PATH (2026-08-29, after an enrolment failed with a bare TLS
        // error and it took a round trip to the machine to learn which of three reasons it was).
        //
        // Falling back to an unpinned session is a real and correct behaviour — a deployment may configure
        // only a device-CA pin, and hasPinnedBootstrap allows that — but it is INVISIBLE. The failure that
        // follows is "A TLS error caused the secure connection to fail", which is what a wrong anchor, a
        // missing anchor and an unparseable one all look like from outside.
        let pem = config.enrolCAPEM.trimmed
        guard !pem.isEmpty else {
            dsseRuntimeLog("enrolment bootstrap UNPINNED: the configuration names no enrol_ca_pem, so the "
                + "endpoint that issues this device's identity is verified against the SYSTEM trust store. "
                + "A deployment's own authority is not in it, so this dial fails unless a device-CA pin is "
                + "what protects the outcome")
            return URLSession(configuration: .ephemeral)
        }
        let anchors = DsseSignedTrustBundle.parseAnchors(pem)
        guard let (host, port) = hostPort(config.enrolURL), !anchors.isEmpty else {
            dsseRuntimeLog("enrolment bootstrap UNPINNED: enrol_ca_pem holds "
                + "\(pem.components(separatedBy: "BEGIN CERTIFICATE").count - 1) certificate(s) and "
                + "\(anchors.count) of them are certificate AUTHORITIES; enrol_url=\(config.enrolURL). "
                + "A leaf is dropped rather than tolerated — an anchor set is not a place for one")
            return URLSession(configuration: .ephemeral)
        }
        dsseRuntimeLog("enrolment bootstrap pinned to \(anchors.count) authority(ies) for \(host):\(port)")
        // No client identity: this is the request that produces one.
        let security = DsseTransportSecurity(host: host, port: port, mtlsRequired: false,
                                             pinnedCACertificates: anchors, clientIdentity: nil)
        // The one dial where the profile's anchors are trusted ALONGSIDE whatever this device adopted from a
        // previous relationship — see the note in DssePinnedURLSessionDelegate.
        return DsseTransportTLS.makePinnedURLSession(security: security,
                                                    trustProvisionedAlongsideAdopted: true,
                                                    withoutClientIdentity: true, channel: "enrolment")
    }

    static func hostPort(_ raw: String) -> (String, Int)? {
        guard let comps = URLComponents(string: raw.trimmed),
              let host = comps.host, !host.isEmpty else { return nil }
        return (host, comps.port ?? 443)
    }

    // SHA-256 of the FIRST certificate in the returned ca_pem, lower-case hex — the same shape the Windows agent
    // pins with, so one profile can carry one pin for both platforms.
    static func deviceCAFingerprint(caPEM: String) -> String {
        guard let certificate = DsseSignedTrustBundle.parseAnchors(caPEM).first else { return "" }
        let der = SecCertificateCopyData(certificate) as Data
        return SHA256.hash(data: der).map { String(format: "%02x", $0) }.joined()
    }
}

private extension String {
    var trimmed: String { trimmingCharacters(in: .whitespacesAndNewlines) }
}
