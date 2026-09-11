import Foundation
import Security

// DsseCertificateRenewal — the endpoint half of automated device-certificate renewal.
//
// WHY THIS HAS TO EXIST: POST /enroll issues device certificates with a 60-day TTL and its own flag text
// promises they are "re-issued before expiry", but until now nothing performed that re-issue. Enrolling a real
// fleet in that state puts every device into a simultaneous mTLS failure on day 60. The same class of outage
// already happened here once with a 30-day leaf. Short-lived certificates are only safe WITH automated
// renewal. The server side (POST /enroll/renew) landed first; this is the client that uses it.
// (short-lived device certificates, renewed before expiry rather than reissued by re-enrolment)
//
// A FRESH KEY IS GENERATED FOR EVERY RENEWAL rather than re-certifying the existing one. Re-certifying would
// let one key stay in use for the life of the device, so a key that leaked once would keep being blessed by
// every subsequent renewal. It also matches where this is going: when device keys move into the Secure
// Enclave, renewal becomes "create a new Enclave key", which only works if renewal never assumed it could
// reuse the old one.
//
// NOTHING HERE REPLACES THE WORKING IDENTITY. This component produces a candidate — a new key plus the
// certificate the Edge signed for it — and validates that candidate hard. Installing it is a separate step,
// deliberately, because the dangerous failure is not "renewal did not happen" (there are weeks of retry budget
// for that) but "renewal happened and left the device unable to connect".

public enum DsseCertificateRenewalError: Error, Equatable {
    case notDue
    case noTransportSecurity
    case keyGenerationFailed(String)
    case csrEncodingFailed(String)
    case requestFailed(String)
    case serverRefused(status: Int, message: String)
    case responseUnusable(String)
}

// The outcome of a successful renewal: a new private key and the certificate the Edge issued for it.
// Both are needed together — a certificate without its key is useless, which is exactly why installation
// treats them as one unit.
public struct DsseRenewedIdentity {
    public let privateKey: SecKey
    // The keychain tag the private key was generated under. Carried so a failed renewal can delete exactly
    // this key and nothing else — the key is in the keychain from the moment it is generated (see
    // generateDeviceKey), so every failure path has something to clean up.
    public let privateKeyTag: String
    public let certificate: SecCertificate
    public let certificatePEM: String
    public let caPEM: String
    public let commonName: String
    public let notAfter: Date

    public init(privateKey: SecKey, privateKeyTag: String, certificate: SecCertificate, certificatePEM: String,
                caPEM: String, commonName: String, notAfter: Date) {
        self.privateKey = privateKey
        self.privateKeyTag = privateKeyTag
        self.certificate = certificate
        self.certificatePEM = certificatePEM
        self.caPEM = caPEM
        self.commonName = commonName
        self.notAfter = notAfter
    }
}

public enum DsseCertificateRenewal {

    // MARK: - When to renew

    // renewalDue mirrors renewalDue() in cmd/edge/enroll_renew_endpoint.go and MUST keep mirroring it.
    //
    // Renewal opens at two thirds of the certificate's life, which leaves the final third as retry budget: on a
    // 60-day certificate the device has 20 days of failed attempts before anything stops working. That margin
    // is the difference between a broken renewal path being an alert and being an outage. Renewing at the last
    // moment would delete it.
    //
    // A degenerate window (zero, or notAfter before notBefore) is NOT due. Treating "we cannot tell when this
    // expires" as "renew immediately" would turn one bad certificate into a fleet-wide renewal storm.
    public static func renewalDue(notBefore: Date, notAfter: Date, now: Date = Date()) -> Bool {
        guard notAfter > notBefore else { return false }
        let life = notAfter.timeIntervalSince(notBefore)
        return now >= notBefore.addingTimeInterval(life * 2.0 / 3.0)
    }

    // renewalDue, with an operator's "anything older than this is stale" cutoff taken into account.
    //
    // The two-thirds rule answers "has this certificate had most of its life", which is the right question
    // almost always and the wrong one after the issuing CA changes: a certificate signed by a superseded CA is
    // stale on the day the CA is replaced, however much validity it has left. This lab has the extreme case —
    // a ten-year certificate from a retired CA whose two-thirds point is in 2033, so the old CA cannot be
    // retired for seven years because something live still depends on it.
    //
    // The cutoff is compared against notBefore, not against now: it asks WHEN THIS CERTIFICATE WAS ISSUED, so
    // an agent that has already renewed holds one issued after the cutoff and stops matching. That is what
    // makes it idempotent without anybody tracking who has done what.
    public static func renewalDue(notBefore: Date, notAfter: Date, renewIfIssuedBefore: Date?,
                                  now: Date = Date()) -> Bool {
        if let cutoff = renewIfIssuedBefore, notBefore < cutoff {
            return true
        }
        return renewalDue(notBefore: notBefore, notAfter: notAfter, now: now)
    }

    // MARK: - Key generation

    // generateDeviceKey creates a fresh P-256 key DIRECTLY IN THE KEYCHAIN, tagged so it can be found and
    // deleted again.
    //
    // The first version generated a transient key and imported it after the Edge had signed for it, so that a
    // failed renewal could not leave orphan keys behind. Measured against the real keychain, that does not
    // work: SecItemAdd of a transient SecKey reports success and the key is findable by tag, but macOS never
    // links it to the certificate — SecIdentityCreateWithCertificate returns errSecItemNotFound and NO IDENTITY
    // EVER FORMS. Generating into the keychain makes the identity appear as soon as the certificate is added.
    //
    // The cost is real and accepted: the key exists before there is any certificate for it, so every failure
    // path from here on has to delete it. That is why the tag is returned and carried through
    // DsseRenewedIdentity — cleanup deletes exactly this key rather than guessing by name.
    public static func generateDeviceKey() throws -> (key: SecKey, tag: String) {
        let tag = "dsse-device-identity-\(UUID().uuidString)"
        // NOTE (2026-07-29): a trusted-application SecAccess restricting this key to the NE's own code was
        // tried and PROVEN INEFFECTIVE on-device — the signed NE generated a restricted key in the System
        // keychain and an unprivileged non-root process still signed with it. Keychain ACLs do not close the
        // "any local process can use the device key" exposure on this macOS; the Secure Enclave (#13,
        // non-extractable key) does. The ineffective code was removed rather than left to imply a protection
        // that does not exist. See docs/2026-07-29_macos_device_key_acl_restriction.ja.md.
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: Data(tag.utf8),
            ],
        ]
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            let detail = (error?.takeRetainedValue()).map { String(describing: $0) } ?? "unknown"
            throw DsseCertificateRenewalError.keyGenerationFailed(detail)
        }
        return (key, tag)
    }

    // deleteKey removes a generated key by its tag. Called on every failure path after generation, so an
    // unsuccessful renewal does not leave key material accumulating on the device.
    public static func deleteKey(tag: String) {
        SecItemDelete([kSecClass as String: kSecClassKey,
                       kSecAttrApplicationTag as String: Data(tag.utf8)] as CFDictionary)
    }

    // MARK: - Renewal

    // renew asks the Edge to re-issue this device's certificate.
    //
    // The request rides the (T) transport with the CURRENT identity, and that is the authentication: the
    // handshake has already proven the client certificate chains to a registered tenant CA, names an identity
    // in the enrolled inventory, and is not revoked. No bootstrap token is involved — that secret is handed out
    // once at enrolment and must not have to live on every endpoint forever. A revoked device is refused at the
    // handshake, which is what makes revocation terminal instead of a 60-day countdown.
    //
    // commonName is passed only so the response can be checked against it. The Edge takes the identity from the
    // verified certificate and ignores whatever the CSR asks for; sending it here does not influence issuance.
    /// renew asks the Edge for a new certificate for commonName.
    ///
    /// serverName is the name to put in the ClientHello. The expired-certificate recovery path passes its own
    /// (the fold selects that path on the Edge BY the name); everything else now falls back to THIS
    /// ORGANIZATION'S announced transport name rather than to no name at all.
    ///
    /// ★★★ AND THAT FALLBACK IS THE WHOLE FIX (2026-08-22, measured on this lab). An ordinary renewal passed
    /// nil, so it dialled the Edge BY ADDRESS and was served the deployment-wide certificate — while the
    /// tunnel beside it sent lab.dsse.invalid and was served the organization's own. That is invisible until
    /// the organization's devices stop holding the shared anchor, which is the last step of roadmap D and the
    /// thing the enrolment fold exists to make safe. Then:
    ///
    ///	transport_trust ★ REFUSED the Edge at 203.0.113.10 served=f007c441… — "Lantern DSSE Transport"
    ///	certificate_renewal FAILED identity=mac-dev-1 error=requestFailed("cancelled")
    ///
    /// and it retries in six hours, for ever. NO DEVICE CAN EVER RENEW, which means no device can move onto
    /// its own organization's device-identity authority — the entire point of that tier. Measured: every
    /// device in this lab still presented a certificate from the DEPLOYMENT's CA, months after the
    /// organization had one of its own, and nothing said why.
    ///
    /// Third channel of the same family in one day, after the agent-policy poller's fetch and its report. The
    /// rule, stated once: every connection this agent makes to its Edge sends its organization's name.
    public static func renew(security: DsseTransportSecurity,
                             commonName: String,
                             session: URLSession? = nil,
                             serverName: String? = nil,
                             timeout: TimeInterval = 30) throws -> DsseRenewedIdentity {
        let (key, tag) = try generateDeviceKey()
        // From here the key is already in the keychain, so every exit must clean it up. Only a fully validated
        // renewal keeps it.
        var keep = false
        defer { if !keep { deleteKey(tag: tag) } }
        let csrPEM = try certificateSigningRequestPEM(privateKey: key, commonName: commonName)

        var request = URLRequest(url: URL(string: "https://\(security.dialHost):\(security.port)/enroll/renew")!)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONSerialization.data(withJSONObject: ["csr_pem": csrPEM])
        request.timeoutInterval = timeout

        var data = Data()
        var status = 0
        // The caller's name when it gave one (recovery), else the one this organization was announced — read
        // HERE rather than captured, exactly like the anchors and the identity, because it arrives in a trust
        // bundle after start-up. An injected session is a test seam and keeps the old path.
        let dialName = (serverName?.trimmingCharacters(in: .whitespacesAndNewlines)).flatMap { $0.isEmpty ? nil : $0 }
            ?? { let n = DsseLiveTransportServerName.current(); return n.isEmpty ? nil : n }()
        if let serverName = dialName, !serverName.isEmpty, session == nil {
            // The one case URLSession cannot carry. Same TLS construction as every other connection this agent
            // makes — same identity, same pinned anchors, same fail-closed verify block — with the name set.
            do {
                let answer = try DsseSingleRequestOverNW.post(
                    host: security.host, port: security.port, serverName: serverName,
                    path: "/enroll/renew", body: request.httpBody ?? Data(),
                    security: security, timeout: timeout)
                data = answer.body
                status = answer.status
            } catch {
                throw DsseCertificateRenewalError.requestFailed("\(error)")
            }
        } else {
            let urlSession = session ?? DsseTransportTLS.makePinnedURLSession(security: security, channel: "certificate-renewal")
            let (d, s, transportError) = synchronousData(for: request, session: urlSession, timeout: timeout)
            if let transportError {
                throw DsseCertificateRenewalError.requestFailed(transportError)
            }
            data = d
            status = s
        }

        let decoded = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] ?? [:]
        guard status == 200 else {
            throw DsseCertificateRenewalError.serverRefused(
                status: status, message: (decoded["error"] as? String) ?? "no error message")
        }
        guard let certPEM = decoded["cert_pem"] as? String, !certPEM.isEmpty else {
            throw DsseCertificateRenewalError.responseUnusable("response carried no cert_pem")
        }

        let renewed = try validate(certificatePEM: certPEM,
                                   caPEM: (decoded["ca_pem"] as? String) ?? "",
                                   privateKey: key,
                                   privateKeyTag: tag,
                                   expectedCommonName: commonName)
        keep = true
        return renewed
    }

    // validate refuses anything that would leave the device worse off than before.
    //
    // Every check here guards a way a renewal can "succeed" and still brick the endpoint. The one that matters
    // most is the key match: a certificate issued for a DIFFERENT key installs cleanly and then fails at the
    // next handshake, at which point the old identity is already gone. Checking here means a bad response is a
    // failed renewal attempt (harmless, retried) instead of a dead device.
    static func validate(certificatePEM: String, caPEM: String, privateKey: SecKey,
                         privateKeyTag: String = "",
                         expectedCommonName: String) throws -> DsseRenewedIdentity {
        guard let certificate = DsseTransportSecurityFactory.certificate(fromPEM: certificatePEM) else {
            throw DsseCertificateRenewalError.responseUnusable("the issued certificate could not be parsed")
        }

        // The certificate must belong to the key we just generated.
        guard let ourPublic = SecKeyCopyPublicKey(privateKey),
              let ourData = SecKeyCopyExternalRepresentation(ourPublic, nil) as Data? else {
            throw DsseCertificateRenewalError.responseUnusable("could not read our own public key")
        }
        guard let certPublic = SecCertificateCopyKey(certificate),
              let certData = SecKeyCopyExternalRepresentation(certPublic, nil) as Data? else {
            throw DsseCertificateRenewalError.responseUnusable("could not read the issued certificate's public key")
        }
        guard ourData == certData else {
            throw DsseCertificateRenewalError.responseUnusable(
                "the issued certificate is for a DIFFERENT key — installing it would break the next handshake")
        }

        // The Edge canonicalizes verified device identities by trimming and lowercasing.
        // Older certificates can retain the host's original case. Compare the same
        // identity, while retaining the issued spelling in the committed pointer.
        var cn: CFString?
        SecCertificateCopyCommonName(certificate, &cn)
        let issuedCN = (cn as String?) ?? ""
        let expectedIdentity = expectedCommonName.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let issuedIdentity = issuedCN.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !expectedIdentity.isEmpty, issuedIdentity == expectedIdentity else {
            throw DsseCertificateRenewalError.responseUnusable(
                "the issued certificate names \(issuedCN), not \(expectedCommonName)")
        }

        // It has to actually make progress: the new certificate must not be immediately due for renewal
        // again, or the device would renew on every single check forever.
        //
        // Note what this deliberately does NOT require: that the new certificate outlive the old one. The
        // first version of this check demanded exactly that, and the live run against the reference lab
        // rejected a perfectly good certificate because of it — the lab's bootstrap certificate is a hand-made
        // one-year cert and renewal correctly replaces it with a 60-day managed one. Moving from long-lived
        // hand-issued certificates to short-lived automated ones is the entire point of this work, so a rule
        // that forbids shortening would block the migration it exists to support. "Not immediately due again"
        // is the property that actually prevents the loop.
        guard let notAfter = notAfter(of: certificate) else {
            throw DsseCertificateRenewalError.responseUnusable("the issued certificate has no readable expiry")
        }
        guard notAfter > Date() else {
            throw DsseCertificateRenewalError.responseUnusable("the issued certificate is already expired")
        }
        let issuedNotBefore = notBefore(of: certificate) ?? Date()
        if renewalDue(notBefore: issuedNotBefore, notAfter: notAfter) {
            throw DsseCertificateRenewalError.responseUnusable(
                "the issued certificate is already past its own renewal point — renewal would loop")
        }

        return DsseRenewedIdentity(privateKey: privateKey, privateKeyTag: privateKeyTag,
                                   certificate: certificate,
                                   certificatePEM: certificatePEM, caPEM: caPEM,
                                   commonName: issuedCN, notAfter: notAfter)
    }

    // notAfter reads a certificate's expiry. Same mechanism the startup expiry warning uses.
    public static func notAfter(of certificate: SecCertificate) -> Date? {
        let keys = [kSecOIDX509V1ValidityNotAfter] as CFArray
        guard let values = SecCertificateCopyValues(certificate, keys, nil) as? [CFString: Any],
              let entry = values[kSecOIDX509V1ValidityNotAfter] as? [CFString: Any],
              let seconds = entry[kSecPropertyKeyValue] as? Double else {
            return nil
        }
        return Date(timeIntervalSinceReferenceDate: seconds)
    }

    // notBefore reads a certificate's start of validity, needed to decide whether renewal is due.
    public static func notBefore(of certificate: SecCertificate) -> Date? {
        let keys = [kSecOIDX509V1ValidityNotBefore] as CFArray
        guard let values = SecCertificateCopyValues(certificate, keys, nil) as? [CFString: Any],
              let entry = values[kSecOIDX509V1ValidityNotBefore] as? [CFString: Any],
              let seconds = entry[kSecPropertyKeyValue] as? Double else {
            return nil
        }
        return Date(timeIntervalSinceReferenceDate: seconds)
    }

    // MARK: - CSR construction

    // certificateSigningRequestPEM builds a PKCS#10 CSR for an EC P-256 key and signs it with that key.
    //
    // This is hand-rolled DER because the platform offers no CSR builder and the package deliberately has no
    // third-party dependencies. Hand-rolled encoders are exactly the kind of code that looks right and produces
    // something no real signer accepts, so it is verified against the live Edge signer, not only against unit
    // tests that would happily agree with my own encoder.
    //
    // The subject common name is included because a CSR without a subject is unusual enough that some parsers
    // reject it. It carries no authority: the Edge overwrites the subject from the verified certificate.
    public static func certificateSigningRequestPEM(privateKey: SecKey, commonName: String) throws -> String {
        guard let publicKey = SecKeyCopyPublicKey(privateKey),
              let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, nil) as Data? else {
            throw DsseCertificateRenewalError.csrEncodingFailed("could not export the public key")
        }

        let info = certificationRequestInfo(publicKeyPoint: publicKeyData, commonName: commonName)

        var signError: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            privateKey, .ecdsaSignatureMessageX962SHA256, info as CFData, &signError) as Data? else {
            let detail = (signError?.takeRetainedValue()).map { String(describing: $0) } ?? "unknown"
            throw DsseCertificateRenewalError.csrEncodingFailed("could not sign the request: \(detail)")
        }

        // CertificationRequest ::= SEQUENCE { info, signatureAlgorithm, signature BIT STRING }
        var body = Data()
        body.append(info)
        body.append(DER.sequence(DER.oidEcdsaWithSHA256))
        body.append(DER.bitString(signature))
        let der = DER.sequence(body)

        return pem(der, label: "CERTIFICATE REQUEST")
    }

    // CertificationRequestInfo ::= SEQUENCE { version(0), subject, subjectPKInfo, [0] attributes }
    static func certificationRequestInfo(publicKeyPoint: Data, commonName: String) -> Data {
        var content = Data()
        content.append(DER.integer(0))
        content.append(DER.name(commonName: commonName))
        content.append(DER.ecPublicKeyInfo(point: publicKeyPoint))
        // Attributes are context-tag 0, IMPLICIT, and empty. The tag must be present even with no attributes:
        // it is not OPTIONAL in the structure, and omitting it makes the request unparseable.
        content.append(Data([0xA0, 0x00]))
        return DER.sequence(content)
    }

    static func pem(_ der: Data, label: String) -> String {
        let body = der.base64EncodedString()
        var lines: [String] = ["-----BEGIN \(label)-----"]
        var index = body.startIndex
        while index < body.endIndex {
            let end = body.index(index, offsetBy: 64, limitedBy: body.endIndex) ?? body.endIndex
            lines.append(String(body[index..<end]))
            index = end
        }
        lines.append("-----END \(label)-----")
        return lines.joined(separator: "\n") + "\n"
    }

    // MARK: - Plumbing

    // synchronousData runs the request and waits. Renewal happens on a background schedule, once every few
    // weeks, never on a flow's path — blocking here costs nothing and keeps the caller readable.
    static func synchronousData(for request: URLRequest, session: URLSession,
                                timeout: TimeInterval) -> (Data, Int, String?) {
        var payload = Data()
        var status = 0
        var failure: String?
        let done = DispatchSemaphore(value: 0)
        let task = session.dataTask(with: request) { data, response, error in
            if let error { failure = error.localizedDescription }
            if let http = response as? HTTPURLResponse { status = http.statusCode }
            if let data { payload = data }
            done.signal()
        }
        task.resume()
        if done.wait(timeout: .now() + timeout + 5) == .timedOut {
            task.cancel()
            return (Data(), 0, "renewal request timed out")
        }
        return (payload, status, failure)
    }
}

// Minimal DER writer. Only the shapes a PKCS#10 EC request needs — deliberately not a general encoder, so
// there is less of it to be wrong.
enum DER {
    // Definite-length encoding. Lengths below 128 are a single byte; anything larger needs the long form,
    // which is where naive encoders break as soon as a structure exceeds 127 bytes (a CSR always does).
    static func length(_ count: Int) -> Data {
        if count < 0x80 { return Data([UInt8(count)]) }
        var bytes: [UInt8] = []
        var value = count
        while value > 0 {
            bytes.insert(UInt8(value & 0xFF), at: 0)
            value >>= 8
        }
        return Data([0x80 | UInt8(bytes.count)] + bytes)
    }

    static func tagged(_ tag: UInt8, _ content: Data) -> Data {
        var out = Data([tag])
        out.append(length(content.count))
        out.append(content)
        return out
    }

    static func sequence(_ content: Data) -> Data { tagged(0x30, content) }
    static func set(_ content: Data) -> Data { tagged(0x31, content) }
    static func integer(_ value: UInt8) -> Data { Data([0x02, 0x01, value]) }
    static func utf8String(_ s: String) -> Data { tagged(0x0C, Data(s.utf8)) }

    // BIT STRING with zero unused bits — the leading 0x00 is the unused-bit count, not padding, and omitting
    // it silently shifts the whole value.
    static func bitString(_ content: Data) -> Data {
        var body = Data([0x00])
        body.append(content)
        return tagged(0x03, body)
    }

    static let oidCommonName = Data([0x06, 0x03, 0x55, 0x04, 0x03])                          // 2.5.4.3
    static let oidEcPublicKey = Data([0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]) // 1.2.840.10045.2.1
    static let oidPrime256v1 = Data([0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07])
    static let oidEcdsaWithSHA256 = Data([0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02])

    // Name ::= SEQUENCE OF RelativeDistinguishedName; each RDN is a SET OF AttributeTypeAndValue.
    static func name(commonName: String) -> Data {
        var atv = Data()
        atv.append(oidCommonName)
        atv.append(utf8String(commonName))
        return sequence(set(sequence(atv)))
    }

    // SubjectPublicKeyInfo for an uncompressed P-256 point (0x04 || X || Y), which is what
    // SecKeyCopyExternalRepresentation returns for an EC public key.
    static func ecPublicKeyInfo(point: Data) -> Data {
        var algorithm = Data()
        algorithm.append(oidEcPublicKey)
        algorithm.append(oidPrime256v1)
        var content = Data()
        content.append(sequence(algorithm))
        content.append(bitString(point))
        return sequence(content)
    }
}
