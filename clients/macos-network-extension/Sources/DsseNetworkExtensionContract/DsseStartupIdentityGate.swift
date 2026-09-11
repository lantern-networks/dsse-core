import Foundation

/// Should the provider take the device's traffic, given what it knows about its own identity?
///
/// ★ Why this is a gate and not a log line (2026-08-10). The provider enabled the transparent proxy, captured
/// every flow, and dropped them all, while holding a certificate whose PRIVATE KEY it was not allowed to use.
/// The device ended up neither protected nor usable, and `NEVPNStatusDidChange status=connected` said it was
/// fine — that status means "the provider started", never "it can carry traffic".
///
/// The rule: **prove the identity, then take the traffic.** Everything else about failure handling —
/// fail-open versus fail-closed once running — is a separate argument. This one only says that "reporting
/// connected while carrying nothing" must not be reachable.
public enum DsseStartupIdentityDecision: String, Equatable, Sendable {
    /// Usable identity: take the traffic.
    case proceed
    /// No identity at all — the enrolment gate owns this case and its messages.
    case noIdentity
    /// ★ A certificate is present and this process may NOT use its private key. Distinct from `noIdentity`
    /// because the remedy is different: not "enrol", but "re-provision for THIS build". A key's ACL names the
    /// code identity that created it, so a rebrand, a re-sign or a new team produces exactly this.
    case identityUnusable
}

public enum DsseStartupIdentityGate {
    public static func decide(identityPresent: Bool, identityUsable: Bool) -> DsseStartupIdentityDecision {
        if !identityPresent { return .noIdentity }
        return identityUsable ? .proceed : .identityUnusable
    }

    /// What an operator has to be told, in the one case that used to be silent.
    public static let unusableIdentityOperatorMessage =
        "this device has a certificate it is NOT ALLOWED TO USE: the private key's ACL names a different code "
        + "identity, which is what a changed bundle id, a re-signed build or a new team produces. The device is "
        + "NOT steering — its traffic is going direct — because taking traffic it cannot carry would leave it "
        + "neither protected nor usable. Re-provision this device's identity for the current build."
}
