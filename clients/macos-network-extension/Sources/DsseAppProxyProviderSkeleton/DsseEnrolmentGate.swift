import Foundation

// What an agent should do when it starts and finds it has no device identity.
//
// This is a question the product previously had no answer to, and the default answer was the worst one. The
// transport resolver hands back a security object with a nil client identity rather than refusing, so a machine
// with no certificate TAKES OVER the network path and is then rejected at every handshake. The user gets a
// machine with no working network and no explanation, from an agent that never had anything to protect.
//
// The distinction that decides it is the same one the Edge draws between an identity that is ABSENT and one an
// admin DISABLED:
//
//   never enrolled  — the ordinary Day-0 state. Nothing has been lost, because nothing was ever gained. Taking
//                     over would only break a machine that was working. Enrol if there is a token; otherwise
//                     stand aside and say so.
//   was enrolled    — a machine that HAS held an identity and no longer does. That is a different event, and it
//                     is not this gate's to reinterpret: existing behaviour stands.
//
// Standing aside is not a bypass of anything. There is no policy to bypass on a machine that has never enrolled;
// the alternative is not "more secure", it is "no network". A machine an operator has never approved should not
// be silently steering its traffic through a tenant's Edge either.
public enum DsseEnrolmentGateDecision: Equatable, Sendable {
    /// A device identity is present. Nothing to do.
    case proceed
    /// No identity, but the install config carries a token. Enrol, then proceed.
    case enrolFirst
    /// No identity and no token, and this machine has never had one. Do not take over the network path.
    case standAsideNotEnrolled
    /// No identity, but this machine HAS been enrolled before. Leave the existing handling alone.
    case proceedPreviouslyEnrolled
}

public enum DsseEnrolmentGate {
    /// Decides from facts the caller has already established, so this stays testable without a keychain,
    /// a filesystem, or an Edge.
    ///
    /// - Parameters:
    ///   - hasIdentity: a usable device client identity was resolved.
    ///   - hasEnrolmentToken: the install config carries an unspent admin-issued token.
    ///   - wasEnrolledBefore: this machine has previously held an identity (a renewed-identity pointer, or a
    ///     provisioned identity reference in the contract). Distinguishes a device that LOST its credential from
    ///     one that never had one — collapsing the two would either strand every new machine or silently let a
    ///     stripped one carry on as if nothing happened.
    /// - Parameter identityWorksHere: whether the identity this device holds completes a (T) handshake with the
    ///   deployment it is INSTALLED FOR. nil when the question could not be asked — no transport contract, or
    ///   no identity to ask about — and nil must never be read as "no".
    /// - Parameter identityBelongsToThisOrganization: whether the identity this device holds was issued by the
    ///   device CA the profile in force PINS. nil when the question could not be asked, and nil must never be
    ///   read as "no" — an issuer that is simply not in the keychain is a different fault.
    public static func decide(hasIdentity: Bool,
                              hasEnrolmentToken: Bool,
                              wasEnrolledBefore: Bool,
                              identityWorksHere: Bool? = nil,
                              identityBelongsToThisOrganization: Bool? = nil) -> DsseEnrolmentGateDecision {
        // ★★★ AND AN IDENTITY FROM ANOTHER ORGANIZATION IS NOT AN IDENTITY HERE EITHER (2026-09-04, measured).
        //
        // The rule below catches a certificate from another DEPLOYMENT, because that one fails the handshake.
        // Within one deployment it does not: a `tenant_default` certificate completes a (T) handshake with the
        // Edge that serves every organization, so the device kept it, and every flow was then attributed — and
        // INSPECTED — under the wrong organization while the right one's authority sat loaded and unused.
        // Same shape as below, different proof: the issuer, not the handshake.
        if hasIdentity, hasEnrolmentToken, identityBelongsToThisOrganization == false {
            return .enrolFirst
        }
        // ★★★ AN IDENTITY FROM ANOTHER DEPLOYMENT IS NOT AN IDENTITY HERE (2026-08-30, measured on a real Mac).
        //
        // A Mac was handed the four artefacts of a NEW deployment — profile, verifying key, one-time token,
        // package — and kept steering with the certificate the PREVIOUS deployment had issued it. The gate saw
        // hasIdentity and said proceed:
        //
        //	enrolment_gate decision=proceed has_identity=true has_token=true enrolled_before=true
        //	device_identity renewed_identity=in_use sha256=a295a9c4…      ← yesterday's, from a destroyed lab
        //	curl https://example.com -> 000
        //
        // So the machine held a credential the deployment could not possibly accept, an administrator's unused
        // approval sat beside it, and nothing connected the two. That is the whole "move a device to another
        // deployment" lane, and it is also every rebuild of a lab.
        //
        // The evidence is the handshake, not the certificate's paperwork: what matters is not who issued it but
        // whether it works HERE. Asked only when there is an unspent token to act on, so a device with a broken
        // credential and no approval keeps whatever behaviour it had — widening that is a posture decision and
        // not this gate's to make.
        // A failed connection does not invalidate a signed same-tenant identity. Keep renewal/recovery
        // responsible for expired credentials; a reinstall may have restored an already spent token.
        if hasIdentity, identityBelongsToThisOrganization == true { return .proceed }
        if hasIdentity, hasEnrolmentToken, identityWorksHere == false { return .enrolFirst }
        if hasIdentity { return .proceed }
        if hasEnrolmentToken { return .enrolFirst }
        if wasEnrolledBefore { return .proceedPreviouslyEnrolled }
        return .standAsideNotEnrolled
    }

    /// The line an operator reads when the agent stands aside. It has to say what is wrong AND what to do about
    /// it: "not enrolled" alone sends someone hunting through logs for a cause that is really a missing step.
    public static let notEnrolledOperatorMessage =
        "this device is not enrolled and has no enrolment token — traffic is NOT being steered or inspected. " +
        "An administrator issues a one-time enrolment token in the Console (Enrolment Tokens) and places it in " +
        "the agent config as enrolment.enrolment_token; the agent then enrols itself on the next start."
}
