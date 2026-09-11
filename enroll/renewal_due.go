package enroll

import "time"

// renewal_due.go — when a certificate should be renewed.
//
// ★★ WHY IT LIVES HERE (2026-08-23). "This is the ONE place that decision is made so the client and any
// server-side warning cannot drift apart" is what the comment on the Edge's copy says, and by then there were
// three copies of it — the Edge, the Windows steering agent, and the macOS one. Writing a connector's renewal
// was about to make a fourth, with a DIFFERENT rule: a fixed twenty days rather than a fraction of the
// certificate's life. On the 60-day certificates the deployment issues today those two agree, which is exactly
// why the drift would not have been noticed; on a deployment that shortens its certificate lifetime — the very
// thing -enroll-cert-ttl exists for — the fixed number stops renewing in time and the fleet expires.
//
// So the rule moved to the package both sides already import. The agents' copies are not collapsed here
// because theirs carries an extra "renew if issued before" input for forced rotation; they should come to this
// one when that input has somewhere to live.

// RenewalDue reports whether a certificate should be renewed now.
//
// Renewal starts at two thirds of the certificate's life. That leaves a third of the validity as retry budget:
// with a 60-day certificate the holder has 20 days of failed attempts before anything breaks, which is what
// turns a broken renewal path into an alert instead of an outage. Renewing at the last minute would remove
// exactly that margin — and a fixed number of days would remove it silently on any shorter certificate.
//
// A certificate with no expiry, or one whose expiry does not follow its start, is never due: there is no life
// to take two thirds of, and guessing would renew constantly.
func RenewalDue(notBefore, notAfter, now time.Time) bool {
	if notAfter.IsZero() || !notAfter.After(notBefore) {
		return false
	}
	life := notAfter.Sub(notBefore)
	return !now.Before(notBefore.Add(life * 2 / 3))
}
