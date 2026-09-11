// Package authenticode answers one question about a file on a Windows endpoint: is it validly
// Authenticode-signed, and who signed it.
//
// Two callers, one implementation, deliberately. The steering agent asks it of a process image so a
// steer-exclusion can name a publisher instead of a spoofable path substring; the updater asks it of an MSI
// before handing that MSI to `msiexec /i` as SYSTEM. The two decisions differ — see the caller — but the
// mechanism is one, because a wintrust wrapper per caller is a rule that gets fixed in one of them.
package authenticode

// Sig is the leaf signer identity extracted from a file's signature, plus the trust verdict.
//
// ★ THE FIELDS ARE THE VOCABULARY, and it is deliberately the same one an operator already writes in a
// steer-exclusion: Org is what `subject:` matches, Thumbprint is what `thumbprint:` matches, Publisher is what
// `publisher:` matches. A second set of words for the same three facts would mean an operator who has learned
// how to name Lantern once has to learn it again for the update gate.
//
// Everything except Valid is best-effort — "" when the signature could not be parsed, which happens for
// catalog-signed files (no leaf to read) and for anything unsigned. A caller must therefore treat an empty
// field as "unknown", never as "does not match": the two are the same value in Go and must not be the same
// decision, which is the failure family this codebase names most often.
//
// This file carries no build tag so that the callers' JUDGEMENT — which identity satisfies which requirement —
// is testable on any machine, from captured real values. Only the syscalls are windows-only. What makes a
// gate wrong is almost never the syscall; it is the comparison, and a comparison that can only be exercised on
// the platform where a mistake installs something is one nobody exercises.
type Sig struct {
	// Valid is the Authenticode trust verdict: a signature that verifies and chains to a trusted root. On
	// Windows it also covers the bytes, so a tampered file is invalid rather than validly-signed-by-someone.
	Valid bool
	// Publisher is the signer's simple display name, e.g. "Lantern Networks, Inc.". Cosmetic: another
	// certificate could carry a similar one, which is why the update gate refuses to match on it.
	Publisher string
	// Org is the Subject Organization (O=) — the practical analog of a macOS Team ID, stable across app
	// versions and across the organisation's individual signing certificates.
	Org string
	// Thumbprint is the leaf certificate's SHA-256, lowercase hex. The strongest identity and the least
	// durable: it changes when the certificate is renewed.
	Thumbprint string
}
