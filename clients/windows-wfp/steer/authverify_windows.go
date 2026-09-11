//go:build windows

// authverify_windows.go — the steer-exclusion side of Authenticode: the rule VOCABULARY, and a thin adapter
// onto the shared verifier.
//
// ★ THE SYSCALLS MOVED OUT (2026-08-14). They now live in clients/windows-wfp/authenticode, because the
// updater needed the same question answered — who built this MSI, asked immediately before `msiexec /i` runs
// as SYSTEM — and the alternative was a second hand-written WinVerifyTrust wrapper. This month's review
// convergence plan names that shape as the thing to stop producing: one rule, two implementations, of which a
// later fix reaches one.
//
// What stays here is what is genuinely this caller's: which identifier forms an exclusion may use. The
// update gate accepts a strict subset of them and says why, in updateplatform/publisher.go — the same
// vocabulary, a narrower grant, because a bypass rule decides whether one app's traffic is inspected and the
// update gate decides whether arbitrary code runs as SYSTEM.
package main

import (
	"strings"

	"github.com/lantern-networks/dsse-core/clients/windows-wfp/authenticode"
)

// imageSig is the local shape the bypass matcher reads. It is a mapping of authenticode.Sig rather than a
// re-export so that this file, not its callers, absorbs any future change to the shared type.
type imageSig struct {
	valid      bool
	publisher  string
	org        string
	thumbprint string
}

// imageAuthenticodeValid reports whether the file at path carries a valid embedded Authenticode signature
// that chains to a trusted root. False for unsigned, tampered, or untrusted-chain files.
func imageAuthenticodeValid(path string) bool { return authenticode.Valid(path) }

// imageCatalogSignature verifies a file via the system catalog store — Windows system binaries (notepad,
// cmd) are catalog-signed rather than embedded-signed.
func imageCatalogSignature(path string) (bool, string) { return authenticode.CatalogSignature(path) }

// imageSignature is the combined check used by the bypass matcher: embedded signature first, catalog
// fallback second.
func imageSignature(path string) imageSig {
	s := authenticode.Signature(path)
	return imageSig{valid: s.Valid, publisher: s.Publisher, org: s.Org, thumbprint: s.Thumbprint}
}

// isSignatureRule reports whether an exclusion identifier is signature-based (publisher:/signed:) rather
// than a legacy image-path substring. Signature rules are enforced in userspace (appBypass.matchAppRule),
// NOT in the kernel WFP callout (which matches image-path substrings only).
func isSignatureRule(rule string) bool {
	r := strings.ToLower(strings.TrimSpace(rule))
	return strings.HasPrefix(r, "publisher:") || strings.HasPrefix(r, "signed:") ||
		strings.HasPrefix(r, "subject:") || strings.HasPrefix(r, "thumbprint:")
}

// signatureRuleCount counts the signature-based identifiers in an exclusion set.
func signatureRuleCount(rules []string) int {
	n := 0
	for _, r := range rules {
		if isSignatureRule(r) {
			n++
		}
	}
	return n
}
