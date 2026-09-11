package main

import (
	"crypto/x509"
	"flag"
	"log"
	"strings"
)

// interception_announced_anchor.go — the certificate a DEVICE must hold, which is not the one that signs.
//
// ★★★ ANNOUNCING THE SIGNING CA COST A REAL MACHINE ITS WHOLE NETWORK (2026-08-26, win-dev-1 letter 112).
// This deployment's interception CA is signed by the deployment root, so it is an INTERMEDIATE. The Edge
// announced its fingerprint as interception_root_sha256; the operator did the obvious thing and installed
// exactly that into the Windows Root store — and every HTTPS request still failed with
// SEC_E_UNTRUSTED_ROOT, because a chain does not close on an intermediate. What worked was the deployment
// ROOT in Root and the announced certificate in the intermediate store.
//
// Measured the same day from the deployment side: the Edge presents TWO certificates (leaf + interception
// CA) and the chain closes only on "DSSE Deployment Root CA", which it does not present. So a device holding
// the anchor accepts the chain without needing the intermediate at all — and the anchor is the only thing
// worth naming.
//
// ★ THE FIELD'S NAME SAYS root AND THE AGENT TREATS IT AS ONE: interceptionRootsPresent scans the machine's
// Root stores for exactly these fingerprints and reports which it holds. Naming an intermediate there means
// the answer is "not held" for ever — a fleet that reports itself unready while it is working, or ready while
// it is about to fail, depending on which way the deployment is misconfigured.
//
// ★ IT IS A FLAG RATHER THAN A DERIVATION, because the alternative is guessing. The Edge holds the
// interception CA and no general picture of who signed it; the deployment knows. Pointing this at the
// deployment's anchor is one line in the generated launch script, and when it is absent this says so at
// start-up rather than announcing something a device cannot use.

// registerInterceptionAnchorFlag defines this surface's flag here rather than in main.go — the rule the
// decomposition ratchet enforces.
func registerInterceptionAnchorFlag() *string {
	return flag.String("interception-anchor-cert", "",
		"PEM of the certificate a DEVICE must hold in its trust store for the chain this Edge presents on "+
			"intercepted traffic to close. Announced to agents as interception_root_sha256. Leave empty only "+
			"when the interception authority is itself self-signed: announcing an intermediate makes every "+
			"device that installs it report the root as missing, and fail every site if it installs nothing else")
}

// announcedInterceptionAnchor picks what to announce for a signing certificate.
//
// Returns the anchor's fingerprints when one is configured and it actually terminates the signing
// certificate's chain; the signing certificate's own when it is self-signed; and — deliberately — the
// signing certificate's own when neither holds, together with a log line saying what that costs. Silence
// would be worse: an agent reads an empty list as "this deployment does not inspect".
func announcedInterceptionAnchor(signing *x509.Certificate, anchorPEM string) []string {
	if signing == nil {
		return nil
	}
	selfSigned := signing.CheckSignatureFrom(signing) == nil
	if selfSigned {
		return []string{certFingerprint(signing)}
	}
	for _, candidate := range parseAllCerts([]byte(anchorPEM)) {
		if err := signing.CheckSignatureFrom(candidate); err == nil {
			return []string{certFingerprint(candidate)}
		}
		// A chain of more than two: the configured material may hold the root above an intermediate that
		// signed this one. Accepting any self-signed certificate whose subject matches the issuer chain would
		// be guessing, so only a direct signature counts, and a deeper chain is reported rather than assumed.
	}
	log.Printf("interception WARNING the authority signing intercepted traffic (%q) is NOT self-signed and no "+
		"-interception-anchor-cert names what closes its chain, so agents are told to hold %s — a device that "+
		"installs exactly that still cannot verify anything this Edge presents, and every site on it fails",
		signing.Subject.CommonName, strings.ToLower(certFingerprint(signing))[:16]+"…")
	return []string{certFingerprint(signing)}
}
