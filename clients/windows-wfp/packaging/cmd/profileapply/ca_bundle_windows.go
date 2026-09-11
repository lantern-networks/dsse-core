//go:build windows

package main

// ca_bundle_windows.go — write the trust bundle the CA environment variables point at, and point them at it.
//
// ★★★ THIS REVERSES A DELIBERATE STANCE, AND THE PREMISE IT RESTED ON HAS CHANGED (2026-09-07, the
// operator's decision: "write the bundle and set the variables; whatever that cannot reach is the user's to
// handle"). sibling_trust_bundle.go refused to touch this file, and its reason was good: the bundle was an
// operator's composition — public roots from several sources plus the interception root — that this program
// did not build and could not know the intent of. Silently rewriting somebody else's trust store is a worse
// habit than the one it would fix.
//
// That objection does not apply to a file this package AUTHORS. We build it, we own it, and we rewrite it on
// every provision — so the failure it was written to report cannot occur in the first place: the 2026-08-31
// incident was a bundle that existed and went STALE for eleven hours, and a file that is rebuilt from the
// machine's own store plus the current root has no stale state to hold.
//
// ★ WHY THIS IS NOT A SIDE EFFECT. It announces every part of what it did — the path, how many public roots
// it copied, which interception root it added by fingerprint, and each variable it set. A tool that edits
// trust stores silently is the thing that cannot be reasoned about; one that says the whole of it can be.
//
// ★ WHAT IT CANNOT REACH, said here so it is not discovered later. Java keeps its own cacerts keystore and
// reads no environment variable; Firefox keeps NSS; GUI programs do not inherit a shell's environment.
// Measured on a steered box: schannel, .NET and Go programs verify without any of this (they read the machine
// store), while node, curl, ruby and the python-based AWS CLI all fail without it. This closes the second
// group and does not pretend to close the first.

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"github.com/lantern-networks/dsse-core/clients/windows-wfp/datadir"
	"golang.org/x/sys/windows"
)

// caBundleName is the file every CA environment variable is pointed at. Kept as the name the previous
// convention already used, so a box that had one composed by hand keeps the same path.
const caBundleName = "ca-bundle-with-interception.pem"

// caEnvVars are the variables that decide what an own-bundle program trusts. NODE_EXTRA_CA_CERTS is NOT here:
// it APPENDS to Node's built-in roots rather than replacing them, so it is pointed at the interception root
// alone (setNodeExtraCACerts). Pointing it at the full bundle would work but would tell a reader that Node
// needs the public roots from us, which it does not.
var caEnvVars = []string{
	"SSL_CERT_FILE",      // OpenSSL, and everything linked against it
	"CURL_CA_BUNDLE",     // curl
	"REQUESTS_CA_BUNDLE", // python-requests, and the AWS CLI through it
	"PIP_CERT",           // pip, which reads neither of the two above
	"GIT_SSL_CAINFO",     // git when built against OpenSSL rather than schannel
}

// writeCABundleAndPointAtIt builds the bundle from this machine's own root store plus the organization's
// interception root, writes it, and sets the variables.
//
// The public half comes from the machine store rather than from a list we ship: what this box already trusts
// is the right answer to "what should still verify", and copying it means an own-bundle program and a
// schannel program agree about the public internet as well as about the interception root. A list of our own
// would be a second opinion that drifts.
func writeCABundleAndPointAtIt(dataDir string, interceptionRootPEM []byte) error {
	publicRoots, err := machineRootStorePEM(interceptionRootPEM)
	if err != nil {
		return fmt.Errorf("read this machine's root store: %w", err)
	}
	var buf bytes.Buffer
	buf.Write(publicRoots.pem)
	if len(interceptionRootPEM) > 0 {
		if !bytes.HasSuffix(publicRoots.pem, []byte("\n")) {
			buf.WriteByte('\n')
		}
		buf.Write(interceptionRootPEM)
	}
	bundlePath := filepath.Join(dataDir, caBundleName)

	// ★ IF ONE IS ALREADY THERE, IT MAY NOT BE OURS. This path is the convention an operator following the
	// old advice would have used to compose a bundle by hand — public roots from several sources plus the
	// interception root — and that composition is exactly what sibling_trust_bundle.go refused to destroy.
	// Taking ownership of the path is the decision; destroying somebody's file without a copy is not part of
	// it. Keep the original beside it and say so, once, with the path they need.
	if existing, rerr := os.ReadFile(bundlePath); rerr == nil {
		// Deliberately NOT staleBundleWarning: its text ends "this program did not write that bundle and will
		// not rewrite it", which was true under the old stance and would be printed one line before
		// "CA bundle WRITTEN". Two adjacent lines saying opposite things is worse than no line at all.
		backup := bundlePath + ".before-agent-took-it-over"
		if berr := os.WriteFile(backup, existing, 0o644); berr == nil {
			fmt.Printf("profileapply: the bundle already at %s has been copied to %s before being replaced — "+
				"if it was composed by hand, whatever else it carried is in that copy\n", bundlePath, backup)
		}
	}

	if err := os.WriteFile(bundlePath, buf.Bytes(), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", bundlePath, err)
	}
	keepPublicReadable(bundlePath)
	fmt.Printf("profileapply: CA bundle WRITTEN -> %s (%d root(s) copied from this machine's own store",
		bundlePath, publicRoots.count)
	if fp := fingerprintOf(interceptionRootPEM); fp != "" {
		fmt.Printf(", plus this organization's interception root %s", fp)
	}
	fmt.Println(")")

	for _, name := range caEnvVars {
		if err := setMachineEnv(name, bundlePath); err != nil {
			// Not fatal: the device is provisioned and steering either way, and a variable that could not be
			// written is worth saying rather than worth refusing an install over.
			fmt.Fprintf(os.Stderr, "profileapply: could not set %s (%v) — programs reading it will not verify "+
				"intercepted TLS until it is set by hand to %s\n", name, err, bundlePath)
			continue
		}
		fmt.Printf("profileapply: %s -> %s\n", name, bundlePath)
	}
	// Node is the exception in the list and gets its own line. NODE_EXTRA_CA_CERTS APPENDS to Node's built-in
	// roots instead of replacing them, so it is pointed at the interception root alone: pointing it at the
	// full bundle would also work, and would tell the next reader that Node needs the public roots from us,
	// which it does not.
	if len(interceptionRootPEM) > 0 {
		rootPath := filepath.Join(dataDir, "interception-root.pem")
		if err := setMachineEnv("NODE_EXTRA_CA_CERTS", rootPath); err != nil {
			fmt.Fprintf(os.Stderr, "profileapply: could not set NODE_EXTRA_CA_CERTS (%v) — Node programs will "+
				"not verify intercepted TLS until it is set by hand to %s\n", err, rootPath)
		} else {
			fmt.Printf("profileapply: NODE_EXTRA_CA_CERTS -> %s (appended to Node's own roots, not replacing them)\n", rootPath)
		}
	}

	fmt.Println("profileapply: ★ these take effect for processes started AFTER this point. A program already " +
		"running reads its environment once, so anything open now — a shell, an editor, an agent — keeps the " +
		"old answer until it is restarted.")
	fmt.Println("profileapply: ★ NOT covered, and nothing here can cover them: Java (its own cacerts keystore, " +
		"reads no variable — use keytool), Firefox (its own NSS store), and GUI programs that do not inherit a " +
		"shell environment.")
	return nil
}

// removeCABundlePointers takes the interception root back out of the bundle and unsets the variables.
//
// ★ IT REWRITES THE FILE RATHER THAN DELETING IT. Every shell and daemon started while the agent ran is still
// holding this path, and deleting the file underneath them takes TLS away from all of them at once —
// including, when it happens, whatever the operator is using to work on the machine. Rewriting it without our
// root leaves those processes verifying the public internet exactly as before, and no longer trusting us.
func removeCABundlePointers(dataDir string, interceptionRootPEM []byte) {
	bundlePath := filepath.Join(dataDir, caBundleName)
	if _, err := os.Stat(bundlePath); err == nil {
		if publicRoots, rerr := machineRootStorePEM(interceptionRootPEM); rerr == nil {
			if werr := os.WriteFile(bundlePath, publicRoots.pem, 0o644); werr == nil {
				keepPublicReadable(bundlePath)
				fmt.Printf("profileapply: CA bundle rewritten WITHOUT this organization's interception root "+
					"-> %s (%d public root(s)). The file is deliberately not deleted: processes started while "+
					"the agent ran still hold this path, and removing it would take TLS from all of them.\n",
					bundlePath, publicRoots.count)
			} else {
				fmt.Fprintf(os.Stderr, "profileapply: could not rewrite %s (%v) — it still carries this "+
					"organization's interception root; take that one certificate out by hand, and do not "+
					"delete the file\n", bundlePath, werr)
			}
		}
	}
	for _, name := range append(append([]string{}, caEnvVars...), "NODE_EXTRA_CA_CERTS") {
		if err := setMachineEnv(name, ""); err != nil {
			fmt.Fprintf(os.Stderr, "profileapply: could not unset %s (%v) — remove it by hand\n", name, err)
			continue
		}
		fmt.Printf("profileapply: %s unset\n", name)
	}
	fmt.Println("profileapply: ★ a shell that was open while the agent ran still holds the old values. It will " +
		"keep pointing at the bundle until it is closed, which is harmless now that the bundle no longer " +
		"carries this organization's root.")
}

type rootStorePEM struct {
	pem   []byte
	count int
}

// machineRootStorePEM exports every certificate in LocalMachine\Root as PEM, skipping the one we are about to
// add so it is never written twice.
func machineRootStorePEM(skipPEM []byte) (rootStorePEM, error) {
	skip := map[string]bool{}
	if fp := fingerprintOf(skipPEM); fp != "" {
		skip[fp] = true
	}
	store, err := openMachineRootStore()
	if err != nil {
		return rootStorePEM{}, err
	}
	defer windows.CertCloseStore(store, 0)
	certs, err := enumerateStore(store)
	if err != nil {
		return rootStorePEM{}, err
	}
	var buf bytes.Buffer
	n := 0
	for _, c := range certs {
		if skip[c.SHA256] {
			continue
		}
		if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: c.DER}); err != nil {
			return rootStorePEM{}, err
		}
		n++
	}
	return rootStorePEM{pem: buf.Bytes(), count: n}, nil
}

// fingerprintOf returns the SHA-256 of the first certificate in a PEM blob, uppercase hex, or "".
func fingerprintOf(pemBytes []byte) string {
	b, _ := pem.Decode(pemBytes)
	if b == nil {
		return ""
	}
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:])
}

// keepPublicReadable re-asserts that a file every user-context program must open is readable by them.
//
// ★ CALLED AFTER EVERY WRITE, not once at install. %ProgramData%\DSSE is protected and its inheritable
// entries are SYSTEM/Administrators-only, so each rewrite of these files produces one no standard user can
// read — and the machine-wide variables set below still point at it. The symptom is every own-bundle program
// failing TLS verification after a CA rotation that reported success, with nothing in any log.
//
// Non-fatal and loud: the material is correct either way, and refusing an install over an ACL would be the
// worse trade. What must not happen is the failure being silent.
func keepPublicReadable(path string) {
	if err := datadir.MakePublicReadable(path); err != nil {
		fmt.Fprintf(os.Stderr, "profileapply: WARNING - %s could not be made readable by non-administrators "+
			"(%v). Programs reading SSL_CERT_FILE / CURL_CA_BUNDLE / NODE_EXTRA_CA_CERTS as a normal user will "+
			"fail to verify intercepted TLS.\n", path, err)
	}
}
