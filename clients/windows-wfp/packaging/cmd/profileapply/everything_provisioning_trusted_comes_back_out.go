//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// everything_provisioning_trusted_comes_back_out.go — an uninstall takes back what provisioning trusted.
//
// ★★★ THE AGENT UNINSTALLED AND LEFT THREE ROOTS TRUSTED (2026-09-03, measured on the Windows box while
// tearing the lab down). msiexec removed the services, the driver and the binaries, and removed not one
// certificate. Still in LocalMachine\Root afterwards:
//
//	8D38DD8F…  Keyaki Networks Root CA                  (installed as the step-up portal's authority)
//	EABE0F67…  Asahi Manufacturing Interception Root    (installed by provisioning, from the profile)
//
// A removal action DOES exist — RemoveInterceptionRoot, matched by fingerprint, scheduled before RemoveFiles.
// It is inside <?ifdef InterceptionRoot ?>, so it is compiled into the package ONLY when the root was baked
// into the artifact at build time. The lane this product actually ships — a signed profile, applied by
// profileapply on the machine — installs the root at PROVISIONING time, and that lane had no removal at all.
// The portal authority, added the same day, had none by any route.
//
// ★ WHY THIS MATTERS MORE THAN A TIDY UNINSTALL. An interception root is a certificate authority whose
// private key belongs to a deployment. Left trusted on a machine that no longer runs the agent, it signs
// anything for that machine, for as long as the certificate is valid, with nothing on the box that would use
// it or notice it. The deployment it belongs to may by then have been destroyed — this one was, an hour later
// — so nobody is left who could revoke it either.
//
// ★★ AND IT REMOVES ONLY WHAT IT CAN PROVE IT PUT THERE. Every removal is BY FINGERPRINT, against the PEM
// provisioning wrote for that purpose. Never by subject: another deployment can hold a root with the same
// name — a rotation in flight, a device moved between organizations — and taking that one is an outage rather
// than a cleanup. A file that is not there means this machine was never given that anchor, which is not an
// error.
func doRemoveEverythingProvisioningTrusted(dataDir string) {
	// The artefacts provisioning writes when it trusts something. transport_ca.pem is deliberately NOT here:
	// it is written for the agent to verify the Edge with and is never put in the machine's trust store.
	for _, name := range []string{
		"interception-root.pem", // the organization's inspection authority
		"step_up_portal_ca.pem", // whoever serves this deployment's step-up portal
	} {
		path := filepath.Join(dataDir, name)
		if _, err := os.Stat(path); err != nil {
			// Never installed on this machine, or already taken back. Both are silence, not failure.
			continue
		}
		fmt.Printf("profileapply: taking back what provisioning trusted from %s\n", path)
		_ = doRemoveInterceptionRoot(path)
	}

	// ★ And the bundle this package wrote, plus the variables it pointed at it. Left in place they are a
	// deployment's inspection authority still trusted by every openssl-linked program on the machine, on a box
	// that no longer runs the agent and may belong to a deployment that no longer exists.
	//
	// It rewrites rather than deletes, for a reason that has already cost this project an afternoon: every
	// shell and daemon started while the agent ran is holding that path, and removing the file takes TLS from
	// all of them at once. Rewriting it without our root leaves them verifying the public internet exactly as
	// before, and no longer trusting us.
	rootPEM, _ := os.ReadFile(filepath.Join(dataDir, "interception-root.pem"))
	removeCABundlePointers(dataDir, rootPEM)
}
