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
func doRemoveEverythingProvisioningTrusted(dataDir string) error {
	var steps []cleanupStep
	for _, name := range []string{
		"interception-root.pem", // provisioned inspection authority
		"interception_root.pem", // the optional MSI-bundled authority
		"step_up_portal_ca.pem", // provisioned portal authority
	} {
		path := filepath.Join(dataDir, name)
		steps = append(steps, cleanupStep{name, func() error {
			fmt.Printf("profileapply: taking back trust named by %s\n", path)
			return doRemoveInterceptionRoot(path)
		}})
	}
	steps = append(steps, cleanupStep{"CA bundle and environment", func() error {
		var rootPEM []byte
		for _, name := range []string{"interception-root.pem", "interception_root.pem", "step_up_portal_ca.pem"} {
			b, err := os.ReadFile(filepath.Join(dataDir, name))
			if err != nil && !os.IsNotExist(err) {
				return err
			}
			rootPEM = append(rootPEM, b...)
			rootPEM = append(rootPEM, '\n')
		}
		return removeCABundlePointers(dataDir, rootPEM)
	}})
	return runCleanup(steps...)
}
