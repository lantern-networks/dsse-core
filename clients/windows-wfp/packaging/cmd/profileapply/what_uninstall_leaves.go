package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// what_uninstall_leaves.go — naming, at uninstall, the material that says which deployment this machine was.
//
// ★★★ BOTH PLATFORMS LEAVE IT, AND NEITHER SAID SO (2026-09-07).
//
// Removing the agent stops what is running. It does not collect the profile, the key profiles are verified
// against, or the anchors the device adopted. Those name a deployment which may no longer exist, and anything
// that reads one afterwards adopts it. Measured: a Windows box whose uninstall could not run came back bound
// to a deployment destroyed the previous day; a Mac still held a torn-down deployment's material after an
// uninstall that reported success.
//
// Deleting them is a decision and not an obvious one — a reinstall that must spend a fresh approval is a real
// cost, and a device identity has uses across a reinstall. Leaving them SILENTLY is not a decision. So this
// reports, which is this tree's recorded rule for ambiguous input: fail loud, not fail closed.
func reportWhatUninstallLeaves(w io.Writer) {
	dir := deploymentMaterialDir()
	if dir == "" {
		return
	}
	left := []string{}
	for _, name := range []string{
		"install-profile.json",    // which deployment, and which organization within it
		"profile_signing_key.txt", // the key any future profile would be verified against
		"trust_anchors_adopted.pem",
		"trust_anchor_pointer.json",
		"transport_ca.pem",
		"step_up_portal_ca.pem",
	} {
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			left = append(left, name)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "enroll")); err == nil {
		left = append(left, "enroll\\")
	}
	if len(left) == 0 {
		return
	}
	fmt.Fprintf(w, "profileapply: ★ left in place, and they name the deployment this machine belonged to: %s\n",
		strings.Join(left, " "))
	fmt.Fprintf(w, "profileapply:   in %s — anything that reads them later adopts that deployment, including\n", dir)
	fmt.Fprintf(w, "profileapply:   one that no longer exists. Remove the directory if this machine is not\n")
	fmt.Fprintf(w, "profileapply:   going back to the same organization.\n")
}

// deploymentMaterialDir is where provisioning puts what it writes. Empty when the platform has no such place,
// which keeps this file buildable everywhere the package is.
func deploymentMaterialDir() string {
	if pd := strings.TrimSpace(os.Getenv("ProgramData")); pd != "" {
		return filepath.Join(pd, "DSSE")
	}
	return ""
}
