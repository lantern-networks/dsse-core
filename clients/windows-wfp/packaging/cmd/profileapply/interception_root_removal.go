package main

// interception_root_removal.go -- taking OUT the interception root this package put IN.
//
// ★★★ THE INSTALLER PUT ONE IN AND NOTHING EVER TOOK ONE OUT (2026-08-30). DsseAgent.wxs schedules
// InstallInterceptionRoot with Condition="NOT REMOVE" and has no counterpart, so uninstalling the agent left
// the machine trusting a CA for EVERY name on the internet -- one whose private key belongs to a deployment
// that, in a lab, is usually already deleted.
//
// Measured on win-dev-1 the evening the second lab was torn down: FOUR interception roots in
// LocalMachine\Root, from four deployments, ALL of which had been destroyed. One per rebuild, because nothing
// removed any. The peer session found nine on its Mac, from five deployments, four of them long gone.
//
// ★ IT REMOVES BY FINGERPRINT, NEVER BY NAME. "Everything whose subject says Interception Root" would take
// another deployment's root with it -- and on a machine that legitimately holds two (a rotation in flight, a
// device moved between organizations) that is an outage, not a cleanup. The certificate to remove is the one
// in the package's own artifact: the same file the install read.
//
// ★ AND A MISSING FILE IS NOT A FAILURE. An uninstall runs when things are already partly gone. If the
// artifact is absent there is nothing this package can prove it installed. Other read errors must fail.

import (
	"errors"
	"fmt"
	"os"
)

// rootRemovalPlan is what a removal would do, decided before the store is touched.
type rootRemovalPlan struct {
	// Remove are the certificates present in the store AND named by this package's artifact.
	Remove []parsedRoot
	// Absent are the ones the artifact names that the store does not hold -- already removed, or never
	// installed. Reported, not an error.
	Absent []parsedRoot
}

// planRootRemoval matches the store's contents against the artifact BY FINGERPRINT.
//
// existing is what the store holds; ours is what this package installed. A certificate that shares a subject
// with ours but not a fingerprint is somebody else's authority and is left alone -- that is the whole reason
// this is a fingerprint match and not a name match.
func planRootRemoval(existing, ours []parsedRoot) rootRemovalPlan {
	have := make(map[string]parsedRoot, len(existing))
	for _, e := range existing {
		have[e.SHA256] = e
	}
	var plan rootRemovalPlan
	for _, o := range ours {
		if e, ok := have[o.SHA256]; ok {
			plan.Remove = append(plan.Remove, e)
		} else {
			plan.Absent = append(plan.Absent, o)
		}
	}
	return plan
}

// readOurRoots reads the package's own interception-root artifact for the removal.
//
// Only an absent file returns (nil, nil). Permission and malformed-content errors remain failures.
func readOurRoots(path string) ([]parsedRoot, error) {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("stat root artifact: %w", err)
	}
	roots, err := readInterceptionRoots(path)
	if err != nil {
		return nil, fmt.Errorf("the interception root artifact %q is present but unreadable (%w) -- this "+
			"uninstall cannot tell which certificate it installed, so none is removed. Remove it by "+
			"fingerprint by hand", path, err)
	}
	return roots, nil
}

// Each deletion is attempted, then read back. This catches deletion APIs that
// return success without removing the target and supports retry after a partial
// failure without touching a different certificate with the same subject.
func removeRootsVerified(ours []parsedRoot, list func() ([]parsedRoot, error), remove func(parsedRoot) error) error {
	existing, err := list()
	if err != nil {
		return err
	}
	var steps []cleanupStep
	for _, root := range planRootRemoval(existing, ours).Remove {
		steps = append(steps, cleanupStep{root.SHA256, func() error { return remove(root) }})
	}
	deleteErr := runCleanup(steps...)
	existing, err = list()
	if err != nil {
		return errors.Join(deleteErr, fmt.Errorf("readback: %w", err))
	}
	for _, root := range planRootRemoval(existing, ours).Remove {
		deleteErr = errors.Join(deleteErr, fmt.Errorf("%s still trusted after deletion", root.SHA256))
	}
	return deleteErr
}
