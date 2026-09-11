//go:build windows

package main

// restore_pins_windows.go — reading a service's conditions honestly, and writing back only what is missing.
//
// Separate from putPinsInServiceArgs on purpose. That one implements ADOPTION: an operator placed a key and
// both of DsseSteer's pins are set to it. This one implements RESTORATION: an upgrade emptied the arguments
// and only what is missing is put back, per (service, flag). Sharing one function would have meant one
// behaviour serving two intentions, and the intention that loses is the unattended one nobody is watching.
//
// ★★★ AND A FAILURE TO READ IS NOT AN EMPTY READ. serviceArgsOf
// was written as a diagnostic and drops every error to nil: no SCM, no such service, access denied and an
// unreadable configuration all come back as "this service names nothing". The pre-upgrade capture then reads
// that as "there is nothing to save", exits 0, and Return="check" has nothing to refuse — so the upgrade
// proceeds to delete the only copy of the conditions, which is the precise disaster the capture exists to
// prevent. serviceArgsFor separates the three answers so the capture can stop on the one that matters.

import (
	"errors"
	"fmt"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

// serviceArgsFor reads one service's argument list.
//
// found=false means the service is genuinely not installed, which during a fresh install is the ordinary case
// and nothing to stop for. An error means the answer could NOT be established — and a caller about to let an
// upgrade delete that service must treat it as a reason to stop, not as an absence.
func serviceArgsFor(name string) (args []string, found bool, err error) {
	// ★ SC_MANAGER_CONNECT, NOT mgr.Connect. mgr.Connect asks the service
	// control manager for SC_MANAGER_ALL_ACCESS, so a function documented as "reads with the least privilege
	// it needs" was in fact demanding everything and would be refused for an unprivileged caller at the FIRST
	// call — before the per-service right it actually wanted was ever tested. The claim and the code now
	// agree: connect to enumerate, then open the one service for SERVICE_QUERY_CONFIG.
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return nil, false, fmt.Errorf("open the service manager: %w", err)
	}
	defer windows.CloseServiceHandle(scm)

	h, err := windows.OpenService(scm, windows.StringToUTF16Ptr(name), windows.SERVICE_QUERY_CONFIG)
	if err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("open %s for reading: %w", name, err)
	}
	s := &mgr.Service{Name: name, Handle: h}
	defer s.Close()

	cfg, err := s.Config()
	if err != nil {
		return nil, true, fmt.Errorf("read %s configuration: %w", name, err)
	}
	_, args, derr := decomposeImagePath(cfg.BinaryPathName)
	if derr != nil {
		return nil, true, fmt.Errorf("%s: %w", name, derr)
	}
	return args, true, nil
}

// restoreMissingPinsInServiceArgs fills the named service's absent conditions from the store, preserving
// everything else on the command line — including a condition that is already present and different.
//
// It reads the arguments back rather than composing them, for the reason putPinsInServiceArgs gives: the MSI
// registered the service with site facts (a bypass destination, a manifest path) that a freshly composed
// command line would silently drop, and the bypass destination is this box's management path.
func restoreMissingPinsInServiceArgs(service string, stored pinSet) (pinRestoration, error) {
	for _, purpose := range purposesFor(service) {
		v := stored.get(purpose.ValueName)
		if v == "" {
			continue
		}
		if err := purpose.Validate(v); err != nil {
			return pinRestoration{}, fmt.Errorf("refusing to put a malformed value into %s %s: %w",
				service, purpose.Flag, err)
		}
	}
	m, err := mgr.Connect()
	if err != nil {
		return pinRestoration{}, fmt.Errorf("open the service manager: %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(service)
	if err != nil {
		return pinRestoration{}, fmt.Errorf("open %s: %w", service, err)
	}
	defer s.Close()
	cfg, err := s.Config()
	if err != nil {
		return pinRestoration{}, fmt.Errorf("read %s configuration: %w", service, err)
	}

	exe, args, derr := decomposeImagePath(cfg.BinaryPathName)
	if derr != nil {
		return pinRestoration{}, fmt.Errorf("%s: %w", service, derr)
	}

	r := fillMissingPins(service, args, stored)
	if !r.Changed() {
		// Nothing to write. Deliberately not a no-op UpdateConfig: rewriting a service's command line to the
		// value it already has is a change in the audit record that did not change anything on the box.
		return r, nil
	}
	cfg.BinaryPathName = composeImagePath(exe, r.Args)
	if err := s.UpdateConfig(cfg); err != nil {
		return r, fmt.Errorf("update %s configuration: %w", service, err)
	}
	return r, nil
}

// joinArgs renders an argument list the way CreateProcess will read it back. Kept as a helper so a test can
// assert the round trip without an executable in front of it.
func joinArgs(args []string) string { return windows.ComposeCommandLine(args) }

// verifierInForce returns the CONFIG verifier the named service will actually use, or "" when it names none or
// cannot be read. Service arguments are the protected source: set by an elevated installer, as protected as
// the binary they name (review S1).
func verifierInForce(service string) string {
	args, found, err := serviceArgsFor(service)
	if err != nil || !found {
		return ""
	}
	return pinsInArgs(service, args).get("Steer_ConfigPin")
}

// resolveConfigVerifier answers "what key should this process verify configuration against" for a build that
// bakes none, in order of decreasing directness: what the service will actually use, then what the protected
// store recorded. It returns the key and where it came from, because a step that silently picks a different
// source than the operator expects is the shape review S1 exists to prevent.
//
// An untrusted store is an ERROR, never an empty answer: falling through to "no pin" would turn a tampered
// store into the same outcome as a clean box that was never provisioned.
func resolveConfigVerifier(service string) (key, from string, err error) {
	if v := verifierInForce(service); v != "" {
		return v, service + "'s service arguments", nil
	}
	stored, serr := readCapturedPins()
	if serr != nil {
		return "", "", serr
	}
	if v := stored.get("Steer_ConfigPin"); v != "" {
		return v, "the protected verifier store", nil
	}
	return "", "", nil
}
