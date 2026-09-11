// Package datadir owns %ProgramData%\DSSE — the one directory every endpoint component writes into, and the
// reason it needs owning rather than creating.
//
// ★ WHAT IS WRONG WITHOUT THIS, measured on win-dev-1 rather than assumed:
//
//	a directory freshly created under %ProgramData%:
//	  NT AUTHORITY\SYSTEM      FullControl
//	  BUILTIN\Administrators   FullControl
//	  BUILTIN\Users            ReadAndExecute, Synchronize
//	  BUILTIN\Users            Write            <-- inherited from %ProgramData% itself
//
// A plain os.MkdirAll inherits that. Under this directory sit the staged installer package that msiexec runs
// as SYSTEM, the rollback packages an update falls back to, and the signed update manifest — so an inherited
// DACL means any non-admin on the box can replace the thing about to be executed with our privileges.
//
// The staged package is re-verified against its digest immediately before launch, which DETECTS a
// substitution. This is the half that prevents one, and neither should be the only half.
//
// WHY THE PARENT AND NOT EACH DIRECTORY. There are three components racing to create these paths — the
// agent's manifest courier, rollbackstore, and the updater's stager — and whichever wins decides the DACL for
// what it creates. Fixing the parent fixes all of them by inheritance, whoever gets there first, and there is
// exactly one place to get it right.
//
// Nothing here is //go:build windows except the syscall: what the decisions are — set on create, never
// silently tighten, report what was found — is the content, and it is tested on any host.
package datadir

import (
	"fmt"
	"os"
	"path/filepath"
)

// hardenedDACL is the target: LocalSystem (SY) and Administrators (BA) full control and INHERITED by
// everything below, plus BUILTIN\Users read on THIS FOLDER ONLY. "P" makes it PROTECTED so the %ProgramData%
// ACL cannot re-widen it by inheritance — which is the entire failure being closed.
//
// ★★★ THE USERS ACE CARRIES NO OI/CI, AND THAT IS THE WHOLE DESIGN (2026-09-09). An earlier version granted
// Users nothing at all, on the argument that "this directory holds an installer package and a rollback
// package, and no user-mode reader needs them". That is true of what is BELOW it and false of the directory
// itself. profileapply's ca_bundle sets machine-wide SSL_CERT_FILE, CURL_CA_BUNDLE, GIT_SSL_CAINFO and
// NODE_EXTRA_CA_CERTS to files in here, and those are read by curl, git, node and everything linked against
// OpenSSL — running as the logged-in user. With no Users ACE a fresh install points every own-bundle program
// on the machine at a file it cannot open, and they fail TLS verification against this deployment's
// interception while the box looks perfectly provisioned.
//
// So Users get exactly enough to TRAVERSE and LIST this one directory, and nothing is inherited from it:
// enroll, rollback, staged and the private files below stay SYSTEM/Administrators-only. Read access to the
// two PUBLIC PEMs is then granted on those files explicitly (PublicReadableDACL), which is a decision made
// once per file rather than a right that leaks to every future file someone drops in here.
const hardenedDACL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x1200a9;;;BU)"

// Root is %ProgramData%\DSSE.
//
// %ProgramData% rather than the install directory because an upgrade rewrites that directory and an uninstall
// removes it — so the rollback package for the version being replaced would vanish during the install that
// needs it.
func Root() string {
	if pd := os.Getenv("ProgramData"); pd != "" {
		return filepath.Join(pd, "DSSE")
	}
	return "DSSE"
}

// State is what Ensure found or did, so a caller can report it rather than assume.
type State struct {
	Path string
	// Created is true when Ensure created the directory and therefore set the DACL itself.
	Created bool
	// Hardened is true when this call applied the protected DACL.
	Hardened bool
	// PreExisting is true when the directory was already there. Ensure does NOT change its DACL — see Ensure.
	PreExisting bool
	// Protected says whether an existing directory's DACL is PROTECTED, i.e. shielded from %ProgramData%'s
	// inheritance. ProtectionKnown is false when it could not be read.
	//
	// ★ This exists so the warning below can be RARE. Without it, PreExisting is true on every call after the
	// very first — including on a directory this product created and hardened a minute earlier — so a caller
	// that reports it warns about a healthy box forever. A warning that fires every minute on every machine is
	// one nobody reads, which would leave the genuinely wide-open directory exactly as invisible as before.
	//
	// Reading the DACL is not tightening it: the restraint below is about not CHANGING what an operator may
	// have set, and looking costs nothing.
	Protected       bool
	ProtectionKnown bool
}

// Ensure creates Root() with a protected SYSTEM+Administrators DACL, and returns what it found.
//
// ★ IT DOES NOT TIGHTEN A DIRECTORY THAT ALREADY EXISTS, and that restraint is deliberate rather than
// laziness. An operator may have opened it on purpose; more to the point, an installer that rewrites ACLs it
// did not create is exactly how the util:PermissionEx attempt rolled installs back on this product before.
// Setting the DACL at CREATION is safe because nothing else has had a chance to depend on it yet.
//
// The consequence is that an existing wide-open directory stays wide open, silently, unless someone looks —
// which is why the state is RETURNED rather than swallowed. Callers that have somewhere to report it should
// (see Describe).
func Ensure() (State, error) {
	p := Root()
	st := State{Path: p}

	if fi, err := os.Stat(p); err == nil {
		if !fi.IsDir() {
			return st, fmt.Errorf("datadir: %s exists and is not a directory", p)
		}
		st.PreExisting = true
		st.Protected, st.ProtectionKnown = daclIsProtected(p)
		return st, nil
	} else if !os.IsNotExist(err) {
		return st, fmt.Errorf("datadir: stat %s: %w", p, err)
	}

	// The parent must exist (%ProgramData% always does); only the leaf is ours to create, so MkdirAll on the
	// parent and Mkdir on the leaf — creating intermediate directories with an inherited DACL would reintroduce
	// the very problem one level up.
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return st, fmt.Errorf("datadir: create %s: %w", filepath.Dir(p), err)
	}
	if err := os.Mkdir(p, 0o755); err != nil {
		if os.IsExist(err) {
			// Lost a race with another component. It created it, so it owns the DACL decision, and the
			// pre-existing rule applies for the same reason.
			st.PreExisting = true
			return st, nil
		}
		return st, fmt.Errorf("datadir: create %s: %w", p, err)
	}
	st.Created = true

	if err := harden(p); err != nil {
		// The directory exists but is inherited-wide. Reported as an error rather than tolerated: the caller
		// created it, so nothing depends on it yet, and a caller that ignores this is choosing to write an
		// installer package somewhere a non-admin can replace it.
		return st, err
	}
	st.Hardened = true
	return st, nil
}

// Describe renders the state for a log or a --status line. Empty when there is nothing worth saying: a
// directory this process created and hardened is the ordinary case and should not be announced every tick.
func (s State) Describe() string {
	switch {
	case s.Created && s.Hardened:
		return fmt.Sprintf("datadir: created %s (SYSTEM and Administrators only)", s.Path)
	case s.PreExisting && s.ProtectionKnown && s.Protected:
		// The ordinary steady state: the directory exists because we made it, and its DACL is shielded from
		// %ProgramData%'s inheritance. Silent, so that the two cases below are worth reading when they appear.
		return ""
	case s.PreExisting && s.ProtectionKnown:
		// Measured, not suspected: this directory's DACL is inheritable from %ProgramData%, which grants
		// BUILTIN\Users write.
		return fmt.Sprintf("datadir: ★ %s already existed and its permissions are NOT protected from "+
			"inheritance, so non-administrators may be able to write into it. The staged installer package "+
			"there is run as SYSTEM, and its digest is re-checked immediately before launch — that DETECTS a "+
			"substitution and does not prevent one. Its permissions were deliberately not changed by this "+
			"process; an administrator should tighten them", s.Path)
	case s.PreExisting:
		return fmt.Sprintf("datadir: %s already existed and its permissions could not be read, so whether a "+
			"non-administrator can replace the installer package in it is unknown — check it", s.Path)
	default:
		return ""
	}
}
