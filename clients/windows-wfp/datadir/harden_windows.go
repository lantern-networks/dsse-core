//go:build windows

package datadir

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// harden applies the protected DACL to a directory. Needs WRITE_DAC, which the creator has: this only ever
// runs on a directory this process just created.
//
// The same shape as configstore.HardenKeyACL, with SE_FILE_OBJECT instead of SE_REGISTRY_KEY —
// PROTECTED_DACL_SECURITY_INFORMATION is the load-bearing flag in both, because without it the inherited
// %ProgramData% entries (which include Users:Write) survive alongside the ones being set.
// ★ AND THE OWNER IS ASSIGNED, NOT LEFT TO WHOEVER CREATED IT (2026-09-09). An owner holds WRITE_DAC
// implicitly, so a directory owned by a standard user can have this DACL rewritten by that user whatever it
// currently says — which is exactly what verifyStore refuses one level down, and what made the first-install
// regression fail when the creating process was not SYSTEM. Administrators rather than SYSTEM because
// assigning SYSTEM needs SeRestorePrivilege, which the installer's SYSTEM context has and an elevated
// administrator does not; Administrators is in both tokens with SE_GROUP_OWNER, so both can set it.
func harden(path string) error {
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return fmt.Errorf("datadir: resolve the Administrators SID: %w", err)
	}

	sd, err := windows.SecurityDescriptorFromString(hardenedDACL)
	if err != nil {
		return fmt.Errorf("datadir: parse hardened DACL: %w", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("datadir: extract DACL: %w", err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		admins, nil, dacl, nil); err != nil {
		return fmt.Errorf("datadir: set owner and DACL on %s: %w", path, err)
	}
	return nil
}

// daclIsProtected reports whether a directory's DACL is PROTECTED — shielded from the inheritance that
// carries %ProgramData%'s BUILTIN\\Users:Write down into it.
//
// The single flag is the whole question. A directory created by this package is protected and carries exactly
// SYSTEM and Administrators; one created by a bare MkdirAll is unprotected and carries whatever %ProgramData%
// hands down. Comparing full ACEs would be a more precise answer to a question nobody asked: an administrator
// who deliberately added an entry to a protected directory has made a choice, and this must not nag about it.
//
// READ ONLY. Ensure's restraint is about not changing what it did not create; looking is free.
func daclIsProtected(path string) (bool, bool) {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false, false
	}
	control, _, err := sd.Control()
	if err != nil {
		return false, false
	}
	return control&windows.SE_DACL_PROTECTED != 0, true
}

// publicReadableDACL is what a file every user-context program must read gets: SYSTEM and Administrators full
// control, BUILTIN\Users read. PROTECTED, so it does not depend on what the parent happens to allow.
const publicReadableDACL = "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x120089;;;BU)"

// MakePublicReadable marks one file as deliberately readable by every account on the machine.
//
// ★★★ AND IT MUST BE RE-APPLIED AFTER EVERY REWRITE (2026-09-09). The CA bundle and the interception root are
// written atomically — staged to a temporary file and renamed — so each update produces a NEW file, and a new
// file in a directory whose inheritable entries are SYSTEM/Administrators-only is a file no user can read.
// The variables still point at it, nothing logs an error, and every own-bundle program on the machine starts
// failing TLS verification after a CA rotation that looked like a success. Calling this at each write site is
// what keeps the guarantee true across the rewrite rather than only at install time.
//
// Only the two PUBLIC PEMs may be passed. Anything else in this tree — the enrolment material, the stored
// packages — is private, and widening one of those would undo the reason the parent is protected at all.
func MakePublicReadable(path string) error {
	sd, err := windows.SecurityDescriptorFromString(publicReadableDACL)
	if err != nil {
		return fmt.Errorf("datadir: parse public DACL: %w", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("datadir: extract public DACL: %w", err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil); err != nil {
		return fmt.Errorf("datadir: set public DACL on %s: %w", path, err)
	}
	return nil
}
