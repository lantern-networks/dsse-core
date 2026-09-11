//go:build windows

package main

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// self_integrity_windows.go — who may rewrite this agent, asked of the ACL rather than of permission bits that
// Windows does not have.
//
// ★ WHY (2026-08-14, reported from a Windows machine). The shared check read
// `info.Mode().Perm() & 0o002`. Go synthesises that value on Windows from one bit — the read-only attribute —
// so every writable directory reads 0666/0777 and the agent reported C:\Windows\System32 as WORLD-WRITABLE.
// The finding it exists to raise is the precondition under everything else the agent claims (policy, logging,
// revocation are only ever what the binary says they are), and it was firing on every single start. A warning
// that is always on is not a warning; it is a thing operators learn to scroll past, which is strictly worse
// than not checking, because it also consumes the attention a real finding would need.
//
// So: read the DACL and name the principals that can actually write. "World-writable" is not a Windows
// concept; "Everyone has FILE_ADD_FILE here" is, and it is what the 2026-07-28 finding actually was.

// writeAccessMask is the set of rights that let somebody REPLACE this executable — directly, or by creating a
// new file next to it and renaming over it, or by taking ownership and granting themselves the rest.
//
// FILE_DELETE_CHILD is in the list deliberately: with add-file and delete-child on the directory, the file's
// own ACL does not matter. That is the substitution this check exists to detect, and a mask that only looked
// at FILE_WRITE_DATA would miss it.
const writeAccessMask = windows.FILE_WRITE_DATA | // create a file here
	windows.FILE_APPEND_DATA | // create a subdirectory here
	windows.FILE_WRITE_EA |
	windows.FILE_WRITE_ATTRIBUTES |
	0x40 | // FILE_DELETE_CHILD — remove what is already here, including this agent
	windows.DELETE |
	windows.WRITE_DAC | // rewrite the ACL, then grant yourself the rest
	windows.WRITE_OWNER |
	windows.GENERIC_WRITE |
	windows.GENERIC_ALL

// trustedSIDTypes are the principals whose write access is the INTENDED state on a correctly installed
// machine. Everything else that can write is the finding.
//
// CREATOR OWNER (S-1-3-0) is not a principal — it is a template applied to newly created objects — so an ACE
// for it says nothing about who can rewrite what is already there, and treating it as a writer would produce
// the same always-on warning this file exists to end.
var trustedSIDTypes = []windows.WELL_KNOWN_SID_TYPE{
	windows.WinLocalSystemSid,
	windows.WinBuiltinAdministratorsSid,
	windows.WinLocalServiceSid,
}

// trustedSIDStrings covers principals with no WELL_KNOWN_SID_TYPE constant.
var trustedSIDStrings = map[string]bool{
	// NT SERVICE\TrustedInstaller — owns most of %SystemRoot% and is how Windows Update writes there.
	"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464": true,
	// CREATOR OWNER: a template, not a principal (see above).
	"S-1-3-0": true,
}

func sidIsTrusted(sid *windows.SID) bool {
	if sid == nil {
		return true // an ACE we cannot read a SID from is not evidence of an untrusted writer
	}
	for _, t := range trustedSIDTypes {
		if sid.IsWellKnown(t) {
			return true
		}
	}
	return trustedSIDStrings[sid.String()]
}

// describeSID prefers the readable account name, because the operator has to act on this: "BUILTIN\Users" tells
// them what to remove and "S-1-5-32-545" makes them go and look it up.
func describeSID(sid *windows.SID) string {
	if sid == nil {
		return "an unreadable principal"
	}
	account, domain, _, err := sid.LookupAccount("")
	if err != nil || account == "" {
		return sid.String()
	}
	if domain != "" {
		return domain + "\\" + account
	}
	return account
}

// probeDirectoryWritability reads the directory's security descriptor and hands the DACL to the judgement.
//
// ★ THE SYSCALL AND THE JUDGEMENT ARE SEPARATE ON PURPOSE (2026-08-14). This probe is the only part of the
// check that must touch a real directory, and while it was one function the ACL judgement below — which
// principals count as trusted, which rights amount to "can replace this binary", what a NULL DACL means —
// could not be tested at all without a live filesystem, so it never was. That is a poor place to have no
// coverage: it is the code that decides whether the agent's own guarantees hold.
func probeDirectoryWritability(dir string, _ os.FileInfo, report *selfIntegrityReport) error {
	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("read the ACL of %s: %w", dir, err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("read the DACL of %s: %w", dir, err)
	}
	return untrustedWritersFromDACL(dacl, dir, report)
}

// untrustedWritersFromDACL names every principal the DACL lets rewrite this directory's contents, minus the
// ones whose write access is the intended state. The POSIX fields are left false on purpose: they are not a
// weaker version of this answer, they are a different question that Windows cannot be asked.
func untrustedWritersFromDACL(dacl *windows.ACL, dir string, report *selfIntegrityReport) error {
	if dacl == nil {
		// A NULL DACL is not "no permissions", it is EVERYONE FULL CONTROL — the one case where the absence of
		// a thing means the maximum of it, and the one an ACE loop alone would report as clean.
		report.UntrustedWriters = []string{"EVERYONE (this directory has a NULL DACL)"}
		return nil
	}

	seen := map[string]bool{}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var header *windows.ACCESS_ALLOWED_ACE
		if aerr := windows.GetAce(dacl, i, &header); aerr != nil {
			return fmt.Errorf("read ACE %d of %s: %w", i, dir, aerr)
		}
		// Only ALLOW aces grant. A DENY ace is read past deliberately: this check reports what an ACL PERMITS,
		// and modelling deny-overrides-allow correctly is the access-check algorithm, not a summary. Erring
		// toward naming a principal that a deny ace also blocks is the safe direction for a warning.
		if header.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			continue
		}
		if uint32(header.Mask)&uint32(writeAccessMask) == 0 {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&header.SidStart))
		if sidIsTrusted(sid) {
			continue
		}
		if name := describeSID(sid); !seen[name] {
			seen[name] = true
			report.UntrustedWriters = append(report.UntrustedWriters, name)
		}
	}
	return nil
}
