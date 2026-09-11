//go:build windows

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// self_integrity_windows_test.go — the DACL judgement, which had no tests at all until 2026-08-14.
//
// ★ WHY IT HAD NONE, AND WHY THAT MATTERED. The Windows probe was written as one function that called
// GetNamedSecurityInfo, so the only way to exercise its reasoning was to own a directory with the ACL you
// wanted to test. The result was that the code deciding whether this agent's guarantees hold — the trusted
// principal list, the write-mask, the NULL DACL case — shipped unexercised, while three shared tests that
// were never about Windows failed on every run and made the box's gate permanently red. Splitting the
// syscall from the judgement fixes both: the ACLs below are built in memory, so these assert what the
// product will actually conclude, on any Windows machine, with no privileges and no cleanup hazard.

func mustSID(t *testing.T, sidType windows.WELL_KNOWN_SID_TYPE) *windows.SID {
	t.Helper()
	sid, err := windows.CreateWellKnownSid(sidType)
	if err != nil {
		t.Fatalf("create well-known SID %d: %v", sidType, err)
	}
	return sid
}

// aclOf builds a DACL from (sid, rights, grant-or-deny) triples, in order.
func aclOf(t *testing.T, entries ...windows.EXPLICIT_ACCESS) *windows.ACL {
	t.Helper()
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		t.Fatalf("build ACL: %v", err)
	}
	return acl
}

func ace(sid *windows.SID, rights windows.ACCESS_MASK, mode windows.ACCESS_MODE) windows.EXPLICIT_ACCESS {
	return windows.EXPLICIT_ACCESS{
		AccessPermissions: rights,
		AccessMode:        mode,
		Inheritance:       windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}
}

func writersFor(t *testing.T, dacl *windows.ACL) []string {
	t.Helper()
	var report selfIntegrityReport
	if err := untrustedWritersFromDACL(dacl, `C:\Program Files\Lantern DSSE`, &report); err != nil {
		t.Fatalf("judge the DACL: %v", err)
	}
	return report.UntrustedWriters
}

// A NULL DACL is the one case where the ABSENCE of a thing means the MAXIMUM of it. An ACE loop on its own
// walks zero entries and reports a clean directory, which is exactly backwards.
func TestANullDACLIsEveryoneNotClean(t *testing.T) {
	writers := writersFor(t, nil)
	if len(writers) == 0 {
		t.Fatal("a NULL DACL was reported as clean — it means EVERYONE FULL CONTROL, the worst case, not the best")
	}
	if !strings.Contains(strings.ToUpper(writers[0]), "EVERYONE") {
		t.Fatalf("the finding does not say who can write: %q", writers[0])
	}
}

// The intended state of a correctly installed directory must produce NO finding, or the warning is noise and
// operators learn to scroll past it — which is the failure this whole check was rewritten to end.
func TestOnlySystemAndAdministratorsIsClean(t *testing.T) {
	dacl := aclOf(t,
		ace(mustSID(t, windows.WinLocalSystemSid), windows.GENERIC_ALL, windows.GRANT_ACCESS),
		ace(mustSID(t, windows.WinBuiltinAdministratorsSid), windows.GENERIC_ALL, windows.GRANT_ACCESS),
	)
	if writers := writersFor(t, dacl); len(writers) != 0 {
		t.Fatalf("a correctly installed directory was flagged as writable by %v — a false alarm here trains "+
			"operators to ignore the real one", writers)
	}
}

// The finding that started this: a principal who is not part of the install can replace the binary.
func TestEveryoneWithWriteIsNamed(t *testing.T) {
	dacl := aclOf(t,
		ace(mustSID(t, windows.WinLocalSystemSid), windows.GENERIC_ALL, windows.GRANT_ACCESS),
		ace(mustSID(t, windows.WinWorldSid), windows.GENERIC_WRITE, windows.GRANT_ACCESS),
	)
	writers := writersFor(t, dacl)
	if len(writers) != 1 {
		t.Fatalf("want exactly the one untrusted writer, got %v", writers)
	}
	// The name is looked up so the operator knows what to remove; on a non-English Windows it is localised,
	// so assert that SOMETHING nameable came back rather than the exact string.
	if strings.TrimSpace(writers[0]) == "" {
		t.Fatal("an untrusted writer was found but not named — the operator cannot act on it")
	}
}

// ★ The mask exists to catch REPLACEMENT, not just overwriting. With delete-child on the directory, the
// agent's own file ACL is irrelevant: delete it and put your binary there under the same name. A mask that
// only looked at FILE_WRITE_DATA would call this directory clean.
func TestDeleteChildAloneCountsAsBeingAbleToReplaceTheAgent(t *testing.T) {
	const fileDeleteChild = 0x40
	dacl := aclOf(t,
		ace(mustSID(t, windows.WinLocalSystemSid), windows.GENERIC_ALL, windows.GRANT_ACCESS),
		ace(mustSID(t, windows.WinWorldSid), fileDeleteChild, windows.GRANT_ACCESS),
	)
	if writers := writersFor(t, dacl); len(writers) == 0 {
		t.Fatal("delete-child was not treated as the ability to replace the agent — it is: remove the file " +
			"and write your own in its place, and the file's own ACL never comes into it")
	}
}

// Read access is not the question. Flagging it would put a finding in front of an operator on directories
// that are correctly configured.
func TestReadOnlyAccessIsNotAWriter(t *testing.T) {
	dacl := aclOf(t,
		ace(mustSID(t, windows.WinLocalSystemSid), windows.GENERIC_ALL, windows.GRANT_ACCESS),
		ace(mustSID(t, windows.WinWorldSid), windows.GENERIC_READ|windows.GENERIC_EXECUTE, windows.GRANT_ACCESS),
	)
	if writers := writersFor(t, dacl); len(writers) != 0 {
		t.Fatalf("a read-only ACE was reported as a writer: %v", writers)
	}
}

// CREATOR OWNER is a template applied to newly created objects, not a principal that holds access to what is
// already there. Counting it produces the always-on warning this file exists to prevent.
func TestCreatorOwnerIsNotAWriter(t *testing.T) {
	dacl := aclOf(t,
		ace(mustSID(t, windows.WinLocalSystemSid), windows.GENERIC_ALL, windows.GRANT_ACCESS),
		ace(mustSID(t, windows.WinCreatorOwnerSid), windows.GENERIC_ALL, windows.GRANT_ACCESS),
	)
	if writers := writersFor(t, dacl); len(writers) != 0 {
		t.Fatalf("CREATOR OWNER was counted as a writer: %v — it is a template for new objects, so it says "+
			"nothing about who can rewrite what is already there", writers)
	}
}

// Only ALLOW aces grant. This is a documented simplification — the check summarises what an ACL PERMITS
// rather than running the access-check algorithm — and the test pins the direction of the error: a DENY ace
// must not be read as a grant.
func TestADenyAceIsNotAGrant(t *testing.T) {
	dacl := aclOf(t,
		ace(mustSID(t, windows.WinWorldSid), windows.GENERIC_WRITE, windows.DENY_ACCESS),
		ace(mustSID(t, windows.WinLocalSystemSid), windows.GENERIC_ALL, windows.GRANT_ACCESS),
	)
	if writers := writersFor(t, dacl); len(writers) != 0 {
		t.Fatalf("a DENY ace was counted as granting write access: %v", writers)
	}
}

// The syscall half: prove the probe is actually plumbed to a real directory on this platform. What it finds
// is not asserted — a temp directory legitimately grants the running user write access.
func TestTheProbeReadsARealDirectorysACL(t *testing.T) {
	dir := t.TempDir()
	var report selfIntegrityReport
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := probeDirectoryWritability(dir, info, &report); err != nil {
		t.Fatalf("the probe could not read the ACL of a directory it just created: %v", err)
	}
}

// A path that does not exist must be an ERROR, not a clean report. This is the distinction the shared tests
// tripped over: "I could not read the ACL" and "the ACL is fine" must not look the same.
func TestAMissingDirectoryIsAnErrorNotAPass(t *testing.T) {
	var report selfIntegrityReport
	missing := filepath.Join(t.TempDir(), "no-such-directory")
	if err := probeDirectoryWritability(missing, nil, &report); err == nil {
		t.Fatal("a directory that does not exist probed clean — 'could not tell' must not read as 'fine'")
	}
}
