//go:build windows

package rollbackstore

// protect_windows.go — the package store is created protected, before a package is written into it.
//
// The store needs protection at creation, before it contains any package.
// datadir.Ensure protects %ProgramData%\DSSE, but this directory is a level below it and was created by a bare
// os.MkdirAll — so it inherited whatever the parent allowed. Measured on win-dev-1 before this existed:
//
//	C:\ProgramData\DSSE\rollback   BUILTIN\Users  ReadAndExecute + Write   (two 26 MB MSIs)
//
// Read alone defeats the file ACLs on %ProgramFiles%\DSSE: a standard user extracts the agent from the stored
// package and runs their own copy. Write is worse, and it falsifies a security argument this tree makes out
// loud — updateplatform.ExecuteRollback declines to re-check the stored package's digest because it is "under
// a SYSTEM-only directory". What actually stands between a planted package and msiexec running it as SYSTEM is
// VerifyPublisher, and this tree already documents what a device with no --update-publisher does.
//
// ★ AND IT IS DONE HERE, NOT BY AN INSTALLER STEP AFTERWARDS. An installer that hardens the directory after
// the fact proves nothing about the package already inside it: the window between creation and hardening is
// exactly when a standard user could have written one. Protecting at creation, before the first Stash copies
// anything in, means there has never been a moment when the store held a package a non-administrator could
// have placed.
//
// A pre-existing directory is REPORTED, not silently re-ACLed, for the reason datadir gives: an installer that
// rewrites ACLs it did not create is how the util:PermissionEx attempt rolled installs back on this product.
// The caller decides what to do with a store that was already open.

import (
	"fmt"
	"github.com/lantern-networks/dsse-core/clients/windows-wfp/datadir"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// storeDACL: LocalSystem and Administrators, and nobody else. Stricter than the data root above it, which
// keeps Users read because the CA bundle and interception root live there and every own-bundle program on the
// machine has to read them (SSL_CERT_FILE, CURL_CA_BUNDLE, GIT_SSL_CAINFO, NODE_EXTRA_CA_CERTS all point
// inside it). Nothing in user mode needs an installer package. "P" protects it from the parent's inheritance.
// ★ OWNED BY ADMINISTRATORS AT CREATION, not merely ACL'd. An owner holds WRITE_DAC implicitly, so a
// directory whose owner is a standard user can have its DACL rewritten by that user whatever it currently
// says — and verifyACL refuses exactly that. Assigning SYSTEM would need SeRestorePrivilege, which the
// installer's SYSTEM context has and an elevated administrator does not; Administrators is in both tokens
// with SE_GROUP_OWNER, so both can create the same descriptor. Same finding as the verifier store.
const storeDACL = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"

// createProtected makes dir with storeDACL applied at creation, and reports whether it already existed.
//
// It returns preExisting=true without touching the DACL when the directory is already there, so the caller can
// say so rather than assume the guarantee holds.
func createProtected(dir string) (preExisting bool, err error) {
	if fi, serr := os.Stat(dir); serr == nil {
		if !fi.IsDir() {
			return false, fmt.Errorf("rollbackstore: %s exists and is not a directory", dir)
		}
		return true, nil
	} else if !os.IsNotExist(serr) {
		return false, fmt.Errorf("rollbackstore: stat %s: %w", dir, serr)
	}

	sd, err := windows.SecurityDescriptorFromString(storeDACL)
	if err != nil {
		return false, fmt.Errorf("rollbackstore: parse the store DACL: %w", err)
	}
	sa := windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(sa))

	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return false, err
	}
	if err := windows.CreateDirectory(p, &sa); err != nil {
		if err == windows.ERROR_ALREADY_EXISTS {
			// Lost a race. Whoever won it owns the DACL decision, and the pre-existing rule applies for the
			// same reason it does above.
			return true, nil
		}
		return false, fmt.Errorf("rollbackstore: create %s: %w", dir, err)
	}
	return false, nil
}

// fileDeleteChild is FILE_DELETE_CHILD, which x/sys/windows does not name. On a DIRECTORY it lets a holder
// delete files inside it REGARDLESS of those files' own ACLs — so a store granting it to Users is a store
// whose packages can be swapped, however carefully each package is protected.
const fileDeleteChild = 0x40

// storeWriteMask is every right that would let a principal replace a package in the store. GENERIC_WRITE and
// GENERIC_ALL are included because an ACE may carry unmapped generic bits, and reading such an ACE as harmless
// because none of the specific bits are set is exactly the mistake this check exists to avoid.
const storeWriteMask = windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.FILE_WRITE_EA |
	windows.FILE_WRITE_ATTRIBUTES | fileDeleteChild | windows.DELETE | windows.WRITE_DAC |
	windows.WRITE_OWNER | windows.GENERIC_WRITE | windows.GENERIC_ALL | windows.FILE_APPEND_DATA | windows.FILE_WRITE_EA |
	windows.FILE_WRITE_ATTRIBUTES | windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER |
	windows.GENERIC_WRITE | windows.GENERIC_ALL

// trustedInstallerSID is NT SERVICE\TrustedInstaller, which owns and writes machine state on a serviced
// Windows install. It has no WELL_KNOWN_SID_TYPE constant, so it is named directly.
const trustedInstallerSID = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"

// verifyStore reports whether dir still holds the guarantee createProtected gives it: owned by an
// administrative principal, carrying a protected DACL, and granting write to nobody outside that set.
//
// ★★★ TWO CONTROL BITS WERE NOT A CHECK. The first version
// returned true when SE_DACL_PRESENT and SE_DACL_PROTECTED were set, and never looked at the owner or a single
// ACE — so `D:P(A;;FA;;;WD)`, a protected DACL granting Everyone full control, read as "protected". A test
// that passes on the worst case it is meant to catch is not a weak test, it is a decoration.
//
// It returns a descriptive error rather than a bool because the caller must be able to print WHY: naming the
// principal that holds the extra right sends an operator to the thing to remove.
// verifyStore is the DIRECTORY check: the DACL must additionally be PROTECTED, because that is what stops
// the permissive %ProgramData% entries flowing back in by inheritance.
func verifyStore(dir string) error { return verifyACL(dir, true, storeWriteMask) }

// verifyACL walks owner and every ACE, and optionally requires the DACL to be protected.
//
// ★ THE CHILD MUST NOT BE REQUIRED TO BE PROTECTED, and getting this wrong rejected the correct state. A file
// created inside an already-protected directory INHERITS that directory's entries, so SE_DACL_PROTECTED is
// unset on it — which is exactly what should happen. Demanding it on the package would refuse every normally
// stored MSI while accepting one somebody had deliberately given its own protected-but-open descriptor.
func verifyACL(dir string, requireProtected bool, mask uint32) error {
	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("read the security of %s: %w", dir, err)
	}
	control, _, err := sd.Control()
	if err != nil {
		return fmt.Errorf("read the security control flags of %s: %w", dir, err)
	}
	if control&windows.SE_DACL_PRESENT == 0 {
		// A NULL DACL grants everyone everything. It is the most permissive state a securable object has, and
		// it presents as "no ACL problems found" to anything that only walks ACEs.
		return fmt.Errorf("%s has NO DACL at all, which grants every principal full control", dir)
	}
	if requireProtected && control&windows.SE_DACL_PROTECTED == 0 {
		return fmt.Errorf("%s does not have a PROTECTED DACL, so the permissive %%ProgramData%% ACL can flow "+
			"back into it by inheritance", dir)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("read the owner of %s: %w", dir, err)
	}
	if !isAdministrativeSID(owner) {
		// The owner holds WRITE_DAC implicitly, so a non-administrative owner can restore its own access
		// whatever the DACL currently says.
		return fmt.Errorf("%s is owned by %s, which is not SYSTEM or Administrators — an owner can rewrite the "+
			"DACL regardless of what it currently says", dir, sidLabel(owner))
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("read the DACL of %s: %w", dir, err)
	}
	if dacl == nil {
		return fmt.Errorf("%s reports a DACL that is present and empty of structure", dir)
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return fmt.Errorf("read ACE %d of %s: %w", i, dir, err)
		}
		switch ace.Header.AceType {
		case windows.ACCESS_ALLOWED_ACE_TYPE:
		case windows.ACCESS_DENIED_ACE_TYPE:
			// A deny ACE only ever removes access, so it cannot create the exposure this checks for.
			continue
		default:
			// Object and callback ACEs can grant access through structures this does not decode. Refusing an
			// ACL that cannot be read completely is the only honest answer.
			return fmt.Errorf("%s carries an ACE of type %d that this check cannot decode, so it cannot state "+
				"that no standard user can replace a package here", dir, ace.Header.AceType)
		}
		// ★ AN INHERIT-ONLY ACE GRANTS NOTHING ON THE OBJECT CARRYING IT. C: carries
		// (A;OICIIO;SDGXGWGR;;;AU) by Windows default — Authenticated Users, delete and generic write, INHERIT
		// ONLY. It applies to children, not to C: itself, and each child is checked on its own ACL, so reading
		// it as "anyone may replace C:\" would refuse every stock Windows volume.
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		if uint32(ace.Mask)&mask == 0 {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(uintptr(unsafe.Pointer(ace)) + unsafe.Offsetof(ace.SidStart)))
		if isAdministrativeSID(sid) {
			continue
		}
		// ★ CREATOR OWNER IS NOT A PRINCIPAL. S-1-3-0 is an inheritance TEMPLATE: it grants nobody anything on
		// the object carrying it, and is replaced by the creator's real SID on objects created below. Both
		// %ProgramData% and %WINDIR%Temp carry it by Windows default, so reading it as "a non-administrator can
		// write here" would refuse every stock installation. What it templates IS caught, on the child, where the
		// ACE carries a real SID — which is how the fixture that granted the test user full control was found.
		if creatorOwner, err := windows.StringToSid("S-1-3-0"); err == nil && sid.Equals(creatorOwner) {
			continue
		}
		return fmt.Errorf("%s grants write access to %s, so a package stored here is not evidence of what this "+
			"device was given", dir, sidLabel(sid))
	}
	return nil
}

// isAdministrativeSID reports whether holding write access here would tell us nothing new about the principal
// — because it is already able to replace the agent binary itself.
func isAdministrativeSID(sid *windows.SID) bool {
	if sid == nil {
		return false
	}
	for _, t := range []windows.WELL_KNOWN_SID_TYPE{windows.WinLocalSystemSid, windows.WinBuiltinAdministratorsSid} {
		if known, err := windows.CreateWellKnownSid(t); err == nil && sid.Equals(known) {
			return true
		}
	}
	if ti, err := windows.StringToSid(trustedInstallerSID); err == nil && sid.Equals(ti) {
		return true
	}
	return false
}

// sidLabel renders a SID for an operator: the account name when it resolves, the SID string when it does not.
// A deleted or foreign-domain account has no name and is exactly the case worth printing precisely.
func sidLabel(sid *windows.SID) string {
	if sid == nil {
		return "(no SID)"
	}
	if account, domain, _, err := sid.LookupAccount(""); err == nil {
		if domain != "" {
			return domain + `\` + account + " (" + sid.String() + ")"
		}
		return account + " (" + sid.String() + ")"
	}
	return sid.String()
}

// VerifyStoreAndPackage is the check a caller must pass before treating a stored package as restore material.
//
// ★★★ WHY A MARKER FILE WAS NOT A FIX. The previous attempt wrote
// ".store-unverified" beside the packages when the directory could not be shown safe, and carried on. Three
// things were wrong with it at once: nothing ever read it, so msiexec's launch conditions were unchanged; it
// lived in the very directory an attacker could write, so it could simply be deleted; and a read failure
// returned "not marked", so absence was being treated as evidence of safety. A guarantee that an attacker can
// erase is not a guarantee, and one nobody consults is not a check.
//
// So the store is verified at the moment it matters, twice: Stash refuses to write into a store it cannot
// vouch for, and the rollback path re-verifies immediately before launching the installer. Nothing is
// inferred from the absence of a file.
//
// ★ AND THE PACKAGE ITSELF, NOT ONLY THE DIRECTORY. A protected directory whose child MSI carries an explicit
// Users:Write ACE is a directory that passes a directory check and hands msiexec an attacker's bytes as
// SYSTEM. FILE_DELETE_CHILD on the parent is the same hole from the other side — it lets a holder replace a
// file whose own ACL is perfect — which is why it is in storeWriteMask.
//
// ★ AND NEITHER MAY BE A REPARSE POINT. A junction or symlink means the name that was verified and the bytes
// that will be installed are two different objects, and the substitution can be made between the check and
// the launch by anyone who can write the parent.
func VerifyStoreAndPackage(dir, pkg string) error {
	var err error
	dir, err = filepath.Abs(dir)
	if err != nil {
		return err
	}
	if pkg != "" {
		pkg, err = filepath.Abs(pkg)
		if err != nil {
			return err
		}
	}
	if err := verifyNotReparsePoint(dir); err != nil {
		return err
	}
	if err := verifyStore(dir); err != nil {
		return err
	}
	// ★ AND FROM ABOVE. A protected store inside a parent whose children Users may delete is a store that can
	// be replaced wholesale, ACL and all, by someone who then owns the replacement.
	if err := verifyAncestry(dir); err != nil {
		return err
	}
	if pkg == "" {
		return nil
	}
	// ★ AND THE PACKAGE MUST BE A PLAIN FILE DIRECTLY INSIDE THE STORE THAT WAS JUST VERIFIED. A path that
	// merely ends up somewhere else — through a different directory, or a directory of its own — inherits none
	// of what was checked above.
	if !strings.EqualFold(filepath.Dir(filepath.Clean(pkg)), filepath.Clean(dir)) {
		return fmt.Errorf("%s is not directly inside the verified store %s", pkg, dir)
	}
	if fi, serr := os.Lstat(pkg); serr != nil {
		return fmt.Errorf("read %s: %w", pkg, serr)
	} else if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", pkg)
	}
	if err := verifyNotReparsePoint(pkg); err != nil {
		return err
	}
	// The same walk as the directory: a package a standard user can rewrite is not evidence of what this
	// device was given, whatever the directory around it allows.
	// The package inherits the store's entries, which were just verified, so it is checked for owner and ACEs
	// but NOT for protection — see verifyACL.
	if err := verifyACL(pkg, false, storeWriteMask); err != nil {
		return fmt.Errorf("the stored package is not protected: %w", err)
	}
	return nil
}

// verifyNotReparsePoint refuses a path that is a junction, symlink or mount point.
func verifyNotReparsePoint(path string) error {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	attrs, err := windows.GetFileAttributes(p)
	if err != nil {
		return fmt.Errorf("read the attributes of %s: %w", path, err)
	}
	if attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("%s is a reparse point, so the name checked here and the bytes that would be "+
			"installed are not necessarily the same object", path)
	}
	return nil
}

// ancestorReplaceMask is the set of rights on a PARENT that would let a principal swap out the directory
// underneath — delete the protected store and put their own in its place.
//
// ★ DELIBERATELY NOT PLAIN WRITE. %ProgramData% grants BUILTIN\Users "create files" and "create folders" by
// Windows default, and that is not the hole: creating a SIBLING of DSSE does not touch DSSE. What matters is
// the right to remove or re-own the child — FILE_DELETE_CHILD on the parent, or DELETE / WRITE_DAC /
// WRITE_OWNER reaching the child itself. Refusing plain write here would refuse every stock Windows install
// and teach an operator that the check is noise.
const ancestorReplaceMask = fileDeleteChild | windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER |
	windows.GENERIC_ALL

// verifyAncestry refuses a path that a non-administrator could substitute from above.
//
// Protecting the store's own DACL says who may write INSIDE it. It says nothing about who may delete the
// directory and create a new one with the same name — and the replacement would be created by that user, who
// then owns it and its contents. Every ancestor up to the volume root is therefore checked for the rights
// that permit that, and for reparse points, because a junction anywhere on the path means the name verified
// here and the object opened later need not be the same.
func verifyAncestry(dir string) error {
	p, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	for {
		parent := filepath.Dir(p)
		if parent == p {
			return nil // reached the volume root
		}
		if err := verifyNotReparsePoint(parent); err != nil {
			return fmt.Errorf("an ancestor of %s cannot be trusted: %w", dir, err)
		}
		if err := verifyACL(parent, false, ancestorReplaceMask); err != nil {
			return fmt.Errorf("an ancestor of %s could be substituted: %w", dir, err)
		}
		p = parent
	}
}

// verifyStoreForWriting is the gate Stash runs BEFORE any path that can report success.
//
// A store that does not exist yet is not a failure: createProtected is about to make it, and the check that
// follows creation covers what it made. What is verified in that case is the ANCESTRY, because a parent
// somebody can substitute is a parent that can hand us a directory of their choosing to create into.
func verifyStoreForWriting(root string) error {
	if _, err := os.Stat(root); err != nil {
		if os.IsNotExist(err) {
			return verifyAncestry(root)
		}
		return fmt.Errorf("rollbackstore: stat %s: %w", root, err)
	}
	if err := VerifyStoreAndPackage(root, ""); err != nil {
		return fmt.Errorf("rollbackstore: refusing to use %s as restore material storage: %w", root, err)
	}
	return nil
}

// Only the default store owns creation of the deployment data parent. Every root still passes the same checks.
func prepareStoreForWriting(root string) error {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	absDefault, err := filepath.Abs(DefaultRoot())
	if err != nil {
		return err
	}
	if !strings.EqualFold(absRoot, absDefault) {
		return nil
	}
	_, err = datadir.Ensure()
	return err
}

// Reuse and newly published packages must meet the same requirements as execution.
func verifyStoredPackageForWriting(root, pkg string) error {
	return VerifyStoreAndPackage(root, pkg)
}

// claimStoredPackage assigns Administrators as the owner of a package this process just wrote.
//
// ★★★ WHY WRITING IT INTO A PROTECTED DIRECTORY IS NOT ENOUGH (2026-09-09). The file inherits the store's
// DACL, which is right — but the OWNER of a newly created file is whoever created it, and an owner holds
// WRITE_DAC implicitly. So a package written by an elevated administrator, rather than by SYSTEM, is a package
// that administrator can re-permission at will, and verifyACL refuses it for exactly that reason. In
// production the stash runs as SYSTEM inside an MSI custom action and the point is moot; by hand, or in a
// test, it is the difference between the guarantee holding and not.
//
// Administrators rather than SYSTEM for the reason established elsewhere in this tree: assigning SYSTEM needs
// SeRestorePrivilege, which an elevated administrator does not hold, so "O:SY" would work only when the
// installer ran it.
func claimStoredPackage(path string) error {
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return fmt.Errorf("rollbackstore: resolve the Administrators SID: %w", err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION, admins, nil, nil, nil); err != nil {
		return fmt.Errorf("rollbackstore: set the owner of %s: %w", path, err)
	}
	return nil
}
