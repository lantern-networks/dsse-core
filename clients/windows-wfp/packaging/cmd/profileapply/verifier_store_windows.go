//go:build windows

package main

// verifier_store_windows.go — holding the adopted profile verifier somewhere a standard user cannot reach.
//
// ★★★ WHY THIS EXISTS, AND WHY THE OBVIOUS PLACE WAS WRONG (2026-09-09, review point 1).
//
// The first attempt at restoring the verifier after a major upgrade read it back out of
// %ProgramData%\DSSE\profile_signing_key.txt. Measured on win-dev-1, that file is 0644 and its parent
// directory grants BUILTIN\Users Write and CREATOR OWNER GenericAll. The file's own ACL stops a standard user
// EDITING it; nothing stops a standard user CREATING it when it is absent, and then owning what they created.
// An upgrade that read it would install an attacker's authority as the thing this device verifies its
// configuration against — a standard-user privilege escalation delivered by the installer.
//
// Hardening that file afterwards is not the fix, and signing_key_artefact.go said so before this code existed:
// the file is the operator's DELIVERY, not the authority. service_args_windows.go states the same rule as
// review S1 — a pin read from beside the document it verifies can be replaced by whoever replaced the
// document, and the check becomes circular. So the fix is not to protect the file. It is to stop treating the
// file as a source of truth and keep the adopted key somewhere that is protected AT CREATION.
//
// ★ AT CREATION, not afterwards. Creating a key and then hardening its DACL leaves a window between the two
// calls in which the inherited ACL is in force, and on this box the inherited ACL is the permissive one. The
// key is therefore created by RegCreateKeyEx with an explicit SECURITY_ATTRIBUTES, so it has never in its life
// been writable by a standard user. HardenKeyACL remains right for the config store, which the MSI creates and
// hardens under its own elevated transaction; it is not right for the thing that decides what this device
// trusts.
//
// ★ AND A SEPARATE KEY FROM THE ENVELOPE. This lives at SOFTWARE\DSSE\Verifier, not under
// SOFTWARE\DSSE\Agent where configstore keeps the profile envelope. Putting the verifier beside the envelope
// would recreate review S1's circularity exactly: whoever could rewrite the envelope could rewrite the key
// that approves it.
//
// ★ AND THE GUARANTEE IS CHECKED BEFORE THE VALUE IS BELIEVED. Creating it protected is a claim about the
// past. A local administrator can rewrite any DACL, and a box that has been through one is not a box whose
// registry contents should silently decide what it trusts. So every read verifies the owner and walks the
// DACL first, and a key that does not still hold the guarantee yields a refusal — never a value.

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	// verifierStoreKeyPath is deliberately NOT configstore.DefaultKeyPath (SOFTWARE\DSSE\Agent). See above.
	verifierStoreKeyPath = `SOFTWARE\DSSE\Verifier`

	// verifierStoreSDDL is the security descriptor the key is CREATED with. "P" makes the DACL protected, so
	// the permissive parent ACL cannot flow back in by inheritance.
	//
	// ★ ADMINISTRATORS OWNS IT, NOT SYSTEM, AND THAT IS NOT COSMETIC (measured on win-dev-1). Assigning SYSTEM
	// as an owner needs SeRestorePrivilege, which the MSI's SYSTEM context has and an ELEVATED ADMINISTRATOR
	// does not: "O:SY" made every by-hand run fail with "This security ID may not be assigned as the owner of
	// this object", so the store would exist only on boxes provisioned through the installer. Administrators is
	// in both tokens with SE_GROUP_OWNER, so both contexts can create the same descriptor, and an
	// administrative owner is what verifierStoreGuarantee requires anyway.
	verifierStoreSDDL = "O:BAD:P(A;;KA;;;SY)(A;;KA;;;BA)(A;;KR;;;BU)"
)

// verifierStoreWriteMask is every right that would let a principal change what this device verifies against.
// GENERIC_WRITE and GENERIC_ALL are included because an ACE may carry unmapped generic bits, and reading such
// an ACE as harmless because none of the specific bits are set is exactly the mistake this check exists to
// avoid.
const verifierStoreWriteMask = registry.SET_VALUE | registry.CREATE_SUB_KEY | registry.CREATE_LINK |
	windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER |
	windows.GENERIC_WRITE | windows.GENERIC_ALL

var (
	advapi32            = syscall.NewLazyDLL("advapi32.dll")
	procRegCreateKeyExW = advapi32.NewProc("RegCreateKeyExW")
)

// createProtectedVerifierStore creates (or opens) the verifier key with verifierStoreSDDL applied at creation.
//
// x/sys/windows/registry.CreateKey cannot pass a SECURITY_ATTRIBUTES, which is the whole point here, so the
// one call is declared directly. On an existing key the descriptor is ignored by Windows — which is correct:
// this must not silently re-ACL a key someone else's policy owns. verifierStoreGuarantee is what decides
// whether an existing key is acceptable.
func createProtectedVerifierStore() (registry.Key, error) {
	sd, err := windows.SecurityDescriptorFromString(verifierStoreSDDL)
	if err != nil {
		return 0, fmt.Errorf("parse the verifier store's security descriptor: %w", err)
	}
	sa := windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(sa))

	path, err := windows.UTF16PtrFromString(verifierStoreKeyPath)
	if err != nil {
		return 0, err
	}
	var h windows.Handle
	var disposition uint32
	r, _, _ := procRegCreateKeyExW.Call(
		uintptr(windows.HKEY_LOCAL_MACHINE),
		uintptr(unsafe.Pointer(path)),
		0, 0,
		0, // REG_OPTION_NON_VOLATILE: the store must survive a reboot
		uintptr(registry.QUERY_VALUE|registry.SET_VALUE|windows.READ_CONTROL|registry.WOW64_64KEY),
		uintptr(unsafe.Pointer(&sa)),
		uintptr(unsafe.Pointer(&h)),
		uintptr(unsafe.Pointer(&disposition)),
	)
	if r != 0 {
		return 0, fmt.Errorf("create %s: %w", verifierStoreKeyPath, syscall.Errno(r))
	}
	return registry.Key(h), nil
}

// verifierValuePath names one stored value the way an operator would type it into regedit. A raw string
// literal so the separator needs no escaping — the escaped form has been mangled by enough tooling.
func verifierValuePath(name string) string { return verifierStoreKeyPath + `\` + name }

// openVerifierStore opens the key for reading, including READ_CONTROL so its own ACL can be inspected.
// registry.ErrNotExist is returned unwrapped so callers can tell "no store yet" from "a broken store".
func openVerifierStore() (registry.Key, error) {
	return registry.OpenKey(registry.LOCAL_MACHINE, verifierStoreKeyPath,
		registry.QUERY_VALUE|windows.READ_CONTROL|registry.WOW64_64KEY)
}

// verifierStoreGuarantee reports whether the key still is what it was created as: owned by an administrative
// principal, carrying a protected DACL, and granting write access to nobody outside that set.
//
// It returns a descriptive error rather than a bool because the caller must be able to print WHY it refused.
// "the verifier could not be trusted" sends an operator nowhere; naming the principal that holds the extra
// right sends them to the thing to remove.
func verifierStoreGuarantee(k registry.Key) error {
	sd, err := windows.GetSecurityInfo(windows.Handle(k), windows.SE_REGISTRY_KEY,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("read the security of %s: %w", verifierStoreKeyPath, err)
	}

	control, _, err := sd.Control()
	if err != nil {
		return fmt.Errorf("read the security control flags of %s: %w", verifierStoreKeyPath, err)
	}
	if control&windows.SE_DACL_PRESENT == 0 {
		// A NULL DACL grants everyone everything. It is the most permissive state a securable object has, and
		// it presents as "no ACL problems found" to anything that only walks ACEs.
		return fmt.Errorf("%s has NO DACL at all, which grants every principal full control", verifierStoreKeyPath)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return fmt.Errorf("%s no longer has a PROTECTED DACL, so the permissive parent ACL can flow back into "+
			"it by inheritance", verifierStoreKeyPath)
	}

	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("read the owner of %s: %w", verifierStoreKeyPath, err)
	}
	if !isAdministrativeSID(owner) {
		// The owner holds WRITE_DAC implicitly, so a non-administrative owner can restore its own access
		// whatever the DACL currently says.
		return fmt.Errorf("%s is owned by %s, which is not SYSTEM or Administrators — an owner can rewrite the "+
			"DACL regardless of what it currently says", verifierStoreKeyPath, sidLabel(owner))
	}

	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("read the DACL of %s: %w", verifierStoreKeyPath, err)
	}
	if dacl == nil {
		return fmt.Errorf("%s reports a DACL that is present and empty of structure", verifierStoreKeyPath)
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return fmt.Errorf("read ACE %d of %s: %w", i, verifierStoreKeyPath, err)
		}
		switch ace.Header.AceType {
		case windows.ACCESS_ALLOWED_ACE_TYPE:
		case windows.ACCESS_DENIED_ACE_TYPE:
			// A deny ACE only ever removes access, so it cannot create the exposure this checks for.
			continue
		default:
			// Object ACEs and callback ACEs can grant access through structures this does not decode.
			// Refusing an ACL that cannot be read completely is the only honest answer.
			return fmt.Errorf("%s carries an ACE of type %d that this check cannot decode, so it cannot state "+
				"that no standard user has write access", verifierStoreKeyPath, ace.Header.AceType)
		}
		if uint32(ace.Mask)&verifierStoreWriteMask == 0 {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(uintptr(unsafe.Pointer(ace)) + unsafe.Offsetof(ace.SidStart)))
		if isAdministrativeSID(sid) {
			continue
		}
		return fmt.Errorf("%s grants write access to %s, so its contents are not evidence of what this device "+
			"adopted", verifierStoreKeyPath, sidLabel(sid))
	}
	return nil
}

// trustedInstallerSID is NT SERVICE\TrustedInstaller, which owns and writes machine state on a serviced
// Windows install. It has no WELL_KNOWN_SID_TYPE constant, so it is named directly.
const trustedInstallerSID = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"

// isAdministrativeSID reports whether holding write access to the verifier store would tell us nothing new
// about the principal — because it is already able to replace the agent binary itself.
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

// readCapturedPins returns every pin this device has recorded, or an empty set when the store does not exist.
//
// An error means the store EXISTS and cannot be trusted, which is not the same as an absent store and must
// never be collapsed into one: absent is a box that has not recorded yet, untrusted is a box someone has been
// at. Callers restore on neither.
func readCapturedPins() (pinSet, error) {
	out := pinSet{}
	k, err := openVerifierStore()
	if err != nil {
		if err == registry.ErrNotExist {
			return out, nil
		}
		return nil, fmt.Errorf("open %s: %w", verifierStoreKeyPath, err)
	}
	defer k.Close()

	// ★ THE GUARANTEE IS CHECKED ONCE, BEFORE ANY VALUE IS READ, and a failure discards the whole set rather
	// than the offending value. A store that a standard user can write is not a store some of whose entries
	// happen to be fine.
	if err := verifierStoreGuarantee(k); err != nil {
		return nil, err
	}
	for _, purpose := range pinPurposes {
		v, _, gerr := k.GetStringValue(purpose.ValueName)
		if gerr != nil {
			if gerr == registry.ErrNotExist {
				continue
			}
			return nil, fmt.Errorf("read %s: %w", verifierValuePath(purpose.ValueName), gerr)
		}
		key := strings.TrimSpace(v)
		if key == "" {
			continue
		}
		// Shape-checked here as well as at delivery, for the reason readSigningKeyFile gives: a malformed
		// value verifies nothing, and the device falls to SAFE fail-closed defaults looking configured. Each
		// purpose validates its OWN shape — an update key set is not an Ed25519 key.
		if verr := purpose.Validate(key); verr != nil {
			return nil, fmt.Errorf("%s is not usable for %s: %w", verifierValuePath(purpose.ValueName),
				purpose.Flag, verr)
		}
		out[purpose.ValueName] = key
	}
	return out, nil
}

// recordCapturedPins stores the given pins under their own names and reports which ones changed.
//
// ★ THE CALLER MUST HAVE TAKEN THESE FROM A PROTECTED SOURCE. This writes; it does not adjudicate. The
// sources are provisioning, where the operator's explicit act is the authority, and the service arguments,
// which are set by an elevated installer and are as protected as the binary they name (review S1). Neither
// reads profile_signing_key.txt, and neither should.
//
// A purpose absent from `pins` is LEFT AS IT WAS rather than deleted: a capture that could only see some of
// the arguments must not erase a record of the others.
func recordCapturedPins(pins pinSet) (changed []string, err error) {
	for _, purpose := range pinPurposes {
		if v := pins.get(purpose.ValueName); v != "" {
			if verr := purpose.Validate(v); verr != nil {
				return nil, fmt.Errorf("refusing to record a value %s could not use: %w", purpose.Flag, verr)
			}
		}
	}
	k, err := createProtectedVerifierStore()
	if err != nil {
		return nil, err
	}
	defer k.Close()

	// Checked on the WRITE path too. If the key already existed with a weakened ACL, writing the right values
	// into it would produce a store that reads back correct and is still replaceable by whoever weakened it.
	if err := verifierStoreGuarantee(k); err != nil {
		return nil, err
	}
	for _, purpose := range pinPurposes {
		want := pins.get(purpose.ValueName)
		if want == "" {
			continue
		}
		if prev, _, gerr := k.GetStringValue(purpose.ValueName); gerr == nil &&
			strings.EqualFold(strings.TrimSpace(prev), want) {
			continue
		}
		if serr := k.SetStringValue(purpose.ValueName, want); serr != nil {
			return changed, fmt.Errorf("write %s: %w", verifierValuePath(purpose.ValueName), serr)
		}
		changed = append(changed, purpose.Service+" "+purpose.Flag)
	}
	return changed, nil
}

// clearAdoptedVerifier removes the whole record on a genuine uninstall.
//
// DeleteKey rather than deleting the values: an empty key left under SOFTWARE\DSSE is a place for the next
// thing to write into, and the point of this store is that its existence and its ACL are the same fact. An
// absent store is not an error — a box that never provisioned has none, and refusing an uninstall over it
// would be refusing to uninstall because there was nothing to remove.
func clearAdoptedVerifier() error {
	err := registry.DeleteKey(registry.LOCAL_MACHINE, verifierStoreKeyPath)
	if err == nil || err == registry.ErrNotExist {
		return nil
	}
	return fmt.Errorf("delete %s: %w", verifierStoreKeyPath, err)
}
