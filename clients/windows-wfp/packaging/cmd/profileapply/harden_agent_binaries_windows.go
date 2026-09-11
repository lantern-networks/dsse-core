//go:build windows

package main

// harden_agent_binaries_windows.go — a standard user may not run the agent.
//
// ★★★ THE REQUIREMENT (2026-09-09, the operator's): nothing in this product is executable by anyone without
// administrative privilege.
//
// It is not satisfied by default and cannot be. %ProgramFiles% grants BUILTIN\Users ReadAndExecute and every
// file laid down under it inherits that, so a fresh install leaves all seven binaries runnable by any account
// on the machine — measured on win-dev-1 before this existed:
//
//	compatcheck.exe  driversvc.exe  dsse-steer.exe  dsse-stepup-window.exe
//	dsse-updater.exe  dsse-watchdog.exe  profileapply.exe      all: BUILTIN\Users ReadAndExecute
//
// ★ THE DACL IS PROTECTED, WHICH IS THE WHOLE MECHANISM. Removing the Users entry without setting "P" would
// let the inherited one flow straight back from the parent, and the next upgrade — which re-lays every file —
// would restore it silently. Protected means the parent cannot re-widen it.
//
// ★ THIS RUNS ON UPGRADES TOO, and has to. MSI recreates the files from the package, and a recreated file
// inherits the permissive parent again. The harden step is conditioned NOT Installed, which is TRUE during a
// MajorUpgrade (the new ProductCode is not yet installed), so the hardening is reapplied every time the files
// are.
//
// ★★★ AND ONE BINARY IS DELIBERATELY EXEMPT, because the product cannot work otherwise.
// dsse-stepup-window.exe is started by the SYSTEM agent with WTSQueryUserToken + CreateProcessAsUserW — it
// runs AS THE LOGGED-IN USER, in that user's session, because it is a window that user has to see and type
// into. CreateProcessAsUserW fails if the token holds no execute right on the image, so removing the user's
// access here does not harden step-up: it removes step-up. The exception is therefore not a relaxation of the
// rule but a statement of where the rule cannot reach, and it is narrowed to READ|EXECUTE on that single file.
//
// ★ THE EXCEPTION IS ACCEPTED, and by whom is worth recording: the operator, 2026-09-09, after being shown
// that CreateProcessAsUserW is what forces it. It is therefore not an unreviewed gap that a later reader
// should quietly close — closing it removes step-up authentication from the product. Anyone narrowing this
// further is reversing a decision, not tightening an oversight, and needs the same conversation again.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/lantern-networks/dsse-core/clients/windows-wfp/datadir"
	"golang.org/x/sys/windows"
)

// agentBinaryDACL is what every agent binary gets: full control to the three principals that already own the
// machine, and nobody else. "P" protects it from the permissive %ProgramFiles% inheritance.
//
// TrustedInstaller is kept because Windows servicing owns files under %ProgramFiles% and a file it cannot
// touch is a file that breaks servicing rather than a file that is safer.
const agentBinaryDACL = "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)"

// stepUpWindowDACL is agentBinaryDACL plus READ|EXECUTE for BUILTIN\Users (0x1200a9 = FILE_GENERIC_READ |
// FILE_GENERIC_EXECUTE). Read is inseparable from execute for an image the loader has to map.
const stepUpWindowDACL = agentBinaryDACL + "(A;;0x1200a9;;;BU)"

// stepUpWindowExe is the one binary a non-administrator must be able to start. Named here rather than derived,
// so that adding a second user-context binary is an edit somebody has to make on purpose.
const stepUpWindowExe = "dsse-stepup-window.exe"

// hardenAgentBinaries applies the protected DACLs to every executable in dir and reports what it did.
//
// Best-effort per file and never fatal to the caller's install: the MSI custom action is Return="ignore", and
// an install that rolls back because one ACL could not be set is worse than an install that reports it. But a
// FAILURE IS RETURNED as well as printed — a silent partial hardening is the state where the requirement is
// believed to hold and does not.
func hardenAgentBinaries(dir string) (lines []string, err error) {
	entries, rerr := os.ReadDir(dir)
	if rerr != nil {
		return nil, fmt.Errorf("read %s: %w", dir, rerr)
	}
	var failures []string
	for _, e := range entries {
		if e.IsDir() || !strings.EqualFold(filepath.Ext(e.Name()), ".exe") {
			continue
		}
		sddl := agentBinaryDACL
		note := "administrators and SYSTEM only"
		if strings.EqualFold(e.Name(), stepUpWindowExe) {
			sddl = stepUpWindowDACL
			note = "administrators, SYSTEM, and BUILTIN\\Users read+execute — it runs in the user's own " +
				"session by design (CreateProcessAsUserW) and cannot be locked to administrators"
		}
		path := filepath.Join(dir, e.Name())
		if serr := setProtectedFileDACL(path, sddl); serr != nil {
			failures = append(failures, e.Name())
			lines = append(lines, fmt.Sprintf("★ %s could NOT be hardened: %v", e.Name(), serr))
			continue
		}
		lines = append(lines, fmt.Sprintf("%-24s %s", e.Name(), note))
	}
	if len(lines) == 0 {
		return nil, fmt.Errorf("no executables found in %s — nothing was hardened, which is not the same as "+
			"nothing needing it", dir)
	}
	if len(failures) > 0 {
		return lines, fmt.Errorf("these remain runnable by a standard user: %s", strings.Join(failures, ", "))
	}
	return lines, nil
}

// setProtectedFileDACL replaces path's DACL with sddl and marks it protected, so the permissive parent ACL
// cannot flow back in by inheritance.
func setProtectedFileDACL(path, sddl string) error {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return fmt.Errorf("parse the DACL: %w", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("extract the DACL: %w", err)
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil)
}

// agentBinaryDir is where the MSI lays the binaries down: this executable's own directory. profileapply.exe
// co-installs with them in INSTALLDIR, so the exe's directory IS INSTALLDIR by construction — the same
// reasoning --config and installedAgentVersion already use.
func agentBinaryDir() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("locate this executable: %w", err)
	}
	return filepath.Dir(exe), nil
}

// ★★★ AND THE DIRECTORIES THAT HOLD EXECUTABLE MATERIAL (2026-09-09, found while measuring the requirement
// above). Locking the binaries in %ProgramFiles% is not sufficient on its own, because the same binaries exist
// a second time inside the stored installer packages — and those live in %ProgramData%, which grants
// BUILTIN\Users both Read AND Write by inheritance from the Windows default:
//
//	C:\ProgramData\DSSE\rollback   BUILTIN\Users  ReadAndExecute + Write   (two 26 MB MSIs)
//
// Read alone defeats the point of the file ACLs: a standard user extracts the agent from the package and runs
// their own copy. WRITE is worse, and it contradicts a security argument this tree makes out loud.
// updateplatform.ExecuteRollback declines to re-check the stored package's digest and says why:
//
//	"This package is not being fetched from anywhere — it is the one an installer stored on this disk,
//	 under a SYSTEM-only directory"
//
// It is not a SYSTEM-only directory. What stands between a planted package and msiexec running it as SYSTEM is
// VerifyPublisher, and the tree already documents what happens when a device carries no --update-publisher
// (RequirementMissingNote: "an MSI is installed as SYSTEM on ..."). A compensating control is not a reason to
// leave the assumption it compensates for untrue.
//
// ★ THE STATE ROOT KEEPS USERS' READ, and that is deliberate rather than a compromise. %ProgramData%\DSSE
// holds the trust material user-context programs have to read — ca-bundle-with-interception.pem and
// interception-root.pem are what NODE_EXTRA_CA_CERTS and the CA environment variables point at, and removing
// read there breaks every user application that has to trust this deployment's interception. WRITE is what
// creates the exposure (a standard user can create a file that does not exist yet, and CREATOR OWNER then
// gives them full control of what they made), so write is what is removed.

// stateRootDACL matches datadir.hardenedDACL exactly, and the two are meant to stay identical: Ensure sets it
// at creation, this re-asserts it on an existing tree, and a divergence between them would mean a box behaves
// differently depending on which component happened to make the directory.
//
// ★ THE USERS ACE CARRIES NO OI/CI. An earlier
// version of THIS function inherited Users read to everything below, which would have widened enroll/ — the
// device certificate and the DPAPI-wrapped key — to every account on the machine. Users get traverse and list
// on this one directory so they can reach the two public PEMs, whose own ACLs grant the read.
const stateRootDACL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x1200a9;;;BU)"

// privateSubdirs hold nothing a user-mode reader has any business opening: the enrolled identity, the staged
// and stored installer packages, the update journal.
var privateSubdirs = []string{"enroll", "rollback", "staged", "update"}

// publicFiles are the two PEMs the machine-wide CA variables point at. Named explicitly rather than by
// extension: a future .pem in this directory is private until somebody decides otherwise.
var publicFiles = []string{"interception-root.pem", "ca-bundle-with-interception.pem"}

// packageStoreDACL: nobody but SYSTEM and Administrators, because everything in here is an installer.
const packageStoreDACL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"

// hardenStateDirectories applies those DACLs and reports what each one now allows. A directory that is not
// there yet is not an error: the rollback store appears on the first install that stashes a package.
func hardenStateDirectories() (lines []string, err error) {
	root := os.Getenv("ProgramData")
	if strings.TrimSpace(root) == "" {
		root = `C:\ProgramData`
	}
	dsse := filepath.Join(root, "DSSE")
	var failures []string
	for _, d := range []struct {
		path string
		sddl string
		note string
	}{
		{dsse, stateRootDACL, "SYSTEM/Administrators full; Users may traverse and list THIS folder only"},
	} {
		if _, serr := os.Stat(d.path); os.IsNotExist(serr) {
			lines = append(lines, fmt.Sprintf("%-34s not present yet", d.path))
			continue
		}
		if serr := setProtectedFileDACL(d.path, d.sddl); serr != nil {
			failures = append(failures, d.path)
			lines = append(lines, fmt.Sprintf("★ %s could NOT be hardened: %v", d.path, serr))
			continue
		}
		lines = append(lines, fmt.Sprintf("%-34s %s", d.path, d.note))
	}
	// ★ THE PRIVATE SUBTREES ARE PROTECTED SEPARATELY, not by inheritance. They are what the root ACE
	// deliberately does not reach: the enrolled identity, the stored installers, the update journal.
	for _, name := range privateSubdirs {
		p := filepath.Join(dsse, name)
		if _, serr := os.Stat(p); os.IsNotExist(serr) {
			continue
		}
		if serr := setProtectedFileDACL(p, packageStoreDACL); serr != nil {
			failures = append(failures, p)
			lines = append(lines, fmt.Sprintf("★ %s could NOT be hardened: %v", p, serr))
			continue
		}
		lines = append(lines, fmt.Sprintf("%-34s SYSTEM/Administrators only", p))
	}

	// ★ AND THE TWO PUBLIC PEMs GET READ BACK EXPLICITLY. The machine-wide SSL_CERT_FILE, CURL_CA_BUNDLE,
	// GIT_SSL_CAINFO and NODE_EXTRA_CA_CERTS point at these, and they are read by curl, git, node and
	// everything linked against OpenSSL running as the logged-in user. Granted per file so the right does not
	// leak to whatever else is written into this directory later.
	for _, name := range publicFiles {
		p := filepath.Join(dsse, name)
		if _, serr := os.Stat(p); os.IsNotExist(serr) {
			continue
		}
		if serr := datadir.MakePublicReadable(p); serr != nil {
			failures = append(failures, p)
			lines = append(lines, fmt.Sprintf("★ %s could NOT be made readable by non-administrators: %v", p, serr))
			continue
		}
		lines = append(lines, fmt.Sprintf("%-34s Users READ (a machine-wide CA variable points at it)", p))
	}

	if len(failures) > 0 {
		return lines, fmt.Errorf("these remain writable by a standard user: %s", strings.Join(failures, ", "))
	}
	return lines, nil
}
