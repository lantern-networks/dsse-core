package updateplatform

// staging.go — where the verified .pkg waits, and the check immediately before it is run.
//
// The Windows side owns the equivalent and the reasoning is identical, so it is not re-derived here: bytes are
// verified while still under a temporary name, so the path the installer is pointed at only ever appears on a
// file that has already passed; and they are verified AGAIN at launch, because staging happens as soon as a
// manifest is applicable and execution waits for the maintenance window — the two are separated by design, so
// everything staging established is a statement about the past by the time the installer runs.
//
// No build tag: what could go wrong here — a truncated download accepted, a half-written file under the real
// name, bytes replaced between verification and execution — are failures of logic, and each ends in a
// privileged install of the wrong file.

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/lantern-networks/dsse-core/agentupdate"
	"github.com/lantern-networks/dsse-core/clients/windows-wfp/rollbackstore"
)

// StagedPath is where the artifact for a version is staged.
//
// The NAME comes from rollbackstore.FileName — the same validated formatter both platforms use — with the
// macOS extension. A version arrives from a signed manifest and is therefore an input; `../../etc/x` must
// never become a path a privileged installer is handed, and one formatter with one test is how that stays
// true in two places.
func StagedPath(version string) (string, error) {
	name, err := rollbackstore.FileNameFor(version, PackageExtension)
	if err != nil {
		return "", fmt.Errorf("updateplatform: staged path for %q: %w", version, err)
	}
	return filepath.Join(StagedRoot(), name), nil
}

// DefaultRollbackStore is the ONE place a macOS rollback store is constructed.
//
// It exists because the wiring is where this went wrong: the naming rules are shared with Windows, and the
// only macOS-specific part is the extension — so the extension has to be applied at construction, every time.
// A caller that reaches for rollbackstore.New directly gets a store looking for .msi files that no macOS
// installer will ever write, and the symptom is ErrNoMaterial on every device with nothing erroring anywhere.
func DefaultRollbackStore() *rollbackstore.Store {
	return rollbackstore.NewForPackages(RollbackRoot(), PackageExtension)
}

// PackageExtension is what an installer package is called here. It is one constant because the INSTALLER
// writes the rollback file and the UPDATER looks it up, and those are different programs on the same machine —
// a postinstall storing .pkg while Lookup asks for .msi is ErrNoMaterial forever, silently.
const PackageExtension = ".pkg"

// VerifyStaged re-checks the staged package against the manifest and returns its path, immediately before the
// installer is launched. See the file comment for why a second check is not redundant.
func VerifyStaged(m agentupdate.Manifest) (string, error) {
	p, err := StagedPath(m.Version)
	if err != nil {
		return "", err
	}
	f, err := os.Open(p)
	if err != nil {
		return "", fmt.Errorf("refusing to launch the installer for %s: %w", m.Version, err)
	}
	defer f.Close()
	if verr := agentupdate.VerifyArtifact(f, m); verr != nil {
		return "", fmt.Errorf("refusing to launch the installer for %s: the staged package does not match the "+
			"manifest: %w", m.Version, verr)
	}
	return p, nil
}
