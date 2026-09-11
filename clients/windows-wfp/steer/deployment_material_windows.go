package main

// deployment_material_windows.go — putting the derived deployment material where this machine's agent already
// looks for it. The derivation itself is in deployment_material.go and is platform-neutral on purpose; only
// the writing is a Windows act.

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"github.com/lantern-networks/dsse-core/clients/windows-wfp/datadir"
	"github.com/lantern-networks/dsse-core/durablefile"
	"github.com/lantern-networks/dsse-core/installprofile"
)

// applyDeploymentMaterial writes the profile-carried material to the well-known locations under %ProgramData%,
// and returns one line per thing it actually changed. stateDir is the enrolment directory; the provisioned
// transport pin and the interception root live beside it, which is where every other part of this agent already
// reads them from.
//
// ★ IT WRITES ONLY WHAT CHANGED, AND SAYS SO. A rewrite on every start would make the file's timestamp
// meaningless as evidence, and this is the file an operator looks at when asking "when did this box's anchor
// last move". Silence here means the profile agrees with what is on disk, which is the ordinary case.
//
// ★ IT DOES NOT TOUCH THE OPERATING SYSTEM'S TRUST STORE. Carrying the interception root to the machine and
// trusting it are different acts with different blast radii: the first is a file, the second changes what every
// program on this box believes about the whole internet. The agent does the first. What the machine actually
// trusts is still reported by interceptionRootsPresent, by looking, which is the only honest source.
func applyDeploymentMaterial(m installprofile.DeploymentMaterial, stateDir string) []string {
	var notes []string
	base := filepath.Dir(stateDir)
	if base == "" || base == "." {
		return []string{"deployment material: no state directory to write to — nothing was provisioned"}
	}
	if err := os.MkdirAll(base, 0o755); err != nil {
		return []string{fmt.Sprintf("deployment material: cannot create %s (%v) — nothing was provisioned", base, err)}
	}

	if len(m.TransportAnchorsPEM) > 0 {
		path := transportPinPath("")
		if changed, err := writeIfChanged(path, m.TransportAnchorsPEM); err != nil {
			notes = append(notes, fmt.Sprintf("deployment material: could not write the transport anchors to %s: %v", path, err))
		} else if changed {
			notes = append(notes, fmt.Sprintf("the profile provisioned %d transport anchor(s) -> %s", len(m.AnchorFingerprints), path))
			for i, s := range m.AnchorSubjects {
				fp := ""
				if i < len(m.AnchorFingerprints) {
					fp = " sha256=" + m.AnchorFingerprints[i]
				}
				notes = append(notes, "  anchor: "+s+fp)
			}
		}
	}

	if len(m.InterceptionRootPEM) > 0 {
		path := filepath.Join(base, "interception-root.pem")
		if changed, err := writeIfChanged(path, m.InterceptionRootPEM); err != nil {
			notes = append(notes, fmt.Sprintf("deployment material: could not write the interception root to %s: %v", path, err))
		} else {
			// Atomic replacement creates a new file with the private parent ACL. Restore public
			// read access after replacement, and repair it on unchanged material as well.
			if err := datadir.MakePublicReadable(path); err != nil {
				notes = append(notes, fmt.Sprintf("deployment material: public interception root is not readable by normal users at %s: %v", path, err))
			}
			if changed {
				notes = append(notes, fmt.Sprintf("the profile provisioned this organization's interception root -> %s "+
					"(carried, NOT trusted — putting it in the machine's Root store is a separate, deliberate act)", path))
			}
		}
	}
	return notes
}

// writeIfChanged writes content only when it differs from what is there, and reports whether it wrote.
//
// ★ THE DURABILITY IS durablefile's, NOT A SECOND COPY OF IT. This function staged its own temp file and
// renamed it — reasonable line by line, and exactly the shape the "one durable write" gate exists to stop:
// on Windows the replace has to clear the read-only attribute and restore it if the rename fails, and a
// hand-rolled copy silently misses that. A half-written anchor file is a box that cannot verify its Edge,
// and on a fail-closed posture that is a box with no network — so this is the wrong place to keep a copy.
func writeIfChanged(path string, content []byte) (bool, error) {
	if existing, err := os.ReadFile(path); err == nil && bytes.Equal(existing, content) {
		return false, nil
	}
	if err := durablefile.Write(path, content, 0o644); err != nil {
		return false, err
	}
	return true, nil
}
