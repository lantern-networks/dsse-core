//go:build windows

// update_courier_write_windows.go — the one OS-specific thing the couriers do: put bytes on disk in a way the
// updater can never catch half-written.
//
// The couriers themselves (update_manifest_sync.go and the plan courier beside it) are portable Go, because
// what they decide — when to write, when to keep, what counts as plausible — is the content. This file is the
// rename dance and nothing else.
//
// WHY ATOMICITY IS NOT OPTIONAL HERE. The updater re-reads these files on EVERY pass, on its own schedule,
// with no lock and no coordination with this process. A plain os.WriteFile is a truncate followed by a write,
// so a tick landing in that gap sees an empty or partial file — and for the manifest that is not a retry, it
// is `ErrManifestRejected`, which by design means "the release process is broken or artefacts are being
// substituted, look tonight". Torn writes here manufacture security alarms.
package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/lantern-networks/dsse-core/clients/windows-wfp/datadir"

	"github.com/lantern-networks/dsse-core/durablefile"
)

// courierWriteAtomic writes b to path via a temporary file in the SAME directory, then renames.
//
// Same directory specifically: a rename across volumes is not atomic, and %ProgramData% and %TEMP% are not
// guaranteed to be on one. The temp name is prefixed rather than suffixed so a reader globbing for the real
// name never matches it.
func courierWriteAtomic(path string, b []byte) error {
	// Through datadir rather than a bare MkdirAll, because a bare one INHERITS %ProgramData%'s DACL — which
	// grants BUILTIN\Users write (measured, not assumed). This directory ends up holding the installer package
	// msiexec runs as SYSTEM, so whoever creates it first decides whether a non-admin can replace that. There
	// are three racing creators and this is one of them.
	if st, err := datadir.Ensure(); err != nil {
		return err
	} else if d := st.Describe(); d != "" && st.PreExisting {
		// Said once per write is too often for a healthy box, but a pre-existing directory means the protection
		// may simply be absent and nothing else in the system looks. Printed rather than swallowed; the noise is
		// the point on the box where it is true.
		log.Print(d)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	// ★ ONE DURABLE WRITE, AND IT CLOSES A WINDOW (2026-08-14). The hand-written version removed the previous
	// file first, because a plain rename onto an existing name fails on Windows — which left a moment with
	// no file at all, and the comment here acknowledged it as "acceptable and bounded". durablefile's
	// Windows half uses MoveFileEx(REPLACE_EXISTING|WRITE_THROUGH), so the replacement is atomic and the
	// window is not bounded, it is gone.
	if err := durablefile.Write(path, b, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// courierDataDir is %ProgramData%\DSSE — where both couriered documents live, beside the rollback store and
// the staged artifact, and NOT in the install directory: an upgrade rewrites that and an uninstall removes it,
// so a manifest kept there would vanish during the install it describes.
func courierDataDir() string { return datadir.Root() }
