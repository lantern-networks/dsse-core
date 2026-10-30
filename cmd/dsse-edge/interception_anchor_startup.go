package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/lantern-networks/dsse-core/edgeplane"
)

// The constructors load signing material but must not overwrite an existing
// public anchor before the durable re-parent is restored. No network listener
// is started until this sequence succeeds.
func restoreAndPublishInterceptionAnchor(engine *edgeplane.NetworkExtensionLabTLSInterception, stateDir, providerExport string, sourcePaths ...string) error {
	if engine == nil {
		return nil
	}
	if stateDir = strings.TrimSpace(stateDir); stateDir != "" {
		sourcePaths = append(append([]string(nil), sourcePaths...), filepath.Join(stateDir, "interception_reparent_pair.json"))
	}
	// Record a provider's export before restoration so a valid durable adoption
	// can update it. Preparation must never publish the original provider root.
	if providerExport != "" {
		if err := engine.PrepareActiveAnchorExport(providerExport, sourcePaths...); err != nil {
			return fmt.Errorf("prepare public interception anchor export: %w", err)
		}
	}
	// A restore can publish to the recorded offline export path. Validate it
	// before restoring, so it can never replace an input signer certificate/key.
	if err := engine.ValidateActiveAnchorExportInputs(sourcePaths...); err != nil {
		return fmt.Errorf("interception export aliases input authority material: %w", err)
	}
	edgeplane.ReapplyPersistedReparent(engine, stateDir)
	if reason, failed := engine.InterceptionIntermediateStatus()["reparent_restore_failed"]; failed {
		return fmt.Errorf("durable interception authority could not be restored: %v", reason)
	}
	if err := engine.PublishActiveAnchorExport(); err != nil {
		return fmt.Errorf("publish public interception anchor: %w", err)
	}
	path := engine.ActiveAnchorExportPath()
	if path == "" {
		return nil // Explicitly no file export; authenticated API remains available.
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read back public interception anchor: %w", err)
	}
	disk, err := edgeplane.ParseInterceptionCertPEM(data)
	if err != nil {
		return fmt.Errorf("parse exported public interception anchor: %w", err)
	}
	live, err := edgeplane.ParseInterceptionCertPEM(engine.RootCertificatePEM())
	if err != nil || disk == nil || live == nil || !bytes.Equal(disk.Raw, live.Raw) {
		return fmt.Errorf("exported interception anchor does not match the restored authority")
	}
	return nil
}
