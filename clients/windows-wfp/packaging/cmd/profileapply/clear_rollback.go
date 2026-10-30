package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/lantern-networks/dsse-core/clients/windows-wfp/rollbackstore"
)

func ownedRollbackName(name string) bool {
	base := strings.TrimSuffix(name, rollbackstore.IntentMarkerPath(""))
	version := strings.TrimSuffix(strings.TrimPrefix(base, "dsse-agent-"), ".msi")
	expected, err := rollbackstore.FileName(version)
	return err == nil && expected == base
}

// Prune is runtime housekeeping: it deliberately skips empty/unreadable entries.
// An uninstall must also remove torn packages and orphan intent markers, and
// report every failed removal rather than treating them as an empty store.
func clearRollbackPackages(root string) error {
	entries, err := os.ReadDir(root)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var problems []error
	for _, entry := range entries {
		if !ownedRollbackName(entry.Name()) {
			continue
		}
		if entry.IsDir() {
			problems = append(problems, fmt.Errorf("rollback package path is a directory: %s", entry.Name()))
			continue
		}
		if err := os.Remove(filepath.Join(root, entry.Name())); err != nil && !os.IsNotExist(err) {
			problems = append(problems, fmt.Errorf("remove %s: %w", entry.Name(), err))
		}
	}
	entries, err = os.ReadDir(root)
	if err != nil && !os.IsNotExist(err) {
		problems = append(problems, err)
	}
	for _, entry := range entries {
		if ownedRollbackName(entry.Name()) {
			problems = append(problems, fmt.Errorf("rollback material remains: %s", entry.Name()))
		}
	}
	return errors.Join(problems...)
}
