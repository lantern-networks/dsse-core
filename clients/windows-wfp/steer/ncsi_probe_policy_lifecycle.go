package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

// ncsiPolicyOps keeps the registry and SCM operations injectable so the backup/restore ordering can be
// checked without changing a real Windows host's connectivity policy.
type ncsiPolicyOps struct {
	backupPath string
	read       func() (string, bool, error)
	write      func(uint32) error
	delete     func() error
	restart    func(string) error
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func ncsiBackupValue(prior string) (uint32, bool, error) {
	if prior == "absent" {
		return 0, true, nil
	}
	if !isAllDigits(prior) {
		return 0, false, errors.New("invalid NCSI backup value")
	}
	v, err := strconv.ParseUint(prior, 10, 32)
	if err != nil {
		return 0, false, errors.New("NCSI backup value outside DWORD range")
	}
	return uint32(v), false, nil
}

// ncsiSaveBackup writes a complete snapshot before the registry can change. A failed write leaves no
// authoritative backup and the caller must not suppress the OS probe.
func ncsiSaveBackup(path, prior string) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".dsse-ncsi-backup-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write([]byte(prior)); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	// A hard link publishes the fully synced file atomically and, unlike a Rename after Stat, never replaces
	// another service/recovery process's original snapshot. A filesystem without hard-link support causes a
	// safe suppression hold rather than changing policy without a durable original.
	return os.Link(f.Name(), path)
}

func ncsiSuppressWith(ops ncsiPolicyOps) (string, error) {
	b, err := os.ReadFile(ops.backupPath)
	if errors.Is(err, os.ErrNotExist) {
		prior, exists, readErr := ops.read()
		if readErr != nil {
			return "", fmt.Errorf("read original NCSI policy: %w", readErr)
		}
		if !exists {
			prior = "absent"
		}
		if _, _, err := ncsiBackupValue(prior); err != nil {
			return "", err
		}
		if err := ncsiSaveBackup(ops.backupPath, prior); err != nil {
			return "", fmt.Errorf("persist original NCSI policy: %w", err)
		}
		b = []byte(prior)
	} else if err != nil {
		return "", fmt.Errorf("read original NCSI backup: %w", err)
	}
	prior := string(b)
	if _, _, err := ncsiBackupValue(prior); err != nil {
		return "", err
	}
	if err := ops.write(1); err != nil {
		return prior, fmt.Errorf("disable NCSI active probe: %w", err)
	}
	if err := ops.restart("NlaSvc"); err != nil {
		return prior, fmt.Errorf("restart NlaSvc after suppression: %w", err)
	}
	return prior, nil
}

// ncsiRestoreWith never guesses an original value. If the backup is absent or corrupt it leaves the current
// registry policy alone; if restoring or applying it fails, the backup remains for a later recovery attempt.
func ncsiRestoreWith(ops ncsiPolicyOps) (string, error) {
	b, err := os.ReadFile(ops.backupPath)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("read original NCSI backup: %w", err)
	}
	prior := string(b)
	value, absent, err := ncsiBackupValue(prior)
	if err != nil {
		return "", err
	}
	if absent {
		err = ops.delete()
	} else {
		err = ops.write(value)
	}
	if err != nil {
		return prior, fmt.Errorf("restore original NCSI policy: %w", err)
	}
	current, exists, err := ops.read()
	if err != nil {
		return prior, fmt.Errorf("verify restored NCSI policy: %w", err)
	}
	if (absent && exists) || (!absent && (!exists || current != strconv.FormatUint(uint64(value), 10))) {
		return prior, errors.New("restored NCSI policy does not match backup")
	}
	if err := ops.restart("NlaSvc"); err != nil {
		return prior, fmt.Errorf("restart NlaSvc after restore: %w", err)
	}
	if err := os.Remove(ops.backupPath); err != nil {
		return prior, fmt.Errorf("remove restored NCSI backup: %w", err)
	}
	return prior, nil
}
