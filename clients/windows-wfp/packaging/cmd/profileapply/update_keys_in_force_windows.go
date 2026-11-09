//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// putProfileUpdateKeysInForce gives DsseUpdater the deployment's update-signing keys from the verified profile,
// but only when the device holds no update authority of its own, and makes sure the running process reads every
// condition it now has. See updater_restart.go for the sequence and its record.
//
// ★★★ RESTORE FIRST, ADOPT SECOND (2026-11-04). A major upgrade recreates the services from the
// generic package, so their arguments are empty until the protected verifier store is put back. The saved update
// key, plan key and publisher are restored first; the profile's keys are adopted only if no update key is in force
// after that.
//
// ★ AN UNTRUSTED STORE ADOPTS NOTHING. The store is the device's record of who may run code on it. If it cannot be
// trusted, taking the profile's word instead would let whoever damaged the store choose the update authority.
func putProfileUpdateKeysInForce(keys []string, reserved ...string) (string, error) {
	if _, found, err := serviceArgsFor("DsseUpdater"); err != nil {
		return "", fmt.Errorf("read DsseUpdater: %w", err)
	} else if !found {
		return "", nil
	}
	notes, err := putUpdaterConditionsInForce(&windowsUpdaterOps{keys: keys, reserved: reserved})
	return strings.Join(notes, "; "), err
}

type windowsUpdaterOps struct {
	keys, reserved []string
}

func (o *windowsUpdaterOps) marker() string {
	return filepath.Join(filepath.Dir(enrolmentDir()), "updater-restart-pending")
}

func (o *windowsUpdaterOps) ReadMarker() (string, error) {
	b, err := os.ReadFile(o.marker())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func (o *windowsUpdaterOps) WriteMarker(state string) error {
	if err := os.MkdirAll(filepath.Dir(o.marker()), 0o755); err != nil {
		return err
	}
	tmp := o.marker() + ".tmp"
	if err := os.WriteFile(tmp, []byte(state+"\n"), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, o.marker())
}

func (o *windowsUpdaterOps) ClearMarker() error {
	if err := os.Remove(o.marker()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (o *windowsUpdaterOps) ApplyConditions() (bool, []string, error) {
	stored, err := readCapturedPins()
	if err != nil {
		return false, nil, fmt.Errorf("the protected verifier store cannot be trusted, so no update authority is "+
			"adopted from the profile: %w", err)
	}
	restored, err := restoreMissingPinsInServiceArgs("DsseUpdater", stored)
	if err != nil {
		return false, nil, fmt.Errorf("restore DsseUpdater's saved conditions: %w", err)
	}
	notes := []string{}
	if restored.Changed() {
		notes = append(notes, "DsseUpdater's saved verification conditions were restored first")
	}
	args, _, err := serviceArgsFor("DsseUpdater")
	if err != nil {
		return restored.Changed(), notes, fmt.Errorf("read DsseUpdater's conditions back: %w", err)
	}
	adopted := false
	switch {
	case pinsInArgs("DsseUpdater", args).get("Updater_UpdatePin") != "":
		notes = append(notes, "DsseUpdater names an update-signing key; the device's own is kept")
	case profileUpdateKeysConflict(o.keys, o.reserved...):
		notes = append(notes, "★ the profile names an update-signing key that already verifies this device's "+
			"configuration or policy; one key must not also authorise code, so no update key is adopted")
	default:
		if set := profileUpdatePinSet(o.keys, o.reserved...); set != nil {
			r, err := restoreMissingPinsInServiceArgs("DsseUpdater", set)
			if err != nil {
				return restored.Changed(), notes, fmt.Errorf("put the profile's update-signing keys in force: %w", err)
			}
			if r.Changed() {
				adopted = true
				notes = append(notes, fmt.Sprintf("DsseUpdater now verifies update manifests against the "+
					"deployment's %d update-signing key(s) from the profile", len(strings.Split(set.get("Updater_UpdatePin"), ","))))
			}
		}
	}
	return restored.Changed() || adopted, notes, nil
}

func (o *windowsUpdaterOps) open() (*mgr.Mgr, *mgr.Service, error) {
	m, err := mgr.Connect()
	if err != nil {
		return nil, nil, err
	}
	s, err := m.OpenService("DsseUpdater")
	if err != nil {
		m.Disconnect()
		return nil, nil, err
	}
	return m, s, nil
}

func (o *windowsUpdaterOps) Running() (bool, error) {
	m, s, err := o.open()
	if err != nil {
		return false, err
	}
	defer m.Disconnect()
	defer s.Close()
	st, err := s.Query()
	if err != nil {
		return false, err
	}
	return st.State == windows.SERVICE_RUNNING || st.State == windows.SERVICE_START_PENDING, nil
}

func (o *windowsUpdaterOps) waitFor(s *mgr.Service, want svc.State) error {
	deadline := time.Now().Add(30 * time.Second)
	for {
		st, err := s.Query()
		if err != nil {
			return err
		}
		if st.State == want {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("DsseUpdater did not reach state %d within 30s (now %d)", want, st.State)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func (o *windowsUpdaterOps) Stop() error {
	m, s, err := o.open()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	defer s.Close()
	if _, err := s.Control(svc.Stop); err != nil && !errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
		return err
	}
	return o.waitFor(s, svc.Stopped)
}

func (o *windowsUpdaterOps) Start() error {
	m, s, err := o.open()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	defer s.Close()
	if err := s.Start(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
		return err
	}
	return o.waitFor(s, svc.Running)
}
