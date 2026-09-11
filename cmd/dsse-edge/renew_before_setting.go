package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// "Renew every certificate issued before this moment."
//
// An operator sometimes needs a device to renew NOW rather than at two thirds of its certificate's life: the
// issuing CA changed, or a certificate was issued under settings nobody wants any more. This lab has the second
// case — a ten-year device certificate from a superseded CA, next renewing in 2033, which means the old CA
// cannot be retired for seven years because something live still depends on it.
//
// Expressed as a DECLARATION rather than a command, and that is the whole design. A command reaches the devices
// that happen to be listening; a statement that certificates older than T are stale reaches every device the
// next time it asks, including the laptop that was switched off all week. It is idempotent for free — once a
// device renews, its certificate is newer than T and the instruction stops applying to it — so there is no
// per-device state to keep, no acknowledgements to track, and no way to renew twice.
//
// It rides the agent-policy document: signed, fetched over the device's own mTLS connection, and already
// polled. The alternative, the trust bundle, is signed once at startup against a serial that comes from a
// flag, so it cannot carry anything that changes at runtime.
type renewBeforeSetting struct {
	mu   sync.RWMutex
	at   time.Time
	path string
}

type renewBeforeState struct {
	SchemaVersion string `json:"schema_version"`
	At            string `json:"renew_certificates_issued_before,omitempty"`
}

const renewBeforeSchemaVersion = "admin_renew_before.v1"

func newRenewBeforeSetting(path string) *renewBeforeSetting {
	s := &renewBeforeSetting{path: strings.TrimSpace(path)}
	s.load()
	return s
}

func (s *renewBeforeSetting) load() {
	if s == nil || s.path == "" {
		return
	}
	raw, err := os.ReadFile(s.path)
	if err != nil {
		return
	}
	var state renewBeforeState
	if err := json.Unmarshal(raw, &state); err != nil || strings.TrimSpace(state.At) == "" {
		return
	}
	at, err := time.Parse(time.RFC3339, state.At)
	if err != nil {
		return
	}
	s.mu.Lock()
	s.at = at
	s.mu.Unlock()
}

// Set records the cutoff. Durable, because a restart that forgot it would silently stop a fleet-wide renewal
// half-way through — the devices that had not checked in yet would never be told.
func (s *renewBeforeSetting) Set(at time.Time) error {
	if s == nil {
		return fmt.Errorf("renew-before setting is not configured")
	}
	s.mu.Lock()
	s.at = at.UTC()
	path := s.path
	s.mu.Unlock()
	if path == "" {
		return nil
	}
	raw, err := json.Marshal(renewBeforeState{SchemaVersion: renewBeforeSchemaVersion, At: at.UTC().Format(time.RFC3339)})
	if err != nil {
		return err
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	return os.WriteFile(path, raw, 0o600)
}

// Clear stops asking. Renewals already performed are not undone — there is nothing to undo, since a renewed
// certificate is simply a newer certificate.
func (s *renewBeforeSetting) Clear() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	s.at = time.Time{}
	path := s.path
	s.mu.Unlock()
	if path == "" {
		return nil
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (s *renewBeforeSetting) At() (time.Time, bool) {
	if s == nil {
		return time.Time{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.at, !s.at.IsZero()
}

// RFC3339 renders the cutoff for the signed policy, or "" when nothing is being asked. Empty is the ordinary
// state: an agent that never sees this field behaves exactly as it did before.
func (s *renewBeforeSetting) RFC3339() string {
	if at, ok := s.At(); ok {
		return at.Format(time.RFC3339)
	}
	return ""
}
