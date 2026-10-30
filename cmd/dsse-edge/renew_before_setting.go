package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/lantern-networks/dsse-core/durablefile"
	"github.com/lantern-networks/dsse-core/internal/strictjson"
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
	mu    sync.RWMutex
	at    time.Time
	path  string
	write func(string, []byte, os.FileMode) error
}

type renewBeforeState struct {
	SchemaVersion string `json:"schema_version"`
	At            string `json:"renew_certificates_issued_before,omitempty"`
}

const renewBeforeSchemaVersion = "admin_renew_before.v1"

func newRenewBeforeSetting(path string) (*renewBeforeSetting, error) {
	s := &renewBeforeSetting{path: strings.TrimSpace(path), write: durablefile.Write}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *renewBeforeSetting) load() error {
	if s == nil || s.path == "" {
		return nil
	}
	raw, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read renewal declaration: %w", err)
	}
	if err := strictjson.RejectDuplicateKeys(raw); err != nil {
		return fmt.Errorf("invalid renewal declaration: %w", err)
	}
	if err := strictjson.RejectUnknownFields(raw, renewBeforeState{}); err != nil {
		return fmt.Errorf("invalid renewal declaration: %w", err)
	}
	var state renewBeforeState
	if err := json.Unmarshal(raw, &state); err != nil {
		return fmt.Errorf("decode renewal declaration: %w", err)
	}
	if state.SchemaVersion != renewBeforeSchemaVersion {
		return fmt.Errorf("unsupported renewal declaration schema")
	}
	var at time.Time
	if state.At != "" {
		at, err = time.Parse(time.RFC3339Nano, state.At)
		if err != nil || at.IsZero() {
			return fmt.Errorf("invalid renewal declaration cutoff")
		}
	}
	s.mu.Lock()
	s.at = at
	s.mu.Unlock()
	return nil
}

// Set records the cutoff. Durable, because a restart that forgot it would silently stop a fleet-wide renewal
// half-way through — the devices that had not checked in yet would never be told.
func (s *renewBeforeSetting) Set(at time.Time) error {
	if s == nil {
		return fmt.Errorf("renew-before setting is not configured")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.replaceLocked(at.UTC())
}

// Clear stops asking. Renewals already performed are not undone — there is nothing to undo, since a renewed
// certificate is simply a newer certificate.
func (s *renewBeforeSetting) Clear() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// Persist an empty declaration atomically, so clearing has the same
	// durability and failure semantics as setting a cutoff.
	return s.replaceLocked(time.Time{})
}

func (s *renewBeforeSetting) replaceLocked(at time.Time) error {
	var err error
	if s.path != "" {
		state := renewBeforeState{SchemaVersion: renewBeforeSchemaVersion}
		if !at.IsZero() {
			state.At = at.Format(time.RFC3339Nano)
		}
		raw, marshalErr := json.Marshal(state)
		if marshalErr != nil {
			return marshalErr
		}
		if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
			return err
		}
		write := s.write
		if write == nil {
			write = durablefile.Write
		}
		err = write(s.path, raw, 0o600)
	}
	// A staging/replacement failure leaves the live declaration unchanged.
	// A post-rename flush error is different: the new file is already visible.
	// Match that file while returning the durability error to the caller.
	if err == nil || errors.Is(err, durablefile.ErrReplacedNotFlushed) {
		s.at = at
	}
	return err
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
