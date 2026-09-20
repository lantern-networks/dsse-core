package certreload

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/lantern-networks/dsse-core/durablefile"
)

// A process owns its configured certificate files. Serialize reload with writes
// so SIGHUP cannot mistake an in-progress update for an interrupted one.
var pairMu sync.Mutex

const pairJournalSchema = "dsse.certificate_pair_recovery.v1"

type pairJournal struct {
	Schema   string `json:"schema"`
	State    string `json:"state"`
	CertPath string `json:"cert_path"`
	KeyPath  string `json:"key_path"`
	Cert     []byte `json:"cert,omitempty"`
	Key      []byte `json:"key,omitempty"`
}

func pairPaths(certPath, keyPath string) (string, string, string, error) {
	cp, err := filepath.Abs(certPath)
	if err != nil {
		return "", "", "", err
	}
	kp, err := filepath.Abs(keyPath)
	if err != nil {
		return "", "", "", err
	}
	if cp == kp {
		return "", "", "", fmt.Errorf("certificate and key must use separate files")
	}
	return cp, kp, cp + ".dsse-pair-recovery.json", nil
}

func readPairJournal(path, cp, kp string) (*pairJournal, error) {
	st, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || (runtime.GOOS != "windows" && st.Mode().Perm()&0077 != 0) {
		return nil, fmt.Errorf("certificate recovery journal must be a private regular file")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var j pairJournal
	if json.Unmarshal(raw, &j) != nil || j.Schema != pairJournalSchema || j.CertPath != cp || j.KeyPath != kp || (j.State != "prepared" && j.State != "idle") {
		return nil, fmt.Errorf("invalid certificate recovery journal")
	}
	if j.State == "prepared" {
		if _, err := tls.X509KeyPair(j.Cert, j.Key); err != nil {
			return nil, fmt.Errorf("invalid certificate recovery material: %w", err)
		}
	}
	return &j, nil
}
func writePairJournal(path string, j pairJournal) error {
	raw, err := json.Marshal(j)
	if err != nil {
		return err
	}
	return durablefile.Write(path, raw, 0600)
}
func clearPairJournal(path, cp, kp string) error {
	// A durable tombstone avoids relying on deletion durability on Windows and
	// removes the old private key from the live recovery file after completion.
	return writePairJournal(path, pairJournal{Schema: pairJournalSchema, State: "idle", CertPath: cp, KeyPath: kp})
}
func recoverPairLocked(cp, kp, jp string) error {
	j, err := readPairJournal(jp, cp, kp)
	if err != nil {
		return err
	}
	if j == nil || j.State == "idle" {
		return nil
	}
	for i, p := range []string{cp, kp} {
		// Do not follow or replace an unexpected link/directory during recovery.
		st, err := os.Lstat(p)
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		if err == nil && !st.Mode().IsRegular() {
			return fmt.Errorf("certificate recovery destination is not a regular file")
		}
		data := j.Cert
		if i == 1 {
			data = j.Key
		}
		if current, readErr := os.ReadFile(p); readErr == nil && bytes.Equal(current, data) {
			// A previous recovery may have renamed this file but failed its
			// directory flush. Confirm that entry before clearing the journal.
			if err := durablefile.SyncDir(filepath.Dir(p)); err != nil {
				return fmt.Errorf("confirm restored certificate entry (journal retained): %w", err)
			}
			continue
		}
		if err := durablefile.Write(p, data, 0600); err != nil {
			return fmt.Errorf("restore certificate pair (journal retained): %w", err)
		}
	}
	if err := clearPairJournal(jp, cp, kp); err != nil {
		return fmt.Errorf("complete certificate recovery: %w", err)
	}
	log.Printf("certificate_pair_recovery result=restored cert=%s", cp)
	return nil
}

// WithPairUpdate records the previous valid pair durably before update touches
// either file. A failed or interrupted update is recoverable by Reload. The
// callback must durably replace both files and must not call Reload itself.
// Separate processes must not share writable certificate backing files.
func WithPairUpdate(certPath, keyPath string, update func() error) error {
	pairMu.Lock()
	defer pairMu.Unlock()
	cp, kp, jp, err := pairPaths(certPath, keyPath)
	if err != nil {
		return err
	}
	if err := recoverPairLocked(cp, kp, jp); err != nil {
		return err
	}
	for _, p := range []string{cp, kp} {
		st, err := os.Lstat(p)
		if err != nil {
			return err
		}
		if !st.Mode().IsRegular() {
			return fmt.Errorf("certificate backing path is not a regular file")
		}
	}
	c, err := os.ReadFile(cp)
	if err != nil {
		return err
	}
	k, err := os.ReadFile(kp)
	if err != nil {
		return err
	}
	if _, err := tls.X509KeyPair(c, k); err != nil {
		return fmt.Errorf("previous certificate pair is invalid: %w", err)
	}
	j := pairJournal{Schema: pairJournalSchema, State: "prepared", CertPath: cp, KeyPath: kp, Cert: c, Key: k}
	if err := writePairJournal(jp, j); err != nil {
		return fmt.Errorf("prepare certificate recovery: %w", err)
	}
	updateErr := update()
	if updateErr == nil {
		_, updateErr = tls.LoadX509KeyPair(cp, kp)
	}
	if updateErr != nil {
		return errors.Join(updateErr, recoverPairLocked(cp, kp, jp))
	}
	if err := clearPairJournal(jp, cp, kp); err != nil {
		// The clear may already have replaced its destination but failed to flush.
		// Do not guess whether the update committed or destroy recovery evidence.
		return fmt.Errorf("certificate pair commit could not be confirmed; reload before retrying: %w", err)
	}
	return nil
}

// RecoverPair completes an interrupted update before startup code inspects the
// certificate for admission or starts a listener. No journal means no change.
func RecoverPair(certPath, keyPath string) error {
	pairMu.Lock()
	defer pairMu.Unlock()
	cp, kp, jp, err := pairPaths(certPath, keyPath)
	if err != nil {
		return err
	}
	return recoverPairLocked(cp, kp, jp)
}
