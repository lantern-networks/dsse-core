package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	certreload "github.com/lantern-networks/dsse-core/certreload"
	"github.com/lantern-networks/dsse-core/durablefile"
)

// Management-plane certificate rotation — admin surface (slice 2 of docs/admin_certificate_rotation_design.md).
//
// Builds on slice 1's certreload.ReloadableCert (hot-reload, no restart): GET /admin/certs lists the rotatable server
// certs with metadata; PUT /admin/certs/{name} validates an uploaded cert+key, writes it to the backing
// files, and reloads — so an admin rotates a cert from the Console with no restart and no dropped
// connections. Validate-before-accept: a key/cert mismatch or an expired cert is rejected (the link is never
// bricked); the previous cert keeps serving on any failure.

// deriveCertName is the logical name for a backing cert file (edge.crt -> "edge"). Listeners that share a
// cert/key pair share one name, so rotating it updates them all.
func deriveCertName(certFile string) string {
	base := filepath.Base(strings.TrimSpace(certFile))
	return strings.TrimSuffix(base, filepath.Ext(base))
}

// certVersionSnapshot is the rollback payload for a certificate version. It includes the PRIVATE KEY so a
// rollback can re-apply a prior cert+key (the user accepted key-in-version-history so rollback is possible).
// The control-plane config_versions store (postgres) is internal-only; the versions LIST API redacts this.
type certVersionSnapshot struct {
	CertPEM string `json:"cert_pem"`
	KeyPEM  string `json:"key_pem"`
}

type certInventoryEntry struct {
	Name              string   `json:"name"`
	CertFile          string   `json:"cert_file"`
	Subject           string   `json:"subject"`
	DNSNames          []string `json:"dns_names"`
	IPAddresses       []string `json:"ip_addresses"`
	NotBefore         string   `json:"not_before"`
	NotAfter          string   `json:"not_after"`
	FingerprintSHA256 string   `json:"fingerprint_sha256"`
}

func certEntryFor(r *certreload.ReloadableCert) (certInventoryEntry, bool) {
	c := r.Current()
	if c == nil || len(c.Certificate) == 0 {
		return certInventoryEntry{}, false
	}
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		return certInventoryEntry{}, false
	}
	sum := sha256.Sum256(c.Certificate[0])
	ips := make([]string, 0, len(leaf.IPAddresses))
	for _, ip := range leaf.IPAddresses {
		ips = append(ips, ip.String())
	}
	return certInventoryEntry{
		Name:              deriveCertName(r.CertFile()),
		CertFile:          r.CertFile(),
		Subject:           leaf.Subject.String(),
		DNSNames:          leaf.DNSNames,
		IPAddresses:       ips,
		NotBefore:         leaf.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:          leaf.NotAfter.UTC().Format(time.RFC3339),
		FingerprintSHA256: hex.EncodeToString(sum[:]),
	}, true
}

// certInventory lists the rotatable server certs (deduped by logical name).
func certInventory() []certInventoryEntry {
	rs := certreload.Registered()
	seen := map[string]bool{}
	out := []certInventoryEntry{}
	for _, r := range rs {
		name := deriveCertName(r.CertFile())
		if seen[name] {
			continue
		}
		if e, ok := certEntryFor(r); ok {
			seen[name] = true
			out = append(out, e)
		}
	}
	return out
}

var certRotationMu sync.Mutex

// rotateNamedCert validates the uploaded PEM cert+key, writes them to the named cert's backing files, and
// hot-reloads every listener using that cert. Returns the new inventory entry. Fail-safe: validation happens
// before any write; a reload failure after write keeps the previous in-memory cert (it does not crash).
func rotateNamedCert(name, certPEM, keyPEM string, now time.Time) (certInventoryEntry, error) {
	certRotationMu.Lock()
	defer certRotationMu.Unlock()
	return rotateNamedCertLocked(name, certPEM, keyPEM, now)
}

func rotateNamedCertLocked(name, certPEM, keyPEM string, now time.Time) (certInventoryEntry, error) {
	name = strings.TrimSpace(name)
	// validate key<->cert match + parse
	pair, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return certInventoryEntry{}, fmt.Errorf("certificate and key are invalid or do not match: %w", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return certInventoryEntry{}, fmt.Errorf("parse certificate: %w", err)
	}
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return certInventoryEntry{}, fmt.Errorf("certificate is not currently valid (not_before=%s not_after=%s)", leaf.NotBefore.UTC().Format(time.RFC3339), leaf.NotAfter.UTC().Format(time.RFC3339))
	}

	rs := certreload.Registered()
	matched := []*certreload.ReloadableCert{}
	for _, r := range rs {
		if deriveCertName(r.CertFile()) == name {
			matched = append(matched, r)
		}
	}
	if len(matched) == 0 {
		return certInventoryEntry{}, fmt.Errorf("no rotatable certificate named %q", name)
	}

	// One name must resolve to one physical pair. Otherwise a late failure could
	// rotate only part of an unrelated set of listeners with the same basename.
	first := matched[0]
	for _, r := range matched[1:] {
		if filepath.Clean(r.CertFile()) != filepath.Clean(first.CertFile()) || filepath.Clean(r.KeyFile()) != filepath.Clean(first.KeyFile()) {
			return certInventoryEntry{}, fmt.Errorf("certificate name is ambiguous across backing files")
		}
	}
	if err := saveNamedCertPair(first.CertFile(), first.KeyFile(), []byte(certPEM), []byte(keyPEM)); err != nil {
		return certInventoryEntry{}, err
	}
	for _, r := range matched {
		if err := r.Reload(); err != nil {
			return certInventoryEntry{}, fmt.Errorf("reload after rotation: %w", err)
		}
	}
	entry, _ := certEntryFor(matched[0])
	return entry, nil
}

// Stage every file before changing either destination, then restore the previous
// pair on a handled commit failure. Separate configured cert/key paths cannot be
// atomically replaced as a pair; this does not promise power-loss atomicity.
func saveNamedCertPair(certPath, keyPath string, cert, key []byte) error {
	return saveNamedCertPairWithReplace(certPath, keyPath, cert, key, durablefile.Replace)
}

func saveNamedCertPairWithReplace(certPath, keyPath string, cert, key []byte, replace func(string, string) error) error {
	if filepath.Clean(certPath) == filepath.Clean(keyPath) {
		return fmt.Errorf("certificate and key must use separate files")
	}
	paths := []string{certPath, keyPath}
	old := make([][]byte, 2)
	for i, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("certificate backing path is not a regular file")
		}
		old[i], err = os.ReadFile(path)
		if err != nil {
			return err
		}
		// Retain the existing permission boundary even where rename would bypass a
		// read-only destination file. Opening must not truncate the old material.
		f, err := os.OpenFile(path, os.O_WRONLY, 0)
		if err != nil {
			return fmt.Errorf("certificate backing file is not writable: %w", err)
		}
		if err := f.Close(); err != nil {
			return err
		}
	}
	staged, backups := make([]string, 2), make([]string, 2)
	defer func() {
		for _, p := range append(staged, backups...) {
			if p != "" {
				_ = os.Remove(p)
			}
		}
	}()
	for i, value := range [][]byte{cert, key} {
		var err error
		staged[i], err = stageNamedCertFile(paths[i], value)
		if err != nil {
			return err
		}
		backups[i], err = stageNamedCertFile(paths[i], old[i])
		if err != nil {
			return err
		}
	}
	restore := func(cause error, count int) error {
		errs := []error{cause}
		for i := 0; i < count; i++ {
			if err := replace(backups[i], paths[i]); err != nil {
				if errors.Is(err, durablefile.ErrReplacedNotFlushed) {
					errs = append(errs, fmt.Errorf("previous certificate material restored but durability is unconfirmed: %w", err))
				} else {
					errs = append(errs, fmt.Errorf("restore previous certificate material failed; recovery copy retained at %s: %w", backups[i], err))
					backups[i] = "" // Do not erase the recovery copy when restoration failed.
				}
			}
		}
		return errors.Join(errs...)
	}
	for i, path := range paths {
		if err := replace(staged[i], path); err != nil {
			changed := i
			if errors.Is(err, durablefile.ErrReplacedNotFlushed) {
				changed++ // This destination already changed before its flush failed.
			}
			return restore(err, changed)
		}
	}
	return nil
}

func stageNamedCertFile(path string, data []byte) (string, error) {
	f, err := os.CreateTemp(filepath.Dir(path), ".dsse-cert-*")
	if err != nil {
		return "", err
	}
	name := f.Name()
	keep := false
	defer func() {
		_ = f.Close()
		if !keep {
			_ = os.Remove(name)
		}
	}()
	if _, err = f.Write(data); err != nil {
		return "", err
	}
	if err = f.Sync(); err != nil {
		return "", err
	}
	if err = f.Close(); err != nil {
		return "", err
	}
	keep = true
	return name, nil
}
