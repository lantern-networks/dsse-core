package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	certreload "github.com/lantern-networks/dsse-core/certreload"
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

// rotateNamedCert validates the uploaded PEM cert+key, writes them to the named cert's backing files, and
// hot-reloads every listener using that cert. Returns the new inventory entry. Fail-safe: validation happens
// before any write; a reload failure after write keeps the previous in-memory cert (it does not crash).
func rotateNamedCert(name, certPEM, keyPEM string, now time.Time) (certInventoryEntry, error) {
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

	written := map[string]bool{}
	for _, r := range matched {
		if written[r.CertFile()] {
			continue
		}
		written[r.CertFile()] = true
		if err := os.WriteFile(r.CertFile(), []byte(certPEM), 0o644); err != nil {
			return certInventoryEntry{}, fmt.Errorf("write cert %s: %w", r.CertFile(), err)
		}
		if err := os.WriteFile(r.KeyFile(), []byte(keyPEM), 0o600); err != nil {
			return certInventoryEntry{}, fmt.Errorf("write key %s: %w", r.KeyFile(), err)
		}
	}
	for _, r := range matched {
		if err := r.Reload(); err != nil {
			return certInventoryEntry{}, fmt.Errorf("reload after rotation: %w", err)
		}
	}
	entry, _ := certEntryFor(matched[0])
	return entry, nil
}
