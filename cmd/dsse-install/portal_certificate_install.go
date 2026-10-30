package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

func portalCertificateNames(env map[string]string) ([]string, error) {
	portal := strings.TrimSpace(env["DSSE_NODE_PORTAL_NAME"])
	if !validPlanDNSName(portal) {
		return nil, fmt.Errorf("this is not an Edge with a declared Portal name")
	}
	portals := []string{portal}
	foundLocal := false
	for _, raw := range strings.Split(env["DSSE_STEPUP_PORTAL_ORIGINS"], ",") {
		if raw == "" {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "https" || !validPlanDNSName(u.Hostname()) || u.User != nil {
			return nil, fmt.Errorf("invalid Portal origin")
		}
		portals = append(portals, u.Hostname())
		foundLocal = foundLocal || u.Hostname() == portal
	}
	if env["DSSE_TOPOLOGY_PROFILE"] == "three-regions-multi-edge" {
		if !foundLocal {
			return nil, fmt.Errorf("owning Region Portal is missing from approved origins")
		}
		// The signed client profile lists every Region's possible origin, but
		// this Edge serves only the Portal at its own Region's entrance.
		return []string{portal}, nil
	}
	return dedupeSorted(portals, portal), nil
}

// Extra trust is an explicit operator input, never fetched from the target.
// The Edge uses the same input only for Portal self-verification; never through
// SSL_CERT_FILE or the trust pools used for upstream/IdP connections.
func portalTrustPool(extra []byte) (*x509.CertPool, error) {
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("read system trust roots: %w", err)
	}
	if len(extra) == 0 {
		return roots, nil
	}
	count := 0
	for len(strings.TrimSpace(string(extra))) > 0 {
		if !strings.HasPrefix(strings.TrimSpace(string(extra)), "-----BEGIN CERTIFICATE-----") {
			return nil, fmt.Errorf("Portal CA file must contain only PEM CA certificates")
		}
		block, rest := pem.Decode(extra)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("Portal CA file must contain only PEM CA certificates")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !cert.IsCA || !cert.BasicConstraintsValid {
			return nil, fmt.Errorf("Portal trust contains a non-CA certificate")
		}
		roots.AddCert(cert)
		count++
		extra = rest
	}
	if count == 0 {
		return nil, fmt.Errorf("Portal CA file contains no certificate")
	}
	return roots, nil
}

func validatePortalPair(certPEM, keyPEM []byte, env map[string]string, roots *x509.CertPool) error {
	names, err := portalCertificateNames(env)
	if err != nil {
		return err
	}
	for rest := certPEM; len(strings.TrimSpace(string(rest))) > 0; {
		if !strings.HasPrefix(strings.TrimSpace(string(rest)), "-----BEGIN CERTIFICATE-----") {
			return fmt.Errorf("browser chain must contain only PEM certificates, never private keys")
		}
		block, tail := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" {
			return fmt.Errorf("invalid browser certificate PEM")
		}
		rest = tail
	}
	keyBlock, keyRest := pem.Decode(keyPEM)
	if !strings.HasPrefix(strings.TrimSpace(string(keyPEM)), "-----BEGIN ") || keyBlock == nil || strings.TrimSpace(string(keyRest)) != "" || (keyBlock.Type != "PRIVATE KEY" && keyBlock.Type != "EC PRIVATE KEY" && keyBlock.Type != "RSA PRIVATE KEY") {
		return fmt.Errorf("supply exactly one unencrypted browser private key")
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("browser certificate/key pair: %w", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return fmt.Errorf("parse browser certificate: %w", err)
	}
	if leaf.IsCA {
		return fmt.Errorf("browser certificate must be a server leaf, not a CA signing identity")
	}
	intermediates := x509.NewCertPool()
	for _, raw := range pair.Certificate[1:] {
		cert, err := x509.ParseCertificate(raw)
		if err != nil {
			return fmt.Errorf("parse browser certificate chain: %w", err)
		}
		intermediates.AddCert(cert)
	}
	for _, host := range names {
		if _, err := leaf.Verify(x509.VerifyOptions{DNSName: host, Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
			return fmt.Errorf("%s is not currently trusted: %w", host, err)
		}
	}
	return nil
}

func installPortalCertificate(dir, certPath, keyPath, caPath string) error {
	env, err := readEnvFile(filepath.Join(dir, "deployment.env"))
	if err != nil {
		return err
	}
	cert, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("read supplied Portal certificate: %w", err)
	}
	key, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("read supplied Portal key: %w", err)
	}
	trustPath := filepath.Join(dir, "clientless", "trust.pem")
	var extra []byte
	if caPath != "" {
		extra, err = os.ReadFile(caPath)
		if err != nil || len(extra) == 0 {
			return fmt.Errorf("read supplied Portal CA: nonempty CA file required")
		}
	} else {
		extra, err = os.ReadFile(trustPath)
		if err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	roots, err := portalTrustPool(extra)
	if err != nil {
		return err
	}
	if err := validatePortalPair(cert, key, env, roots); err != nil {
		return err
	}
	if info, e := os.Lstat(filepath.Join(dir, "clientless")); e == nil && (!info.IsDir() || info.Mode()&os.ModeSymlink != 0) {
		return fmt.Errorf("clientless must be a local deployment directory, not a symlink")
	} else if e != nil && !os.IsNotExist(e) {
		return e
	}
	// Validate before changing material. Individual durable renames are not a
	// transaction across the pair: provision before startup or in maintenance,
	// then require preflight before (re)starting a service.
	if err := os.MkdirAll(filepath.Join(dir, "clientless"), 0700); err != nil {
		return err
	}
	for _, f := range []struct {
		path string
		data []byte
		mode os.FileMode
	}{
		{filepath.Join(dir, "clientless", "tls.key"), key, 0600},
		{filepath.Join(dir, "clientless", "tls.crt"), cert, 0644},
	} {
		if err := publishInstallerFile(f.path, f.data, f.mode); err != nil {
			return err
		}
	}
	if len(extra) > 0 {
		if err := publishInstallerFile(trustPath, extra, 0644); err != nil {
			return err
		}
	}
	if env[stepUpPortalCertEnvKey] == "operator" {
		return nil
	}
	raw, err := os.ReadFile(filepath.Join(dir, "deployment.env"))
	if err != nil {
		return err
	}
	return publishInstallerFile(filepath.Join(dir, "deployment.env"), []byte(PlanEnvironmentFor(string(raw), map[string]string{stepUpPortalCertEnvKey: "operator"})), 0600)
}

func publishInstallerFile(path string, body []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".dsse-install-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if err := f.Chmod(mode); err != nil {
		return err
	}
	if _, err := f.Write(body); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(f.Name(), path); err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
