package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

// the_step_up_portal_is_a_browser_facing_page.go — the certificate a USER'S BROWSER validates when a held
// flow sends them to authenticate.
//
// ★★★ IT IS NOT DERIVED FROM THIS DEPLOYMENT'S CAs, AND THAT IS THE POINT (2026-09-02, decided by the
// operator after the ceremony was walked on a real device).
//
// The portal was served on the agent plane, with the deployment's transport certificate, which a browser has
// no reason to trust: the only deployment-related root a steered device carries is its organization's
// INTERCEPTION root. Two ways to reuse what is already trusted were considered and both are wrong:
//
//   - Sign the portal with the organization's interception CA. That makes the interception authority vouch
//     for a real server this deployment runs, so mistrusting or rotating it takes the step-up — a recovery
//     path — down with it.
//   - Steer the portal so it is intercepted like any site. Measured: impossible as things stand. The device's
//     transparent passthrough matches by ADDRESS, and every one of this deployment's names (console, admin,
//     agents, authority, recovery) resolves to the same address per region — so the portal is passed through
//     with the agent's own control channel and cannot be intercepted without giving it an address of its own.
//
// The operator's reading is the one that settles it: the identity provider is NOT part of DSSE. It is the
// customer's — Okta, Entra ID — and the browser reaches it over a publicly trusted certificate. The DSSE hop
// in the middle is a browser-facing page like any other, and its certificate is provided for it, per
// deployment, for a name the operator holds. Not minted here, and not borrowed from a CA that exists to do
// something else.
//
// The one-region-three-nodes profile reserves its portal name and refuses TLS
// when browser material is absent or invalid. Explicit lab mode and legacy
// profiles retain their agent-certificate fallback.
type stepUpPortalCertificate struct {
	host    string
	cert    *tls.Certificate
	refusal error
	others  map[string]*stepUpPortalCertificate
}

var stepUpPortalCert atomic.Pointer[stepUpPortalCertificate]

// configureStepUpPortalCertificate loads the operator-supplied pair and binds it to the host in the portal's
// base URL. Only legacy optional-certificate profiles fall back to the agent-plane certificate if it is missing.
func configureStepUpPortalCertificate(baseURL, certPath, keyPath string) {
	configureStepUpPortalCertificateForProfile(baseURL, certPath, keyPath, false)
}

func configureStepUpPortalCertificateForProfile(baseURL, certPath, keyPath string, required bool) {
	configureStepUpPortalCertificatesForProfile([]string{baseURL}, certPath, keyPath, required)
}

// A deployment can have several independent browser entrances. A combined-node
// one-region Edge serves them all; a dedicated three-region Edge serves only
// its own entrance. Every other approved Portal name is reserved and fails TLS
// on this Edge rather than falling through to the transport certificate.
func configureStepUpPortalCertificatesForProfile(origins []string, certPath, keyPath string, required bool) {
	configureStepUpPortalCertificatesWithTrust(origins, certPath, keyPath, "", required)
}

// The explicit Portal CA belongs to this certificate check only. In particular,
// it must never be installed through SSL_CERT_FILE or a shared HTTP transport.
func stepUpPortalTrustPool(caPath string) (*x509.CertPool, error) {
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}
	if caPath == "" {
		return roots, nil
	}
	raw, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read explicit Portal CA: %w", err)
	}
	count := 0
	for len(strings.TrimSpace(string(raw))) > 0 {
		if !strings.HasPrefix(strings.TrimSpace(string(raw)), "-----BEGIN CERTIFICATE-----") {
			return nil, fmt.Errorf("Portal trust must contain only PEM CA certificates")
		}
		block, rest := pem.Decode(raw)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("Portal trust must contain only PEM CA certificates")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !cert.IsCA || !cert.BasicConstraintsValid {
			return nil, fmt.Errorf("Portal trust contains an invalid CA certificate")
		}
		roots.AddCert(cert)
		count++
		raw = rest
	}
	if count == 0 {
		return nil, fmt.Errorf("Portal trust contains no CA certificate")
	}
	return roots, nil
}

func configureStepUpPortalCertificatesWithTrust(origins []string, certPath, keyPath, caPath string, required bool) {
	configureStepUpPortalCertificatesForServedOriginsWithTrust(origins, origins, certPath, keyPath, caPath, required)
}

func configureStepUpPortalCertificatesForServedOriginsWithTrust(origins, served []string, certPath, keyPath, caPath string, required bool) {
	stepUpPortalCert.Store(nil)
	servedHosts := make(map[string]bool, len(served))
	for _, origin := range served {
		servedHosts[stepUpPortalHost(origin)] = true
	}
	var pair *tls.Certificate
	var loadErr error
	if strings.TrimSpace(certPath) != "" && strings.TrimSpace(keyPath) != "" {
		loaded, err := tls.LoadX509KeyPair(certPath, keyPath)
		pair, loadErr = &loaded, err
	} else {
		loadErr = fmt.Errorf("missing browser certificate/key pair")
	}
	var roots *x509.CertPool
	if loadErr == nil && (required || caPath != "") {
		roots, loadErr = stepUpPortalTrustPool(caPath)
	}
	var first *stepUpPortalCertificate
	for _, origin := range origins {
		host := stepUpPortalHost(origin)
		if host == "" {
			continue
		}
		err := loadErr
		if !servedHosts[host] {
			err = fmt.Errorf("Portal belongs to another Regional entrance")
		}
		if err == nil && (required || caPath != "") {
			err = validateStepUpPortalCertificate(host, pair, roots, time.Now())
		} else if err == nil && len(origins) > 1 {
			var leaf *x509.Certificate
			leaf, err = x509.ParseCertificate(pair.Certificate[0])
			if err == nil {
				err = leaf.VerifyHostname(host)
			}
		}
		entry := &stepUpPortalCertificate{host: host}
		if err != nil {
			if !required && caPath == "" && len(origins) == 1 {
				continue
			} // legacy fallback only
			entry.refusal = fmt.Errorf("portal %s requires a valid browser certificate: %w", host, err)
			log.Printf("step-up portal certificate: refusing %s: %v", host, err)
		} else {
			entry.cert = pair
		}
		if first == nil {
			first = entry
			first.others = map[string]*stepUpPortalCertificate{}
		} else {
			first.others[host] = entry
		}
	}
	stepUpPortalCert.Store(first)
}

func stepUpPortalCertificateEntry(serverName string) *stepUpPortalCertificate {
	held := stepUpPortalCert.Load()
	if held == nil {
		return nil
	}
	name := strings.ToLower(strings.TrimSpace(serverName))
	if name == held.host {
		return held
	}
	return held.others[name]
}

func validateStepUpPortalCertificate(host string, pair *tls.Certificate, roots *x509.CertPool, now time.Time) error {
	if pair == nil || len(pair.Certificate) == 0 {
		return fmt.Errorf("missing certificate")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return err
	}
	if leaf.IsCA {
		return fmt.Errorf("Portal certificate must be a server leaf")
	}
	intermediates := x509.NewCertPool()
	for _, raw := range pair.Certificate[1:] {
		cert, err := x509.ParseCertificate(raw)
		if err != nil {
			return err
		}
		intermediates.AddCert(cert)
	}
	_, err = leaf.Verify(x509.VerifyOptions{DNSName: host, Roots: roots, Intermediates: intermediates, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	return err
}

func stepUpPortalCertificateRefusal(serverName string) error {
	held := stepUpPortalCertificateEntry(serverName)
	if held != nil {
		return held.refusal
	}
	return nil
}

// stepUpPortalHost is the host a browser asks for when it is sent to the portal.
func stepUpPortalHost(baseURL string) string {
	u, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil || u == nil {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(u.Hostname()))
}

// stepUpPortalCertificateFor answers with the operator's certificate when the browser asked for the portal's
// name, and nil otherwise so the caller falls through to what it served before.
func stepUpPortalCertificateFor(serverName string) *tls.Certificate {
	held := stepUpPortalCertificateEntry(serverName)
	if held == nil {
		return nil
	}
	return held.cert
}
