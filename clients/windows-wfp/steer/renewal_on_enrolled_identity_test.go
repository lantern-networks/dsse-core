package main

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// ★ RENEWAL WAS DISABLED ON EVERY DEVICE THIS PRODUCT INSTALLS (2026-08-20, read off win-dev-1's own log).
//
// The scheduler used to require --transport-client-cert, a FILE PATH. The configuration the MSI installs
// (--config-store) never passes it: the client certificate comes from the enrolment material and is held in
// memory. So the scheduler switched itself off, said so once per start, and nothing renewed a certificate
// issued for sixty days. The expired-certificate recovery path — the one two platforms spent a day folding
// onto a single port — was unreachable code on the only configuration that ships.
//
// What the loop needs is somewhere to KEEP a renewed identity, not a file to read the current one from: the
// current one comes from the live transport either way.

func captureRenewalLog(t *testing.T, fn func()) string {
	t.Helper()
	var buf bytes.Buffer
	prevOut, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	defer func() { log.SetOutput(prevOut); log.SetFlags(prevFlags) }()
	fn()
	return buf.String()
}

func commonNameOf(t *testing.T, cert *tls.Certificate) string {
	t.Helper()
	if cert == nil || len(cert.Certificate) == 0 {
		t.Fatalf("no client certificate in force")
	}
	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return parsed.Subject.CommonName
}

func TestRenewalRunsWithoutACertificateFileOnTheCommandLine(t *testing.T) {
	ca := newTestCA(t, "shared-ca")
	tc := announcingTransport(t, "10.0.0.9:18543", ca)

	// The regression: an identity directory is enough. Before this, an empty cert path disabled everything.
	logged := captureRenewalLog(t, func() {
		startCertificateRenewal(tc, t.TempDir(), "", &atomic.Pointer[string]{}, &atomic.Pointer[time.Time]{})
	})
	if strings.Contains(logged, "certificate_renewal disabled") {
		t.Fatalf("renewal disabled itself on an enrolled-style configuration:\n%s", logged)
	}
	if !strings.Contains(logged, "scheduler started") {
		t.Fatalf("renewal did not start:\n%s", logged)
	}
}

// And with nowhere to keep a renewed identity it still refuses, loudly — that guard is the real one.
func TestRenewalStillRefusesWithNowhereToKeepTheResult(t *testing.T) {
	ca := newTestCA(t, "shared-ca")
	tc := announcingTransport(t, "10.0.0.9:18543", ca)
	logged := captureRenewalLog(t, func() {
		startCertificateRenewal(tc, "", "", &atomic.Pointer[string]{}, &atomic.Pointer[time.Time]{})
	})
	if !strings.Contains(logged, "certificate_renewal disabled") {
		t.Fatalf("renewal started with no directory to write into:\n%s", logged)
	}
}

// A renewed identity supersedes the provisioned one across a restart. Without this an enrolled device would
// renew, restart, and go back to presenting the credential it was enrolled with — the one that expires.
func TestARenewedIdentityIsPreferredOverTheEnrolledOne(t *testing.T) {
	dir := t.TempDir()
	enrolledCert, enrolledKey, _ := mkSelfSigned(t, "win-dev-1-enrolled", nil)
	renewedCert, renewedKey, _ := mkSelfSigned(t, "win-dev-1-renewed", nil)

	// What a renewal leaves behind: material in the identity directory, named by a pointer.
	certPath := filepath.Join(dir, "device-renewed.crt")
	keyPath := filepath.Join(dir, "device-renewed.key")
	if err := os.WriteFile(certPath, renewedCert, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, renewedKey, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeIdentityPointer(dir, deviceIdentityPointer{
		CertificateSHA256: "abc123", CertFile: certPath, KeyFile: keyPath,
		KeyStorage: "file", CommonName: "win-dev-1-renewed", InstalledAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	tc, err := buildTransportConfigFromAnchors("https://10.0.0.9:18543", nil, nil, 0, dir, enrolledCert, enrolledKey)
	if err != nil {
		t.Fatal(err)
	}
	if got := commonNameOf(t, tc.clientCert); got != "win-dev-1-renewed" {
		t.Fatalf("identity in force = %q, want the renewed one — an enrolled device that renews must not "+
			"revert to its enrolment certificate on restart", got)
	}
}

// With no renewal recorded, the provisioned material is used exactly as before.
func TestTheEnrolledIdentityIsUsedWhenNothingHasBeenRenewed(t *testing.T) {
	enrolledCert, enrolledKey, _ := mkSelfSigned(t, "win-dev-1-enrolled", nil)
	tc, err := buildTransportConfigFromAnchors("https://10.0.0.9:18543", nil, nil, 0, t.TempDir(), enrolledCert, enrolledKey)
	if err != nil {
		t.Fatal(err)
	}
	if got := commonNameOf(t, tc.clientCert); got != "win-dev-1-enrolled" {
		t.Fatalf("identity in force = %q, want the enrolled one", got)
	}
}

// Reprovisioning can leave the previous deployment's renewal pointer intact.
// The newly enrolled identity must win without destroying the old key material.
func TestForeignRenewedIdentityDoesNotOverrideNewEnrollment(t *testing.T) {
	for _, renewedTenant := range []string{"tenant_previous", "tenant_current", ""} {
		t.Run("renewed_"+renewedTenant, func(t *testing.T) {
			makeIdentity := func(cn, tenant string) ([]byte, []byte) {
				_, keyPEM, cert := mkSelfSigned(t, cn, nil)
				leaf, err := x509.ParseCertificate(cert.Certificate[0])
				if err != nil {
					t.Fatal(err)
				}
				if tenant != "" {
					leaf.Subject.Organization = []string{tenant}
					leaf.RawSubject = nil
				}
				der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, leaf.PublicKey, cert.PrivateKey)
				if err != nil {
					t.Fatal(err)
				}
				return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), keyPEM
			}
			enrolledCert, enrolledKey := makeIdentity("current-enrolled", "tenant_current")
			oldCert, oldKey := makeIdentity("renewed", renewedTenant)
			dir := t.TempDir()
			cp, kp := filepath.Join(dir, "renewed.crt"), filepath.Join(dir, "renewed.key")
			if err := os.WriteFile(cp, oldCert, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(kp, oldKey, 0600); err != nil {
				t.Fatal(err)
			}
			if err := writeIdentityPointer(dir, deviceIdentityPointer{CertFile: cp, KeyFile: kp, KeyStorage: "file"}); err != nil {
				t.Fatal(err)
			}
			tc, err := buildTransportConfigFromAnchors("https://edge.example:443", nil, nil, 0, dir, enrolledCert, enrolledKey)
			if err != nil {
				t.Fatal(err)
			}
			want := "current-enrolled"
			if renewedTenant == "tenant_current" {
				want = "renewed"
			}
			if got := commonNameOf(t, tc.currentClientCert()); got != want {
				t.Fatalf("selected %s, want %s", got, want)
			}
			retained, err := os.ReadFile(kp)
			if err != nil || !bytes.Equal(retained, oldKey) {
				t.Fatal("previous identity key was changed")
			}
		})
	}
}
