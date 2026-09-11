package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The renewal window must match renewalDue() in cmd/edge/enroll_renew_endpoint.go and the macOS client
// exactly. If a client renewed later than the server's design assumes, the retry budget that turns a broken
// renewal path into an alert rather than an outage would not exist.
func TestRenewalOpensAtTwoThirdsOfLife(t *testing.T) {
	notBefore := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter := notBefore.Add(60 * 24 * time.Hour)

	cases := []struct {
		name string
		at   time.Time
		want bool
	}{
		{"fresh", notBefore, false},
		{"halfway", notBefore.Add(30 * 24 * time.Hour), false},
		{"just before two thirds", notBefore.Add(40*24*time.Hour - time.Minute), false},
		{"at two thirds", notBefore.Add(40 * 24 * time.Hour), true},
		{"day 50 — 10 days of retries left", notBefore.Add(50 * 24 * time.Hour), true},
		{"expired", notAfter.Add(time.Hour), true},
	}
	for _, tc := range cases {
		// No operator declaration here: pure two-thirds-of-life schedule.
		if got := renewalDue(notBefore, notAfter, time.Time{}, tc.at); got != tc.want {
			t.Errorf("renewalDue at %s = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// "We cannot tell when this expires" must not mean "renew now" — that would turn one malformed certificate
// into a device renewing on every check.
func TestRenewalDueRejectsDegenerateWindows(t *testing.T) {
	now := time.Now()
	if renewalDue(time.Time{}, time.Time{}, time.Time{}, now) {
		t.Error("a zero window must not be due")
	}
	if renewalDue(now, now.Add(-time.Hour), time.Time{}, now) {
		t.Error("an inverted window must not be due")
	}
	if renewalDue(now, now, time.Time{}, now) {
		t.Error("a zero-length window must not be due")
	}
}

// The operator's DECLARATION triggers renewal ahead of the schedule for a certificate ISSUED before the cutoff,
// and — this is the whole point — it is idempotent: a certificate issued AT or AFTER the cutoff (the renewed
// one) no longer matches, so no server-side tracking of who has renewed is needed.
func TestRenewalDueOperatorCutoff(t *testing.T) {
	notBefore := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	// A ten-year certificate whose two-thirds point is years away — the case the schedule cannot handle.
	notAfter := notBefore.Add(10 * 365 * 24 * time.Hour)
	early := notBefore.Add(24 * time.Hour) // nowhere near two-thirds

	// Cutoff AFTER this certificate was issued -> stale -> due, even though the schedule says no.
	cutoff := notBefore.Add(180 * 24 * time.Hour)
	if !renewalDue(notBefore, notAfter, cutoff, early) {
		t.Fatal("a certificate issued before the operator cutoff must be due")
	}
	// The renewed certificate is issued AT/after the cutoff -> not stale -> not due (idempotency).
	renewedNotBefore := cutoff.Add(time.Second)
	if renewalDue(renewedNotBefore, renewedNotBefore.Add(10*365*24*time.Hour), cutoff, renewedNotBefore.Add(time.Hour)) {
		t.Fatal("a certificate issued after the cutoff must NOT re-trigger — the declaration would loop")
	}
	// A certificate issued exactly AT the cutoff is not "before" it -> not due.
	if renewalDue(cutoff, cutoff.Add(10*365*24*time.Hour), cutoff, cutoff.Add(time.Hour)) {
		t.Fatal("issued exactly at the cutoff is not 'before' it and must not be due")
	}
	// The declaration fires even on a malformed window — a stale-issuing-CA certificate should renew regardless.
	if !renewalDue(notBefore, time.Time{}, cutoff, early) {
		t.Fatal("the declaration must fire even when the validity window is degenerate")
	}
	// No declaration (zero cutoff) leaves the schedule untouched: this early certificate is not due.
	if renewalDue(notBefore, notAfter, time.Time{}, early) {
		t.Fatal("with no declaration an early long-lived certificate must not be due")
	}
}

// parseRenewCutoff must fall back to the zero time (== no declaration) for anything empty or unparseable —
// never a value that could read as "renew now". A garbled response must not become a fleet-wide renewal storm.
func TestParseRenewCutoff(t *testing.T) {
	if got := parseRenewCutoff("2026-07-30T20:55:50Z"); got.IsZero() {
		t.Fatal("a valid RFC3339 cutoff parsed to zero")
	} else if !got.Equal(time.Date(2026, 7, 30, 20, 55, 50, 0, time.UTC)) {
		t.Fatalf("parsed cutoff = %v", got)
	}
	for _, bad := range []string{"", "   ", "not-a-date", "2026-07-30", "30/07/2026"} {
		if got := parseRenewCutoff(bad); !got.IsZero() {
			t.Fatalf("parseRenewCutoff(%q) = %v, want zero (no declaration)", bad, got)
		}
	}
}

// mintFor issues a certificate for a given public key, so tests can build the exact responses the Edge could
// plausibly return — including the wrong ones.
func mintFor(t *testing.T, pub *ecdsa.PublicKey, cn string, notBefore, notAfter time.Time) string {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// These are the checks that stand between a bad response and a device that can no longer connect.
func TestValidateIssuedRefusesResponsesThatWouldBreakTheDevice(t *testing.T) {
	ourKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()

	t.Run("a certificate for somebody else's key", func(t *testing.T) {
		// The most dangerous response to accept: it installs perfectly and then fails at the next handshake,
		// by which point the working identity would already be gone.
		pemStr := mintFor(t, &otherKey.PublicKey, "win-dev-1", now.Add(-time.Hour), now.Add(60*24*time.Hour))
		_, err := validateIssued(pemStr, &ourKey.PublicKey, "win-dev-1")
		if err == nil || !strings.Contains(err.Error(), "DIFFERENT key") {
			t.Fatalf("expected a wrong-key rejection, got %v", err)
		}
	})

	t.Run("a certificate naming another device", func(t *testing.T) {
		pemStr := mintFor(t, &ourKey.PublicKey, "ceo-laptop", now.Add(-time.Hour), now.Add(60*24*time.Hour))
		if _, err := validateIssued(pemStr, &ourKey.PublicKey, "win-dev-1"); err == nil {
			t.Fatal("a certificate for a different device was accepted")
		}
	})

	t.Run("an already expired certificate", func(t *testing.T) {
		pemStr := mintFor(t, &ourKey.PublicKey, "win-dev-1", now.Add(-48*time.Hour), now.Add(-time.Hour))
		if _, err := validateIssued(pemStr, &ourKey.PublicKey, "win-dev-1"); err == nil {
			t.Fatal("an expired certificate was accepted")
		}
	})

	t.Run("a certificate already past its own renewal point", func(t *testing.T) {
		// Would leave the device permanently due, renewing on every single check.
		pemStr := mintFor(t, &ourKey.PublicKey, "win-dev-1", now.Add(-50*time.Hour), now.Add(time.Hour))
		_, err := validateIssued(pemStr, &ourKey.PublicKey, "win-dev-1")
		if err == nil || !strings.Contains(err.Error(), "renewal would loop") {
			t.Fatalf("expected a loop rejection, got %v", err)
		}
	})

	t.Run("a shorter-lived certificate is ACCEPTED", func(t *testing.T) {
		// Renewal legitimately shortens validity: a fleet moving from hand-issued long-lived certificates to
		// short-lived managed ones is the migration this exists to enable. An earlier version of this rule
		// required the new certificate to outlive the old one, and rejected a perfectly good 60-day
		// certificate replacing a hand-made one-year one — blocking exactly the case it was written for.
		pemStr := mintFor(t, &ourKey.PublicKey, "win-dev-1", now.Add(-time.Minute), now.Add(60*24*time.Hour))
		if _, err := validateIssued(pemStr, &ourKey.PublicKey, "win-dev-1"); err != nil {
			t.Fatalf("a shorter-lived but valid certificate was rejected: %v", err)
		}
	})

	t.Run("garbage", func(t *testing.T) {
		if _, err := validateIssued("not a pem block", &ourKey.PublicKey, "win-dev-1"); err == nil {
			t.Fatal("unparseable input was accepted")
		}
	})
}

// writePair writes a cert+key pair to disk and returns the two paths.
func writePair(t *testing.T, dir, name, cn string, notAfter time.Time) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := mintFor(t, &key.PublicKey, cn, time.Now().Add(-time.Hour), notAfter)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dir, name+".crt")
	keyPath := filepath.Join(dir, name+".key")
	if err := os.WriteFile(certPath, []byte(certPEM), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

// Once a device has renewed, the renewed identity is what it must present — the configured files are by then
// the older credential heading for expiry.
func TestRenewedIdentityIsPreferredOverTheBootstrapFiles(t *testing.T) {
	dir := t.TempDir()
	bootCert, bootKey := writePair(t, dir, "bootstrap", "win-dev-1", time.Now().Add(365*24*time.Hour))
	newCert, newKey := writePair(t, dir, "renewed", "win-dev-1", time.Now().Add(60*24*time.Hour))

	if _, source, err := loadDeviceIdentity(bootCert, bootKey); err != nil || source != "bootstrap" {
		t.Fatalf("with no pointer the configured files must be used: source=%q err=%v", source, err)
	}

	if err := writeIdentityPointer(dir, deviceIdentityPointer{
		CertificateSHA256: "deadbeef", CertFile: newCert, KeyFile: newKey,
		CommonName: "win-dev-1", NotAfter: time.Now().Add(60 * 24 * time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	if _, source, err := loadDeviceIdentity(bootCert, bootKey); err != nil || source != "renewed" {
		t.Fatalf("the renewed identity must win: source=%q err=%v", source, err)
	}
}

// A pointer naming material that is gone must NOT stop the agent. Falling back to a working bootstrap identity
// beats refusing to start — the whole point is that renewal cannot cause an outage.
func TestBrokenPointerFallsBackInsteadOfFailing(t *testing.T) {
	dir := t.TempDir()
	bootCert, bootKey := writePair(t, dir, "bootstrap", "win-dev-1", time.Now().Add(365*24*time.Hour))

	if err := writeIdentityPointer(dir, deviceIdentityPointer{
		CertificateSHA256: "deadbeef",
		CertFile:          filepath.Join(dir, "vanished.crt"),
		KeyFile:           filepath.Join(dir, "vanished.key"),
		CommonName:        "win-dev-1",
	}); err != nil {
		t.Fatal(err)
	}
	_, source, err := loadDeviceIdentity(bootCert, bootKey)
	if err != nil {
		t.Fatalf("a pointer to missing material must not be fatal: %v", err)
	}
	if source != "bootstrap" {
		t.Fatalf("expected a fallback to the configured files, got source=%q", source)
	}
}

// The pointer must never carry key material. It is written to a config directory and read by operators; the
// day it contains a private key is the day renewal becomes a secret-disclosure path.
func TestPointerCarriesNoKeyMaterial(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writePair(t, dir, "renewed", "win-dev-1", time.Now().Add(60*24*time.Hour))
	if err := writeIdentityPointer(dir, deviceIdentityPointer{
		CertificateSHA256: "abc123", CertFile: certPath, KeyFile: keyPath, CommonName: "win-dev-1",
	}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, renewalPointerFile))
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"PRIVATE KEY", "BEGIN EC", "BEGIN CERTIFICATE"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("the pointer file contains %q — it must hold references and metadata only", forbidden)
		}
	}
}

// A FIXED check interval is wrong for short-lived certificates, and wrong in the worst way: nothing errors,
// nothing logs, and the certificate simply expires unchecked. The interval has to fit inside the retry budget,
// which is a third of the certificate's life.
func TestCheckIntervalFitsInsideTheRetryBudget(t *testing.T) {
	cases := []struct {
		name string
		life time.Duration
	}{
		{"60-day certificate — what /enroll issues today", 60 * 24 * time.Hour},
		{"24-hour certificate", 24 * time.Hour},
		{"1-hour certificate", time.Hour},
		{"5-minute certificate", 5 * time.Minute},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			notBefore := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
			notAfter := notBefore.Add(tc.life)
			interval := renewalCheckInterval(notBefore, notAfter)
			budget := tc.life / 3

			if interval > budget {
				t.Fatalf("check interval %s exceeds the %s retry budget — with a fixed 6h interval a 1-hour "+
					"certificate got ZERO checks before expiring", interval, budget)
			}
			if attempts := budget / interval; attempts < 2 {
				t.Fatalf("only %d attempt(s) inside the retry budget — a single transient failure would use up "+
					"the whole margin", attempts)
			}
			if interval > maxRenewalCheckInterval {
				t.Fatalf("interval %s exceeds the cap %s", interval, maxRenewalCheckInterval)
			}
			if interval < minRenewalCheckInterval {
				t.Fatalf("interval %s is below the floor %s — a very short certificate must not turn renewal "+
					"into a busy loop against the Edge", interval, minRenewalCheckInterval)
			}
		})
	}
}

// A long-lived certificate must not push the interval out to something absurd; six hours is the cap.
func TestCheckIntervalIsCappedForLongLivedCertificates(t *testing.T) {
	notBefore := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	got := renewalCheckInterval(notBefore, notBefore.Add(10*365*24*time.Hour))
	if got != maxRenewalCheckInterval {
		t.Fatalf("a 10-year certificate gave interval %s, want the %s cap", got, maxRenewalCheckInterval)
	}
}

// An unreadable validity window must not produce a nonsensical interval.
func TestCheckIntervalHandlesDegenerateWindows(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct{ notBefore, notAfter time.Time }{
		{time.Time{}, time.Time{}},
		{now, now.Add(-time.Hour)},
		{now, now},
	} {
		if got := renewalCheckInterval(tc.notBefore, tc.notAfter); got != maxRenewalCheckInterval {
			t.Fatalf("a degenerate window gave %s, want the %s default", got, maxRenewalCheckInterval)
		}
	}
}
