//go:build windows

package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os/exec"
	"strings"
	"testing"
)

// The real Windows trust-store scan finds a root that IS installed and does not find one that is not. Uses a
// fingerprint taken from the machine's own Root store via certutil, so the test is self-calibrating rather than
// hard-coding a certificate that may not be present on a given box.
func TestInterceptionRootsPresentAgainstRealStore(t *testing.T) {
	real := aRootStoreFingerprint(t)
	absent := "0000000000000000000000000000000000000000000000000000000000000000"

	got := interceptionRootsPresent([]string{real, absent})
	foundReal := false
	for _, f := range got {
		if strings.EqualFold(f, real) {
			foundReal = true
		}
		if strings.EqualFold(f, absent) {
			t.Fatal("a fingerprint that is not in any store was reported as present")
		}
	}
	if !foundReal {
		t.Fatalf("a root known to be in the store (%s) was not found; got %v", real, got)
	}

	// Empty wanted => empty answer, no scan claimed.
	if interceptionRootsPresent(nil) != nil {
		t.Fatal("no roots wanted must yield no roots found")
	}
}

// aRootStorefingerprint returns the SHA-256 of some certificate actually in the LocalMachine Root store, by
// exporting one via certutil. Skips if the environment cannot produce one (a bare CI container).
func aRootStoreFingerprint(t *testing.T) string {
	t.Helper()
	// certutil -store Root dumps the machine Root store; each cert has a base64 blob we can hash. Simpler:
	// enumerate with our own scanner is what we are testing, so take an independent path — grab any cert DER
	// from the store via PowerShell and hash it here.
	out, err := exec.Command("powershell", "-NoProfile", "-Command",
		`$c = Get-ChildItem Cert:\LocalMachine\Root | Select-Object -First 1; `+
			`[System.Convert]::ToBase64String($c.RawData)`).Output()
	if err != nil {
		t.Skipf("cannot read the LocalMachine Root store to calibrate the test: %v", err)
	}
	b64 := strings.TrimSpace(string(out))
	if b64 == "" {
		t.Skip("LocalMachine Root store is empty")
	}
	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Skipf("could not decode a root cert for calibration: %v", err)
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}
