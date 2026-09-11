//go:build windows

package main

import (
	"os"
	"testing"
)

// Day-0 self-enrolment against the REAL reference Edge. No stubs.
//
// The fake-Edge E2E proves the ordering (enrol -> probe -> store -> erase) and both refusal paths, but it
// cannot answer the questions that decide whether this ships: does the real /enroll accept the CSR this code
// builds and the admin-issued token, does the issued identity verify against the device-CA pin, and — the one
// the unit fixtures were rebuilt to expose — does the freshly issued device certificate actually complete a
// (T) mTLS handshake against the transport whose SERVER chains to a SEPARATE transport CA. A fake Edge answers
// yes to all of it by construction.
//
// OFF by default — it needs the reference lab and a one-time admin-issued token (each run needs a fresh one,
// since the token is spent on success). Enable it explicitly:
//
//	DSSE_LIVE_ENROL_URL=https://203.0.113.10:8443/enroll \
//	DSSE_LIVE_ENROL_TRANSPORT=https://203.0.113.10:18543 \
//	DSSE_LIVE_ENROL_CA=<enroll endpoint cert PEM path> \
//	DSSE_LIVE_ENROL_TRANSPORT_CA=<transport CA PEM path> \
//	DSSE_LIVE_ENROL_TOKEN=<one-time secret> \
//	DSSE_LIVE_ENROL_DEVICE=win-dev-dayzero \
//	go test ./clients/windows-wfp/steer -run TestLiveDayZeroEnrolment -v
//
// It works entirely inside a temporary directory (never defaultEnrollDir()), so win-dev-1's live material is
// untouched. It leaves an enrolled identity for the chosen device name on the Edge ledger — remove it after.
func TestLiveDayZeroEnrolment(t *testing.T) {
	enrolURL := os.Getenv("DSSE_LIVE_ENROL_URL")
	transportURL := os.Getenv("DSSE_LIVE_ENROL_TRANSPORT")
	enrolCAPath := os.Getenv("DSSE_LIVE_ENROL_CA")
	transportCAPath := os.Getenv("DSSE_LIVE_ENROL_TRANSPORT_CA")
	token := os.Getenv("DSSE_LIVE_ENROL_TOKEN")
	device := os.Getenv("DSSE_LIVE_ENROL_DEVICE")
	if enrolURL == "" || transportURL == "" || enrolCAPath == "" || transportCAPath == "" || token == "" || device == "" {
		t.Skip("live Day-0 enrolment not configured — set DSSE_LIVE_ENROL_* to run it")
	}

	enrolCA, err := os.ReadFile(enrolCAPath)
	if err != nil {
		t.Fatalf("read enrol CA: %v", err)
	}
	transportCA, err := os.ReadFile(transportCAPath)
	if err != nil {
		t.Fatalf("read transport CA: %v", err)
	}

	dir := t.TempDir()
	cfgPath := writeEnrolmentConfig(t, dir, enrolmentConfig{
		EnrolURL:   enrolURL,
		DeviceID:   device,
		Token:      token,
		EnrolCAPEM: string(enrolCA),
	})
	cfg, ok, err := loadEnrolmentConfig(cfgPath)
	if err != nil || !ok {
		t.Fatalf("load enrolment config: ok=%v err=%v", ok, err)
	}

	// The whole gate-driven path, exactly as the service runs it: enrol over the pinned bootstrap, prove the
	// issued identity on the (T) transport verifying the server with the transport CA, store, erase the token.
	if err := performSelfEnrolment(cfg, cfgPath, transportURL, "", transportCA, dir); err != nil {
		t.Fatalf("live Day-0 enrolment failed: %v", err)
	}

	// The identity is committed and loads back through the DPAPI round-trip.
	m, ok, err := loadEnrollment(dir)
	if err != nil || !ok {
		t.Fatalf("enrolled material after success: ok=%v err=%v", ok, err)
	}
	if m.Meta.DeviceID != device {
		t.Fatalf("enrolled device = %q, want %q", m.Meta.DeviceID, device)
	}
	t.Logf("live Day-0 enrolment OK device=%q tenant=%q group=%q not_after via meta=%q",
		m.Meta.DeviceID, m.Meta.Tenant, m.Meta.Group, m.Meta.EnrolledAt)

	// The one-time token was spent and erased from the config file — the erase-once-spent principle, end to end.
	c, _, _ := loadEnrolmentConfig(cfgPath)
	if c.hasUnspentToken() || !c.TokenSpent {
		t.Fatalf("token not spent/erased after a live enrolment: %+v", c)
	}
	raw, _ := os.ReadFile(cfgPath)
	if len(raw) == 0 {
		t.Fatal("config vanished")
	}

	// A second attempt with the SAME token must be refused by the Edge — one-time, verified live. Nothing is
	// committed to a fresh directory.
	dir2 := t.TempDir()
	cfg2Path := writeEnrolmentConfig(t, dir2, enrolmentConfig{
		EnrolURL: enrolURL, DeviceID: device + "-replay", Token: token,
		EnrolCAPEM: string(enrolCA),
	})
	cfg2, _, _ := loadEnrolmentConfig(cfg2Path)
	if err := performSelfEnrolment(cfg2, cfg2Path, transportURL, "", transportCA, dir2); err == nil {
		t.Fatal("the spent token enrolled a second machine — one-time was not enforced")
	} else {
		t.Logf("replay correctly refused: %v", err)
	}
	if _, ok, _ := loadEnrollment(dir2); ok {
		t.Fatal("the replay attempt committed material")
	}
}
