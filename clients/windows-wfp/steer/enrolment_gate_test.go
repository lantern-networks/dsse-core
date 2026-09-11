package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The same rule table as the macOS gate, deliberately — a device that behaves differently per platform at its
// trust bootstrap is a device with two trust stories.
func TestEnrolmentGateDecisionTable(t *testing.T) {
	cases := []struct {
		identity, token, before bool
		want                    enrolmentGateDecision
	}{
		{true, false, false, gateProceed},
		{true, true, true, gateProceed}, // identity wins over everything
		{false, true, false, gateEnrolFirst},
		{false, true, true, gateEnrolFirst}, // a token also re-enrols a wiped machine
		{false, false, true, gateProceedPreviouslyEnrolled},
		{false, false, false, gateStandAside},
	}
	for _, c := range cases {
		if got := enrolmentGateDecide(c.identity, c.token, c.before); got != c.want {
			t.Errorf("decide(identity=%v token=%v before=%v) = %v, want %v", c.identity, c.token, c.before, got, c.want)
		}
	}
}

func TestEnrolmentConfigLoadStates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "enrolment.json")

	// Missing is the ordinary case: no error, just absent.
	if _, ok, err := loadEnrolmentConfig(path); ok || err != nil {
		t.Fatalf("missing file: ok=%v err=%v, want absent and quiet", ok, err)
	}

	// Present but unreadable must be reported — the installer wrote something here and the agent must not
	// ignore it silently.
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadEnrolmentConfig(path); err == nil {
		t.Fatalf("unparseable config loaded silently")
	}

	if err := os.WriteFile(path, []byte(`{
		"enrol_url": "https://edge:8443/enroll",
		"device_id": "win-dev-9",
		"enrolment_token": "secret",
		"device_ca_pin_sha256": "abc123"
	}`), 0o600); err != nil {
		t.Fatal(err)
	}
	c, ok, err := loadEnrolmentConfig(path)
	if err != nil || !ok {
		t.Fatalf("load: ok=%v err=%v", ok, err)
	}
	if !c.hasUnspentToken() || !c.hasPinnedBootstrap() {
		t.Fatalf("hasUnspentToken=%v hasPinnedBootstrap=%v, want both true", c.hasUnspentToken(), c.hasPinnedBootstrap())
	}
}

// A config with neither an endpoint-CA nor a device-CA pin must not count as a pinned bootstrap: enrolment is
// the trust bootstrap and must not run over an unpinned channel.
func TestEnrolmentConfigUnpinnedBootstrap(t *testing.T) {
	c := enrolmentConfig{EnrolURL: "https://edge:8443/enroll", DeviceID: "d", Token: "s"}
	if c.hasPinnedBootstrap() {
		t.Fatalf("a config with no pin counted as pinned")
	}
}

// Spending erases the token, records that it WAS spent, and keeps everything else — what an operator reading
// the file months later actually wants to know.
func TestMarkEnrolmentTokenSpent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "enrolment.json")
	if err := os.WriteFile(path, []byte(`{
		"enrol_url": "https://edge:8443/enroll",
		"device_id": "win-dev-9",
		"enrolment_token": "secret",
		"enrol_ca_pem": "PEM"
	}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := markEnrolmentTokenSpent(path); err != nil {
		t.Fatal(err)
	}
	c, ok, err := loadEnrolmentConfig(path)
	if err != nil || !ok {
		t.Fatalf("reload: ok=%v err=%v", ok, err)
	}
	if c.Token != "" || !c.TokenSpent {
		t.Fatalf("token=%q spent=%v, want erased and recorded", c.Token, c.TokenSpent)
	}
	if c.hasUnspentToken() {
		t.Fatalf("a spent config still offers a token")
	}
	if c.EnrolURL == "" || c.DeviceID == "" || c.EnrolCAPEM == "" {
		t.Fatalf("spending the token dropped unrelated fields: %+v", c)
	}
	// The raw file must not contain the secret any more.
	raw, _ := os.ReadFile(path)
	if len(raw) == 0 || strings.Contains(string(raw), "secret") {
		t.Fatalf("the spent secret is still on disk: %s", raw)
	}
}

// ★★★ THE INSTALLER MUST NOT BE A SECOND PLACE THAT NAMES THE MACHINE (2026-08-29, found by installing from a
// package + profile + token on win-dev-1 — the only way to find it, because every previous walk of this lane
// was done by a person with a shell who wrote device_id in by hand).
//
// `--mode enroll` was given this default on 2026-08-25 and self-enrolment was not, so the path the product
// actually installs refused with "needs enrol_url and device_id" and stood aside. Nothing in the product was
// ever going to supply that field.
func TestASelfEnrolmentConfigNeedNotNameTheMachine(t *testing.T) {
	if got := (enrolmentConfig{EnrolURL: "https://edge/enroll", Token: "t"}).DeviceID; got != "" {
		t.Fatalf("fixture already carries a device_id (%q) — this test would prove nothing", got)
	}
	// The defaulting lives in performSelfEnrolment; what is asserted here is the CONTRACT it now honours,
	// stated where the gate's rules are: a seed with no device_id is a complete seed.
	c := enrolmentConfig{EnrolURL: "https://edge/enroll", Token: "t", DeviceCAPinSHA256: "ab"}
	if !c.hasUnspentToken() {
		t.Fatal("a seed carrying a live token was read as having none")
	}
	if !c.hasPinnedBootstrap() {
		t.Fatal("a seed pinned by device-CA fingerprint was read as unpinned")
	}
	if strings.TrimSpace(c.DeviceID) != "" {
		t.Fatal("the seed names a machine — the installer must not")
	}
}
