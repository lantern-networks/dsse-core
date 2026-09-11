package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const goodKey = "0ae740bd219e4bc112ac84f6153972406a5415999f1eec6e8fa9cacf1a518220"

// ★★★ A PROFILE CANNOT CARRY THE KEY THAT PROVES IT. The key is the fourth artefact, placed by the operator
// beside the token — placing it IS the explicit act the operator's rule requires.
func TestTheOperatorsKeyIsReadAndItsOrdinaryMistakesAreNamed(t *testing.T) {
	dir := t.TempDir()
	ok := filepath.Join(dir, "k.txt")
	if err := os.WriteFile(ok, []byte("  "+strings.ToUpper(goodKey)+"\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readSigningKeyFile(ok)
	if err != nil || got != goodKey {
		t.Fatalf("got %q, %v — whitespace and case must not decide whether a device can verify anything", got, err)
	}

	empty := filepath.Join(dir, "empty.txt")
	if err := os.WriteFile(empty, []byte("\n \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The failure this prevents is silent: no key verifies nothing, every profile is refused, and the device
	// lands in the same state as one that was never given a profile.
	if _, err := readSigningKeyFile(empty); err == nil || !strings.Contains(err.Error(), "refuse every configuration") {
		t.Fatalf("an empty key file was accepted, or the message did not say what it costs: %v", err)
	}

	junk := filepath.Join(dir, "junk.txt")
	if err := os.WriteFile(junk, []byte("-----BEGIN PUBLIC KEY-----\nnope\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err = func() error { _, e := readSigningKeyFile(junk); return e }()
	if err == nil || !strings.Contains(err.Error(), "64") {
		t.Fatalf("a file that is not a key was accepted, or the message did not say what one looks like: %v", err)
	}

	// No key path at all is the ordinary pre-4th-artefact install and must not be an error here; the caller
	// decides whether it can proceed without one.
	if got, err := readSigningKeyFile(""); err != nil || got != "" {
		t.Fatalf("got %q, %v", got, err)
	}
}

// The file is written for the person, not the program: an operator asking which authority this box verifies
// against needs somewhere to look that is not a service's command line.
func TestTheKeyIsLeftWhereAnOperatorWillLookForIt(t *testing.T) {
	dir := t.TempDir()
	note, err := installSigningKey(dir, goodKey)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(note, signingKeyFileName) {
		t.Fatalf("note = %q", note)
	}
	raw, err := os.ReadFile(filepath.Join(dir, signingKeyFileName))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(raw)) != goodKey {
		t.Fatalf("stored %q", strings.TrimSpace(string(raw)))
	}
	// Re-running the installer must not make the file's timestamp meaningless as evidence.
	again, err := installSigningKey(dir, goodKey)
	if err != nil || !strings.Contains(again, "unchanged") {
		t.Fatalf("note = %q, err = %v", again, err)
	}
	// One name on both platforms, or one product has two runbooks.
	if signingKeyFileName != "profile_signing_key.txt" {
		t.Fatalf("the file name drifted from the macOS one: %q", signingKeyFileName)
	}
}

// ★ THE RUNNING AGENT READS ITS SERVICE ARGUMENTS, NOT THE FILE. A pin read from beside the envelope could be
// replaced by whoever replaced the envelope, and the verification would be circular (review S1).
func TestThePinsAreReplacedInTheServiceArgumentsNotAppendedTo(t *testing.T) {
	old := "b" + strings.Repeat("0", 63)
	args := []string{"--service-run", "--config-store", "--config-pin", old, "--agent-policy-pin", old,
		"--bypass-dest", "100.72.135.18:22"}
	got := pinArgs(args, goodKey)

	joined := strings.Join(got, " ")
	if strings.Contains(joined, old) {
		t.Fatalf("the superseded pin is still on the command line, and which one wins is flag-package "+
			"ordering an operator cannot read: %v", got)
	}
	if strings.Count(joined, "--config-pin") != 1 || strings.Count(joined, "--agent-policy-pin") != 1 {
		t.Fatalf("a pin appears more than once: %v", got)
	}
	if !strings.Contains(joined, "--config-pin "+goodKey) || !strings.Contains(joined, "--agent-policy-pin "+goodKey) {
		t.Fatalf("the new pin is not in force: %v", got)
	}
	// Everything the package baked in for THIS site must survive: the bypass destination is the management
	// path, and losing it puts this box's own route inside the thing it manages.
	if !strings.Contains(joined, "--bypass-dest 100.72.135.18:22") {
		t.Fatalf("a site fact was dropped: %v", got)
	}
	if !strings.Contains(joined, "--service-run") || !strings.Contains(joined, "--config-store") {
		t.Fatalf("the service no longer runs as a service: %v", got)
	}
}

// The joined --flag=value form is the same flag and must not survive as a duplicate.
func TestTheJoinedFlagFormIsReplacedToo(t *testing.T) {
	got := pinArgs([]string{"--service-run", "--config-pin=" + strings.Repeat("a", 64)}, goodKey)
	joined := strings.Join(got, " ")
	if strings.Contains(joined, strings.Repeat("a", 64)) {
		t.Fatalf("the --flag=value form survived: %v", got)
	}
	if strings.Count(joined, "--config-pin") != 1 {
		t.Fatalf("%v", got)
	}
}

// A service that never carried a pin gets one, which is the generic-package case this whole change exists for.
func TestAPackageThatBakedNoPinGetsOneFromTheOperator(t *testing.T) {
	got := pinArgs([]string{"--service-run", "--config-store"}, goodKey)
	if strings.Count(strings.Join(got, " "), goodKey) != 2 {
		t.Fatalf("%v", got)
	}
}
