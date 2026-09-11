package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ★★★ THE DEPLOYMENT DIRECTORY IS READABLE, SO NOTHING READABLE IN IT MAY HOLD A SECRET (2026-09-02).
//
// It was created 0700 by an installer running as root, which made the next printed step — `cd <dir> &&
// docker compose` — impossible to run for the operator who had just created it. Widening the directory to
// 0755 is right, and it moves the whole question onto the FILES: a private key at 0644 inside a 0700
// directory was safe by accident, and is not any more.
//
// Measured on the live deployment when the change was made: every key, deployment.env and the authority
// directory were already 0600/0700, and what is readable is certificates, public keys and haproxy configs.
// This holds that, because "it happened to be right on the day" is not a property anybody can rely on.
func TestNothingReadableInTheDeploymentHoldsASecret(t *testing.T) {
	dir := t.TempDir()
	if err := writeEnvironment(dir, []string{"localhost"}, nil); err != nil {
		t.Fatalf("render the environment: %v", err)
	}
	if err := writeComposeFileFor(dir, foundingShape); err != nil {
		t.Fatalf("render the compose file: %v", err)
	}
	if err := writeLaunchScripts(dir); err != nil {
		t.Fatalf("render the launch scripts: %v", err)
	}
	// ★ AND THE WALK IS PROVEN TO SEE A READABLE SECRET. Without this the test passes on a directory it
	// never looked into, which is the shape of every check this file exists because of.
	if err := os.WriteFile(filepath.Join(dir, "proof-of-walk.pem"),
		[]byte("-----BEGIN PRIVATE KEY-----\nnot a key\n-----END PRIVATE KEY-----\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	saw := false
	if err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && filepath.Base(path) == "proof-of-walk.pem" {
			saw = true
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if !saw {
		t.Fatal("the walk did not reach a file placed for it to find")
	}
	if err := os.Remove(filepath.Join(dir, "proof-of-walk.pem")); err != nil {
		t.Fatal(err)
	}

	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Mode().Perm()&0o044 == 0 {
			return nil // readable only by its owner: nothing to check
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, secret := range []string{"PRIVATE KEY", "PASSWORD=", "PASSWORD='", "_TOKEN=", "_TOKEN='"} {
			if strings.Contains(string(body), secret) {
				t.Errorf("%s is mode %#o — readable by anyone on the machine — and contains %q",
					filepath.Base(path), info.Mode().Perm(), secret)
				break
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk the deployment: %v", err)
	}
}
