package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// ★★★ THE MINTING MATERIAL IS NOT A RUNTIME POSSESSION (2026-08-27, the operator called mounting one directory into
// everything too big a mistake to ship).
//
// Measured on a generated deployment: `./:/deployment` is mounted into both control planes, both Edges and the
// Console, and that directory holds root.key, transport-ca.key, management-ca.key, the interception root key
// and bundle-signing.key. None of those five is read by any running process — they are what the INSTALLER
// signs with. On one host they look like an operator's directory; split across machines, as this product is
// meant to be deployed, it means the deployment's root CA private key is on every Edge box.
//
// ★ AND THE INTERIM ALLOWANCE DEPENDED ON THIS. Keeping a root on disk before it moves into hardware is
// acceptable only while nothing running is handed it. In the generated deployment everything was.
//
// The done-condition is measurable and this test is it: the authority material lives in its own directory, and
// no service mounts anything that reaches it.
func TestNoRunningNodeCanReachTheAuthorityMaterial(t *testing.T) {
	dir := t.TempDir()
	if err := run(dir, "the-deployment.example", "Example", 3, false); err != nil {
		t.Fatalf("mint: %v", err)
	}

	// The five that nothing reads at runtime, and where they must live.
	for _, name := range []string{
		"root.key",
		"transport-ca.key",
		"management-ca.key",
		"bundle-signing.key",
		// ★ NOT the interception root key. It looked like it belonged here — no start script names it — and
		// four tests said otherwise: the Edge finds it by convention as the sibling of the certificate path, so
		// it is read at runtime and moving it makes every node mint a root of its own. That an Edge holds the
		// ROOT at all is a gap the PKI document already answers with a per-tenant intermediate; it is not this
		// check's business, and pretending otherwise here would have broken interception fleet-wide.
	} {
		if _, err := os.Stat(filepath.Join(dir, authorityDirName, name)); err != nil {
			t.Fatalf("%s must live under %s/, where no container can reach it: %v", name, authorityDirName, err)
		}
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			t.Fatalf("%s is still at the top of the deployment directory, which every service mounts", name)
		}
	}

	raw, err := os.ReadFile(filepath.Join(dir, "docker-compose.yml"))
	if err != nil {
		t.Fatalf("read compose: %v", err)
	}
	// ★ NO SERVICE MOUNTS THE DIRECTORY ITSELF. A whole-directory mount reaches the authority whatever else is
	// arranged, so its absence is the assertion — checking the individual entries would pass a file that
	// happened to be listed while the parent was mounted beside it.
	if m := regexp.MustCompile(`(?m)^\s+-\s+"\./:/deployment"?`).FindString(string(raw)); m != "" {
		t.Fatalf("a service still mounts the whole deployment directory (%q) — every key in it travels with it",
			strings.TrimSpace(m))
	}
	if strings.Contains(string(raw), "/deployment/"+authorityDirName) {
		t.Fatalf("the compose file names %s/, which nothing running may reach", authorityDirName)
	}
}
