package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ★★★ TWO MEMBERS WITH ONE NAME IS NOT REDUNDANCY (2026-08-27, found while making a joining region hold state).
//
// Patroni identifies cluster members by name, and every region is rendered from the same file — so a second
// region would call its members dsse-postgres-a and dsse-postgres-b, exactly as the first one does. The result
// is not two copies of the state; it is two machines each taking the other's for its own.
func TestPatroniMembersDoNotShareANameAcrossRegions(t *testing.T) {
	founding := t.TempDir()
	if err := run(founding, "the-deployment.example", "Example", 3, false); err != nil {
		t.Fatalf("mint: %v", err)
	}
	joining := t.TempDir()
	copyDeploymentForTest(t, founding, joining)
	if err := regionInstall(joining, "region-b", machineShape{holds: regionShapeStateBearingJoin, edges: true}); err != nil {
		t.Fatalf("region: %v", err)
	}

	a := envValue(t, filepath.Join(founding, "deployment.env"), "DSSE_PG_A_NAME")
	b := envValue(t, filepath.Join(joining, "deployment.env"), "DSSE_PG_A_NAME")
	if b == "" {
		t.Fatal("the joining region names no Patroni member, so it takes the default — which is the name the " +
			"founding region's member already answers to")
	}
	if a == b {
		t.Fatalf("both regions call their first database member %q; a Patroni cluster cannot tell them apart", a)
	}
	if !strings.Contains(b, "region-b") {
		t.Fatalf("the joining region's member name %q does not say which region it is — which is the one thing "+
			"somebody reading pg_stat_replication needs it to say", b)
	}
}

func copyDeploymentForTest(t *testing.T, from, to string) {
	t.Helper()
	entries, err := os.ReadDir(from)
	if err != nil {
		t.Fatalf("read %s: %v", from, err)
	}
	for _, e := range entries {
		src, dst := filepath.Join(from, e.Name()), filepath.Join(to, e.Name())
		if e.IsDir() {
			if err := os.MkdirAll(dst, 0o700); err != nil {
				t.Fatal(err)
			}
			copyDeploymentForTest(t, src, dst)
			continue
		}
		body, err := os.ReadFile(src)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dst, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func envValue(t *testing.T, path, key string) string {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, key+"=") {
			return strings.Trim(strings.TrimPrefix(line, key+"="), "'\"")
		}
	}
	return ""
}
