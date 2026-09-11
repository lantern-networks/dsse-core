package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ★ A STANDBY REGION MUST NOT STAND UP A DATABASE, AND MUST STAND UP A CONTROL PLANE. Those are the two ways
// this can be wrong, and they fail in opposite directions: one makes a second deployment, the other makes a
// region that still cannot hold leadership. Both are asserted, on the same rendering.
func TestAStandbyRegionJoinsTheDatabaseAndDoesNotCreateOne(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"root.crt":                "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n",
		"deployment.env":          "ADMIN_TOKEN='x'\nDSSE_EDGE_REGION='region-a'\n",
		agentPolicySigningKeyFile: strings.Repeat("ab", 32),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := regionInstall(dir, "region-b", machineShape{holds: regionShapeStandbyCP, edges: true}); err != nil {
		t.Fatalf("preparing a standby region: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "docker-compose.yml"))
	if err != nil {
		t.Fatal(err)
	}
	compose := string(raw)

	for _, mustNot := range []string{"\n  dsse-postgres-a:", "\n  dsse-store-a:", "\n  postgres:", "\n  dsse-clickhouse:"} {
		if strings.Contains(compose, mustNot) {
			t.Fatalf("a standby region stands up %q — that is a second deployment, not a standby", strings.TrimSpace(mustNot))
		}
	}
	if !strings.Contains(compose, "\n  dsse-control-plane-a:") {
		t.Fatal("a standby region has no control plane, so leadership can never move there")
	}
	// ★ AND THE DSN HAS NO DEFAULT. A fallback to a local host is how a standby quietly becomes an authority
	// over a different database.
	if !strings.Contains(compose, "DSSE_POSTGRES_DSN: ${DSSE_POSTGRES_DSN:?") {
		t.Fatal("the standby's database is defaulted rather than required")
	}
	// The internal door for this region, with the same leader check.
	if _, err := os.Stat(filepath.Join(dir, "haproxy-standby.cfg")); err != nil {
		t.Fatalf("no internal control-plane door was written for the standby: %v", err)
	}
	door, _ := os.ReadFile(filepath.Join(dir, "haproxy-standby.cfg"))
	for _, want := range []string{"option httpchk GET /leader", "on-marked-down shutdown-sessions"} {
		if !strings.Contains(string(door), want) {
			t.Fatalf("the standby's door is missing %q", want)
		}
	}

	// And the ordinary joining region is unchanged: no control plane at all.
	plain := t.TempDir()
	for name, body := range map[string]string{
		"root.crt":                "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n",
		"deployment.env":          "ADMIN_TOKEN='x'\nDSSE_EDGE_REGION='region-a'\n",
		agentPolicySigningKeyFile: strings.Repeat("ab", 32),
	} {
		if err := os.WriteFile(filepath.Join(plain, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := regionInstall(plain, "region-c", machineShape{holds: regionShapeEdgesOnly, edges: true}); err != nil {
		t.Fatal(err)
	}
	plainCompose, _ := os.ReadFile(filepath.Join(plain, "docker-compose.yml"))
	if strings.Contains(string(plainCompose), "\n  dsse-control-plane-a:") {
		t.Fatal("an ordinary joining region now stands up a control plane")
	}
}
