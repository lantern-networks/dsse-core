package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ★ THE GUARD FIRST. The failure this prevents is silent — Edges keep serving and simply stop pulling — so
// the test asserts the BAD outcome is impossible by first proving the placeholder IS written when there is no
// answer, and then that a second run does not overwrite one.
func TestRegionDoesNotOverwriteTheOperatorsControlPlaneAddress(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "deployment.env")
	if err := os.WriteFile(path, []byte("ADMIN_TOKEN='x'\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// First pass: nothing answered, so the placeholder must appear — otherwise this test would pass on a
	// build that never writes anything at all.
	if err := setRegionEnvironment(dir, "region-b", false, false); err != nil {
		t.Fatal(err)
	}
	if body, _ := os.ReadFile(path); !strings.Contains(string(body), placeholderHost) {
		t.Fatalf("the placeholder was not written on a fresh region:\n%s", body)
	}

	// The operator answers it.
	body, _ := os.ReadFile(path)
	answered := strings.ReplaceAll(string(body),
		"https://admin."+placeholderHost, "https://admin.example.test")
	answered = strings.ReplaceAll(answered,
		"https://authority."+placeholderHost, "https://authority.example.test")
	if err := os.WriteFile(path, []byte(answered), 0o600); err != nil {
		t.Fatal(err)
	}

	// Second pass — a rename, or a re-carried directory. Their answer must survive.
	if err := setRegionEnvironment(dir, "region-c", false, false); err != nil {
		t.Fatal(err)
	}
	final, _ := os.ReadFile(path)
	if strings.Contains(string(final), placeholderHost) {
		t.Fatalf("running -region again put the placeholder back over the operator's address:\n%s", final)
	}
	for _, want := range []string{"https://admin.example.test", "https://authority.example.test"} {
		if !strings.Contains(string(final), want) {
			t.Fatalf("the operator's %s did not survive:\n%s", want, final)
		}
	}
	// And the values that ARE this installer's to decide still moved with the new region name.
	if !strings.Contains(string(final), "DSSE_EDGE_REGION='region-c'") {
		t.Fatalf("the region name did not move:\n%s", final)
	}
}

// ★★★ TWO REGIONS ON ONE HOST MUST NOT COLLIDE (2026-08-26, found by bringing the second one up):
//
//	Bind for 0.0.0.0:19543 failed: port is already allocated
//
// This command already derives per-region subnets, front-door addresses and compose project names precisely
// because two regions may share a host. The published ports were the one thing left identical, so the second
// region created its containers and then failed on the first one that binds.
func TestASecondRegionDoesNotBindTheFirstRegionsPorts(t *testing.T) {
	// ★★★ EVERY PORT A MACHINE PUBLISHES, AND ONLY THOSE (2026-09-05). This listed seven, four of which
	// nothing bound — so the test passed by comparing values that could not collide because neither existed —
	// while the AGENT port, published on every Edge machine since 2026-09-03, was absent from both the list
	// and the offsetting, and two regions on one host really did collide on it.
	published := []string{
		"DSSE_REGION_PORT", "DSSE_EDGE_AGENT_PORT", "DSSE_EDGE_ADMIN_PORT",
	}
	read := func(region string) map[string]string {
		t.Helper()
		dir := t.TempDir()
		if err := writeEnvironment(dir, []string{"localhost"}, nil); err != nil {
			t.Fatal(err)
		}
		if err := setRegionEnvironment(dir, region, true, false); err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(filepath.Join(dir, "deployment.env"))
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]string{}
		for _, line := range strings.Split(string(raw), "\n") {
			if name, value, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
				out[strings.TrimSpace(name)] = strings.Trim(value, "'\"")
			}
		}
		return out
	}

	b, c := read("region-b"), read("region-c")
	// region-a's numbers are the single-region defaults and must not move: they are what an operator already
	// wrote down for the deployment they have.
	a := read("region-a")
	for _, key := range published {
		if b[key] == "" || c[key] == "" {
			t.Fatalf("%s is not set for a joining region, so it falls back to the first region's port", key)
		}
		if b[key] == c[key] {
			t.Fatalf("region-b and region-c both publish %s on %s", key, b[key])
		}
		if a[key] != "" && (b[key] == a[key] || c[key] == a[key]) {
			t.Fatalf("a joining region publishes %s on the first region's port %s", key, a[key])
		}
	}
}
