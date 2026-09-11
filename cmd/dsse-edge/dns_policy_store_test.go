package main

import (
	"os"
	"path/filepath"
	"testing"

	dnsresolver "github.com/lantern-networks/dsse-core/dnsresolver"
)

// A DNS rule an operator wrote must survive a restart.
//
// It did not. The policy lived only in the resolver's live pointer, so a rule written through the admin API
// was reverted by the next restart and the deployment silently returned to its boot environment. On
// 2026-07-30 that dropped the stub making an internal name resolve, and what reached a person was a browser
// reporting no internet — an experience with nothing in it that points at a DNS rule ceasing to exist.
func TestDNSPolicySurvivesARestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dns_policy.json")

	// First boot: nothing stored, so the environment's policy is seeded.
	booted := dnsresolver.NewWithUpstream("t", nil, nil)
	seed, err := dnsresolver.PolicyFromDTO(dnsresolver.PolicyDTO{StubIPv4: map[string]string{"app.corp": "100.64.0.9"}})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	booted.SetPolicy(seed)
	store := newDNSPolicyStore(path)
	if line := restoreDNSPolicy(store, booted); line == "" {
		t.Fatalf("the first boot should seed the store and say so")
	}

	// An operator adds a rule.
	authored, err := dnsresolver.PolicyFromDTO(dnsresolver.PolicyDTO{
		StubIPv4: map[string]string{"app.corp": "100.64.0.9", "wiki.corp": "100.64.0.10"},
		Deny:     []string{"bad.example"},
	})
	if err != nil {
		t.Fatalf("authored: %v", err)
	}
	booted.SetPolicy(authored)
	if err := store.save(dnsresolver.PolicyToDTO(authored)); err != nil {
		t.Fatalf("save: %v", err)
	}

	// Restart: a fresh resolver built from an environment that knows nothing about the operator's change.
	restarted := dnsresolver.NewWithUpstream("t", nil, nil)
	restarted.SetPolicy(seed)
	if line := restoreDNSPolicy(store, restarted); line == "" {
		t.Fatalf("the stored policy should have been restored")
	}
	got := dnsresolver.PolicyToDTO(restarted.CurrentPolicy())
	if got.StubIPv4["wiki.corp"] != "100.64.0.10" {
		t.Fatalf("the operator's rule did not survive the restart: %+v", got.StubIPv4)
	}
	if len(got.Deny) != 1 || got.Deny[0] != "bad.example" {
		t.Fatalf("the operator's deny rule did not survive the restart: %+v", got.Deny)
	}
}

// The stored policy wins over the boot environment, which is the whole point: anything else means a restart
// reverts an administrator's change, and that is the bug rather than a safety net.
func TestStoredDNSPolicyBeatsTheBootEnvironment(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dns_policy.json")
	store := newDNSPolicyStore(path)
	stored, _ := dnsresolver.PolicyFromDTO(dnsresolver.PolicyDTO{StubIPv4: map[string]string{"authored.corp": "100.64.0.20"}})
	if err := store.save(dnsresolver.PolicyToDTO(stored)); err != nil {
		t.Fatalf("save: %v", err)
	}

	resolver := dnsresolver.NewWithUpstream("t", nil, nil)
	boot, _ := dnsresolver.PolicyFromDTO(dnsresolver.PolicyDTO{StubIPv4: map[string]string{"from-env.corp": "100.64.0.99"}})
	resolver.SetPolicy(boot)
	restoreDNSPolicy(store, resolver)

	got := dnsresolver.PolicyToDTO(resolver.CurrentPolicy())
	if got.StubIPv4["authored.corp"] == "" {
		t.Fatalf("the stored policy was not applied: %+v", got.StubIPv4)
	}
	if got.StubIPv4["from-env.corp"] != "" {
		t.Fatalf("the boot environment overrode the stored policy — a restart would revert an operator's change")
	}
}

// An unreadable store must not take the datapath down. Falling back to the boot configuration is recoverable;
// refusing to start over a corrupt DNS file is an outage for a fixable problem.
func TestCorruptDNSPolicyStoreFallsBackToBoot(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dns_policy.json")
	if err := writeFileForTest(path, "{not json"); err != nil {
		t.Fatalf("write: %v", err)
	}
	resolver := dnsresolver.NewWithUpstream("t", nil, nil)
	boot, _ := dnsresolver.PolicyFromDTO(dnsresolver.PolicyDTO{StubIPv4: map[string]string{"app.corp": "100.64.0.9"}})
	resolver.SetPolicy(boot)

	restoreDNSPolicy(newDNSPolicyStore(path), resolver)
	if dnsresolver.PolicyToDTO(resolver.CurrentPolicy()).StubIPv4["app.corp"] != "100.64.0.9" {
		t.Fatalf("a corrupt store discarded the boot policy")
	}
}

func writeFileForTest(path, body string) error {
	return os.WriteFile(path, []byte(body), 0o600)
}
