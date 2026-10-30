package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/lantern-networks/dsse-core/dnsresolver"
)

func TestDNSPolicyCorruptionIsNotOverwrittenByBootSeed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dns.json")
	before := []byte(`{"deny":["private.example"`)
	if err := os.WriteFile(path, before, 0600); err != nil {
		t.Fatal(err)
	}
	restoreDNSPolicy(newDNSPolicyStore(path), dnsresolver.NewWithUpstream("tenant", nil, nil))
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("corrupt operator policy was destroyed by startup")
	}
}
