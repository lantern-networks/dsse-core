package main

import "testing"

// ECH-strip must default ON (decrypt-all reachability); the env var overrides for resolver-only deployments.
// This tests the cmd/edge env glue (env var names live here, not in the OSS core).
func TestEdgeDNSResolverECHStripDefaultsOn(t *testing.T) {
	t.Setenv("DSSE_DNS_ECH_STRIP", "") // unset => default
	if !newEdgeDNSResolverFromEnv("tenant_x", nil).CurrentPolicy().ECHStripValue() {
		t.Fatalf("ECH-strip must DEFAULT ON")
	}
	t.Setenv("DSSE_DNS_ECH_STRIP", "false") // explicit opt-out
	if newEdgeDNSResolverFromEnv("tenant_x", nil).CurrentPolicy().ECHStripValue() {
		t.Fatalf("DSSE_DNS_ECH_STRIP=false must disable ECH-strip")
	}
}
