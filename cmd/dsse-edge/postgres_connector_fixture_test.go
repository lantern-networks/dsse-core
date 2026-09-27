package main

import (
	"crypto/tls"
	"github.com/lantern-networks/dsse-core/tenantca"
	"testing"
)

// These database integration tests still pass through the production certificate guard.
func postgresTestConnectorIdentity(t *testing.T, tenant, id string) (*tenantca.TenantCARegistry, *tls.ConnectionState) {
	t.Helper()
	dir := t.TempDir()
	ca := makeTestCA(t, dir, "Integration device CA", 87)
	reg, err := tenantca.LoadTenantCARegistry(writeRegistry(t, dir, map[string]string{tenant: ca.pemPath}))
	if err != nil {
		t.Fatal(err)
	}
	chains := leafSignedBy(t, ca, id, reg.Pool)
	if len(chains) == 0 {
		t.Fatal("connector certificate failed verification")
	}
	return reg, connectorRequestPresenting(chains).TLS
}
