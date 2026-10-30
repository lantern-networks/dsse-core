package main

import (
	"fmt"
	"strings"
)

// A bundle receiver must not open the CP's shared state database. Bundle
// snapshots can lag behind authoring, and receiver imports do not carry a CP
// write lease. Allowing both roles would let an older bundle replace authority.
// Check before opening the database, including when only failover endpoints
// are configured. Per-store overrides are not an exemption: imports and newly
// added stores must remain unable to acquire a shared authority backend.
func validateConfigReceiverAuthority(postgresDSN, sourceURL, sourceEndpoints string) error {
	// Authority separation follows the declared receiver role, even when a
	// malformed endpoint list cannot be parsed into a usable control plane.
	// Endpoint validation is a separate startup gate and must not turn an
	// invalid declaration into permission to open shared CP state.
	if strings.TrimSpace(postgresDSN) != "" &&
		(strings.TrimSpace(sourceURL) != "" || strings.TrimSpace(sourceEndpoints) != "") {
		return fmt.Errorf("-postgres-dsn cannot be combined with -config-source-url or -config-source-endpoints: a config bundle receiver must use node-local stores; remove -postgres-dsn from the receiving Edge and keep shared authority on the control plane")
	}
	return nil
}
