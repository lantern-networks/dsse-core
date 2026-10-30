package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/lantern-networks/dsse-core/idpregistry"
)

// Bind evidence to the provider's identity/claim interpretation, not merely its
// reusable registry ID. Exclude secrets (no password verifier in a grant) and
// labels; rotating a client secret does not change an authenticated identity.
// CA, endpoints, domain constraints and claim mappings remain bound: changing
// who may assert an identity is not a cosmetic edit. Such changes require new
// evidence even when an operator intended only a routine provider migration.
func authEvidenceProviderDigest(conn idpregistry.Connection) string {
	conn = conn.Redacted()
	conn.DisplayName = ""
	conn.DeviceUserBindings = nil
	raw, _ := json.Marshal(conn)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
