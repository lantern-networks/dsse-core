package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/edgeplane"
	"github.com/lantern-networks/dsse-core/idpregistry"
)

func validAuthOwner(principal, session string) bool {
	return idpregistry.ValidOSPrincipal(principal) && idpregistry.ValidOSSession(session)
}

// Domain separation binds evidence to the device owner and login incarnation.
// The required-feature marker and modern storage key keep released readers from
// authorizing these grants; the hash alone is not a rolling-upgrade boundary.
func authEvidenceForOwner(conn idpregistry.Connection, device, principal, session string) string {
	if device == "" || principal == "" {
		return authEvidenceProviderDigest(conn)
	}
	binding, ok := conn.AssignedBinding(device, principal)
	if !ok {
		return ""
	}
	raw, _ := json.Marshal([]string{"dsse device user authorization v1", authEvidenceProviderDigest(conn), device, principal, session, binding.Revision})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func authOwnerFromAuthority(authority string) edgeplane.AuthOwner {
	_, meta, ok := strings.Cut(authority, "\x00")
	if !ok {
		return edgeplane.AuthOwner{}
	}
	var result edgeplane.AuthOwner
	seen := map[string]bool{}
	for _, part := range strings.Fields(meta) {
		key, value, _ := strings.Cut(part, "=")
		if key != "op" && key != "ls" {
			continue
		}
		if seen[key] {
			return edgeplane.AuthOwner{}
		}
		seen[key] = true
		if key == "op" {
			result.Principal = value
		} else {
			result.Session = value
		}
	}
	if !validAuthOwner(result.Principal, result.Session) {
		return edgeplane.AuthOwner{}
	}
	return result
}

// Unknown upgrade state is not permission to fall back to device-only grants.
// In particular a read failure after activation must never undo its requirement.
func (r *authRolloutRuntime) deviceUserBindingMode() (enabled, known bool) {
	if r == nil {
		return true, true
	}
	d, err := r.decisionDistribution(time.Now())
	if err != nil || d == nil || !r.isExpectedMember(d) {
		return false, false
	}
	return d.FeatureEnabled("device-user-session-v1", time.Now()), true
}
