package main

import (
	"fmt"
	"strings"

	"github.com/lantern-networks/dsse-core/agentpolicy"
	"github.com/lantern-networks/dsse-core/blobstore"
)

func sameRecoveryName(a, b string) bool {
	return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}

// The introduction accompanies the signed envelope over the authenticated
// CP-to-Edge material channel; its name and tenant are those of that envelope.
func validateRecoveryIntroduction(item tenantTrustDistribution, p agentpolicy.TrustBundlePayload) error {
	if item.RecoveryNameSince < 0 || item.RecoveryNameSince > p.Serial ||
		(item.RecoveryNameSince != 0 && strings.TrimSpace(p.RenewalRecoverySNI) == "") {
		return fmt.Errorf("invalid canonical recovery introduction")
	}
	return nil
}

// Reads the already-published record without issuing a revision. An Edge uses
// only its adopted cache; it cannot bypass a failed material adoption by reading
// a newer CP row. A CP reads the durable record. Missing or invalid evidence is
// unknown (zero), including older records written before this metadata existed.
func canonicalRecoveryNameSince(cache *tenantTrustDistributionCache, store blobstore.Persister, keys []string, tenant, name string) int64 {
	var item tenantTrustDistribution
	if cache != nil {
		cache.mu.RLock()
		item = cache.items[tenant]
		keys = append([]string(nil), cache.keys...)
		cache.mu.RUnlock()
	} else if store != nil {
		raw, err := store.Load()
		if err != nil {
			return 0
		}
		state, err := decodeTenantTrustDistributions(raw)
		if err != nil {
			return 0
		}
		item = state.Tenants[tenant].Distribution
		p, err := agentpolicy.VerifyTrustBundleWithKeys(item.Envelope, keys, 0)
		if err != nil || p.Serial > state.SerialFloor {
			return 0
		}
	}
	p, err := agentpolicy.VerifyTrustBundleWithKeys(item.Envelope, keys, 0)
	if err != nil || p.TenantID != tenant || strings.TrimSpace(name) == "" ||
		!sameRecoveryName(p.RenewalRecoverySNI, name) || validateRecoveryIntroduction(item, p) != nil {
		return 0
	}
	return item.RecoveryNameSince
}
