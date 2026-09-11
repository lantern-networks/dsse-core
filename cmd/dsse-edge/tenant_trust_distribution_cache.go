package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/lantern-networks/dsse-core/agentpolicy"
)

// The cache is hydrated before an Edge serves TLS. It never signs a replacement
// envelope, and retains its last verified answer if the control plane is down.
// restart-durability: cp_durable — the control plane persists the envelopes;
// an Edge hydrates this cache synchronously before serving TLS.
// populated-by: hydrated — every authenticated material poll carries the current set.
type tenantTrustDistributionCache struct {
	mu    sync.RWMutex
	keys  []string
	items map[string]tenantTrustDistribution
}

func (c *tenantTrustDistributionCache) For(tenant string) (agentpolicy.Envelope, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	item, ok := c.items[tenant]
	return item.Envelope, ok
}
func (c *tenantTrustDistributionCache) Validate(items map[string]tenantTrustDistribution) error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.validateLocked(items)
}
func (c *tenantTrustDistributionCache) validateLocked(items map[string]tenantTrustDistribution) error {
	if items == nil {
		return fmt.Errorf("control plane omitted canonical tenant trust distributions")
	}
	for tenant, item := range items {
		p, err := agentpolicy.VerifyTrustBundleWithKeys(item.Envelope, c.keys, 0)
		if err != nil {
			return fmt.Errorf("tenant %s trust signature: %w", tenant, err)
		}
		if p.TenantID != tenant || strings.TrimSpace(tenant) == "" {
			return fmt.Errorf("tenant trust distribution identity mismatch")
		}
		if err := validateRecoveryIntroduction(item, p); err != nil {
			return err
		}
		if item.ActivateIncoming != "" {
			fps, _ := p.Fingerprints()
			found := false
			for _, fp := range fps {
				if fp == item.ActivateIncoming {
					found = true
				}
			}
			if !found {
				return fmt.Errorf("activation names an unannounced authority")
			}
		}
		if previous, ok := c.items[tenant]; ok {
			held, err := agentpolicy.VerifyTrustBundleWithKeys(previous.Envelope, c.keys, 0)
			if err != nil {
				return err
			}
			if sameRecoveryName(p.RenewalRecoverySNI, held.RenewalRecoverySNI) && item.RecoveryNameSince != previous.RecoveryNameSince && item.RecoveryNameSince <= held.Serial {
				return fmt.Errorf("recovery introduction rewrote previously published history")
			}
			if !sameRecoveryName(p.RenewalRecoverySNI, held.RenewalRecoverySNI) && item.RecoveryNameSince != 0 && item.RecoveryNameSince <= held.Serial {
				return fmt.Errorf("new recovery name predates the held distribution")
			}
			if p.Serial < held.Serial {
				return fmt.Errorf("tenant trust distribution rollback: %d below %d", p.Serial, held.Serial)
			}
			if p.Serial == held.Serial {
				a, _ := json.Marshal(p)
				b, _ := json.Marshal(held)
				if !bytes.Equal(a, b) {
					return fmt.Errorf("tenant trust distribution changed at the same serial")
				}
			}
		}
	}
	return nil
}
func (c *tenantTrustDistributionCache) Adopt(items map[string]tenantTrustDistribution) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.validateLocked(items); err != nil {
		return err
	}
	next := make(map[string]tenantTrustDistribution, len(items))
	for tenant, item := range items {
		next[tenant] = item
	}
	c.items = next
	for tenant, item := range items {
		if item.ActivateIncoming != "" && item.ActivateIncoming == transportTenantCertificates.PendingFingerprintFor(tenant) {
			transportTenantCertificates.PromotePending(tenant)
		}
	}
	return nil
}
