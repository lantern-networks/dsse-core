package tenantca

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// BeginWithdrawal retains the target while the two independent writes complete.
// File authors persist an intent before removing attribution; shared weak backends
// still require reconciliation before restart.
func (r *TenantCARegistry) BeginWithdrawal(tenant, fingerprint string) {
	r.beginWithdrawal(tenant, fingerprint, false)
}

// BeginTrustWithdrawal also requires removing the anchor from device trust.
func (r *TenantCARegistry) BeginTrustWithdrawal(tenant, fingerprint string) {
	r.beginWithdrawal(tenant, fingerprint, true)
}

func (r *TenantCARegistry) beginWithdrawal(tenant, fingerprint string, trustRequired bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := strings.ToLower(strings.TrimSpace(fingerprint))
	if owner, ok := r.byAnchorKey[key]; ok && strings.EqualFold(owner, tenant) {
		if r.pendingWithdrawals == nil {
			r.pendingWithdrawals = map[string]string{}
		}
		r.pendingWithdrawals[key] = owner
		if trustRequired {
			if r.pendingTrustWithdrawals == nil {
				r.pendingTrustWithdrawals = map[string]bool{}
			}
			r.pendingTrustWithdrawals[key] = true
		}
	}
}

func (r *TenantCARegistry) PendingWithdrawals(tenant string) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := []string{}
	for key, owner := range r.pendingWithdrawals {
		if tenant == "" || strings.EqualFold(owner, tenant) {
			out = append(out, key)
		}
	}
	return out
}

func (r *TenantCARegistry) CompleteWithdrawal(tenant string, fingerprints ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, key := range fingerprints {
		key = strings.ToLower(strings.TrimSpace(key))
		if strings.EqualFold(r.pendingWithdrawals[key], tenant) {
			delete(r.pendingWithdrawals, key)
			delete(r.pendingTrustWithdrawals, key)
		}
	}
}

// WithdrawalRetryAllowed keeps a different mutation from forgetting a partial
// trust withdrawal. Tenant-wide removal only changes attribution and therefore
// cannot finish an anchor withdrawal that must also remove device trust.
func (r *TenantCARegistry) WithdrawalRetryAllowed(tenant, fingerprint string, whole bool) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for key, owner := range r.pendingWithdrawals {
		if !strings.EqualFold(owner, tenant) {
			return false
		}
		if whole {
			if r.pendingTrustWithdrawals[key] {
				return false
			}
		} else if !r.pendingTrustWithdrawals[key] || !strings.EqualFold(key, fingerprint) {
			return false
		}
	}
	return true
}

// Only the withdrawal caller that completed its preceding stage may persist
// removal of a pending target. Ordinary saves must retain the old durable view.
func (r *TenantCARegistry) checkWithdrawalSaveLocked(removed []string) error {
	allowed := map[string]bool{}
	for _, key := range removed {
		allowed[strings.ToLower(strings.TrimSpace(key))] = true
	}
	for key := range r.pendingWithdrawals {
		if !allowed[key] {
			return fmt.Errorf("unfinished CA withdrawal: retry the original removal before saving other changes")
		}
	}
	return nil
}

// WithdrawalReceipt is a startup interlock, not an instruction to guess or replay
// trust-store writes. A pending file must be reconciled before serving devices.
type WithdrawalReceipt struct {
	TenantID      string `json:"tenant_id"`
	Fingerprint   string `json:"fingerprint"`
	TrustRequired bool   `json:"trust_required"`
}

var ErrPendingWithdrawal = errors.New("tenant CA withdrawal is unfinished; keep device serving stopped and reconcile the saved registry and trust store before startup")

// SavePendingWithdrawals writes an intent before either side of a file-backed
// withdrawal is changed. Its caller serializes all administrative CA writes.
// Successful final SaveWithdrawals replaces the intent with the completed view.
func (r *TenantCARegistry) SavePendingWithdrawals(path string) error {
	if r == nil || strings.TrimSpace(path) == "" {
		return fmt.Errorf("no tenant CA registry file is configured")
	}
	r.mu.RLock()
	doc := r.registryFileLocked()
	for key, owner := range r.pendingWithdrawals {
		doc.PendingWithdrawals = append(doc.PendingWithdrawals, WithdrawalReceipt{TenantID: owner, Fingerprint: key, TrustRequired: r.pendingTrustWithdrawals[key]})
	}
	r.mu.RUnlock()
	if len(doc.PendingWithdrawals) == 0 {
		return nil
	}
	sort.Slice(doc.PendingWithdrawals, func(i, j int) bool {
		return doc.PendingWithdrawals[i].Fingerprint < doc.PendingWithdrawals[j].Fingerprint
	})
	sort.Slice(doc.Tenants, func(i, j int) bool { return doc.Tenants[i].TenantID < doc.Tenants[j].TenantID })
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return writeRegistryFile(strings.TrimSpace(path), data)
}
