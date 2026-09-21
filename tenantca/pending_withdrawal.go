package tenantca

import "strings"

// BeginWithdrawal retains the target while the two independent writes complete.
// Receipts are process-local: a reported partial failure must be retried before restart.
func (r *TenantCARegistry) BeginWithdrawal(tenant, fingerprint string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := strings.ToLower(strings.TrimSpace(fingerprint))
	if owner, ok := r.byAnchorKey[key]; ok && strings.EqualFold(owner, tenant) {
		if r.pendingWithdrawals == nil {
			r.pendingWithdrawals = map[string]string{}
		}
		r.pendingWithdrawals[key] = owner
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
		}
	}
}
