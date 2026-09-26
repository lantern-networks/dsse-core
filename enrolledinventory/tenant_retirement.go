package enrolledinventory

import (
	"errors"
	"strings"
	"time"
)

// RetireTenantChecked denies the tenant's identities while retaining their
// ownership while a purge processes the device-keyed stores. Tombstones travel in
// the config bundle and remain available to a purge retry after restart.
// A failed save keeps the restrictive live state; a repeated call resaves it.
func (l *Ledger) RetireTenantChecked(tenantID, now string) (int, error) {
	if l == nil || strings.TrimSpace(tenantID) == "" {
		return 0, nil
	}
	if _, err := time.Parse(time.RFC3339, now); err != nil {
		return 0, errors.New("invalid tenant retirement time")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.persistBlocked != nil {
		return 0, errors.New("tenant retirement unavailable: inventory restore failed")
	}
	n, changed := 0, false
	for id, e := range l.entries {
		if !strings.EqualFold(strings.TrimSpace(e.TenantID), strings.TrimSpace(tenantID)) {
			continue
		}
		n++
		if e.isTombstone() && !e.Enabled {
			continue
		}
		l.entries[id] = Entry{Identity: e.Identity, TenantID: e.TenantID, Enabled: false,
			RemovedAt: now, UpdatedAt: now, ReenrolmentNonce: e.ReenrolmentNonce}
		changed = true
	}
	if changed {
		l.generation.Add(1)
	}
	if n > 0 {
		if err := l.persistCheckedLocked(); err != nil {
			return 0, errors.New("tenant retirement saving could not be confirmed")
		}
	}
	return n, nil
}

// CountTenantRecords includes disabled identities and retained removal records.
// Admission/seat counts cannot prove that a tenant's stored data was erased.
func (l *Ledger) CountTenantRecords(tenantID string) int {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, e := range l.entries {
		if strings.EqualFold(strings.TrimSpace(e.TenantID), strings.TrimSpace(tenantID)) {
			n++
		}
	}
	return n
}
