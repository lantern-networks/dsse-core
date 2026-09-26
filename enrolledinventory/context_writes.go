package enrolledinventory

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
)

type contextUpdater interface {
	UpdateContext(context.Context, func([]byte) ([]byte, error)) error
}

// SetEnabledContext preserves other entries/groups and rechecks ownership in
// the locked shared snapshot. The caller's authority is validated by storage.
func (l *Ledger) SetEnabledContext(ctx context.Context, id, tenant string, enabled bool, now string) (Entry, error) {
	l.mu.Lock()
	p, ok := l.persister.(contextUpdater)
	if !ok {
		l.mu.Unlock()
		entry, exists, err := l.setEnabledForTenant(id, tenant, enabled, now)
		if err != nil {
			return Entry{}, err
		}
		if !exists {
			return Entry{}, ErrIdentityNotFound
		}
		return entry, nil
	}
	defer l.mu.Unlock()
	if l.persistBlocked != nil {
		return Entry{}, ErrInventoryLoad
	}
	var candidate stateFile
	var entry Entry
	var absent bool
	err := p.UpdateContext(ctx, func(raw []byte) ([]byte, error) {
		if raw == nil {
			return nil, ErrInventoryLoad
		}
		var err error
		candidate, err = decodeInventorySnapshot(raw)
		if err != nil {
			return nil, err
		}
		key := NormalizeIdentity(id)
		var exists bool
		entry, exists = candidate.Entries[key]
		tenant = strings.TrimSpace(tenant)
		if !exists || entry.isTombstone() || (tenant != "" && !strings.EqualFold(strings.TrimSpace(entry.TenantID), tenant)) {
			absent = true
			return nil, ErrIdentityNotFound
		}
		entry.Enabled = enabled
		entry.UpdatedAt = now
		candidate.Entries[key] = entry
		candidate.SchemaVersion = enrolledInventoryStateSchemaVersion
		return json.Marshal(candidate)
	})
	if err != nil {
		if absent {
			return Entry{}, ErrIdentityNotFound
		}
		return Entry{}, errors.New("enrolled inventory save was not confirmed")
	}
	l.entries, l.groups = candidate.Entries, candidate.Groups
	l.snapshotKnown = true
	l.generation.Add(1)
	return entry, nil
}
