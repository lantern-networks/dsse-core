package enrolledinventory

import (
	"context"
	"log"
	"strings"
)

// RemoveTenantContext removes the tenant from the latest shared row. Claims are
// released only after a confirmed commit and outside the ledger/storage locks.
func (l *Ledger) RemoveTenantContext(ctx context.Context, tenant string) (ids []string, err error) {
	tenant = strings.TrimSpace(tenant)
	if tenant == "" {
		return nil, nil
	}
	removed := map[string]Entry{}
	shared, err := l.mutateShared(ctx, func(c *Ledger) error {
		for _, e := range c.Authoritative() {
			if strings.EqualFold(strings.TrimSpace(e.TenantID), tenant) {
				removed[e.Identity] = e
			}
		}
		var err error
		ids, err = c.RemoveTenantChecked(tenant)
		return err
	})
	if err != nil {
		return nil, err
	}
	if !shared {
		return ids, nil
	} // file implementation already released its claims
	l.mu.Lock()
	claimer := l.claimer
	l.mu.Unlock()
	if claimer != nil {
		for _, id := range ids {
			if err := claimer.ReleaseIdentity(context.Background(), tenant, id, removed[id].ReenrolmentNonce); err != nil {
				log.Printf("enrolled_inventory: committed tenant erasure could not release identity claim %q: %v", id, err)
			}
		}
	}
	return ids, nil
}

// RetireTenantContext carries retirement through the latest shared row. An
// authorized but unconfirmed save keeps a restrictive local tombstone, while a
// refusal before the update callback changes nothing.
func (l *Ledger) RetireTenantContext(ctx context.Context, tenant, now string) (n int, err error) {
	if l == nil || strings.TrimSpace(tenant) == "" {
		return 0, nil
	}
	var retired []Entry
	shared, err := l.mutateShared(ctx, func(c *Ledger) error {
		var err error
		n, err = c.RetireTenantChecked(tenant, now)
		if err == nil {
			for _, e := range c.Authoritative() {
				if strings.EqualFold(strings.TrimSpace(e.TenantID), strings.TrimSpace(tenant)) {
					retired = append(retired, e)
				}
			}
		}
		return err
	})
	if shared && err != nil {
		l.mu.Lock()
		changed := false
		for _, e := range retired {
			current, ok := l.entries[e.Identity]
			if ok && strings.EqualFold(current.TenantID, e.TenantID) && current.ReenrolmentNonce == e.ReenrolmentNonce && (!current.isTombstone() || current.Enabled) {
				l.entries[e.Identity] = e
				changed = true
			}
		}
		if changed {
			l.generation.Add(1)
		}
		l.mu.Unlock()
		return 0, err
	}
	return n, err
}
