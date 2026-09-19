package enrolledinventory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"strings"
)

// ErrInventorySave hides storage details and does not promise that an uncertain
// commit was rolled back. Callers must reload before retrying.
var ErrInventorySave = errors.New("enrolled inventory saving could not be confirmed; reload and retry when storage and write authority are available")

// mutateShared runs existing ledger rules against a private copy of the latest
// locked row. No callbacks or identity claims may be performed by edit. The
// published ledger changes only after commit. File callers keep their contracts.
func (l *Ledger) mutateShared(ctx context.Context, edit func(*Ledger) error) (bool, error) {
	l.mu.Lock()
	p, shared := l.persister.(contextUpdater)
	if !shared {
		l.mu.Unlock()
		return false, edit(l)
	}
	defer l.mu.Unlock()
	if l.persistBlocked != nil {
		return true, ErrInventorySave
	}
	var candidate *Ledger
	var ruleErr error
	err := p.UpdateContext(ctx, func(raw []byte) ([]byte, error) {
		candidate = NewLedger()
		if raw == nil {
			if l.snapshotKnown {
				return nil, ErrInventoryLoad
			}
			candidate.entries = maps.Clone(l.entries)
			candidate.groups = maps.Clone(l.groups)
		} else {
			f, err := decodeInventorySnapshot(raw)
			if err != nil {
				return nil, err
			}
			candidate.entries, candidate.groups = f.Entries, f.Groups
		}
		// The clone has no persister or shared claimer: edit is a local calculation.
		if ruleErr = edit(candidate); ruleErr != nil {
			return nil, ruleErr
		}
		return json.Marshal(stateFile{SchemaVersion: enrolledInventoryStateSchemaVersion, Entries: candidate.entries, Groups: candidate.groups})
	})
	if ruleErr != nil {
		return true, ruleErr
	}
	if err != nil {
		return true, ErrInventorySave
	}
	l.entries, l.groups = candidate.entries, candidate.groups
	l.snapshotKnown = true
	l.generation.Add(1)
	return true, nil
}

func ownedEntry(l *Ledger, id, tenant string) error {
	e, ok := l.EntryFor(id)
	if !ok || (strings.TrimSpace(tenant) != "" && !sameGroupTenant(e.TenantID, tenant)) {
		return ErrIdentityNotFound
	}
	return nil
}
func ownedGroup(l *Ledger, id, tenant string) (Group, error) {
	g, ok := l.GroupByID(id)
	if !ok || (strings.TrimSpace(tenant) != "" && !sameGroupTenant(g.TenantID, tenant)) {
		return Group{}, ErrIdentityNotFound
	}
	return g, nil
}

func (l *Ledger) EnrollGroupForTenantContext(ctx context.Context, id, claimant, assignTo, group, note, now string, adopt bool) (entry Entry, err error) {
	shared, err := l.mutateShared(ctx, func(c *Ledger) error {
		var e error
		entry, e = c.EnrollGroupForTenant(id, claimant, assignTo, group, note, now, adopt)
		return e
	})
	if shared && err != nil {
		entry = Entry{}
	}
	return entry, err
}
func (l *Ledger) AllowReenrolmentContext(ctx context.Context, id, tenant, now string) (entry, before Entry, err error) {
	shared, err := l.mutateShared(ctx, func(c *Ledger) error { var e error; entry, before, e = c.AllowReenrolment(id, tenant, now); return e })
	if shared && err != nil {
		entry, before = Entry{}, Entry{}
	}
	return entry, before, err
}
func (l *Ledger) SetGroupContext(ctx context.Context, id, tenant, group, now string) (entry Entry, ok bool, err error) {
	shared, err := l.mutateShared(ctx, func(c *Ledger) error {
		if e := ownedEntry(c, id, tenant); e != nil {
			return e
		}
		var e error
		entry, ok, e = c.SetGroup(id, group, now)
		if !ok && e == nil {
			return ErrIdentityNotFound
		}
		return e
	})
	if shared && err != nil {
		entry, ok = Entry{}, false
	}
	return entry, ok, err
}
func (l *Ledger) SetKindContext(ctx context.Context, id, tenant, kind, now string) (entry Entry, ok bool, err error) {
	shared, err := l.mutateShared(ctx, func(c *Ledger) error {
		if e := ownedEntry(c, id, tenant); e != nil {
			return e
		}
		var e error
		entry, ok, e = c.SetKind(id, kind, now)
		return e
	})
	if shared && err != nil {
		entry, ok = Entry{}, false
	}
	return entry, ok, err
}
func (l *Ledger) RemoveCheckedContext(ctx context.Context, id, tenant, now string) (entry Entry, err error) {
	shared, err := l.mutateShared(ctx, func(c *Ledger) error {
		if e := ownedEntry(c, id, tenant); e != nil {
			return e
		}
		var e error
		entry, e = c.RemoveChecked(id, now)
		return e
	})
	if shared && err != nil {
		entry = Entry{}
	}
	return entry, err
}
func (l *Ledger) RecordReportedMachineContext(ctx context.Context, id, tenant, ref, now string) error {
	_, err := l.mutateShared(ctx, func(c *Ledger) error {
		if e := ownedEntry(c, id, tenant); e != nil {
			return e
		}
		return c.RecordReportedMachine(id, ref, now)
	})
	return err
}
func (l *Ledger) CreateGroupContext(ctx context.Context, name, tenant, description, risk, now string) (group Group, err error) {
	shared, err := l.mutateShared(ctx, func(c *Ledger) error {
		var e error
		group, e = c.CreateGroup(name, tenant, description, risk, now)
		return e
	})
	if shared && err != nil {
		group = Group{}
	}
	return group, err
}
func (l *Ledger) UpdateGroupContext(ctx context.Context, id, tenant string, name, description, risk *string, now string) (group Group, reassigned int, err error) {
	shared, err := l.mutateShared(ctx, func(c *Ledger) error {
		if _, e := ownedGroup(c, id, tenant); e != nil {
			return e
		}
		var e error
		group, reassigned, e = c.UpdateGroup(id, name, description, risk, now)
		return e
	})
	if shared && err != nil {
		group, reassigned = Group{}, 0
	}
	return group, reassigned, err
}

var ErrGroupAssigned = errors.New("device group still has assigned devices")

func (l *Ledger) DeleteGroupContext(ctx context.Context, id, tenant string, force bool) (removed bool, group Group, err error) {
	shared, err := l.mutateShared(ctx, func(c *Ledger) error {
		var e error
		group, e = ownedGroup(c, id, tenant)
		if e != nil {
			return e
		}
		if !force {
			for _, entry := range c.List() {
				if sameGroupTenant(entry.TenantID, group.TenantID) && NormalizeGroupName(entry.Group) == NormalizeGroupName(group.Name) {
					return fmt.Errorf("%w; reassign them first or use force", ErrGroupAssigned)
				}
			}
		}
		removed, e = c.DeleteGroup(id)
		return e
	})
	if shared && err != nil {
		removed = false
	}
	return removed, group, err
}
