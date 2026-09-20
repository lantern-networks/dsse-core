package idpregistry

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/lantern-networks/dsse-core/blobstore"
	"reflect"
	"sort"
)

type contextUpdater interface {
	UpdateContext(context.Context, func([]byte) ([]byte, error)) error
}
type updater interface {
	Update(func([]byte) ([]byte, error)) error
}

func isShared(p blobstore.Persister) bool {
	switch p.(type) {
	case contextUpdater, updater:
		return true
	}
	return false
}
func decodeRegistry(raw []byte) (persistedRegistry, error) {
	var next persistedRegistry
	if err := json.Unmarshal(raw, &next); err != nil {
		return next, err
	}
	if next.Connections == nil || next.Defaults == nil {
		return next, fmt.Errorf("incomplete identity provider snapshot")
	}
	for tenant, rows := range next.Connections {
		for id, c := range rows {
			if c.TenantID != tenant || c.IdPID != id || tenant == "" || id == "" {
				return next, fmt.Errorf("identity provider key mismatch")
			}
		}
	}
	for tenant, id := range next.Defaults {
		if _, ok := next.Connections[tenant][id]; !ok {
			return next, fmt.Errorf("identity provider default is absent")
		}
	}
	return next, nil
}
func (s *Store) publishLocked(next persistedRegistry) {
	if !reflect.DeepEqual(s.connections, next.Connections) || !reflect.DeepEqual(s.defaults, next.Defaults) {
		s.generation++
	}
	s.connections, s.defaults = next.Connections, next.Defaults
}

// edit applies the existing validation to an isolated candidate built from the locked shared row.
func (s *Store) edit(ctx context.Context, change func(*Store) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ctx == nil {
		ctx = context.Background()
	}
	if ctx.Err() != nil {
		return ErrPersistence
	}
	next := s.snapshotLocked()
	var domainErr error
	build := func(raw []byte) ([]byte, error) {
		if raw == nil {
			if s.authorityKnown {
				return nil, ErrPersistence
			}
		} else {
			var err error
			next, err = decodeRegistry(raw)
			if err != nil {
				return nil, err
			}
			s.authorityKnown = true
		}
		candidate := &Store{connections: next.Connections, defaults: next.Defaults}
		if err := change(candidate); err != nil {
			domainErr = err
			return nil, err
		}
		next = candidate.snapshotLocked()
		return json.Marshal(next)
	}
	var err error
	switch p := s.persister.(type) {
	case contextUpdater:
		err = p.UpdateContext(ctx, build)
	case updater:
		err = p.Update(build)
	default:
		candidate := &Store{connections: next.Connections, defaults: next.Defaults}
		if err = change(candidate); err != nil {
			return err
		}
		next = candidate.snapshotLocked()
		err = s.saveLocked(next)
	}
	if err != nil {
		if domainErr != nil {
			return domainErr
		}
		return ErrPersistence
	}
	s.publishLocked(next)
	if s.persister != nil {
		s.authorityKnown = true
	}
	return nil
}
func (s *Store) RefreshShared() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !isShared(s.persister) {
		return nil
	}
	raw, err := s.persister.Load()
	if err != nil {
		return ErrPersistence
	}
	if raw == nil {
		if s.authorityKnown {
			return ErrPersistence
		}
		return nil
	}
	next, err := decodeRegistry(raw)
	if err != nil {
		return ErrPersistence
	}
	s.publishLocked(next)
	s.authorityKnown = true
	return nil
}
func (s *Store) Upsert(c Connection) (Connection, error) {
	return s.UpsertContext(context.Background(), c)
}
func (s *Store) UpsertContext(ctx context.Context, c Connection) (Connection, error) {
	var out Connection
	err := s.edit(ctx, func(n *Store) error { var e error; out, e = n.upsertLocal(c); return e })
	if err != nil {
		return Connection{}, err
	}
	return out, nil
}
func (s *Store) Delete(tenant, id string) (bool, error) {
	return s.DeleteContext(context.Background(), tenant, id)
}
func (s *Store) DeleteContext(ctx context.Context, tenant, id string) (bool, error) {
	var out bool
	err := s.edit(ctx, func(n *Store) error { var e error; out, e = n.deleteLocal(tenant, id); return e })
	return out && err == nil, err
}
func (s *Store) SetDefault(tenant, id string) error {
	return s.SetDefaultContext(context.Background(), tenant, id)
}
func (s *Store) SetDefaultContext(ctx context.Context, tenant, id string) error {
	return s.edit(ctx, func(n *Store) error { return n.setDefaultLocal(tenant, id) })
}
func (s *Store) RemoveTenantChecked(tenant string) (int, error) {
	return s.RemoveTenantContext(context.Background(), tenant)
}
func (s *Store) RemoveTenantContext(ctx context.Context, tenant string) (int, error) {
	if s == nil {
		return 0, nil
	}
	var out int
	err := s.edit(ctx, func(n *Store) error { var e error; out, e = n.removeTenantCheckedLocal(tenant); return e })
	if err != nil {
		return 0, err
	}
	return out, nil
}

// TenantSnapshot is a checked, internally consistent view for management and classification.
func (s *Store) TenantSnapshot(tenant string) ([]Connection, string, error) {
	if err := s.RefreshShared(); err != nil {
		return nil, "", err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	rows := make([]Connection, 0, len(s.connections[tenant]))
	for _, c := range s.connections[tenant] {
		c.VerifiedDomains = append([]string(nil), c.VerifiedDomains...)
		rows = append(rows, c)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].IdPID < rows[j].IdPID })
	return rows, s.defaults[tenant], nil
}
