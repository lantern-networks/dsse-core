package policyrule

import (
	"context"
	"encoding/json"
	"reflect"
)

type contextUpdater interface {
	UpdateContext(context.Context, func([]byte) ([]byte, error)) error
}

func (s *Store) sharedCandidateLocked(raw []byte) (*Store, error) {
	n := NewStore()
	n.generation = s.generation
	if raw == nil {
		if len(s.rules) > 0 {
			return nil, ErrPersistence
		}
		return n, nil
	}
	var snap persistedRules
	if err := json.Unmarshal(raw, &snap); err != nil || snap.Rules == nil || snap.Seq < 0 {
		return nil, ErrPersistence
	}
	for tenant, rows := range snap.Rules {
		for id, r := range rows {
			if tenant == "" || id == "" || r.TenantID != tenant || r.ID != id {
				return nil, ErrPersistence
			}
			r = cloneRule(r)
			if err := r.normalizeAndValidate(); err != nil {
				return nil, ErrPersistence
			}
			rows[id] = r
		}
	}
	n.rules, n.seq = snap.Rules, snap.Seq
	return n, nil
}

func mutateRules[T any](ctx context.Context, s *Store, edit func(*Store) (T, error)) (T, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n *Store
	var result T
	var validation error
	if p, ok := s.persister.(contextUpdater); ok {
		err := p.UpdateContext(ctx, func(raw []byte) ([]byte, error) {
			var err error
			n, err = s.sharedCandidateLocked(raw)
			if err != nil {
				return nil, err
			}
			result, validation = edit(n)
			if validation != nil {
				return nil, validation
			}
			return json.Marshal(persistedRules{Seq: n.seq, Rules: n.rules})
		})
		if validation != nil {
			return result, validation
		}
		if err != nil {
			var zero T
			return zero, ErrPersistence
		}
	} else {
		n = &Store{rules: cloneRules(s.rules), seq: s.seq, generation: s.generation, persister: s.persister}
		var err error
		result, err = edit(n)
		if err != nil {
			return result, err
		}
	}
	if !reflect.DeepEqual(s.rules, n.rules) {
		s.generation++
	}
	s.rules, s.seq = n.rules, n.seq
	return result, nil
}

// RefreshShared loads shared authority for checked administrative reads. On failure
// the last confirmed local state is retained and the caller must refuse the read.
func (s *Store) RefreshShared() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.persister.(contextUpdater); !ok {
		return nil
	}
	raw, err := s.persister.Load()
	if err != nil {
		return ErrPersistence
	}
	n, err := s.sharedCandidateLocked(raw)
	if err != nil {
		return ErrPersistence
	}
	if !reflect.DeepEqual(s.rules, n.rules) {
		s.generation++
	}
	s.rules, s.seq = n.rules, n.seq
	return nil
}
func (s *Store) Upsert(r Rule) (Rule, error) { return s.UpsertContext(context.Background(), r) }
func (s *Store) UpsertContext(ctx context.Context, r Rule) (Rule, error) {
	return mutateRules(ctx, s, func(n *Store) (Rule, error) { return n.upsert(r) })
}
func (s *Store) Delete(tenant, id string) (bool, error) {
	return s.DeleteContext(context.Background(), tenant, id)
}
func (s *Store) DeleteContext(ctx context.Context, tenant, id string) (bool, error) {
	return mutateRules(ctx, s, func(n *Store) (bool, error) { return n.delete(tenant, id) })
}
func (s *Store) RemoveTenantChecked(tenant string) (int, error) {
	return s.RemoveTenantContext(context.Background(), tenant)
}
func (s *Store) RemoveTenantContext(ctx context.Context, tenant string) (int, error) {
	if s == nil {
		return 0, nil
	}
	return mutateRules(ctx, s, func(n *Store) (int, error) { return n.removeTenantChecked(tenant) })
}
func (s *Store) ReplaceAll(rules []Rule) error {
	_, err := mutateRules(context.Background(), s, func(n *Store) (bool, error) { return true, n.replaceAll(rules) })
	return err
}
