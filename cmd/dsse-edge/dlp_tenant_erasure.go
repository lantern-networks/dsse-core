package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/lantern-networks/dsse-core/blobstore"
)

// Tenant erasure uses the same confirmed writers as DLP administration. It
// removes authored state and its compiled data-path cache as one publication.
// A shared CP store must inspect the latest snapshot inside its transaction;
// an apparently empty local cache is not proof that another CP has no data.

func (s *dlpAllowlistRuntimeStore) CountForTenant(tenant string) int {
	if s == nil {
		return 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.values[tenant])
}

func (s *dlpAllowlistRuntimeStore) RemoveTenantContext(ctx context.Context, tenant string) (int, error) {
	if err := dlpErasureInput(ctx, tenant); err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if isDLPSharedPersister(s.persister) {
		var removed int
		err := s.mutateSharedLocked(ctx, func(next *dlpAllowlistRuntimeStore) error {
			removed = len(next.values[tenant])
			delete(next.values, tenant)
			delete(next.sets, tenant)
			return nil
		})
		return removed, err
	}
	removed := len(s.values[tenant])
	if removed == 0 && !s.dirty {
		return 0, nil
	}
	next := s.snapshotLocked()
	delete(next.Values, tenant)
	if err := s.saveSnapshotLocked(next); err != nil {
		if errors.Is(err, blobstore.ErrDurabilityUnconfirmed) {
			s.values, s.dirty = next.Values, true
			delete(s.sets, tenant)
			s.generation++
		}
		return 0, err
	}
	s.values, s.dirty = next.Values, false
	delete(s.sets, tenant)
	if removed > 0 {
		s.generation++
	}
	return removed, nil
}

func (s *dlpClassifierRuntimeStore) CountForTenant(tenant string) int {
	if s == nil {
		return 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.specs[tenant])
}

func (s *dlpClassifierRuntimeStore) RemoveTenantContext(ctx context.Context, tenant string) (int, error) {
	if err := dlpErasureInput(ctx, tenant); err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if isDLPSharedPersister(s.persister) {
		var removed int
		err := s.mutateSharedLocked(ctx, func(next *dlpClassifierRuntimeStore) error {
			removed = len(next.specs[tenant])
			delete(next.specs, tenant)
			delete(next.sets, tenant)
			return nil
		})
		return removed, err
	}
	removed := len(s.specs[tenant])
	if removed == 0 && !s.dirty {
		return 0, nil
	}
	next := s.snapshotLocked()
	delete(next.Specs, tenant)
	if err := s.saveSnapshotLocked(next); err != nil {
		if errors.Is(err, blobstore.ErrDurabilityUnconfirmed) {
			s.specs, s.dirty = next.Specs, true
			delete(s.sets, tenant)
			s.generation++
		}
		return 0, err
	}
	s.specs, s.dirty = next.Specs, false
	delete(s.sets, tenant)
	if removed > 0 {
		s.generation++
	}
	return removed, nil
}

func (s *dlpFingerprintRuntimeStore) CountForTenant(tenant string) int {
	if s == nil {
		return 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.datasets[tenant])
}

func (s *dlpFingerprintRuntimeStore) RemoveTenantContext(ctx context.Context, tenant string) (int, error) {
	if err := dlpErasureInput(ctx, tenant); err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if isDLPSharedPersister(s.persister) {
		var removed int
		err := s.mutateSharedLocked(ctx, func(next *dlpFingerprintRuntimeStore) error {
			removed = len(next.datasets[tenant])
			delete(next.datasets, tenant)
			delete(next.sets, tenant)
			return nil
		})
		return removed, err
	}
	removed := len(s.datasets[tenant])
	if removed == 0 && !s.dirty {
		return 0, nil
	}
	next := s.snapshotLocked()
	delete(next.Datasets, tenant)
	if err := s.saveSnapshotLocked(next); err != nil {
		if errors.Is(err, blobstore.ErrDurabilityUnconfirmed) {
			s.datasets, s.dirty = next.Datasets, true
			delete(s.sets, tenant)
			s.generation++
		}
		return 0, err
	}
	s.datasets, s.dirty = next.Datasets, false
	delete(s.sets, tenant)
	if removed > 0 {
		s.generation++
	}
	return removed, nil
}

func (s *dlpPolicyObjectStore) CountForTenant(tenant string) int {
	if s == nil {
		return 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.byTenant[tenant])
}

func (s *dlpPolicyObjectStore) RemoveTenantContext(ctx context.Context, tenant string) (int, error) {
	if err := dlpErasureInput(ctx, tenant); err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if isDLPSharedPersister(s.persister) {
		var removed int
		err := s.mutateSharedLocked(ctx, func(next *dlpPolicyObjectStore) error {
			removed = len(next.byTenant[tenant])
			delete(next.byTenant, tenant)
			return nil
		})
		return removed, err
	}
	removed := len(s.byTenant[tenant])
	if removed == 0 && !s.dirty {
		return 0, nil
	}
	next := s.snapshotLocked()
	delete(next.ByTenant, tenant)
	if err := s.saveSnapshotLocked(next); err != nil {
		s.adoptReplacedSnapshotLocked(next, err)
		return 0, err
	}
	s.byTenant, s.dirty = next.ByTenant, false
	if removed > 0 {
		s.generation++
	}
	return removed, nil
}

func (s *dlpRuleRuntimeStore) CountForTenant(tenant string) int {
	if s == nil {
		return 0
	}
	return len(s.RulesForTenant(tenant))
}

func (s *dlpRuleRuntimeStore) RemoveTenantContext(ctx context.Context, tenant string) (int, error) {
	if err := dlpErasureInput(ctx, tenant); err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if isDLPSharedPersister(s.persister) {
		var removed int
		err := s.mutateSharedLocked(ctx, func(next *dlpRuleRuntimeStore) error {
			current := next.snapshotLocked()
			removed = len(current.Rules[tenant])
			delete(current.Rules, tenant)
			next.rules.Store(&current.Rules)
			return nil
		})
		return removed, err
	}
	next := s.snapshotLocked()
	removed := len(next.Rules[tenant])
	if removed == 0 && !s.dirty {
		return 0, nil
	}
	delete(next.Rules, tenant)
	if err := s.saveSnapshotLocked(next); err != nil {
		if errors.Is(err, blobstore.ErrDurabilityUnconfirmed) {
			s.rules.Store(&next.Rules)
			s.dirty = true
			s.generation++
		}
		return 0, err
	}
	s.rules.Store(&next.Rules)
	s.dirty = false
	if removed > 0 {
		s.generation++
	}
	return removed, nil
}

func dlpErasureInput(ctx context.Context, tenant string) error {
	if ctx == nil {
		return fmt.Errorf("DLP erasure context is missing")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !validDLPLibraryTenant(tenant) {
		return fmt.Errorf("invalid DLP erasure tenant")
	}
	return nil
}
