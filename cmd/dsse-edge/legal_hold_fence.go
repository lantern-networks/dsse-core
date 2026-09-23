package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

var errTenantErasureInProgress = errors.New("tenant erasure is in progress or requires recovery")

type tenantErasureFence struct {
	ID        string `json:"id"`
	Node      string `json:"node"`
	StartedAt string `json:"started_at"`
}
type legalHoldSnapshot struct {
	Version  int                           `json:"version"`
	Holds    []legalHoldRecord             `json:"holds"`
	Erasures map[string]tenantErasureFence `json:"erasures"`
}
type tenantErasureContext struct{ Tenant, ID string }

// V2 remains V2 after the last fence is cleared. Old array-only readers fail
// closed rather than silently dropping an in-flight erasure during an upgrade.
func decodeHoldSnapshot(raw []byte, known bool) (legalHoldSnapshot, error) {
	out := legalHoldSnapshot{Version: 1, Holds: []legalHoldRecord{}, Erasures: map[string]tenantErasureFence{}}
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		if known {
			return out, fmt.Errorf("known legal hold row is missing")
		}
		return out, nil
	}
	if raw[0] == '[' {
		if err := json.Unmarshal(raw, &out.Holds); err != nil {
			return out, err
		}
	} else {
		out = legalHoldSnapshot{}
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&out); err != nil {
			return out, err
		}
		if err := dec.Decode(new(any)); err != io.EOF {
			return out, fmt.Errorf("trailing legal hold state")
		}
		if out.Version != 2 || out.Erasures == nil {
			return out, fmt.Errorf("unsupported legal hold state")
		}
	}
	if out.Holds == nil {
		return out, fmt.Errorf("legal hold records must be an array")
	}
	seen := map[string]bool{}
	for i, r := range out.Holds {
		tenant := strings.TrimSpace(r.TenantID)
		if tenant == "" || seen[tenant] {
			return out, fmt.Errorf("invalid or duplicate legal hold tenant")
		}
		seen[tenant] = true
		out.Holds[i].TenantID = tenant
	}
	for tenant, f := range out.Erasures {
		id, e := hex.DecodeString(f.ID)
		_, te := time.Parse(time.RFC3339Nano, f.StartedAt)
		if tenant == "" || strings.TrimSpace(tenant) != tenant || seen[tenant] || e != nil || len(id) != 16 || te != nil {
			return out, fmt.Errorf("invalid tenant erasure fence")
		}
	}
	return out, nil
}
func (v legalHoldSnapshot) held() map[string]legalHoldRecord {
	out := map[string]legalHoldRecord{}
	for _, r := range v.Holds {
		out[r.TenantID] = r
	}
	return out
}
func encodeHoldSnapshot(held map[string]legalHoldRecord, fences map[string]tenantErasureFence, version int) ([]byte, error) {
	rows := make([]legalHoldRecord, 0, len(held))
	for _, r := range held {
		rows = append(rows, r)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].TenantID < rows[j].TenantID })
	if version < 2 && len(fences) == 0 {
		return json.Marshal(rows)
	}
	if fences == nil {
		fences = map[string]tenantErasureFence{}
	}
	return json.Marshal(legalHoldSnapshot{Version: 2, Holds: rows, Erasures: fences})
}
func ownsTenantErasure(ctx context.Context, tenant string, f tenantErasureFence) bool {
	owner, ok := ctx.Value(tenantErasureContext{}).(tenantErasureContext)
	return ok && owner.Tenant == tenant && owner.ID == f.ID
}

// Administrative status distinguishes an erasure fence from an accepted hold.
// Refresh once, then copy all displayed values under the same state lock.
func (s *legalHoldStore) adminStatus(ctx context.Context, tenant string) ([]legalHoldRecord, bool, bool, error) {
	if s == nil {
		return nil, false, false, nil
	}
	if err := s.refreshSharedContext(ctx); err != nil {
		return nil, false, false, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.loadErr != nil {
		return nil, false, false, fmt.Errorf("legal hold state is unavailable; restore storage and restart")
	}
	if _, busy := s.erasures[tenant]; busy {
		return nil, false, false, errTenantErasureInProgress
	}
	rows := make([]legalHoldRecord, 0, len(s.held))
	for _, r := range s.held {
		rows = append(rows, r)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].TenantID < rows[j].TenantID })
	_, held := s.held[tenant]
	return rows, held || s.pending[tenant], s.pending[tenant], nil
}

// Persist a fence before touching any resource. A SQL session/leader loss cannot
// release it. No transaction is held across nested Store mutations.
func (s *legalHoldStore) beginErasure(ctx context.Context, tenant, node string) (context.Context, func() error, error) {
	ctx = retentionWriteContext(ctx)
	if s == nil {
		return ctx, func() error { return nil }, nil
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return ctx, nil, err
	}
	fence := tenantErasureFence{ID: hex.EncodeToString(nonce[:]), Node: node, StartedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	if err := s.changeErasure(ctx, tenant, fence, true); err != nil {
		return ctx, nil, err
	}
	owned := context.WithValue(ctx, tenantErasureContext{}, tenantErasureContext{Tenant: tenant, ID: fence.ID})
	finish := func() error {
		// Cleanup is bounded but outlives request cancellation. Retain the original
		// leader term: a lost leader leaves recovery evidence rather than clearing it.
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), cpStateBlobDBTimeout)
		defer cancel()
		return s.changeErasure(cleanup, tenant, fence, false)
	}
	return owned, finish, nil
}
func (s *legalHoldStore) changeErasure(ctx context.Context, tenant string, fence tenantErasureFence, begin bool) error {
	ctx = retentionWriteContext(ctx)
	if err := lockPolicyWriter(ctx, &s.writeMu); err != nil {
		return err
	}
	defer s.writeMu.Unlock()
	var next legalHoldSnapshot
	mutate := func(v legalHoldSnapshot) ([]byte, error) {
		if begin {
			s.mu.RLock()
			pending := s.pending[tenant]
			s.mu.RUnlock()
			if pending {
				return nil, fmt.Errorf("legal hold save is unconfirmed")
			}
			if _, held := v.held()[tenant]; held {
				return nil, fmt.Errorf("tenant is held")
			}
			if _, exists := v.Erasures[tenant]; exists {
				return nil, errTenantErasureInProgress
			}
			v.Erasures[tenant] = fence
		} else {
			current, exists := v.Erasures[tenant]
			if !exists || current.ID != fence.ID {
				return nil, errTenantErasureInProgress
			}
			delete(v.Erasures, tenant)
		}
		v.Version = 2
		next = v
		return encodeHoldSnapshot(v.held(), v.Erasures, v.Version)
	}
	if p, ok := s.persister.(retentionSharedUpdater); ok {
		err := p.UpdateContext(ctx, func(raw []byte) ([]byte, error) {
			v, err := decodeHoldSnapshot(raw, s.sharedKnown)
			if err != nil {
				return nil, err
			}
			return mutate(v)
		})
		if err != nil {
			return err
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		s.held, s.erasures, s.snapshotVersion, s.sharedKnown, s.loadErr = next.held(), next.Erasures, 2, true, nil
		return nil
	}
	// The local path serializes writers throughout saving. Build a
	// detached candidate so an unconfirmed write never publishes a clear fence.
	s.mu.RLock()
	if s.loadErr != nil {
		s.mu.RUnlock()
		return fmt.Errorf("legal hold state unavailable")
	}
	raw, err := encodeHoldSnapshot(s.held, s.erasures, s.snapshotVersion)
	s.mu.RUnlock()
	if err != nil {
		return err
	}
	v, err := decodeHoldSnapshot(raw, false)
	if err != nil {
		return err
	}
	data, err := mutate(v)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	// setLocal shares writeMu, so no writer can change the inspected state.
	if s.persister != nil {
		if err := s.persister.Save(data); err != nil {
			return err
		}
	}
	s.held, s.erasures, s.snapshotVersion = next.held(), next.Erasures, 2
	return nil
}
