package main

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

type retentionSharedUpdater interface {
	UpdateContext(context.Context, func([]byte) ([]byte, error)) error
}

func retentionWriteContext(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if _, ok := ctx.Value(cpWriteLeaseKey{}).(cpWriteLease); !ok {
		ctx = captureCPWriteLease(ctx)
	}
	return ctx
}
func decodeSharedRetention(raw []byte, known bool) (map[string]int, error) {
	if len(raw) == 0 {
		if known {
			return nil, fmt.Errorf("known retention row is missing")
		}
		return map[string]int{}, nil
	}
	return decodeRetentionOverrides(raw)
}
func decodeSharedHolds(raw []byte, known bool) (map[string]legalHoldRecord, error) {
	result := map[string]legalHoldRecord{}
	if len(raw) == 0 {
		if known {
			return nil, fmt.Errorf("known legal hold row is missing")
		}
		return result, nil
	}
	var rows []legalHoldRecord
	if err := json.Unmarshal(raw, &rows); err != nil {
		return nil, err
	}
	if rows == nil {
		return nil, fmt.Errorf("legal hold snapshot must be an array")
	}
	for _, r := range rows {
		r.TenantID = strings.TrimSpace(r.TenantID)
		if r.TenantID == "" {
			return nil, fmt.Errorf("legal hold record has no tenant")
		}
		if _, ok := result[r.TenantID]; ok {
			return nil, fmt.Errorf("duplicate legal hold tenant")
		}
		result[r.TenantID] = r
	}
	return result, nil
}
func encodeSharedHolds(held map[string]legalHoldRecord) ([]byte, error) {
	rows := make([]legalHoldRecord, 0, len(held))
	for _, r := range held {
		rows = append(rows, r)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].TenantID < rows[j].TenantID })
	return json.Marshal(rows)
}

func (s *retentionOverrideStore) refreshShared() error {
	if _, ok := s.persister.(retentionSharedUpdater); !ok {
		return nil
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	raw, err := s.persister.Load()
	var next map[string]int
	if err == nil {
		next, err = decodeSharedRetention(raw, s.sharedKnown)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		s.loadErr = fmt.Errorf("retention settings are unavailable")
		return s.loadErr
	}
	s.days, s.loadErr = next, nil
	if len(raw) > 0 {
		s.sharedKnown = true
	}
	return nil
}
func (s *legalHoldStore) refreshShared() error {
	if _, ok := s.persister.(retentionSharedUpdater); !ok {
		return nil
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	raw, err := s.persister.Load()
	var next map[string]legalHoldRecord
	if err == nil {
		next, err = decodeSharedHolds(raw, s.sharedKnown)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		s.loadErr = fmt.Errorf("legal hold state is unavailable")
		return s.loadErr
	}
	s.held, s.loadErr = next, nil
	if len(raw) > 0 {
		s.sharedKnown = true
	}
	return nil
}
func (s *retentionOverrideStore) SetContext(ctx context.Context, stream string, days int) error {
	if s == nil || stream == "" || strings.TrimSpace(stream) != stream || days > maxRetentionDays {
		return fmt.Errorf("invalid retention setting")
	}
	p, ok := s.persister.(retentionSharedUpdater)
	if !ok {
		return s.setLocal(stream, days)
	}
	ctx = retentionWriteContext(ctx)
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	var next map[string]int
	err := p.UpdateContext(ctx, func(raw []byte) ([]byte, error) {
		candidate, err := decodeSharedRetention(raw, s.sharedKnown)
		if err != nil {
			return nil, err
		}
		if days < 0 {
			delete(candidate, stream)
		} else {
			candidate[stream] = days
		}
		next = candidate
		return json.Marshal(candidate)
	})
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.days, s.loadErr, s.sharedKnown = next, nil, true
	return nil
}
func (s *legalHoldStore) SetContext(ctx context.Context, tenantID, heldBy, reason string, active bool, now time.Time) error {
	tenantID = strings.TrimSpace(tenantID)
	if s == nil || tenantID == "" {
		return fmt.Errorf("legal hold store or tenant is unavailable")
	}
	p, ok := s.persister.(retentionSharedUpdater)
	if !ok {
		return s.setLocal(tenantID, heldBy, reason, active, now)
	}
	ctx = retentionWriteContext(ctx)
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	var next map[string]legalHoldRecord
	err := p.UpdateContext(ctx, func(raw []byte) ([]byte, error) {
		candidate, err := decodeSharedHolds(raw, s.sharedKnown)
		if err != nil {
			return nil, err
		}
		if active {
			if _, exists := candidate[tenantID]; !exists {
				candidate[tenantID] = legalHoldRecord{TenantID: tenantID, HeldSince: now.UTC().Format(time.RFC3339), HeldBy: heldBy, Reason: reason}
			}
		} else {
			delete(candidate, tenantID)
		}
		next = candidate
		return encodeSharedHolds(candidate)
	})
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.held, s.loadErr, s.sharedKnown = next, nil, true
	return nil
}
