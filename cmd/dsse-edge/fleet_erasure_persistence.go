package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/internal/strictjson"
)

// Only erasure evidence is durable. Configuration freshness is deliberately not
// restored, so a powered-off Edge cannot appear alive after a CP restart.
type fleetErasureSnapshot struct {
	Version int                                           `json:"version"`
	Tenants map[string]map[string]fleetTenantErasureState `json:"tenants"`
}

type fleetErasureUpdater interface {
	UpdateContext(context.Context, func([]byte) ([]byte, error)) error
}

func newPersistentFleetConfigStatusStore(poll time.Duration, p blobstore.Persister) (*fleetConfigStatusStore, error) {
	if p == nil {
		return nil, fmt.Errorf("control-plane erasure evidence requires -postgres-dsn or -state-dir")
	}
	s := newFleetConfigStatusStore(poll)
	s.erasurePersister = p
	if err := s.refreshErasureLocked(); err != nil {
		return nil, err
	}
	return s, nil
}

func decodeFleetErasure(raw []byte, known bool) (fleetErasureSnapshot, error) {
	empty := fleetErasureSnapshot{Version: 1, Tenants: map[string]map[string]fleetTenantErasureState{}}
	if raw == nil {
		if known {
			return empty, fmt.Errorf("fleet erasure evidence disappeared")
		}
		return empty, nil
	}
	if err := strictjson.RejectDuplicateKeys(raw); err != nil {
		return empty, err
	}
	if err := strictjson.RejectUnknownFields(raw, empty); err != nil {
		return empty, err
	}
	var snap fleetErasureSnapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		return empty, err
	}
	if snap.Version != 1 || snap.Tenants == nil {
		return empty, fmt.Errorf("invalid fleet erasure snapshot")
	}
	// The standard decoder accepts case variants of field names. Do not let
	// an aliased Clean/Remaining field override the persisted evidence.
	var encoded struct {
		Tenants map[string]map[string]json.RawMessage `json:"tenants"`
	}
	if err := json.Unmarshal(raw, &encoded); err != nil {
		return empty, err
	}
	for tenant, nodes := range snap.Tenants {
		if tenant == "" || tenant != strings.TrimSpace(tenant) || len(nodes) == 0 {
			return empty, fmt.Errorf("invalid fleet erasure tenant")
		}
		for key, state := range nodes {
			if err := strictjson.RejectUnknownFields(encoded.Tenants[tenant][key], fleetTenantErasureState{}); err != nil {
				return empty, err
			}
			if key == "" || key != strings.TrimSpace(key) || state.ReportedAt.IsZero() || state.Remaining < 0 || (state.Clean && state.Remaining != 0) || state.Stale {
				return empty, fmt.Errorf("invalid fleet erasure node evidence")
			}
			state.NodeKey = key
			nodes[key] = state
		}
	}
	return snap, nil
}

// Preserve every other node and tenant. A delayed report cannot overwrite a
// newer observation; at an equal timestamp, non-clean evidence wins.
func mergeFleetErasure(dst, src map[string]map[string]fleetTenantErasureState) {
	for tenant, nodes := range src {
		if dst[tenant] == nil {
			dst[tenant] = map[string]fleetTenantErasureState{}
		}
		for key, state := range nodes {
			old, exists := dst[tenant][key]
			if exists && (old.ReportedAt.After(state.ReportedAt) ||
				(old.ReportedAt.Equal(state.ReportedAt) && (!old.Clean || old.Remaining > state.Remaining))) {
				continue
			}
			dst[tenant][key] = state
		}
	}
}

func (s *fleetConfigStatusStore) recordErasureLocked(ctx context.Context, rep fleetConfigReport, now time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	key := fleetConfigKey(rep.RegionID, rep.ClusterID, rep.NodeID)
	changes := map[string]map[string]fleetTenantErasureState{}
	for _, er := range rep.Erasures {
		tenant := strings.TrimSpace(er.TenantID)
		if tenant == "" || now.IsZero() || er.Remaining < 0 || (er.Clean && er.Remaining != 0) {
			return fmt.Errorf("invalid fleet erasure report")
		}
		if _, duplicate := changes[tenant]; duplicate {
			return fmt.Errorf("duplicate fleet erasure tenant")
		}
		changes[tenant] = map[string]fleetTenantErasureState{key: {
			NodeKey: key, NodeID: rep.NodeID, Clean: er.Clean, Remaining: er.Remaining, ReportedAt: now.UTC(),
		}}
	}
	if s.erasurePersister == nil {
		mergeFleetErasure(s.erasures, changes)
		return nil // explicit in-memory development/test store
	}
	if s.erasurePending == nil {
		s.erasurePending = map[string]map[string]fleetTenantErasureState{}
	}
	mergeFleetErasure(s.erasurePending, changes)
	if len(s.erasurePending) == 0 {
		return nil
	}
	var accepted fleetErasureSnapshot
	edit := func(raw []byte) ([]byte, error) {
		next, err := decodeFleetErasure(raw, s.erasureKnown)
		if err != nil {
			return nil, err
		}
		mergeFleetErasure(next.Tenants, s.erasurePending)
		data, err := json.Marshal(next)
		if err == nil {
			accepted = next
		}
		return data, err
	}
	var err error
	if p, shared := s.erasurePersister.(fleetErasureUpdater); shared {
		// Existing CP transaction fencing and row locking serialize promotions
		// and concurrent reporters; never save a whole stale process snapshot.
		err = p.UpdateContext(ctx, edit)
	} else {
		var raw, next []byte
		raw, err = s.erasurePersister.Load()
		if err == nil {
			next, err = edit(raw)
		}
		if err == nil {
			err = ctx.Err()
		}
		if err == nil {
			err = blobstore.UnconfirmedSave(s.erasurePersister.Save(next))
		}
	}
	if err != nil {
		return err // pending observations remain; the completion endpoint refuses a guess
	}
	if accepted.Tenants == nil {
		return fmt.Errorf("fleet erasure evidence was not committed")
	}
	s.erasures, s.erasureKnown, s.erasurePending = accepted.Tenants, true, nil
	return nil
}

func (s *fleetConfigStatusStore) refreshErasureLocked() error {
	if s.erasurePersister == nil {
		return nil
	}
	if len(s.erasurePending) > 0 {
		return fmt.Errorf("fleet erasure evidence has uncommitted observations")
	}
	raw, err := s.erasurePersister.Load()
	if err != nil {
		return err
	}
	next, err := decodeFleetErasure(raw, s.erasureKnown)
	if err != nil {
		return err
	}
	s.erasures, s.erasureKnown = next.Tenants, raw != nil
	return nil
}
