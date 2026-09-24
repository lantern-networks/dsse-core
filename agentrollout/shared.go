package agentrollout

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
)

type contextUpdater interface {
	UpdateContext(context.Context, func([]byte) ([]byte, error)) error
}

// ErrPersistence does not expose database credentials, tenant data or disk paths.
var ErrPersistence = errors.New("agent rollout persistence is unavailable")

func clonePlan(p AgentRolloutPlan) AgentRolloutPlan {
	if p.Window != nil {
		v := *p.Window
		p.Window = &v
	}
	if p.Waves != nil {
		v := *p.Waves
		v.Waves = append([]RolloutWave(nil), p.Waves.Waves...)
		if v.DefaultDelayDays != nil {
			n := *v.DefaultDelayDays
			v.DefaultDelayDays = &n
		}
		p.Waves = &v
	}
	return p
}
func clonePlans(plans map[string]AgentRolloutPlan) map[string]AgentRolloutPlan {
	out := make(map[string]AgentRolloutPlan, len(plans))
	for k, v := range plans {
		out[k] = clonePlan(v)
	}
	return out
}
func (s *AgentRolloutStore) decodeCurrentLocked(raw []byte) (map[string]AgentRolloutPlan, error) {
	if raw == nil {
		if len(s.plans) > 0 {
			return nil, ErrPersistence
		}
		return map[string]AgentRolloutPlan{}, nil
	}
	return decodeRolloutSnapshot(raw)
}
func (s *AgentRolloutStore) mutateLocked(ctx context.Context, edit func(map[string]AgentRolloutPlan)) error {
	var candidate map[string]AgentRolloutPlan
	if p, ok := s.blob.(contextUpdater); ok {
		if err := p.UpdateContext(ctx, func(raw []byte) ([]byte, error) {
			var err error
			candidate, err = s.decodeCurrentLocked(raw)
			if err != nil {
				return nil, err
			}
			edit(candidate)
			return json.Marshal(candidate)
		}); err != nil {
			return ErrPersistence
		}
	} else {
		candidate = clonePlans(s.plans)
		edit(candidate)
		if reflect.DeepEqual(candidate, s.plans) {
			return nil
		}
		if err := s.persistPlansLocked(candidate); err != nil {
			return ErrPersistence
		}
	}
	s.plans = candidate
	return nil
}

// SnapshotChecked refreshes shared authority before answering Console or fleet
// polls. It holds the store lock across load/publication so a concurrent local
// save cannot be replaced by an older read. File-only stores retain their live
// state; their write failures are reported by the mutation that encountered them.
func (s *AgentRolloutStore) SnapshotChecked() (map[string]AgentRolloutPlan, error) {
	if s == nil {
		return map[string]AgentRolloutPlan{}, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, shared := s.blob.(contextUpdater); shared {
		raw, err := s.blob.Load()
		if err != nil {
			return nil, ErrPersistence
		}
		plans, err := s.decodeCurrentLocked(raw)
		if err != nil {
			return nil, ErrPersistence
		}
		s.plans = plans
	}
	return clonePlans(s.plans), nil
}
