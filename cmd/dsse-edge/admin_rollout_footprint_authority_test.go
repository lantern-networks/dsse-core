package main

import (
	"context"
	"errors"
	"testing"

	"github.com/lantern-networks/dsse-core/agentrollout"
)

type failedRolloutFootprintAuthority struct{ fail bool }

func (a *failedRolloutFootprintAuthority) Load() ([]byte, error) {
	if a.fail {
		return nil, errors.New("shared authority unavailable")
	}
	return nil, nil
}
func (a *failedRolloutFootprintAuthority) Save([]byte) error { return nil }
func (a *failedRolloutFootprintAuthority) UpdateContext(context.Context, func([]byte) ([]byte, error)) error {
	return errors.New("not used in count test")
}

func TestRolloutFootprintRefusesUnreadableSharedAuthority(t *testing.T) {
	a := &failedRolloutFootprintAuthority{}
	store := agentrollout.NewAgentRolloutStore()
	if err := store.LoadFromPersister(a); err != nil {
		t.Fatal(err)
	}
	a.fail = true
	f := adminTenantFootprint{TenantID: "own"}
	(adminTenantExtraStores{AgentRolloutPlans: store}).count(&f)
	if f.Clean() {
		t.Fatal("unreadable rollout authority cannot count as zero for tenant erasure")
	}
	for _, row := range f.Stores {
		if row.Store == "agent_rollout_plans" {
			if row.Count != -1 || row.Error == "" {
				t.Fatalf("rollout authority failure must produce an unknown row: %+v", row)
			}
			return
		}
	}
	t.Fatal("rollout authority row missing")
}
