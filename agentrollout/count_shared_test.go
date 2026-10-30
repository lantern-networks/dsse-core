package agentrollout

import (
	"context"
	"errors"
	"testing"
)

type countSharedAuthority struct {
	raw      []byte
	loadFail bool
}

func (a *countSharedAuthority) Load() ([]byte, error) {
	if a.loadFail {
		return nil, errors.New("shared authority unavailable")
	}
	return append([]byte(nil), a.raw...), nil
}
func (a *countSharedAuthority) Save(raw []byte) error {
	a.raw = append([]byte(nil), raw...)
	return nil
}
func (a *countSharedAuthority) UpdateContext(_ context.Context, edit func([]byte) ([]byte, error)) error {
	next, err := edit(a.raw)
	if err != nil {
		return err
	}
	return a.Save(next)
}

func TestCountForTenantCheckedReadsSharedAuthorityAndRefusesUnknown(t *testing.T) {
	a := &countSharedAuthority{}
	reader, writer := NewAgentRolloutStore(), NewAgentRolloutStore()
	for _, store := range []*AgentRolloutStore{reader, writer} {
		if err := store.LoadFromPersister(a); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Set("own", AgentRolloutPlan{Frozen: true, Intent: AgentRolloutIntentFreeze}); err != nil {
		t.Fatal(err)
	}
	if got, err := reader.CountForTenantChecked("own"); err != nil || got != 1 {
		t.Fatalf("remote write was not counted: count=%d err=%v", got, err)
	}
	if got, err := reader.CountForTenantChecked("foreign"); err != nil || got != 0 {
		t.Fatalf("foreign tenant must remain empty: count=%d err=%v", got, err)
	}
	a.loadFail = true
	if got, err := reader.CountForTenantChecked("own"); got != 0 || !errors.Is(err, ErrPersistence) {
		t.Fatalf("authority failure must be unknown, never a trusted count: count=%d err=%v", got, err)
	}
}
