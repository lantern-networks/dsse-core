package policy

import (
	"context"
	"errors"
	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/model"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

type replacementWriter struct {
	blobstore.FilePersister
	unconfirmed bool
}

func (p *replacementWriter) Save(raw []byte) error {
	if err := p.FilePersister.Save(raw); err != nil {
		return err
	}
	if p.unconfirmed {
		return blobstore.ErrDurabilityUnconfirmed
	}
	return nil
}

func TestReplacedRuntimeMatchesReloadAndSurvivesNextEdit(t *testing.T) {
	for _, op := range []string{"authored", "incoming", "eastwest"} {
		t.Run(op, func(t *testing.T) {
			p := &replacementWriter{FilePersister: blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "runtime.json")}}
			s := NewStore(nil)
			if err := s.SetRuntimeStatePersister(p); err != nil {
				t.Fatal(err)
			}
			p.unconfirmed = true
			var err error
			switch op {
			case "authored":
				_, err = s.Upsert(context.Background(), model.Policy{ID: "p", TenantID: "own", Name: "policy", Status: "active", Conditions: map[string]any{"actor_type": "user"}, Action: model.PolicyAction{Decision: "deny"}}, "own", time.Now())
			case "incoming":
				err = s.SetServerInitiatedEnabledConfirmed("own", true)
			case "eastwest":
				enabled := true
				err = s.ApplyEastWestUpdateConfirmed("own", nil, nil, &enabled, nil)
			}
			if !errors.Is(err, ErrPolicyPersistence) {
				t.Fatal("unconfirmed save acknowledged", err)
			}
			fresh := NewStore(nil)
			if err := fresh.SetRuntimeStatePersister(p); err != nil {
				t.Fatal(err)
			}
			expected := fresh.SnapshotTenantConfig("own")
			policies := fresh.Snapshot("own")
			if !reflect.DeepEqual(s.SnapshotTenantConfig("own"), expected) || !reflect.DeepEqual(s.Snapshot("own"), policies) {
				t.Fatal("live/reload differ")
			}
			p.unconfirmed = false
			if err := s.SetServerInitiatedEnabledConfirmed("other", true); err != nil {
				t.Fatal(err)
			}
			final := NewStore(nil)
			if err := final.SetRuntimeStatePersister(p); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(final.SnapshotTenantConfig("own"), expected) || !reflect.DeepEqual(final.Snapshot("own"), policies) {
				t.Fatal("next edit undid replacement")
			}
		})
	}
}
