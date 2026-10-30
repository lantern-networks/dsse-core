package humanidentity

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/model"
)

func TestRejectedDirectorySnapshotCannotBeOverwritten(t *testing.T) {
	for name, raw := range map[string]string{
		"torn":               `{not-json`,
		"empty":              ``,
		"missing-map":        `{"users":{}}`,
		"wrong-key":          `{"users":{"Acme\u0000alice":{"id":"alice","tenant_id":"Other","subject":"alice","status":"active"}},"source_states":{},"source_policies":{}}`,
		"duplicate-policy":   `{"users":{},"source_states":{},"source_policies":{"Acme\u0000idp":{"tenant_id":"Acme","source":"idp","enabled":false},"Acme\u0000idp":{"tenant_id":"Acme","source":"idp","enabled":true}}}`,
		"alias-policy-field": `{"users":{},"source_states":{},"source_policies":{"Acme\u0000idp":{"tenant_id":"Acme","source":"idp","enabled":false,"Enabled":true}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "directory.json")
			if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
				t.Fatal(err)
			}
			store := NewHumanIdentityDirectoryStore()
			if err := store.SetPersister(blobstore.FilePersister{Path: path}); err == nil {
				t.Fatal("corrupt directory accepted")
			}
			if _, err := store.Upsert(context.Background(), model.HumanIdentity{ID: "new", Subject: "new"}, "Acme", time.Now()); err != nil {
				t.Fatal(err)
			}
			after, err := os.ReadFile(path)
			if err != nil || string(after) != raw {
				t.Fatalf("failed SetPersister overwrote recovery evidence: changed=%v err=%v", string(after) != raw, err)
			}
		})
	}
}

func TestDisabledSourcePolicyIsPublishedOnlyAfterConfirmedSave(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "directory.json")
	gate := &directorySaveGate{base: blobstore.FilePersister{Path: path}}
	s := NewHumanIdentityDirectoryStore()
	if err := s.SetPersister(gate); err != nil {
		t.Fatal(err)
	}
	initial := HumanIdentitySourcePolicy{TenantID: "Acme", Source: "idp", Enabled: true, Metadata: map[string]any{"connector_id": "connector-a"}}
	if _, err := s.UpsertSourcePolicy(ctx, initial); err != nil {
		t.Fatal(err)
	}
	gen := s.ConfigGeneration()
	gate.fail = true
	initial.Enabled = false
	if _, err := s.UpsertSourcePolicy(ctx, initial); !errors.Is(err, ErrDirectoryPersistence) {
		t.Fatalf("unsaved policy reported success: %v", err)
	}
	listed, err := s.ListSourcePolicies(ctx, "Acme")
	if err != nil || len(listed) != 1 || !listed[0].Enabled || s.ConfigGeneration() != gen {
		t.Fatalf("unsaved policy entered live authority: %+v gen=%d err=%v", listed, s.ConfigGeneration(), err)
	}
	gate.fail = false
	if _, err := s.Upsert(ctx, model.HumanIdentity{ID: "alice", Subject: "alice"}, "Acme", time.Now()); err != nil {
		t.Fatal(err)
	}
	restarted := newPersistedDirectory(t, path)
	listed, err = restarted.ListSourcePolicies(ctx, "Acme")
	if err != nil || len(listed) != 1 || !listed[0].Enabled {
		t.Fatalf("failed policy was saved later: %+v err=%v", listed, err)
	}
}

func TestDirectoryRejectsNULKeyBoundaryCollision(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	s := NewHumanIdentityDirectoryStore()
	for _, user := range []model.HumanIdentity{
		{TenantID: "A\x00B", ID: "C", Subject: "one"},
		{TenantID: "A", ID: "B\x00C", Subject: "two"},
	} {
		if _, err := s.Upsert(ctx, user, "", now); err == nil {
			t.Fatalf("ambiguous tenant/ID key accepted: %#v", user)
		}
	}
	if _, err := s.UpsertSourcePolicy(ctx, HumanIdentitySourcePolicy{TenantID: "A", Source: "B\x00C", Enabled: true}); err == nil {
		t.Fatal("ambiguous source policy key accepted")
	}
}
