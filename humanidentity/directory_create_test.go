package humanidentity

import (
	"bytes"
	"context"
	"errors"
	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/model"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestDirectoryCreatePreservesExistingAndOnlyPublishesSavedIdentity(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	path := filepath.Join(t.TempDir(), "people.json")
	gate := &directorySaveGate{base: blobstore.FilePersister{Path: path}}
	s := NewHumanIdentityDirectoryStore()
	if err := s.SetPersister(gate); err != nil {
		t.Fatal(err)
	}
	original, err := s.Upsert(ctx, model.HumanIdentity{ID: "alice", Subject: "synced", Source: "idp", Status: "deleted", Metadata: map[string]any{"kept": "yes"}}, "tenant", now)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	gen := s.ConfigGeneration()
	if _, err := s.Create(ctx, model.HumanIdentity{ID: "alice", Subject: "replacement"}, "tenant", now); !errors.Is(err, ErrIdentityExists) {
		t.Fatalf("conflict=%v", err)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) || s.ConfigGeneration() != gen {
		t.Fatal("conflict changed saved state")
	}
	gate.fail = true
	if _, err := s.Create(ctx, model.HumanIdentity{ID: "bob", Subject: "bob"}, "tenant", now); !errors.Is(err, ErrDirectoryPersistence) {
		t.Fatalf("save rejection=%v", err)
	}
	users, _ := s.List(ctx, "tenant")
	after, _ = os.ReadFile(path)
	if !reflect.DeepEqual(users, []model.HumanIdentity{original}) || !bytes.Equal(before, after) || s.ConfigGeneration() != gen {
		t.Fatal("rejected create became visible")
	}
	gate.fail = false
	if _, err := s.Create(ctx, model.HumanIdentity{ID: "alice", Subject: "other"}, "other", now); err != nil {
		t.Fatal(err)
	}
	created, err := s.Create(ctx, model.HumanIdentity{ID: "bob", Subject: "bob"}, "tenant", now)
	if err != nil {
		t.Fatal(err)
	}
	restarted := newPersistedDirectory(t, path)
	users, _ = restarted.List(ctx, "tenant")
	if !reflect.DeepEqual(users, []model.HumanIdentity{original, created}) {
		t.Fatal("saved create did not reload")
	}
	if s.ConfigGeneration() != gen+2 {
		t.Fatal("generation did not track creates")
	}
}
