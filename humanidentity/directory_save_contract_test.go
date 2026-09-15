package humanidentity

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/model"
)

type directorySaveGate struct {
	base    blobstore.Persister
	fail    bool
	warning bool
}

func (p *directorySaveGate) Load() ([]byte, error) { return p.base.Load() }
func (p *directorySaveGate) Save(data []byte) error {
	if p.fail {
		return errors.New("storage path must not reach the API")
	}
	if err := p.base.Save(data); err != nil {
		return err
	}
	if p.warning {
		return fmt.Errorf("committed: %w", blobstore.ErrSavedWithoutAtomicity)
	}
	return nil
}

func TestDirectoryUpsertPublishesOnlySavedIdentity(t *testing.T) {
	for _, operation := range []string{"create", "update", "suspend", "remove", "marshal"} {
		t.Run(operation, func(t *testing.T) {
			ctx := context.Background()
			now := time.Now()
			path := filepath.Join(t.TempDir(), "directory.json")
			gate := &directorySaveGate{base: blobstore.FilePersister{Path: path}}
			s := NewHumanIdentityDirectoryStore()
			if err := s.SetPersister(gate); err != nil {
				t.Fatal(err)
			}
			original, err := s.Upsert(ctx, model.HumanIdentity{ID: "alice", Subject: "alice", Status: "active", Source: "manual"}, "tenant", now)
			if err != nil {
				t.Fatal(err)
			}
			before, _ := os.ReadFile(path)
			generation := s.ConfigGeneration()
			candidate := original
			switch operation {
			case "create":
				candidate.ID = "bob"
				candidate.Subject = "bob"
			case "update":
				candidate.Subject = "changed"
			case "suspend":
				candidate.Status = "suspended"
			case "remove":
				candidate.Status = "deleted"
			case "marshal":
				candidate.Metadata = map[string]any{"unsupported": make(chan int)}
			}
			gate.fail = operation != "marshal"
			result, err := s.Upsert(ctx, candidate, "tenant", now)
			if !errors.Is(err, ErrDirectoryPersistence) || result.ID != "" {
				t.Fatalf("result=%#v err=%v", result, err)
			}
			if err.Error() != ErrDirectoryPersistence.Error() {
				t.Fatalf("storage detail exposed: %v", err)
			}
			users, _ := s.List(ctx, "tenant")
			after, _ := os.ReadFile(path)
			if !reflect.DeepEqual(users, []model.HumanIdentity{original}) || !bytes.Equal(before, after) || s.ConfigGeneration() != generation {
				t.Fatalf("rejected change became visible: %#v gen=%d", users, s.ConfigGeneration())
			}
			gate.fail = false
			// An unrelated later save must not persist any part of the rejected change.
			if _, err := s.Upsert(ctx, model.HumanIdentity{ID: "carol", Subject: "carol"}, "tenant", now); err != nil {
				t.Fatal(err)
			}
			restarted := newPersistedDirectory(t, path)
			users, _ = restarted.List(ctx, "tenant")
			if len(users) != 2 || !reflect.DeepEqual(users[0], original) {
				t.Fatalf("rejected change survived later save/restart: %#v", users)
			}
			if operation != "marshal" {
				if _, err := s.Upsert(ctx, candidate, "tenant", now); err != nil {
					t.Fatalf("retry: %v", err)
				}
				again := newPersistedDirectory(t, path)
				users, _ = again.List(ctx, "tenant")
				var found bool
				for _, u := range users {
					if u.ID == candidate.ID {
						found = u.Subject == candidate.Subject && u.Status == candidate.Status
					}
				}
				if !found {
					t.Fatalf("retry not durable: %#v", users)
				}
			}
		})
	}
}

func TestDirectoryUpsertKeepsCommittedWarningInSync(t *testing.T) {
	path := filepath.Join(t.TempDir(), "directory.json")
	gate := &directorySaveGate{base: blobstore.FilePersister{Path: path}, warning: true}
	s := NewHumanIdentityDirectoryStore()
	if err := s.SetPersister(gate); err != nil {
		t.Fatal(err)
	}
	previous := OnPersistError
	defer func() { OnPersistError = previous }()
	var reported error
	OnPersistError = func(err error) { reported = err }
	if _, err := s.Upsert(context.Background(), model.HumanIdentity{ID: "alice", Subject: "alice"}, "tenant", time.Now()); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(reported, blobstore.ErrSavedWithoutAtomicity) {
		t.Fatalf("warning not reported: %v", reported)
	}
	original, _ := s.List(context.Background(), "tenant")
	again := newPersistedDirectory(t, path)
	saved, _ := again.List(context.Background(), "tenant")
	if !reflect.DeepEqual(original, saved) || s.ConfigGeneration() != 1 {
		t.Fatalf("committed warning diverged: %#v %#v", original, saved)
	}
}
