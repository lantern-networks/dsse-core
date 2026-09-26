package policycandidate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
)

type candidateSaveGate struct {
	blobstore.Persister
	reject bool
	weak   bool
}

func (p *candidateSaveGate) Save(data []byte) error {
	if p.reject {
		return errors.New("synthetic storage rejection")
	}
	if err := p.Persister.Save(data); err != nil {
		return err
	}
	if p.weak {
		return blobstore.ErrSavedWithoutAtomicity
	}
	return nil
}

func TestCandidateFailedWritesPreserveStateAndRetry(t *testing.T) {
	for _, operation := range []string{"create", "edit", "review", "materialize", "manual-bypass", "observe-flow", "observe-connector", "observe-certpin"} {
		t.Run(operation, func(t *testing.T) {
			ctx, now := context.Background(), time.Now()
			path := filepath.Join(t.TempDir(), "candidates.json")
			disk := blobstore.FilePersister{Path: path}
			gate := &candidateSaveGate{Persister: disk}
			s := NewStore()
			if err := s.SetPersister(gate); err != nil {
				t.Fatal(err)
			}
			seed, err := s.ObserveUnmatchedFlow(ctx, "one", "old.example.test", "", 443, "", now)
			if err != nil {
				t.Fatal(err)
			}
			if operation == "materialize" {
				if _, _, err = s.Review(ctx, "one", seed.CandidateID, ReviewRequest{Decision: "approved"}, now); err != nil {
					t.Fatal(err)
				}
			}
			before, err := s.List(ctx, "one", ListOptions{})
			if err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			mutate := func() error {
				switch operation {
				case "create":
					n := seed
					n.CandidateID = "new"
					_, err = s.Upsert(ctx, n, "one", now)
				case "edit":
					n := seed
					n.ReasonCodes = []string{"updated"}
					_, err = s.Upsert(ctx, n, "one", now)
				case "review":
					_, _, err = s.Review(ctx, "one", seed.CandidateID, ReviewRequest{Decision: "suppressed"}, now)
				case "materialize":
					_, _, err = s.Materialize(ctx, "one", seed.CandidateID, false, now)
				case "manual-bypass":
					_, err = s.AddManualCertPinBypass(ctx, "one", "pin.example.test", now)
				case "observe-flow":
					_, err = s.ObserveUnmatchedFlow(ctx, "one", "new.example.test", "", 443, "", now)
				case "observe-connector":
					_, err = s.ObserveConnectorDiscovered(ctx, "one", "connector.example.test", 443, "web", "connector", "site", "", nil, now)
				case "observe-certpin":
					_, err = s.ObserveCertPinFailure(ctx, "one", "pin.example.test", "pin.example.test", 443, "reset", now)
				}
				return err
			}
			gate.reject = true
			if err := mutate(); err == nil {
				t.Fatal("failed save was acknowledged")
			}
			after, err := s.List(ctx, "one", ListOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(before, after) {
				t.Fatal("failed save changed live candidates")
			}
			saved, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(saved) != string(raw) {
				t.Fatal("rejected save changed disk")
			}
			gate.reject = false
			other := seed
			other.TenantID = "other"
			if _, err := s.Upsert(ctx, other, "other", now); err != nil {
				t.Fatal(err)
			}
			fresh := NewStore()
			if err := fresh.SetPersister(disk); err != nil {
				t.Fatal(err)
			}
			after, err = fresh.List(ctx, "one", ListOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(before, after) {
				t.Fatal("later save persisted rejected mutation")
			}
			if err := mutate(); err != nil {
				t.Fatal("retry failed", err)
			}
			final := NewStore()
			if err := final.SetPersister(disk); err != nil {
				t.Fatal(err)
			}
			live, err := s.List(ctx, "one", ListOptions{})
			if err != nil {
				t.Fatal(err)
			}
			durable, err := final.List(ctx, "one", ListOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(live, durable) {
				t.Fatal("successful retry differs after restart")
			}
		})
	}
}

func TestCandidateWrittenSnapshotWarningKeepsLiveAndReloadedState(t *testing.T) {
	disk := blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "candidates.json")}
	s := NewStore()
	if err := s.SetPersister(&candidateSaveGate{Persister: disk, weak: true}); err != nil {
		t.Fatal(err)
	}
	saved, err := s.ObserveUnmatchedFlow(context.Background(), "one", "wiki.example.test", "", 443, "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	fresh := NewStore()
	if err := fresh.SetPersister(disk); err != nil {
		t.Fatal(err)
	}
	got, found, err := fresh.Get(context.Background(), "one", saved.CandidateID)
	if err != nil || !found || !reflect.DeepEqual(saved, got) {
		t.Fatalf("written snapshot lost: %+v %v %v", got, found, err)
	}
}
