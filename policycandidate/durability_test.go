package policycandidate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
)

func TestCandidateSaveFailureDoesNotPublish(t *testing.T) {
	for _, op := range []string{"upsert", "review", "observe", "dns", "manual", "materialize", "learning", "discovery"} {
		t.Run(op, func(t *testing.T) {
			ctx := context.Background()
			now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
			path := filepath.Join(t.TempDir(), "state.json")
			s := NewStore()
			if e := s.SetStatePath(path); e != nil {
				t.Fatal(e)
			}
			c, e := s.ObserveCertPinFailure(ctx, "own", "named.example", "named.example", 443, "rejected", now)
			if e != nil {
				t.Fatal(e)
			}
			if op == "materialize" {
				if _, _, e := s.Review(ctx, "own", c.CandidateID, ReviewRequest{Decision: "approved"}, now); e != nil {
					t.Fatal(e)
				}
			}
			mutate := func() error {
				var e error
				switch op {
				case "upsert":
					c.Status = "rejected"
					_, e = s.Upsert(ctx, c, "own", now)
				case "review":
					_, _, e = s.Review(ctx, "own", c.CandidateID, ReviewRequest{Decision: "approved"}, now)
				case "observe":
					_, e = s.ObserveCertPinFailure(ctx, "own", "named.example", "named.example", 443, "rejected", now.Add(time.Minute))
				case "dns":
					_, e = s.ObserveCertPinFailureDNSCorrelated(ctx, "own", "named.example", "192.0.2.1", 443, "rejected", now)
				case "manual":
					_, e = s.AddManualCertPinBypass(ctx, "own", "manual.example", now)
				case "materialize":
					_, _, e = s.Materialize(ctx, "own", c.CandidateID, false, now)
				case "learning":
					_, e = s.ObserveUnmatchedFlow(ctx, "own", "learning.example", "", 443, "", now)
				case "discovery":
					_, e = s.ObserveConnectorDiscovered(ctx, "own", "discovery.example", 443, "web", "conn", "site", "ns", []string{"route"}, now)
				}
				return e
			}
			before, _ := s.List(ctx, "own", ListOptions{})
			old, _ := json.Marshal(before)
			disk, e := os.ReadFile(path)
			if e != nil {
				t.Fatal(e)
			}
			if e = os.Rename(path, path+".saved"); e != nil {
				t.Fatal(e)
			}
			if e = os.Mkdir(path, 0700); e != nil {
				t.Fatal(e)
			}
			if e = mutate(); e == nil {
				t.Error("unconfirmed save returned success")
			}
			after, _ := s.List(ctx, "own", ListOptions{})
			live, _ := json.Marshal(after)
			if !bytes.Equal(old, live) {
				t.Error("failed candidate published")
			}
			// A successful write for another tenant must not carry the failed change into storage.
			if e = os.Remove(path); e != nil {
				t.Fatal(e)
			}
			if e = os.Rename(path+".saved", path); e != nil {
				t.Fatal(e)
			}
			reopened := NewStore()
			if e = reopened.SetStatePath(path); e != nil {
				t.Fatal(e)
			}
			restored, _ := reopened.List(ctx, "own", ListOptions{})
			b, _ := json.Marshal(restored)
			if !bytes.Equal(old, b) {
				t.Error("old disk state changed")
			}
			if _, e = s.ObserveCertPinFailure(ctx, "other", "other.example", "", 443, "rejected", now); e != nil {
				t.Fatal(e)
			}
			saved, _ := os.ReadFile(path)
			var snapshots map[string]map[string]Candidate
			json.Unmarshal(saved, &snapshots)
			var prior map[string]map[string]Candidate
			json.Unmarshal(disk, &prior)
			x, _ := json.Marshal(snapshots["own"])
			y, _ := json.Marshal(prior["own"])
			if !bytes.Equal(x, y) {
				t.Error("other tenant write persisted unconfirmed change")
			}
			if e = mutate(); e != nil {
				t.Fatal("retry", e)
			}
			fresh := NewStore()
			if e = fresh.SetStatePath(path); e != nil {
				t.Fatal(e)
			}
			a, _ := s.List(ctx, "own", ListOptions{})
			bList, _ := fresh.List(ctx, "own", ListOptions{})
			x, _ = json.Marshal(a)
			y, _ = json.Marshal(bList)
			if !bytes.Equal(x, y) {
				t.Error("retry/restart differ")
			}
		})
	}
}

type candidateTestPersister struct {
	data            []byte
	fail, uncertain bool
	loadErr         error
}

func (p *candidateTestPersister) Load() ([]byte, error) { return bytes.Clone(p.data), p.loadErr }
func (p *candidateTestPersister) Save(b []byte) error {
	if p.fail {
		if p.uncertain {
			p.data = bytes.Clone(b)
		}
		return errors.New("private storage failure")
	}
	p.data = bytes.Clone(b)
	return nil
}

func TestCandidateWriterFailureKeepsPreviousState(t *testing.T) {
	s := NewStore()
	p := &candidateTestPersister{}
	if e := s.SetPersister(p); e != nil {
		t.Fatal(e)
	}
	ctx := context.Background()
	now := time.Now()
	c, e := s.AddManualCertPinBypass(ctx, "own", "named.example", now)
	if e != nil {
		t.Fatal(e)
	}
	bad := &candidateTestPersister{loadErr: errors.New("load refused")}
	if e = s.SetPersister(bad); e == nil {
		t.Fatal("accepted failed load")
	}
	if _, _, e = s.Review(ctx, "own", c.CandidateID, ReviewRequest{Decision: "rejected"}, now); e != nil {
		t.Fatal(e)
	}
	if !bytes.Contains(p.data, []byte(`"rejected"`)) || len(bad.data) != 0 {
		t.Fatal("failed load replaced writer")
	}
	p.fail = true
	p.uncertain = true
	if _, _, e = s.Review(ctx, "own", c.CandidateID, ReviewRequest{Decision: "approved"}, now); e == nil {
		t.Fatal("uncertain save accepted")
	}
	for _, writer := range []blobstore.Persister{nil, &candidateTestPersister{}} {
		if e = s.SetPersister(writer); e == nil {
			t.Fatal("unconfirmed writer replaced")
		}
	}
	got, _, _ := s.Get(ctx, "own", c.CandidateID)
	if got.Status != "rejected" {
		t.Fatal("uncertain live change")
	}
	p.fail = false
	if _, _, e = s.Review(ctx, "own", c.CandidateID, ReviewRequest{Decision: "approved"}, now); e != nil {
		t.Fatal(e)
	}
	if e = s.SetPersister(nil); e != nil {
		t.Fatal(e)
	}
}

func TestCandidateReturnedTimestampsAreIsolated(t *testing.T) {
	s := NewStore()
	ctx := context.Background()
	c, e := s.AddManualCertPinBypass(ctx, "own", "named.example", time.Now())
	if e != nil {
		t.Fatal(e)
	}
	want := *c.LastObserved
	*c.LastObserved = "corrupt"
	*c.UpdatedAt = "corrupt"
	list, _ := s.List(ctx, "own", ListOptions{})
	if *list.Candidates[0].LastObserved != want {
		t.Fatal("returned timestamp aliases live")
	}
	*list.Candidates[0].LastObserved = "corrupt"
	got, _, _ := s.Get(ctx, "own", c.CandidateID)
	if *got.LastObserved != want {
		t.Fatal("list aliases live")
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); x, _, _ := s.Get(ctx, "own", c.CandidateID); *x.LastObserved = "caller" }()
	}
	wg.Wait()
}

func TestCandidateMissingErasureReconcilesUncertainSnapshot(t *testing.T) {
	ctx := context.Background()
	p := &candidateTestPersister{}
	s := NewStore()
	if e := s.SetPersister(p); e != nil {
		t.Fatal(e)
	}
	p.fail = true
	p.uncertain = true
	if _, e := s.AddManualCertPinBypass(ctx, "own", "named.example", time.Now()); !errors.Is(e, ErrPersistence) {
		t.Fatal("uncertain result", e)
	}
	if s.CountForTenant("own") != 0 || !bytes.Contains(p.data, []byte("named.example")) {
		t.Fatal("uncertain state not reproduced")
	}
	if n, e := s.RemoveTenant("own"); n != 0 || !errors.Is(e, ErrPersistence) {
		t.Fatal("missing erase skipped reconciliation", n, e)
	}
	if e := s.SetPersister(nil); e == nil {
		t.Fatal("dirty writer detached")
	}
	p.fail = false
	if n, e := s.RemoveTenant("own"); n != 0 || e != nil {
		t.Fatal(n, e)
	}
	fresh := NewStore()
	if e := fresh.SetPersister(p); e != nil || fresh.CountForTenant("own") != 0 {
		t.Fatal("uncertain candidate not erased", e)
	}
	if e := s.SetPersister(nil); e != nil {
		t.Fatal(e)
	}
}
