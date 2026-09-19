package knownbypass

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
)

type overrideTestPersister struct {
	data             []byte
	fail             error
	writeBeforeError bool
	loadError        error
	saves            int
}

func (p *overrideTestPersister) Load() ([]byte, error) { return bytes.Clone(p.data), p.loadError }
func (p *overrideTestPersister) Save(b []byte) error {
	p.saves++
	if p.fail == nil || p.writeBeforeError {
		p.data = bytes.Clone(b)
	}
	return p.fail
}
func setTestOverride(t *testing.T, s *OverrideStore, tenant, entry, mode string) {
	t.Helper()
	if _, e := s.Set(tenant, Override{EntryID: entry, Mode: mode}, time.Now()); e != nil {
		t.Fatal(e)
	}
}

func TestOverrideMutationsKeepConfirmedStateOnFileFailure(t *testing.T) {
	for _, operation := range []string{"create", "replace", "clear", "erase"} {
		t.Run(operation, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "overrides.json")
			s := NewOverrideStore()
			if e := s.SetStatePath(path); e != nil {
				t.Fatal(e)
			}
			setTestOverride(t, s, "other", "apple_time", OverrideDisabled)
			if operation != "create" {
				setTestOverride(t, s, "own", "github_asset_cdn", OverrideForceInspect)
			}
			original := sortedOverrideSnapshot(s)
			saved, e := os.ReadFile(path)
			if e != nil {
				t.Fatal(e)
			}
			mutate := func() error {
				switch operation {
				case "create", "replace":
					_, e := s.Set("own", Override{EntryID: "github_asset_cdn", Mode: OverrideDisabled}, time.Now())
					return e
				case "clear":
					removed, e := s.Clear("own", "github_asset_cdn")
					if e != nil && removed {
						t.Fatal("failed clear reported removed")
					}
					return e
				default:
					n, e := s.RemoveTenant("own")
					if e != nil && n != 0 {
						t.Fatal("failed erasure reported removal")
					}
					return e
				}
			}
			if e := os.Rename(path, path+".original"); e != nil {
				t.Fatal(e)
			}
			if e := os.Mkdir(path, 0700); e != nil {
				t.Fatal(e)
			}
			if e := mutate(); !errors.Is(e, ErrPersistence) {
				t.Fatalf("wanted persistence error: %v", e)
			}
			if !reflect.DeepEqual(sortedOverrideSnapshot(s), original) {
				t.Fatal("failed mutation visible")
			}
			if e := s.SetPersister(nil); !errors.Is(e, ErrPersistence) {
				t.Fatal("unconfirmed state detached from writer")
			}
			if e := os.Remove(path); e != nil {
				t.Fatal(e)
			}
			if e := os.Rename(path+".original", path); e != nil {
				t.Fatal(e)
			}
			after, _ := os.ReadFile(path)
			if !bytes.Equal(after, saved) {
				t.Fatal("staging rejection changed saved data")
			}
			// An unrelated successful save must not smuggle the failed mutation into storage.
			setTestOverride(t, s, "other", "apple_push", OverrideDisabled)
			reopened := NewOverrideStore()
			if e := reopened.SetStatePath(path); e != nil {
				t.Fatal(e)
			}
			if !reflect.DeepEqual(reopened.List("own"), s.List("own")) {
				t.Fatal("restart differs")
			}
			if !reflect.DeepEqual(sortedOverrideSnapshot(reopened)["own"], original["own"]) {
				t.Fatal("failed mutation persisted later")
			}
			if e := mutate(); e != nil {
				t.Fatal(e)
			}
			reopened = NewOverrideStore()
			if e := reopened.SetStatePath(path); e != nil {
				t.Fatal(e)
			}
			if !reflect.DeepEqual(sortedOverrideSnapshot(reopened), sortedOverrideSnapshot(s)) {
				t.Fatal("retry not durable")
			}
		})
	}
}

func TestOverrideUncertainSaveRequiresRetryEvenForMissingRemoval(t *testing.T) {
	for _, failure := range []error{errors.New("reply lost after write"), blobstore.ErrSavedWithoutAtomicity, blobstore.ErrDurabilityUnconfirmed} {
		for _, operation := range []string{"clear", "erase"} {
			t.Run(failure.Error()+"/"+operation, func(t *testing.T) {
				p := &overrideTestPersister{}
				s := NewOverrideStore()
				if e := s.SetPersister(p); e != nil {
					t.Fatal(e)
				}
				setTestOverride(t, s, "other", "apple_time", OverrideDisabled)
				p.fail = failure
				p.writeBeforeError = true
				if _, e := s.Set("own", Override{EntryID: "github_asset_cdn", Mode: OverrideDisabled}, time.Now()); !errors.Is(e, ErrPersistence) {
					t.Fatal(e)
				}
				if len(s.List("own")) != 0 {
					t.Fatal("uncertain write published")
				}
				persisted := NewOverrideStore()
				if e := persisted.SetPersister(&overrideTestPersister{data: p.data}); e != nil {
					t.Fatal(e)
				}
				if len(persisted.List("own")) != 1 {
					t.Fatal("fixture did not write before error")
				}
				if e := s.SetPersister(&overrideTestPersister{}); !errors.Is(e, ErrPersistence) {
					t.Fatal("writer replaced before reconciliation")
				}
				remove := func() error {
					if operation == "clear" {
						n, e := s.Clear("own", "github_asset_cdn")
						if n {
							t.Fatal("reported unacknowledged object removed")
						}
						return e
					}
					n, e := s.RemoveTenant("own")
					if n != 0 {
						t.Fatal("incorrect count")
					}
					return e
				}
				if e := remove(); !errors.Is(e, ErrPersistence) {
					t.Fatal("no-op reported success while storage still failing", e)
				}
				p.fail = nil
				if e := remove(); e != nil {
					t.Fatal(e)
				}
				persisted = NewOverrideStore()
				if e := persisted.SetPersister(p); e != nil {
					t.Fatal(e)
				}
				if len(persisted.List("own")) != 0 || len(persisted.List("other")) != 1 {
					t.Fatal("retry did not reconcile saved snapshot")
				}
				if e := s.SetPersister(p); e != nil {
					t.Fatal("clean writer reload refused", e)
				}
			})
		}
	}
}

func TestOverrideFailedLoadKeepsPreviousWriter(t *testing.T) {
	for _, bad := range []*overrideTestPersister{{loadError: errors.New("load failed")}, {data: []byte(`{broken`)}} {
		p := &overrideTestPersister{}
		s := NewOverrideStore()
		if e := s.SetPersister(p); e != nil {
			t.Fatal(e)
		}
		setTestOverride(t, s, "own", "apple_time", OverrideDisabled)
		old := sortedOverrideSnapshot(s)
		if e := s.SetPersister(bad); e == nil {
			t.Fatal("bad load accepted")
		}
		if !reflect.DeepEqual(old, sortedOverrideSnapshot(s)) {
			t.Fatal("load failure changed state")
		}
		setTestOverride(t, s, "own", "apple_push", OverrideDisabled)
		if bad.saves != 0 || p.saves != 2 {
			t.Fatal("failed load replaced writer")
		}
	}
}

func TestOverrideConcurrentMutationsSurviveRestart(t *testing.T) {
	p := &overrideTestPersister{}
	s := NewOverrideStore()
	if e := s.SetPersister(p); e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, e := s.Set(fmt.Sprintf("tenant-%d", i), Override{EntryID: "apple_push", Mode: OverrideForceInspect}, time.Now()); e != nil {
				t.Error(e)
			}
		}(i)
	}
	wg.Wait()
	reopened := NewOverrideStore()
	if e := reopened.SetPersister(p); e != nil {
		t.Fatal(e)
	}
	if len(sortedOverrideSnapshot(reopened)) != 20 || !reflect.DeepEqual(sortedOverrideSnapshot(reopened), sortedOverrideSnapshot(s)) {
		t.Fatal("concurrent mutation lost")
	}
}

func sortedOverrideSnapshot(s *OverrideStore) map[string][]Override {
	result := s.Snapshot()
	for _, entries := range result {
		slices.SortFunc(entries, func(a, b Override) int { return strings.Compare(a.EntryID, b.EntryID) })
	}
	return result
}
