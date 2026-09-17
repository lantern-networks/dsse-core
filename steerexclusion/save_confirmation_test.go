package steerexclusion

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/lantern-networks/dsse-core/blobstore"
	"reflect"
	"testing"
	"time"
)

type steerSaveProbe struct {
	data   []byte
	err    error
	retain bool
}

func (p *steerSaveProbe) Load() ([]byte, error) { return append([]byte(nil), p.data...), nil }
func (p *steerSaveProbe) Save(b []byte) error {
	if p.err == nil || p.retain {
		p.data = append([]byte(nil), b...)
	}
	return p.err
}
func policyForSave(id, tenant, app string) Policy {
	return Policy{ID: id, TenantID: tenant, ScopeType: "tenant", ExcludedAppSigningIDs: []string{app}}
}
func TestSteerExclusionSaveConfirmation(t *testing.T) {
	for _, action := range []string{"create", "update", "delete"} {
		for _, outcome := range []struct {
			name             string
			err              error
			retain, accepted bool
		}{
			{"atomic", nil, true, true}, {"in-place", blobstore.ErrSavedWithoutAtomicity, true, true},
			{"failed", errors.New("private storage failure"), false, false},
			{"uncertain-not-written", blobstore.ErrDurabilityUnconfirmed, false, false},
			{"uncertain-written", blobstore.ErrDurabilityUnconfirmed, true, false},
			{"combined-warning", errors.Join(blobstore.ErrSavedWithoutAtomicity, blobstore.ErrDurabilityUnconfirmed), true, false},
		} {
			t.Run(action+"/"+outcome.name, func(t *testing.T) {
				p := &steerSaveProbe{}
				fp := &FilePersistence{persister: p, byID: map[string]*Policy{}}
				s, err := NewStoreWithPersistence(fp)
				if err != nil {
					t.Fatal(err)
				}
				now := time.Now()
				for _, v := range []Policy{policyForSave("owned", "t1", "old"), policyForSave("keep", "t1", "keep"), policyForSave("foreign", "t2", "foreign")} {
					if _, err = s.Upsert(v, now); err != nil {
						t.Fatal(err)
					}
				}
				before := s.List("t1")
				p.err, p.retain = outcome.err, outcome.retain
				id := "owned"
				if action == "create" {
					id = "new"
				}
				if action == "delete" {
					var ok bool
					ok, err = s.DeleteChecked(id, "t1", now)
					if ok != outcome.accepted {
						t.Fatal("delete acknowledgement", ok)
					}
				} else {
					_, err = s.Upsert(policyForSave(id, "t1", "new"), now)
				}
				if (err == nil) != outcome.accepted {
					t.Fatalf("save err=%v accepted=%v", err, outcome.accepted)
				}
				if !outcome.accepted {
					if !errors.Is(err, ErrPersistence) {
						t.Fatal(err)
					}
					if !reflect.DeepEqual(s.List("t1"), before) {
						t.Fatal("failed mutation published")
					}
					// An unrelated save must not accidentally flush the rejected candidate.
					p.err = nil
					if _, err = s.Upsert(policyForSave("unrelated", "t1", "unrelated"), now); err != nil {
						t.Fatal(err)
					}
					restarted, err := NewStoreWithPersistence(&FilePersistence{persister: p, byID: map[string]*Policy{}})
					if err != nil {
						t.Fatal(err)
					}
					old, ok := restarted.Get("owned", "t1")
					if !ok || old.ExcludedAppSigningIDs[0] != "old" {
						t.Fatal("rejected update/delete leaked into subsequent save")
					}
					if _, ok = restarted.Get("new", "t1"); ok {
						t.Fatal("rejected create leaked into subsequent save")
					}
					if action == "delete" {
						if ok, err := s.DeleteChecked(id, "t1", now); !ok || err != nil {
							t.Fatal("retry", ok, err)
						}
					} else if _, err = s.Upsert(policyForSave(id, "t1", "new"), now); err != nil {
						t.Fatal("retry", err)
					}
				}
				restarted, err := NewStoreWithPersistence(&FilePersistence{persister: p, byID: map[string]*Policy{}})
				if err != nil {
					t.Fatal(err)
				}
				got, ok := restarted.Get(id, "t1")
				if action == "delete" {
					if ok {
						t.Fatal("delete not saved")
					}
				} else if !ok || got.ExcludedAppSigningIDs[0] != "new" {
					t.Fatal("upsert not saved")
				}
				if got, ok := restarted.Get("foreign", "t2"); !ok || got.ExcludedAppSigningIDs[0] != "foreign" {
					t.Fatal("foreign policy changed")
				}
			})
		}
	}
}
func TestSteerExclusionOwnershipAtBothLayers(t *testing.T) {
	p := &steerSaveProbe{}
	f := &FilePersistence{persister: p, byID: map[string]*Policy{}}
	s, err := NewStoreWithPersistence(f)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	foreign := policyForSave("same", "t2", "foreign")
	if _, err = s.Upsert(foreign, now); err != nil {
		t.Fatal(err)
	}
	before := string(p.data)
	if _, err = s.Upsert(policyForSave("same", "t1", "attack"), now); !errors.Is(err, ErrTenantConflict) {
		t.Fatal("live conflict", err)
	}
	// The backend holds the other tenant's ID while this node's cache is stale.
	stale := NewStore()
	stale.persistence = f
	stale.refreshedAt = now
	if _, err = stale.Upsert(policyForSave("same", "t1", "attack"), now); !errors.Is(err, ErrTenantConflict) {
		t.Fatal("durable conflict", err)
	}
	if len(stale.byID) != 0 || string(p.data) != before {
		t.Fatal("rejected conflict changed state")
	}
	if ok, err := s.DeleteChecked("same", "t1", now); ok || err != nil {
		t.Fatal("foreign delete", ok, err)
	}
	if err := f.Delete(context.Background(), "same", "t1"); err != nil {
		t.Fatal(err)
	}
	if string(p.data) != before {
		t.Fatal("foreign delete wrote snapshot")
	}
	if _, err = s.Upsert(policyForSave("owned", "t1", "own"), now); err != nil {
		t.Fatal(err)
	}
	own := s.List("t1")
	s.ReplaceTenant("t1", []Policy{policyForSave("same", "t1", "attack")})
	if !reflect.DeepEqual(own, s.List("t1")) {
		t.Fatal("rejected sync removed own policies")
	}
	if got, ok := s.Get("same", "t2"); !ok || got.ExcludedAppSigningIDs[0] != "foreign" {
		t.Fatal("sync overwrote foreign policy")
	}
}
func TestSteerExclusionFailedLoadKeepsBackendCache(t *testing.T) {
	p := &steerSaveProbe{}
	f := &FilePersistence{persister: p, byID: map[string]*Policy{}}
	old := policyForSave("old", "t1", "old")
	if err := f.Upsert(context.Background(), &old); err != nil {
		t.Fatal(err)
	}
	p.data = []byte("{broken")
	if _, err := f.LoadAll(context.Background()); err == nil {
		t.Fatal("expected parse error")
	}
	next := policyForSave("next", "t1", "next")
	if err := f.Upsert(context.Background(), &next); err != nil {
		t.Fatal(err)
	}
	var saved filePersistSnapshot
	if err := json.Unmarshal(p.data, &saved); err != nil {
		t.Fatal(err)
	}
	if len(saved.Policies) != 2 {
		t.Fatal("parse failure discarded previous backend cache")
	}
}
func TestSteerExclusionReturnedPoliciesDoNotAlias(t *testing.T) {
	s := NewStore()
	p := policyForSave("id", "t1", "original")
	saved, err := s.Upsert(p, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	p.ExcludedAppSigningIDs[0] = "input"
	saved.ExcludedAppSigningIDs[0] = "output"
	got, _ := s.Get("id", "t1")
	got.ExcludedAppSigningIDs[0] = "get"
	s.List("t1")[0].ExcludedAppSigningIDs[0] = "list"
	if got := s.ResolveForDevice("t1", "", ""); !reflect.DeepEqual(got, []string{"original"}) {
		t.Fatal("aliased policy", got)
	}
}
