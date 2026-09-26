package enrolledinventory

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/lantern-networks/dsse-core/blobstore"
	"reflect"
	"testing"
)

type tenantRetirementStore struct {
	data   []byte
	err    error
	retain bool
	writes int
}

func (p *tenantRetirementStore) Load() ([]byte, error) { return bytes.Clone(p.data), nil }
func (p *tenantRetirementStore) Save(b []byte) error {
	p.writes++
	if p.err == nil || p.retain {
		p.data = bytes.Clone(b)
	}
	return p.err
}
func TestTenantRetirementAndErasureSaveOutcomes(t *testing.T) {
	bridge := errors.Join(blobstore.ErrSavedWithoutAtomicity, blobstore.ErrDurabilityUnconfirmed)
	for _, tc := range []struct {
		name             string
		err              error
		retain, accepted bool
	}{
		{"atomic", nil, true, true}, {"synced_in_place", blobstore.ErrSavedWithoutAtomicity, true, true},
		{"no_write", errors.New("private path"), false, false}, {"write_error", errors.New("private path"), true, false},
		{"unconfirmed_lost", blobstore.ErrDurabilityUnconfirmed, false, false}, {"unconfirmed_retained", blobstore.ErrDurabilityUnconfirmed, true, false},
		{"bridge_lost", bridge, false, false}, {"bridge_retained", bridge, true, false}, {"wrapped_bridge", fmt.Errorf("private path: %w", bridge), true, false},
	} {
		for _, action := range []string{"retire", "erase"} {
			t.Run(tc.name+"/"+action, func(t *testing.T) {
				p := &tenantRetirementStore{}
				l := NewLedger()
				if err := l.SetPersisterChecked(p); err != nil {
					t.Fatal(err)
				}
				stamp := "2026-09-17T05:00:00Z"
				for _, x := range []struct{ id, tenant string }{{"own", "tenant_a"}, {"foreign", "tenant_b"}} {
					if _, err := l.Enroll(x.id, x.tenant, "private note", stamp); err != nil {
						t.Fatal(err)
					}
				}
				e := l.entries["own"]
				e.ReenrolmentNonce = 7
				l.entries["own"] = e
				if err := l.persistCheckedLocked(); err != nil {
					t.Fatal(err)
				}
				if action == "erase" {
					if _, err := l.RetireTenantChecked("tenant_a", stamp); err != nil {
						t.Fatal(err)
					}
				}
				gen := l.ConfigGeneration()
				foreign, _ := l.EntryFor("foreign")
				p.err, p.retain = tc.err, tc.retain
				mutate := func() (int, error) {
					if action == "retire" {
						return l.RetireTenantChecked(" TENANT_A ", stamp)
					}
					ids, err := l.RemoveTenantChecked("tenant_a")
					return len(ids), err
				}
				n, err := mutate()
				if (err == nil) != tc.accepted || n != map[bool]int{false: 0, true: 1}[tc.accepted] {
					t.Fatalf("result %d %v", n, err)
				}
				own, exists := l.EntryFor("own")
				if action == "retire" {
					if !exists || own.Enabled || !own.isTombstone() || own.ReenrolmentNonce != 7 || own.Note != "" || l.ConfigGeneration() != gen+1 {
						t.Fatal("retirement did not preserve a restrictive ownership record")
					}
				} else {
					if exists == tc.accepted || l.ConfigGeneration() != gen+map[bool]uint64{true: 1, false: 0}[tc.accepted] {
						t.Fatal("erasure published an unconfirmed outcome")
					}
				}
				after, _ := l.EntryFor("foreign")
				if !reflect.DeepEqual(after, foreign) {
					t.Fatal("foreign changed")
				}
				reloaded := NewLedger()
				if err := reloaded.SetPersisterChecked(p); err != nil {
					t.Fatal(err)
				}
				saved, exists := reloaded.EntryFor("own")
				if action == "retire" {
					if !exists || saved.isTombstone() != tc.retain {
						t.Fatal("wrong retained/lost retirement outcome")
					}
				} else if exists == tc.retain {
					t.Fatal("wrong retained/lost erase outcome")
				}
				p.err = nil
				p.retain = true
				before := l.ConfigGeneration()
				writes := p.writes
				if _, err := mutate(); err != nil {
					t.Fatal(err)
				}
				if action == "retire" {
					if p.writes != writes+1 || l.ConfigGeneration() != before {
						t.Fatal("retirement retry did not resave or churned generation")
					}
				} else if !tc.accepted && l.ConfigGeneration() != before+1 {
					t.Fatal("confirmed removal did not advance generation")
				}
				reloaded = NewLedger()
				if err := reloaded.SetPersisterChecked(p); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(l.Authoritative(), reloaded.Authoritative()) {
					t.Fatal("retry does not survive reload")
				}
			})
		}
	}
}
func TestTenantRetirementCountsAndValidation(t *testing.T) {
	p := &tenantRetirementStore{}
	l := NewLedger()
	l.SetPersister(p)
	stamp := "2026-09-17T05:00:00Z"
	l.Enroll("one", "tenant_a", "", stamp)
	l.Enroll("two", "tenant_a", "", stamp)
	l.SetEnabled("two", false, stamp)
	if l.CountTenantRecords("tenant_a") != 2 {
		t.Fatal("disabled identity uncounted")
	}
	writes := p.writes
	if _, err := l.RetireTenantChecked("tenant_a", "invalid"); err == nil || p.writes != writes {
		t.Fatal("invalid time changed state")
	}
	if n, err := l.RetireTenantChecked("tenant_a", stamp); n != 2 || err != nil {
		t.Fatal(n, err)
	}
	if len(l.List()) != 0 || len(l.Authoritative()) != 2 || l.CountTenantRecords("tenant_a") != 2 {
		t.Fatal("retirement lost ownership or appeared as a device")
	}
	gen := l.ConfigGeneration()
	writes = p.writes
	if n, err := l.RetireTenantChecked("absent", stamp); n != 0 || err != nil || p.writes != writes || l.ConfigGeneration() != gen {
		t.Fatal("absent tenant changed state")
	}
}
