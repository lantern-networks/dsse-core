package revocation

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/lantern-networks/dsse-core/blobstore"
)

type admissionSavePersister struct {
	data   []byte
	err    error
	retain bool
	writes int
}

func (p *admissionSavePersister) Load() ([]byte, error) { return bytes.Clone(p.data), nil }
func (p *admissionSavePersister) Save(b []byte) error {
	p.writes++
	if p.err == nil || p.retain {
		p.data = bytes.Clone(b)
	}
	return p.err
}

// Retained/lost model the ambiguous commit outcome, not an actual power failure.
func TestAdmissionCheckedSaveOutcomes(t *testing.T) {
	bridge := errors.Join(blobstore.ErrSavedWithoutAtomicity, blobstore.ErrDurabilityUnconfirmed)
	for _, tc := range []struct {
		name             string
		err              error
		retain, accepted bool
	}{
		{"atomic", nil, true, true},
		{"synced_in_place", blobstore.ErrSavedWithoutAtomicity, true, true},
		{"no_write", errors.New("private storage error"), false, false},
		{"error_after_write", errors.New("private storage error"), true, false},
		{"unconfirmed_lost", blobstore.ErrDurabilityUnconfirmed, false, false},
		{"unconfirmed_retained", blobstore.ErrDurabilityUnconfirmed, true, false},
		{"bridge_lost", bridge, false, false}, {"bridge_retained", bridge, true, false},
		{"wrapped_lost", fmt.Errorf("private path: %w", bridge), false, false},
		{"wrapped_retained", fmt.Errorf("private path: %w", bridge), true, false},
	} {
		for _, action := range []string{"revoke", "restore"} {
			t.Run(tc.name+"/"+action, func(t *testing.T) {
				p := &admissionSavePersister{}
				a := NewAdmissionRevocations()
				a.SetPersister(p)
				a.Revoke("foreign", "foreign block")
				a.RevokeFromMesh("mesh-only", "mesh block")
				a.ReplaceSynced(map[string]string{"synced-only": "synced block"})
				if action == "restore" {
					a.Revoke(" OWNED ", "prior")
				}
				gen := a.ConfigGeneration()
				reported, meshed, closed := 0, 0, 0
				a.SetReporter(func(id, reason string) {
					if id != "owned" {
						t.Error("unnormalized callback")
					}
					reported++
				})
				a.SetMeshReporter(func(id, reason string) { meshed++ })
				// A callback can safely query the overlay: never invoked under its mutex.
				a.SetOnRevoked(func(id, reason string) {
					if _, ok := a.IsRevoked(id); !ok {
						t.Error("callback before block")
					}
					closed++
				})
				p.err, p.retain = tc.err, tc.retain
				mutate := func() error {
					if action == "revoke" {
						return a.RevokeChecked(" OWNED ", " incident ")
					}
					return a.RestoreChecked(" OWNED ")
				}
				err := mutate()
				if (err == nil) != tc.accepted {
					t.Fatalf("error=%v accepted=%v", err, tc.accepted)
				}
				if err != nil && err != ErrAdmissionSave {
					t.Fatal("private error escaped")
				}
				changed := action == "revoke" || tc.accepted
				wantGen := gen
				if changed {
					wantGen++
				}
				if a.ConfigGeneration() != wantGen {
					t.Fatal("generation differs from published state")
				}
				_, blocked := a.IsRevoked("owned")
				if blocked != (action == "revoke" || !tc.accepted) {
					t.Fatal("failed restore relaxed or failed revoke did not restrict")
				}
				wantCalls := 0
				if action == "revoke" {
					wantCalls = 1
				}
				if reported != wantCalls || meshed != wantCalls || closed != wantCalls {
					t.Fatal("callback contract changed")
				}
				reopened := NewAdmissionRevocations()
				reopened.SetPersister(p)
				_, savedBlock := reopened.IsRevoked("owned")
				wantSaved := action == "restore"
				if tc.retain {
					wantSaved = action == "revoke"
				}
				if savedBlock != wantSaved {
					t.Fatal("retained/lost restore assumption wrong")
				}
				if r, ok := reopened.IsRevoked("foreign"); !ok || r != "foreign block" {
					t.Fatal("foreign changed")
				}
				if _, ok := reopened.IsRevoked("mesh-only"); !ok {
					t.Fatal("mesh persistence changed")
				}
				if _, ok := a.IsRevoked("synced-only"); !ok {
					t.Fatal("synced changed")
				}
				p.err = nil
				beforeRetry := a.ConfigGeneration()
				writes := p.writes
				if err := mutate(); err != nil {
					t.Fatal(err)
				}
				if p.writes != writes+1 {
					t.Fatal("explicit retry did not save")
				}
				if action == "restore" && !tc.accepted {
					beforeRetry++
				}
				if a.ConfigGeneration() != beforeRetry {
					t.Fatal("retry generation churn")
				}
				if reported != wantCalls || meshed != wantCalls || closed != wantCalls {
					t.Fatal("retry repeated callback")
				}
				reopened = NewAdmissionRevocations()
				reopened.SetPersister(p)
				if !reflect.DeepEqual(a.Snapshot(), reopened.Snapshot()) {
					t.Fatal("retry not recoverable")
				}
				// Both legacy and checked restore leave other enforcement layers untouched.
				a.Restore("mesh-only")
				if err := a.RestoreChecked("synced-only"); err != nil {
					t.Fatal(err)
				}
				for _, id := range []string{"mesh-only", "synced-only"} {
					if _, ok := a.IsRevoked(id); !ok {
						t.Fatal("cleared another layer")
					}
				}
			})
		}
	}
}

func TestAdmissionAutomaticRevokeAndLegacyRestoreSaveContract(t *testing.T) {
	p := &admissionSavePersister{}
	a := NewAdmissionRevocations()
	a.SetPersister(p)
	a.Revoke("device", "block")
	gen, writes := a.ConfigGeneration(), p.writes
	p.err = errors.New("offline")
	a.Revoke("device", "block")
	if a.ConfigGeneration() != gen || p.writes != writes {
		t.Fatal("automatic no-op churn")
	}
	a.Restore("device")
	if _, ok := a.IsRevoked("device"); !ok || a.ConfigGeneration() != gen {
		t.Fatal("legacy restore ignored failed persistence")
	}
	if err := a.RevokeChecked("device", "block"); err != ErrAdmissionSave {
		t.Fatal("unchanged explicit block did not retry saving")
	}
	// An independent later save may persist the restrictive local block. The API
	// error must not promise rollback or that storage remained unchanged.
	p.err = nil
	a.Revoke("second", "later")
	reopened := NewAdmissionRevocations()
	reopened.SetPersister(p)
	if _, ok := reopened.IsRevoked("device"); !ok {
		t.Fatal("later snapshot lost block")
	}
}
