package revocation

import (
	"errors"
	"fmt"
	"github.com/lantern-networks/dsse-core/blobstore"
	"reflect"
	"testing"
)

func TestAdmissionRemovalSaveAndRetry(t *testing.T) {
	bridge := errors.Join(blobstore.ErrSavedWithoutAtomicity, blobstore.ErrDurabilityUnconfirmed)
	for _, tc := range []struct {
		name             string
		err              error
		retain, accepted bool
	}{
		{"atomic", nil, true, true}, {"in_place", blobstore.ErrSavedWithoutAtomicity, true, true},
		{"no_write", errors.New("private path"), false, false}, {"write_error", errors.New("private path"), true, false},
		{"unconfirmed_lost", blobstore.ErrDurabilityUnconfirmed, false, false}, {"unconfirmed_retained", blobstore.ErrDurabilityUnconfirmed, true, false},
		{"bridge_lost", bridge, false, false}, {"bridge_retained", bridge, true, false}, {"wrapped_bridge", fmt.Errorf("private path: %w", bridge), true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &admissionSavePersister{}
			a := NewAdmissionRevocations()
			a.SetPersister(p)
			a.Revoke("own", "local")
			a.Revoke("foreign", "keep")
			a.RevokeFromMesh("own", "peer")
			a.ReplaceSynced(map[string]string{"synced": "CP"})
			gen := a.ConfigGeneration()
			a.SetReporter(func(string, string) { t.Error("removal reported as revocation") })
			a.SetMeshReporter(func(string, string) { t.Error("removal repushed") })
			a.SetOnRevoked(func(string, string) { t.Error("removal callback") })
			p.err, p.retain = tc.err, tc.retain
			n, err := a.RemoveDevicesChecked([]string{" OWN ", "own", "missing"})
			if (err == nil) != tc.accepted || n != map[bool]int{true: 1, false: 0}[tc.accepted] {
				t.Fatal(n, err)
			}
			if err != nil && err != ErrAdmissionSave {
				t.Fatal("private error escaped")
			}
			_, exists := a.Snapshot()["own"]
			if exists == tc.accepted {
				t.Fatal("unconfirmed removal published")
			}
			if a.ConfigGeneration() != gen+map[bool]uint64{true: 1, false: 0}[tc.accepted] {
				t.Fatal("wrong generation")
			}
			reloaded := NewAdmissionRevocations()
			reloaded.SetPersister(p)
			_, saved := reloaded.Snapshot()["own"]
			if saved == tc.retain {
				t.Fatal("wrong disk outcome")
			}
			p.err = nil
			p.retain = true
			writes := p.writes
			if _, err := a.RemoveDevicesChecked([]string{"own"}); err != nil {
				t.Fatal(err)
			}
			if p.writes != writes+1 || a.ConfigGeneration() != gen+1 {
				t.Fatal("retry did not save or churned generation")
			}
			if reason, ok := a.IsRevoked("own"); !ok || reason != "peer" {
				t.Fatal("removed mesh layer")
			}
			if _, ok := a.IsRevoked("synced"); !ok {
				t.Fatal("lost synced layer")
			}
			reloaded = NewAdmissionRevocations()
			reloaded.SetPersister(p)
			if !reflect.DeepEqual(a.FeedSnapshot(), reloaded.FeedSnapshot()) || a.Snapshot()["foreign"] != "keep" {
				t.Fatal("reload or foreign mismatch")
			}
		})
	}
}
