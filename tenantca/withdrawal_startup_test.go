package tenantca

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestPendingWithdrawalFileRejectsAllSnapshotReaders(t *testing.T) {
	for _, trust := range []bool{false, true} {
		t.Run(map[bool]string{false: "attribution", true: "trust"}[trust], func(t *testing.T) {
			r := NewTenantCARegistry()
			c, _, pem := mkCA(t, "pending")
			_, _, peer := mkCA(t, "peer")
			if _, err := r.Register("own", pem); err != nil {
				t.Fatal(err)
			}
			if _, err := r.Register("peer", peer); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "registry.json")
			if err := r.Save(path); err != nil {
				t.Fatal(err)
			}
			fp := CAAnchorKey(c)
			if trust {
				r.BeginTrustWithdrawal("own", fp)
			} else {
				r.BeginWithdrawal("own", fp)
			}
			if err := r.SavePendingWithdrawals(path); err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = LoadTenantCARegistry(path); !errors.Is(err, ErrPendingWithdrawal) {
				t.Fatal(err)
			}
			if _, err = RegistryFromSnapshot(raw); !errors.Is(err, ErrPendingWithdrawal) {
				t.Fatal(err)
			}
			fresh := NewTenantCARegistry()
			if _, err = fresh.Adopt(raw); !errors.Is(err, ErrPendingWithdrawal) {
				t.Fatal(err)
			}
			if _, _, err = fresh.Reconcile(raw); !errors.Is(err, ErrPendingWithdrawal) {
				t.Fatal(err)
			}
			if len(fresh.Anchors()) != 0 {
				t.Fatal("pending snapshot mutated fresh registry")
			}
			if err = r.Save(path); err == nil {
				t.Fatal("ordinary save removed interlock")
			}
			if ok, _ := r.WithdrawAnchor("own", fp); !ok {
				t.Fatal("missing target")
			}
			// Completion is explicitly after the caller's required trust stage.
			if err = r.SaveWithdrawals(path, fp); err != nil {
				t.Fatal(err)
			}
			r.CompleteWithdrawal("own", fp)
			loaded, err := LoadTenantCARegistry(path)
			if err != nil {
				t.Fatal(err)
			}
			if loaded.Registrations()["own"] != 0 || loaded.Registrations()["peer"] != 1 {
				t.Fatal("bad completed view")
			}
		})
	}
}
