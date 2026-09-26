package revocation

import (
	"context"
	"errors"
	"testing"

	"github.com/lantern-networks/dsse-core/blobstore"
)

func TestAdmissionExplicitRetryRecoversMissingMeshIntent(t *testing.T) {
	for _, shared := range []bool{false, true} {
		t.Run(map[bool]string{false: "file-contract", true: "shared-contract"}[shared], func(t *testing.T) {
			file, db := &admissionSavePersister{}, &automaticSharedStore{}
			var p blobstore.Persister = file
			if shared {
				p = db
			}
			a := NewAdmissionRevocations()
			if err := a.SetPersister(p); err != nil {
				t.Fatal(err)
			}
			// Storage contains the origin block, but the delivery intent never ran.
			if _, err := a.RevokeCheckedContext(context.Background(), "target", "incident"); err != nil {
				t.Fatal(err)
			}
			a = NewAdmissionRevocations()
			if err := a.SetPersister(p); err != nil {
				t.Fatal(err)
			}
			gen := a.ConfigGeneration()
			calls := 0
			type key struct{}
			ctx := context.WithValue(context.Background(), key{}, "original authority")
			a.SetMeshReporterContext(func(got context.Context, id, reason string) {
				calls++
				if got != ctx || id != "target" || reason != "incident" {
					t.Error("lost request or target")
				}
				if _, ok := a.IsRevoked(id); !ok {
					t.Error("callback before local block")
				}
			})
			a.SetReporter(func(string, string) { t.Error("retry repeated node reporter") })
			a.SetOnRevoked(func(string, string) { t.Error("retry repeated session callback") })
			// A refused/unconfirmed retry must not renew a previously saved intent.
			file.err, db.failBefore = errors.New("offline"), true
			if _, err := a.RevokeCheckedContext(ctx, "target", "incident"); err == nil {
				t.Fatal("refusal accepted")
			}
			if calls != 0 {
				t.Fatal("refused retry dispatched")
			}
			file.err, db.failBefore, db.failAfter = nil, false, shared
			if shared {
				if _, err := a.RevokeCheckedContext(ctx, "target", "incident"); err == nil {
					t.Fatal("unconfirmed accepted")
				}
				if calls != 0 {
					t.Fatal("unconfirmed unchanged retry dispatched")
				}
			}
			db.failAfter = false
			if _, err := a.RevokeCheckedContext(ctx, " TARGET ", " incident "); err != nil {
				t.Fatal(err)
			}
			if calls != 1 {
				t.Fatalf("saved origin retry did not recover mesh delivery: calls=%d", calls)
			}
			if a.ConfigGeneration() != gen {
				t.Fatal("unchanged retry changed generation")
			}
			a.Revoke("target", "incident")
			a.SetOnRevoked(nil)
			if _, err := a.RevokeFromMeshChecked("peer-origin", "incident"); err != nil {
				t.Fatal(err)
			}
			if calls != 1 {
				t.Fatal("automatic duplicate or mesh reception re-pushed")
			}
		})
	}
}
