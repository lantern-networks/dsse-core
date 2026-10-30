package main

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/grantstore"
)

type authAmbiguousCommit struct {
	authLocalAuthority
	commit, failRead, revoke, changeSubject bool
	writes                                  int
}

func (a *authAmbiguousCommit) Load() ([]byte, error) {
	if a.failRead && a.writes > 0 {
		return nil, errors.New("authority unavailable")
	}
	return a.authLocalAuthority.Load()
}
func (a *authAmbiguousCommit) UpdateContext(ctx context.Context, f func([]byte) ([]byte, error)) error {
	a.writes++
	if a.commit {
		if err := a.authLocalAuthority.UpdateContext(ctx, f); err != nil {
			return err
		}
		if a.revoke || a.changeSubject {
			var snapshot struct {
				Version int                         `json:"schema_version"`
				Grants  map[string]grantstore.Grant `json:"grants"`
			}
			_ = json.Unmarshal(a.raw, &snapshot)
			for id, g := range snapshot.Grants {
				g.Revoked = a.revoke
				if a.changeSubject {
					g.UserID = "other-user"
				}
				snapshot.Grants[id] = g
			}
			a.raw, _ = json.Marshal(snapshot)
		}
	}
	return errors.New("commit acknowledgement unavailable")
}

func TestAuthGrantAmbiguousCommitReconciliation(t *testing.T) {
	for _, test := range []struct {
		name                                            string
		commit, failRead, revoke, changeSubject, wantOK bool
	}{
		{"committed", true, false, false, false, true},
		{"not-committed", false, false, false, false, false},
		{"read-failed", true, true, false, false, false},
		{"revoked-before-readback", true, false, true, false, false},
		{"different-identity", true, false, false, true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			a := &authAmbiguousCommit{commit: test.commit, failRead: test.failRead, revoke: test.revoke, changeSubject: test.changeSubject}
			s := grantstore.NewStore()
			if err := s.SetPersister(a); err != nil {
				t.Fatal(err)
			}
			g, err := mintAuthenticationGrant(context.Background(), s, grantstore.Grant{GrantID: "unique-attempt", TenantID: "tenant", UserID: "user", DeviceID: "device", Scope: "app:22"}, time.Minute, time.Now())
			if (err == nil) != test.wantOK {
				t.Fatalf("success=%v want=%v", err == nil, test.wantOK)
			}
			if test.wantOK && g.GrantID != "unique-attempt" {
				t.Fatal("different grant returned")
			}
			if a.writes != 1 {
				t.Fatal("ambiguous commit retried a write")
			}
		})
	}
}
