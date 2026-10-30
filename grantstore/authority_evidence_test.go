package grantstore

import (
	"errors"
	"github.com/lantern-networks/dsse-core/blobstore"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestOnlyAuthorityCanRestoreReleasedEvidence(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	for _, durable := range []bool{false, true} {
		t.Run(map[bool]string{false: "memory", true: "file"}[durable], func(t *testing.T) {
			s := NewStore()
			path := filepath.Join(t.TempDir(), "grants.json")
			if durable {
				if e := s.SetPersister(blobstore.FilePersister{Path: path}); e != nil {
					t.Fatal(e)
				}
			}
			old, e := s.Mint(grantFixture("issued", now), time.Hour, now)
			if e != nil {
				t.Fatal(e)
			}
			full := cloneGrant(old)
			full.Issuer = "https://idp.invalid"
			full.ProviderConfigSHA256 = strings.Repeat("a", 64)
			full.AuthTime = now.Format(time.RFC3339)
			if _, _, e = s.MergeChecked([]Grant{full}, now); !errors.Is(e, ErrConflict) {
				t.Fatal("ordinary report enriched evidence", e)
			}
			for _, change := range []func(*Grant){
				func(g *Grant) { g.UserID = "another" }, func(g *Grant) { g.DeviceID = "another" }, func(g *Grant) { g.Scope = "*" }, func(g *Grant) { g.IdPID = "another" }, func(g *Grant) { g.ACR = "stronger" }, func(g *Grant) { g.AMR = []string{"different"} }, func(g *Grant) { g.ExpiresAt = now.Add(2 * time.Hour).Format(time.RFC3339) }, func(g *Grant) { g.RequiredFeatures = []string{"future"} },
			} {
				bad := cloneGrant(full)
				change(&bad)
				if _, _, e = s.MergeAuthorityEvidence([]Grant{bad}, now); !errors.Is(e, ErrConflict) {
					t.Fatal("authority changed immutable authorization", e)
				}
			}
			gen := s.ConfigGeneration()
			if a, u, e := s.MergeAuthorityEvidence([]Grant{full}, now); e != nil || a != 0 || u != 1 {
				t.Fatalf("restore evidence: %d %d %v", a, u, e)
			}
			if s.ConfigGeneration() <= gen {
				t.Fatal("evidence upgrade did not advance generation")
			}
			got, _ := s.Get(old.GrantID)
			if !sameAuthorization(got, full) {
				t.Fatal("evidence not restored")
			}
			if durable {
				restarted := NewStore()
				if e := restarted.SetPersister(blobstore.FilePersister{Path: path}); e != nil {
					t.Fatal(e)
				}
				got, _ = restarted.Get(old.GrantID)
				if !sameAuthorization(got, full) {
					t.Fatal("evidence not durable")
				}
			}
			gen = s.ConfigGeneration()
			if a, u, e := s.MergeAuthorityEvidence([]Grant{full}, now); e != nil || a != 0 || u != 0 || gen != s.ConfigGeneration() {
				t.Fatal("replay changed evidence")
			}
			changed := cloneGrant(full)
			changed.AuthTime = now.Add(-time.Second).Format(time.RFC3339)
			if _, _, e = s.MergeAuthorityEvidence([]Grant{changed}, now); !errors.Is(e, ErrConflict) {
				t.Fatal("existing evidence was replaced", e)
			}
			if !s.Revoke(old.GrantID) {
				t.Fatal("revoke")
			}
			if _, _, e = s.MergeAuthorityEvidence([]Grant{full}, now); e != nil {
				t.Fatal(e)
			}
			if s.Valid(old.GrantID, now) {
				t.Fatal("evidence restored revoked access")
			}
		})
	}
}

func TestAuthorityEvidenceSaveFailureCannotAuthorize(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	s := NewStore()
	old, _ := s.Mint(grantFixture("issued", now), time.Hour, now)
	full := cloneGrant(old)
	full.Issuer = "https://idp.invalid"
	full.ProviderConfigSHA256 = strings.Repeat("a", 64)
	s.persister = authorityFailPersister{}
	if _, _, e := s.MergeAuthorityEvidence([]Grant{full}, now); e == nil {
		t.Fatal("save failure hidden")
	}
	got, _ := s.Get(old.GrantID)
	if !sameAuthorization(got, old) {
		t.Fatal("unsaved evidence became live")
	}
}

type authorityFailPersister struct{}

func (authorityFailPersister) Load() ([]byte, error) { return nil, nil }
func (authorityFailPersister) Save([]byte) error     { return errors.New("fixture save failure") }
