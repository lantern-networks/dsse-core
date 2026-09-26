package delegatedgrant

import (
	"bytes"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/model"
)

type rejectedLoadWriter struct {
	data    []byte
	loadErr error
	saves   int
}

func (p *rejectedLoadWriter) Load() ([]byte, error) { return p.data, p.loadErr }
func (p *rejectedLoadWriter) Save([]byte) error     { p.saves++; return nil }

func TestRejectedGrantLoadPreservesStateWriterAndGeneration(t *testing.T) {
	for _, tc := range []struct {
		name, raw string
		loadErr   error
	}{
		{name: "unavailable", loadErr: errors.New("fixture unavailable")},
		{name: "malformed", raw: `{"broken"`},
		{name: "null", raw: `null`},
		{name: "empty existing snapshot", raw: ""},
		{name: "array", raw: `[]`},
		{name: "foreign key", raw: `{"foreign\u0000same":{"id":"same","tenant_id":"own","status":"active"}}`},
		{name: "wrong legacy ID", raw: `{"wrong":{"id":"same","tenant_id":"own","status":"active"}}`},
		{name: "composite duplicate", raw: `{"same":{"id":"same","tenant_id":"own","status":"active"},"own\u0000same":{"id":"same","tenant_id":"own","status":"revoked"}}`},
		{name: "invalid tenant", raw: `{"same":{"id":"same","tenant_id":" own","status":"active"}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			good := blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "accepted.json")}
			s := NewStore(5)
			if e := s.SetPersister(good); e != nil {
				t.Fatal(e)
			}
			for _, tenant := range []string{"own", "foreign"} {
				if _, e := s.Upsert(sampleGrant(tenant, "retained")); e != nil {
					t.Fatal(e)
				}
			}
			if _, e := s.RevokeForTenant("own", "retained", "original denial", time.Now()); e != nil {
				t.Fatal(e)
			}
			diskBefore, _ := good.Load()
			generation := s.ConfigGeneration()
			candidate := &rejectedLoadWriter{data: []byte(tc.raw), loadErr: tc.loadErr}
			if e := s.SetPersister(candidate); e == nil {
				t.Fatal("unaccepted snapshot installed")
			}
			diskAfter, _ := good.Load()
			if !bytes.Equal(diskBefore, diskAfter) || s.ConfigGeneration() != generation {
				t.Fatal("failed load changed disk or generation")
			}
			own, ok := s.GetForTenant("own", "retained")
			other, otherOK := s.GetForTenant("foreign", "retained")
			if !ok || !otherOK || own.Status != "revoked" || other.Status != "active" || s.Count() != 2 {
				t.Fatal("failed load replaced authorization state")
			}
			if _, e := s.Upsert(sampleGrant("own", "later")); e != nil {
				t.Fatal(e)
			}
			if candidate.saves != 0 {
				t.Fatal("subsequent mutation reached rejected writer")
			}
			restarted := NewStore(5)
			if e := restarted.SetPersister(good); e != nil {
				t.Fatal(e)
			}
			if _, ok := restarted.GetForTenant("own", "later"); !ok {
				t.Fatal("later mutation missing from accepted writer")
			}
			revoked, ok := restarted.GetForTenant("own", "retained")
			if !ok || revoked.Status != "revoked" {
				t.Fatal("saved revocation changed")
			}
		})
	}
}

func TestGrantLoadAcceptsLegacyAndScopedSnapshotsWithoutDroppingTenants(t *testing.T) {
	g1 := sampleGrant("own", "shared")
	g1.Status = "revoked"
	g2 := sampleGrant("foreign", "shared")
	for _, legacy := range []bool{true, false} {
		t.Run(map[bool]string{true: "mixed legacy", false: "scoped"}[legacy], func(t *testing.T) {
			key := grantKey("own", "shared")
			if legacy {
				key = "shared"
			}
			raw, _ := json.Marshal(map[string]model.DelegatedAccessGrant{key: g1, grantKey("foreign", "shared"): g2})
			p := blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "grants.json")}
			if e := p.Save(raw); e != nil {
				t.Fatal(e)
			}
			s := NewStore(1)
			if e := s.SetPersister(p); e != nil {
				t.Fatal(e)
			}
			for _, expected := range []model.DelegatedAccessGrant{g1, g2} {
				got, ok := s.GetForTenant(expected.TenantID, expected.ID)
				if !ok || got.Status != expected.Status {
					t.Fatal("valid same-ID tenant record lost")
				}
			}
			if _, e := s.RevokeForTenant("foreign", "shared", "review", time.Now()); e != nil {
				t.Fatal(e)
			}
			saved, _ := p.Load()
			var scoped map[string]model.DelegatedAccessGrant
			if e := json.Unmarshal(saved, &scoped); e != nil {
				t.Fatal(e)
			}
			if len(scoped) != 2 || scoped[grantKey("own", "shared")].Status != "revoked" || scoped[grantKey("foreign", "shared")].Status != "revoked" {
				t.Fatal("normalized save lost valid records")
			}
		})
	}
}

func TestGrantWriterFirstBootEmptyAndExplicitDetach(t *testing.T) {
	s := NewStore(4)
	if _, e := s.Upsert(sampleGrant("own", "retained")); e != nil {
		t.Fatal(e)
	}
	if _, e := s.RevokeForTenant("own", "retained", "review", time.Now()); e != nil {
		t.Fatal(e)
	}
	p := blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "new.json")}
	if e := s.SetPersister(p); e != nil {
		t.Fatal(e)
	}
	if g, ok := s.GetForTenant("own", "retained"); !ok || g.Status != "revoked" {
		t.Fatal("missing first-boot snapshot cleared live data")
	}
	if _, e := s.Upsert(sampleGrant("own", "later")); e != nil {
		t.Fatal(e)
	}
	before, _ := p.Load()
	if e := s.SetStatePath(""); e != nil {
		t.Fatal(e)
	}
	if _, e := s.Upsert(sampleGrant("own", "volatile")); e != nil {
		t.Fatal(e)
	}
	after, _ := p.Load()
	if !bytes.Equal(before, after) {
		t.Fatal("explicit detach still writes")
	}
	// An explicit empty object is a valid empty store; null is not.
	empty := &rejectedLoadWriter{data: []byte(`{}`)}
	if e := s.SetPersister(empty); e != nil {
		t.Fatal(e)
	}
	if s.Count() != 0 {
		t.Fatal("valid empty snapshot not adopted")
	}
	if _, e := s.Upsert(sampleGrant("own", "fresh")); e != nil || empty.saves != 1 {
		t.Fatal("accepted empty writer not installed")
	}
}
