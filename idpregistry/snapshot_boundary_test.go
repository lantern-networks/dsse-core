package idpregistry

import "testing"

func TestConnectionViewsDoNotMutateStoredDomains(t *testing.T) {
	s := NewStore()
	c := sampleConn("own", "a")
	c.VerifiedDomains = []string{"example.invalid"}
	saved, err := s.Upsert(c)
	if err != nil {
		t.Fatal(err)
	}
	views := []Connection{saved}
	got, _ := s.Get("own", "a")
	views = append(views, got)
	def, _ := s.Default("own")
	views = append(views, def)
	views = append(views, s.List("own")...)
	views = append(views, s.ListAll()...)
	rows, _, err := s.SnapshotAll()
	if err != nil {
		t.Fatal(err)
	}
	views = append(views, rows...)
	for _, v := range views {
		v.VerifiedDomains[0] = "changed.invalid"
	}
	got, _ = s.Get("own", "a")
	if got.VerifiedDomains[0] != "example.invalid" {
		t.Fatal("caller changed stored domain without saving")
	}
}
func TestReplacementRejectsInvalidCompleteSnapshot(t *testing.T) {
	s := NewStore()
	s.Upsert(sampleConn("own", "a"))
	generation := s.ConfigGeneration()
	for _, conns := range [][]Connection{{sampleConn("own", "a"), sampleConn("own", "a")}, {{TenantID: "own"}}} {
		if s.ReplaceAllChecked(conns, map[string]string{"own": "missing"}) == nil {
			t.Fatal("invalid snapshot accepted")
		}
		if len(s.ListAll()) != 1 || s.ConfigGeneration() != generation {
			t.Fatal("invalid replacement changed live state")
		}
	}
}
