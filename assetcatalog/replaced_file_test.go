package assetcatalog

import (
	"errors"
	"github.com/lantern-networks/dsse-core/blobstore"
	"path/filepath"
	"reflect"
	"testing"
)

type replacementWriter struct {
	blobstore.FilePersister
	unconfirmed bool
}

func (p *replacementWriter) Save(raw []byte) error {
	if err := p.FilePersister.Save(raw); err != nil {
		return err
	}
	if p.unconfirmed {
		return blobstore.ErrDurabilityUnconfirmed
	}
	return nil
}

func TestReplacedCatalogMatchesReloadAndSurvivesNextEdit(t *testing.T) {
	for _, op := range []string{"create", "edit", "delete"} {
		t.Run(op, func(t *testing.T) {
			p := &replacementWriter{FilePersister: blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "catalog.json")}}
			s := NewStore()
			if err := s.SetPersister(p); err != nil {
				t.Fatal(err)
			}
			row := Group{ID: "g", TenantID: "own", Alias: "before"}
			if op != "create" {
				if _, err := s.UpsertGroup(row); err != nil {
					t.Fatal(err)
				}
			}
			p.unconfirmed = true
			var err error
			if op == "delete" {
				_, err = s.DeleteGroup("own", "g")
			} else {
				row.Alias = "after"
				_, err = s.UpsertGroup(row)
			}
			if !errors.Is(err, ErrPersistence) {
				t.Fatal("unconfirmed save acknowledged", err)
			}
			fresh := NewStore()
			if err := fresh.SetPersister(p); err != nil {
				t.Fatal(err)
			}
			expected := fresh.ListGroups("own")
			if !reflect.DeepEqual(s.ListGroups("own"), expected) {
				t.Fatal("live/reload differ")
			}
			p.unconfirmed = false
			if _, err := s.UpsertGroup(Group{ID: "other", TenantID: "other", Alias: "other"}); err != nil {
				t.Fatal(err)
			}
			final := NewStore()
			if err := final.SetPersister(p); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(final.ListGroups("own"), expected) {
				t.Fatal("next edit undid replacement")
			}
		})
	}
}
