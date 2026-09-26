package main

import (
	"errors"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/model"
)

type dlpOutcomeWriter struct {
	blobstore.FilePersister
	result error
	write  bool
}

func (p *dlpOutcomeWriter) Save(raw []byte) error {
	if p.write {
		if err := p.FilePersister.Save(raw); err != nil {
			return err
		}
	}
	return p.result
}
func TestDLPDurableSaveOutcomeKeepsLiveAndReloadAligned(t *testing.T) {
	for _, op := range []string{"upsert", "delete"} {
		for _, kind := range []string{"synced_in_place", "replaced_unconfirmed", "not_written"} {
			t.Run(op+"/"+kind, func(t *testing.T) {
				p := &dlpOutcomeWriter{FilePersister: blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "dlp.json")}, write: true}
				s := newDLPPolicyObjectStore()
				if err := s.SetPersister(p); err != nil {
					t.Fatal(err)
				}
				row := model.DLPPolicyObject{ID: "policy", TenantID: "tenant", Name: "before", Identifiers: []string{"credit_card"}, Status: "active", OnMatch: "block"}
				if err := s.UpsertDurable(row); err != nil {
					t.Fatal(err)
				}
				before := s.generation
				switch kind {
				case "synced_in_place":
					p.result = blobstore.ErrSavedWithoutAtomicity
				case "replaced_unconfirmed":
					p.result = blobstore.ErrDurabilityUnconfirmed
				case "not_written":
					p.result = errors.New("cannot write")
					p.write = false
				}
				var err error
				if op == "delete" {
					_, err = s.DeleteDurable(row.TenantID, row.ID)
				} else {
					row.Name = "after"
					err = s.UpsertDurable(row)
				}
				if (err == nil) != (kind == "synced_in_place") {
					t.Fatalf("wrong result: %v", err)
				}
				fresh := newDLPPolicyObjectStore()
				if err := fresh.SetPersister(p); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(s.List("tenant"), fresh.List("tenant")) {
					t.Fatal("live state differs from restart state")
				}
				if (s.generation > before) != (kind != "not_written") {
					t.Fatal("generation does not reflect visible change")
				}
				if kind == "replaced_unconfirmed" {
					if !s.dirty {
						t.Fatal("unconfirmed replacement not scheduled for retry")
					}
					p.result = nil
					p.write = true
					if err := s.PersistIfDirty(); err != nil || s.dirty {
						t.Fatal("retry did not confirm save", err)
					}
				}
			})
		}
	}
}
