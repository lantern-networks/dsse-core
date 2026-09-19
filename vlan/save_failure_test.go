package vlan

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/model"
)

type saveOutcome struct {
	file   blobstore.FilePersister
	result error
	write  bool
}

func (p *saveOutcome) Load() ([]byte, error) { return p.file.Load() }
func (p *saveOutcome) Save(raw []byte) error {
	if p.write {
		if err := p.file.Save(raw); err != nil {
			return err
		}
	}
	return p.result
}

func TestNetworkMutationsRequireConfirmedSave(t *testing.T) {
	for _, mutation := range []string{"object", "policy", "delete", "replace", "erase"} {
		for _, outcome := range []string{"refused", "unconfirmed", "confirmed-nonatomic"} {
			t.Run(mutation+"/"+outcome, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "networks.json")
				p := &saveOutcome{file: blobstore.FilePersister{Path: path}, write: true}
				s := NewStore()
				if err := s.SetPersister(p); err != nil {
					t.Fatal(err)
				}
				for _, tenant := range []string{"own", "other"} {
					if _, err := s.UpsertObject(model.VLANObject{ID: tenant, TenantID: tenant, Class: "server", CIDRs: []string{"10.1.0.0/24"}}); err != nil {
						t.Fatal(err)
					}
				}
				if _, err := s.UpsertPolicy(model.VLANBoundaryPolicy{ID: "own-policy", TenantID: "own", SourceClass: "server", DestClass: "server", Mode: "deny"}); err != nil {
					t.Fatal(err)
				}
				oldObjects, oldPolicies, gen := s.ListObjects(), s.ListPolicies(), s.ConfigGeneration()
				disk, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				switch outcome {
				case "refused":
					if err := os.Rename(path, path+".saved"); err != nil {
						t.Fatal(err)
					}
					if err := os.Mkdir(path, 0700); err != nil {
						t.Fatal(err)
					}
				case "unconfirmed":
					p.result = errors.Join(blobstore.ErrSavedWithoutAtomicity, blobstore.ErrDurabilityUnconfirmed)
				case "confirmed-nonatomic":
					p.result = blobstore.ErrSavedWithoutAtomicity
				}
				mutate := func() error {
					switch mutation {
					case "object":
						o := oldObjects[1]
						o.Name = "changed"
						_, err := s.UpsertObject(o)
						return err
					case "policy":
						o := oldPolicies[0]
						o.Mode = "warn"
						_, err := s.UpsertPolicy(o)
						return err
					case "delete":
						_, err := s.DeleteObject("own")
						return err
					case "replace":
						return s.ReplaceAll([]model.VLANObject{oldObjects[0]}, nil)
					case "erase":
						_, _, err := s.RemoveTenant("own")
						return err
					}
					panic("mutation")
				}
				err = mutate()
				if outcome != "confirmed-nonatomic" {
					if !errors.Is(err, ErrPersistence) {
						t.Fatalf("unconfirmed save accepted: %v", err)
					}
					if !reflect.DeepEqual(oldObjects, s.ListObjects()) || !reflect.DeepEqual(oldPolicies, s.ListPolicies()) || s.ConfigGeneration() != gen {
						t.Fatal("failed save published candidate")
					}
					if outcome == "refused" {
						got, e := os.ReadFile(path + ".saved")
						if e != nil || !bytes.Equal(got, disk) {
							t.Fatal("old disk changed")
						}
						if err := os.Remove(path); err != nil {
							t.Fatal(err)
						}
						if err := os.Rename(path+".saved", path); err != nil {
							t.Fatal(err)
						}
					}
					p.result = nil
					if err := mutate(); err != nil {
						t.Fatal(err)
					}
				} else if err != nil {
					t.Fatal(err)
				}
				if s.ConfigGeneration() != gen+1 {
					t.Fatal("incorrect generation")
				}
				reload := NewStore()
				if err := reload.SetPersister(p.file); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(s.ListObjects(), reload.ListObjects()) || !reflect.DeepEqual(s.ListPolicies(), reload.ListPolicies()) {
					t.Fatal("retry not durable")
				}
				if _, ok := reload.GetObject("other"); !ok {
					t.Fatal("other tenant changed")
				}
			})
		}
	}
}
