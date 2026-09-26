package assetcatalog

import (
	"bytes"
	"errors"
	"reflect"
	"testing"

	"github.com/lantern-networks/dsse-core/blobstore"
)

type rejectingCatalogPersister struct {
	raw  []byte
	fail bool
	weak bool
}

func (p *rejectingCatalogPersister) Load() ([]byte, error) {
	return bytes.Clone(p.raw), nil
}

func (p *rejectingCatalogPersister) Save(raw []byte) error {
	if p.fail {
		return errors.New("private-storage-location")
	}
	p.raw = bytes.Clone(raw)
	if p.weak {
		return blobstore.ErrSavedWithoutAtomicity
	}
	return nil
}

var _ blobstore.Persister = (*rejectingCatalogPersister)(nil)

func TestCatalogAcceptsSavedWithoutAtomicityAndReloads(t *testing.T) {
	p := &rejectingCatalogPersister{weak: true}
	s := NewStore()
	if err := s.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	group := Group{ID: "group-one", TenantID: "tenant-a", Alias: "operators"}
	service := Service{ID: "service-one", TenantID: "tenant-a", Alias: "ssh", Ports: []PortProto{{Protocol: "tcp", Port: 22}}}
	if _, err := s.UpsertGroup(group); err != nil {
		t.Fatalf("saved group was reported as failed: %v", err)
	}
	if _, err := s.UpsertService(service); err != nil {
		t.Fatalf("saved service was reported as failed: %v", err)
	}
	if s.ConfigGeneration() != 2 || len(s.ListGroups("tenant-a")) != 1 || len(s.ListServices("tenant-a")) != 1 {
		t.Fatal("saved create was not published to live readers")
	}
	reloaded := NewStore()
	if err := reloaded.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(reloaded.ListGroups("tenant-a"), s.ListGroups("tenant-a")) ||
		!reflect.DeepEqual(reloaded.ListServices("tenant-a"), s.ListServices("tenant-a")) {
		t.Fatal("saved create was not readable from a fresh store")
	}
	if _, err := s.DeleteGroup("tenant-a", group.ID); err != nil {
		t.Fatalf("saved group deletion was reported as failed: %v", err)
	}
	if _, err := s.DeleteService("tenant-a", service.ID); err != nil {
		t.Fatalf("saved service deletion was reported as failed: %v", err)
	}
	afterDelete := NewStore()
	if err := afterDelete.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	if len(afterDelete.ListGroups("tenant-a")) != 0 || len(afterDelete.ListServices("tenant-a")) != 0 ||
		len(s.ListGroups("tenant-a")) != 0 || len(s.ListServices("tenant-a")) != 0 || s.ConfigGeneration() != 4 {
		t.Fatal("saved deletion did not reach live and fresh readers")
	}
}

func TestGroupServiceMutationsDoNotPublishUnconfirmedSaves(t *testing.T) {
	type action struct {
		name  string
		seed  func(*Store) error
		apply func(*Store) error
	}
	group := Group{ID: "group-one", TenantID: "tenant-a", Alias: "group-one"}
	service := Service{ID: "service-one", TenantID: "tenant-a", Alias: "service-one", Ports: []PortProto{{Protocol: "tcp", Port: 443}}}
	seedGroup := func(s *Store) error { _, err := s.UpsertGroup(group); return err }
	seedService := func(s *Store) error { _, err := s.UpsertService(service); return err }
	cases := []action{
		{"create group", nil, func(s *Store) error {
			_, err := s.UpsertGroup(Group{TenantID: "tenant-a", Alias: "new-group"})
			return err
		}},
		{"edit group", seedGroup, func(s *Store) error {
			_, err := s.UpsertGroup(Group{ID: group.ID, TenantID: group.TenantID, Alias: "renamed-group"})
			return err
		}},
		{"delete group", seedGroup, func(s *Store) error { _, err := s.DeleteGroup(group.TenantID, group.ID); return err }},
		{"create service", nil, func(s *Store) error {
			_, err := s.UpsertService(Service{TenantID: "tenant-a", Alias: "new-service", Ports: []PortProto{{Protocol: "tcp", Port: 22}}})
			return err
		}},
		{"edit service", seedService, func(s *Store) error {
			_, err := s.UpsertService(Service{ID: service.ID, TenantID: service.TenantID, Alias: "renamed-service", Ports: []PortProto{{Protocol: "tcp", Port: 22}}})
			return err
		}},
		{"delete service", seedService, func(s *Store) error { _, err := s.DeleteService(service.TenantID, service.ID); return err }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &rejectingCatalogPersister{}
			s := NewStore()
			if err := s.SetPersister(p); err != nil {
				t.Fatal(err)
			}
			if tc.seed != nil {
				if err := tc.seed(s); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := s.UpsertGroup(Group{ID: "foreign", TenantID: "tenant-b", Alias: "foreign"}); err != nil {
				t.Fatal(err)
			}
			beforeGroups, beforeServices := s.ListGroups("tenant-a"), s.ListServices("tenant-a")
			beforeForeign, beforeGeneration, beforeRaw := s.ListGroups("tenant-b"), s.ConfigGeneration(), bytes.Clone(p.raw)
			p.fail = true
			if err := tc.apply(s); err == nil {
				t.Fatal("unconfirmed save succeeded")
			}
			if !reflect.DeepEqual(s.ListGroups("tenant-a"), beforeGroups) || !reflect.DeepEqual(s.ListServices("tenant-a"), beforeServices) ||
				!reflect.DeepEqual(s.ListGroups("tenant-b"), beforeForeign) || s.ConfigGeneration() != beforeGeneration || !bytes.Equal(p.raw, beforeRaw) {
				t.Fatal("unconfirmed save changed live catalog, another tenant, generation, or saved bytes")
			}
			p.fail = false
			if err := tc.apply(s); err != nil {
				t.Fatalf("retry: %v", err)
			}
			reloaded := NewStore()
			if err := reloaded.SetPersister(p); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(reloaded.ListGroups("tenant-a"), s.ListGroups("tenant-a")) ||
				!reflect.DeepEqual(reloaded.ListServices("tenant-a"), s.ListServices("tenant-a")) ||
				!reflect.DeepEqual(reloaded.ListGroups("tenant-b"), s.ListGroups("tenant-b")) {
				t.Fatal("confirmed retry was not readable from a fresh store")
			}
		})
	}
}
