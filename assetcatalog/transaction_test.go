package assetcatalog

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

type catalogTestWriter struct {
	data  []byte
	fail  bool
	saves int
}

func (p *catalogTestWriter) Load() ([]byte, error) { return append([]byte(nil), p.data...), nil }
func (p *catalogTestWriter) Save(b []byte) error {
	if p.fail {
		return errors.New("private storage failed")
	}
	p.saves++
	p.data = append([]byte(nil), b...)
	return nil
}

func catalogState(t *testing.T, s *Store) string {
	t.Helper()
	e, g, v := s.AuthoredSnapshot()
	b, err := json.Marshal([]any{e, g, v, s.aliases, s.seq, s.ConfigGeneration()})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func seedCatalogTransaction(t *testing.T) (*Store, *catalogTestWriter) {
	t.Helper()
	s := NewStore()
	p := &catalogTestWriter{}
	if err := s.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpsertEndpoint(Endpoint{ID: "ep", TenantID: "t", Alias: "endpoint", Kind: KindNetwork, Source: SourceManual, Address: "old.invalid", Tags: []string{"old"}}); err != nil {
		t.Fatal(err)
	}
	platform := "macos"
	steered := true
	if _, err := s.UpsertGroup(Group{ID: "g", TenantID: "t", Alias: "group", StaticMembers: []string{"ep"}, Dynamic: &MembershipRule{Platform: &platform, Steered: &steered}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpsertService(Service{ID: "svc", TenantID: "t", Alias: "service", Ports: []PortProto{{Protocol: "tcp", Port: 443}}}); err != nil {
		t.Fatal(err)
	}
	return s, p
}

func TestCatalogRejectedMutationsPreserveStateAndRetry(t *testing.T) {
	ops := map[string]func(*Store) error{
		"create endpoint": func(s *Store) error {
			_, e := s.UpsertEndpoint(Endpoint{TenantID: "t", Alias: "created", Kind: KindNetwork, Source: SourceManual})
			return e
		},
		"edit endpoint": func(s *Store) error {
			_, e := s.UpsertEndpoint(Endpoint{ID: "ep", TenantID: "t", Alias: "renamed", Kind: KindNetwork, Source: SourceManual, Address: "new.invalid"})
			return e
		},
		"delete endpoint": func(s *Store) error { _, e := s.DeleteEndpoint("t", "ep"); return e },
		"create group": func(s *Store) error {
			_, e := s.UpsertGroup(Group{TenantID: "t", Alias: "created", StaticMembers: []string{"ep"}})
			return e
		},
		"edit group":   func(s *Store) error { _, e := s.UpsertGroup(Group{ID: "g", TenantID: "t", Alias: "renamed"}); return e },
		"delete group": func(s *Store) error { _, e := s.DeleteGroup("t", "g"); return e },
		"create service": func(s *Store) error {
			_, e := s.UpsertService(Service{TenantID: "t", Alias: "created", Ports: []PortProto{{Protocol: "udp", Port: 443}}})
			return e
		},
		"edit service": func(s *Store) error {
			_, e := s.UpsertService(Service{ID: "svc", TenantID: "t", Alias: "renamed", Ports: []PortProto{{Protocol: "udp", Port: 443}}})
			return e
		},
		"delete service": func(s *Store) error { _, e := s.DeleteService("t", "svc"); return e },
		"replace": func(s *Store) error {
			_, e := s.ReplaceAuthored([]Endpoint{{TenantID: "t", ID: "next", Kind: KindNetwork}}, nil, nil)
			return e
		},
		"clear": func(s *Store) error { _, e := s.ReplaceAuthored(nil, nil, nil); return e },
	}
	for name, op := range ops {
		t.Run(name, func(t *testing.T) {
			s, p := seedCatalogTransaction(t)
			before := catalogState(t, s)
			saved := string(p.data)
			p.fail = true
			if err := op(s); !errors.Is(err, ErrPersistence) {
				t.Fatal("missing save error", err)
			}
			if catalogState(t, s) != before || string(p.data) != saved {
				t.Fatal("failed save changed state, aliases, sequence or generation")
			}
			p.fail = false
			if _, err := s.UpsertGroup(Group{TenantID: "other", ID: "unrelated", Alias: "unrelated"}); err != nil {
				t.Fatal(err)
			}
			reload := NewStore()
			if err := reload.SetPersister(p); err != nil {
				t.Fatal(err)
			}
			old := NewStore()
			if err := old.SetPersister(&catalogTestWriter{data: []byte(saved)}); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(reload.ListEndpoints("t"), old.ListEndpoints("t")) || !reflect.DeepEqual(reload.ListGroups("t"), old.ListGroups("t")) || !reflect.DeepEqual(reload.ListServices("t"), old.ListServices("t")) {
				t.Fatal("later tenant save contaminated the original tenant")
			}
			if err := op(s); err != nil {
				t.Fatal("retry", err)
			}
			reload = NewStore()
			if err := reload.SetPersister(p); err != nil {
				t.Fatal(err)
			}
			e, g, v := s.AuthoredSnapshot()
			re, rg, rv := reload.AuthoredSnapshot()
			if !reflect.DeepEqual(e, re) || !reflect.DeepEqual(g, rg) || !reflect.DeepEqual(v, rv) {
				t.Fatal("retry not durable")
			}
		})
	}
}

func TestCatalogBatchValidationAndCopies(t *testing.T) {
	s, p := seedCatalogTransaction(t)
	before := catalogState(t, s)
	writes := p.saves
	if _, err := s.ReplaceAuthored([]Endpoint{{ID: "valid", TenantID: "t", Kind: KindNetwork}}, nil, []Service{{TenantID: "t", ID: "bad"}}); err == nil {
		t.Fatal("invalid batch accepted")
	}
	if before != catalogState(t, s) || p.saves != writes {
		t.Fatal("partial batch published")
	}
	e, g, v := s.AuthoredSnapshot()
	e[0].Tags[0] = "changed"
	g[0].StaticMembers[0] = "changed"
	*g[0].Dynamic.Platform = "windows"
	*g[0].Dynamic.Steered = false
	v[0].Ports[0].Port = 22
	if before != catalogState(t, s) {
		t.Fatal("snapshot aliases live state")
	}
	e = s.ListEndpoints("t")
	g = s.ListGroups("t")
	v = s.ListServices("t")
	e[0].Tags[0] = "changed"
	g[0].StaticMembers[0] = "changed"
	v[0].Ports[0].Port = 22
	got, _ := s.GetEndpoint("t", "ep")
	got.Tags[0] = "changed"
	if before != catalogState(t, s) {
		t.Fatal("read aliases live state")
	}
	platform := "macos"
	input := Group{ID: "copy", TenantID: "t", Alias: "copy", StaticMembers: []string{"ep"}, Dynamic: &MembershipRule{Platform: &platform}}
	output, err := s.UpsertGroup(input)
	if err != nil {
		t.Fatal(err)
	}
	saved := catalogState(t, s)
	input.StaticMembers[0] = "input"
	platform = "windows"
	output.StaticMembers[0] = "output"
	*output.Dynamic.Platform = "linux"
	if saved != catalogState(t, s) {
		t.Fatal("input/output aliases live state")
	}
	if err := s.SetPersister(&catalogTestWriter{data: []byte("invalid")}); err == nil {
		t.Fatal("invalid load accepted")
	}
	if saved != catalogState(t, s) {
		t.Fatal("invalid load changed state")
	}
	p.fail = true
	if _, err := s.DeleteGroup("t", "copy"); !errors.Is(err, ErrPersistence) {
		t.Fatal("invalid load replaced original writer", err)
	}
}

func TestCatalogRealFileFailureKeepsDurableSnapshot(t *testing.T) {
	dir := t.TempDir()
	parent := filepath.Join(dir, "state")
	path := filepath.Join(parent, "assets.json")
	if err := os.MkdirAll(parent, 0700); err != nil {
		t.Fatal(err)
	}
	s := NewStore()
	if err := s.SetStatePath(path); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpsertGroup(Group{ID: "g", TenantID: "t", Alias: "old"}); err != nil {
		t.Fatal(err)
	}
	before := catalogState(t, s)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(parent, parent+"-saved"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(parent, []byte("not a directory"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpsertGroup(Group{ID: "g", TenantID: "t", Alias: "new"}); !errors.Is(err, ErrPersistence) {
		t.Fatal("save did not fail", err)
	}
	if before != catalogState(t, s) {
		t.Fatal("failed file save changed live state")
	}
	saved, err := os.ReadFile(filepath.Join(parent+"-saved", "assets.json"))
	if err != nil || string(saved) != string(data) {
		t.Fatal("original snapshot changed", err)
	}
	if err := os.Remove(parent); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(parent+"-saved", parent); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpsertGroup(Group{ID: "g", TenantID: "t", Alias: "new"}); err != nil {
		t.Fatal(err)
	}
	reload := NewStore()
	if err := reload.SetStatePath(path); err != nil {
		t.Fatal(err)
	}
	if got := reload.ListGroups("t"); len(got) != 1 || got[0].Alias != "new" {
		t.Fatal("retry not durable", got)
	}
}
