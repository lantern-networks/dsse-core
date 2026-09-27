package main

import (
	"encoding/json"

	"testing"
)

type gatedOrgDomainPersister struct {
	entered, release chan struct{}
	writes           int
	data             []byte
}

func (p *gatedOrgDomainPersister) Load() ([]byte, error) { return nil, nil }
func (p *gatedOrgDomainPersister) Save(b []byte) error {
	p.writes++
	if p.writes == 1 {
		close(p.entered)
		<-p.release
	}
	p.data = append([]byte(nil), b...)
	return nil
}

func TestOrganizationDomainsPeriodicFlushCannotOverwriteAdminCommit(t *testing.T) {
	p := &gatedOrgDomainPersister{entered: make(chan struct{}), release: make(chan struct{})}
	s := newOrganizationDomainsStore()
	if err := s.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	s.SetDomains("one", []string{"old.example"})
	flushed := make(chan error, 1)
	go func() { flushed <- s.PersistIfDirty() }()
	<-p.entered
	committed := make(chan error, 1)
	go func() { _, err := s.SetDomainsDurable("one", []string{"new.example"}); committed <- err }()
	close(p.release)
	if err := <-flushed; err != nil {
		t.Fatal(err)
	}
	if err := <-committed; err != nil {
		t.Fatal(err)
	}
	var snap organizationDomainsSnapshot
	if err := json.Unmarshal(p.data, &snap); err != nil {
		t.Fatal(err)
	}
	if p.writes != 2 || len(snap.ByTenant["one"]) != 1 || snap.ByTenant["one"][0] != "new.example" {
		t.Fatal("older periodic snapshot overwrote acknowledged admin value")
	}
	if got := s.Domains("one"); len(got) != 1 || got[0] != "new.example" || s.dirty {
		t.Fatal("live state differs from committed state")
	}
}
