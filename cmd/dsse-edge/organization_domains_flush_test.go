package main

import (
	"encoding/json"

	"github.com/lantern-networks/dsse-core/idpregistry"
	"testing"
	"time"
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

func TestCorporateDomainsRemainAvailableDuringAdministrativeSave(t *testing.T) {
	org := newOrganizationDomainsStore()
	p := &gatedOrgDomainPersister{entered: make(chan struct{}), release: make(chan struct{})}
	if err := org.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	org.SetDomains("one", []string{"old.example"})
	idp := idpregistry.NewStore()
	if _, err := idp.Upsert(idpregistry.Connection{TenantID: "one", IdPID: "oidc", Type: "oidc", Issuer: "https://idp.example", AuthorizationEndpoint: "https://idp.example/a", ClientID: "test", VerifiedDomains: []string{"verified.example"}}); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := org.SetDomainsDurable("one", []string{"new.example"}); done <- err }()
	<-p.entered
	released := false
	defer func() {
		if !released {
			close(p.release)
			<-done
		}
	}()
	resolver := corporateDomainsResolver(org, idp)
	answer := make(chan []string, 1)
	go func() { answer <- resolver("one") }()
	select {
	case got := <-answer:
		if dlpInstanceClass("person@old.example", got) != "corporate" || dlpInstanceClass("person@verified.example", got) != "corporate" {
			t.Fatal("last confirmed domains lost")
		}
	case <-time.After(time.Second):
		t.Fatal("flow classification blocked by storage")
	}
	close(p.release)
	released = true
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if got := resolver("one"); dlpInstanceClass("person@new.example", got) != "corporate" || dlpInstanceClass("person@old.example", got) == "corporate" {
		t.Fatal("successful edit not applied")
	}
	copy := idp.AppliedVerifiedDomains("one")
	copy[0] = "mutated.example"
	if idp.AppliedVerifiedDomains("one")[0] != "verified.example" {
		t.Fatal("runtime snapshot exposed")
	}
}
