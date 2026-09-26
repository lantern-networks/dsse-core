package main

import (
	"encoding/json"
	"github.com/lantern-networks/dsse-core/model"
	"testing"
)

type gatedDLPPolicyPersister struct {
	entered, release chan struct{}
	writes           int
	data             []byte
}

func (p *gatedDLPPolicyPersister) Load() ([]byte, error) { return nil, nil }
func (p *gatedDLPPolicyPersister) Save(b []byte) error {
	p.writes++
	if p.writes == 1 {
		close(p.entered)
		<-p.release
	}
	p.data = append([]byte(nil), b...)
	return nil
}

func TestDLPPolicyPeriodicFlushCannotOverwriteAdminCommit(t *testing.T) {
	p := &gatedDLPPolicyPersister{entered: make(chan struct{}), release: make(chan struct{})}
	s := newDLPPolicyObjectStore()
	if err := s.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	obj := model.DLPPolicyObject{ID: "one", TenantID: "one", Name: "Old", Identifiers: []string{"email"}, OnMatch: "observe"}
	s.Upsert(obj)
	flushed := make(chan error, 1)
	go func() { flushed <- s.PersistIfDirty() }()
	<-p.entered
	obj.Name = "New"
	committed := make(chan error, 1)
	go func() { committed <- s.UpsertDurable(obj) }()
	close(p.release)
	if err := <-flushed; err != nil {
		t.Fatal(err)
	}
	if err := <-committed; err != nil {
		t.Fatal(err)
	}
	var snap dlpPolicyObjectSnapshot
	if err := json.Unmarshal(p.data, &snap); err != nil {
		t.Fatal(err)
	}
	if p.writes != 2 || snap.ByTenant["one"]["one"].Name != "New" {
		t.Fatal("older periodic snapshot overwrote acknowledged admin value")
	}
	if got, _ := s.Get("one", "one"); got.Name != "New" || s.dirty {
		t.Fatal("live state differs from committed state")
	}
}
