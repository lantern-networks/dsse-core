package main

import (
	"errors"
	"github.com/lantern-networks/dsse-core/blobstore"
	"testing"
)

func TestDLPPolicyReceiverSaveRetryAndReload(t *testing.T) {
	cp, edge := dlpStoresForTest("cp"), dlpStoresForTest("edge")
	p := &allowlistSaveFixture{}
	if err := edge.policies.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	obj := policyLibraryFixture("own", "protect")
	if err := cp.policies.Upsert(obj); err != nil {
		t.Fatal(err)
	}
	p.err = errors.New("storage unavailable")
	if edge.Apply(cp.Snapshot()) == nil {
		t.Fatal("receiver ignored policy save error")
	}
	if len(edge.policies.List("own")) != 0 {
		t.Fatal("failed save published policy")
	}
	p.err = nil
	for _, status := range []string{"active", "disabled", "active", "deleted"} {
		if status == "deleted" {
			cp.policies.Delete("own", "protect")
		} else {
			obj.Status = status
			cp.policies.Upsert(obj)
		}
		if err := edge.Apply(cp.Snapshot()); err != nil {
			t.Fatal(err)
		}
		fresh := newDLPPolicyObjectStore()
		if err := fresh.SetPersister(p); err != nil {
			t.Fatal(err)
		}
		got, ok := fresh.Get("own", "protect")
		if status == "deleted" && ok || status != "deleted" && (!ok || got.Status != status) {
			t.Fatal("reloaded policy differs")
		}
	}
}
func TestDLPPolicyReplacedButUnconfirmedRetry(t *testing.T) {
	s := newDLPPolicyObjectStore()
	p := &policyReplacementFixture{}
	s.SetPersister(p)
	obj := policyLibraryFixture("own", "protect")
	if err := s.UpsertDurable(obj); err != nil {
		t.Fatal(err)
	}
	p.err = blobstore.ErrDurabilityUnconfirmed
	obj.Status = "disabled"
	if s.UpsertDurable(obj) == nil {
		t.Fatal("unconfirmed replacement reported success")
	}
	// Preserve the retained store contract: replacement is visible, but dirty until confirmed.
	got, _ := s.Get("own", "protect")
	if got.Status != "disabled" || !s.dirty {
		t.Fatal("replacement state lost")
	}
	p.err = nil
	if err := s.PersistIfDirty(); err != nil {
		t.Fatal(err)
	}
	fresh := newDLPPolicyObjectStore()
	if err := fresh.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	got, _ = fresh.Get("own", "protect")
	if got.Status != "disabled" {
		t.Fatal("retry lost replacement")
	}
}

type policyReplacementFixture struct{ allowlistSaveFixture }

func (p *policyReplacementFixture) Save(b []byte) error {
	p.data = append([]byte(nil), b...)
	return p.err
}
