package main

import (
	"github.com/lantern-networks/dsse-core/knownbypass"
	"testing"
	"time"
)

func TestCatalogOverrideSharedPeerPreservation(t *testing.T) {
	p := &entitlementReviewPersister{}
	a, b := knownbypass.NewOverrideStore(), knownbypass.NewOverrideStore()
	for _, s := range []*knownbypass.OverrideStore{a, b} {
		if e := s.SetPersister(p); e != nil {
			t.Fatal(e)
		}
	}
	id := knownbypass.Catalog().Entries[0].ID
	for tenant, s := range map[string]*knownbypass.OverrideStore{"own": a, "foreign": b} {
		if _, e := s.Set(tenant, knownbypass.Override{EntryID: id, Mode: "force_inspect"}, time.Now()); e != nil {
			t.Fatal(e)
		}
	}
	restored := knownbypass.NewOverrideStore()
	if e := restored.SetPersister(p); e != nil {
		t.Fatal(e)
	}
	if len(restored.List("own")) != 1 || len(restored.List("foreign")) != 1 {
		t.Fatal("acknowledged tenant override erased by stale peer")
	}
}

func TestCatalogOverrideSharedFailureRefreshAndClear(t *testing.T) {
	p := &entitlementReviewPersister{}
	a, b := knownbypass.NewOverrideStore(), knownbypass.NewOverrideStore()
	for _, s := range []*knownbypass.OverrideStore{a, b} {
		if e := s.SetPersister(p); e != nil {
			t.Fatal(e)
		}
	}
	id := knownbypass.Catalog().Entries[0].ID
	if _, e := a.Set("own", knownbypass.Override{EntryID: id, Mode: "force_inspect"}, time.Now()); e != nil {
		t.Fatal(e)
	}
	if _, e := b.Set("foreign", knownbypass.Override{EntryID: id, Mode: "disabled"}, time.Now()); e != nil {
		t.Fatal(e)
	}
	p.fail = true
	if ok, e := a.Clear("own", id); e == nil || ok {
		t.Fatal("failed clear acknowledged")
	}
	if len(a.List("own")) != 1 {
		t.Fatal("failed clear changed live")
	}
	p.fail = false
	if ok, e := a.Clear("foreign", id); e != nil || !ok {
		t.Fatalf("latest-row clear %v %v", ok, e)
	}
	if changed, e := b.RefreshShared(); e != nil || !changed || len(b.List("own")) != 1 || len(b.List("foreign")) != 0 {
		t.Fatalf("refresh %v %v", changed, e)
	}
	saved := append([]byte(nil), p.raw...)
	for _, raw := range [][]byte{nil, []byte(`null`), []byte(`{"own":null}`)} {
		p.raw = raw
		if _, e := b.RefreshShared(); e == nil {
			t.Fatal("bad authority read as empty")
		}
		if _, e := b.Set("own", knownbypass.Override{EntryID: id, Mode: "disabled"}, time.Now()); e == nil {
			t.Fatal("bad authority overwritten")
		}
		if b.List("own")[0].Mode != "force_inspect" {
			t.Fatal("failure published")
		}
	}
	p.raw = saved
	if n, e := b.RemoveTenant("own"); e != nil || n != 1 {
		t.Fatalf("purge %d %v", n, e)
	}
	if _, e := a.RefreshShared(); e != nil || len(a.Snapshot()) != 0 {
		t.Fatalf("deleted value resurrected %v", e)
	}
}
