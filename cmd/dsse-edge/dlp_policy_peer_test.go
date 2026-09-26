package main

import (
	"context"
	"encoding/json"
	"github.com/lantern-networks/dsse-core/dlp"
	"strings"
	"testing"
)

func TestPostgresDLPPolicyPeerLifecycle(t *testing.T) {
	db := initialBlobDB(t)
	p := initialBlob(t, db, "dlp_policy_peer")
	cp := initialBlob(t, db, "dlp_policy_classifier")
	a, b := newDLPPolicyObjectStore(), newDLPPolicyObjectStore()
	c, d := newDLPClassifierRuntimeStore(), newDLPClassifierRuntimeStore()
	for _, s := range []*dlpPolicyObjectStore{a, b} {
		if err := s.SetPersister(p); err != nil {
			t.Fatal(err)
		}
	}
	for _, s := range []*dlpClassifierRuntimeStore{c, d} {
		if err := s.SetPersister(cp); err != nil {
			t.Fatal(err)
		}
	}
	if err := d.SetSpecsDurable("own", []dlp.ClassifierSpec{{Name: "employee_id", Kind: "keyword", Keywords: []string{"EMPLOYEE"}}}); err != nil {
		t.Fatal(err)
	}
	ha, hb := policyLibraryHandler(a, c, nil), policyLibraryHandler(b, d, nil)
	obj := policyLibraryFixture("own", "first")
	obj.Identifiers = []string{"employee_id"}
	raw, _ := json.Marshal(obj)
	if w := libraryRequest(ha, "POST", "/admin/dlp-policies", string(raw), "own"); w.Code != 200 {
		t.Fatal("peer detector not refreshed", w.Code, w.Body)
	}
	for _, tenant := range []string{"own", "foreign"} {
		obj := policyLibraryFixture(tenant, "second")
		raw, _ := json.Marshal(obj)
		if w := libraryRequest(hb, "POST", "/admin/dlp-policies", string(raw), tenant); w.Code != 200 {
			t.Fatal(w.Code, w.Body)
		}
	}
	for _, status := range []string{"disabled", "active"} {
		obj.Status = status
		obj.Name = "Renamed"
		raw, _ := json.Marshal(obj)
		if w := libraryRequest(ha, "POST", "/admin/dlp-policies", string(raw), "own"); w.Code != 200 {
			t.Fatal(w.Code, w.Body)
		}
		if w := libraryRequest(hb, "GET", "/admin/dlp-policies", "", "own"); w.Code != 200 || !strings.Contains(w.Body.String(), status) || !strings.Contains(w.Body.String(), "Renamed") {
			t.Fatal("peer read", w.Code, w.Body)
		}
	}
	if w := libraryRequest(ha, "DELETE", "/admin/dlp-policies?id=first", "", "own"); w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	if err := b.RefreshShared(); err != nil {
		t.Fatal(err)
	}
	if _, ok := b.Get("own", "first"); ok {
		t.Fatal("deleted policy remained")
	}
	if len(b.List("own")) != 1 || len(b.List("foreign")) != 1 {
		t.Fatal("peer policy erased")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if b.UpsertContext(ctx, obj) == nil {
		t.Fatal("cancelled save accepted")
	}
	for _, tenant := range []string{"own", "foreign"} {
		if _, err := b.DeleteDurable(tenant, "second"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", p.key); err != nil {
		t.Fatal(err)
	}
	if w := libraryRequest(hb, "GET", "/admin/dlp-policies", "", "own"); w.Code != 503 {
		t.Fatal("missing authority accepted", w.Code)
	}
	if err := b.UpsertDurable(obj); err == nil {
		t.Fatal("missing authority recreated")
	}
}
