package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func TestPostgresDLPAllowlistPeer(t *testing.T) {
	db := initialBlobDB(t)
	p := initialBlob(t, db, "dlp_allowlist_peer")
	a, b := newDLPAllowlistRuntimeStore("a"), newDLPAllowlistRuntimeStore("b")
	for _, s := range []*dlpAllowlistRuntimeStore{a, b} {
		if err := s.SetPersister(p); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.SetValuesDurable("own", []string{"safe@example.invalid"}); err != nil {
		t.Fatal(err)
	}
	if err := b.SetValuesDurable("other", []string{"other@example.invalid"}); err != nil {
		t.Fatal(err)
	}
	h := allowlistTestHandler(a)
	r := httptest.NewRequest("GET", "/admin/dlp-allowlist", nil)
	r = r.WithContext(context.WithValue(r.Context(), adminIdentityContextKey{}, adminIdentity{PrincipalID: "admin", TenantID: "other"}))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "other@example.invalid") {
		t.Fatal("peer read missing", w.Code, w.Body)
	}
	if err := a.SetValuesDurable("own", nil); err != nil {
		t.Fatal(err)
	}
	if err := b.RefreshShared(); err != nil {
		t.Fatal(err)
	}
	if len(b.ValuesForTenant("own")) != 0 || len(b.ValuesForTenant("other")) != 1 {
		t.Fatal("peer deletion lost")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := b.SetValuesContext(ctx, "other", nil); err == nil {
		t.Fatal("cancelled save accepted")
	}
	if err := b.SetValuesDurable("other", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", p.key); err != nil {
		t.Fatal(err)
	}
	if err := b.RefreshShared(); err == nil {
		t.Fatal("known empty authority disappeared unnoticed")
	}
	if err := b.SetValuesDurable("own", []string{"new@example.invalid"}); err == nil {
		t.Fatal("missing authority recreated")
	}
}
func TestAllowlistAdminTenantConflictAndRetry(t *testing.T) {
	p := &allowlistSaveFixture{}
	s := newDLPAllowlistRuntimeStore("salt")
	s.SetPersister(p)
	h := allowlistTestHandler(s)
	if r := allowlistRequest(h, `{"values":["foreign"],"expected_tenant_id":"other"}`); r.Code != 409 {
		t.Fatal(r.Code, r.Body)
	}
	for _, body := range []string{`{"values":["safe@example.invalid"]}`, `{"values":[]}`} {
		r := allowlistRequest(h, body)
		if r.Code != 200 {
			t.Fatal(r.Code, r.Body)
		}
		fresh := newDLPAllowlistRuntimeStore("other-salt")
		if err := fresh.SetPersister(p); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(fresh.ValuesForTenant("own"), s.ValuesForTenant("own")) {
			t.Fatal("reload differs")
		}
		var got map[string]any
		json.Unmarshal(r.Body.Bytes(), &got)
		if got["tenant_id"] != "own" {
			t.Fatal(got)
		}
	}
}
func TestDLPReceiverLibraryStoreRole(t *testing.T) {
	db := &sql.DB{}
	for _, key := range []string{"dlp_allowlist", "dlp_policy_objects", "dlp_classifiers", "dlp_fingerprints"} {
		p, err := dlpLibraryPersisterForRole("", db, key, "https://cp.example.test")
		if err != nil || p != nil {
			t.Fatal(key, err)
		}
		if _, err := dlpLibraryPersisterForRole("postgres", db, key, "https://cp.example.test"); err == nil {
			t.Fatal("receiver authority accepted")
		}
		p, err = dlpLibraryPersisterForRole("", db, key, "")
		if err != nil || !isDLPSharedPersister(p) {
			t.Fatal("CP shared store lost", err)
		}
	}
}
