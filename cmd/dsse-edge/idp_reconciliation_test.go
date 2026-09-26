package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/idpregistry"
)

func idpFixture(tenant, id string) idpregistry.Connection {
	return idpregistry.Connection{TenantID: tenant, IdPID: id, Issuer: "https://idp.example.invalid", AuthorizationEndpoint: "https://idp.example.invalid/authorize", ClientID: "synthetic-client", VerifiedDomains: []string{"example.invalid"}}
}
func idpHandler(s *idpregistry.Store) http.Handler {
	mux := http.NewServeMux()
	registerIdPConnectionsAdmin(mux, func(_ string, h http.HandlerFunc) http.HandlerFunc { return h }, s, "", nil)
	return mux
}
func idpWrite(t *testing.T, h http.Handler, c idpregistry.Connection, want int) {
	t.Helper()
	raw, _ := json.Marshal(c)
	w := libraryRequest(h, "POST", "/admin/idp-connections", string(raw), c.TenantID)
	if w.Code != want {
		t.Fatalf("IdP save: status=%d want=%d", w.Code, want)
	}
	if c.ClientSecret != "" && strings.Contains(w.Body.String(), c.ClientSecret) {
		t.Fatal("secret disclosed")
	}
}
func TestIdPAdminSaveFailureAndRetry(t *testing.T) {
	p := &allowlistSaveFixture{}
	s := idpregistry.NewStore()
	if err := s.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	h := idpHandler(s)
	a, b := idpFixture("own", "first"), idpFixture("own", "second")
	a.ClientSecret = "synthetic-secret-not-for-use"
	idpWrite(t, h, a, 200)
	idpWrite(t, h, b, 200)
	before := s.ListAll()
	defaults := s.DefaultsAll()
	p.err = errors.New("private storage detail")
	a.DisplayName = "Changed"
	idpWrite(t, h, a, 500)
	for _, op := range []struct{ method, path string }{{"POST", "/admin/idp-connections/second/default"}, {"DELETE", "/admin/idp-connections/second"}} {
		w := libraryRequest(h, op.method, op.path, "", "own")
		if w.Code != 500 || strings.Contains(w.Body.String(), "private storage detail") {
			t.Fatal("save failure not sanitized")
		}
	}
	if !reflect.DeepEqual(before, s.ListAll()) || !reflect.DeepEqual(defaults, s.DefaultsAll()) {
		t.Fatal("failed write changed live state")
	}
	p.err = nil
	idpWrite(t, h, a, 200)
	fresh := idpregistry.NewStore()
	if err := fresh.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	got, ok := fresh.Get("own", "first")
	if !ok || got.DisplayName != "Changed" {
		t.Fatal("successful retry not durable")
	}
}
func TestPostgresIdPPeerLifecycle(t *testing.T) {
	db := initialBlobDB(t)
	p := initialBlob(t, db, "idp_peer")
	a, b := idpregistry.NewStore(), idpregistry.NewStore()
	for _, s := range []*idpregistry.Store{a, b} {
		if err := s.SetPersister(p); err != nil {
			t.Fatal(err)
		}
	}
	ha, hb := idpHandler(a), idpHandler(b)
	first := idpFixture("own", "first")
	first.ClientSecret = "synthetic-peer-secret"
	idpWrite(t, hb, first, 200)
	idpWrite(t, hb, idpFixture("foreign", "keep"), 200)
	first.ClientSecret = ""
	first.DisplayName = "Edited"
	idpWrite(t, ha, first, 200)
	got, ok := b.Get("own", "first")
	if !ok || got.ClientSecret != "synthetic-peer-secret" {
		t.Fatal("blank peer edit lost secret")
	}
	idpWrite(t, hb, idpFixture("own", "second"), 200)
	if w := libraryRequest(hb, "POST", "/admin/idp-connections/second/default", "", "own"); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if w := libraryRequest(ha, "DELETE", "/admin/idp-connections/second", "", "own"); w.Code != 400 {
		t.Fatal("latest default guard ignored", w.Code)
	}
	if w := libraryRequest(ha, "GET", "/admin/idp-connections", "", "own"); w.Code != 200 || !strings.Contains(w.Body.String(), `"default_idp_id":"second"`) || !strings.Contains(w.Body.String(), "Edited") || strings.Contains(w.Body.String(), "synthetic-peer-secret") || strings.Contains(w.Body.String(), "foreign") {
		t.Fatal("peer read incorrect")
	}
	for _, id := range []string{"first", "second"} {
		if w := libraryRequest(ha, "DELETE", "/admin/idp-connections/"+id, "", "own"); w.Code != 200 {
			t.Fatal(w.Code)
		}
		section := idpConnectionBundleSection(b)
		if section == nil || !section.Complete {
			t.Fatal("peer bundle unavailable")
		}
		edge := idpregistry.NewStore()
		if _, _, err := applyIdPConnectionBundleSectionChecked(edge, section); err != nil {
			t.Fatal(err)
		}
		if _, ok := edge.Get("own", id); ok {
			t.Fatal("deleted IdP remained on Edge")
		}
		if _, ok := edge.Get("foreign", "keep"); !ok {
			t.Fatal("foreign connection erased")
		}
	}
	if _, err := db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", p.key); err != nil {
		t.Fatal(err)
	}
	if w := libraryRequest(hb, "GET", "/admin/idp-connections", "", "own"); w.Code != 503 {
		t.Fatal("missing authority returned empty success", w.Code)
	}
	if section := idpConnectionBundleSection(b); section.Complete {
		t.Fatal("missing authority published complete")
	}
	idpWrite(t, hb, idpFixture("own", "new"), 500)
}
func TestIdPReceiverSaveBeforeAcknowledgement(t *testing.T) {
	prev := theIdPRegistry.Load()
	t.Cleanup(func() { theIdPRegistry.Store(prev) })
	edge := idpregistry.NewStore()
	p := &allowlistSaveFixture{}
	if err := edge.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	theIdPRegistry.Store(edge)
	c := idpFixture("own", "provider")
	section := &idpConnectionBundle{Complete: true, Connections: []idpregistry.Connection{c}, Defaults: map[string]string{"own": "provider"}}
	src := configBundleSource{}
	p.err = errors.New("save unavailable")
	if _, err := src.apply(configBundlePayload{IdPConnections: section}, configApplyTargets{}); err == nil {
		t.Fatal("receiver acknowledged failed save")
	}
	if len(edge.ListAll()) != 0 {
		t.Fatal("failed received save published")
	}
	p.err = nil
	for _, empty := range []bool{false, true} {
		if empty {
			section = &idpConnectionBundle{Complete: true}
		}
		if _, err := src.apply(configBundlePayload{IdPConnections: section}, configApplyTargets{}); err != nil {
			t.Fatal(err)
		}
		fresh := idpregistry.NewStore()
		if err := fresh.SetPersister(p); err != nil {
			t.Fatal(err)
		}
		if len(fresh.ListAll()) == 0 != empty {
			t.Fatal("received state lost at restart")
		}
	}
	if _, err := src.apply(configBundlePayload{IdPConnections: &idpConnectionBundle{Complete: false}}, configApplyTargets{}); err == nil {
		t.Fatal("incomplete snapshot acknowledged")
	}
}

func TestIdPReceiverUsesNodeLocalStore(t *testing.T) {
	db := &sql.DB{}
	for _, value := range []string{"", filepath.Join(t.TempDir(), "idp.json")} {
		p, err := idpPersisterForRole(value, db, "https://cp.example.invalid")
		if err != nil {
			t.Fatal(err)
		}
		s := idpregistry.NewStore()
		if err := s.SetPersister(p); err != nil {
			t.Fatal(err)
		}
		if err := s.ReplaceAllChecked([]idpregistry.Connection{idpFixture("own", "a")}, map[string]string{"own": "a"}); err != nil {
			t.Fatal("receiver did not use node local storage", err)
		}
	}
	if _, err := idpPersisterForRole("postgres", db, "https://cp.example.invalid"); err == nil {
		t.Fatal("receiver allowed shared CP authority")
	}
}
