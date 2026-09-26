package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

type allowlistSaveFixture struct {
	data []byte
	err  error
}

func (p *allowlistSaveFixture) Load() ([]byte, error) { return append([]byte(nil), p.data...), nil }
func (p *allowlistSaveFixture) Save(b []byte) error {
	if p.err != nil {
		return p.err
	}
	p.data = append([]byte(nil), b...)
	return nil
}
func allowlistTestHandler(s *dlpAllowlistRuntimeStore) http.Handler {
	m := http.NewServeMux()
	registerDLPRoutes(m, func(_ string, h http.HandlerFunc) http.HandlerFunc { return h }, testEvaluator(), nil, nil, s, nil, nil, nil, nil, nil, "")
	return m
}
func allowlistRequest(h http.Handler, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "/admin/dlp-allowlist", strings.NewReader(body))
	r = r.WithContext(context.WithValue(r.Context(), adminIdentityContextKey{}, adminIdentity{PrincipalID: "admin", TenantID: "own"}))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func TestAllowlistAdminIncompleteDoesNotClear(t *testing.T) {
	s := newDLPAllowlistRuntimeStore("salt")
	s.SetValues("own", []string{"safe@example.invalid"})
	h := allowlistTestHandler(s)
	for _, b := range []string{`{}`, `{"values":null}`} {
		r := allowlistRequest(h, b)
		if r.Code != 400 || len(s.ValuesForTenant("own")) != 1 {
			t.Fatalf("incomplete input cleared: %d %s", r.Code, r.Body)
		}
	}
}
func TestAllowlistAdminSaveFailurePreservesLive(t *testing.T) {
	p := &allowlistSaveFixture{}
	s := newDLPAllowlistRuntimeStore("salt")
	if err := s.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	s.SetValues("own", []string{"old@example.invalid"})
	if err := s.PersistIfDirty(); err != nil {
		t.Fatal(err)
	}
	p.err = errors.New("private storage failure")
	h := allowlistTestHandler(s)
	r := allowlistRequest(h, `{"values":["new@example.invalid"]}`)
	if r.Code != 500 || !reflect.DeepEqual(s.ValuesForTenant("own"), []string{"old@example.invalid"}) {
		t.Fatalf("failed save accepted: %d %s", r.Code, r.Body)
	}
}
func TestAllowlistRuntimeDistributionWiring(t *testing.T) {
	rt := buildDLPRuntime(serverConfig{})
	stores := &dlpConfigStores{policies: rt.policyObjects, classifiers: rt.classifiers, fingerprints: rt.fingerprints, allowlist: rt.allowlist}
	before := stores.Generation()
	rt.allowlist.SetValues("own", []string{"safe@example.invalid"})
	raw, _ := json.Marshal(stores.Snapshot())
	if stores.Generation() <= before || !strings.Contains(string(raw), "safe@example.invalid") {
		t.Fatal("allowlist edit absent from distributed generation/payload")
	}
}
