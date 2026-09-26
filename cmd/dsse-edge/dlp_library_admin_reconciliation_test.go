package main

import (
	"context"
	"errors"
	"github.com/lantern-networks/dsse-core/dlp"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func libraryHandler(c *dlpClassifierRuntimeStore, f *dlpFingerprintRuntimeStore) http.Handler {
	m := http.NewServeMux()
	registerDLPRoutes(m, func(_ string, h http.HandlerFunc) http.HandlerFunc { return h }, testEvaluator(), nil, nil, nil, nil, f, c, nil, nil, "")
	return m
}
func libraryRequest(h http.Handler, method, path, body, tenant string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r = r.WithContext(context.WithValue(r.Context(), adminIdentityContextKey{}, adminIdentity{PrincipalID: "admin", TenantID: tenant}))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func TestLibraryAdminRejectedReplacementPreservesLive(t *testing.T) {
	c := newDLPClassifierRuntimeStore()
	f := newDLPFingerprintRuntimeStore("fixture")
	cp, fp := &allowlistSaveFixture{}, &allowlistSaveFixture{}
	if err := c.SetPersister(cp); err != nil {
		t.Fatal(err)
	}
	if err := f.SetPersister(fp); err != nil {
		t.Fatal(err)
	}
	c.SetSpecs("own", []dlp.ClassifierSpec{{Name: "employee_id", Kind: "keyword", Keywords: []string{"EMPLOYEE"}}})
	f.SetDataset("own", "employees", []string{"EMPLOYEE123"})
	if err := c.PersistIfDirty(); err != nil {
		t.Fatal(err)
	}
	if err := f.PersistIfDirty(); err != nil {
		t.Fatal(err)
	}
	h := libraryHandler(c, f)
	for _, tt := range []struct{ path, body string }{{"/admin/dlp-classifiers", `{}`}, {"/admin/dlp-classifiers", `{"classifiers":null}`}, {"/admin/dlp-fingerprints", `{"name":"employees"}`}, {"/admin/dlp-fingerprints", `{"name":"employees","values":[]}`}} {
		t.Run(tt.path+tt.body, func(t *testing.T) {
			w := libraryRequest(h, "POST", tt.path, tt.body, "own")
			if w.Code != 400 {
				t.Errorf("incomplete replacement returned %d", w.Code)
			}
		})
	}
	if len(c.SpecsForTenant("own")) != 1 || len(f.DatasetsForTenant("own")) != 1 {
		t.Error("incomplete replacement erased saved definitions")
	}
}
func TestLibraryAdminFailedSavePreservesLive(t *testing.T) {
	for _, kind := range []string{"classifiers", "fingerprints"} {
		t.Run(kind, func(t *testing.T) {
			c := newDLPClassifierRuntimeStore()
			f := newDLPFingerprintRuntimeStore("fixture")
			p := &allowlistSaveFixture{}
			var path, body string
			if kind == "classifiers" {
				c.SetPersister(p)
				c.SetSpecs("own", []dlp.ClassifierSpec{{Name: "employee_id", Kind: "keyword", Keywords: []string{"EMPLOYEE"}}})
				c.PersistIfDirty()
				path = "/admin/dlp-classifiers"
				body = `{"classifiers":[]}`
			} else {
				f.SetPersister(p)
				f.SetDataset("own", "employees", []string{"EMPLOYEE123"})
				f.PersistIfDirty()
				path = "/admin/dlp-fingerprints?name=employees"
			}
			p.err = errors.New("private storage detail")
			method := "POST"
			if kind == "fingerprints" {
				method = "DELETE"
			}
			w := libraryRequest(libraryHandler(c, f), method, path, body, "own")
			if w.Code != 500 || strings.Contains(w.Body.String(), "private storage detail") {
				t.Errorf("save failure status/body: %d %s", w.Code, w.Body)
			}
			if kind == "classifiers" && len(c.SpecsForTenant("own")) != 1 || kind == "fingerprints" && len(f.DatasetsForTenant("own")) != 1 {
				t.Error("failed save changed live definitions")
			}
		})
	}
}
