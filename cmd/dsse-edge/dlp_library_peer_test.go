package main

import (
	"context"
	"github.com/lantern-networks/dsse-core/dlp"
	"strings"
	"testing"
)

func TestPostgresDLPLibraryPeerCRUD(t *testing.T) {
	db := initialBlobDB(t)
	cp := initialBlob(t, db, "classifier_peer")
	fp := initialBlob(t, db, "fingerprint_peer")
	a, b := newDLPClassifierRuntimeStore(), newDLPClassifierRuntimeStore()
	x, y := newDLPFingerprintRuntimeStore("first"), newDLPFingerprintRuntimeStore("second")
	for _, s := range []*dlpClassifierRuntimeStore{a, b} {
		if err := s.SetPersister(cp); err != nil {
			t.Fatal(err)
		}
	}
	for _, s := range []*dlpFingerprintRuntimeStore{x, y} {
		if err := s.SetPersister(fp); err != nil {
			t.Fatal(err)
		}
	}
	ha, hb := libraryHandler(a, x), libraryHandler(b, y)
	for _, tenant := range []string{"own", "other"} {
		h := ha
		if tenant == "other" {
			h = hb
		}
		for _, row := range []struct{ path, body string }{{"/admin/dlp-classifiers", `{"classifiers":[{"name":"employee_id","kind":"keyword","keywords":["EMPLOYEE"]}]}`}, {"/admin/dlp-fingerprints", `{"name":"employees","values":["EMPLOYEE123"]}`}} {
			if w := libraryRequest(h, "POST", row.path, row.body, tenant); w.Code != 200 {
				t.Fatal(w.Code, w.Body)
			}
		}
	}
	for _, row := range []struct{ path, word string }{{"/admin/dlp-classifiers", "employee_id"}, {"/admin/dlp-fingerprints", "employees"}} {
		if w := libraryRequest(ha, "GET", row.path, "", "other"); w.Code != 200 || !strings.Contains(w.Body.String(), row.word) {
			t.Fatal("peer read", w.Code, w.Body)
		}
	}
	for _, row := range []struct{ method, path, body string }{
		{"POST", "/admin/dlp-classifiers", `{"classifiers":[{"name":"new_id","kind":"keyword","keywords":["NEWVALUE"]}]}`},
		{"POST", "/admin/dlp-fingerprints", `{"name":"employees","values":["NEWVALUE123"]}`},
		{"POST", "/admin/dlp-classifiers", `{"classifiers":[]}`},
		{"DELETE", "/admin/dlp-fingerprints?name=employees", ""},
	} {
		if w := libraryRequest(ha, row.method, row.path, row.body, "own"); w.Code != 200 {
			t.Fatal(w.Code, w.Body)
		}
	}
	if err := b.RefreshShared(); err != nil {
		t.Fatal(err)
	}
	if err := y.RefreshShared(); err != nil {
		t.Fatal(err)
	}
	if len(b.SpecsForTenant("own")) != 0 || len(y.DatasetsForTenant("own")) != 0 || len(b.SpecsForTenant("other")) != 1 || len(y.DatasetsForTenant("other")) != 1 {
		t.Fatal("delete lost peer state")
	}
	found := dlp.DetectWithOptions([]byte("EMPLOYEE123"), "text/plain", dlp.Options{Fingerprints: y.FingerprintSetForTenant("other")})
	if len(found) != 1 {
		t.Fatal("peer salt not adopted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if b.SetSpecsContext(ctx, "other", nil) == nil {
		t.Fatal("cancelled classifier save accepted")
	}
	if _, err := y.RemoveDatasetContext(ctx, "other", "employees"); err == nil {
		t.Fatal("cancelled dataset delete accepted")
	}
	if err := b.SetSpecsDurable("other", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := y.RemoveDatasetDurable("other", "employees"); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{cp.key, fp.key} {
		if _, err := db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", key); err != nil {
			t.Fatal(err)
		}
	}
	if b.RefreshShared() == nil || y.RefreshShared() == nil {
		t.Fatal("empty authority loss ignored")
	}
	for _, path := range []string{"/admin/dlp-classifiers", "/admin/dlp-fingerprints"} {
		if w := libraryRequest(hb, "GET", path, "", "other"); w.Code != 503 {
			t.Fatal("missing authority response", w.Code)
		}
	}
}
