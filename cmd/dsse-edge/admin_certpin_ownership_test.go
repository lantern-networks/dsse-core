package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/lantern-networks/dsse-core/assetcatalog"
	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/edgeplane"
)

func TestCertPinEndpointCannotBeRetargetedThroughAssetAPI(t *testing.T) {
	for _, method := range []string{"POST", "DELETE"} {
		t.Run(method, func(t *testing.T) {
			dir := t.TempDir()
			ap := blobstore.FilePersister{Path: filepath.Join(dir, "assets.json")}
			f := newCertPinPartialFixture(t, blobstore.FilePersister{Path: filepath.Join(dir, "candidates.json")}, ap, blobstore.FilePersister{Path: filepath.Join(dir, "rules.json")}, "")
			if w := f.post("/admin/cert-pin-bypass", `{"host":"manual.example"}`); w.Code != 200 {
				t.Fatal(w.Code, w.Body)
			}
			before, _ := ap.Load()
			id := "certpin-ep-" + f.candidate.CandidateID
			forged, _ := json.Marshal(assetcatalog.Endpoint{ID: id, TenantID: f.tenant, Alias: "Manual resource", Kind: assetcatalog.KindNetwork, Address: "unreviewed.example", Source: assetcatalog.SourceManual})
			path := "/admin/assets/endpoints"
			if method == "DELETE" {
				path += "/" + id
			}
			req := httptest.NewRequest(method, path, bytes.NewReader(forged))
			req.AddCookie(&http.Cookie{Name: "admin_session", Value: "pin-session"})
			req.Header.Set("X-CSRF-Token", "pin-csrf")
			w := httptest.NewRecorder()
			f.handler.ServeHTTP(w, req)
			if w.Code != 403 {
				t.Fatalf("generic mutation must be refused: %d %s", w.Code, w.Body)
			}
			after, _ := ap.Load()
			if !bytes.Equal(before, after) {
				t.Fatal("refusal changed persistence")
			}
			restored := assetcatalog.NewStore()
			if err := restored.SetPersister(ap); err != nil {
				t.Fatal(err)
			}
			got, ok := restored.GetEndpoint(f.tenant, id)
			if !ok || got.Address != "manual.example" {
				t.Fatal("approved endpoint changed", got)
			}
			if f.inspect(f.tenant) || !f.engine.Matches(edgeplane.NetworkExtensionRuntimeCopyTCPRoute{TenantID: f.tenant, Host: "unreviewed.example", Port: 443}) {
				t.Fatal("bypass destination changed")
			}
			rows, err := f.writer.ReadJSONL("audit.log.jsonl")
			if err != nil {
				t.Fatal(err)
			}
			if len(rows) != 4 || rows[2]["result"] != "rejected" || rows[3]["result"] != "error" {
				t.Fatal("missing refusal audits", rows)
			}
		})
	}
}
