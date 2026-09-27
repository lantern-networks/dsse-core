package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// Identical bytes do not establish which publication scope supplied them.
func TestConnectorProgramScopeTracksResolvedPublication(t *testing.T) {
	root := t.TempDir()
	body := []byte("same program in both scopes")
	own := connectorProgramTestMux(root, false, "own")
	other := connectorProgramTestMux(root, false, "other")
	if r := publishConnectorProgram(t, own, "linux", "amd64", body, sha256Of(body)); r.Code != 200 {
		t.Fatal(r.Code)
	}
	tenantDir, _ := connectorProgramDir(root, "own", "linux-amd64")
	sharedDir, _ := connectorProgramDeploymentDir(root, "linux-amd64")
	if err := os.MkdirAll(filepath.Dir(sharedDir), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tenantDir, sharedDir); err != nil {
		t.Fatal(err)
	}
	// A sidecar must not dictate the response source.
	raw, err := os.ReadFile(filepath.Join(sharedDir, connectorProgramMetaName))
	if err != nil {
		t.Fatal(err)
	}
	var meta map[string]any
	if err := json.Unmarshal(raw, &meta); err != nil {
		t.Fatal(err)
	}
	meta["source"] = "tenant"
	raw, _ = json.Marshal(meta)
	if err := os.WriteFile(filepath.Join(sharedDir, connectorProgramMetaName), raw, 0600); err != nil {
		t.Fatal(err)
	}
	check := func(t *testing.T, mux *http.ServeMux, tenant, source string) {
		t.Helper()
		list := httptest.NewRecorder()
		mux.ServeHTTP(list, httptest.NewRequest("GET", "/admin/connector-programs", nil))
		var got struct {
			TenantID string                    `json:"tenant_id"`
			Programs []connectorProgramListing `json:"programs"`
			Count    int                       `json:"count"`
		}
		if err := json.Unmarshal(list.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if list.Code != 200 || got.TenantID != tenant || got.Count != 1 || len(got.Programs) != 1 || got.Programs[0].Source != source {
			t.Fatalf("list: %d %s", list.Code, list.Body.String())
		}
		download := httptest.NewRecorder()
		mux.ServeHTTP(download, httptest.NewRequest("GET", "/admin/connector-program?platform=linux&arch=amd64", nil))
		if download.Code != 200 || download.Body.String() != string(body) || download.Header().Get("X-Dsse-Connector-Program-Tenant") != tenant || download.Header().Get("X-Dsse-Connector-Program-Source") != source || download.Header().Get("x-artifact-sha256") != got.Programs[0].SHA256 || download.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("download: %d %v", download.Code, download.Header())
		}
	}
	t.Run("shared", func(t *testing.T) { check(t, own, "own", "deployment"); check(t, other, "other", "deployment") })
	if r := publishConnectorProgram(t, own, "linux", "amd64", body, sha256Of(body)); r.Code != 200 {
		t.Fatal(r.Code)
	}
	t.Run("override", func(t *testing.T) { check(t, own, "own", "tenant"); check(t, other, "other", "deployment") })
	if err := os.RemoveAll(tenantDir); err != nil {
		t.Fatal(err)
	}
	t.Run("removed override exposes shared source", func(t *testing.T) { check(t, own, "own", "deployment") })
}

func TestConnectorProgramScopeOnEmptyCatalogueAndRejectedDownload(t *testing.T) {
	root := t.TempDir()
	for _, tenant := range []string{"own", ""} {
		mux := connectorProgramTestMux(root, false, tenant)
		r := httptest.NewRecorder()
		mux.ServeHTTP(r, httptest.NewRequest("GET", "/admin/connector-programs", nil))
		var body struct {
			TenantID string `json:"tenant_id"`
			Count    int    `json:"count"`
		}
		if err := json.Unmarshal(r.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if r.Code != 200 || body.TenantID != tenant || body.Count != 0 {
			t.Fatalf("empty: %s", r.Body.String())
		}
		r = httptest.NewRecorder()
		mux.ServeHTTP(r, httptest.NewRequest("GET", "/admin/connector-program?platform=linux&arch=amd64", nil))
		want := 404
		if tenant == "" {
			want = 403
		}
		if r.Code != want || r.Header().Get("X-Dsse-Connector-Program-Source") != "" {
			t.Fatalf("rejected: %d %v", r.Code, r.Header())
		}
	}
}
