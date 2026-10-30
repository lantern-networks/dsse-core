package main

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestVerifyBreakGlassClosureRequiresAnExplicitRefusal(t *testing.T) {
	for _, status := range []int{0, 200, 401, 403, 404, 500, 503} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/admin/config-bundle" {
					if status == 0 {
						conn, _, err := w.(http.Hijacker).Hijack()
						if err != nil {
							t.Error(err)
							return
						}
						conn.Close()
						return
					}
					w.WriteHeader(status)
					return
				}
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{}`))
			}))
			defer server.Close()
			dir := t.TempDir()
			marker := runtimePath(dir, adminBootstrappedMarker)
			if err := os.MkdirAll(filepath.Dir(marker), 0700); err != nil {
				t.Fatal(err)
			}
			for path, body := range map[string][]byte{
				marker:                               []byte("fixture administrator created\n"),
				filepath.Join(dir, "deployment.env"): []byte("ADMIN_TOKEN=fixture-break-glass\n"),
				filepath.Join(dir, "deployment-anchor.pem"): pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}),
			} {
				if err := os.WriteFile(path, body, 0600); err != nil {
					t.Fatal(err)
				}
			}
			results := verifyDeployment(dir, server.URL, []string{server.URL}, server.URL, "", nil, true)
			for _, result := range results {
				if result.name == "the break-glass credential is no longer accepted" {
					want := status == http.StatusUnauthorized || status == http.StatusForbidden
					if result.ok != want || result.skipped {
						t.Fatalf("status %d: closure check ok=%t skipped=%t; want ok=%t", status, result.ok, result.skipped, want)
					}
					return
				}
			}
			t.Fatal("break-glass closure was not checked")
		})
	}
}
