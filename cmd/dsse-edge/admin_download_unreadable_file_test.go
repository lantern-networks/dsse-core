package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/logs"
)

type unreadableExportObjects struct{ path string }

func (u unreadableExportObjects) WriteGzipJSONL(string, []map[string]any) (string, error) {
	return "", errors.New("unused")
}
func (u unreadableExportObjects) WriteGzipJSONLStream(string, func() (map[string]any, bool, error)) (string, error) {
	return "", errors.New("unused")
}
func (u unreadableExportObjects) ReadGeneratedFile(string) ([]byte, error) {
	return nil, errors.New("read generated object: open " + u.path + ": no such file or directory")
}
func (u unreadableExportObjects) ListGeneratedFiles(string, string, int) ([]string, error) {
	return nil, nil
}

// A link minted where the payload could not be carried is spent before the file
// is read. When the file is then unreadable, the spend has taken effect: it must
// be audited, and the anonymous bearer must not be handed the server's file path.
func TestSpentDownloadWithUnreadableFileIsAuditedWithoutPath(t *testing.T) {
	dir := t.TempDir()
	w, err := logs.NewWriter(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	tokens := newAdminDownloadTokenStore()
	tok, err := tokens.Create(downloadTestJob("tenant_a"), "local-only.gz", "review", nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	secretPath := "/var/lib/dsse/private/exports/local-only.gz"
	mux := http.NewServeMux()
	registerAdminSessionRoutes(mux, func(_ string, next http.HandlerFunc) http.HandlerFunc { return next }, serverConfig{}, testEvaluator(), w, nil, newAdminAuthStore(), tokens, unreadableExportObjects{path: secretPath}, nil, true)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest("GET", "/admin/export-downloads/"+tok.Token, nil))
	if rr.Code != http.StatusNotFound || strings.Contains(rr.Body.String(), secretPath) || strings.Contains(rr.Body.String(), "no such file") {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body)
	}
	w.Close()
	audit, _ := os.ReadFile(filepath.Join(dir, "audit.log.jsonl"))
	if !strings.Contains(string(audit), "admin_export_download_failed") {
		t.Fatalf("spent link with no bytes left no audit record: %s", audit)
	}
	if strings.Contains(string(audit), tok.Token) {
		t.Fatal("audit record carries the bearer token")
	}
}

// A bind-mounted token file answers every save with ErrSavedWithoutAtomicity,
// after writing. Treating that as failure burned the link on disk (status "used")
// while the bearer got 503 and no bytes.
func TestDownloadTokenInPlaceSaveDeliversTheSpend(t *testing.T) {
	p := &checkedClassifierPersister{}
	s := newAdminDownloadTokenStore()
	if err := s.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	p.err = blobstore.ErrSavedWithoutAtomicity
	tok, err := s.Create(downloadTestJob("tenant_a"), "test.gz", "review", []byte("private-export"), time.Now())
	if err != nil {
		t.Fatalf("in-place save refused the new link: %v", err)
	}
	got, ok, err := s.ConsumeContext(context.Background(), tok.Token, time.Now())
	if err != nil || !ok || string(got.Payload) != "private-export" {
		t.Fatalf("in-place spend not delivered: ok=%v err=%v", ok, err)
	}
	if _, ok, _ := s.ConsumeContext(context.Background(), tok.Token, time.Now()); ok {
		t.Fatal("spent link served twice")
	}
}
