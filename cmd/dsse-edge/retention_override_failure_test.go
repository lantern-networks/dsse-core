package main

import (
	"encoding/json"
	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/logs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLocalOnlyRetentionCannotPromiseDeletion(t *testing.T) {
	store := newRetentionOverrideStore(nil)
	handler := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Registry: connector.NewRegistry(), RetentionOverride: store})
	get := httptest.NewRecorder()
	handler.ServeHTTP(get, httptest.NewRequest(http.MethodGet, "/admin/retention-config", nil))
	if get.Code != http.StatusOK {
		t.Fatalf("local-only retention status=%d", get.Code)
	}
	var status struct {
		ArchiveEnabled bool `json:"archive_enabled"`
	}
	if err := json.Unmarshal(get.Body.Bytes(), &status); err != nil || status.ArchiveEnabled {
		t.Fatalf("local-only mode was reported as archive-enabled: %v", err)
	}
	post := httptest.NewRecorder()
	handler.ServeHTTP(post, httptest.NewRequest(http.MethodPost, "/admin/retention-config", strings.NewReader(`{"stream":"access","days":30}`)))
	if post.Code != http.StatusConflict || len(store.All()) != 0 {
		t.Fatalf("inert local-only retention setting was accepted: status=%d", post.Code)
	}
}

func TestLocalOnlyRetentionCanClearSavedOverride(t *testing.T) {
	store := newRetentionOverrideStore(nil)
	if err := store.Set("audit", 30); err != nil {
		t.Fatal(err)
	}
	handler := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Registry: connector.NewRegistry(), RetentionOverride: store})
	post := httptest.NewRecorder()
	handler.ServeHTTP(post, httptest.NewRequest(http.MethodPost, "/admin/retention-config", strings.NewReader(`{"stream":"audit","clear":true}`)))
	if post.Code != http.StatusOK || len(store.All()) != 0 {
		t.Fatalf("local-only clear failed: status=%d overrides=%v", post.Code, store.All())
	}
	var status struct {
		ArchiveEnabled bool `json:"archive_enabled"`
	}
	if err := json.Unmarshal(post.Body.Bytes(), &status); err != nil || status.ArchiveEnabled {
		t.Fatalf("local-only clear response advertised archive: %v", err)
	}
}

func TestRetentionOverrideSaveOutcome(t *testing.T) {
	for _, body := range []string{`{"stream":"audit","days":1}`, `{"stream":"audit","clear":true}`} {
		t.Run(body, func(t *testing.T) {
			p := &holdOutcomePersister{}
			store := newRetentionOverrideStore(p)
			if err := store.Set("audit", 365); err != nil {
				t.Fatal(err)
			}
			writer, err := logs.NewWriter(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			handler := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: writer, Registry: connector.NewRegistry(), RetentionOverride: store, ColdArchive: &fakeArchive{objs: map[string][]byte{}}})
			p.fail = true
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/admin/retention-config", strings.NewReader(body)))
			if rec.Code != 500 {
				t.Fatalf("status=%d", rec.Code)
			}
			for _, s := range []*retentionOverrideStore{store, newRetentionOverrideStore(p)} {
				if days, ok := s.Get("audit"); !ok || days != 365 {
					t.Fatal("failed save changed retention")
				}
			}
			rows, err := writer.ReadJSONL("audit.log.jsonl")
			if err != nil {
				t.Fatal(err)
			}
			if len(rows) != 1 || rows[0]["result"] != "error" {
				t.Fatal("failed save recorded success")
			}
			p.fail = false
			rec = httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/admin/retention-config", strings.NewReader(body)))
			if rec.Code != 200 {
				t.Fatal("retry failed")
			}
		})
	}
}

func TestRetentionOverrideRejectsInvalidDays(t *testing.T) {
	for _, body := range []string{`{"stream":"audit"}`, `{"stream":"audit","days":null}`, `{"stream":"audit","days":0.5}`, `{"stream":"audit","days":-2}`, `{"stream":"audit","days":106752}`} {
		store := newRetentionOverrideStore(nil)
		writer, err := logs.NewWriter(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		handler := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: writer, Registry: connector.NewRegistry(), RetentionOverride: store, ColdArchive: &fakeArchive{objs: map[string][]byte{}}})
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/admin/retention-config", strings.NewReader(body)))
		if rec.Code != 400 || len(store.All()) != 0 {
			t.Fatal("invalid duration changed retention")
		}
	}
}
