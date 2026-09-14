package main

import (
	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/logs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

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
			handler := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: writer, Registry: connector.NewRegistry(), RetentionOverride: store})
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
	for _, body := range []string{`{"stream":"audit","days":-2}`, `{"stream":"audit","days":106752}`} {
		store := newRetentionOverrideStore(nil)
		writer, err := logs.NewWriter(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		handler := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: writer, Registry: connector.NewRegistry(), RetentionOverride: store})
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/admin/retention-config", strings.NewReader(body)))
		if rec.Code != 400 || len(store.All()) != 0 {
			t.Fatal("invalid duration changed retention")
		}
	}
}
