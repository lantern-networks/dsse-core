package main

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/logs"
)

func TestRetentionOverrideLoadFailurePreservesLogs(t *testing.T) {
	for _, data := range []string{"read_error", `{"audit":`, `null`, `{"audit":null}`, `{"audit":-1}`, `{"audit":106752}`, `{"audit":0,"audit":1}`, `{"":1}`, `{"audit":1} {}`} {
		t.Run(data, func(t *testing.T) {
			p := &unreadableHoldPersister{data: []byte(data)}
			if data == "read_error" {
				p.err = errors.New("private-location")
			}
			store := newRetentionOverrideStore(p)
			if store.Health() == nil {
				t.Fatal("unknown retention reported healthy")
			}
			cfg := retentionConfig{override: store, hotEvents: time.Hour, outboxPublished: time.Hour, outboxDead: time.Hour}
			for _, stream := range []string{"audit", "access", "another"} {
				if cfg.retentionForStream(stream) != 0 {
					t.Fatal("unknown retention fell back to deletion")
				}
			}
			// Any access to the nil DB would panic: no retention SQL may run.
			runRetentionPrune(context.Background(), nil, cfg)
			if err := store.Set("audit", 1); err == nil {
				t.Fatal("unreadable settings overwritten")
			}
			writer, err := logs.NewWriter(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			handler := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: writer, RetentionOverride: store})
			for _, method := range []string{"GET", "POST"} {
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, httptest.NewRequest(method, "/admin/retention-config", strings.NewReader(`{"stream":"audit","days":1}`)))
				if rec.Code != 503 {
					t.Fatalf("%s status=%d body=%s", method, rec.Code, rec.Body.String())
				}
				if strings.Contains(rec.Body.String(), "private-") {
					t.Fatal("private location leaked")
				}
			}
			rows, err := writer.ReadJSONL("audit.log.jsonl")
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, row := range rows {
				if row["event_type"] == "admin_config_change" && row["target_id"] == "/admin/retention-config" {
					found = true
					if row["result"] != "error" {
						t.Fatal("failed mutation audited as success")
					}
				}
			}
			if !found {
				t.Fatal("mutation audit missing")
			}
			if p.saves != 0 {
				t.Fatal("persisted settings changed")
			}
			p.err = nil
			p.data = []byte(`{"audit":0,"access":90}`)
			if store.Health() == nil {
				t.Fatal("health silently recovered without reload")
			}
			restored := newRetentionOverrideStore(p)
			if restored.Health() != nil {
				t.Fatal("valid reload failed")
			}
			cfg.override = restored
			if cfg.retentionForStream("audit") != 0 || cfg.retentionForStream("access") != 90*24*time.Hour || cfg.retentionForStream("other") != time.Hour {
				t.Fatal("restored policy incorrect")
			}
		})
	}
}

func TestRetentionOverrideEmptySnapshotIsConfiguredDefault(t *testing.T) {
	for _, data := range [][]byte{nil, []byte(`{}`)} {
		s := newRetentionOverrideStore(&unreadableHoldPersister{data: data})
		if s.Health() != nil {
			t.Fatal("empty initial snapshot rejected")
		}
		if err := s.Set("audit", 0); err != nil {
			t.Fatal(err)
		}
		if days, ok := s.Get("audit"); !ok || days != 0 {
			t.Fatal("zero did not mean forever")
		}
	}
	var absent *retentionOverrideStore
	if absent.Health() != nil {
		t.Fatal("optional store disabled pruning")
	}
}
