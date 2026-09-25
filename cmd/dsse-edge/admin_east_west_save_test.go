package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/policy"
)

type eastWestRejectingPersister struct {
	memoryPersister
	reject bool
}

func (p *eastWestRejectingPersister) Save(raw []byte) error {
	if p.reject {
		return errors.New("fixture storage refused")
	}
	return p.memoryPersister.Save(raw)
}

func TestEastWestHTTPConfirmedEditAndRetry(t *testing.T) {
	stored := &eastWestRejectingPersister{}
	s := policy.NewStore(nil)
	if err := s.SetRuntimeStatePersister(stored); err != nil {
		t.Fatal(err)
	}
	writer, err := logs.NewWriter(filepath.Join(t.TempDir(), "audit"))
	if err != nil {
		t.Fatal(err)
	}
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Registry: connector.NewRegistry(),
		AdminAuth: newAdminAuthStore(), PolicyStore: s, Writer: writer})
	call := func(method, body string, want int) []byte {
		t.Helper()
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(method, "/admin/east-west", strings.NewReader(body)))
		if rec.Code != want {
			t.Fatalf("%s status=%d want=%d body=%s", method, rec.Code, want, rec.Body.String())
		}
		return rec.Body.Bytes()
	}
	initial := `{"mode":"partial","rules":[{"id":"old","mode":"deny","protocols":["ssh"]}],"max_grant_ttl_seconds":60}`
	call(http.MethodPost, initial, http.StatusOK)
	before := append([]byte(nil), stored.blob...)
	badMode := `{"mode":"bad","rules":[{"id":"new","mode":"allow","protocols":["ssh"]}],"max_grant_ttl_seconds":120}`
	call(http.MethodPost, badMode, http.StatusBadRequest)
	if string(stored.blob) != string(before) {
		t.Fatal("invalid mode changed durable settings")
	}
	stored.reject = true
	update := strings.Replace(badMode, `"bad"`, `"full"`, 1)
	failedBody := call(http.MethodPost, update, http.StatusServiceUnavailable)
	if strings.Contains(string(failedBody), "fixture storage") || string(stored.blob) != string(before) {
		t.Fatal("failed save leaked detail or changed authority")
	}
	var got struct {
		Mode  string `json:"mode"`
		Rules []struct {
			ID string `json:"id"`
		} `json:"rules"`
		TTL int `json:"max_grant_ttl_seconds"`
	}
	if err := json.Unmarshal(call(http.MethodGet, "", http.StatusOK), &got); err != nil {
		t.Fatal(err)
	}
	if got.Mode != "partial" || len(got.Rules) != 1 || got.Rules[0].ID != "old" || got.TTL != 60 {
		t.Fatalf("failed edit was published: %+v", got)
	}
	stored.reject = false
	call(http.MethodPost, update, http.StatusOK)
	if err := json.Unmarshal(call(http.MethodGet, "", http.StatusOK), &got); err != nil {
		t.Fatal(err)
	}
	if got.Mode != "full" || len(got.Rules) != 1 || got.Rules[0].ID != "new" || got.TTL != 120 {
		t.Fatalf("retry not redisplayed: %+v", got)
	}
	reloaded := policy.NewStore(nil)
	if err := reloaded.SetRuntimeStatePersister(stored); err != nil {
		t.Fatal(err)
	}
	if !reloaded.EastWestIsEnabled("tenant_lab_001") || reloaded.EastWestAllowsUnmatched("tenant_lab_001") || reloaded.EastWestRulesFor("tenant_lab_001")[0].ID != "new" {
		t.Fatal("confirmed edit not durable")
	}
	rows, err := writer.ReadJSONL("audit.log.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	success, failed := 0, 0
	for _, row := range rows {
		if row["event_type"] != "admin_config_change" || row["target_id"] != "/admin/east-west" {
			continue
		}
		switch row["result"] {
		case "success":
			success++
		case "error":
			failed++
		}
	}
	if success != 2 || failed != 2 {
		t.Fatalf("audit success=%d error=%d", success, failed)
	}
}
