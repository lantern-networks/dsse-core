package main

import (
	"context"
	"encoding/json"
	"github.com/lantern-networks/dsse-core/eastwestobserve"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestPostgresObservationReadbackOnAnotherControlPlane(t *testing.T) {
	db := initialBlobDB(t)
	p := initialBlob(t, db, "observation_readback")
	sender, reader := eastwestobserve.NewStore(), eastwestobserve.NewStore()
	for _, s := range []*eastwestobserve.Store{sender, reader} {
		if err := s.SetPersister(p, 0); err != nil {
			t.Fatal(err)
		}
	}
	tenant := testEvaluator().PolicyBundle.TenantID
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := sender.ApplyReport(context.Background(), tenant, "edge", 1, []eastwestobserve.FlowObservation{{Source: "device", Destination: "db.example", Count: 3, Port: 22, ServiceFamily: "ssh", FirstSeen: now, LastSeen: now}}, time.Now()); err != nil {
		t.Fatal(err)
	}
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), AdminAuth: newAdminAuthStore(), EastWestObserveStore: reader})
	read := func() *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/admin/east-west/observations", nil))
		return w
	}
	w := read()
	var result struct {
		Observations []eastwestobserve.FlowObservation `json:"observations"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil || w.Code != 200 || len(result.Observations) != 1 || result.Observations[0].Count != 3 {
		t.Fatalf("peer read: %d %s %v", w.Code, w.Body, err)
	}
	if _, err := db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", p.key); err != nil {
		t.Fatal(err)
	}
	if w = read(); w.Code != 503 {
		t.Fatalf("missing inventory appeared healthy: %d %s", w.Code, w.Body)
	}
}
