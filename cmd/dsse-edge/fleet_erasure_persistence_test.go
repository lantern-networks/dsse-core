package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
)

func erasureReport(node, tenant string, remaining int64) fleetConfigReport {
	return fleetConfigReport{RegionID: "region-a", ClusterID: "cluster", NodeID: node,
		Erasures: []fleetTenantErasure{{TenantID: tenant, Clean: remaining == 0, Remaining: remaining}}}
}

func persistentFleet(t *testing.T, p blobstore.Persister) *fleetConfigStatusStore {
	t.Helper()
	s, err := newPersistentFleetConfigStatusStore(time.Second, p)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func recordErasure(t *testing.T, s *fleetConfigStatusStore, rep fleetConfigReport, now time.Time) {
	t.Helper()
	if err := s.Record(rep, now); err != nil {
		t.Fatal(err)
	}
}

func TestFleetErasureSurvivesFileRestartWithoutInventingLiveness(t *testing.T) {
	p := blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "erasure.json")}
	s := persistentFleet(t, p)
	now := time.Now().UTC()
	recordErasure(t, s, erasureReport("offline", "Acme", 3), now)
	recordErasure(t, s, erasureReport("online", "Acme", 0), now)
	recordErasure(t, s, erasureReport("peer", "acme", 0), now)
	restarted := persistentFleet(t, p)
	if rows := restarted.List(0, "", now); len(rows) != 0 {
		t.Fatal("restored erasure evidence as live fleet")
	}
	recordErasure(t, restarted, erasureReport("online", "Acme", 0), now.Add(time.Hour))
	nodes, complete, err := restarted.tenantErasure("Acme", now.Add(time.Hour))
	if err != nil || complete || len(nodes) != 2 {
		t.Fatalf("forgot offline participant: %v %v %v", nodes, complete, err)
	}
	for _, n := range nodes {
		if n.NodeID == "offline" && (!n.Stale || n.Remaining != 3) {
			t.Fatalf("lost last evidence: %+v", n)
		}
	}
	recordErasure(t, restarted, erasureReport("offline", "Acme", 0), now.Add(2*time.Hour))
	if _, clean := restarted.TenantErasure("Acme", now.Add(2*time.Hour)); !clean {
		t.Fatal("fresh clean report did not finish erasure")
	}
	if rows, clean := restarted.TenantErasure("acme", now); !clean || len(rows) != 1 {
		t.Fatal("case-distinct tenant changed")
	}
}

func TestFleetErasureSharedPromotionAndConcurrentReports(t *testing.T) {
	p := &transactionalCAFixture{}
	a, standby := persistentFleet(t, p), persistentFleet(t, p)
	now := time.Now().UTC()
	recordErasure(t, a, erasureReport("offline", "gone", 7), now)
	// This process was created before the old leader wrote any evidence.
	recordErasure(t, standby, erasureReport("online", "gone", 0), now.Add(time.Hour))
	if rows, done := standby.TenantErasure("gone", now.Add(time.Hour)); done || len(rows) != 2 {
		t.Fatal("promotion dropped offline node", rows)
	}
	const count = 24
	var wg sync.WaitGroup
	errs := make(chan error, count)
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s, err := newPersistentFleetConfigStatusStore(time.Second, p)
			if err == nil {
				err = s.Record(erasureReport(fmt.Sprintf("node-%d", i), "parallel", 1), now)
			}
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	rows, done, err := a.tenantErasure("parallel", now)
	if err != nil || done || len(rows) != count {
		t.Fatalf("concurrent report lost: %d %v %v", len(rows), done, err)
	}
}

type failingFleetBlob struct {
	raw              []byte
	loadErr, saveErr error
	saves            int
}

func (p *failingFleetBlob) Load() ([]byte, error) { return bytes.Clone(p.raw), p.loadErr }
func (p *failingFleetBlob) Save(raw []byte) error {
	p.saves++
	if p.saveErr != nil {
		return p.saveErr
	}
	p.raw = bytes.Clone(raw)
	return nil
}

func TestFleetErasureUncommittedNodeIsNotForgottenOnOtherNodeReport(t *testing.T) {
	p := &failingFleetBlob{}
	s := persistentFleet(t, p)
	now := time.Now().UTC()
	recordErasure(t, s, erasureReport("clean", "gone", 0), now)
	p.saveErr = fmt.Errorf("disk full")
	if err := s.Record(erasureReport("offline", "gone", 2), now); err == nil {
		t.Fatal("failed save acknowledged")
	}
	if _, done, err := s.tenantErasure("gone", now); done || err == nil {
		t.Fatal("uncommitted report hidden")
	}
	p.saveErr = nil
	recordErasure(t, s, erasureReport("clean", "gone", 0), now.Add(time.Minute))
	fresh := persistentFleet(t, p)
	if rows, done := fresh.TenantErasure("gone", now); done || len(rows) != 2 {
		t.Fatal("retry lost pending offline evidence", rows)
	}
}

func TestFleetErasureUnavailableCorruptOrMissingStateCannotComplete(t *testing.T) {
	for _, kind := range []string{"read", "missing", "null", "empty", "duplicate", "invalid-clean"} {
		t.Run(kind, func(t *testing.T) {
			p := &failingFleetBlob{}
			s := persistentFleet(t, p)
			now := time.Now().UTC()
			recordErasure(t, s, erasureReport("clean", "gone", 0), now)
			switch kind {
			case "read":
				p.loadErr = fmt.Errorf("unavailable")
			case "missing":
				p.raw = nil
			case "null":
				p.raw = []byte("null")
			case "empty":
				p.raw = []byte("{}")
			case "duplicate":
				p.raw = []byte(`{"version":1,"tenants":{"gone":{}},"tenants":{}}`)
			case "invalid-clean":
				var snap fleetErasureSnapshot
				_ = json.Unmarshal(p.raw, &snap)
				for key, st := range snap.Tenants["gone"] {
					st.Remaining = 1
					snap.Tenants["gone"][key] = st
				}
				p.raw, _ = json.Marshal(snap)
			}
			before, saves := bytes.Clone(p.raw), p.saves
			if _, done, err := s.tenantErasure("gone", now); done || err == nil {
				t.Fatal("unsafe completion")
			}
			if err := s.Record(erasureReport("new", "gone", 0), now); err == nil {
				t.Fatal("overwrote missing/corrupt history")
			}
			if !bytes.Equal(before, p.raw) || p.saves != saves {
				t.Fatal("changed unavailable original")
			}
		})
	}
}

func TestFleetErasureRejectsContradictoryAndDelayedCleanEvidence(t *testing.T) {
	p := &transactionalCAFixture{}
	s := persistentFleet(t, p)
	now := time.Now().UTC()
	recordErasure(t, s, erasureReport("node", "gone", 5), now)
	for _, at := range []time.Time{now.Add(-time.Second), now} {
		recordErasure(t, s, erasureReport("node", "gone", 0), at)
		if _, done := s.TenantErasure("gone", now); done {
			t.Fatal("delayed clean replaced newer dirty evidence")
		}
	}
	bad := erasureReport("node", "gone", 5)
	bad.Erasures[0].Clean = true
	if err := s.Record(bad, now.Add(time.Minute)); err == nil {
		t.Fatal("accepted clean with remaining data")
	}
	bad = erasureReport("node", "gone", 0)
	bad.Erasures = append(bad.Erasures, bad.Erasures[0])
	if err := s.Record(bad, now); err == nil {
		t.Fatal("duplicate report accepted")
	}
	p.failCommit = true
	if err := s.Record(erasureReport("node", "gone", 0), now.Add(time.Minute)); err == nil {
		t.Fatal("uncommitted clean accepted")
	}
	fresh := persistentFleet(t, p)
	if _, done := fresh.TenantErasure("gone", now); done {
		t.Fatal("failed shared commit erased evidence")
	}
}

func TestFleetErasureHTTPReadFailureIs503(t *testing.T) {
	p := &failingFleetBlob{}
	s := persistentFleet(t, p)
	recordErasure(t, s, erasureReport("node", "gone", 0), time.Now())
	mux := http.NewServeMux()
	registerFleetConfigStatusRoutes(mux, func(_ string, h http.HandlerFunc) http.HandlerFunc { return h }, s, nil)
	r := httptest.NewRequest("GET", "/admin/fleet/tenant-erasure/gone", nil)
	r = r.WithContext(context.WithValue(r.Context(), adminIdentityContextKey{}, adminIdentity{TenantID: "gone", Roles: []string{"owner"}}))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("valid read %d %s", w.Code, w.Body)
	}
	p.loadErr = fmt.Errorf("database unavailable")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != 503 || bytes.Contains(w.Body.Bytes(), []byte(`"complete":true`)) {
		t.Fatalf("false completion: %d %s", w.Code, w.Body)
	}
}

func TestFleetErasureRequiresDurableBackend(t *testing.T) {
	if _, err := newPersistentFleetConfigStatusStore(time.Second, nil); err == nil {
		t.Fatal("production accepted volatile erasure evidence")
	}
}

func TestFleetErasureHTTPDoesNotAcknowledgeUncommittedReport(t *testing.T) {
	previous := operatorTenantConfigured()
	declareOperatorTenant("operator", false)
	t.Cleanup(func() { declareOperatorTenant(previous, false) })
	p := &failingFleetBlob{saveErr: fmt.Errorf("storage unavailable")}
	s := persistentFleet(t, p)
	mux := http.NewServeMux()
	registerFleetConfigStatusRoutes(mux, func(_ string, h http.HandlerFunc) http.HandlerFunc { return h }, s, nil)
	post := func() *httptest.ResponseRecorder {
		raw, err := json.Marshal(erasureReport("offline", "gone", 4))
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest("POST", "/admin/fleet/config-status", bytes.NewReader(raw))
		r = r.WithContext(context.WithValue(r.Context(), adminIdentityContextKey{}, adminIdentity{TenantID: "operator", Roles: []string{"super_admin"}, AuthMethod: "admin_api_token", Scopes: []string{"*"}}))
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}
	if w := post(); w.Code != 503 {
		t.Fatalf("uncommitted report: %d %s", w.Code, w.Body)
	}
	if len(s.List(0, "", time.Now())) != 0 {
		t.Fatal("unacknowledged report published")
	}
	p.saveErr = nil
	if w := post(); w.Code != 200 {
		t.Fatalf("report retry: %d %s", w.Code, w.Body)
	}
	fresh := persistentFleet(t, p)
	if rows, done := fresh.TenantErasure("gone", time.Now()); done || len(rows) != 1 || rows[0].Remaining != 4 {
		t.Fatal("accepted report not durable", rows)
	}
}

// Uses the same row-locked CP persister as production, with two live store
// instances and a restarted reader. No external infrastructure is required.
func TestFleetErasurePostgresPromotion(t *testing.T) {
	dsn := os.Getenv("DSSE_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("set DSSE_TEST_POSTGRES_DSN for real PostgreSQL")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS cp_state_blobs (store_key text PRIMARY KEY,payload bytea NOT NULL,updated_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		t.Fatal(err)
	}
	key := fmt.Sprintf("test_fleet_erasure_%d", time.Now().UnixNano())
	defer db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", key)
	p := postgresBlobPersister{db: db, key: key}
	a, b := persistentFleet(t, p), persistentFleet(t, p)
	now := time.Now().UTC()
	recordErasure(t, a, erasureReport("offline", "gone", 3), now)
	recordErasure(t, b, erasureReport("online", "gone", 0), now.Add(time.Minute))
	c := persistentFleet(t, p)
	if rows, done := c.TenantErasure("gone", now.Add(time.Hour)); done || len(rows) != 2 {
		t.Fatal("shared database lost offline evidence", rows)
	}
	recordErasure(t, b, erasureReport("offline", "gone", 0), now.Add(time.Hour))
	if _, done := a.TenantErasure("gone", now.Add(time.Hour)); !done {
		t.Fatal("old process did not refresh confirmed erasure")
	}
}
