package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/hotstore"
)

func TestManualHotLogDeleteDeploymentHistoryIsOperatorOnly(t *testing.T) {
	declareOperatorTenantForTest(t, "tenant_operator")
	mux := http.NewServeMux()
	registerManualHotLogDeleteRoutes(mux, func(_ string, handler http.HandlerFunc) http.HandlerFunc { return handler },
		&manualHotLogDeleteManager{hotCH: hotstore.NewClickHouseStore("http://127.0.0.1", "", "", "dsse", "events")}, decision.Evaluator{}, nil, nil)
	req := func(identity *adminIdentity, selectedTenant string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/admin/manual-hot-log-delete/all", nil)
		if identity != nil {
			r = requestWithAdminIdentity(r, *identity)
		}
		if selectedTenant != "" {
			r.Header.Set("X-Operate-Tenant", selectedTenant)
		}
		return r
	}
	customer := adminIdentity{PrincipalID: "customer", TenantID: "tenant_customer", Roles: []string{"super_admin"}, AuthMethod: "admin_session"}
	operator := adminIdentity{PrincipalID: "operator", TenantID: "tenant_operator", Roles: []string{"super_admin"}, AuthMethod: "admin_session"}
	for _, tc := range []struct {
		name           string
		identity       *adminIdentity
		selectedTenant string
		want           bool
	}{
		{"anonymous", nil, "", false},
		{"customer super admin", &customer, "", false},
		{"customer with override", &customer, "tenant_other", false},
		{"operator viewing customer", &operator, "tenant_customer", false},
		{"operator deployment view", &operator, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := req(tc.identity, tc.selectedTenant)
			if got := manualHotLogDeleteDeploymentHistoryAllowed(r); got != tc.want {
				t.Fatalf("deployment history allowed=%t, want %t", got, tc.want)
			}
			if !tc.want {
				response := httptest.NewRecorder()
				mux.ServeHTTP(response, r)
				if response.Code != http.StatusForbidden {
					t.Fatalf("history route status=%d, want 403", response.Code)
				}
			}
		})
	}
	for _, identity := range []adminIdentity{customer, operator} {
		r := httptest.NewRequest(http.MethodPost, "/admin/manual-hot-log-delete/hot_delete_test/cancel", strings.NewReader(`{"confirm":true,"reason":"stalled"}`))
		r = requestWithAdminIdentity(r, identity)
		if identity.PrincipalID == "operator" {
			r.Header.Set("X-Operate-Tenant", "tenant_customer")
		}
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, r)
		if response.Code != http.StatusForbidden {
			t.Fatalf("non-deployment cancellation access %s: %d", identity.PrincipalID, response.Code)
		}
	}
}

func TestManualHotLogDeleteDigestBindsScopeAndCount(t *testing.T) {
	base := manualHotLogDeleteJob{ID: "job", Tenant: "a", Stream: "access", Cutoff: time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC), PreviewCount: 2}
	digest := manualHotLogDeleteDigest(base)
	if digest == "" || digest == manualHotLogDeleteDigest(manualHotLogDeleteJob{ID: "job", Tenant: "b", Stream: "access", Cutoff: base.Cutoff, PreviewCount: 2}) {
		t.Fatal("confirmation digest did not bind tenant")
	}
	base.PreviewCount++
	if digest == manualHotLogDeleteDigest(base) {
		t.Fatal("confirmation digest did not bind count")
	}
}

func TestManualHotLogDeleteFreezesRowsAndResumes(t *testing.T) {
	p, leader, peer := blobWriterPostgresFixture(t)
	p.key = "legal_hold"
	if err := p.Save([]byte(`[]`)); err != nil {
		t.Fatal(err)
	}
	holds := newLegalHoldStore(p)
	migration, err := os.ReadFile(filepath.Join("..", "..", "migrations", "055_manual_hot_log_delete.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.db.Exec(string(migration)); err != nil {
		t.Fatal(err)
	}
	if _, err := p.db.Exec(`CREATE TABLE hot_events(tenant_id text NOT NULL,stream text NOT NULL,event_id text NOT NULL,occurred_at timestamptz NOT NULL,received_at timestamptz NOT NULL,PRIMARY KEY(tenant_id,stream,event_id))`); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	for _, row := range []struct {
		tenant, id string
		at         time.Time
	}{{"a", "old1", now.Add(-3 * time.Hour)}, {"a", "old2", now.Add(-2 * time.Hour)}, {"a", "new", now.Add(-time.Minute)}, {"b", "foreign", now.Add(-3 * time.Hour)}} {
		if _, err := p.db.Exec(`INSERT INTO hot_events VALUES($1,'access',$2,$3,$3)`, row.tenant, row.id, row.at); err != nil {
			t.Fatal(err)
		}
	}
	m := &manualHotLogDeleteManager{db: p.db, kind: "postgres", identity: "fixture", holds: holds}
	cutoff := now.Add(-time.Hour)
	job, err := m.preview(context.Background(), "a", "access", cutoff, "admin-a")
	if err != nil || job.PreviewCount != 2 || job.Status != "preview_ready" {
		t.Fatalf("preview %+v: %v", job, err)
	}
	if _, err := m.confirm(context.Background(), job.ID, "a", "wrong"); err == nil {
		t.Fatal("wrong digest accepted")
	}
	// A late arrival is older than the cutoff but has no frozen receipt.
	if _, err := p.db.Exec(`INSERT INTO hot_events VALUES('a','access','late',$1,$2)`, now.Add(-4*time.Hour), now); err != nil {
		t.Fatal(err)
	}
	if _, err := m.confirm(context.Background(), job.ID, "a", job.PreviewDigest); err != nil {
		t.Fatal(err)
	}
	if _, err := m.confirm(context.Background(), job.ID, "a", job.PreviewDigest); err == nil {
		t.Fatal("second confirmation was accepted")
	}
	if err := m.step(context.Background()); err != nil {
		t.Fatal(err)
	}
	leader.release()
	peer.tick()
	if !peer.IsLeader() {
		t.Fatal("peer did not promote")
	}
	cpLeaderElectorInstance = peer
	recovered := &manualHotLogDeleteManager{db: p.db, kind: "postgres", identity: "fixture", holds: newLegalHoldStore(p)}
	if err := recovered.step(context.Background()); err != nil {
		t.Fatal(err)
	}
	job, err = recovered.get(context.Background(), job.ID)
	if err != nil || job.Status != "completed" || job.ConfirmedGone != 2 {
		t.Fatalf("durable result %+v: %v", job, err)
	}
	for id, want := range map[string]int{"old1": 0, "old2": 0, "new": 1, "late": 1, "foreign": 1} {
		var count int
		if err := p.db.QueryRow(`SELECT count(*) FROM hot_events WHERE event_id=$1`, id).Scan(&count); err != nil || count != want {
			t.Errorf("%s count=%d want=%d err=%v", id, count, want, err)
		}
	}
}

func TestManualHotLogDeleteFailureIsVisibleAndRetryable(t *testing.T) {
	p, _, _ := blobWriterPostgresFixture(t)
	p.key = "legal_hold"
	if err := p.Save([]byte(`[]`)); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join("..", "..", "migrations", "055_manual_hot_log_delete.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.db.Exec(string(data)); err != nil {
		t.Fatal(err)
	}
	create := `CREATE TABLE hot_events(tenant_id text,stream text,event_id text,occurred_at timestamptz,received_at timestamptz)`
	if _, err := p.db.Exec(create); err != nil {
		t.Fatal(err)
	}
	rowAt := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Second)
	insert := func() {
		t.Helper()
		if _, err := p.db.Exec(`INSERT INTO hot_events VALUES('a','access','one',$1,$1)`, rowAt); err != nil {
			t.Fatal(err)
		}
	}
	insert()
	m := &manualHotLogDeleteManager{db: p.db, kind: "postgres", identity: "fixture", holds: newLegalHoldStore(p)}
	job, err := m.preview(context.Background(), "a", "access", time.Now().Add(-time.Hour), "admin-a")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.confirm(context.Background(), job.ID, "a", job.PreviewDigest); err != nil {
		t.Fatal(err)
	}
	if _, err := p.db.Exec(`DROP TABLE hot_events`); err != nil {
		t.Fatal(err)
	}
	if err := m.step(context.Background()); err == nil {
		t.Fatal("missing hot store was accepted")
	}
	failed, err := m.get(context.Background(), job.ID)
	if err != nil || failed.Status != "failed" || failed.FailureCode != "store_operation_failed" {
		t.Fatalf("failure state %+v: %v", failed, err)
	}
	if _, err := p.db.Exec(create); err != nil {
		t.Fatal(err)
	}
	insert()
	if _, err := m.confirm(context.Background(), job.ID, "a", job.PreviewDigest); err != nil {
		t.Fatal(err)
	}
	if err := m.step(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := m.step(context.Background()); err != nil {
		t.Fatal(err)
	}
	result, err := m.get(context.Background(), job.ID)
	if err != nil || result.Status != "completed" || result.ConfirmedGone != 1 {
		t.Fatalf("retry result %+v: %v", result, err)
	}
}

func TestManualHotLogDeleteRequiresNewPreviewWhenTargetChanged(t *testing.T) {
	p, _, _ := blobWriterPostgresFixture(t)
	p.key = "legal_hold"
	if err := p.Save([]byte(`[]`)); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join("..", "..", "migrations", "055_manual_hot_log_delete.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.db.Exec(string(data)); err != nil {
		t.Fatal(err)
	}
	if _, err := p.db.Exec(`CREATE TABLE hot_events(tenant_id text,stream text,event_id text,occurred_at timestamptz,received_at timestamptz)`); err != nil {
		t.Fatal(err)
	}
	if _, err := p.db.Exec(`INSERT INTO hot_events VALUES('a','access','one',$1,$1)`, time.Now().Add(-2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	m := &manualHotLogDeleteManager{db: p.db, kind: "postgres", identity: "fixture", holds: newLegalHoldStore(p)}
	job, err := m.preview(context.Background(), "a", "access", time.Now().Add(-time.Hour), "admin-a")
	if err != nil || job.PreviewCount != 1 {
		t.Fatalf("preview %+v: %v", job, err)
	}
	if _, err := p.db.Exec(`DELETE FROM hot_events WHERE event_id='one'`); err != nil {
		t.Fatal(err)
	}
	if _, err := m.confirm(context.Background(), job.ID, "a", job.PreviewDigest); err == nil {
		t.Fatal("changed preview was confirmed")
	}
	job, err = m.get(context.Background(), job.ID)
	if err != nil || job.Status != "stale" || job.FailureCode != "preview_changed" {
		t.Fatalf("stale job %+v: %v", job, err)
	}
}

func TestManualHotLogDeleteRechecksHoldAtWorker(t *testing.T) {
	p, _, _ := blobWriterPostgresFixture(t)
	p.key = "legal_hold"
	if err := p.Save([]byte(`[]`)); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join("..", "..", "migrations", "055_manual_hot_log_delete.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.db.Exec(string(data)); err != nil {
		t.Fatal(err)
	}
	if _, err := p.db.Exec(`CREATE TABLE hot_events(tenant_id text,stream text,event_id text,occurred_at timestamptz,received_at timestamptz)`); err != nil {
		t.Fatal(err)
	}
	if _, err := p.db.Exec(`INSERT INTO hot_events VALUES('a','access','one',$1,$1)`, time.Now().Add(-2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	holds := newLegalHoldStore(p)
	m := &manualHotLogDeleteManager{db: p.db, kind: "postgres", identity: "fixture", holds: holds}
	job, err := m.preview(context.Background(), "a", "access", time.Now().Add(-time.Hour), "admin-a")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.confirm(context.Background(), job.ID, "a", job.PreviewDigest); err != nil {
		t.Fatal(err)
	}
	if err := holds.Set("a", "legal", "", true, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := m.step(context.Background()); err == nil {
		t.Fatal("worker ignored new hold")
	}
	var count int
	if err := p.db.QueryRow(`SELECT count(*) FROM hot_events WHERE tenant_id='a'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("held row count=%d err=%v", count, err)
	}
	job, err = m.get(context.Background(), job.ID)
	if err != nil || job.Status != "failed" || job.FailureCode != "legal_hold_or_policy_unavailable" {
		t.Fatalf("held job %+v: %v", job, err)
	}
}

func TestManualHotLogDeleteHonorsHoldAfterPreview(t *testing.T) {
	p, _, _ := blobWriterPostgresFixture(t)
	p.key = "legal_hold"
	if err := p.Save([]byte(`[]`)); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join("..", "..", "migrations", "055_manual_hot_log_delete.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.db.Exec(string(data)); err != nil {
		t.Fatal(err)
	}
	if _, err := p.db.Exec(`CREATE TABLE hot_events(tenant_id text,stream text,event_id text,occurred_at timestamptz,received_at timestamptz)`); err != nil {
		t.Fatal(err)
	}
	holds := newLegalHoldStore(p)
	m := &manualHotLogDeleteManager{db: p.db, kind: "postgres", identity: "fixture", holds: holds}
	job, err := m.preview(context.Background(), "a", "access", time.Now().Add(-time.Hour), "admin-a")
	if err != nil {
		t.Fatal(err)
	}
	if err := holds.Set("a", "litigation", "", true, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := m.confirm(context.Background(), job.ID, "a", job.PreviewDigest); err == nil {
		t.Fatal("held tenant confirmation succeeded")
	}
}

func TestManualHotLogDeleteRejectedMutationDoesNotStrandOtherTenants(t *testing.T) {
	p, _, _ := blobWriterPostgresFixture(t)
	p.key = "legal_hold"
	if err := p.Save([]byte(`[]`)); err != nil {
		t.Fatal(err)
	}
	migration, err := os.ReadFile(filepath.Join("..", "..", "migrations", "055_manual_hot_log_delete.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.db.Exec(string(migration)); err != nil {
		t.Fatal(err)
	}
	var aID, bID string
	allowA, startedA, startedB := false, false, false
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		body, _ := io.ReadAll(r.Body)
		query := string(body)
		switch {
		case strings.Contains(query, "system.columns"):
			_, _ = w.Write([]byte("1"))
		case strings.Contains(query, "system.parts"):
			_, _ = w.Write([]byte("0"))
		case strings.Contains(query, "system.tables"):
		case strings.Contains(query, "toString(now64"):
			_, _ = w.Write([]byte(time.Now().UTC().Format("2006-01-02 15:04:05.000000")))
		case strings.Contains(query, "system.processes"):
			_, _ = w.Write([]byte("0"))
		case strings.Contains(query, "system.mutations"):
			marker := r.URL.Query().Get("param_marker")
			if marker == "'"+aID+"'" && startedA || marker == "'"+bID+"'" && startedB {
				_, _ = w.Write([]byte(fmt.Sprintf(`{"mutation_id":"mutation_%s","is_done":1,"parts_to_do":0,"failed":0}`, strings.Trim(marker, "'"))))
			}
		case strings.HasPrefix(query, "SELECT count() FROM dsse.events"):
			tenant := r.URL.Query().Get("param_tenant")
			if tenant == "a" && startedA || tenant == "b" && startedB {
				_, _ = w.Write([]byte("0"))
			} else {
				_, _ = w.Write([]byte("1"))
			}
		case strings.HasPrefix(query, "ALTER TABLE"):
			if aID != "" && strings.Contains(query, aID) {
				if !allowA {
					w.WriteHeader(http.StatusForbidden)
					return
				}
				startedA = true
			} else if bID != "" && strings.Contains(query, bID) {
				startedB = true
			}
		default:
			t.Errorf("unexpected ClickHouse query class")
		}
	}))
	defer server.Close()
	store := hotstore.NewClickHouseStore(server.URL, "", "", "dsse", "events")
	m := &manualHotLogDeleteManager{db: p.db, hotCH: store, kind: "clickhouse", identity: store.RetentionIdentity(), holds: newLegalHoldStore(p)}
	cutoff := time.Now().UTC().Add(-time.Hour)
	a, err := m.preview(context.Background(), "a", "access", cutoff, "operator")
	if err != nil {
		t.Fatal(err)
	}
	b, err := m.preview(context.Background(), "b", "access", cutoff, "operator")
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	aID, bID = a.ID, b.ID
	mu.Unlock()
	if _, err := m.confirm(context.Background(), a.ID, "a", a.PreviewDigest); err != nil {
		t.Fatal(err)
	}
	if _, err := m.confirm(context.Background(), b.ID, "b", b.PreviewDigest); err != nil {
		t.Fatal(err)
	}
	if err := m.step(context.Background()); err == nil {
		t.Fatal("definite ALTER rejection was ignored")
	}
	a, _ = m.get(context.Background(), a.ID)
	if a.Status != "failed" || a.FailureCode != "mutation_not_submitted" {
		t.Fatalf("rejected job remains active: %+v", a)
	}
	if err := m.step(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := m.step(context.Background()); err != nil {
		t.Fatal(err)
	}
	b, _ = m.get(context.Background(), b.ID)
	if b.Status != "completed" {
		t.Fatalf("other tenant stalled behind rejected job: %+v", b)
	}
	mu.Lock()
	allowA = true
	mu.Unlock()
	if _, err := m.confirm(context.Background(), a.ID, "a", a.PreviewDigest); err != nil {
		t.Fatal(err)
	}
	if err := m.step(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := m.step(context.Background()); err != nil {
		t.Fatal(err)
	}
	a, _ = m.get(context.Background(), a.ID)
	if a.Status != "completed" {
		t.Fatalf("reconfirmed deletion did not finish: %+v", a)
	}
}

func TestManualHotLogDeleteRetryingMutationCanBeStoppedAndReconciled(t *testing.T) {
	p, _, _ := blobWriterPostgresFixture(t)
	p.key = "legal_hold"
	if err := p.Save([]byte(`[]`)); err != nil {
		t.Fatal(err)
	}
	migration, err := os.ReadFile(filepath.Join("..", "..", "migrations", "055_manual_hot_log_delete.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.db.Exec(string(migration)); err != nil {
		t.Fatal(err)
	}
	active, killed := false, false
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		body, _ := io.ReadAll(r.Body)
		query := string(body)
		switch {
		case strings.Contains(query, "system.columns"):
			_, _ = w.Write([]byte("1"))
		case strings.Contains(query, "system.parts"):
			_, _ = w.Write([]byte("0"))
		case strings.Contains(query, "system.tables"):
		case strings.Contains(query, "toString(now64"):
			_, _ = w.Write([]byte(time.Now().UTC().Format("2006-01-02 15:04:05.000000")))
		case strings.Contains(query, "system.processes"):
			_, _ = w.Write([]byte("0"))
		case strings.Contains(query, "system.mutations"):
			if active {
				_, _ = w.Write([]byte(`{"mutation_id":"mutation_stalled","is_done":0,"parts_to_do":1,"failed":1}`))
			}
		case strings.HasPrefix(query, "SELECT count() FROM dsse.events"):
			_, _ = w.Write([]byte("1"))
		case strings.HasPrefix(query, "ALTER TABLE"):
			active = true
		case strings.HasPrefix(query, "KILL MUTATION"):
			killed, active = true, false
		default:
			t.Errorf("unexpected ClickHouse query class")
		}
	}))
	defer server.Close()
	store := hotstore.NewClickHouseStore(server.URL, "", "", "dsse", "events")
	holds := newLegalHoldStore(p)
	m := &manualHotLogDeleteManager{db: p.db, hotCH: store, kind: "clickhouse", identity: store.RetentionIdentity(), holds: holds}
	job, err := m.preview(context.Background(), "a", "access", time.Now().UTC().Add(-time.Hour), "operator")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.confirm(context.Background(), job.ID, "a", job.PreviewDigest); err != nil {
		t.Fatal(err)
	}
	if err := m.step(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := m.step(context.Background()); err != nil {
		t.Fatal(err)
	}
	job, err = m.get(context.Background(), job.ID)
	if err != nil || job.Status != "running" || job.FailureCode != "mutation_retrying" {
		t.Fatalf("retrying mutation status: %+v %v", job, err)
	}
	if err := holds.Set("a", "litigation", "", true, time.Now()); !errors.Is(err, errManualHotLogDeleteInProgress) {
		t.Fatalf("running deletion did not fence legal hold: %v", err)
	}
	if _, err := m.cancel(context.Background(), job.ID); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	wasKilled := killed
	mu.Unlock()
	if !wasKilled {
		t.Fatal("operator cancellation did not send KILL MUTATION")
	}
	if err := m.step(context.Background()); err != nil {
		t.Fatal(err)
	}
	job, err = m.get(context.Background(), job.ID)
	if err != nil || job.Status != "failed" || job.FailureCode != "mutation_not_present" {
		t.Fatalf("cancelled mutation was not reconciled: %+v %v", job, err)
	}
}

func TestManualHotLogDeleteLostALTERResponseKeepsHoldFenceUntilQueryAndMutationEnd(t *testing.T) {
	p, _, _ := blobWriterPostgresFixture(t)
	p.key = "legal_hold"
	if err := p.Save([]byte(`[]`)); err != nil {
		t.Fatal(err)
	}
	migration, err := os.ReadFile(filepath.Join("..", "..", "migrations", "055_manual_hot_log_delete.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.db.Exec(string(migration)); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var jobID string
	queryRunning, observationFails, registerDuringQueryRead := false, false, false
	mutationRegistered, mutationDone, rowsGone := false, false, false
	alterCalls, mutationReads := 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		body, _ := io.ReadAll(r.Body)
		query := string(body)
		switch {
		case strings.Contains(query, "system.columns"):
			_, _ = io.WriteString(w, "1")
		case strings.Contains(query, "system.parts"):
			_, _ = io.WriteString(w, "0")
		case strings.Contains(query, "system.tables"):
		case strings.Contains(query, "toString(now64"):
			_, _ = io.WriteString(w, time.Now().UTC().Format("2006-01-02 15:04:05.000000"))
		case strings.Contains(query, "system.processes"):
			if r.URL.Query().Get("param_job") != jobID {
				t.Error("running ALTER lookup used a different job ID")
			}
			if observationFails {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			if registerDuringQueryRead {
				// The query leaves the process list as the asynchronous mutation
				// becomes visible. Reading mutations first would miss this handoff.
				mutationRegistered, queryRunning = true, false
			}
			if queryRunning {
				_, _ = io.WriteString(w, "1")
			} else {
				_, _ = io.WriteString(w, "0")
			}
		case strings.Contains(query, "system.mutations"):
			mutationReads++
			if mutationRegistered {
				done := 0
				if mutationDone {
					done = 1
				}
				_, _ = fmt.Fprintf(w, `{"mutation_id":"mutation_late","is_done":%d,"parts_to_do":1,"failed":0}`, done)
			}
		case strings.HasPrefix(query, "SELECT count() FROM dsse.events"):
			if rowsGone {
				_, _ = io.WriteString(w, "0")
			} else {
				_, _ = io.WriteString(w, "1")
			}
		case strings.HasPrefix(query, "ALTER TABLE"):
			alterCalls++
			if r.URL.Query().Get("query_id") != jobID {
				t.Error("ALTER was submitted without the durable job ID")
			}
			queryRunning = true
			// Model a lost response while the server remains in its lock wait.
			conn, _, hijackErr := w.(http.Hijacker).Hijack()
			if hijackErr != nil {
				t.Error(hijackErr)
				return
			}
			_ = conn.Close()
		default:
			t.Error("unexpected ClickHouse query class")
		}
	}))
	defer server.Close()
	store := hotstore.NewClickHouseStore(server.URL, "", "", "dsse", "events")
	holds := newLegalHoldStore(p)
	m := &manualHotLogDeleteManager{db: p.db, hotCH: store, kind: "clickhouse", identity: store.RetentionIdentity(), holds: holds}
	job, err := m.preview(context.Background(), "a", "access", time.Now().UTC().Add(-time.Hour), "operator")
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	jobID = job.ID
	mu.Unlock()
	if _, err := m.confirm(context.Background(), job.ID, "a", job.PreviewDigest); err != nil {
		t.Fatal(err)
	}
	if err := m.step(context.Background()); err == nil {
		t.Fatal("lost ALTER response was not reported")
	}
	// A new manager models restart/promotion: the PG ledger and remote query
	// identity, not an in-memory HTTP request, must preserve the hold fence.
	m = &manualHotLogDeleteManager{db: p.db, hotCH: store, kind: "clickhouse", identity: store.RetentionIdentity(), holds: holds}
	assertFenced := func() {
		t.Helper()
		current, getErr := m.get(context.Background(), job.ID)
		if getErr != nil || current.Status != "running" {
			t.Fatalf("unfinished ALTER lost its durable fence: %+v %v", current, getErr)
		}
		if err := holds.Set("a", "litigation", "", true, time.Now()); !errors.Is(err, errManualHotLogDeleteInProgress) {
			t.Fatalf("unfinished ALTER allowed a legal hold: %v", err)
		}
		if _, err := m.confirm(context.Background(), job.ID, "a", job.PreviewDigest); err == nil {
			t.Fatal("unfinished ALTER allowed a second confirmation")
		}
		mu.Lock()
		calls := alterCalls
		mu.Unlock()
		if calls != 1 {
			t.Fatalf("ALTER submitted %d times", calls)
		}
	}
	if err := m.step(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertFenced()
	mu.Lock()
	readsWhileRunning := mutationReads
	queryRunning = false
	mu.Unlock()
	if readsWhileRunning != 1 {
		t.Fatal("mutation lookup ran before the still-running ALTER check")
	}
	// A workload queue can hold the lost request outside system.processes.
	// Neither an empty process list nor an empty mutation list proves rejection.
	if err := m.step(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertFenced()
	if _, err := m.cancel(context.Background(), job.ID); err == nil {
		t.Fatal("unobserved mutation cancellation falsely reported success")
	}
	assertFenced()
	mu.Lock()
	rowsGone = true
	mu.Unlock()
	if err := m.step(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertFenced() // Empty rows alone do not prove the unobserved request ended.
	mu.Lock()
	queryRunning = true
	mu.Unlock()
	if err := m.step(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertFenced() // Even an empty predicate cannot release a still-running write.
	mu.Lock()
	observationFails = true
	mu.Unlock()
	if err := m.step(context.Background()); err == nil {
		t.Fatal("failed query observation was treated as query absence")
	}
	assertFenced()
	mu.Lock()
	observationFails, registerDuringQueryRead = false, true
	mu.Unlock()
	if err := m.step(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertFenced()
	var mutationID string
	if err := p.db.QueryRow(`SELECT mutation_id FROM manual_hot_log_delete_jobs WHERE job_id=$1`, job.ID).Scan(&mutationID); err != nil || mutationID != "mutation_late" {
		t.Fatalf("query-to-mutation transition was missed: %q %v", mutationID, err)
	}
	mu.Lock()
	mutationDone = true
	mu.Unlock()
	if err := m.step(context.Background()); err != nil {
		t.Fatal(err)
	}
	job, err = m.get(context.Background(), job.ID)
	if err != nil || job.Status != "completed" {
		t.Fatalf("finished deletion not reconciled: %+v %v", job, err)
	}
	if err := holds.Set("a", "litigation", "", true, time.Now()); err != nil {
		t.Fatalf("completed deletion stranded its hold fence: %v", err)
	}
}

func TestManualHotLogDeleteClickHouseReceipts(t *testing.T) {
	endpoint := os.Getenv("CLICKHOUSE_TEST_ENDPOINT")
	if endpoint == "" {
		t.Skip("CLICKHOUSE_TEST_ENDPOINT not set")
	}
	user, password := os.Getenv("CLICKHOUSE_TEST_USER"), os.Getenv("CLICKHOUSE_TEST_PASSWORD")
	query := func(statement string) {
		t.Helper()
		r, err := http.NewRequest(http.MethodPost, endpoint+"/?database=dsse", strings.NewReader(statement))
		if err != nil {
			t.Fatal(err)
		}
		r.SetBasicAuth(user, password)
		response, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("clickhouse status %d", response.StatusCode)
		}
	}
	table := fmt.Sprintf("manual_hot_%d", time.Now().UnixNano())
	query("CREATE TABLE dsse." + table + " (event_id String,tenant_id String,stream String,ts DateTime64(3,'UTC'),raw String,retention_id UUID DEFAULT generateUUIDv4(),inserted_at DateTime64(9,'UTC') DEFAULT now64(9,'UTC')) ENGINE=MergeTree ORDER BY (tenant_id,ts,event_id)")
	defer query("DROP TABLE IF EXISTS dsse." + table)
	query("INSERT INTO dsse." + table + " (event_id,tenant_id,stream,ts,raw) VALUES ('old','a','access','2020-01-01 00:00:00','{}'),('other','b','access','2020-01-01 00:00:00','{}')")
	store := hotstore.NewClickHouseStore(endpoint, user, password, "dsse", table)
	p, leader, peer := blobWriterPostgresFixture(t)
	p.key = "legal_hold"
	if err := p.Save([]byte(`[]`)); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join("..", "..", "migrations", "055_manual_hot_log_delete.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.db.Exec(string(data)); err != nil {
		t.Fatal(err)
	}
	holds := newLegalHoldStore(p)
	m := &manualHotLogDeleteManager{db: p.db, hotCH: store, kind: "clickhouse", identity: store.RetentionIdentity(), holds: holds}
	job, err := m.preview(context.Background(), "a", "access", time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC), "admin-a")
	if err != nil || job.PreviewCount != 1 {
		t.Fatalf("clickhouse preview %+v: %v", job, err)
	}
	query("INSERT INTO dsse." + table + " (event_id,tenant_id,stream,ts,raw) VALUES ('late','a','access','2019-01-01 00:00:00','{}')")
	if _, err := m.confirm(context.Background(), job.ID, "a", job.PreviewDigest); err != nil {
		t.Fatal(err)
	}
	if err := m.step(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := holds.Set("a", "litigation", "", true, time.Now()); !errors.Is(err, errManualHotLogDeleteInProgress) {
		t.Fatalf("hold during unresolved ClickHouse mutation: %v", err)
	}
	var journalRows int
	if err := p.db.QueryRow(`SELECT count(*) FROM manual_hot_log_delete_candidates WHERE job_id=$1`, job.ID).Scan(&journalRows); err != nil || journalRows != 0 {
		t.Fatalf("ClickHouse preview copied row receipts: %d %v", journalRows, err)
	}
	leader.release()
	peer.tick()
	if !peer.IsLeader() {
		t.Fatal("peer did not promote")
	}
	cpLeaderElectorInstance = peer
	recovered := &manualHotLogDeleteManager{db: p.db, hotCH: store, kind: "clickhouse", identity: store.RetentionIdentity(), holds: newLegalHoldStore(p)}
	for attempt := 0; attempt < 30; attempt++ {
		if err := recovered.step(context.Background()); err != nil {
			t.Fatal(err)
		}
		job, err = recovered.get(context.Background(), job.ID)
		if err != nil || job.Status == "completed" || job.Status == "failed" {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if err != nil || job.Status != "completed" || job.ConfirmedGone != 1 {
		t.Fatalf("clickhouse result %+v: %v", job, err)
	}
	if err := holds.Set("a", "litigation", "", true, time.Now()); err != nil {
		t.Fatalf("hold still blocked after deletion completed: %v", err)
	}
	if state, found, err := store.ManualDeleteMutationState(context.Background(), job.ID); err != nil || !found || state.Done != 1 {
		t.Fatalf("single async mutation not completed: %+v %v %v", state, found, err)
	}
	rows, err := store.RetentionCandidates(context.Background(), "a", "access", time.Now(), "", "", 100)
	if err != nil || len(rows) != 1 {
		t.Fatalf("late row not preserved: %v %v", rows, err)
	}
	rows, err = store.RetentionCandidates(context.Background(), "b", "access", time.Now(), "", "", 100)
	if err != nil || len(rows) != 1 {
		t.Fatalf("other tenant not preserved: %v %v", rows, err)
	}
}
