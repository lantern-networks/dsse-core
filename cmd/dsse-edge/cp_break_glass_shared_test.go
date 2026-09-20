package main

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/lantern-networks/dsse-core/logs"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestPostgresBreakGlassLatestApprovalAndTerm(t *testing.T) {
	leader, peerLeader := postgresFailureElectors(t)
	db, err := newCPStateBlobDB(os.Getenv("POSTGRES_QUEUE_E2E_DSN"), "../../migrations", true)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	oldE, oldCP := cpLeaderElectorInstance, edgeIsControlPlane
	cpLeaderElectorInstance = nil
	defer func() { cpLeaderElectorInstance = oldE; edgeIsControlPlane = oldCP }()
	p := postgresBlobPersister{db: db, key: "break_glass"}
	saved, err := p.Load()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", p.key); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if saved == nil {
			db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", p.key)
		} else {
			db.Exec("INSERT INTO cp_state_blobs(store_key,payload) VALUES($1,$2) ON CONFLICT(store_key) DO UPDATE SET payload=$2", p.key, saved)
		}
	}()
	a, b := newBreakGlassRequestStore(), newBreakGlassRequestStore()
	gate := &runtimeLeaseGate{postgresBlobPersister: p}
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	auth := newAdminAuthStore()
	tenant := "tenant_lab_001"
	auth.UpsertPrincipal(adminPrincipal{ID: "bg-admin", TenantID: tenant, Roles: []string{"admin"}, Status: "active"})
	auth.UpsertSession(adminSession{ID: "bg-session", TenantID: tenant, AdminPrincipalID: "bg-admin", Roles: []string{"admin"}, Status: "active", ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339), Metadata: map[string]any{adminCSRFTokenKey: "bg-csrf"}})
	h := newServerWithConfig(serverConfig{Writer: writer, Evaluator: testEvaluator(), AdminAuth: auth, BreakGlassRequests: a})
	if err = a.SetPersister(gate); err != nil {
		t.Fatal(err)
	}
	if err = b.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	foreign, err := b.Create(breakGlassSessionRequest{TenantID: "foreign", UserID: "keep", Reason: "peer"}, "foreign", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	call := func(path, body string, want int) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest("POST", path, strings.NewReader(body))
		r.AddCookie(&http.Cookie{Name: "admin_session", Value: "bg-session"})
		r.Header.Set("X-CSRF-Token", "bg-csrf")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("%s: %d want %d %s", path, w.Code, want, w.Body)
		}
		return w
	}
	cpLeaderElectorInstance = leader
	edgeIsControlPlane = true
	leader.tick()
	if !leader.IsLeader() {
		t.Fatal("initial leader")
	}
	rotate := func() {
		leader.release()
		peerLeader.tick()
		if !peerLeader.IsLeader() {
			t.Fatal("peer election")
		}
		peerLeader.release()
		leader.tick()
		if !leader.IsLeader() {
			t.Fatal("reelection")
		}
	}
	body := `{"user_id":"requester","reason":"synthetic recovery"}`
	for _, stage := range []string{"create", "approve", "issue"} {
		path := "/break-glass/requests"
		payload := body
		if stage != "create" {
			item, err := b.CreateContext(captureCPWriteLease(context.Background()), breakGlassSessionRequest{TenantID: tenant, UserID: "requester", Reason: "peer request"}, tenant, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			path += "/" + item.ID
			if stage == "approve" {
				path += "/approve"
				payload = `{"approver_user_id":"approver"}`
			} else {
				if _, err = b.ApproveContext(captureCPWriteLease(context.Background()), item.ID, breakGlassApprovalRequest{ApproverUserID: "peer-approver"}, time.Now(), nil); err != nil {
					t.Fatal(err)
				}
				path += "/issue-session"
				payload = ""
			}
		}
		before, _ := p.Load()
		gate.before = rotate
		call(path, payload, 503)
		gate.before = nil
		after, _ := p.Load()
		if !bytes.Equal(before, after) {
			t.Fatal("old term wrote authority")
		}
		want := 201
		if stage == "approve" {
			want = 200
		}
		call(path, payload, want)
		if stage == "issue" {
			call(path, payload, 400)
		}
		fresh := newBreakGlassRequestStore()
		if err = fresh.SetPersister(p); err != nil {
			t.Fatal(err)
		}
		if _, ok := fresh.Get(foreign.ID); !ok {
			t.Fatal("peer request lost")
		}
	}
	call("/break-glass/requests/"+foreign.ID+"/approve", `{"approver_user_id":"intruder"}`, 404)
	// Two stale CP copies cannot consume the same approval, even without a shared process lock.
	item, err := b.CreateContext(captureCPWriteLease(context.Background()), breakGlassSessionRequest{TenantID: tenant, UserID: "u", Reason: "once"}, tenant, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = b.ApproveContext(captureCPWriteLease(context.Background()), item.ID, breakGlassApprovalRequest{ApproverUserID: "a"}, time.Now(), nil); err != nil {
		t.Fatal(err)
	}
	ctx := captureCPWriteLease(context.Background())
	done := make(chan error, 2)
	for i, s := range []*breakGlassRequestStore{a, b} {
		go func(i int, s *breakGlassRequestStore) {
			id := []string{"session-a", "session-b"}[i]
			_, err := s.MarkSessionIssuedContext(ctx, item.ID, id, time.Now(), nil)
			done <- err
		}(i, s)
	}
	successes := 0
	for i := 0; i < 2; i++ {
		if <-done == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("issued %d times", successes)
	}
	raw, _ := p.Load()
	for _, bad := range [][]byte{[]byte(`null`), []byte(`{"bad":{"id":"bad","status":"approved"}}`), {}} {
		if _, err = db.Exec("UPDATE cp_state_blobs SET payload=$2 WHERE store_key=$1", p.key, bad); err != nil {
			t.Fatal(err)
		}
		if _, _, err = a.GetChecked(item.ID); err == nil {
			t.Fatal("bad authority trusted")
		}
		call("/break-glass/requests", body, 503)
	}
	if _, err = db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", p.key); err != nil {
		t.Fatal(err)
	}
	if _, _, err = a.GetChecked(item.ID); err == nil {
		t.Fatal("missing authority trusted")
	}
	call("/break-glass/requests", body, 503)
	if _, err = db.Exec("INSERT INTO cp_state_blobs(store_key,payload) VALUES($1,$2)", p.key, raw); err != nil {
		t.Fatal(err)
	}
	got, ok, err := a.GetChecked(item.ID)
	if err != nil || !ok || got.Status != "session_issued" {
		t.Fatalf("recovery: %v %v %+v", err, ok, got)
	}
	rows, _ := writer.ReadJSONL("audit.log.jsonl")
	domainCount := 0
	for _, row := range rows {
		if strings.HasPrefix(stringValue(row["event_type"]), "break_glass_") {
			domainCount++
			if row["actor_user_id"] != "bg-admin" || row["tenant_id"] != tenant {
				t.Fatalf("wrong domain actor: %+v", row)
			}
		}
	}
	if domainCount != 3 {
		t.Fatalf("domain audit count %d", domainCount)
	}
	outcomes := map[string]int{}
	for _, row := range readTransportAudits(t, writer) {
		if row.EventType == "admin_config_change" && row.Result != nil {
			outcomes[*row.Result]++
		}
	}
	if outcomes["success"] != 3 || outcomes["error"] != 9 {
		raw, _ := json.Marshal(readTransportAudits(t, writer))
		t.Fatalf("transport audit missing: %s", raw)
	}
	t.Logf("transport outcomes: %+v", outcomes)
}
