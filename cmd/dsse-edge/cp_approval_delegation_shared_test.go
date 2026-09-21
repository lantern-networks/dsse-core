package main

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/delegatedgrant"
	"github.com/lantern-networks/dsse-core/humanapproval"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestPostgresApprovalDelegationPeerTermRevocation(t *testing.T) {
	leader, peerLeader := postgresFailureElectors(t)
	db, err := newCPStateBlobDB(os.Getenv("POSTGRES_QUEUE_E2E_DSN"), "../../migrations", true)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	oldE, oldCP := cpLeaderElectorInstance, edgeIsControlPlane
	defer func() { cpLeaderElectorInstance = oldE; edgeIsControlPlane = oldCP }()
	for _, key := range []string{"human_approvals", "delegated_grants"} {
		t.Run(key, func(t *testing.T) {
			cpLeaderElectorInstance = nil
			edgeIsControlPlane = true
			p := postgresBlobPersister{db: db, key: key}
			saved, err := p.Load()
			if err != nil {
				t.Fatal(err)
			}
			if _, err = db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", key); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if saved == nil {
					db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", key)
				} else {
					db.Exec("INSERT INTO cp_state_blobs(store_key,payload) VALUES($1,$2) ON CONFLICT(store_key) DO UPDATE SET payload=$2", key, saved)
				}
			}()
			gate := &runtimeLeaseGate{postgresBlobPersister: p}
			writer, err := logs.NewWriter(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer writer.Close()
			auth := newAdminAuthStore()
			tenant := "tenant_lab_001"
			auth.UpsertPrincipal(adminPrincipal{ID: "pair-admin", TenantID: tenant, Roles: []string{"admin"}, Status: "active"})
			auth.UpsertSession(adminSession{ID: "pair-session", TenantID: tenant, AdminPrincipalID: "pair-admin", Roles: []string{"admin"}, Status: "active", ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339), Metadata: map[string]any{adminCSRFTokenKey: "pair-csrf"}})
			config := serverConfig{Writer: writer, Evaluator: testEvaluator(), AdminAuth: auth}
			var bind func(blobstore.Persister) error
			var peerWrite func(context.Context, string, string) error
			var erased func(context.Context, string) (int, error)
			var restart func() error
			path, body := "/admin/human-approval-events", `{"id":"own","approver_user_id":"approver","subject_user_id":"person","actor_nhi_id":"agent","action_type":"read","approval_result":"approved"}`
			if key == "human_approvals" {
				a, b := humanapproval.NewStore(16), humanapproval.NewStore(16)
				config.HumanApprovals = a
				bind = a.SetPersister
				erased = a.RemoveTenantContext
				if err = b.SetPersister(p); err != nil {
					t.Fatal(err)
				}
				peerWrite = func(ctx context.Context, tenant, id string) error {
					_, err := b.UpsertContext(ctx, model.HumanApprovalEvent{TenantID: tenant, ID: id, ApprovalResult: "approved"})
					return err
				}
				restart = func() error { return humanapproval.NewStore(16).SetPersister(p) }
			} else {
				a, b := delegatedgrant.NewStore(16), delegatedgrant.NewStore(16)
				config.DelegatedGrants = a
				bind = a.SetPersister
				erased = a.RemoveTenantContext
				if err = b.SetPersister(p); err != nil {
					t.Fatal(err)
				}
				peerWrite = func(ctx context.Context, tenant, id string) error {
					_, err := b.UpsertContext(ctx, model.DelegatedAccessGrant{TenantID: tenant, ID: id, Status: "active"})
					return err
				}
				restart = func() error { return delegatedgrant.NewStore(16).SetPersister(p) }
				path, body = "/admin/delegated-grants", `{"id":"own","actor_nhi_id":"agent","subject_user_id":"person","tool_ids":["read"],"status":"active"}`
			}
			h := newServerWithConfig(config)
			if err = bind(gate); err != nil {
				t.Fatal(err)
			}
			if err = peerWrite(context.Background(), "foreign", "keep"); err != nil {
				t.Fatal(err)
			}
			call := func(method, path, body string, want int) *httptest.ResponseRecorder {
				t.Helper()
				r := httptest.NewRequest(method, path, strings.NewReader(body))
				r.AddCookie(&http.Cookie{Name: "admin_session", Value: "pair-session"})
				r.Header.Set("X-CSRF-Token", "pair-csrf")
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				if w.Code != want {
					t.Fatalf("%s %s: %d want %d %s", method, path, w.Code, want, w.Body)
				}
				return w
			}
			cpLeaderElectorInstance = leader
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
			for _, suffix := range []string{"", "/own/revoke"} {
				payload := body
				if suffix != "" {
					payload = `{}`
				}
				before, _ := p.Load()
				gate.before = rotate
				failed := call("POST", path+suffix, payload, 500)
				if suffix != "" && key == "delegated_grants" {
					var result map[string]any
					if err := json.Unmarshal(failed.Body.Bytes(), &result); err != nil || result["status"] != "partial" || result["applied"] != true {
						t.Fatalf("missing denial outcome: %s", failed.Body)
					}
					grant, ok := config.DelegatedGrants.GetForTenant(tenant, "own")
					if !ok || delegatedgrant.IsActive(grant, time.Now()) {
						t.Fatal("old-term save refusal revived local authorization")
					}
				}
				gate.before = nil
				after, _ := p.Load()
				if !bytes.Equal(before, after) {
					t.Fatal("old term changed authority")
				}
				call("POST", path+suffix, payload, 200)
				if err = restart(); err != nil {
					t.Fatal(err)
				}
				raw, _ := p.Load()
				var rows map[string]json.RawMessage
				if err = json.Unmarshal(raw, &rows); err != nil || len(rows) != 2 {
					t.Fatalf("peer lost: %s %v", raw, err)
				}
			}
			if err = peerWrite(captureCPWriteLease(context.Background()), tenant, "own"); err == nil {
				t.Fatal("stale peer revived revoked record")
			}
			call("POST", path+"/keep/revoke", `{}`, 404)
			call("GET", path+"/own", "", 200)
			// A second CP adds an erasure target after this copy's last edit.
			if err = peerWrite(captureCPWriteLease(context.Background()), "erase-me", "later"); err != nil {
				t.Fatal(err)
			}
			if n, err := erased(captureCPWriteLease(context.Background()), "erase-me"); err != nil || n != 1 {
				t.Fatalf("latest-row erasure %d %v", n, err)
			}
			raw, _ := p.Load()
			for _, bad := range [][]byte{[]byte(`null`), []byte(`{}`[:1]), {}} {
				if _, err = db.Exec("UPDATE cp_state_blobs SET payload=$2 WHERE store_key=$1", key, bad); err != nil {
					t.Fatal(err)
				}
				call("GET", path, "", 500)
				call("POST", path, body, 500)
			}
			if _, err = db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", key); err != nil {
				t.Fatal(err)
			}
			call("GET", path+"/own", "", 500)
			call("POST", path, body, 500)
			if _, err = db.Exec("INSERT INTO cp_state_blobs(store_key,payload) VALUES($1,$2)", key, raw); err != nil {
				t.Fatal(err)
			}
			call("GET", path+"/own", "", 200)
			audits, _ := writer.ReadJSONL("audit.log.jsonl")
			domain := 0
			for _, row := range audits {
				if strings.HasPrefix(stringValue(row["event_type"]), "admin_human_approval_event_") || strings.HasPrefix(stringValue(row["event_type"]), "admin_delegated_access_grant_") {
					domain++
					if row["actor_user_id"] != "pair-admin" || row["tenant_id"] != tenant {
						t.Fatalf("wrong audit attribution: %+v", row)
					}
				}
			}
			wantDomain := 3
			if domain != wantDomain {
				t.Fatalf("domain audits %d", domain)
			}
			outcomes := map[string]int{}
			for _, row := range readTransportAudits(t, writer) {
				if row.EventType == "admin_config_change" && row.Result != nil {
					outcomes[*row.Result]++
				}
			}
			if outcomes["success"] != 2 || outcomes["error"] != 7 {
				t.Fatalf("transport outcomes %+v", outcomes)
			}
			t.Logf("peer/terminal/term/read/erasure/restart/audit: %+v", outcomes)
			leader.release()
		})
	}
}
