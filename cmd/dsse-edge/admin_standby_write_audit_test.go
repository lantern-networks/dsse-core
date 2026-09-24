package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
)

// Embedding a nil interface makes any auth-store or outbox call panic. A routing
// refusal must not resolve credentials or contact the authority to record itself.
type standbyNoAuthCalls struct{ adminAuthRuntimeStore }
type standbyNoOutboxCalls struct{ adminAuditOutboxDeadReader }
type standbyUnreadBody struct{}

func (standbyUnreadBody) Read([]byte) (int, error) { panic("standby read request body") }
func (standbyUnreadBody) Close() error             { return nil }

func standbyAuditElection(t *testing.T) *cpLeaderElector {
	t.Helper()
	old := cpLeaderElectorInstance
	e := newPromotionModelElector(&promotionLockModel{})
	cpLeaderElectorInstance = e
	t.Cleanup(func() { e.release(); e.db.Close(); cpLeaderElectorInstance = old })
	return e
}

func assertStandbyAudit(t *testing.T, a model.AuditLog, permission string) {
	t.Helper()
	if a.EventType != "admin_write_refused_on_standby" || a.TenantID != testEvaluator().PolicyBundle.TenantID ||
		a.ActorUserID != nil || a.ActorNHIID != nil || a.TargetID != nil || a.SourceIP != nil || a.SessionID != nil ||
		stringPtrValue(a.TargetType) != "admin_endpoint" || stringPtrValue(a.Action) != "admin_route" ||
		stringPtrValue(a.Result) != "refused" || stringPtrValue(a.Reason) != "not_leader" || a.ID == "" || a.Timestamp == "" {
		t.Fatalf("untruthful routing audit: %+v", a)
	}
	want := map[string]any{"audit_scope": "node", "authentication": "not_evaluated", "request_tenant": "not_evaluated", "required_permission": permission, "http_status": float64(409)}
	metadata := make(map[string]any)
	for k, v := range a.Metadata {
		metadata[k] = v
	}
	if metadata["aggregation"] != "permission_window" || metadata["interval_seconds"] != float64(60) {
		t.Fatalf("missing aggregation contract: %#v", metadata)
	}
	count, ok := metadata["request_count"].(float64)
	if !ok || count < 1 {
		t.Fatal("invalid count", metadata)
	}
	first, err := time.Parse(time.RFC3339Nano, metadata["first_seen"].(string))
	if err != nil {
		t.Fatal(err)
	}
	last, err := time.Parse(time.RFC3339Nano, metadata["last_seen"].(string))
	if err != nil || last.Before(first) {
		t.Fatal("invalid observation interval", metadata)
	}
	for _, k := range []string{"aggregation", "interval_seconds", "request_count", "first_seen", "last_seen"} {
		delete(metadata, k)
	}
	if !reflect.DeepEqual(metadata, want) {
		t.Fatalf("unexpected metadata: %#v", a.Metadata)
	}
}

func TestStandbyWriteAuditDoesNotAuthenticateReadBodyOrMirror(t *testing.T) {
	standbyAuditElection(t)
	w, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	recorder := newAdminStandbyAudit(w, testEvaluator())
	mw := newAdminEndpointMiddleware(testEvaluator(), w, standbyNoOutboxCalls{}, standbyNoAuthCalls{}, "", false, nil, nil, nil, recorder)
	for _, permission := range []string{"admin.endpoints.write", "admin.tenant.admin", "admin.export.create", "admin.export.cancel"} {
		for _, credentials := range []string{"anonymous", "bearer", "cookie"} {
			r := httptest.NewRequest("POST", "/admin/private-path?token=private-query", nil)
			r.Body = standbyUnreadBody{}
			r.Header.Set("X-Operate-Tenant", "foreign-private-tenant")
			r.Header.Set("User-Agent", strings.Repeat("private-agent", 10000))
			r.Header.Set("X-Forwarded-For", "private-forwarded")
			if credentials == "bearer" {
				r.Header.Set("Authorization", "Bearer private-token")
			}
			if credentials == "cookie" {
				r.AddCookie(&http.Cookie{Name: "admin_session", Value: "private-session"})
			}
			ctx, cancel := context.WithCancel(r.Context())
			cancel()
			rec := httptest.NewRecorder()
			mw(permission, func(http.ResponseWriter, *http.Request) { t.Fatal("refused handler called") })(rec, r.WithContext(ctx))
			if rec.Code != 409 {
				t.Fatalf("refusal changed: %d %s", rec.Code, rec.Body)
			}
			rows := readTransportAudits(t, w)
			if len(rows) == 0 {
				t.Fatal("routing refusal left no audit")
			}
			assertStandbyAudit(t, rows[len(rows)-1], permission)
		}
	}
	recorder.flush(true)
	rows := readTransportAudits(t, w)
	if len(rows) != 8 {
		t.Fatalf("want initial and summary per permission: %d", len(rows))
	}
	var count float64
	for _, row := range rows {
		count += row.Metadata["request_count"].(float64)
	}
	if count != 12 {
		t.Fatal("lost refusal counts", count)
	}
	b, _ := json.Marshal(rows)
	if bytes.Contains(b, []byte("private-")) || len(b) > 16000 {
		t.Fatal("untrusted request data entered routing audit")
	}
}

func TestStandbyWriteAuditActualRoutePreservesStateAndResumes(t *testing.T) {
	cpBefore := cpLeaderElectorInstance
	cpLeaderElectorInstance = nil
	t.Cleanup(func() { cpLeaderElectorInstance = cpBefore })
	h, w, risk, out, runtime, disk := deviceRiskAuditHandler(t)
	e := standbyAuditElection(t)
	before, err := disk.Load()
	if err != nil {
		t.Fatal(err)
	}
	oldRisk, oldRuntime := risk.Snapshot(), runtime.List()
	for _, bearer := range []string{transportAuditBearer, transportAuditReadBearer, "invalid"} {
		r := deviceRiskRequest(h, `{"entity_type":"device","entity_id":"owned-device","severity":"critical","evidence_ref":"private-body"}`, bearer)
		if r.Code != 409 {
			t.Fatalf("standby %d %s", r.Code, r.Body)
		}
	}
	after, _ := disk.Load()
	if !bytes.Equal(before, after) || !reflect.DeepEqual(oldRisk, risk.Snapshot()) || !reflect.DeepEqual(oldRuntime, runtime.List()) || len(out.insertedAudits) != 0 {
		t.Fatal("refused request changed state or contacted outbox")
	}
	rows := readTransportAudits(t, w)
	if len(rows) != 1 {
		t.Fatalf("want immediate refusal record, got %d", len(rows))
	}
	for _, a := range rows {
		assertStandbyAudit(t, a, "admin.risk.write")
	}
	e.tick()
	if !e.IsLeader() {
		t.Fatal("promotion failed")
	}
	r := deviceRiskRequest(h, `{"entity_type":"device","entity_id":"owned-device","severity":"high"}`, transportAuditBearer)
	if r.Code != 200 || risk.Snapshot()["owned-device"] != "high" {
		t.Fatalf("leader failed %d %s", r.Code, r.Body)
	}
	rows = readTransportAudits(t, w)
	if len(rows) != 3 || len(out.insertedAudits) != 1 {
		t.Fatalf("leader audit changed: %d / %d", len(rows), len(out.insertedAudits))
	}
	for _, a := range rows[1:] {
		if stringPtrValue(a.ActorUserID) != "transport-admin" {
			t.Fatal("leader lost verified actor")
		}
	}
}

func TestStandbyWriteAuditStorageFailureKeepsRefusal(t *testing.T) {
	standbyAuditElection(t)
	for _, missing := range []bool{false, true} {
		t.Run(map[bool]string{false: "unwritable", true: "unconfigured"}[missing], func(t *testing.T) {
			var w *logs.Writer
			if !missing {
				var err error
				w, err = logs.NewWriter(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				if err = os.Mkdir(filepath.Join(w.Dir(), "audit.log.jsonl"), 0700); err != nil {
					t.Fatal(err)
				}
			}
			var captured bytes.Buffer
			previous := log.Writer()
			log.SetOutput(&captured)
			defer log.SetOutput(previous)
			recorder := newAdminStandbyAudit(w, testEvaluator())
			mw := newAdminEndpointMiddleware(testEvaluator(), w, standbyNoOutboxCalls{}, standbyNoAuthCalls{}, "", false, nil, nil, nil, recorder)
			r := httptest.NewRequest("POST", "/admin/private-path", nil)
			r.Header.Set("Authorization", "Bearer private-token")
			rec := httptest.NewRecorder()
			mw("admin.policy.write", func(http.ResponseWriter, *http.Request) { t.Fatal("handler called") })(rec, r)
			if rec.Code != 409 {
				t.Fatalf("audit failure opened request: %d", rec.Code)
			}
			if !strings.Contains(captured.String(), "admin_audit_write_failed") || !strings.Contains(captured.String(), "admin_write_refused_on_standby") || strings.Contains(captured.String(), "private-") {
				t.Fatalf("missing/unsafe failure signal: %s", &captured)
			}
			if !missing && w.AuditHealth().PrimaryFailures != 1 {
				t.Fatal("writer health did not record failure")
			}
		})
	}
}

func TestStandbyWriteAuditConcurrentRefusals(t *testing.T) {
	standbyAuditElection(t)
	w, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	recorder := newAdminStandbyAudit(w, testEvaluator())
	mw := newAdminEndpointMiddleware(testEvaluator(), w, standbyNoOutboxCalls{}, standbyNoAuthCalls{}, "", false, nil, nil, nil, recorder)
	h := mw("admin.policy.write", func(http.ResponseWriter, *http.Request) { panic("handler called") })
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rec := httptest.NewRecorder()
			h(rec, httptest.NewRequest("PUT", "/admin/policy", nil))
			if rec.Code != 409 {
				t.Errorf("status %d", rec.Code)
			}
		}()
	}
	wg.Wait()
	if attempts := w.AuditHealth().Attempts; attempts != 1 {
		t.Fatal("burst amplified writes", attempts)
	}
	recorder.flush(true)
	rows := readTransportAudits(t, w)
	if len(rows) != 2 {
		t.Fatalf("want first and summary: %d", len(rows))
	}
	if rows[0].Metadata["request_count"].(float64)+rows[1].Metadata["request_count"].(float64) != 64 {
		t.Fatal("lost request count")
	}
	ids := map[string]bool{}
	for _, a := range rows {
		assertStandbyAudit(t, a, "admin.policy.write")
		if ids[a.ID] {
			t.Fatal("duplicate id")
		}
		ids[a.ID] = true
	}
}

func TestStandbyWriteAuditDoesNotMislabelReadsOrSingleNode(t *testing.T) {
	standbyAuditElection(t)
	w, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	mw := newAdminEndpointMiddleware(testEvaluator(), w, nil, nil, "", false, nil, nil, nil)
	for _, single := range []bool{false, true} {
		if single {
			cpLeaderElectorInstance = nil
		}
		p := "admin.state.read"
		if single {
			p = "admin.policy.write"
		}
		rec := httptest.NewRecorder()
		mw(p, func(http.ResponseWriter, *http.Request) { t.Fatal("anonymous authorized") })(rec, httptest.NewRequest("GET", "/admin/state", nil))
		if rec.Code != 401 {
			t.Fatalf("authentication changed: %d", rec.Code)
		}
	}
	if h := w.AuditHealth(); h.Attempts != 0 {
		t.Fatalf("invented routing audit: %+v", h)
	}
}
