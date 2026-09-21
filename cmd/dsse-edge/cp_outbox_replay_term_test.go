package main

import (
	"context"
	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/logs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPostgresOutboxReplayRejectsPreviousLeadershipTerm(t *testing.T) {
	a, b := postgresFailureElectors(t)
	ctx := context.Background()
	applyPostgresExportTaskQueueMigration(t, ctx, a.db)
	oldE, oldCP := cpLeaderElectorInstance, edgeIsControlPlane
	cpLeaderElectorInstance = a
	edgeIsControlPlane = true
	defer func() { cpLeaderElectorInstance = oldE; edgeIsControlPlane = oldCP }()
	for _, table := range []string{"admin_audit_outbox", "domain_event_outbox"} {
		_, err := a.db.Exec("DELETE FROM " + table + " WHERE tenant_id='replay-term-test'")
		if err != nil {
			t.Fatal(err)
		}
		defer a.db.Exec("DELETE FROM " + table + " WHERE tenant_id='replay-term-test'")
	}
	statements := []string{
		`INSERT INTO admin_audit_outbox (tenant_id,outbox_id,event_type,status,occurred_at,dead_at,publish_attempt,last_error,payload) VALUES ('replay-term-test','dead','test','dead',now(),now(),5,'failed','{}')`,
		`INSERT INTO domain_event_outbox (tenant_id,outbox_id,schema_version,event_plane,stream,event_type,status,occurred_at,received_at,dead_at,publish_attempt,last_error,payload_checksum,payload) VALUES ('replay-term-test','dead','test','domain','device_events','test','dead',now(),now(),now(),5,'failed','sha256:'||repeat('0',64),'{}')`,
	}
	for _, sql := range statements {
		if _, err := a.db.Exec(sql); err != nil {
			t.Fatal(err)
		}
	}
	a.tick()
	if !a.IsLeader() {
		t.Fatal("no initial leader")
	}
	stale := captureCPWriteLease(ctx)
	a.release()
	b.tick()
	if !b.IsLeader() {
		t.Fatal("peer takeover failed")
	}
	b.release()
	a.tick()
	if !a.IsLeader() {
		t.Fatal("new term absent")
	}
	replay := []struct {
		name string
		run  func(context.Context, string) (bool, error)
	}{
		{"admin_audit_outbox", func(c context.Context, tenant string) (bool, error) {
			_, found, err := replayPostgresAdminAuditOutboxDeadRow(c, a.db, tenant, "dead", time.Now())
			return found, err
		}},
		{"domain_event_outbox", func(c context.Context, tenant string) (bool, error) {
			_, found, err := replayPostgresDomainEventOutboxDeadRow(c, a.db, tenant, "domain", "dead", time.Now())
			return found, err
		}},
	}
	for _, item := range replay {
		t.Run(item.name, func(t *testing.T) {
			if found, err := item.run(stale, "replay-term-test"); found || err == nil {
				t.Fatal("previous term replayed", found, err)
			}
			var status string
			var attempt int
			if err := a.db.QueryRow("SELECT status,publish_attempt FROM "+item.name+" WHERE tenant_id='replay-term-test'").Scan(&status, &attempt); err != nil || status != "dead" || attempt != 5 {
				t.Fatal("stale replay changed row", status, attempt, err)
			}
			// The route must capture leadership before decoding a request body.
			writer, err := logs.NewWriter(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer writer.Close()
			h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: writer, Registry: connector.NewRegistry(), AdminAuditOutbox: postgresAdminAuditOutboxReader{DB: a.db}, DomainEventOutbox: postgresDomainEventOutboxStore{DB: a.db}})
			path := "/admin/audit-outbox/dead/dead/replay"
			if item.name == "domain_event_outbox" {
				path = "/admin/domain-event-outbox/dead/dead/replay?event_plane=domain"
			}
			req := httptest.NewRequest(http.MethodPost, path, nil)
			req.Body = &enrolmentTermBody{Reader: strings.NewReader(`{"reason":"old term"}`), before: func() {
				a.release()
				b.tick()
				if !b.IsLeader() {
					t.Fatal("body takeover failed")
				}
				b.release()
				a.tick()
			}}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusInternalServerError {
				t.Fatal("route lost old lease", rec.Code, rec.Body.String())
			}
			fresh := captureCPWriteLease(ctx)
			if found, err := item.run(fresh, "foreign"); found || err != nil {
				t.Fatal("foreign replay", found, err)
			}
			if found, err := item.run(fresh, "replay-term-test"); !found || err != nil {
				t.Fatal("current term refused", found, err)
			}
			if err := a.db.QueryRow("SELECT status,publish_attempt FROM "+item.name+" WHERE tenant_id='replay-term-test'").Scan(&status, &attempt); err != nil || status != "pending" || attempt != 0 {
				t.Fatal("retry not committed", status, attempt, err)
			}
		})
	}
}

func TestOutboxReplayStandbyRefusalIsAudited(t *testing.T) {
	old := cpLeaderElectorInstance
	cpLeaderElectorInstance = &cpLeaderElector{}
	defer func() { cpLeaderElectorInstance = old }()
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	audit := &recordingAdminAuditOutboxDeadReader{replayFound: true}
	domain := &recordingDomainEventOutbox{replayFound: true}
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: writer, Registry: connector.NewRegistry(), AdminAuditOutbox: audit, DomainEventOutbox: domain})
	for _, path := range []string{"/admin/audit-outbox/dead/dead/replay", "/admin/domain-event-outbox/dead/dead/replay?event_plane=domain"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"reason":"retry"}`)))
		if rec.Code != http.StatusConflict {
			t.Fatal(rec.Code, rec.Body.String())
		}
	}
	if audit.replayOutboxID != "" || domain.replayOutboxID != "" {
		t.Fatal("standby reached replay writer")
	}
	rows, err := readAuditRowsExcludingWrapper(writer)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatal("missing refusals", rows)
	}
	for _, row := range rows {
		if row["event_type"] != "admin_write_refused_on_standby" || row["result"] != "refused" {
			t.Fatal(row)
		}
	}
}
