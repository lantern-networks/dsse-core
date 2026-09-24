package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/enrolledinventory"
	"github.com/lantern-networks/dsse-core/tenantca"
)

func TestPostgresEnrolmentReportCannotOutliveLeadership(t *testing.T) {
	for _, reacquire := range []bool{false, true} {
		t.Run(fmt.Sprint("reacquire=", reacquire), func(t *testing.T) {
			a, b := postgresFailureElectors(t)
			db, err := newCPStateBlobDB(os.Getenv("POSTGRES_QUEUE_E2E_DSN"), "../../migrations", true)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			p := postgresBlobPersister{db: db, key: "test_report_leader"}
			db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", p.key)
			defer db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", p.key)
			l := enrolledinventory.NewLedger()
			if err := l.SetPersisterChecked(p); err != nil {
				t.Fatal(err)
			}
			l.Enroll("target", "tenant_a", "", "now")
			old := cpLeaderElectorInstance
			cpLeaderElectorInstance = a
			defer func() { cpLeaderElectorInstance = old }()
			a.tick()
			h := http.NewServeMux()
			registerEnrolmentReportRoute(h, l, nil, "", true, nil)
			body := &pausedSeatBody{Reader: strings.NewReader(`{"identity":"target","tenant_id":"tenant_a","machine_ref":"machine"}`), entered: make(chan struct{}), resume: make(chan struct{})}
			w := httptest.NewRecorder()
			done := make(chan struct{})
			go func() { defer close(done); h.ServeHTTP(w, httptest.NewRequest("POST", "/enrolment-report", body)) }()
			select {
			case <-body.entered:
			case <-time.After(5 * time.Second):
				t.Fatal("body not reached")
			}
			a.release()
			b.tick()
			if !b.IsLeader() {
				close(body.resume)
				<-done
				t.Fatal("peer not elected")
			}
			peer := enrolledinventory.NewLedger()
			if err := peer.SetPersisterChecked(p); err != nil {
				t.Fatal(err)
			}
			peer.SetEnabledChecked("target", false, "peer")
			peer.Enroll("foreign", "tenant_b", "peer", "peer")
			if reacquire {
				b.release()
				a.tick()
				if !a.IsLeader() {
					close(body.resume)
					<-done
					t.Fatal("original node not re-elected")
				}
			}
			before, _ := p.Load()
			generation := l.ConfigGeneration()
			close(body.resume)
			<-done
			after, _ := p.Load()
			if w.Code != 503 || !bytes.Equal(before, after) || generation != l.ConfigGeneration() {
				t.Fatalf("stale report status=%d saved_unchanged=%v generation_unchanged=%v", w.Code, bytes.Equal(before, after), generation == l.ConfigGeneration())
			}
		})
	}
}

func TestPostgresEnrolmentReportRetriesStorageFailure(t *testing.T) {
	a, _ := postgresFailureElectors(t)
	db, err := newCPStateBlobDB(os.Getenv("POSTGRES_QUEUE_E2E_DSN"), "../../migrations", true)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	p := postgresBlobPersister{db: db, key: "test_report_retry"}
	db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", p.key)
	defer db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", p.key)
	l := enrolledinventory.NewLedger()
	if err := l.SetPersisterChecked(p); err != nil {
		t.Fatal(err)
	}
	l.Enroll("foreign", "tenant_b", "untouched", "now")
	old := cpLeaderElectorInstance
	cpLeaderElectorInstance = a
	defer func() { cpLeaderElectorInstance = old }()
	a.tick()
	h := http.NewServeMux()
	registerEnrolmentReportRoute(h, l, nil, "", true, nil)
	srv := httptest.NewServer(h)
	defer srv.Close()
	if _, err := db.Exec("ALTER TABLE cp_state_blobs ADD CONSTRAINT test_report_refusal CHECK (store_key <> 'test_report_retry') NOT VALID"); err != nil {
		t.Fatal(err)
	}
	defer db.Exec("ALTER TABLE cp_state_blobs DROP CONSTRAINT IF EXISTS test_report_refusal")
	outbox := filepath.Join(t.TempDir(), "outbox.jsonl")
	reporter := func() *enrolmentCPReporter {
		return &enrolmentCPReporter{url: srv.URL, machineURL: srv.URL + "/enrolment-report", machineClient: srv.Client(), outboxPath: outbox}
	}
	reporter().Report(enrolmentReport{Identity: "new-device", TenantID: "tenant_a", Group: "Pilot", MachineRef: "machine-a"})
	raw, err := os.ReadFile(outbox)
	if err != nil || !strings.Contains(string(raw), "new-device") {
		t.Fatalf("durable retry lost: %v", err)
	}
	if _, ok := l.EntryFor("new-device"); ok {
		t.Fatal("failed save published")
	}
	if _, err := db.Exec("ALTER TABLE cp_state_blobs DROP CONSTRAINT test_report_refusal"); err != nil {
		t.Fatal(err)
	}
	reporter().drainOnce(context.Background())
	if _, err := os.Stat(outbox); !os.IsNotExist(err) {
		t.Fatal("delivered report still queued")
	}
	restored := enrolledinventory.NewLedger()
	if err := restored.SetPersisterChecked(p); err != nil {
		t.Fatal(err)
	}
	e, ok := restored.EntryFor("new-device")
	if !ok || e.MachineRef != "machine-a" || e.DeviceEnrolledAt == "" || e.TenantID != "tenant_a" || e.Group != "Pilot" {
		t.Fatalf("incomplete saved report: %+v", e)
	}
	if e, ok := restored.EntryFor("foreign"); !ok || e.Note != "untouched" {
		t.Fatal("foreign device lost")
	}
	if _, err := restored.SetEnabledChecked("new-device", false, "disabled"); err != nil {
		t.Fatal(err)
	}
	reporter().Report(enrolmentReport{Identity: "new-device", TenantID: "tenant_a", MachineRef: "other"})
	final := enrolledinventory.NewLedger()
	final.SetPersisterChecked(p)
	if e, _ := final.EntryFor("new-device"); e.Enabled || e.MachineRef != "machine-a" {
		t.Fatal("delayed report undid admin disable")
	}
	if _, err := os.Stat(outbox); !os.IsNotExist(err) {
		t.Fatal("settled disabled refusal was queued")
	}
}

func TestEnrolmentReportEnforcesShipperTenant(t *testing.T) {
	dir := t.TempDir()
	ca := makeTestCA(t, dir, "report-ca", 77)
	reg, err := tenantca.LoadTenantCARegistry(writeRegistry(t, dir, map[string]string{"tenant_a": ca.pemPath}))
	if err != nil {
		t.Fatal(err)
	}
	chains := leafSignedBy(t, ca, "edge-a", reg.Pool)
	if len(chains) == 0 {
		t.Fatal("unverified fixture")
	}
	old := auditIngestAuthorityMap
	defer func() { auditIngestAuthorityMap = old }()
	for _, tc := range []struct {
		name, tenant string
		authority    *auditIngestAuthority
		status       int
	}{
		{"own", "tenant_a", nil, 204}, {"foreign", "tenant_b", nil, 403}, {"explicit foreign", "tenant_b", &auditIngestAuthority{byEdge: map[string][]string{"edge-a": {"tenant_b"}}}, 204}, {"wildcard", "tenant_b", &auditIngestAuthority{byEdge: map[string][]string{"edge-a": {"*"}}}, 204}, {"unmapped", "tenant_a", &auditIngestAuthority{byEdge: map[string][]string{}}, 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			auditIngestAuthorityMap = tc.authority
			l := enrolledinventory.NewLedger()
			h := http.NewServeMux()
			registerEnrolmentReportRoute(h, l, reg, "", false, nil)
			req := httptest.NewRequest("POST", "/enrolment-report", strings.NewReader(`{"identity":"new-device","tenant_id":"`+tc.tenant+`"}`))
			req.TLS = &tls.ConnectionState{PeerCertificates: chains[0][:1], VerifiedChains: chains}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			if w.Code != tc.status {
				t.Fatalf("status=%d want=%d", w.Code, tc.status)
			}
			if _, ok := l.EntryFor("new-device"); ok != (tc.status == 204) {
				t.Fatal("authorization state mismatch")
			}
		})
	}
}
