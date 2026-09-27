package main

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/revocation"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// A deterministic advisory-lock connection model. This does not substitute for
// the separately gated test against Postgres; it lets storage/promotion barriers
// be paused and failed without timers or an external database.
type promotionLockModel struct {
	mu      sync.Mutex
	owner   *promotionModelConn
	pingErr error
}
type promotionConnector struct{ model *promotionLockModel }

func (c promotionConnector) Connect(context.Context) (driver.Conn, error) {
	return &promotionModelConn{model: c.model}, nil
}
func (c promotionConnector) Driver() driver.Driver { return promotionDriver{} }

type promotionDriver struct{}

func (promotionDriver) Open(string) (driver.Conn, error) { return nil, fmt.Errorf("use connector") }

type promotionModelConn struct{ model *promotionLockModel }

func (*promotionModelConn) Prepare(string) (driver.Stmt, error) {
	return nil, fmt.Errorf("unexpected prepare")
}
func (*promotionModelConn) Begin() (driver.Tx, error) {
	return nil, fmt.Errorf("unexpected transaction")
}
func (c *promotionModelConn) Close() error {
	c.model.mu.Lock()
	defer c.model.mu.Unlock()
	if c.model.owner == c {
		c.model.owner = nil
	}
	return nil
}
func (c *promotionModelConn) Ping(context.Context) error {
	c.model.mu.Lock()
	defer c.model.mu.Unlock()
	return c.model.pingErr
}
func (c *promotionModelConn) QueryContext(_ context.Context, q string, _ []driver.NamedValue) (driver.Rows, error) {
	if q != "SELECT pg_try_advisory_lock($1)" {
		return nil, fmt.Errorf("unexpected query")
	}
	c.model.mu.Lock()
	defer c.model.mu.Unlock()
	got := c.model.owner == nil || c.model.owner == c
	if got {
		c.model.owner = c
	}
	return &promotionBoolRows{value: got}, nil
}
func (c *promotionModelConn) ExecContext(_ context.Context, q string, _ []driver.NamedValue) (driver.Result, error) {
	if q != "SELECT pg_advisory_unlock($1)" {
		return nil, fmt.Errorf("unexpected exec")
	}
	c.model.mu.Lock()
	defer c.model.mu.Unlock()
	if c.model.owner == c {
		c.model.owner = nil
	}
	return driver.RowsAffected(1), nil
}

type promotionBoolRows struct{ value, done bool }

func (*promotionBoolRows) Columns() []string { return []string{"locked"} }
func (*promotionBoolRows) Close() error      { return nil }
func (r *promotionBoolRows) Next(dst []driver.Value) error {
	if r.done {
		return io.EOF
	}
	r.done = true
	dst[0] = r.value
	return nil
}
func newPromotionModelElector(m *promotionLockModel) *cpLeaderElector {
	db := sql.OpenDB(promotionConnector{m})
	db.SetMaxOpenConns(2)
	return &cpLeaderElector{db: db}
}

func promotionRead(h http.Handler, path string) *httptest.ResponseRecorder {
	q := httptest.NewRequest("GET", path, nil)
	q.Header.Set("Authorization", "Bearer "+transportAuditBearer)
	r := httptest.NewRecorder()
	h.ServeHTTP(r, q)
	return r
}
func TestAdmissionPromotionLoadsLatestAuthoredState(t *testing.T) {
	oldCP, oldE := edgeIsControlPlane, cpLeaderElectorInstance
	defer func() { edgeIsControlPlane = oldCP; cpLeaderElectorInstance = oldE }()
	edgeIsControlPlane = true
	for _, backend := range []string{"postgres", "postgres+import:carried.json"} {
		for _, initialBlock := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/initial_%t", backend, initialBlock), func(t *testing.T) {
				cpLeaderElectorInstance = nil
				h, _, candidate, _ := transportAuditHandler(t)
				p := blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "state.json")}
				author := revocation.NewAdmissionRevocations()
				if err := author.SetPersister(p); err != nil {
					t.Fatal(err)
				}
				author.Revoke("other-device", "keep foreign")
				if initialBlock {
					author.Revoke("owned-device", "old")
				}
				if err := candidate.SetPersister(p); err != nil {
					t.Fatal(err)
				}
				if initialBlock {
					author.Restore("owned-device")
				} else {
					author.Revoke("owned-device", "new")
				}
				e := newPromotionModelElector(&promotionLockModel{})
				defer func() { e.release(); e.db.Close() }()
				configureAdmissionPromotion(e, backend, candidate)
				cpLeaderElectorInstance = e
				for _, path := range []string{"/admin/revocations", "/admin/transport-admission"} {
					r := promotionRead(h, path)
					if r.Code != 409 || strings.Contains(r.Body.String(), "owned-device") {
						t.Fatalf("standby answered %s: %d", path, r.Code)
					}
				}
				e.tick()
				if !e.IsLeader() {
					t.Fatal("not promoted")
				}
				r := promotionRead(h, "/admin/revocations")
				var f revocationFeed
				if err := json.Unmarshal(r.Body.Bytes(), &f); err != nil {
					t.Fatal(err)
				}
				_, blocked := f.Revoked["owned-device"]
				if r.Code != 200 || !f.Authoritative || blocked == initialBlock || f.Revoked["other-device"] != "keep foreign" {
					t.Fatalf("stale promoted feed: %+v", f)
				}
				if r := promotionRead(h, "/admin/transport-admission"); r.Code != 200 || strings.Contains(r.Body.String(), "other-device") {
					t.Fatalf("tenant read: %d %s", r.Code, r.Body.String())
				}
				before := candidate.ConfigGeneration()
				e.release()
				e.tick()
				if !e.IsLeader() || candidate.ConfigGeneration() != before {
					t.Fatal("same snapshot promotion churn")
				}
			})
		}
	}
}
func TestAdmissionPromotionWaitsForReadAndReleasesFailedLock(t *testing.T) {
	oldCP, oldE := edgeIsControlPlane, cpLeaderElectorInstance
	defer func() { edgeIsControlPlane = oldCP; cpLeaderElectorInstance = oldE }()
	edgeIsControlPlane = true
	cpLeaderElectorInstance = nil
	h, _, _, _ := transportAuditHandler(t)
	m := &promotionLockModel{}
	e := newPromotionModelElector(m)
	peer := newPromotionModelElector(m)
	defer func() { e.release(); peer.release(); e.db.Close(); peer.db.Close() }()
	cpLeaderElectorInstance = e
	entered, finish, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	e.prepareLeadership = func() error { close(entered); <-finish; return errors.New("PRIVATE_STORAGE_VALUE") }
	go func() { e.tick(); close(done) }()
	<-entered
	if e.IsLeader() || !e.LeaderSince().IsZero() {
		t.Fatal("published while reading")
	}
	if r := promotionRead(h, "/leader"); r.Code != 503 {
		t.Fatalf("leader status %d", r.Code)
	}
	if r := promotionRead(h, "/admin/revocations"); r.Code != 409 {
		t.Fatalf("feed status %d", r.Code)
	}
	if r := transportAuditRequest(h, "revoke", `{"identity":"owned-device"}`, transportAuditBearer); r.Code != 409 {
		t.Fatalf("write admitted while preparing: %d", r.Code)
	}
	peer.tick()
	if peer.IsLeader() {
		t.Fatal("peer acquired lock during preparation")
	}
	close(finish)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("preparation did not finish")
	}
	if e.IsLeader() {
		t.Fatal("failed preparation published")
	}
	peer.tick()
	if !peer.IsLeader() {
		t.Fatal("failure stranded the lock")
	}
	peer.release()
	e.prepareLeadership = func() error { return nil }
	e.tick()
	if !e.IsLeader() {
		t.Fatal("retry did not recover")
	}
}
func TestAdmissionPromotionRefusesInvalidRefresh(t *testing.T) {
	for _, raw := range []string{"", `{"schema_version":"unknown","revoked":{}}`, `{"schema_version":"admission_revocations_state.v1","revoked":null}`} {
		t.Run(fmt.Sprintf("bytes_%d", len(raw)), func(t *testing.T) {
			p := blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "state.json")}
			a := revocation.NewAdmissionRevocations()
			a.SetPersister(p)
			a.Revoke("owned-device", "keep")
			os.WriteFile(p.Path, []byte(raw), 0600)
			e := newPromotionModelElector(&promotionLockModel{})
			defer func() { e.release(); e.db.Close() }()
			configureAdmissionPromotion(e, "postgres", a)
			e.tick()
			if e.IsLeader() {
				t.Fatal("invalid state acquired leadership")
			}
			if _, ok := a.IsRevoked("owned-device"); !ok {
				t.Fatal("invalid state discarded live block")
			}
			got, _ := os.ReadFile(p.Path)
			if string(got) != raw {
				t.Fatal("invalid state rewritten")
			}
		})
	}
}
func TestAdmissionPromotionBackendAndStartupWiring(t *testing.T) {
	for _, backend := range []string{"", "memory", "state.json"} {
		e := newPromotionModelElector(&promotionLockModel{})
		configureAdmissionPromotion(e, backend, revocation.NewAdmissionRevocations())
		if e.prepareLeadership != nil {
			t.Fatalf("changed %q ownership", backend)
		}
		e.db.Close()
	}
	configureAdmissionPromotion(nil, "postgres", revocation.NewAdmissionRevocations())
	// Pin the production startup boundary: election must not run before the
	// loaded overlay has been attached to its promotion barrier.
	b, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	start := strings.Index(s, "cpLeaderElectorInstance.Start()")
	load := strings.Index(s, "livenessRevocations.SetPersister(p)")
	attach := strings.Index(s, "configureAdmissionPromotion(cpLeaderElectorInstance,")
	if strings.Count(s, "cpLeaderElectorInstance.Start()") != 1 || load < 0 || attach <= load || start <= attach {
		t.Fatal("election can start before admission preparation is attached")
	}
}

func TestAdmissionPromotionRechecksConnectionAfterRefresh(t *testing.T) {
	m := &promotionLockModel{}
	e, peer := newPromotionModelElector(m), newPromotionModelElector(m)
	defer func() { e.release(); peer.release(); e.db.Close(); peer.db.Close() }()
	e.prepareLeadership = func() error { m.mu.Lock(); m.pingErr = errors.New("connection lost"); m.mu.Unlock(); return nil }
	e.tick()
	if e.IsLeader() {
		t.Fatal("published after losing the lock connection")
	}
	m.mu.Lock()
	m.pingErr = nil
	m.mu.Unlock()
	peer.tick()
	if !peer.IsLeader() {
		t.Fatal("unavailable preparation stranded the peer")
	}
}
