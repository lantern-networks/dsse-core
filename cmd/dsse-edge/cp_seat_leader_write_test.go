package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/seatallocation"
)

type pausedSeatBody struct {
	io.Reader
	entered, resume chan struct{}
	once            sync.Once
}

func (b *pausedSeatBody) Read(p []byte) (int, error) {
	b.once.Do(func() { close(b.entered); <-b.resume })
	return b.Reader.Read(p)
}
func (b *pausedSeatBody) Close() error { return nil }

func TestPostgresSeatRequestCannotOutliveLeadership(t *testing.T) {
	a, b := postgresFailureElectors(t)
	db, err := newCPStateBlobDB(os.Getenv("POSTGRES_QUEUE_E2E_DSN"), filepath.Join("..", "..", "migrations"), true)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	p := postgresBlobPersister{db: db, key: "test_seat_leader_request"}
	db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", p.key)
	defer db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", p.key)
	seats := seatallocation.NewStore()
	if err := seats.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	policy := seatallocation.Policy{PoolSeats: 100}
	if _, err := seats.Allocate(policy, "tenant_target", 5, "seed", "", "now"); err != nil {
		t.Fatal(err)
	}
	peer := seatallocation.NewStore()
	if err := peer.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	old := cpLeaderElectorInstance
	cpLeaderElectorInstance = a
	defer func() { cpLeaderElectorInstance = old }()
	a.tick()
	if !a.IsLeader() {
		t.Fatal("no initial leader")
	}
	auth := newAdminAuthStore()
	now := time.Now()
	auth.UpsertPrincipal(adminPrincipal{ID: "review", TenantID: "tenant_lab_001", Roles: []string{"owner"}, Status: "active"})
	auth.UpsertSession(adminSession{ID: "seat-session", TenantID: "tenant_lab_001", AdminPrincipalID: "review", Roles: []string{"owner"}, Status: "active", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), Metadata: map[string]any{adminCSRFTokenKey: "seat-csrf"}})
	handler := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), AdminAuth: auth, SeatAllocations: seats, VendorLicense: newLicenseStore(), LicenseAllowOversubscription: true, OperatorTenantID: "tenant_lab_001"})
	body := &pausedSeatBody{Reader: strings.NewReader(`{"tenant_id":"tenant_target","seats":7}`), entered: make(chan struct{}), resume: make(chan struct{})}
	req := httptest.NewRequest("POST", "/admin/seat-allocations", body)
	req.AddCookie(&http.Cookie{Name: "admin_session", Value: "seat-session"})
	req.Header.Set("X-CSRF-Token", "seat-csrf")
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { defer close(done); handler.ServeHTTP(rec, req) }()
	select {
	case <-body.entered:
	case <-done:
		t.Fatalf("body not reached: %d %s", rec.Code, rec.Body)
	case <-time.After(5 * time.Second):
		t.Fatal("body deadline")
	}
	oldLease := captureCPWriteLease(context.Background())
	a.release()
	b.tick()
	if !b.IsLeader() {
		close(body.resume)
		<-done
		t.Fatal("peer not elected")
	}
	if _, err := peer.Allocate(policy, "tenant_target", 11, "peer", "", "later"); err != nil {
		t.Fatal(err)
	}
	if _, err := peer.Allocate(policy, "tenant_foreign", 13, "peer", "", "later"); err != nil {
		t.Fatal(err)
	}
	close(body.resume)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("response deadline")
	}
	if removed, err := seats.RemoveConfirmedContext(oldLease, "tenant_target"); removed || !errors.Is(err, seatallocation.ErrPersistence) {
		t.Fatal("stale removal accepted", removed, err)
	}
	fresh := seatallocation.NewStore()
	if err := fresh.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusServiceUnavailable || fresh.SeatsFor("tenant_target") != 11 || fresh.SeatsFor("tenant_foreign") != 13 {
		t.Fatalf("old request wrote after takeover: status=%d target=%d foreign=%d body=%s", rec.Code, fresh.SeatsFor("tenant_target"), fresh.SeatsFor("tenant_foreign"), rec.Body)
	}
}

func TestPostgresSeatCommitUsesLeaderSession(t *testing.T) {
	a, b := postgresFailureElectors(t)
	db, err := newCPStateBlobDB(os.Getenv("POSTGRES_QUEUE_E2E_DSN"), filepath.Join("..", "..", "migrations"), true)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	p := postgresBlobPersister{db: db, key: "test_seat_commit"}
	defer db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", p.key)
	if err := p.Save([]byte(`{"kept":true}`)); err != nil {
		t.Fatal(err)
	}
	old := cpLeaderElectorInstance
	cpLeaderElectorInstance = a
	defer func() { cpLeaderElectorInstance = old }()
	a.tick()
	if !a.IsLeader() {
		t.Fatal("no initial leader")
	}
	lease := captureCPWriteLease(context.Background())
	var pid int
	if err := a.conn.QueryRowContext(context.Background(), "SELECT pg_backend_pid()").Scan(&pid); err != nil {
		t.Fatal(err)
	}
	err = p.UpdateContext(lease, func(raw []byte) ([]byte, error) {
		var killed bool
		if err := b.db.QueryRow("SELECT pg_terminate_backend($1)", pid).Scan(&killed); err != nil || !killed {
			t.Fatalf("terminate: %v", err)
		}
		b.tick()
		if !b.IsLeader() {
			t.Fatal("peer did not take over dead session")
		}
		return []byte(`{"kept":false}`), nil
	})
	if err == nil {
		t.Fatal("old transaction survived lock session termination")
	}
	raw, err := p.Load()
	if err != nil || string(raw) != `{"kept":true}` {
		t.Fatalf("uncommitted write persisted: %s %v", raw, err)
	}
	a.tick()
	b.release()
	a.tick()
	if !a.IsLeader() {
		t.Fatal("reacquire failed")
	}
	called := false
	if err := p.UpdateContext(lease, func(raw []byte) ([]byte, error) { called = true; return raw, nil }); err == nil || called {
		t.Fatal("old lease reused in new term")
	}
	if err := p.UpdateContext(captureCPWriteLease(context.Background()), func(raw []byte) ([]byte, error) { return []byte(`{"fresh":true}`), nil }); err != nil {
		t.Fatal(err)
	}
}

func TestPostgresSeatSharedUpdateAndPromotion(t *testing.T) {
	a, b := postgresFailureElectors(t)
	db, err := newCPStateBlobDB(os.Getenv("POSTGRES_QUEUE_E2E_DSN"), filepath.Join("..", "..", "migrations"), true)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	p := postgresBlobPersister{db: db, key: "test_seat_shared"}
	db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", p.key)
	defer db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", p.key)
	newStore := func() *seatallocation.Store {
		t.Helper()
		s := seatallocation.NewStore()
		if err := s.SetPersister(p); err != nil {
			t.Fatal(err)
		}
		return s
	}
	author, stale := newStore(), newStore()
	policy := seatallocation.Policy{PoolSeats: 20}
	if _, err := author.Allocate(policy, "foreign", 13, "admin", "", "now"); err != nil {
		t.Fatal(err)
	}
	if _, err := stale.Allocate(policy, "target", 8, "admin", "", "now"); !errors.Is(err, seatallocation.ErrPoolExceeded) {
		t.Fatalf("pool check used stale state: %v", err)
	}
	if _, err := stale.Allocate(policy, "target", 7, "admin", "", "now"); err != nil {
		t.Fatal(err)
	}
	if stale.SeatsFor("foreign") != 13 {
		t.Fatal("foreign lost")
	}
	if removed, err := author.RemoveConfirmed("target"); err != nil || !removed {
		t.Fatal("cached absence hid shared allocation", removed, err)
	}
	if newStore().SeatsFor("foreign") != 13 {
		t.Fatal("remove erased foreign")
	}
	configureSeatPromotion(b, "postgres", stale)
	a.tick()
	a.release()
	b.tick()
	if !b.IsLeader() || stale.Has("target") || stale.SeatsFor("foreign") != 13 {
		t.Fatal("promotion used stale allocations")
	}
	b.release()
	saved, _ := p.Load()
	if err := p.Save([]byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	b.tick()
	if b.IsLeader() {
		t.Fatal("corrupt snapshot promoted")
	}
	if stale.SeatsFor("foreign") != 13 {
		t.Fatal("failed load changed live state")
	}
	if err := p.Save(saved); err != nil {
		t.Fatal(err)
	}
	b.tick()
	if !b.IsLeader() {
		t.Fatal("repair failed")
	}
}

func TestPostgresSeatCommitCompletesBeforeGracefulHandover(t *testing.T) {
	a, b := postgresFailureElectors(t)
	db, err := newCPStateBlobDB(os.Getenv("POSTGRES_QUEUE_E2E_DSN"), "../../migrations", true)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	p := postgresBlobPersister{db: db, key: "test_seat_handover"}
	defer db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", p.key)
	old := cpLeaderElectorInstance
	cpLeaderElectorInstance = a
	defer func() { cpLeaderElectorInstance = old }()
	a.tick()
	lease := captureCPWriteLease(context.Background())
	entered, resume := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- p.UpdateContext(lease, func(raw []byte) ([]byte, error) { close(entered); <-resume; return []byte(`{"committed":true}`), nil })
	}()
	select {
	case <-entered:
	case err := <-done:
		t.Fatal(err)
	case <-time.After(5 * time.Second):
		t.Fatal("transaction did not begin")
	}
	released := make(chan struct{})
	go func() { a.release(); close(released) }()
	select {
	case <-released:
		close(resume)
		<-done
		t.Fatal("leadership released during transaction")
	case <-time.After(20 * time.Millisecond):
	}
	b.tick()
	if b.IsLeader() {
		close(resume)
		<-done
		t.Fatal("peer acquired while transaction open")
	}
	close(resume)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	select {
	case <-released:
	case <-time.After(5 * time.Second):
		t.Fatal("release did not finish")
	}
	b.tick()
	if !b.IsLeader() {
		t.Fatal("handover failed")
	}
	raw, err := p.Load()
	if err != nil || string(raw) != `{"committed":true}` {
		t.Fatal("commit lost", string(raw), err)
	}
}
