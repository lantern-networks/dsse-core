package main

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRetentionAndHoldSharedPreservePeer(t *testing.T) {
	t.Run("retention", func(t *testing.T) {
		p := &transactionalCAFixture{}
		a, b := newRetentionOverrideStore(p), newRetentionOverrideStore(p)
		if err := a.Set("audit", 0); err != nil {
			t.Fatal(err)
		}
		if err := b.Set("access", 30); err != nil {
			t.Fatal(err)
		}
		fresh := newRetentionOverrideStore(p)
		if n, ok := fresh.Get("audit"); !ok || n != 0 {
			t.Fatal("stale writer erased peer keep-forever override")
		}
	})
	t.Run("hold", func(t *testing.T) {
		p := &transactionalCAFixture{}
		a, b := newLegalHoldStore(p), newLegalHoldStore(p)
		if err := a.Set("a", "review", "", true, time.Now()); err != nil {
			t.Fatal(err)
		}
		if err := b.Set("b", "review", "", true, time.Now()); err != nil {
			t.Fatal(err)
		}
		fresh := newLegalHoldStore(p)
		if !fresh.IsHeld("a") || !fresh.IsHeld("b") {
			t.Fatal("stale writer erased peer legal hold")
		}
	})
}

type retentionReadFailure struct {
	*transactionalCAFixture
	failRead bool
}

func (p *retentionReadFailure) Load() ([]byte, error) {
	if p.failRead {
		return nil, fmt.Errorf("private-storage-location")
	}
	return p.transactionalCAFixture.Load()
}
func TestRetentionAndHoldSharedFailureAndRecovery(t *testing.T) {
	for _, kind := range []string{"hold", "retention"} {
		t.Run(kind, func(t *testing.T) {
			p := &retentionReadFailure{transactionalCAFixture: &transactionalCAFixture{}}
			hold, ret := newLegalHoldStore(p), newRetentionOverrideStore(p)
			set := func() error {
				if kind == "hold" {
					return hold.Set("a", "review", "", true, time.Now())
				}
				return ret.Set("audit", 0)
			}
			clear := func() error {
				if kind == "hold" {
					return hold.Set("a", "review", "", false, time.Now())
				}
				return ret.Set("audit", -1)
			}
			health := func() error {
				if kind == "hold" {
					return hold.Health()
				}
				return ret.Health()
			}
			protected := func() bool {
				if kind == "hold" {
					return hold.IsHeld("a")
				}
				n, ok := ret.Get("audit")
				return ok && n == 0
			}
			if err := set(); err != nil {
				t.Fatal(err)
			}
			original, _ := p.Load()
			p.failCommit = true
			if err := clear(); err == nil {
				t.Fatal("failed commit acknowledged")
			}
			if !protected() {
				t.Fatal("failed clear removed protection")
			}
			after, _ := p.Load()
			if !bytes.Equal(original, after) {
				t.Fatal("failed commit changed row")
			}
			p.failCommit = false
			p.failRead = true
			if health() == nil || !protected() {
				t.Fatal("read failure permitted deletion")
			}
			cfg := retentionConfig{hotEvents: time.Hour, outboxPublished: time.Hour}
			if kind == "hold" {
				cfg.legalHold = hold
			} else {
				cfg.override = ret
			}
			runRetentionPrune(context.Background(), nil, cfg) // a DB access would panic
			p.failRead = false
			if err := health(); err != nil {
				t.Fatal("valid shared state did not recover", err)
			}
			for _, bad := range [][]byte{nil, []byte(`null`), []byte(`broken`)} {
				p.Save(bad)
				if health() == nil || !protected() {
					t.Fatal("missing/corrupt known state permitted deletion")
				}
				if set() == nil {
					t.Fatal("corrupt row overwritten")
				}
				after, _ := p.Load()
				if !bytes.Equal(bad, after) {
					t.Fatal("corrupt row changed")
				}
			}
			p.Save(original)
			if err := clear(); err != nil {
				t.Fatal(err)
			}
			if protected() {
				t.Fatal("clear retry failed")
			}
		})
	}
}

func TestPostgresRetentionHoldRequestAndPruning(t *testing.T) {
	d, _, a, b := trustDistributionPostgresFixture(t)
	hp := d.store.(postgresBlobPersister)
	hp.key = "legal_hold"
	rp := hp
	rp.key = "retention_override"
	h, hPeer := newLegalHoldStore(hp), newLegalHoldStore(hp)
	r, rPeer := newRetentionOverrideStore(rp), newRetentionOverrideStore(rp)
	now := time.Now()
	if err := hPeer.Set("a", "review", "", true, now); err != nil {
		t.Fatal(err)
	}
	if err := rPeer.Set("audit", 0); err != nil {
		t.Fatal(err)
	}
	if err := h.Set("b", "review", "", true, now); err != nil {
		t.Fatal(err)
	}
	if err := r.Set("access", 1); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	registerLogsRetentionRoutes(mux, func(_ string, next http.HandlerFunc) http.HandlerFunc { return next }, nil, nil, nil, h, r)
	for _, op := range []struct {
		path, body string
		p          postgresBlobPersister
	}{
		{"/admin/legal-hold", `{"active":false}`, hp},
		{"/admin/retention-config", `{"stream":"audit","days":1}`, rp},
	} {
		before, _ := op.p.Load()
		req := httptest.NewRequest("POST", op.path, nil)
		if op.path == "/admin/legal-hold" {
			req = requestWithAdminIdentity(req, adminIdentity{PrincipalID: "review", TenantID: "a"})
		}
		req.Body = &enrolmentTermBody{Reader: strings.NewReader(op.body), before: func() { a.release(); b.tick(); b.release(); a.tick() }}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != 500 {
			t.Fatalf("old term %s got %d: %s", op.path, rec.Code, rec.Body.String())
		}
		after, _ := op.p.Load()
		if !bytes.Equal(before, after) {
			t.Fatal("old request changed row")
		}
	}
	// Isolated real rows: peer hold and keep-forever must affect stale readers.
	if _, err := hp.db.Exec(`CREATE TABLE hot_events(tenant_id text,stream text,received_at timestamptz)`); err != nil {
		t.Fatal(err)
	}
	if _, err := hp.db.Exec(`INSERT INTO hot_events VALUES ('a','access',$1),('c','audit',$1)`, now.Add(-90*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	cfg := retentionConfig{hotEvents: time.Hour, override: r, legalHold: h}
	count := func() int {
		var n int
		if err := hp.db.QueryRow(`SELECT count(*) FROM hot_events`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	pruneHotEventsPerStream(context.Background(), hp.db, cfg, now)
	if count() != 2 {
		t.Fatal("peer protection ignored")
	}
	if err := hPeer.Set("a", "review", "", false, now); err != nil {
		t.Fatal(err)
	}
	if err := rPeer.Set("audit", -1); err != nil {
		t.Fatal(err)
	}
	pruneHotEventsPerStream(context.Background(), hp.db, cfg, now)
	if count() != 0 {
		t.Fatal("committed release/clear did not resume pruning")
	}
	freshH, freshR := newLegalHoldStore(hp), newRetentionOverrideStore(rp)
	if freshH.IsHeld("a") || !freshH.IsHeld("b") {
		t.Fatal("peer hold/release reload mismatch")
	}
	if n, ok := freshR.Get("access"); !ok || n != 1 {
		t.Fatal("peer retention lost")
	}
}
