package main

import (
	"context"
	"github.com/lantern-networks/dsse-core/grantstore"
	"os"
	"testing"
	"time"
)

func TestPostgresGrantPendingErasureAndTenantReplacement(t *testing.T) {
	_, _ = postgresFailureElectors(t)
	db, err := newCPStateBlobDB(os.Getenv("POSTGRES_QUEUE_E2E_DSN"), "../../migrations", true)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	oldE, oldCP := cpLeaderElectorInstance, edgeIsControlPlane
	cpLeaderElectorInstance = nil
	edgeIsControlPlane = true
	defer func() { cpLeaderElectorInstance = oldE; edgeIsControlPlane = oldCP }()
	p := postgresBlobPersister{db: db, key: "grants"}
	saved, err := p.Load()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if saved == nil {
			db.Exec("DELETE FROM cp_state_blobs WHERE store_key='grants'")
		} else {
			db.Exec("UPDATE cp_state_blobs SET payload=$1 WHERE store_key='grants'", saved)
		}
	}()
	for _, replacement := range []bool{false, true} {
		name := "erased"
		if replacement {
			name = "reassigned"
		}
		t.Run(name, func(t *testing.T) {
			if _, err := db.Exec("DELETE FROM cp_state_blobs WHERE store_key='grants'"); err != nil {
				t.Fatal(err)
			}
			a, b := grantstore.NewStore(), grantstore.NewStore()
			for _, s := range []*grantstore.Store{a, b} {
				if err := s.SetPersister(p); err != nil {
					t.Fatal(err)
				}
			}
			now := time.Now()
			if _, err := a.Mint(grantstore.Grant{GrantID: "target", TenantID: "a"}, time.Hour, now); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if _, found, err := a.RevokeForTenantContext(ctx, "a", "target"); !found || err == nil {
				t.Fatal("missing local denial", found, err)
			}
			if _, err := b.RemoveTenantChecked("a"); err != nil {
				t.Fatal(err)
			}
			if replacement {
				if _, err := b.Mint(grantstore.Grant{GrantID: "target", TenantID: "b"}, time.Hour, now); err != nil {
					t.Fatal(err)
				}
			}
			if rows, err := a.ListChecked("a"); err != nil || len(rows) != 0 {
				t.Fatal("erasure/read boundary", rows, err)
			}
			if replacement && !a.Valid("target", now) {
				t.Fatal("foreign replacement blocked")
			}
			if _, err := a.Mint(grantstore.Grant{GrantID: "peer", TenantID: "c"}, time.Hour, now); err != nil {
				t.Fatal(err)
			}
			if rows, err := b.ListChecked("a"); err != nil || len(rows) != 0 {
				t.Fatal("erased record written back", rows, err)
			}
			if replacement {
				if _, err := b.RemoveTenantChecked("b"); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := b.Mint(grantstore.Grant{GrantID: "target", TenantID: "a"}, time.Hour, now); err != nil {
				t.Fatal(err)
			}
			if a.Valid("target", now) {
				t.Fatal("unrelated write lost denial")
			}
			if _, _, err := a.RevokeForTenant("a", "target"); err != nil {
				t.Fatal(err)
			}
			restart := grantstore.NewStore()
			if err := restart.SetPersister(p); err != nil || restart.Valid("target", now) || !restart.Valid("peer", now) {
				t.Fatal("durable retry lost denial or peer", err)
			}
		})
	}
}
