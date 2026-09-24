package main

import (
	"bytes"
	"context"
	"fmt"
	"github.com/lantern-networks/dsse-core/enrolledinventory"
	"github.com/lantern-networks/dsse-core/revocation"
	"github.com/lantern-networks/dsse-core/seatallocation"
	"os"
	"testing"
	"time"
)

func TestPostgresTenantPurgeSharedStores(t *testing.T) {
	for _, stale := range []bool{false, true} {
		t.Run(fmt.Sprint("stale=", stale), func(t *testing.T) {
			a, b := postgresFailureElectors(t)
			db, err := newCPStateBlobDB(os.Getenv("POSTGRES_QUEUE_E2E_DSN"), "../../migrations", true)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			p := func(k string) postgresBlobPersister { return postgresBlobPersister{db: db, key: "test_purge_" + k} }
			for _, k := range []string{"inventory", "risk", "admission", "seats"} {
				db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", p(k).key)
				defer db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", p(k).key)
			}
			ledger := enrolledinventory.NewLedger()
			if err := ledger.SetPersisterChecked(p("inventory")); err != nil {
				t.Fatal(err)
			}
			risk := revocation.NewHighRiskOverlay()
			if err := risk.SetPersister(p("risk")); err != nil {
				t.Fatal(err)
			}
			ad := revocation.NewAdmissionRevocations()
			if err := ad.SetPersister(p("admission")); err != nil {
				t.Fatal(err)
			}
			seats := seatallocation.NewStore()
			if err := seats.SetPersister(p("seats")); err != nil {
				t.Fatal(err)
			}
			policy := seatallocation.Policy{PoolSeats: 100}
			if _, err := ledger.Enroll("owned", "tenant_gone", "", "now"); err != nil {
				t.Fatal(err)
			}
			if _, err := risk.SetDeviceRisk("owned", "high"); err != nil {
				t.Fatal(err)
			}
			if _, err := risk.SetUserRisk(revocation.UserRisk{TenantID: "tenant_gone", ID: "user", Severity: "high"}); err != nil {
				t.Fatal(err)
			}
			if err := ad.RevokeChecked("owned", "block"); err != nil {
				t.Fatal(err)
			}
			if _, err := seats.Allocate(policy, "tenant_gone", 3, "", "", "now"); err != nil {
				t.Fatal(err)
			}
			old := cpLeaderElectorInstance
			cpLeaderElectorInstance = a
			defer func() { cpLeaderElectorInstance = old }()
			a.tick()
			ctx := captureCPWriteLease(context.Background())
			// Peer's newer unrelated data must survive a purge using stale live caches.
			peerLedger := enrolledinventory.NewLedger()
			peerLedger.SetPersisterChecked(p("inventory"))
			peerLedger.Enroll("foreign", "tenant_other", "peer", "now")
			peerLedger.Enroll("late-owned", "tenant_gone", "late", "now")
			peerRisk := revocation.NewHighRiskOverlay()
			peerRisk.SetPersister(p("risk"))
			peerRisk.SetDeviceRisk("foreign", "critical")
			peerRisk.SetDeviceRisk("late-owned", "high")
			peerRisk.SetUserRisk(revocation.UserRisk{TenantID: "tenant_other", ID: "user", Severity: "critical"})
			peerAd := revocation.NewAdmissionRevocations()
			peerAd.SetPersister(p("admission"))
			peerAd.RevokeChecked("foreign", "peer")
			peerAd.RevokeChecked("late-owned", "late")
			peerAd.RevokeFromMeshChecked("received", "mesh")
			peerSeats := seatallocation.NewStore()
			peerSeats.SetPersister(p("seats"))
			peerSeats.Allocate(policy, "tenant_other", 7, "", "", "now")
			before := map[string][]byte{}
			for _, k := range []string{"inventory", "risk", "admission", "seats"} {
				before[k], _ = p(k).Load()
			}
			if stale {
				a.release()
				b.tick()
				if !b.IsLeader() {
					t.Fatal("peer election")
				}
				b.release()
				a.tick()
				if !a.IsLeader() {
					t.Fatal("re-election")
				}
			}
			result := purgeAdminTenantData(ctx, "node", "tenant_gone", nil, nil, nil, ledger, nil, nil, "", nil, nil, adminTenantExtraStores{HighRisk: risk, Admissions: ad, SeatAllocations: seats, DeviceIDs: []string{"owned"}}, nil, time.Now())
			if stale {
				if _, err := risk.RemoveTenantRisksContext(ctx, "tenant_gone", []string{"owned"}); err == nil {
					t.Error("risk accepted stale term")
				}
				if _, err := ad.RemoveDevicesContext(ctx, []string{"owned"}); err == nil {
					t.Error("admission accepted stale term")
				}
				if _, err := seats.RemoveTenantContext(ctx, "tenant_gone"); err == nil {
					t.Error("seats accepted stale term")
				}
				if _, err := ledger.RemoveTenantContext(ctx, "tenant_gone"); err == nil {
					t.Error("inventory accepted stale term")
				}
				if result.Complete || len(result.Failures) == 0 {
					t.Errorf("stale purge claimed completion: %+v", result)
				}
				for k, raw := range before {
					after, _ := p(k).Load()
					if !bytes.Equal(raw, after) {
						t.Errorf("stale purge changed %s", k)
					}
				}
				return
			}
			if len(result.Failures) != 0 {
				t.Fatalf("purge failures: %v", result.Failures)
			}
			restored := enrolledinventory.NewLedger()
			restored.SetPersisterChecked(p("inventory"))
			if _, ok := restored.EntryFor("owned"); ok {
				t.Error("owned inventory remains")
			}
			if e, ok := restored.EntryFor("foreign"); !ok || e.Note != "peer" {
				t.Error("foreign inventory lost")
			}
			rr := revocation.NewHighRiskOverlay()
			rr.SetPersister(p("risk"))
			if _, ok := rr.Snapshot()["owned"]; ok {
				t.Error("owned risk remains")
			}
			if rr.Snapshot()["foreign"] != "critical" || len(rr.UserSnapshot()) != 1 || rr.UserSnapshot()[0].TenantID != "tenant_other" {
				t.Error("foreign risk lost")
			}
			ra := revocation.NewAdmissionRevocations()
			ra.SetPersister(p("admission"))
			if _, ok := ra.Snapshot()["owned"]; ok {
				t.Error("owned admission remains")
			}
			if ra.Snapshot()["foreign"] != "peer" || ra.FeedSnapshot()["received"] != "mesh" {
				t.Error("foreign or mesh revocation lost")
			}
			rs := seatallocation.NewStore()
			rs.SetPersister(p("seats"))
			if _, ok := restored.EntryFor("late-owned"); ok {
				t.Error("late inventory remains")
			}
			if _, ok := rr.Snapshot()["late-owned"]; ok {
				t.Error("late risk remains")
			}
			if _, ok := ra.Snapshot()["late-owned"]; ok {
				t.Error("late admission remains")
			}
			if rs.Allocated() != 7 {
				t.Errorf("seat total %d", rs.Allocated())
			}
		})
	}
}
