package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/lantern-networks/dsse-core/enrolledinventory"
	"github.com/lantern-networks/dsse-core/revocation"
)

func TestPostgresPromotionRefreshesAuthoredStoresBeforeServing(t *testing.T) {
	a, b := postgresFailureElectors(t)
	db, err := newCPStateBlobDB(os.Getenv("POSTGRES_QUEUE_E2E_DSN"), filepath.Join("..", "..", "migrations"), true)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	keys := []string{"test_promotion_admission", "test_promotion_risk", "test_promotion_inventory"}
	for _, key := range keys {
		if _, err := db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", key); err != nil {
			t.Fatal(err)
		}
	}
	defer func() {
		for _, key := range keys {
			db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", key)
		}
	}()
	pa, pr, pi := postgresBlobPersister{db: db, key: keys[0]}, postgresBlobPersister{db: db, key: keys[1]}, postgresBlobPersister{db: db, key: keys[2]}
	newStores := func() (*revocation.AdmissionRevocations, *revocation.HighRiskOverlay, *enrolledinventory.Ledger) {
		t.Helper()
		ad := revocation.NewAdmissionRevocations()
		risk := revocation.NewHighRiskOverlay()
		inventory := enrolledinventory.NewLedger()
		if err := ad.SetPersister(pa); err != nil {
			t.Fatal(err)
		}
		if err := risk.SetPersister(pr); err != nil {
			t.Fatal(err)
		}
		if err := inventory.SetPersisterChecked(pi); err != nil {
			t.Fatal(err)
		}
		return ad, risk, inventory
	}
	authorAd, authorRisk, authorInventory := newStores()
	if _, err := authorInventory.Enroll("target", "tenant_lab_001", "", "now"); err != nil {
		t.Fatal(err)
	}
	if _, err := authorInventory.Enroll("foreign", "other", "", "now"); err != nil {
		t.Fatal(err)
	}
	if err := authorAd.RevokeChecked("foreign", "keep"); err != nil {
		t.Fatal(err)
	}
	if _, err := authorRisk.SetDeviceRisk("foreign", "high"); err != nil {
		t.Fatal(err)
	}
	ad, risk, inventory := newStores()
	configureAdmissionPromotion(b, "postgres", ad)
	configureRiskPromotion(b, "postgres", risk)
	configureInventoryPromotion(b, "postgres", inventory)
	a.tick()
	if !a.IsLeader() {
		t.Fatal("initial election failed")
	}
	if err := authorAd.RevokeChecked("target", "new block"); err != nil {
		t.Fatal(err)
	}
	if _, err := authorRisk.SetDeviceRisk("target", "critical"); err != nil {
		t.Fatal(err)
	}
	if _, err := authorInventory.SetEnabledChecked("target", false, "later"); err != nil {
		t.Fatal(err)
	}
	if _, blocked := ad.IsRevoked("target"); blocked || !inventory.IsAdmitted("target") {
		t.Fatal("candidate was not stale")
	}
	b.tick()
	if b.IsLeader() {
		t.Fatal("candidate became leader while old leader held lock")
	}
	a.release()
	b.tick()
	if !b.IsLeader() {
		t.Fatal("promotion failed")
	}
	if _, blocked := ad.IsRevoked("target"); !blocked || risk.Snapshot()["target"] != "critical" || inventory.IsAdmitted("target") {
		t.Fatal("promoted stale state")
	}
	if _, blocked := ad.IsRevoked("foreign"); !blocked || !inventory.IsAdmitted("foreign") {
		t.Fatal("foreign state lost")
	}
	// A real database row with invalid content cannot be published as an authority.
	saved, err := pr.Load()
	if err != nil {
		t.Fatal(err)
	}
	b.release()
	if err := pr.Save([]byte(`{"version":`)); err != nil {
		t.Fatal(err)
	}
	b.tick()
	if b.IsLeader() {
		t.Fatal("bad shared row published leadership")
	}
	a.tick()
	if !a.IsLeader() {
		t.Fatal("failed preparation stranded the advisory lock")
	}
	if err := pr.Save(saved); err != nil {
		t.Fatal(err)
	}
	a.release()
	b.tick()
	if !b.IsLeader() {
		t.Fatal("repaired row did not recover")
	}
	// Startup of another store instance observes the same durable authored state.
	ad2, risk2, inventory2 := newStores()
	if _, blocked := ad2.IsRevoked("target"); !blocked || risk2.Snapshot()["target"] != "critical" || inventory2.IsAdmitted("target") {
		t.Fatal("shared persistence lost updates")
	}
	if err := db.PingContext(context.Background()); err != nil {
		t.Fatal(err)
	}
}
