package main

import (
	"context"
	"github.com/lantern-networks/dsse-core/seatallocation"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSeatErasureCannotCompleteWithoutSaving(t *testing.T) {
	path := filepath.Join(t.TempDir(), "seats.json")
	seats := seatallocation.NewStore()
	seats.SetStateFile(path)
	for _, id := range []string{"tenant_own", "tenant_other"} {
		if _, err := seats.Allocate(seatallocation.Policy{PoolSeats: 20}, id, 5, "admin", "", "now"); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Rename(path, path+".saved"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	purge := func() adminTenantPurgeResult {
		return purgeAdminTenantData(context.Background(), "node", "tenant_own", nil, nil, nil, nil, nil, nil, "", nil, nil, adminTenantExtraStores{SeatAllocations: seats}, nil, time.Now())
	}
	result := purge()
	if result.Complete || len(result.Failures) != 1 || seats.SeatsFor("tenant_own") != 5 {
		t.Fatal("unsaved allocation erasure accepted")
	}
	for _, r := range result.Erased {
		if r.Store == "seat_allocation" {
			t.Fatal("reported unconfirmed erasure")
		}
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path+".saved", path); err != nil {
		t.Fatal(err)
	}
	if result = purge(); !result.Complete || len(result.Failures) != 0 {
		t.Fatalf("retry: %+v", result)
	}
	reload := seatallocation.NewStore()
	reload.SetStateFile(path)
	if reload.SeatsFor("tenant_own") != 0 || reload.SeatsFor("tenant_other") != 5 {
		t.Fatal("stored erasure wrong")
	}
}
