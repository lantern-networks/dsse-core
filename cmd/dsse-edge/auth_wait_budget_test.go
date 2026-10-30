package main

import (
	"fmt"
	"testing"
)

func TestAuthWaitBudgetCountsAcrossTunnelsAndReleases(t *testing.T) {
	var b authWaitBudget
	var releases []func()
	for tenant := 0; tenant < 4; tenant++ {
		for device := 0; device < 8; device++ {
			for flow := 0; flow < authWaitDeviceLimit; flow++ {
				release, ok := b.acquire(fmt.Sprint(tenant), fmt.Sprint(device))
				if !ok {
					t.Fatal("premature refusal")
				}
				releases = append(releases, release)
			}
			if _, ok := b.acquire(fmt.Sprint(tenant), fmt.Sprint(device)); ok {
				t.Fatal("device limit bypassed")
			}
		}
		if _, ok := b.acquire(fmt.Sprint(tenant), "new"); ok {
			t.Fatal("tenant limit bypassed")
		}
	}
	if _, ok := b.acquire("new", "new"); ok {
		t.Fatal("Edge limit bypassed")
	}
	for _, release := range releases {
		release()
		release()
	}
	if b.total != 0 || len(b.devices) != 0 || len(b.tenants) != 0 {
		t.Fatal("wait accounting leaked")
	}
	if _, ok := b.acquire("", "device"); ok {
		t.Fatal("unattributed wait admitted")
	}
}
