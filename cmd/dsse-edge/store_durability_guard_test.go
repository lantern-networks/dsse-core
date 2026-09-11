package main

import (
	"path/filepath"
	"sort"
	"testing"
)

func TestWarnVolatileDurableStoresSplitsConfigFromRuntime(t *testing.T) {
	checks := []storeDurabilityCheck{
		{flag: "first-party-store", value: "memory", class: storeClassConfig, impact: "creds"},          // volatile CONFIG
		{flag: "connector-registry-store", value: "postgres", class: storeClassConfig, impact: "fleet"}, // durable CONFIG
		{flag: "vlan-object-store", value: "", jsonMode: true, class: storeClassConfig, impact: "nets"}, // volatile CONFIG (empty)
		{flag: "grant-store", value: "/var/lib/g.json", jsonMode: true, class: storeClassConfig},        // durable CONFIG (path)
		{flag: "admin-auth-store", value: "memory", class: storeClassRuntime, impact: "sessions"},       // volatile RUNTIME
	}

	// Lab: never warns.
	if got := warnVolatileDurableStores(true, checks); len(got.config) != 0 || len(got.runtime) != 0 {
		t.Fatalf("lab must not warn, got %+v", got)
	}

	// Production: CONFIG and RUNTIME are reported separately — the split is the whole point (only CONFIG is the bug).
	got := warnVolatileDurableStores(false, checks)
	sort.Strings(got.config)
	wantConfig := []string{"first-party-store", "vlan-object-store"}
	if len(got.config) != len(wantConfig) || got.config[0] != wantConfig[0] || got.config[1] != wantConfig[1] {
		t.Fatalf("volatile CONFIG stores = %v, want %v", got.config, wantConfig)
	}
	if len(got.runtime) != 1 || got.runtime[0] != "admin-auth-store" {
		t.Fatalf("volatile RUNTIME stores = %v, want [admin-auth-store]", got.runtime)
	}
}

func TestRequireDurableStoresViolationFailsOnConfigOnly(t *testing.T) {
	report := volatileStoreReport{
		config:  []string{"first-party-store", "vlan-object-store"},
		runtime: []string{"admin-auth-store"},
	}
	if got := requireDurableStoresViolation(true, true, report); got != nil {
		t.Fatalf("lab must never fail startup: %v", got)
	}
	if got := requireDurableStoresViolation(false, false, report); got != nil {
		t.Fatalf("requirement off must not fail: %v", got)
	}
	// The teeth apply to CONFIG only: a volatile RUNTIME store is a legitimate production choice, so it must NOT
	// be in the violation set even when the requirement is on.
	got := requireDurableStoresViolation(false, true, report)
	if len(got) != 2 {
		t.Fatalf("production + require: want the 2 CONFIG stores, got %v", got)
	}
	for _, f := range got {
		if f == "admin-auth-store" {
			t.Fatalf("a RUNTIME store must never fail startup: %v", got)
		}
	}
	if got := requireDurableStoresViolation(false, true, volatileStoreReport{runtime: []string{"admin-auth-store"}}); got != nil {
		t.Fatalf("only-runtime-volatile -> no violation: %v", got)
	}
}

func TestDurableStorePathIsDurableByDefault(t *testing.T) {
	// No state dir → legacy behaviour: the value is unchanged (may stay volatile).
	if got := durableStorePath("", "memory", "device_inventory"); got != "memory" {
		t.Fatalf("no state-dir: got %q, want unchanged \"memory\"", got)
	}
	if got := durableStorePath("", "", "vlan_objects"); got != "" {
		t.Fatalf("no state-dir, empty jsonMode: got %q, want unchanged \"\"", got)
	}
	// State dir set + unset/memory store → durable file under the state dir (the whole point: no per-store wiring).
	// Expected values are built with filepath.Join because that is what the function does: this is a real path on
	// the host filesystem, so the separator is the host's. Hard-coding "/dataplane-ne/..." asserted the Linux
	// spelling of a platform-dependent answer, which is the deployment's shape but not the function's contract.
	wantInventory := filepath.Join("/dataplane-ne", "device_inventory.json")
	if got := durableStorePath("/dataplane-ne", "memory", "device_inventory"); got != wantInventory {
		t.Fatalf("memory + state-dir: got %q, want %q", got, wantInventory)
	}
	wantVLAN := filepath.Join("/dataplane-ne", "vlan_objects.json")
	if got := durableStorePath("/dataplane-ne", "", "vlan_objects"); got != wantVLAN {
		t.Fatalf("empty + state-dir: got %q, want %q", got, wantVLAN)
	}
	// An explicit override always wins — a path or "postgres" is the operator's deliberate choice.
	if got := durableStorePath("/dataplane-ne", "/custom/x.json", "device_inventory"); got != "/custom/x.json" {
		t.Fatalf("explicit path must win: got %q", got)
	}
	if got := durableStorePath("/dataplane-ne", "postgres", "device_inventory"); got != "postgres" {
		t.Fatalf("explicit postgres must win: got %q", got)
	}
}
