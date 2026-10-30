package main

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

func TestObservedAuthAccountsStayTenantScopedAndRequireOwnerMetadata(t *testing.T) {
	store := newEndpointRuntimeStore()
	now := time.Now().UTC().Truncate(time.Second)
	principal := "windows:S-1-5-21-100-200-300-1001"
	store.recordSteeredFlowWithOwner("device-a", "tenant-a", "Alice", principal, now)
	store.recordSteeredFlowWithOwner("device-b", "tenant-b", "Bob", "windows:S-1-5-21-100-200-300-1002", now)
	store.recordSteeredFlowWithOwner("device-c", "tenant-a", "Carol", "", now)
	store.recordSteeredFlowWithOwner("device-d", "tenant-a", "", principal, now)
	got := store.observedAuthAccounts("tenant-a")
	if len(got) != 1 || got[0].DeviceID != "device-a" || got[0].OSPrincipal != principal || got[0].DisplayName != "Alice" {
		t.Fatalf("unexpected tenant candidate set: %+v", got)
	}
	if len(store.observedAuthAccounts("tenant-b")) != 1 {
		t.Fatal("other tenant's account was lost")
	}
	if len(store.snapshot(now)["device-a"].LoggedInUsers) == 0 {
		t.Fatal("general device view lost its existing display names")
	}
}

func TestObservedAuthAccountsSurviveFleetProjectionAndHistory(t *testing.T) {
	store := newEndpointRuntimeStore()
	now := time.Now().UTC().Truncate(time.Second)
	principal := "macos:00000000-0000-0000-0000-000000000001"
	store.recordSteeredFlowWithOwner("device-a", "tenant-a", "Alice", principal, now)
	entry := store.m["device-a"]
	entry.lastSig = ""
	event := store.changeEventLocked(entry, "device-a")
	if event == nil {
		t.Fatal("observed account was absent from the change event")
	}
	projection := newFleetDeviceProjection()
	projection.Fold(event)
	accounts, _ := fleetObservedAuthAccounts(nil, projection, "tenant-a")
	if len(accounts) != 1 || accounts[0].OSPrincipal != principal {
		t.Fatalf("fleet lost observed principal: %+v", accounts)
	}
	if foreign, _ := fleetObservedAuthAccounts(nil, projection, "tenant-b"); len(foreign) != 0 {
		t.Fatalf("fleet exposed another tenant's principal: %+v", foreign)
	}
	restored := newEndpointRuntimeStore()
	history := []map[string]any{{
		"tenant_id": "tenant-a", "device_id": "device-a", "timestamp": now.Format(time.RFC3339),
		"auth_accounts": []any{map[string]any{"os_principal": principal, "display_name": "Alice"}},
	}}
	if restored.seedFromHistory(history) != 1 {
		t.Fatal("history did not restore device")
	}
	if got := restored.observedAuthAccounts("tenant-a"); len(got) != 1 || got[0].OSPrincipal != principal {
		t.Fatalf("history lost account: %+v", got)
	}
}

func TestObservedAuthAccountsClearOnTenantChange(t *testing.T) {
	store := newEndpointRuntimeStore()
	now := time.Now().UTC()
	store.recordSteeredFlowWithOwner("device-a", "tenant-a", "Alice", "windows:S-1-5-21-100-200-300-1001", now)
	store.recordSteeredFlowWithOwner("device-a", "tenant-b", "Bob", "windows:S-1-5-21-100-200-300-1002", now.Add(time.Second))
	if got := store.observedAuthAccounts("tenant-a"); len(got) != 0 {
		t.Fatalf("old tenant account remained: %+v", got)
	}
	if got := store.observedAuthAccounts("tenant-b"); len(got) != 1 || got[0].DisplayName != "Bob" {
		t.Fatalf("new tenant candidates: %+v", got)
	}
}

func TestObservedAuthAccountsAdmitNewSharedDeviceUserAfterLimitAndHydration(t *testing.T) {
	store := newEndpointRuntimeStore()
	start := time.Now().UTC().Truncate(time.Second)
	principal := func(n int) string { return fmt.Sprintf("windows:S-1-5-21-100-200-300-%d", 1000+n) }
	for n := 0; n < maxObservedAuthAccountsPerDevice; n++ {
		store.recordSteeredFlowWithOwner("shared", "tenant-a", fmt.Sprintf("User %d", n), principal(n), start.Add(time.Duration(n)*time.Second))
	}
	store.recordSteeredFlowWithOwner("shared", "tenant-a", "Updated", principal(0), start.Add(32*time.Second))
	store.recordSteeredFlowWithOwner("shared", "tenant-a", "New user", principal(32), start.Add(33*time.Second))
	e := store.m["shared"]
	if len(e.authAccounts) != maxObservedAuthAccountsPerDevice || e.authAccounts[principal(0)] != "" || e.authAccounts[principal(32)] != "New user" {
		t.Fatalf("the new user did not replace the oldest candidate: %+v", e.authAccounts)
	}
	// The order must survive the device-state record, not merely the live map.
	e.lastSig = ""
	event := store.changeEventLocked(e, "shared")
	encoded, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	var persisted map[string]any
	if err := json.Unmarshal(encoded, &persisted); err != nil {
		t.Fatal(err)
	}
	restored := newEndpointRuntimeStore()
	if got := restored.seedFromHistory([]map[string]any{persisted}); got != 1 {
		t.Fatalf("restored %d devices, want 1", got)
	}
	restored.recordSteeredFlowWithOwner("shared", "tenant-a", "Next user", principal(33), start.Add(34*time.Second))
	re := restored.m["shared"]
	if len(re.authAccounts) != maxObservedAuthAccountsPerDevice || re.authAccounts[principal(1)] != "" || re.authAccounts[principal(32)] != "New user" || re.authAccounts[principal(33)] != "Next user" {
		t.Fatalf("hydration lost candidate eviction order: %+v", re.authAccounts)
	}
}

func TestObservedAuthAccountsClearWhenReportChangesTenant(t *testing.T) {
	store := newEndpointRuntimeStore()
	now := time.Now().UTC()
	store.recordSteeredFlowWithOwner("shared", "tenant-a", "Alice", "windows:S-1-5-21-100-200-300-1001", now)
	store.ingestFromReport("shared", "tenant-b", "Windows", nil, nil, "", "", now.Add(time.Second))
	if len(store.m["shared"].authAccounts) != 0 || len(store.m["shared"].authAccountOrder) != 0 {
		t.Fatal("tenant change through the report retained another tenant's candidate")
	}
	if got := store.observedAuthAccounts("tenant-b"); len(got) != 0 {
		t.Fatalf("old tenant's candidate leaked into new tenant: %+v", got)
	}
}

func TestObservedAuthAccountOrderLegacyAndMalformedRows(t *testing.T) {
	accounts := map[string]string{"windows:S-1-5-21-100-200-300-1002": "Bob", "windows:S-1-5-21-100-200-300-1001": "Alice"}
	legacy := parseObservedAuthAccountOrder(nil, accounts)
	if len(legacy) != 2 || legacy[0] != "windows:S-1-5-21-100-200-300-1001" {
		t.Fatalf("legacy order was not deterministic: %+v", legacy)
	}
	malformed := parseObservedAuthAccountOrder([]any{"foreign", "windows:S-1-5-21-100-200-300-1002", "windows:S-1-5-21-100-200-300-1002"}, accounts)
	if len(malformed) != 2 || malformed[0] != "windows:S-1-5-21-100-200-300-1002" || malformed[1] != "windows:S-1-5-21-100-200-300-1001" {
		t.Fatalf("malformed order was not filtered: %+v", malformed)
	}
}
