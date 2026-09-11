package endpointinventory

import (
	"context"
	"testing"
	"time"
)

func TestNormalizeValidation(t *testing.T) {
	now := time.Now().UTC()
	if _, err := normalize(Entry{}, "", now); err == nil {
		t.Fatal("expected error for missing tenant_id")
	}
	if _, err := normalize(Entry{}, "t1", now); err == nil {
		t.Fatal("expected error for missing endpoint_id")
	}
	if _, err := normalize(Entry{EndpointID: "a/b"}, "t1", now); err == nil {
		t.Fatal("expected error for slash in endpoint_id")
	}
	if _, err := normalize(Entry{EndpointID: "ep1", TenantID: "other"}, "t1", now); err == nil {
		t.Fatal("expected error for tenant mismatch")
	}
}

func TestUpsertAndListScopeTenant(t *testing.T) {
	store := NewStore()
	now := time.Now().UTC()
	ctx := context.Background()
	if _, err := store.Upsert(ctx, Entry{EndpointID: "ep_a", Status: "active"}, "t1", now); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if _, err := store.Upsert(ctx, Entry{EndpointID: "ep_b", Status: "active"}, "t2", now); err != nil {
		t.Fatalf("upsert t2: %v", err)
	}
	resp, err := store.List(ctx, "t1", ListOptions{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if resp.Count != 1 || resp.Endpoints[0].EndpointID != "ep_a" {
		t.Fatalf("tenant t1 list = %+v, want only ep_a", resp.Endpoints)
	}
}

// A build-stamped version must survive the inventory's field allowlist.
//
// The macOS agent reports "<short>+<CFBundleVersion>" — semver build metadata, the format this product
// stamps. '+' was not in the allowlist, so normalize rejected the record and the caller dropped the device
// from /admin/endpoints entirely: on 2026-08-05 a Mac heartbeating every 15 seconds was absent from the
// operator's inventory, and the only agent reporting a REAL version was the one being rejected for it.
func TestInventoryAcceptsASemverBuildStampedAgentVersion(t *testing.T) {
	store := NewStore()
	now := time.Date(2026, 8, 5, 11, 0, 0, 0, time.UTC)
	if _, err := store.Upsert(context.Background(), Entry{
		EndpointID: "mac-dev-1", TenantID: "tenant_lab_001", Status: "active",
		DeviceTrustLevel: "managed", AgentVersion: "0.1.0+20260805170618",
	}, "tenant_lab_001", now); err != nil {
		t.Fatalf("a build-stamped version was rejected: %v", err)
	}
	got, found, err := store.Get(context.Background(), "tenant_lab_001", "mac-dev-1")
	if err != nil || !found {
		t.Fatalf("Get: found=%v err=%v", found, err)
	}
	if got.AgentVersion != "0.1.0+20260805170618" {
		t.Fatalf("agent_version = %q, want it stored verbatim", got.AgentVersion)
	}
}

// The allowlist still refuses genuinely unsafe text — widening it for '+' must not open it generally.
func TestInventoryStillRejectsUnsafeText(t *testing.T) {
	store := NewStore()
	now := time.Date(2026, 8, 5, 11, 0, 0, 0, time.UTC)
	for _, bad := range []string{"0.1.0 <script>", "ver;rm -rf /", "a/b", "x\ny"} {
		if _, err := store.Upsert(context.Background(), Entry{
			EndpointID: "dev-1", TenantID: "tenant_lab_001", Status: "active",
			DeviceTrustLevel: "managed", AgentVersion: bad,
		}, "tenant_lab_001", now); err == nil {
			t.Fatalf("agent_version %q was accepted; the allowlist must still refuse it", bad)
		}
	}
}
