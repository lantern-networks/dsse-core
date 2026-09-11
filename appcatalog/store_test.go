package appcatalog

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestNormalizeValidation(t *testing.T) {
	now := time.Now().UTC()
	if _, err := normalize(Entry{}, "", now); err == nil {
		t.Fatal("expected error for missing tenant_id")
	}
	if _, err := normalize(Entry{}, "t1", now); err == nil {
		t.Fatal("expected error for missing application_id")
	}
	if _, err := normalize(Entry{ApplicationID: "a/b"}, "t1", now); err == nil {
		t.Fatal("expected error for slash in application_id")
	}
	if _, err := normalize(Entry{ApplicationID: "app", ApplicationType: "bogus"}, "t1", now); err == nil {
		t.Fatal("expected error for invalid application_type")
	}
	if _, err := normalize(Entry{ApplicationID: "app", TenantID: "other"}, "t1", now); err == nil {
		t.Fatal("expected error for tenant mismatch")
	}
}

func TestUpsertAndListScopeTenant(t *testing.T) {
	store := NewStore()
	now := time.Now().UTC()
	ctx := context.Background()
	if _, err := store.Upsert(ctx, Entry{ApplicationID: "app_a", ApplicationType: "private_app", Status: "active"}, "t1", now); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if _, err := store.Upsert(ctx, Entry{ApplicationID: "app_b", ApplicationType: "saas", Status: "active"}, "t2", now); err != nil {
		t.Fatalf("upsert t2: %v", err)
	}
	resp, err := store.List(ctx, "t1", ListOptions{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if resp.Count != 1 || resp.Applications[0].ApplicationID != "app_a" {
		t.Fatalf("tenant t1 list = %+v, want only app_a", resp.Applications)
	}
	// status filter excludes the active app.
	if filtered, _ := store.List(ctx, "t1", ListOptions{Status: "disabled"}); filtered.Count != 0 {
		t.Fatalf("status=disabled filter should exclude the active app, got %d", filtered.Count)
	}
}

// TestServiceFamilyDerivedFromPort verifies a published private app on a well-known lateral-protocol port is
// classified into the matching service family (so decision.IsEastWestProtocol engages), instead of defaulting
// to "https" — the bug that made Console-authored East-West rules silently not enforce on SSH/RDP/SMB apps.
func TestServiceFamilyDerivedFromPort(t *testing.T) {
	store := NewStore()
	ctx := context.Background()
	now := time.Now()
	cases := map[int]string{22: "ssh", 3389: "rdp", 445: "smb", 5985: "winrm", 5900: "vnc"}
	for port, want := range cases {
		got, err := store.Upsert(ctx, Entry{ApplicationID: fmt.Sprintf("app_%d", port), ApplicationType: "private_app", Destination: "corp.internal", DestinationPort: port, Status: "active"}, "t1", now)
		if err != nil {
			t.Fatalf("upsert port %d: %v", port, err)
		}
		if got.ServiceFamily != want {
			t.Errorf("port %d service_family = %q, want %q", port, got.ServiceFamily, want)
		}
	}
	// A web port (or no known lateral port) still falls back to https.
	web, err := store.Upsert(ctx, Entry{ApplicationID: "app_web", ApplicationType: "private_app", Destination: "wiki.internal", DestinationPort: 443, Status: "active"}, "t1", now)
	if err != nil {
		t.Fatalf("upsert web: %v", err)
	}
	if web.ServiceFamily != "https" {
		t.Errorf("port 443 service_family = %q, want https", web.ServiceFamily)
	}
}
