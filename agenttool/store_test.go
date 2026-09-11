package agenttool

import (
	"context"
	"testing"
	"time"
)

func TestNormalizeValidation(t *testing.T) {
	now := time.Now().UTC()
	if _, err := normalize(Tool{}, "", now); err == nil {
		t.Fatal("expected error for missing tenant_id")
	}
	if _, err := normalize(Tool{}, "t1", now); err == nil {
		t.Fatal("expected error for missing tool_id")
	}
	if _, err := normalize(Tool{ToolID: "a/b"}, "t1", now); err == nil {
		t.Fatal("expected error for slash in tool_id")
	}
	if _, err := normalize(Tool{ToolID: "valid_tool", SignatureState: "bogus"}, "t1", now); err == nil {
		t.Fatal("expected error for invalid signature_state")
	}
	if _, err := normalize(Tool{ToolID: "valid_tool", TenantID: "other"}, "t1", now); err == nil {
		t.Fatal("expected error for tenant mismatch")
	}
}

func TestUpsertAndListScopeTenant(t *testing.T) {
	store := &Store{tools: map[string]map[string]Tool{}}
	now := time.Now().UTC()
	ctx := context.Background()
	if _, err := store.Upsert(ctx, Tool{ToolID: "tool_a", ActionType: "read"}, "t1", now); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if _, err := store.Upsert(ctx, Tool{ToolID: "tool_b", ActionType: "write"}, "t2", now); err != nil {
		t.Fatalf("upsert other tenant: %v", err)
	}
	resp, err := store.List(ctx, "t1", ListOptions{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if resp.Count != 1 || resp.Tools[0].ToolID != "tool_a" {
		t.Fatalf("tenant t1 list = %+v, want only tool_a", resp.Tools)
	}
	// action_type filter excludes the read tool.
	if filtered, _ := store.List(ctx, "t1", ListOptions{ActionType: "write"}); filtered.Count != 0 {
		t.Fatalf("action_type=write filter should exclude the read tool, got %d", filtered.Count)
	}
}
