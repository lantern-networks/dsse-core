package toolcallaudit

import (
	"context"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

// Review #36: the tool-call audit store List must be TENANT-SCOPED — a query for tenant A must never return
// tenant B's events. Without this coverage a cross-tenant leak in List (a missing tenant filter) could
// regress silently.
func TestStoreListIsTenantScoped(t *testing.T) {
	s := NewStore()
	now := time.Date(2026, 7, 23, 0, 0, 0, 0, time.UTC)
	ctx := context.Background()

	mk := func(id, tenant string) model.ToolCallEvent {
		return model.ToolCallEvent{ID: id, TenantID: tenant, ActorNHIID: "nhi1", ToolID: "tool1", ActionType: "exec"}
	}
	if _, err := s.Upsert(ctx, mk("a1", "tenant-a"), "tenant-a", now); err != nil {
		t.Fatalf("upsert a1: %v", err)
	}
	if _, err := s.Upsert(ctx, mk("a2", "tenant-a"), "tenant-a", now); err != nil {
		t.Fatalf("upsert a2: %v", err)
	}
	if _, err := s.Upsert(ctx, mk("b1", "tenant-b"), "tenant-b", now); err != nil {
		t.Fatalf("upsert b1: %v", err)
	}

	// tenant-a sees only its own two events.
	resA, err := s.List(ctx, "tenant-a", ListOptions{})
	if err != nil {
		t.Fatalf("list tenant-a: %v", err)
	}
	if resA.Count != 2 || len(resA.Events) != 2 {
		t.Fatalf("tenant-a list = %d events, want 2", resA.Count)
	}
	for _, e := range resA.Events {
		if e.TenantID != "tenant-a" {
			t.Fatalf("tenant-a list leaked a %s event: %+v", e.TenantID, e)
		}
	}

	// tenant-b sees only its own single event.
	resB, err := s.List(ctx, "tenant-b", ListOptions{})
	if err != nil {
		t.Fatalf("list tenant-b: %v", err)
	}
	if resB.Count != 1 || len(resB.Events) != 1 || resB.Events[0].ID != "b1" {
		t.Fatalf("tenant-b list = %+v, want exactly b1", resB.Events)
	}

	// A tenant with no events sees nothing (not an aggregate).
	resC, err := s.List(ctx, "tenant-c", ListOptions{})
	if err != nil {
		t.Fatalf("list tenant-c: %v", err)
	}
	if resC.Count != 0 || len(resC.Events) != 0 {
		t.Fatalf("tenant-c list = %d events, want 0", resC.Count)
	}

	// An empty tenant id is rejected (never returns everything).
	if _, err := s.List(ctx, "  ", ListOptions{}); err == nil {
		t.Fatal("empty tenant_id must be rejected")
	}
}
