package toolcallaudit

import (
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

func TestNormalizeValidation(t *testing.T) {
	now := time.Now().UTC()
	if err := Normalize(&model.ToolCallEvent{}, "t1", now); err == nil {
		t.Fatal("expected error for missing id")
	}
	if err := Normalize(&model.ToolCallEvent{ID: "e1", TenantID: "other"}, "t1", now); err == nil {
		t.Fatal("expected error for tenant mismatch")
	}
	if err := Normalize(&model.ToolCallEvent{ID: "e1", TenantID: "t1"}, "t1", now); err == nil {
		t.Fatal("expected error for missing actor_nhi_id")
	}

	valid := &model.ToolCallEvent{ID: "e1", TenantID: "t1", ActorNHIID: "nhi1", ToolID: "tool1", ActionType: "exec"}
	if err := Normalize(valid, "t1", now); err != nil {
		t.Fatalf("valid event should pass: %v", err)
	}
	// defaults applied
	if valid.Timestamp == "" {
		t.Fatal("Timestamp default not applied")
	}
	if valid.ResultSummaryScope != "metadata_only" {
		t.Fatalf("ResultSummaryScope default = %q, want metadata_only", valid.ResultSummaryScope)
	}

	// a forbidden metadata key is rejected (non-secret audit invariant)
	bad := &model.ToolCallEvent{ID: "e2", TenantID: "t1", ActorNHIID: "nhi1", ToolID: "tool1", ActionType: "exec",
		Metadata: map[string]any{"password": "leak"}}
	if err := Normalize(bad, "t1", now); err == nil {
		t.Fatal("expected error for forbidden metadata key")
	}
}
