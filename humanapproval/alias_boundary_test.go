package humanapproval

import (
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

func TestApprovalInputAndReadbackCannotChangeAuthorization(t *testing.T) {
	now := time.Now().UTC()
	past := now.Add(-time.Minute).Format(time.RFC3339)
	future := now.Add(time.Hour).Format(time.RFC3339)
	event := model.HumanApprovalEvent{ID: "one", TenantID: "Acme", ApprovalResult: "approved", ExpiresAt: &past, RequestedScopes: []string{"read"}, Metadata: map[string]any{"nested": map[string]any{"purpose": "read"}}}
	s := NewStore(0)
	if _, err := s.Upsert(event); err != nil {
		t.Fatal(err)
	}
	*event.ExpiresAt = future
	event.RequestedScopes[0] = "write"
	event.Metadata["nested"].(map[string]any)["purpose"] = "write"
	assertUnchanged := func(label string) {
		t.Helper()
		stored, ok := s.GetForAuthorization("Acme", "one")
		if !ok || IsActive(stored, now) || stored.RequestedScopes[0] != "read" || stored.Metadata["nested"].(map[string]any)["purpose"] != "read" {
			t.Fatalf("%s changed stored authorization: %+v found=%v", label, stored, ok)
		}
	}
	assertUnchanged("input")
	read, _ := s.GetForTenant("Acme", "one")
	*read.ExpiresAt = future
	read.RequestedScopes[0] = "write"
	read.Metadata["nested"].(map[string]any)["purpose"] = "write"
	assertUnchanged("readback")
	snapshot := s.Snapshot()
	*snapshot[0].ExpiresAt = future
	assertUnchanged("snapshot")
}
