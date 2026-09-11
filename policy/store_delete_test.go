package policy

import (
	"context"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

// Deleting is restricted to what the Admin API created. Bundle-seeded policies are configuration — deleting
// one here would only last until the next bundle apply resurrected it, so the refusal says where it lives.
func TestDeleteRemovesOnlyAdminAuthoredPolicies(t *testing.T) {
	const tenant = "t-delete"
	now := time.Now()
	seeded := model.Policy{ID: "pol-from-bundle", TenantID: tenant, Name: "bundle policy",
		Priority: 10, Conditions: map[string]any{"sni": "bundle.example.com"}, Action: model.PolicyAction{Decision: "allow"}, Status: "active"}
	store := NewStore([]model.Policy{seeded})

	authored, err := store.Upsert(context.Background(), model.Policy{
		ID: "pol-agent-fleet-agent", TenantID: tenant, Name: "Fleet agent boundary",
		Priority: 40, Conditions: map[string]any{"actor_nhi_id": "fleet-agent"},
		Action: model.PolicyAction{Decision: "allow"}, Status: "active",
	}, tenant, now)
	if err != nil {
		t.Fatal(err)
	}
	// Disabled-by-override, as the real mistaken policy was — deletion must clear the override too.
	if !store.SetPolicyStatus(tenant, authored.ID, "disabled") {
		t.Fatal("status override should apply")
	}
	genBefore := store.ConfigGeneration()

	removed, existed, err := store.Delete(context.Background(), tenant, authored.ID)
	if err != nil || !existed {
		t.Fatalf("authored policy must delete: existed=%v err=%v", existed, err)
	}
	if removed.Name != "Fleet agent boundary" {
		t.Fatalf("returned policy should be the removed one, got %q", removed.Name)
	}
	if _, found, _ := store.Get(context.Background(), tenant, authored.ID); found {
		t.Fatal("deleted policy must leave the listing")
	}
	if store.ConfigGeneration() <= genBefore {
		t.Fatal("deletion must advance the config generation so edges pull the change")
	}
	if got := store.policyStatusOverride[tenant][authored.ID]; got != "" {
		t.Fatalf("the status override must be cleared with the policy, got %q", got)
	}
	// Idempotence: absent now.
	if _, existed, err := store.Delete(context.Background(), tenant, authored.ID); existed || err != nil {
		t.Fatalf("second delete: existed=%v err=%v", existed, err)
	}

	// The bundle policy refuses with a reason, and stays.
	if _, _, err := store.Delete(context.Background(), tenant, seeded.ID); err == nil {
		t.Fatal("a bundle-sourced policy must refuse deletion through the Admin API")
	}
	if _, found, _ := store.Get(context.Background(), tenant, seeded.ID); !found {
		t.Fatal("the refused bundle policy must remain")
	}
}

// memoryPersister is the blobstore seam the store persists through, in-memory for the test.
type memoryPersister struct{ blob []byte }

func (m *memoryPersister) Load() ([]byte, error)  { return m.blob, nil }
func (m *memoryPersister) Save(data []byte) error { m.blob = append([]byte(nil), data...); return nil }

// The deletion must survive a restart: the persisted overlay no longer contains the policy, so a store
// restored from it does not resurrect what an admin removed.
func TestDeletePersistsAcrossRestore(t *testing.T) {
	const tenant = "t-delete-persist"
	now := time.Now()
	persister := &memoryPersister{}
	store := NewStore(nil)
	store.SetRuntimeStatePersister(persister)

	if _, err := store.Upsert(context.Background(), model.Policy{
		ID: "pol-x", TenantID: tenant, Name: "mistake",
		Priority: 1, Conditions: map[string]any{"sni": "x.example.com"},
		Action: model.PolicyAction{Decision: "allow"}, Status: "active",
	}, tenant, now); err != nil {
		t.Fatal(err)
	}
	if _, existed, err := store.Delete(context.Background(), tenant, "pol-x"); !existed || err != nil {
		t.Fatalf("delete: existed=%v err=%v", existed, err)
	}

	restored := NewStore(nil)
	restored.SetRuntimeStatePersister(persister) // loads the overlay, as boot does
	if _, found, _ := restored.Get(context.Background(), tenant, "pol-x"); found {
		t.Fatal("a deleted policy must not come back from the persisted overlay")
	}
}
