package humanidentity

import (
	"context"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

func TestDirectoryUpsertListStats(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	store := NewHumanIdentityDirectoryStore()

	if _, err := store.Upsert(ctx, model.HumanIdentity{ID: "u1", TenantID: "acme", Subject: "user@acme.example"}, "acme", now); err != nil {
		t.Fatal(err)
	}
	users, err := store.List(ctx, "acme")
	if err != nil || len(users) != 1 {
		t.Fatalf("acme list: %v len=%d", err, len(users))
	}
	// tenant isolation
	if users, err := store.List(ctx, "other"); err != nil || len(users) != 0 {
		t.Fatalf("another tenant must be isolated: %v len=%d", err, len(users))
	}
	// an identity without a subject is rejected
	if _, err := store.Upsert(ctx, model.HumanIdentity{ID: "u2", TenantID: "acme"}, "acme", now); err == nil {
		t.Fatal("a human identity without a subject must be rejected")
	}
	if _, err := store.Stats(ctx, "acme", now); err != nil {
		t.Fatalf("stats: %v", err)
	}
}
