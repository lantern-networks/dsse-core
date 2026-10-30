package humanidentity

import (
	"context"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

func TestDirectoryInputAndReadbackCannotChangeIdentityOrSourcePolicy(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	user := model.HumanIdentity{ID: "alice", Subject: "alice", Status: "active", Metadata: map[string]any{"nested": map[string]any{"role": "user"}}}
	s := NewHumanIdentityDirectoryStore()
	result, err := s.Upsert(ctx, user, "Acme", now)
	if err != nil {
		t.Fatal(err)
	}
	user.Metadata["nested"].(map[string]any)["role"] = "admin"
	result.Metadata["nested"].(map[string]any)["role"] = "admin"
	rows, _ := s.List(ctx, "Acme")
	if len(rows) != 1 || rows[0].Metadata["nested"].(map[string]any)["role"] != "user" {
		t.Fatalf("input/result changed directory: %+v", rows)
	}
	rows[0].Metadata["nested"].(map[string]any)["role"] = "admin"
	rows, _ = s.List(ctx, "Acme")
	if rows[0].Metadata["nested"].(map[string]any)["role"] != "user" {
		t.Fatal("list result changed directory without save or generation")
	}
	policy := HumanIdentitySourcePolicy{TenantID: "Acme", Source: "idp", Enabled: true, Metadata: map[string]any{"connector_id": "connector-a"}}
	returned, err := s.UpsertSourcePolicy(ctx, policy)
	if err != nil {
		t.Fatal(err)
	}
	policy.Metadata["connector_id"] = "connector-b"
	returned.Metadata["connector_id"] = "connector-b"
	allowed, err := HumanIdentityDirectorySourceAllowedForConnector(ctx, s, "Acme", "idp", "connector-b")
	if err != nil || allowed {
		t.Fatalf("source policy changed without save: allowed=%v err=%v", allowed, err)
	}
	listed, _ := s.ListSourcePolicies(ctx, "Acme")
	listed[0].Metadata["connector_id"] = "connector-b"
	allowed, err = HumanIdentityDirectorySourceAllowedForConnector(ctx, s, "Acme", "idp", "connector-b")
	if err != nil || allowed {
		t.Fatalf("source policy list changed authorization: allowed=%v err=%v", allowed, err)
	}
}
