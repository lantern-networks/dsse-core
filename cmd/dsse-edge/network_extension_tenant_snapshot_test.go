package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/policy"
)

func TestNetworkExtensionSnapshotsAreTenantIsolated(t *testing.T) {
	dir := t.TempDir()
	p, err := newLocalNetworkExtensionSnapshotPublisher(localNetworkExtensionSnapshotPublisherConfig{OutputDir: dir, EdgeURL: "https://edge.example.test:443"})
	if err != nil {
		t.Fatal(err)
	}
	for _, tenant := range []string{"Acme", "acme"} {
		var rules []model.Policy
		if tenant == "Acme" {
			var row model.Policy
			if err := json.Unmarshal([]byte(`{"id":"one","tenant_id":"Acme","status":"active","conditions":{"steering_mode":"network_extension"},"action":{"decision":"allow"}}`), &row); err != nil {
				t.Fatal(err)
			}
			rules = append(rules, row)
		}
		err := p.PublishAdminPolicySnapshot(context.Background(), tenant, policy.NewStore(rules), model.PolicyBundle{}, time.Now())
		if (tenant == "Acme") != (err == nil) {
			t.Fatalf("tenant %s publish: %v", tenant, err)
		}
		path := filepath.Join(dir, "tenants", hex.EncodeToString([]byte(tenant)), networkExtensionSnapshotAgentConfigRef)
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var config map[string]any
		if err := json.Unmarshal(raw, &config); err != nil {
			t.Fatal(err)
		}
		organization, ok := config["organization"].(map[string]any)
		if !ok || organization["tenant_id"] != tenant {
			t.Fatalf("wrong tenant config: %v", organization)
		}
		_, rulesErr := os.Stat(filepath.Join(filepath.Dir(path), networkExtensionSnapshotRulesRef))
		if tenant == "Acme" && rulesErr != nil {
			t.Fatal(rulesErr)
		}
		if tenant == "acme" && !os.IsNotExist(rulesErr) {
			t.Fatalf("failed tenant inherited other tenant rules: %v", rulesErr)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, networkExtensionSnapshotAgentConfigRef)); !os.IsNotExist(err) {
		t.Fatal("unscoped root artifact published")
	}
}

func TestNetworkExtensionSnapshotIncludesAllActivePolicyIDs(t *testing.T) {
	dir := t.TempDir()
	p, err := newLocalNetworkExtensionSnapshotPublisher(localNetworkExtensionSnapshotPublisherConfig{OutputDir: dir, EdgeURL: "https://edge.example.test:443"})
	if err != nil {
		t.Fatal(err)
	}
	var rows []model.Policy
	for i := 0; i < 10001; i++ {
		var row model.Policy
		if err := json.Unmarshal([]byte(fmt.Sprintf(`{"id":"p-%d","tenant_id":"tenant","status":"active","conditions":{"steering_mode":"network_extension"},"action":{"decision":"allow"}}`, i)), &row); err != nil {
			t.Fatal(err)
		}
		rows = append(rows, row)
	}
	if err := p.PublishAdminPolicySnapshot(context.Background(), "tenant", policy.NewStore(rows), model.PolicyBundle{}, time.Now()); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "tenants", hex.EncodeToString([]byte("tenant")), networkExtensionSnapshotRulesRef)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Metadata struct {
			IDs []string `json:"active_network_extension_policy_ids"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Metadata.IDs) != len(rows) {
		t.Fatalf("policy metadata truncated: got %d, want %d", len(result.Metadata.IDs), len(rows))
	}
}
