package nhi

import (
	"context"
	"testing"
	"time"
)

func TestRegistryRecordsDoNotExposeMutableAuthorizationState(t *testing.T) {
	for _, source := range []string{"input", "upsert-result", "list-result"} {
		t.Run(source, func(t *testing.T) {
			s := NewStore()
			now := time.Now()
			expires := now.Add(time.Hour).UTC().Format(time.RFC3339)
			input := testIdentity("actor")
			input.ExpiresAt = &expires
			input.AllowedApplicationIDs = []string{"permitted"}
			input.AllowedScopes = []string{"read"}
			input.Metadata = map[string]any{"nested": map[string]any{"note": "original"}}
			result, err := s.Upsert(context.Background(), input, "tenant_a", now)
			if err != nil {
				t.Fatal(err)
			}
			generation := s.ConfigGeneration()
			mutate := input
			if source == "upsert-result" {
				mutate = result
			}
			if source == "list-result" {
				rows, _ := s.List(context.Background(), "tenant_a")
				mutate = rows[0]
			}
			*mutate.ExpiresAt = now.Add(365 * 24 * time.Hour).UTC().Format(time.RFC3339)
			mutate.AllowedApplicationIDs[0] = "forbidden"
			mutate.AllowedScopes[0] = "write"
			mutate.Metadata["nested"].(map[string]any)["note"] = "changed"
			rows, _ := s.List(context.Background(), "tenant_a")
			got := rows[0]
			if *got.ExpiresAt != now.Add(time.Hour).UTC().Format(time.RFC3339) || ApplicationAllowed(got, "forbidden") || ScopeAllowed(got, "write") || got.Metadata["nested"].(map[string]any)["note"] != "original" {
				t.Fatal("caller mutation changed registry without an authorized durable write")
			}
			if s.ConfigGeneration() != generation {
				t.Fatal("read changed configuration generation")
			}
		})
	}
}
