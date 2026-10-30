package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/schema"
)

// The installer embeds its own schema copies. A generated deployment must
// validate the same documents as the source product, including newly added
// event streams, instead of silently shipping an older schema.
func TestGeneratedSchemasMatchSourceSchemas(t *testing.T) {
	dir := t.TempDir()
	if err := writeSchemasAndPolicy(dir); err != nil {
		t.Fatal(err)
	}
	sourceDir := filepath.Join("..", "..", "schemas")
	entries, err := os.ReadDir(sourceDir)
	if err != nil {
		t.Fatal(err)
	}
	wantCount := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		wantCount++
		want, err := os.ReadFile(filepath.Join(sourceDir, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(filepath.Join(dir, "schemas", entry.Name()))
		if err != nil {
			t.Fatalf("generated schema %s: %v", entry.Name(), err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("generated schema %s differs from the source schema", entry.Name())
		}
	}
	generated, err := os.ReadDir(filepath.Join(dir, "schemas"))
	if err != nil {
		t.Fatal(err)
	}
	if len(generated) != wantCount {
		t.Errorf("generated %d schemas, source has %d", len(generated), wantCount)
	}
}

func TestGeneratedRuntimeContractAcceptsTransparentProxyProvider(t *testing.T) {
	dir := t.TempDir()
	if err := writeSchemasAndPolicy(dir); err != nil {
		t.Fatal(err)
	}
	contract, err := os.ReadFile(filepath.Join(dir, "schemas", "network_extension_runtime_evidence.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := os.ReadFile(filepath.Join("..", "..", "samples", "phase1", "network_extension_runtime_evidence_lab.json"))
	if err != nil {
		t.Fatal(err)
	}
	var evidence map[string]any
	if err := json.Unmarshal(fixture, &evidence); err != nil {
		t.Fatal(err)
	}
	// Synthetic contract input, not evidence of an installed provider.
	for _, provider := range []string{"transparent_proxy_provider", "unknown_provider"} {
		evidence["runtime_provider"] = provider
		body, err := json.Marshal(evidence)
		if err != nil {
			t.Fatal(err)
		}
		err = schema.ValidateRequired(contract, body)
		if provider == "transparent_proxy_provider" && err != nil {
			t.Errorf("current macOS provider is rejected by the generated contract: %v", err)
		}
		if provider == "unknown_provider" && err == nil {
			t.Error("unknown provider must remain rejected")
		}
	}
}

func TestGeneratedOutboxSchemaAcceptsColdArchiveHealthEvent(t *testing.T) {
	dir := t.TempDir()
	if err := writeSchemasAndPolicy(dir); err != nil {
		t.Fatal(err)
	}
	contract, err := os.ReadFile(filepath.Join(dir, "schemas", "domain_event_outbox.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	const event = `{
		"id":"health-1", "tenant_id":"deployment", "schema_version":"2026-10-20.1",
		"event_plane":"domain", "stream":"cold_archive_health_events",
		"event_type":"cold_archive_degraded", "status":"pending",
		"occurred_at":"2026-10-20T00:00:00Z", "received_at":"2026-10-20T00:00:00Z",
		"payload":{}, "payload_checksum":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"publish_attempt":0, "metadata":{}
	}`
	if err := schema.ValidateRequired(contract, []byte(event)); err != nil {
		t.Fatalf("generated contract rejects a supported cold archive health stream: %v", err)
	}
}
