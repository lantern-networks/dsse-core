package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

func TestConnectorIdentitySyncImportsDueSourceFromFile(t *testing.T) {
	secret := "tenant-runtime-secret"
	var importRequest connectorHumanIdentityImportRequest
	withConnectorHTTPTransport(t, func(r *http.Request) (*http.Response, error) {
		if got := r.Header.Get(connectorIDHeader); got != "conn_lab_001" {
			t.Errorf("connector id header = %q, want conn_lab_001", got)
		}
		if got := r.Header.Get(connectorSecretHeader); got != secret {
			t.Errorf("connector secret header = %q, want %q", got, secret)
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/identity-sources/due":
			return jsonResponse(http.StatusOK, connectorIdentitySourceDueList{
				TenantID: "tenant_lab_001",
				Sources: []connectorIdentitySourceDue{{
					Source:           "scim_runtime",
					ConnectorType:    "scim",
					ReconcileMissing: true,
					Checkpoint:       "cursor_runtime_001",
					Metadata:         map[string]any{"connector_id": "conn_lab_001"},
				}},
			}), nil
		case r.Method == http.MethodPost && r.URL.Path == "/identity-sources/import":
			if err := json.NewDecoder(r.Body).Decode(&importRequest); err != nil {
				return jsonResponse(http.StatusBadRequest, map[string]string{"error": err.Error()}), nil
			}
			return jsonResponse(http.StatusOK, map[string]string{
				"source":        importRequest.Source,
				"import_run_id": importRequest.ImportRunID,
			}), nil
		default:
			return jsonResponse(http.StatusNotFound, map[string]string{"error": "not found"}), nil
		}
	})

	importFile := writeIdentityImportFile(t, connectorHumanIdentityImportRequest{
		Identities: []model.HumanIdentity{{
			ID:      "human_runtime_001",
			Subject: "alice@example.jp",
			Status:  "active",
		}},
	})
	now := time.Date(2026, 5, 25, 1, 2, 3, 4, time.UTC)

	result, err := syncHumanIdentitiesFromFile(context.Background(), nil, "http://edge.local", "conn_lab_001", secret, "", importFile, now)
	if err != nil {
		t.Fatalf("syncHumanIdentitiesFromFile returned error: %v", err)
	}
	if result.Status != "imported" || result.Source != "scim_runtime" {
		t.Fatalf("result = %+v, want imported scim_runtime", result)
	}
	if importRequest.Source != "scim_runtime" {
		t.Fatalf("import request source = %q, want scim_runtime", importRequest.Source)
	}
	if importRequest.Checkpoint != "cursor_runtime_001" {
		t.Fatalf("import request checkpoint = %q, want cursor_runtime_001", importRequest.Checkpoint)
	}
	if importRequest.ReconcileMissing == nil || !*importRequest.ReconcileMissing {
		t.Fatalf("import request reconcile_missing = %v, want true", importRequest.ReconcileMissing)
	}
	if !strings.HasPrefix(importRequest.ImportRunID, "human_import_connector_") {
		t.Fatalf("import run id = %q, want connector prefix", importRequest.ImportRunID)
	}
	if result.Checkpoint != "cursor_runtime_001" {
		t.Fatalf("result checkpoint = %q, want cursor_runtime_001", result.Checkpoint)
	}
	if len(importRequest.Identities) != 1 || importRequest.Identities[0].ID != "human_runtime_001" {
		t.Fatalf("import request identities = %+v", importRequest.Identities)
	}
}

func TestConnectorRuntimeSecretHashIsDeterministic(t *testing.T) {
	hash := connectorRuntimeSecretHash(" runtime-secret ")
	if hash == "" || !strings.HasPrefix(hash, "sha256:") {
		t.Fatalf("hash = %q, want sha256 prefix", hash)
	}
	if hash != connectorRuntimeSecretHash("runtime-secret") {
		t.Fatalf("hash should trim surrounding whitespace")
	}
	if hash == connectorRuntimeSecretHash("other-secret") {
		t.Fatalf("different secrets should not share a runtime hash")
	}
}

func TestConnectorIdentitySyncSkipsWhenNoDueSource(t *testing.T) {
	importCalled := false
	withConnectorHTTPTransport(t, func(r *http.Request) (*http.Response, error) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/identity-sources/due":
			return jsonResponse(http.StatusOK, connectorIdentitySourceDueList{TenantID: "tenant_lab_001"}), nil
		case r.Method == http.MethodPost && r.URL.Path == "/identity-sources/import":
			importCalled = true
			return jsonResponse(http.StatusTeapot, map[string]string{"error": "unexpected import"}), nil
		default:
			return jsonResponse(http.StatusNotFound, map[string]string{"error": "not found"}), nil
		}
	})

	result, err := syncHumanIdentitiesFromFile(context.Background(), nil, "http://edge.local", "conn_lab_001", "secret", "", filepath.Join(t.TempDir(), "missing.json"), time.Now())
	if err != nil {
		t.Fatalf("syncHumanIdentitiesFromFile returned error: %v", err)
	}
	if result.Status != "no_due_sources" {
		t.Fatalf("result status = %q, want no_due_sources", result.Status)
	}
	if importCalled {
		t.Fatal("import endpoint was called without a due source")
	}
}

func TestConnectorIdentitySyncWritesStateAtomically(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "identity-sync.json")
	now := time.Date(2026, 5, 25, 2, 3, 4, 0, time.UTC)
	if err := writeIdentitySyncState(path, connectorIdentitySyncResult{
		Status:      "imported",
		Source:      "scim_runtime",
		ImportRunID: "human_import_connector_001",
		Checkpoint:  "cursor_runtime_002",
	}, now); err != nil {
		t.Fatalf("writeIdentitySyncState returned error: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read state file: %v", err)
	}
	var state connectorIdentitySyncState
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatalf("decode state: %v", err)
	}
	if state.Status != "imported" || state.Source != "scim_runtime" || state.ImportRunID != "human_import_connector_001" || state.Checkpoint != "cursor_runtime_002" {
		t.Fatalf("state = %+v", state)
	}
	if state.SyncedAt != "2026-05-25T02:03:04Z" {
		t.Fatalf("synced_at = %q", state.SyncedAt)
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("temporary state file still exists: %v", err)
	}
}

func TestConnectorIdentitySyncMonitorRecordsStatusAndError(t *testing.T) {
	monitor := &connectorIdentitySyncMonitor{}
	now := time.Date(2026, 5, 25, 3, 4, 5, 0, time.UTC)
	monitor.Record(connectorIdentitySyncResult{
		Status:      "imported",
		Source:      "scim_runtime",
		ImportRunID: "human_import_connector_001",
		Checkpoint:  "cursor_runtime_003",
	}, now)
	snapshot := monitor.Snapshot(true)
	if !snapshot.Configured || snapshot.Status != "imported" || snapshot.Source != "scim_runtime" || snapshot.Checkpoint != "cursor_runtime_003" || snapshot.SyncedAt != "2026-05-25T03:04:05Z" {
		t.Fatalf("snapshot after record = %+v", snapshot)
	}
	if snapshot.LastError != "" || snapshot.LastErrorAt != "" {
		t.Fatalf("snapshot should not contain error after successful record: %+v", snapshot)
	}

	monitor.RecordError(assertionError("fetch due failed"), now.Add(time.Minute))
	snapshot = monitor.Snapshot(true)
	if snapshot.Status != "imported" || snapshot.LastError != "fetch due failed" || snapshot.LastErrorAt != "2026-05-25T03:05:05Z" {
		t.Fatalf("snapshot after error = %+v", snapshot)
	}
	if monitor.Snapshot(false).Configured {
		t.Fatal("configured flag should be controlled by caller")
	}
}

type assertionError string

func (err assertionError) Error() string {
	return string(err)
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

func withConnectorHTTPTransport(t *testing.T, fn roundTripFunc) {
	t.Helper()
	previous := http.DefaultTransport
	http.DefaultTransport = fn
	t.Cleanup(func() {
		http.DefaultTransport = previous
	})
}

func jsonResponse(status int, value any) *http.Response {
	data, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(string(data))),
	}
}

func writeIdentityImportFile(t *testing.T, request connectorHumanIdentityImportRequest) string {
	t.Helper()
	data, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("marshal import file: %v", err)
	}
	path := filepath.Join(t.TempDir(), "human-identities.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write import file: %v", err)
	}
	return path
}
