package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

type connectorIdentitySourceDueList struct {
	TenantID string                       `json:"tenant_id"`
	Sources  []connectorIdentitySourceDue `json:"sources"`
}

type connectorIdentitySourceDue struct {
	Source           string         `json:"source"`
	ConnectorType    string         `json:"connector_type"`
	ReconcileMissing bool           `json:"reconcile_missing"`
	Checkpoint       string         `json:"checkpoint"`
	Metadata         map[string]any `json:"metadata"`
}

type connectorHumanIdentityImportRequest struct {
	Source           string                `json:"source"`
	ImportRunID      string                `json:"import_run_id"`
	Checkpoint       string                `json:"checkpoint"`
	DryRun           bool                  `json:"dry_run"`
	ReconcileMissing *bool                 `json:"reconcile_missing,omitempty"`
	Identities       []model.HumanIdentity `json:"identities"`
}

type connectorIdentitySyncResult struct {
	Status      string `json:"status"`
	Source      string `json:"source,omitempty"`
	ImportRunID string `json:"import_run_id,omitempty"`
	Checkpoint  string `json:"checkpoint,omitempty"`
}

type connectorIdentitySyncState struct {
	Status      string `json:"status"`
	Source      string `json:"source,omitempty"`
	ImportRunID string `json:"import_run_id,omitempty"`
	Checkpoint  string `json:"checkpoint,omitempty"`
	SyncedAt    string `json:"synced_at"`
}

type connectorIdentitySyncMonitor struct {
	mu          sync.RWMutex
	state       connectorIdentitySyncState
	hasState    bool
	lastError   string
	lastErrorAt string
}

type connectorIdentitySyncMonitorSnapshot struct {
	Configured  bool   `json:"configured"`
	Status      string `json:"status,omitempty"`
	Source      string `json:"source,omitempty"`
	ImportRunID string `json:"import_run_id,omitempty"`
	Checkpoint  string `json:"checkpoint,omitempty"`
	SyncedAt    string `json:"synced_at,omitempty"`
	LastError   string `json:"last_error,omitempty"`
	LastErrorAt string `json:"last_error_at,omitempty"`
}

func (monitor *connectorIdentitySyncMonitor) Record(result connectorIdentitySyncResult, now time.Time) {
	if monitor == nil {
		return
	}
	monitor.mu.Lock()
	defer monitor.mu.Unlock()
	monitor.state = connectorIdentitySyncState{
		Status:      result.Status,
		Source:      result.Source,
		ImportRunID: result.ImportRunID,
		Checkpoint:  result.Checkpoint,
		SyncedAt:    now.UTC().Format(time.RFC3339),
	}
	monitor.hasState = true
	monitor.lastError = ""
	monitor.lastErrorAt = ""
}

func (monitor *connectorIdentitySyncMonitor) RecordError(err error, now time.Time) {
	if monitor == nil || err == nil {
		return
	}
	monitor.mu.Lock()
	defer monitor.mu.Unlock()
	monitor.lastError = err.Error()
	monitor.lastErrorAt = now.UTC().Format(time.RFC3339)
}

func (monitor *connectorIdentitySyncMonitor) Snapshot(configured bool) connectorIdentitySyncMonitorSnapshot {
	if monitor == nil {
		return connectorIdentitySyncMonitorSnapshot{Configured: configured}
	}
	monitor.mu.RLock()
	defer monitor.mu.RUnlock()
	snapshot := connectorIdentitySyncMonitorSnapshot{
		Configured:  configured,
		LastError:   monitor.lastError,
		LastErrorAt: monitor.lastErrorAt,
	}
	if monitor.hasState {
		snapshot.Status = monitor.state.Status
		snapshot.Source = monitor.state.Source
		snapshot.ImportRunID = monitor.state.ImportRunID
		snapshot.Checkpoint = monitor.state.Checkpoint
		snapshot.SyncedAt = monitor.state.SyncedAt
	}
	return snapshot
}

func identitySyncLoop(ctx context.Context, client *http.Client, edgeURL, connectorID, connectorSecret, source, importFile, stateFile string, interval time.Duration, monitor *connectorIdentitySyncMonitor) {
	for {
		now := time.Now().UTC()
		result, err := syncHumanIdentitiesFromFile(ctx, client, edgeURL, connectorID, connectorSecret, source, importFile, now)
		if err != nil {
			monitor.RecordError(err, now)
			log.Printf("identity sync: %v", err)
		} else {
			monitor.Record(result, now)
			log.Printf("identity sync status=%s source=%s import_run_id=%s checkpoint=%s", result.Status, result.Source, result.ImportRunID, result.Checkpoint)
			if err := writeIdentitySyncState(stateFile, result, now); err != nil {
				log.Printf("identity sync state: %v", err)
			}
		}
		if interval <= 0 {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
	}
}

func syncHumanIdentitiesFromFile(ctx context.Context, client *http.Client, edgeURL, connectorID, connectorSecret, source, importFile string, now time.Time) (connectorIdentitySyncResult, error) {
	dueList, err := fetchIdentitySourcesDue(ctx, client, edgeURL, connectorID, connectorSecret)
	if err != nil {
		return connectorIdentitySyncResult{}, err
	}
	due, ok := selectIdentitySourceDue(dueList.Sources, source)
	if !ok {
		return connectorIdentitySyncResult{Status: "no_due_sources"}, nil
	}
	request, err := readConnectorHumanIdentityImportRequest(importFile)
	if err != nil {
		return connectorIdentitySyncResult{}, err
	}
	if strings.TrimSpace(request.Source) == "" {
		request.Source = due.Source
	}
	if request.Source != due.Source {
		return connectorIdentitySyncResult{}, fmt.Errorf("identity sync import source %q does not match due source %q", request.Source, due.Source)
	}
	if strings.TrimSpace(request.Checkpoint) == "" {
		request.Checkpoint = due.Checkpoint
	}
	if request.ReconcileMissing == nil {
		reconcile := due.ReconcileMissing
		request.ReconcileMissing = &reconcile
	}
	if strings.TrimSpace(request.ImportRunID) == "" {
		request.ImportRunID = fmt.Sprintf("human_import_connector_%d", now.UnixNano())
	}
	result, err := postIdentitySourceImport(ctx, client, edgeURL, connectorID, connectorSecret, request)
	if err != nil {
		return connectorIdentitySyncResult{}, err
	}
	result.Checkpoint = request.Checkpoint
	return result, nil
}

func fetchIdentitySourcesDue(ctx context.Context, client *http.Client, edgeURL, connectorID, connectorSecret string) (connectorIdentitySourceDueList, error) {
	var result connectorIdentitySourceDueList
	if err := getJSON(ctx, client, strings.TrimRight(edgeURL, "/")+"/identity-sources/due", connectorID, connectorSecret, &result); err != nil {
		return connectorIdentitySourceDueList{}, err
	}
	return result, nil
}

func postIdentitySourceImport(ctx context.Context, client *http.Client, edgeURL, connectorID, connectorSecret string, request connectorHumanIdentityImportRequest) (connectorIdentitySyncResult, error) {
	var result struct {
		Source      string `json:"source"`
		ImportRunID string `json:"import_run_id"`
	}
	if err := postJSONDecode(ctx, client, strings.TrimRight(edgeURL, "/")+"/identity-sources/import", request, connectorID, connectorSecret, &result); err != nil {
		return connectorIdentitySyncResult{}, err
	}
	return connectorIdentitySyncResult{Status: "imported", Source: result.Source, ImportRunID: result.ImportRunID}, nil
}

func selectIdentitySourceDue(sources []connectorIdentitySourceDue, source string) (connectorIdentitySourceDue, bool) {
	source = strings.TrimSpace(source)
	for _, candidate := range sources {
		if source == "" || candidate.Source == source {
			return candidate, true
		}
	}
	return connectorIdentitySourceDue{}, false
}

func readConnectorHumanIdentityImportRequest(filename string) (connectorHumanIdentityImportRequest, error) {
	if strings.TrimSpace(filename) == "" {
		return connectorHumanIdentityImportRequest{}, fmt.Errorf("identity sync import file is required")
	}
	data, err := os.ReadFile(filename)
	if err != nil {
		return connectorHumanIdentityImportRequest{}, fmt.Errorf("read identity sync import file: %w", err)
	}
	var request connectorHumanIdentityImportRequest
	if err := json.Unmarshal(data, &request); err != nil {
		return connectorHumanIdentityImportRequest{}, fmt.Errorf("decode identity sync import file: %w", err)
	}
	return request, nil
}

func writeIdentitySyncState(filename string, result connectorIdentitySyncResult, now time.Time) error {
	if strings.TrimSpace(filename) == "" {
		return nil
	}
	state := connectorIdentitySyncState{
		Status:      result.Status,
		Source:      result.Source,
		ImportRunID: result.ImportRunID,
		Checkpoint:  result.Checkpoint,
		SyncedAt:    now.UTC().Format(time.RFC3339),
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal identity sync state: %w", err)
	}
	data = append(data, '\n')
	if err := os.MkdirAll(filepath.Dir(filename), 0o700); err != nil {
		return fmt.Errorf("create identity sync state directory: %w", err)
	}
	temp := filename + ".tmp"
	if err := os.WriteFile(temp, data, 0o600); err != nil {
		return fmt.Errorf("write identity sync state: %w", err)
	}
	if err := os.Rename(temp, filename); err != nil {
		return fmt.Errorf("replace identity sync state: %w", err)
	}
	return nil
}

func getJSON(ctx context.Context, client *http.Client, url, connectorID, connectorSecret string, result any) error {
	if client == nil {
		client = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	if connectorID != "" {
		req.Header.Set(connectorIDHeader, connectorID)
	}
	if connectorSecret != "" {
		req.Header.Set(connectorSecretHeader, connectorSecret)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("status %d from %s", resp.StatusCode, url)
	}
	if err := json.NewDecoder(resp.Body).Decode(result); err != nil {
		return fmt.Errorf("decode %s: %w", url, err)
	}
	return nil
}

func postJSONDecode(ctx context.Context, client *http.Client, url string, value any, connectorID, connectorSecret string, result any) error {
	if client == nil {
		client = http.DefaultClient
	}
	payload, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("marshal json: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("content-type", "application/json")
	if connectorID != "" {
		req.Header.Set(connectorIDHeader, connectorID)
	}
	if connectorSecret != "" {
		req.Header.Set(connectorSecretHeader, connectorSecret)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("status %d from %s", resp.StatusCode, url)
	}
	if result == nil {
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(result); err != nil {
		return fmt.Errorf("decode %s: %w", url, err)
	}
	return nil
}
