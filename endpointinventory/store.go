package endpointinventory

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

type RuntimeStore interface {
	List(context.Context, string, ListOptions) (ListResponse, error)
	Get(context.Context, string, string) (Entry, bool, error)
	Upsert(context.Context, Entry, string, time.Time) (Entry, error)
}

type ListOptions struct {
	Status           string
	DeviceTrustLevel string
	Limit            int
}

type ListResponse struct {
	Endpoints []Entry `json:"endpoints"`
	Count     int     `json:"count"`
	Limit     int     `json:"limit"`
}

type Entry struct {
	EndpointID          string  `json:"endpoint_id"`
	TenantID            string  `json:"tenant_id"`
	UserID              string  `json:"user_id"`
	Hostname            string  `json:"hostname"`
	OS                  string  `json:"os"`
	OSVersion           string  `json:"os_version"`
	AgentVersion        string  `json:"agent_version"`
	DeviceTrustLevel    string  `json:"device_trust_level"`
	PolicyBundleID      string  `json:"policy_bundle_id"`
	PolicyBundleVersion string  `json:"policy_bundle_version"`
	Status              string  `json:"status"`
	RegisteredAt        string  `json:"registered_at"`
	LastSeenAt          string  `json:"last_seen_at"`
	MetadataKeyCount    int     `json:"metadata_key_count"`
	Source              string  `json:"source"`
	UpdatedAt           *string `json:"updated_at"`
}

type Store struct {
	mu        sync.RWMutex
	endpoints map[string]map[string]Entry
}

func (store *Store) List(_ context.Context, tenantID string, options ListOptions) (ListResponse, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return ListResponse{}, fmt.Errorf("tenant_id is required")
	}
	status := strings.TrimSpace(options.Status)
	if status != "" && !safeToken(status) {
		return ListResponse{}, fmt.Errorf("status is invalid")
	}
	trustLevel := strings.TrimSpace(options.DeviceTrustLevel)
	if trustLevel != "" && !safeToken(trustLevel) {
		return ListResponse{}, fmt.Errorf("device_trust_level is invalid")
	}
	limit := options.Limit
	if limit <= 0 {
		limit = 100
	}

	store.mu.RLock()
	defer store.mu.RUnlock()

	rows := []Entry{}
	for _, endpoint := range store.endpoints[tenantID] {
		if status != "" && endpoint.Status != status {
			continue
		}
		if trustLevel != "" && endpoint.DeviceTrustLevel != trustLevel {
			continue
		}
		rows = append(rows, endpoint)
	}
	sortEntries(rows)
	count := len(rows)
	if len(rows) > limit {
		rows = rows[:limit]
	}
	return ListResponse{
		Endpoints: rows,
		Count:     count,
		Limit:     limit,
	}, nil
}

func (store *Store) Get(_ context.Context, tenantID, endpointID string) (Entry, bool, error) {
	tenantID = strings.TrimSpace(tenantID)
	endpointID = strings.TrimSpace(endpointID)
	if tenantID == "" {
		return Entry{}, false, fmt.Errorf("tenant_id is required")
	}
	if endpointID == "" {
		return Entry{}, false, fmt.Errorf("endpoint_id is required")
	}
	if strings.Contains(endpointID, "/") {
		return Entry{}, false, fmt.Errorf("endpoint_id cannot contain slash")
	}

	store.mu.RLock()
	defer store.mu.RUnlock()

	endpoint, ok := store.endpoints[tenantID][endpointID]
	if !ok {
		return Entry{}, false, nil
	}
	return endpoint, true, nil
}

func (store *Store) Upsert(_ context.Context, endpoint Entry, tenantID string, now time.Time) (Entry, error) {
	normalized, err := normalize(endpoint, tenantID, now)
	if err != nil {
		return Entry{}, err
	}

	store.mu.Lock()
	defer store.mu.Unlock()

	store.putLocked(normalized)
	return normalized, nil
}

func (store *Store) putLocked(endpoint Entry) {
	if store.endpoints[endpoint.TenantID] == nil {
		store.endpoints[endpoint.TenantID] = map[string]Entry{}
	}
	store.endpoints[endpoint.TenantID][endpoint.EndpointID] = endpoint
}

func normalize(endpoint Entry, tenantID string, now time.Time) (Entry, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return Entry{}, fmt.Errorf("tenant_id is required")
	}
	endpoint.EndpointID = strings.TrimSpace(endpoint.EndpointID)
	if endpoint.EndpointID == "" {
		return Entry{}, fmt.Errorf("endpoint_id is required")
	}
	if strings.Contains(endpoint.EndpointID, "/") {
		return Entry{}, fmt.Errorf("endpoint_id cannot contain slash")
	}
	endpoint.TenantID = strings.TrimSpace(endpoint.TenantID)
	if endpoint.TenantID == "" {
		endpoint.TenantID = tenantID
	}
	if endpoint.TenantID != tenantID {
		return Entry{}, fmt.Errorf("endpoint tenant_id %s does not match authenticated tenant_id %s", endpoint.TenantID, tenantID)
	}
	if err := normalizeText(&endpoint.UserID, "user_id", false); err != nil {
		return Entry{}, err
	}
	if err := normalizeText(&endpoint.Hostname, "hostname", false); err != nil {
		return Entry{}, err
	}
	if err := normalizeText(&endpoint.OS, "os", false); err != nil {
		return Entry{}, err
	}
	if err := normalizeText(&endpoint.OSVersion, "os_version", false); err != nil {
		return Entry{}, err
	}
	if err := normalizeText(&endpoint.AgentVersion, "agent_version", false); err != nil {
		return Entry{}, err
	}
	if err := normalizeText(&endpoint.DeviceTrustLevel, "device_trust_level", false); err != nil {
		return Entry{}, err
	}
	if err := normalizeText(&endpoint.PolicyBundleID, "policy_bundle_id", false); err != nil {
		return Entry{}, err
	}
	if err := normalizeText(&endpoint.PolicyBundleVersion, "policy_bundle_version", false); err != nil {
		return Entry{}, err
	}
	if err := normalizeText(&endpoint.Status, "status", true); err != nil {
		return Entry{}, err
	}
	if endpoint.RegisteredAt != "" {
		endpoint.RegisteredAt = strings.TrimSpace(endpoint.RegisteredAt)
		if _, err := time.Parse(time.RFC3339, endpoint.RegisteredAt); err != nil {
			return Entry{}, fmt.Errorf("registered_at must be RFC3339")
		}
	}
	if endpoint.LastSeenAt != "" {
		endpoint.LastSeenAt = strings.TrimSpace(endpoint.LastSeenAt)
		if _, err := time.Parse(time.RFC3339, endpoint.LastSeenAt); err != nil {
			return Entry{}, fmt.Errorf("last_seen_at must be RFC3339")
		}
	}
	if endpoint.MetadataKeyCount < 0 {
		return Entry{}, fmt.Errorf("metadata_key_count must be non-negative")
	}
	endpoint.Source = strings.TrimSpace(endpoint.Source)
	if endpoint.Source == "" {
		endpoint.Source = "admin"
	}
	if endpoint.Source != "device_inventory" && endpoint.Source != "admin" {
		return Entry{}, fmt.Errorf("source %s is invalid", endpoint.Source)
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	updatedAt := now.UTC().Format(time.RFC3339)
	endpoint.UpdatedAt = &updatedAt
	return endpoint, nil
}

func normalizeText(value *string, field string, required bool) error {
	*value = strings.TrimSpace(*value)
	if *value == "" {
		if required {
			return fmt.Errorf("%s is required", field)
		}
		return nil
	}
	if !safeToken(*value) {
		return fmt.Errorf("%s is invalid", field)
	}
	return nil
}

// safeToken is the character allowlist for inventory text fields. '+' is included because it is the standard
// semver separator for BUILD METADATA, and this product stamps exactly that: the macOS agent reports
// "0.1.0+20260805170618" (version + build timestamp). Without it the agent that finally reported a real
// version was the one the inventory rejected — see the note on the rejection path in normalize's callers.
func safeToken(value string) bool {
	if value == "" {
		return false
	}
	for _, ch := range value {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '_' || ch == '-' || ch == '.' || ch == ':' || ch == '@' || ch == '+' {
			continue
		}
		return false
	}
	return true
}

func EntryFromDevice(device model.Device) Entry {
	return Entry{
		EndpointID:          device.ID,
		TenantID:            device.TenantID,
		UserID:              device.UserID,
		Hostname:            device.Hostname,
		OS:                  device.OS,
		OSVersion:           device.OSVersion,
		AgentVersion:        device.AgentVersion,
		DeviceTrustLevel:    device.DeviceTrustLevel,
		PolicyBundleID:      device.PolicyBundleID,
		PolicyBundleVersion: device.PolicyBundleVersion,
		Status:              device.Status,
		RegisteredAt:        device.RegisteredAt,
		LastSeenAt:          device.LastSeenAt,
		MetadataKeyCount:    len(device.Metadata),
		Source:              "device_inventory",
	}
}

func sortEntries(endpoints []Entry) {
	sort.SliceStable(endpoints, func(i, j int) bool {
		if endpoints[i].Status != endpoints[j].Status {
			return endpoints[i].Status < endpoints[j].Status
		}
		return endpoints[i].EndpointID < endpoints[j].EndpointID
	})
}

// NewStore returns an empty inventory store. Device-derived construction lives in cmd/edge (it depends on the
// deviceRuntimeStore) and populates this store via EntryFromDevice + Upsert.
func NewStore() *Store {
	return &Store{endpoints: map[string]map[string]Entry{}}
}
