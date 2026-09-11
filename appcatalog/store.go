package appcatalog

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// ErrApplicationNotFound is returned by Delete when no application with the given id exists for the tenant.
// It also covers the cross-tenant case (a tenant asking to delete another tenant's id sees not-found), so a
// tenant can never observe or affect another tenant's catalog. Handlers map it to 404.
var ErrApplicationNotFound = errors.New("application not found")

// ErrApplicationNotDeletable is returned by Delete for a CONFIG-SEED entry (one derived from the route profiles
// / SaaS catalog at boot). Config-seed entries are reconstructed from configuration on every restart, so they
// are not deletable via the API — removing one would only reappear on the next boot. Edit configuration (or
// disable the entry) instead. Handlers map it to 404 with an explanatory message.
var ErrApplicationNotDeletable = errors.New("application is config-seeded and cannot be deleted")

type RuntimeStore interface {
	List(context.Context, string, ListOptions) (ListResponse, error)
	Get(context.Context, string, string) (Entry, bool, error)
	Upsert(context.Context, Entry, string, time.Time) (Entry, error)
	// Delete removes an operator-authored application (the durable overlay) for a tenant. It NEVER removes a
	// config-seed entry (returns ErrApplicationNotDeletable) and returns ErrApplicationNotFound when no such id
	// exists for the tenant. On success the entry disappears from List/Get and from any published route overlay
	// (so a published app becomes unreachable — fail-closed — without a separate unpublish).
	Delete(context.Context, string, string) error
}

type ListOptions struct {
	ApplicationType string
	Status          string
	Limit           int
}

type ListResponse struct {
	Applications []Entry `json:"applications"`
	Count        int     `json:"count"`
	Limit        int     `json:"limit"`
}

type Entry struct {
	ApplicationID          string   `json:"application_id"`
	TenantID               string   `json:"tenant_id"`
	Name                   string   `json:"name"`
	ApplicationType        string   `json:"application_type"`
	ServiceFamily          string   `json:"service_family"`
	Protocol               string   `json:"protocol"`
	DestinationRole        string   `json:"destination_role"`
	ApplicationSensitivity string   `json:"application_sensitivity"`
	RouteRef               string   `json:"route_ref"`
	SaaSProvider           string   `json:"saas_provider"`
	SaaSCategory           string   `json:"saas_category"`
	SaaSRiskTier           string   `json:"saas_risk_tier"`
	DomainPatternCount     int      `json:"domain_pattern_count"`
	SNIPatternCount        int      `json:"sni_pattern_count"`
	Tags                   []string `json:"tags"`
	Status                 string   `json:"status"`
	UpdatedAt              *string  `json:"updated_at"`

	// Connector UX Slice 2 (Private App publish) — additive, omitempty. A PUBLISHED private_app entry carries
	// its own route (destination/port/protocol) so the edge can resolve a runtime route for it WITHOUT a
	// -protected-app-map (file) entry. Publishing creates reachability only; authorization stays with policy
	// (Published != Allow). PublishProtocol is the publish app type (web|tcp|network); it is a distinct field
	// from Protocol (the existing L4/transport enum) to stay additive and avoid colliding with the established
	// "protocol" JSON key. last_probe_at records the most recent reachability probe (diagnostics), never a secret.
	Destination      string  `json:"destination,omitempty"`
	DestinationPort  int     `json:"destination_port,omitempty"`
	PublishProtocol  string  `json:"publish_protocol,omitempty"`
	ConnectorGroupID string  `json:"connector_group_id,omitempty"`
	Published        bool    `json:"published,omitempty"`
	LastProbeAt      *string `json:"last_probe_at,omitempty"`

	// Connector UX Slice 5 (CIDR collision + namespace UX, docs/connector_ux_design.md) — additive, omitempty.
	// RoutingNamespace is the site / virtual-network id that SCOPES a network (CIDR) route so overlapping private
	// ranges can coexist across sites. It is consulted only for CIDR-destination (publish_protocol=network) routes
	// at publish time for collision detection; FQDN/web/tcp host routes ignore it. Empty namespace + an overlapping
	// CIDR is "ambiguous" and blocked by default.
	RoutingNamespace string `json:"routing_namespace,omitempty"`
}

type Store struct {
	mu           sync.RWMutex
	applications map[string]map[string]Entry
	statePath    string // when set, authored applications are persisted here (survive restart)
	// seed is the set of CONFIG-DERIVED entries (tenant_id -> application_id), captured by SetStatePath BEFORE the
	// persisted authored overlay is loaded. At that moment the store holds only the config seed (route profiles +
	// SaaS catalog), so this records exactly which ids are non-deletable: Delete refuses to remove an id present
	// here because it would be reconstructed from configuration on the next boot anyway. A bare store that never
	// calls SetStatePath has a nil seed (every entry is treated as authored / deletable).
	seed map[string]map[string]struct{}
}

func (store *Store) List(_ context.Context, tenantID string, options ListOptions) (ListResponse, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return ListResponse{}, fmt.Errorf("tenant_id is required")
	}
	applicationType := strings.TrimSpace(options.ApplicationType)
	if applicationType != "" && !validType(applicationType) {
		return ListResponse{}, fmt.Errorf("application_type %s is invalid", applicationType)
	}
	status := strings.TrimSpace(options.Status)
	if status != "" && !validStatus(status) {
		return ListResponse{}, fmt.Errorf("application status %s is invalid", status)
	}
	limit := options.Limit
	if limit <= 0 {
		limit = 100
	}

	store.mu.RLock()
	defer store.mu.RUnlock()

	rows := []Entry{}
	for _, application := range store.applications[tenantID] {
		if applicationType != "" && application.ApplicationType != applicationType {
			continue
		}
		if status != "" && application.Status != status {
			continue
		}
		rows = append(rows, copyEntry(application))
	}
	sortEntries(rows)
	count := len(rows)
	if len(rows) > limit {
		rows = rows[:limit]
	}
	return ListResponse{
		Applications: rows,
		Count:        count,
		Limit:        limit,
	}, nil
}

func (store *Store) Get(_ context.Context, tenantID, applicationID string) (Entry, bool, error) {
	tenantID = strings.TrimSpace(tenantID)
	applicationID = strings.TrimSpace(applicationID)
	if tenantID == "" {
		return Entry{}, false, fmt.Errorf("tenant_id is required")
	}
	if applicationID == "" {
		return Entry{}, false, fmt.Errorf("application_id is required")
	}

	store.mu.RLock()
	defer store.mu.RUnlock()

	application, ok := store.applications[tenantID][applicationID]
	if !ok {
		return Entry{}, false, nil
	}
	return copyEntry(application), true, nil
}

func (store *Store) Upsert(_ context.Context, application Entry, tenantID string, now time.Time) (Entry, error) {
	normalized, err := normalize(application, tenantID, now)
	if err != nil {
		return Entry{}, err
	}

	store.mu.Lock()
	defer store.mu.Unlock()

	if err := store.putLocked(normalized); err != nil {
		return copyEntry(normalized), err
	}
	return copyEntry(normalized), nil
}

// putLocked stores the application and snapshots. A non-nil error means the entry IS live in memory but
// durability failed (it would vanish on restart) — callers propagate it to the API layer.
func (store *Store) putLocked(application Entry) error {
	if store.applications[application.TenantID] == nil {
		store.applications[application.TenantID] = map[string]Entry{}
	}
	store.applications[application.TenantID][application.ApplicationID] = copyEntry(application)
	if err := store.persistLocked(); err != nil {
		return fmt.Errorf("application %s stored in memory but not persisted (will not survive a restart): %w", application.ApplicationID, err)
	}
	return nil
}

// Delete removes an operator-authored application for a tenant. Tenant-scoped, fail-closed, and idempotent at
// the resource level (the end state is the entry being absent). A config-seed id (recorded by SetStatePath)
// returns ErrApplicationNotDeletable — it is reconstructed from configuration on every boot, so it cannot be
// removed via the API; an unknown id (including any id under another tenant) returns ErrApplicationNotFound.
func (store *Store) Delete(_ context.Context, tenantID, applicationID string) error {
	tenantID = strings.TrimSpace(tenantID)
	applicationID = strings.TrimSpace(applicationID)
	if tenantID == "" {
		return fmt.Errorf("tenant_id is required")
	}
	if applicationID == "" {
		return fmt.Errorf("application_id is required")
	}

	store.mu.Lock()
	defer store.mu.Unlock()

	if _, ok := store.seed[tenantID][applicationID]; ok {
		return ErrApplicationNotDeletable
	}
	if _, ok := store.applications[tenantID][applicationID]; !ok {
		return ErrApplicationNotFound
	}
	delete(store.applications[tenantID], applicationID)
	if len(store.applications[tenantID]) == 0 {
		delete(store.applications, tenantID)
	}
	if err := store.persistLocked(); err != nil {
		return fmt.Errorf("application %s deleted in memory but not persisted (would resurrect on restart): %w", applicationID, err)
	}
	return nil
}

func normalize(application Entry, tenantID string, now time.Time) (Entry, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return Entry{}, fmt.Errorf("tenant_id is required")
	}

	application.ApplicationID = strings.TrimSpace(application.ApplicationID)
	if application.ApplicationID == "" {
		return Entry{}, fmt.Errorf("application_id is required")
	}
	if strings.Contains(application.ApplicationID, "/") {
		return Entry{}, fmt.Errorf("application_id cannot contain slash")
	}

	application.TenantID = strings.TrimSpace(application.TenantID)
	if application.TenantID == "" {
		application.TenantID = tenantID
	}
	if application.TenantID != tenantID {
		return Entry{}, fmt.Errorf("application tenant_id %s does not match authenticated tenant_id %s", application.TenantID, tenantID)
	}

	application.ApplicationType = strings.TrimSpace(application.ApplicationType)
	if application.ApplicationType == "" {
		application.ApplicationType = "private_app"
	}
	if !validType(application.ApplicationType) {
		return Entry{}, fmt.Errorf("application_type %s is invalid", application.ApplicationType)
	}

	application.Name = strings.TrimSpace(application.Name)
	if application.Name == "" {
		application.Name = application.ApplicationID
	}
	application.ServiceFamily = strings.TrimSpace(application.ServiceFamily)
	if application.ServiceFamily == "" {
		if application.ApplicationType == "saas" {
			application.ServiceFamily = "saas"
		} else if fam := serviceFamilyForDestinationPort(application.DestinationPort); fam != "" {
			// Derive the family from a well-known private-app port (22→ssh, 3389→rdp, 445→smb, …) so a
			// published TCP app on a lateral (east-west) protocol port classifies correctly. Without this a
			// port-22 app defaulted to "https", which excluded it from decision.IsEastWestProtocol — so the
			// east-west per-hop authz layer was skipped and Console "Connector Access" rules never engaged.
			application.ServiceFamily = fam
		} else {
			application.ServiceFamily = "https"
		}
	}
	application.Protocol = strings.TrimSpace(application.Protocol)
	if application.Protocol == "" {
		application.Protocol = "tcp"
	}
	application.DestinationRole = strings.TrimSpace(application.DestinationRole)
	if application.DestinationRole == "" && application.ApplicationType == "private_app" {
		application.DestinationRole = destinationRoleForServiceFamily(application.ServiceFamily)
	}
	application.ApplicationSensitivity = strings.TrimSpace(application.ApplicationSensitivity)
	if application.ApplicationSensitivity == "" {
		application.ApplicationSensitivity = "medium"
	}
	application.RouteRef = strings.TrimSpace(application.RouteRef)
	if application.RouteRef != "" && !safeAdminCatalogRef(application.RouteRef) {
		return Entry{}, fmt.Errorf("route_ref is invalid")
	}
	application.SaaSProvider = strings.TrimSpace(application.SaaSProvider)
	application.SaaSCategory = strings.TrimSpace(application.SaaSCategory)
	application.SaaSRiskTier = strings.TrimSpace(application.SaaSRiskTier)
	if application.DomainPatternCount < 0 || application.SNIPatternCount < 0 {
		return Entry{}, fmt.Errorf("pattern counts must be non-negative")
	}
	application.Tags = normalizedStringList(application.Tags)

	// Slice 2 publish fields (additive). All validation is fail-closed: a malformed publish field is rejected
	// rather than silently dropped, and an entry can only be marked published when it carries a routable
	// destination — so publish never produces an unroutable "published" record.
	application.Destination = strings.TrimSpace(application.Destination)
	application.PublishProtocol = strings.TrimSpace(application.PublishProtocol)
	if application.PublishProtocol != "" && !validPublishProtocol(application.PublishProtocol) {
		return Entry{}, fmt.Errorf("publish_protocol %s is invalid", application.PublishProtocol)
	}
	if application.DestinationPort < 0 || application.DestinationPort > 65535 {
		return Entry{}, fmt.Errorf("destination_port must be between 0 and 65535")
	}
	application.ConnectorGroupID = strings.TrimSpace(application.ConnectorGroupID)
	if application.ConnectorGroupID != "" && !safeAdminCatalogRef(application.ConnectorGroupID) {
		return Entry{}, fmt.Errorf("connector_group_id is invalid")
	}
	application.RoutingNamespace = strings.TrimSpace(application.RoutingNamespace)
	if application.RoutingNamespace != "" && !safeAdminCatalogRef(application.RoutingNamespace) {
		return Entry{}, fmt.Errorf("routing_namespace is invalid")
	}
	if application.Published {
		if application.ApplicationType != "private_app" {
			return Entry{}, fmt.Errorf("only private_app entries can be published")
		}
		if application.Destination == "" {
			return Entry{}, fmt.Errorf("destination is required to publish an application")
		}
	}
	if application.LastProbeAt != nil {
		probe := strings.TrimSpace(*application.LastProbeAt)
		if probe == "" {
			application.LastProbeAt = nil
		} else {
			application.LastProbeAt = &probe
		}
	}

	status := strings.TrimSpace(application.Status)
	if status == "" {
		status = "draft"
	}
	if !validStatus(status) {
		return Entry{}, fmt.Errorf("application status %s is invalid", status)
	}
	application.Status = status

	if now.IsZero() {
		now = time.Now().UTC()
	}
	updatedAt := now.UTC().Format(time.RFC3339)
	application.UpdatedAt = &updatedAt
	return application, nil
}

func validType(applicationType string) bool {
	switch applicationType {
	case "private_app", "saas":
		return true
	default:
		return false
	}
}

func validStatus(status string) bool {
	switch status {
	case "active", "draft", "disabled":
		return true
	default:
		return false
	}
}

func validPublishProtocol(publishProtocol string) bool {
	switch publishProtocol {
	case "web", "tcp", "network":
		return true
	default:
		return false
	}
}

// serviceFamilyForDestinationPort maps a well-known private-app destination port to its service family so a
// published TCP app on a lateral (east-west) protocol port is classified correctly instead of defaulting to
// "https". Kept in sync with cmd/edge steerServiceFamilyForPort for the lateral families (this module cannot
// import package main). Only the lateral/internal protocols are mapped; web ports fall through to the "https"
// default. Empty = unknown port (caller keeps the default).
func serviceFamilyForDestinationPort(port int) string {
	switch port {
	case 22:
		return "ssh"
	case 3389:
		return "rdp"
	case 445, 139:
		return "smb"
	case 5985, 5986:
		return "winrm"
	case 135:
		return "wmi_rpc"
	case 5900:
		return "vnc"
	default:
		return ""
	}
}

func copyEntry(application Entry) Entry {
	application.Tags = append([]string(nil), application.Tags...)
	if application.LastProbeAt != nil {
		probe := *application.LastProbeAt
		application.LastProbeAt = &probe
	}
	return application
}

func sortEntries(applications []Entry) {
	sort.SliceStable(applications, func(i, j int) bool {
		if applications[i].ApplicationType != applications[j].ApplicationType {
			return applications[i].ApplicationType < applications[j].ApplicationType
		}
		return applications[i].ApplicationID < applications[j].ApplicationID
	})
}

// NewStore returns an empty catalog store. Config-driven construction (route profiles + SaaS catalog) lives
// in cmd/edge and builds via Upsert.
func NewStore() *Store {
	return &Store{applications: map[string]map[string]Entry{}}
}

// Snapshot returns a deep copy of the catalog keyed by tenant_id -> application_id. It lets an alternative durable
// backend (the Postgres backend in cmd/edge) capture the config-derived SEED so it can overlay durable authored
// entries on top of it — mirroring how SetStatePath/loadLocked merge the persisted set on top of the seed. The
// returned maps are independent of the store's internal state (safe to retain and read concurrently).
func (store *Store) Snapshot() map[string]map[string]Entry {
	store.mu.RLock()
	defer store.mu.RUnlock()
	out := make(map[string]map[string]Entry, len(store.applications))
	for tenantID, byID := range store.applications {
		cp := make(map[string]Entry, len(byID))
		for id, application := range byID {
			cp[id] = copyEntry(application)
		}
		out[tenantID] = cp
	}
	return out
}

// Normalize validates and canonicalizes an entry for the given tenant, stamping UpdatedAt — the exported form of
// the normalization the file store applies on Upsert. Alternative durable backends use it so they normalize
// IDENTICALLY to the file store. now=zero uses time.Now().UTC().
func Normalize(application Entry, tenantID string, now time.Time) (Entry, error) {
	return normalize(application, tenantID, now)
}

// ValidApplicationType reports whether applicationType is a recognized catalog type. Exported so alternative
// backends validate List filters identically to the file store.
func ValidApplicationType(applicationType string) bool { return validType(applicationType) }

// ValidStatus reports whether status is a recognized catalog status. Exported so alternative backends validate
// List filters identically to the file store.
func ValidStatus(status string) bool { return validStatus(status) }

// SortEntries applies the file store's stable list ordering (by application_type then application_id). Exported so
// alternative backends return identically ordered lists.
func SortEntries(applications []Entry) { sortEntries(applications) }

// CopyEntry returns a defensive deep copy of an entry (independent Tags slice + LastProbeAt pointer). Exported so
// alternative backends isolate returned values from their internal/seed state exactly like the file store.
func CopyEntry(application Entry) Entry { return copyEntry(application) }

// normalizedStringList trims, de-dups, drops empties (order-preserving) — package-local copy.
func normalizedStringList(values []string) []string {
	result := []string{}
	seen := map[string]bool{}
	for _, value := range values {
		normalized := strings.TrimSpace(value)
		if normalized == "" || seen[normalized] {
			continue
		}
		seen[normalized] = true
		result = append(result, normalized)
	}
	return result
}

// safeAdminCatalogRef reports whether value is a safe catalog identifier (alphanumerics + _-).
func safeAdminCatalogRef(value string) bool {
	if value == "" {
		return false
	}
	for _, ch := range value {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '_' || ch == '-' {
			continue
		}
		return false
	}
	return true
}

// destinationRoleForServiceFamily maps a service family to its destination role default.
func destinationRoleForServiceFamily(serviceFamily string) string {
	switch serviceFamily {
	case "ssh":
		return "ssh_server"
	case "database":
		return "database_server"
	case "rdp":
		return "admin_server"
	default:
		return "private_app"
	}
}
