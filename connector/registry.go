package connector

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/model"
)

type Registry struct {
	mu         sync.RWMutex
	connectors map[string]model.ConnectorRegistration
	// catalogGen is a monotonic counter bumped ONLY when the route-relevant connector catalog changes (a new
	// connector, or a change to tenant/status/region/cluster/private-base-url/reachable-routes). It is NOT bumped
	// by heartbeats or runtime-secret rotation, so a config-bundle distributor can fan the catalog fleet-wide and
	// trigger an Edge re-pull on real catalog changes only (no per-heartbeat churn).
	catalogGen uint64
	// persister, when set, makes the registry DURABLE. It was in-memory only, and that turns a routine Edge
	// restart into a connector outage: the registry is wiped, a connector only registers ONCE at startup, so
	// every heartbeat and tunnel afterwards gets 404 (unknown connector) forever and the Console shows an empty
	// fleet. Nothing recovers it except restarting every connector. Observed live 2026-07-17 after an Edge
	// rebuild — the connector sat in a 404 loop while healthy. Nil = in-memory only.
	//
	// This does NOT make the connector the authority over its own existence: it still attaches and the Edge
	// still records. It only stops the Edge FORGETTING the fleet when it restarts.
	persister blobstore.Persister
}

// registryPersistSnapshot is the on-disk shape. Only the registrations are persisted: catalogGen is a
// process-local change counter for config distribution, not fleet state, and restarting it at 0 is correct.
type registryPersistSnapshot struct {
	Connectors map[string]model.ConnectorRegistration `json:"connectors"`
}

// OnPersistError, when set, is called if a snapshot fails to save. A dropped save is invisible and expensive:
// registration returns success, the Console shows the fleet, and the next Edge restart forgets every connector.
// That is the outage this persistence prevents, silently recreated while looking healthy. Must not panic.
//
// It does NOT fail the registration: the in-memory registry is already serving the connector, and rejecting an
// attaching connector because the disk is unhappy is the worse failure.
var OnPersistError func(error)

// SetPersister enables durable persistence so registered connectors survive an Edge restart. It loads any prior
// snapshot immediately, then every mutation re-saves the full set. Nil disables persistence.
func (r *Registry) SetPersister(p blobstore.Persister) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.persister = p
	if p == nil {
		return nil
	}
	data, err := p.Load()
	if err != nil {
		return err
	}
	if len(data) == 0 {
		return nil
	}
	var snap registryPersistSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return err
	}
	if snap.Connectors != nil {
		r.connectors = snap.Connectors
	}
	return nil
}

// persistLocked writes the full snapshot. The CALLER must hold r.mu. No-op without a persister.
func (r *Registry) persistLocked() {
	if r.persister == nil {
		return
	}
	data, err := json.Marshal(registryPersistSnapshot{Connectors: r.connectors})
	if err != nil {
		reportRegistryPersistError(fmt.Errorf("marshal connector registry snapshot: %w", err))
		return
	}
	if err := r.persister.Save(data); err != nil {
		reportRegistryPersistError(fmt.Errorf("save connector registry snapshot: %w", err))
	}
}

func reportRegistryPersistError(err error) {
	if OnPersistError != nil {
		OnPersistError(err)
	}
}

const (
	runtimeSecretHashMetadataKey    = "runtime_secret_hash"
	runtimeSecretHashMetadataPrefix = "sha256:"
	runtimeSecretRotatedAtKey       = "runtime_secret_rotated_at"
	runtimeSecretRotatedByKey       = "runtime_secret_rotated_by"
	// connectorDisplayNameKey holds an OPERATOR-set display name for the connector. It is server-managed: the
	// connector cannot set it via registration, and it is preserved across re-registration + heartbeats, so an
	// admin rename sticks even when the connector reconnects.
	connectorDisplayNameKey = "admin_display_name"
)

func NewRegistry() *Registry {
	return &Registry{
		connectors: map[string]model.ConnectorRegistration{},
	}
}

func (r *Registry) Register(conn model.ConnectorRegistration, now time.Time) (model.ConnectorRegistration, error) {
	if conn.ID == "" {
		return conn, fmt.Errorf("connector id is required")
	}
	if conn.TenantID == "" {
		return conn, fmt.Errorf("connector tenant_id is required")
	}
	if conn.PrivateBaseURL == "" {
		return conn, fmt.Errorf("connector private_base_url is required")
	}
	if conn.Status == "" {
		conn.Status = "registered"
	}
	if conn.RegisteredAt == "" {
		conn.RegisteredAt = now.UTC().Format(time.RFC3339)
	}
	if conn.LastHeartbeatAt == "" {
		conn.LastHeartbeatAt = conn.RegisteredAt
	}
	if conn.Metadata == nil {
		conn.Metadata = map[string]any{}
	}
	if err := validateRuntimeSecretHashMetadata(conn.Metadata); err != nil {
		return conn, err
	}
	removeServerManagedRuntimeSecretMetadata(conn.Metadata)

	r.mu.Lock()
	defer r.mu.Unlock()
	prev, had := r.connectors[conn.ID]
	if had {
		if prev.TenantID != conn.TenantID {
			return model.ConnectorRegistration{}, fmt.Errorf("connector %s is already registered for tenant %s", conn.ID, prev.TenantID)
		}
		preserveServerManagedRuntimeSecretMetadata(prev.Metadata, conn.Metadata)
		preserveServerManagedRegistrationState(prev, &conn)
	}
	r.connectors[conn.ID] = conn
	if !had || connectorCatalogChanged(prev, conn) {
		r.catalogGen++
	}
	r.persistLocked()
	return conn, nil
}

// ConfigGeneration is the monotonic catalog version (see catalogGen). A config-bundle distributor folds it into
// the aggregate generation so a catalog change triggers a fleet-wide re-pull.
func (r *Registry) ConfigGeneration() uint64 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.catalogGen
}

// connectorCatalogChanged reports whether the route-relevant (class-1) fields differ — what a config-bundle
// distributor cares about. Runtime state (heartbeat, runtime-secret metadata) is intentionally excluded.
func connectorCatalogChanged(a, b model.ConnectorRegistration) bool {
	if a.TenantID != b.TenantID || a.Status != b.Status || a.EdgeRegionID != b.EdgeRegionID ||
		a.EdgeClusterID != b.EdgeClusterID || a.PrivateBaseURL != b.PrivateBaseURL ||
		a.ConnectorGroupID != b.ConnectorGroupID {
		return true
	}
	return !sameReachableRoutes(a.ReachableRoutes, b.ReachableRoutes)
}

func sameReachableRoutes(a, b model.ConnectorReachableRoutes) bool {
	return a.Namespace == b.Namespace && sameStringSet(a.FQDNDomains, b.FQDNDomains) && sameStringSet(a.CIDRs, b.CIDRs)
}

func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x := append([]string(nil), a...)
	y := append([]string(nil), b...)
	sort.Strings(x)
	sort.Strings(y)
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

func (r *Registry) Heartbeat(heartbeat model.ConnectorHeartbeat, now time.Time) (model.ConnectorRegistration, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	conn, ok := r.connectors[heartbeat.ID]
	if !ok {
		return conn, fmt.Errorf("connector %s is not registered", heartbeat.ID)
	}
	priorStatus := conn.Status
	if heartbeat.TenantID != "" && heartbeat.TenantID != conn.TenantID {
		return conn, fmt.Errorf("connector tenant_id %s does not match registered tenant_id %s", heartbeat.TenantID, conn.TenantID)
	}
	if heartbeat.Status != "" {
		conn.Status = heartbeat.Status
	} else {
		conn.Status = "healthy"
	}
	if heartbeat.Timestamp != "" {
		conn.LastHeartbeatAt = heartbeat.Timestamp
	} else {
		conn.LastHeartbeatAt = now.UTC().Format(time.RFC3339)
	}
	if conn.Metadata == nil {
		conn.Metadata = map[string]any{}
	}
	for key, value := range heartbeat.Metadata {
		if isServerManagedRuntimeSecretMetadata(key) {
			continue
		}
		conn.Metadata[key] = value
	}
	conn.Metadata["policy_bundle_id"] = heartbeat.PolicyBundleID
	conn.Metadata["policy_bundle_version"] = heartbeat.PolicyBundleVersion
	if strings.TrimSpace(heartbeat.Version) != "" {
		conn.Metadata["version"] = strings.TrimSpace(heartbeat.Version)
	}
	if heartbeat.UptimeSeconds > 0 {
		conn.Metadata["uptime_seconds"] = heartbeat.UptimeSeconds
	}
	// A connector may re-report its reachable routes on the heartbeat so the Edge's discovery list stays current
	// without a reconnect. Update the registered set when present (additive — an older connector omits it).
	if heartbeat.ReachableRoutes != nil {
		conn.ReachableRoutes = *heartbeat.ReachableRoutes
	}
	r.connectors[conn.ID] = conn
	if conn.Status != priorStatus {
		r.persistLocked() // a transition is state an operator reads; a steady beat is not
	}
	return conn, nil
}

func (r *Registry) RotateRuntimeSecretHash(id, hash string) (model.ConnectorRegistration, bool, error) {
	return r.RotateRuntimeSecretHashWithMetadata(id, hash, time.Time{}, "")
}

func (r *Registry) RotateRuntimeSecretHashWithMetadata(id, hash string, rotatedAt time.Time, rotatedBy string) (model.ConnectorRegistration, bool, error) {
	return r.rotateRuntimeSecretHashWithMetadata("", id, hash, rotatedAt, rotatedBy)
}

func (r *Registry) RotateRuntimeSecretHashForTenantWithMetadata(tenantID, id, hash string, rotatedAt time.Time, rotatedBy string) (model.ConnectorRegistration, bool, error) {
	return r.rotateRuntimeSecretHashWithMetadata(strings.TrimSpace(tenantID), id, hash, rotatedAt, rotatedBy)
}

func (r *Registry) rotateRuntimeSecretHashWithMetadata(tenantID, id, hash string, rotatedAt time.Time, rotatedBy string) (model.ConnectorRegistration, bool, error) {
	if err := validateRuntimeSecretHashMetadata(map[string]any{runtimeSecretHashMetadataKey: hash}); err != nil {
		return model.ConnectorRegistration{}, false, err
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	conn, ok := r.connectors[id]
	if !ok {
		return model.ConnectorRegistration{}, false, nil
	}
	if tenantID != "" && conn.TenantID != tenantID {
		return model.ConnectorRegistration{}, false, nil
	}
	if conn.Metadata == nil {
		conn.Metadata = map[string]any{}
	}
	conn.Metadata[runtimeSecretHashMetadataKey] = strings.TrimSpace(hash)
	if !rotatedAt.IsZero() {
		conn.Metadata[runtimeSecretRotatedAtKey] = rotatedAt.UTC().Format(time.RFC3339)
	}
	if strings.TrimSpace(rotatedBy) != "" {
		conn.Metadata[runtimeSecretRotatedByKey] = strings.TrimSpace(rotatedBy)
	}
	r.connectors[id] = conn
	r.persistLocked()
	return conn, true, nil
}

func (r *Registry) Get(id string) (model.ConnectorRegistration, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	conn, ok := r.connectors[id]
	return conn, ok
}

func (r *Registry) FindByApplicationID(applicationID string) (model.ConnectorRegistration, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	ids := make([]string, 0, len(r.connectors))
	for id := range r.connectors {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		conn := r.connectors[id]
		if conn.Status == "offline" {
			continue
		}
		for _, candidate := range conn.ApplicationIDs {
			if candidate == applicationID {
				return conn, true
			}
		}
	}
	return model.ConnectorRegistration{}, false
}

func (r *Registry) List() []model.ConnectorRegistration {
	r.mu.RLock()
	defer r.mu.RUnlock()
	connectors := make([]model.ConnectorRegistration, 0, len(r.connectors))
	for _, conn := range r.connectors {
		connectors = append(connectors, conn)
	}
	return connectors
}

func validateRuntimeSecretHashMetadata(metadata map[string]any) error {
	if metadata == nil {
		return nil
	}
	raw, ok := metadata[runtimeSecretHashMetadataKey]
	if !ok {
		return nil
	}
	hash, ok := raw.(string)
	if !ok {
		return fmt.Errorf("connector metadata.%s must be a string", runtimeSecretHashMetadataKey)
	}
	hash = strings.TrimSpace(hash)
	if len(hash) != len(runtimeSecretHashMetadataPrefix)+64 || !strings.HasPrefix(hash, runtimeSecretHashMetadataPrefix) {
		return fmt.Errorf("connector metadata.%s must be sha256:<64 lowercase hex>", runtimeSecretHashMetadataKey)
	}
	for _, r := range strings.TrimPrefix(hash, runtimeSecretHashMetadataPrefix) {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return fmt.Errorf("connector metadata.%s must be sha256:<64 lowercase hex>", runtimeSecretHashMetadataKey)
		}
	}
	return nil
}

func removeServerManagedRuntimeSecretMetadata(metadata map[string]any) {
	if metadata == nil {
		return
	}
	for key := range metadata {
		if key == runtimeSecretRotatedAtKey || key == runtimeSecretRotatedByKey || key == connectorDisplayNameKey {
			delete(metadata, key)
		}
	}
}

func preserveServerManagedRuntimeSecretMetadata(existing, next map[string]any) {
	if existing == nil || next == nil {
		return
	}
	for _, key := range []string{runtimeSecretHashMetadataKey, runtimeSecretRotatedAtKey, runtimeSecretRotatedByKey, connectorDisplayNameKey} {
		if value, ok := existing[key]; ok {
			next[key] = value
		}
	}
}

func preserveServerManagedRegistrationState(existing model.ConnectorRegistration, next *model.ConnectorRegistration) {
	if next == nil {
		return
	}
	next.Status = existing.Status
	next.RegisteredAt = existing.RegisteredAt
	next.LastHeartbeatAt = existing.LastHeartbeatAt
	// ★ A CONNECTOR NEVER REPORTS WHERE IT IS ATTACHED, SO ITS REGISTRATION MUST NOT CLEAR IT. Only a node
	// terminating the tunnel knows that, and it says so separately (RecordAttachedRegion). Letting an incoming
	// registration carry the zero value through would erase it on every connector restart — silence read as an
	// instruction.
	if strings.TrimSpace(next.AttachedRegionID) == "" {
		next.AttachedRegionID = existing.AttachedRegionID
	}
}

func isServerManagedRuntimeSecretMetadata(key string) bool {
	return key == runtimeSecretHashMetadataKey || key == runtimeSecretRotatedAtKey || key == runtimeSecretRotatedByKey || key == connectorDisplayNameKey
}

// SetDisplayNameForTenant sets (or clears, when name is empty) the operator display name for a connector. The
// name is stored as server-managed metadata so it survives re-registration + heartbeats. Reports whether the
// connector exists; errors on a cross-tenant mismatch.
func (r *Registry) SetDisplayNameForTenant(tenantID, id, name string) (model.ConnectorRegistration, bool, error) {
	tenantID, id, name = strings.TrimSpace(tenantID), strings.TrimSpace(id), strings.TrimSpace(name)
	r.mu.Lock()
	defer r.mu.Unlock()
	conn, ok := r.connectors[id]
	if !ok {
		return model.ConnectorRegistration{}, false, nil
	}
	if tenantID != "" && conn.TenantID != tenantID {
		return model.ConnectorRegistration{}, false, fmt.Errorf("connector %s belongs to another tenant", id)
	}
	conn = SetDisplayName(conn, name)
	candidate := make(map[string]model.ConnectorRegistration, len(r.connectors))
	for key, value := range r.connectors {
		candidate[key] = value
	}
	candidate[id] = conn
	if err := r.saveManagementCandidateLocked(candidate); err != nil {
		return model.ConnectorRegistration{}, true, err
	}
	r.connectors = candidate
	return conn, true, nil
}

// RemoveForTenant deletes a connector from the registry (operator decommission). Tenant-scoped: refuses to remove
// a connector owned by another tenant. Returns ok=false if the connector is unknown. Bumps the catalog generation
// so the route table + any config-bundle distribution drop it fleet-wide.
func (r *Registry) RemoveForTenant(tenantID, id string) (bool, error) {
	tenantID, id = strings.TrimSpace(tenantID), strings.TrimSpace(id)
	if id == "" {
		return false, fmt.Errorf("connector id is required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	conn, ok := r.connectors[id]
	if !ok {
		return false, nil
	}
	if tenantID != "" && conn.TenantID != tenantID {
		return false, fmt.Errorf("connector %s belongs to another tenant", id)
	}
	candidate := make(map[string]model.ConnectorRegistration, len(r.connectors))
	for key, value := range r.connectors {
		if key != id {
			candidate[key] = value
		}
	}
	if err := r.saveManagementCandidateLocked(candidate); err != nil {
		return false, err
	}
	r.connectors = candidate
	r.catalogGen++
	return true, nil
}

// ErrRegistryPersistence distinguishes a management save failure from invalid input.
var ErrRegistryPersistence = errors.New("connector registry persistence failed")

// Management changes must be confirmed by storage before becoming visible in this
// process. Unlike registration/heartbeat continuity, a rename/removal can be retried.
// Save errors can be ambiguous on disk; callers must not report confirmed success.
// The caller holds r.mu, and the candidate must not mutate the resident metadata.
func (r *Registry) saveManagementCandidateLocked(candidate map[string]model.ConnectorRegistration) error {
	if r.persister == nil {
		return nil
	}
	data, err := json.Marshal(registryPersistSnapshot{Connectors: candidate})
	if err == nil {
		err = r.persister.Save(data)
	}
	if err != nil {
		reportRegistryPersistError(err)
		return fmt.Errorf("%w: %v", ErrRegistryPersistence, err)
	}
	return nil
}

// SetDisplayName sets (or clears, when name is empty) the operator display name on a registration.
//
// ★ ONE PLACE DECIDES WHAT A RENAME IS. The durable registry needs the same act, and a second copy of "which
// metadata key holds the name" is a rename that works on one store and not the other — which is exactly how
// the two stores came to disagree about whether a connector could be renamed at all.
func SetDisplayName(conn model.ConnectorRegistration, name string) model.ConnectorRegistration {
	name = strings.TrimSpace(name)
	metadata := make(map[string]any, len(conn.Metadata)+1)
	for key, value := range conn.Metadata {
		metadata[key] = value
	}
	conn.Metadata = metadata
	if name == "" {
		delete(conn.Metadata, connectorDisplayNameKey)
	} else {
		conn.Metadata[connectorDisplayNameKey] = name
	}
	return conn
}

// DisplayName returns the operator-set display name for a connector registration, or "" if none.
func DisplayName(conn model.ConnectorRegistration) string {
	if conn.Metadata == nil {
		return ""
	}
	if v, ok := conn.Metadata[connectorDisplayNameKey].(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

// RecordAttachedRegion notes WHERE this connector's tunnel is currently terminating, as observed by the Edge
// that terminated it. It reports whether anything changed.
//
// ★★★ THIS IS THE ONLY PARTY THAT KNOWS (2026-08-26). The region in a registration is what the connector
// DECLARED at enrolment. Give it more than one door and that stops being where it is: after a failover the
// registration names the region it left, every Edge routes there, the far side answers "no live tunnel", and
// everything behind the connector is unreachable while the connector is healthy one region away. The node
// holding the tunnel is the only one that can correct that, so it says so here.
//
// ★ IT IS RUNTIME STATE AND MUST NOT MOVE THE CATALOG VERSION. A connector that flaps between regions would
// otherwise move the deployment's aggregate config generation on every reconnect, and a generation that never
// settles closes every gate that waits for one. catalogGen is deliberately untouched — see
// connectorCatalogChanged, which does not compare this field either.
// RecordLiveness writes ONLY what a report may assert about a connector that is already registered: that it
// was heard from, and what it said its status was.
//
// ★★★ NOT THE WHOLE REGISTRATION (2026-09-01). A reporting Edge's copy is not the authority on the fields an
// operator authored — a name it has not seen would be overwritten by a stale report, which is what the guard
// beside the attachment path exists to prevent. But discarding the report entirely left the authority's
// last_heartbeat frozen at the moment of registration, so a site with two live connectors read "Down — 0 of 2
// connectors online" for as long as it ran. Two facts arrive in one message; the answer is to take the one the
// reporter owns and leave the one it does not.
func (r *Registry) RecordLiveness(id, status, heartbeatAt string) (bool, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return false, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	conn, ok := r.connectors[id]
	if !ok {
		return false, fmt.Errorf("connector %s is not registered", id)
	}
	changed := false
	if hb := strings.TrimSpace(heartbeatAt); hb != "" && hb != conn.LastHeartbeatAt {
		conn.LastHeartbeatAt = hb
		changed = true
	}
	if st := strings.TrimSpace(status); st != "" && st != conn.Status {
		conn.Status = st
		changed = true
	}
	if !changed {
		return false, nil
	}
	r.connectors[id] = conn
	r.persistLocked()
	return true, nil
}

func (r *Registry) RecordAttachedRegion(id, region string) (bool, error) {
	id, region = strings.TrimSpace(id), strings.TrimSpace(region)
	if id == "" || region == "" {
		return false, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	conn, ok := r.connectors[id]
	if !ok {
		return false, fmt.Errorf("connector %s is not registered", id)
	}
	if strings.EqualFold(conn.AttachedRegionID, region) {
		return false, nil
	}
	conn.AttachedRegionID = region
	r.connectors[id] = conn
	r.persistLocked()
	return true, nil
}
