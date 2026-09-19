package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/model"
)

type adminTenantModelRuntimeStore interface {
	Get(context.Context, string) (adminTenantModel, error)
	Update(context.Context, adminTenantModel, string, time.Time) (adminTenantModel, error)
}

// adminTenantModelAdminStore is the cross-tenant (super-admin) surface: list every tenant, create/upsert an
// arbitrary tenant id, and delete one. Self-scoped read/update stays on adminTenantModelRuntimeStore; these
// operations are gated on the super-admin permission (admin.tenant.admin) at the handler. Satisfied by
// *adminTenantModelStore.
type adminTenantModelAdminStore interface {
	adminTenantModelRuntimeStore
	List(context.Context) ([]adminTenantModel, error)
	Put(context.Context, adminTenantModel, time.Time) (adminTenantModel, error)
	Delete(context.Context, string) error
}

// adminTenantModelFleetCarrier is everything the tenant registry has to say to the REST OF THE FLEET: the
// registry's config version, the deletions it carries by name, and the standing erasure orders.
//
// ★ IT EXISTS BECAUSE THESE THREE WERE REACHED THROUGH TYPE ASSERTIONS AND THE POSTGRES BACKEND SATISFIED NONE
// OF THEM (2026-08-18). Each call site was written as `if x, ok := store.(interface{ ... }); ok`, which on the
// Postgres control plane — the backend the deployment documentation names for production — is simply false:
//
//   - ConfigGeneration: the tenant registry never advanced the bundle's aggregate generation, so creating,
//     renaming or deleting an organization published a bundle an Edge had no reason to apply.
//   - PurgeOrders: the bundle carried no erasure orders, ever.
//   - OrderPurge: ordering an erasure recorded nothing, then erased this node's copy and answered with a
//     result — the shape that is worse than an error, because the operator is told it worked.
//
// The assertion is what made all three silent, so the fix is a named contract with a compile-time assertion on
// both stores (see admin_tenant_model_postgres.go). A backend that cannot carry these can no longer be built.
type adminTenantModelFleetCarrier interface {
	ConfigGeneration() uint64
	DeletedTenants() []tenantDeletion
	OrderPurge(string, time.Time) error
	PurgeOrders() []tenantPurgeOrder
}

// tenantPurgeOrderStands verifies the recorded order after a confirmed save.
// Read-back alone cannot establish durability for an in-memory file-store view.
func tenantPurgeOrderStands(carrier adminTenantModelFleetCarrier, tenantID string) bool {
	tenantID = strings.TrimSpace(tenantID)
	for _, order := range carrier.PurgeOrders() {
		if strings.EqualFold(strings.TrimSpace(order.TenantID), tenantID) {
			return true
		}
	}
	return false
}

// tenantModelFleetCarrierWarning fires at most once per process: the condition is a property of how the node was
// built, so it does not change between polls, and the config bundle is fetched continuously.
var tenantModelFleetCarrierWarning sync.Once

// tenantModelFleetCarrier resolves the fleet-carrying contract from whatever tenant-model store this node was
// built with, and SAYS SO when it cannot. Both real stores satisfy it (asserted at compile time), so a failure
// here means a store was introduced that cannot tell the fleet about deletions or erasure orders — which is
// exactly the state the Postgres backend was silently in, and the caller cannot detect it any other way.
func tenantModelFleetCarrier(store any) (adminTenantModelFleetCarrier, bool) {
	carrier, ok := store.(adminTenantModelFleetCarrier)
	if !ok || carrier == nil {
		tenantModelFleetCarrierWarning.Do(func() {
			log.Printf("tenant registry: this node's tenant-model store (%T) carries no config generation, no deletions and no erasure orders, "+
				"so organizations deleted or ordered erased here will never reach any Edge", store)
		})
		return nil, false
	}
	return carrier, true
}

type adminTenantModel struct {
	TenantID      string `json:"tenant_id"`
	DisplayName   string `json:"display_name"`
	Region        string `json:"region"`
	DataResidency string `json:"data_residency"`
	// AllowedRegions is the residency boundary: the regions this tenant may occupy (multi-region). The
	// reach layer denies any connector whose edge_region is outside this set — residency beats availability. Empty
	// = unpinned (no restriction; ranges over all regions). HomeRegion is the anchor/tiebreak/failover default.
	AllowedRegions []string `json:"allowed_regions,omitempty"`
	HomeRegion     string   `json:"home_region,omitempty"`
	// Timezone is the IANA zone this tenant's operators read times in — log timestamps, retention boundaries,
	// scheduled reports. PER TENANT, not per system: a tenant's main region differs from the next tenant's, and
	// an MSSP running several of them cannot have one clock that suits all. Empty = UTC.
	//
	// Stored as an IANA name ("Asia/Tokyo") rather than an offset, because an offset is wrong twice a year
	// wherever daylight saving applies, and "the report covers yesterday" has to mean the operator's yesterday.
	// Timestamps themselves stay UTC everywhere; this governs PRESENTATION and day boundaries only — mixing
	// zones into stored values is how audit trails stop being comparable.
	Timezone            string `json:"timezone,omitempty"`
	Plan                string `json:"plan"`
	Status              string `json:"status"`
	PolicyBundleID      string `json:"policy_bundle_id"`
	PolicyBundleVersion string `json:"policy_bundle_version"`
	MetadataKeyCount    int    `json:"metadata_key_count"`
	// IsOperator marks the SSE operator's own tenant (the one running the multi-tenant control plane), set when
	// tenant_id matches -operator-tenant-id. It is a derived, read-only flag: the Console hides operator tenants
	// from the customer list and the API refuses to delete one (lockout protection). When -operator-tenant-id is
	// unset (the lab default) this is always false and nothing changes — pure additive contract.
	IsOperator bool `json:"is_operator"`
	// OperatorManaged is the organization's STANDING DELEGATION to the operator: inside a tenant that has set
	// it, an operator holding admin.tenant.admin does that tenant's ordinary work with that tenant's ordinary
	// write permissions (the envelope design, decided 2026-08-16). It is the Azure-Lighthouse shape — delegated once at
	// onboarding rather than justified per session — because the product being sold is that the operator does
	// the work, and a gate on every routine act is a gate on the product.
	//
	// ★ FALSE BY DEFAULT, AND THAT IS THE WHOLE POINT. A default of true would widen every organization that
	// already exists, silently, at the moment this field shipped. Absent means "this organization has not
	// delegated anything", which is exactly what was true before the field existed — so the change is
	// additive in behaviour, not only in schema.
	//
	// It does NOT reach the acts named in operatorElevatedActs: irreversible or fleet-wide work needs a
	// time-boxed elevation on top, so the standing delegation cannot be the credential that revokes an
	// authority or strands a fleet.
	OperatorManaged bool `json:"operator_managed,omitempty"`
	// OperatorDelegationChangedAt / By record the last write to OperatorManaged: when, and which principal.
	//
	// ★★ EITHER SIDE MAY WRITE THE DELEGATION, SO THE CUSTOMER HAS TO BE ABLE TO SEE IT MOVE (2026-08-17,
	// measured). The operator sets it at onboarding and the organization can withdraw it — "a delegation only
	// the holder can end is not a delegation". But the operator can equally set it BACK: measured live, an
	// operator turned standing delegation on for an organization that had not delegated, in one call. That is
	// deliberate and it is needed for onboarding, since a brand-new organization has no administrator to grant
	// it. What was not deliberate is that the organization's own "Operator access" screen lists ELEVATIONS
	// only, so a re-grant left no trace anywhere the customer looks.
	//
	// The audit log has always carried the event. A control the customer is told they hold, whose removal the
	// other party can undo without it appearing on the screen that presents the control, is a control in name.
	OperatorDelegationChangedAt *string `json:"operator_delegation_changed_at,omitempty"`
	OperatorDelegationChangedBy *string `json:"operator_delegation_changed_by,omitempty"`
	// OperatorDelegationWithdrawnByCustomer records that the LAST time this delegation went off, the
	// organization itself turned it off — not the operator.
	//
	// ★★★ THE HOLDER COULD REOPEN WHAT THE CUSTOMER CLOSED (decided 2026-08-20, by the operator, after it was
	// measured). Either side could write this field, deliberately: the operator sets it at onboarding, because
	// a brand-new organization has no administrator to grant anything and the customers this product is sold
	// to are the ones who cannot do it themselves. The cost of that shape was that an organization which
	// withdrew its delegation could have it turned back on by the party it had just withdrawn it from — and a
	// permission the holder can re-grant to itself is not a delegation, whatever the screen calls it.
	//
	// So the two directions are now different, which is the only asymmetry that makes this a delegation:
	//
	//   - the operator may set it at onboarding, and may turn it off and back on again themselves
	//   - once the CUSTOMER withdraws it, only the customer can grant it again
	//
	// Cleared when the delegation is granted again, so an organization that re-delegates is back to the
	// ordinary shape and nothing accumulates.
	OperatorDelegationWithdrawnByCustomer bool `json:"operator_delegation_withdrawn_by_customer,omitempty"`
	// OperatorElevationRequiresApproval lets an organization require its OWN admin to approve an elevation
	// before it becomes active. Default false, matching the delegated-management contract; the organizations
	// that want the stricter shape opt into it rather than everyone paying for it.
	OperatorElevationRequiresApproval bool `json:"operator_elevation_requires_approval,omitempty"`
	// OperatorElevations is the history of time-boxed elevations over this organization, newest last.
	//
	// ★ CARRIED HERE ON PURPOSE. An elevation decided on the node the operator happened to reach is the
	// per-Edge shape this repository has already paid for twice (authored rules, steer exclusions): the act
	// succeeds against one Edge and the next Edge in the same fleet refuses it, or worse, allows it after the
	// window closed. Living on the organization's own record means the control plane authors it and the same
	// channel that already carries tombstones and purge orders carries this — one write, every node.
	OperatorElevations []operatorElevation `json:"operator_elevations,omitempty"`
	CreatedAt          *string             `json:"created_at"`
	UpdatedAt          *string             `json:"updated_at"`
}

// stampOperatorFlag derives IsOperator from operatorTenantID (the single source of truth). Called on every read
// path so the flag is correct regardless of any persisted value, and the persisted/stored bool is only a cache.
func stampOperatorFlag(tenant adminTenantModel, operatorTenantID string) adminTenantModel {
	tenant = cloneAdminTenantModel(tenant)
	tenant.IsOperator = operatorTenantID != "" && tenant.TenantID == operatorTenantID
	return tenant
}

// Returned models can be edited by callers without changing authorization state.
func cloneAdminTenantModel(tenant adminTenantModel) adminTenantModel {
	tenant.AllowedRegions = append([]string(nil), tenant.AllowedRegions...)
	tenant.CreatedAt = copyStringPtr(tenant.CreatedAt)
	tenant.UpdatedAt = copyStringPtr(tenant.UpdatedAt)
	tenant.OperatorElevations = append([]operatorElevation(nil), tenant.OperatorElevations...)
	for i := range tenant.OperatorElevations {
		e := &tenant.OperatorElevations[i]
		e.EndedAt = copyStringPtr(e.EndedAt)
		e.EndedBy = copyStringPtr(e.EndedBy)
		e.ApprovedAt = copyStringPtr(e.ApprovedAt)
		e.ApprovedBy = copyStringPtr(e.ApprovedBy)
	}
	return tenant
}

type adminTenantModelStore struct {
	mu sync.RWMutex
	// generation is the monotonic config version of the TENANT REGISTRY.
	//
	// ★ WITHOUT IT, A NEW ORGANIZATION NEVER REACHED AN EDGE (2026-08-15). The config bundle carries the
	// tenant registry, and an Edge re-applies a bundle only when its generation is newer than the one it last
	// applied. That generation is the SUM of every distributed store's counter — and this store had no
	// counter, so it contributed nothing. Creating an organization changed the bundle's contents and not its
	// version, and the Edge, comparing versions, saw nothing to do.
	//
	// Measured on the lab: an organization created on the control plane was still absent from the Edge a
	// minute later, while a DIFFERENT one created earlier was present — because a rebuild had restarted that
	// Edge in between, and a restart pulls unconditionally. So it arrived by coincidence, not by mechanism.
	// The comment on the sum said it "advances on ANY distributed-config change"; that was the intent and
	// this store was missing from it.
	generation atomic.Uint64
	tenants    map[string]adminTenantModel
	// path is an optional durable snapshot file (JSON). "" = in-memory only. When set, the store loads from it
	// on construction and atomically rewrites it after every mutation, so tenant profiles survive a restart —
	// the same file-backed durability the edge uses for its other admin stores. A Postgres backend can later be
	// dropped in behind adminTenantModelAdminStore without touching the handlers.
	path string
	// operatorTenantID, when non-empty, names the SSE operator's own tenant (-operator-tenant-id). Tenants whose
	// id matches it are stamped IsOperator on read and the operator tenant is seeded if absent. "" = feature off
	// (lab default): no operator tenant, IsOperator always false.
	operatorTenantID string
	// deleted records tenants this node has DELETED, keyed by tenant id, valued by the RFC3339 instant.
	//
	// ★ WHY A TOMBSTONE AND NOT "WHATEVER IS MISSING" (2026-08-15). The bundle's tenant section UPSERTs, and
	// deliberately so: an empty or truncated payload must never read as "delete everything", because absence
	// is what a control plane that is not the authority also looks like. The consequence measured on the lab
	// was that deletion did not propagate at all — the control plane listed 2 tenants and the Edge listed 5,
	// and the three ghosts could only be removed by editing the Edge's file by hand.
	//
	// So the deletion is CARRIED rather than inferred: the Edge removes a tenant because it was told to, by
	// name, with a timestamp. Absence still means nothing. This is also why a delete is recorded even when
	// the row is already gone locally — that is exactly the ghost case, where the control plane no longer has
	// the tenant but an Edge still does, and an operator needs a way to say so.
	deleted map[string]string
	// purgeOrders records tenants an operator has ordered ERASED, keyed by tenant id, valued by the instant.
	//
	// Separate from `deleted` on purpose. A deletion is routine and says "this organization is no longer a
	// customer"; a purge order is irreversible and says "erase everything you hold for it". Every node that
	// ever served the tenant has its own copy of that tenant's logs, so the order has to travel — and, like
	// the deletion, it travels by NAME. The order stays forever rather than being cleared once applied: an
	// Edge that was offline for a month must still be told when it comes back, and an order nobody can see
	// any more is how a node keeps data that was supposed to be gone.
	purgeOrders map[string]string
}

type adminTenantModelSnapshot struct {
	Tenants map[string]adminTenantModel `json:"tenants"`
	// Deleted must persist: a tombstone that vanishes on restart resurrects the tenant on the next bundle,
	// because the Edge would stop being told about a deletion it had not yet applied.
	Deleted map[string]string `json:"deleted,omitempty"`
	// PurgeOrders must persist for the same reason, more sharply: a node that has not yet erased a tenant is
	// only ever told by this list.
	PurgeOrders map[string]string `json:"purge_orders,omitempty"`
}

func newAdminTenantModelStore(bundle model.PolicyBundle, now time.Time) *adminTenantModelStore {
	return newDurableAdminTenantModelStore(bundle, now, "")
}

// newDurableAdminTenantModelStore builds the store, loading from the durable snapshot at path when it exists
// (and is non-empty), otherwise seeding the bundle tenant. A non-empty path makes the store restart-resilient.
func newDurableAdminTenantModelStore(bundle model.PolicyBundle, now time.Time, path string) *adminTenantModelStore {
	return newOperatorAwareAdminTenantModelStore(bundle, now, path, "")
}

// newOperatorAwareAdminTenantModelStore is newDurableAdminTenantModelStore plus the operator-tenant feature
// (-operator-tenant-id). operatorTenantID == "" reproduces the legacy behavior exactly (lab default): load or
// seed the bundle tenant, no operator tenant, IsOperator always false. A non-empty operatorTenantID additionally
// seeds the operator tenant (display name "Operator", status active) when absent and stamps IsOperator on reads.
func newOperatorAwareAdminTenantModelStore(bundle model.PolicyBundle, now time.Time, path, operatorTenantID string) *adminTenantModelStore {
	store := &adminTenantModelStore{
		tenants:          map[string]adminTenantModel{},
		deleted:          map[string]string{},
		purgeOrders:      map[string]string{},
		path:             strings.TrimSpace(path),
		operatorTenantID: strings.TrimSpace(operatorTenantID),
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	loaded := false
	if store.path != "" {
		if snapshot, tombstones, orders, ok := loadAdminTenantModelSnapshot(store.path); ok {
			store.tenants = snapshot
			if tombstones != nil {
				store.deleted = tombstones
			}
			if orders != nil {
				store.purgeOrders = orders
			}
			loaded = true
		}
	}
	dirty := false
	if !loaded {
		if tenantID := strings.TrimSpace(bundle.TenantID); tenantID != "" {
			timestamp := now.UTC().Format(time.RFC3339)
			tenant := adminTenantModel{
				TenantID:            tenantID,
				DisplayName:         tenantID,
				Status:              "active",
				PolicyBundleID:      strings.TrimSpace(bundle.ID),
				PolicyBundleVersion: strings.TrimSpace(bundle.Version),
				MetadataKeyCount:    len(bundle.Metadata),
				CreatedAt:           &timestamp,
				UpdatedAt:           &timestamp,
			}
			if normalized, err := normalizeAdminTenantModel(tenant, tenantID, now); err == nil {
				store.tenants[tenantID] = normalized
				dirty = true
			}
		}
	}
	if store.seedOperatorTenantLocked(now) {
		dirty = true
	}
	if dirty {
		store.persistLocked()
	}
	return store
}

// seedOperatorTenantLocked inserts the operator tenant (display name "Operator", status active, IsOperator) when
// -operator-tenant-id is set and the tenant is absent. Returns true when it mutated the map. No-op (returns false)
// when the feature is off or the operator tenant already exists. The caller need not hold the lock during
// construction; Update/Put paths that call it hold store.mu.
func (store *adminTenantModelStore) seedOperatorTenantLocked(now time.Time) bool {
	if store.operatorTenantID == "" {
		return false
	}
	if _, ok := store.tenants[store.operatorTenantID]; ok {
		return false
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	seed := adminTenantModel{TenantID: store.operatorTenantID, DisplayName: "Operator", Status: "active", IsOperator: true}
	normalized, err := normalizeAdminTenantModel(seed, store.operatorTenantID, now)
	if err != nil {
		return false
	}
	normalized.IsOperator = true
	store.tenants[store.operatorTenantID] = normalized
	return true
}

// loadAdminTenantModelSnapshot reads a durable snapshot; returns ok=false when the file is missing/empty/invalid
// so the caller falls back to bundle seeding (never silently starts with a corrupt set).
func loadAdminTenantModelSnapshot(path string) (map[string]adminTenantModel, map[string]string, map[string]string, bool) {
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 {
		return nil, nil, nil, false
	}
	var snapshot adminTenantModelSnapshot
	if err := json.Unmarshal(data, &snapshot); err != nil || snapshot.Tenants == nil {
		return nil, nil, nil, false
	}
	return snapshot.Tenants, snapshot.Deleted, snapshot.PurgeOrders, true
}

// persistLocked atomically rewrites the durable snapshot. The caller must hold store.mu. A no-op when path is "".
func (store *adminTenantModelStore) persistLocked() {
	if store.path == "" {
		return
	}
	data, err := json.MarshalIndent(adminTenantModelSnapshot{Tenants: store.tenants, Deleted: store.deleted, PurgeOrders: store.purgeOrders}, "", "  ")
	if err != nil {
		return
	}
	tmp := store.path + ".tmp"
	if err := os.MkdirAll(filepath.Dir(store.path), 0o750); err != nil {
		return
	}
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return
	}
	_ = os.Rename(tmp, store.path)
}

// ConfigGeneration returns the monotonic tenant-registry version. It feeds the config bundle's aggregate
// generation, which is how an Edge decides a bundle is worth applying.
func (store *adminTenantModelStore) ConfigGeneration() uint64 { return store.generation.Load() }

// OrderPurge records that an operator has ordered this tenant ERASED, so the order can be carried to every
// node that ever held its data. Idempotent: ordering twice keeps the first instant, because the order is not a
// new fact the second time and a moving timestamp would make the audit harder to read, not easier.
func (store *adminTenantModelStore) OrderPurge(tenantID string, now time.Time) error {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return fmt.Errorf("tenant_id is required")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, already := store.purgeOrders[tenantID]; already {
		return nil
	}
	orders := make(map[string]string, len(store.purgeOrders)+1)
	for id, at := range store.purgeOrders {
		orders[id] = at
	}
	orders[tenantID] = now.UTC().Format(time.RFC3339)
	if err := store.saveCandidateLocked(adminTenantModelSnapshot{Tenants: store.tenants, Deleted: store.deleted, PurgeOrders: orders}); err != nil {
		return err
	}
	store.purgeOrders = orders
	store.generation.Add(1)
	return nil
}

// PurgeOrders returns the standing erasure orders. They are never cleared: an Edge that was offline when the
// order was given is only ever told by this list, and an order that disappears once "most" nodes have acted is
// how one node quietly keeps a customer's data.
func (store *adminTenantModelStore) PurgeOrders() []tenantPurgeOrder {
	store.mu.RLock()
	defer store.mu.RUnlock()
	out := make([]tenantPurgeOrder, 0, len(store.purgeOrders))
	for tenantID, at := range store.purgeOrders {
		out = append(out, tenantPurgeOrder{TenantID: tenantID, OrderedAt: at})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TenantID < out[j].TenantID })
	return out
}

// DeletedTenants returns the tombstones — the tenants this node has deleted, by name, with when. The config
// bundle carries these so a receiving Edge deletes because it was TOLD to; see the field comment for why the
// alternative (delete anything the payload omits) is not available to us.
func (store *adminTenantModelStore) DeletedTenants() []tenantDeletion {
	store.mu.RLock()
	defer store.mu.RUnlock()
	out := make([]tenantDeletion, 0, len(store.deleted))
	for tenantID, at := range store.deleted {
		out = append(out, tenantDeletion{TenantID: tenantID, DeletedAt: at})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TenantID < out[j].TenantID })
	return out
}

func (store *adminTenantModelStore) Get(_ context.Context, tenantID string) (adminTenantModel, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return adminTenantModel{}, fmt.Errorf("tenant_id is required")
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	tenant, ok := store.tenants[tenantID]
	if !ok {
		now := time.Now().UTC()
		normalized, err := normalizeAdminTenantModel(adminTenantModel{TenantID: tenantID, DisplayName: tenantID, Status: "active"}, tenantID, now)
		if err != nil {
			return adminTenantModel{}, err
		}
		return stampOperatorFlag(normalized, store.operatorTenantID), nil
	}
	return stampOperatorFlag(tenant, store.operatorTenantID), nil
}

var errAdminTenantSaveUnconfirmed = errors.New("tenant save could not be confirmed")

// Authoring must not publish a candidate or retire its tombstone until storage
// confirms the save. Memory-only stores retain their existing behavior.
func (store *adminTenantModelStore) commitAuthoredTenantLocked(tenant adminTenantModel) error {
	tenant = cloneAdminTenantModel(tenant)
	tenants := make(map[string]adminTenantModel, len(store.tenants)+1)
	for id, row := range store.tenants {
		tenants[id] = row
	}
	tenants[tenant.TenantID] = tenant
	deleted := make(map[string]string, len(store.deleted))
	for id, at := range store.deleted {
		if id != tenant.TenantID {
			deleted[id] = at
		}
	}
	if err := store.saveCandidateLocked(adminTenantModelSnapshot{Tenants: tenants, Deleted: deleted, PurgeOrders: store.purgeOrders}); err != nil {
		return err
	}
	store.tenants = tenants
	store.deleted = deleted
	store.generation.Add(1)
	return nil
}

// saveCandidateLocked confirms storage before publishing a tenant-registry mutation.
// An error can follow replacement; it does not imply the disk still holds the old snapshot.
func (store *adminTenantModelStore) saveCandidateLocked(snapshot adminTenantModelSnapshot) error {
	if store.path != "" {
		raw, err := json.MarshalIndent(snapshot, "", "  ")
		if err != nil {
			return fmt.Errorf("%w: %v", errAdminTenantSaveUnconfirmed, err)
		}
		err = (blobstore.FilePersister{Path: store.path}).Save(raw)
		if err != nil && !(errors.Is(err, blobstore.ErrSavedWithoutAtomicity) && !errors.Is(err, blobstore.ErrDurabilityUnconfirmed)) {
			return fmt.Errorf("%w: %v", errAdminTenantSaveUnconfirmed, err)
		}
	}
	return nil
}

func writeAdminTenantSaveError(w http.ResponseWriter, fallback int, err error) {
	if errors.Is(err, errAdminTenantSaveUnconfirmed) {
		writeError(w, http.StatusServiceUnavailable, errors.New("The tenant change could not be confirmed in storage. Reload before retrying."))
		return
	}
	writeError(w, fallback, err)
}

func (store *adminTenantModelStore) Update(_ context.Context, tenant adminTenantModel, tenantID string, now time.Time) (adminTenantModel, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if existing, ok := store.tenants[strings.TrimSpace(tenantID)]; ok && tenant.CreatedAt == nil {
		tenant.CreatedAt = copyStringPtr(existing.CreatedAt)
	}
	normalized, err := normalizeAdminTenantModel(tenant, tenantID, now)
	if err != nil {
		return adminTenantModel{}, err
	}
	if err := store.commitAuthoredTenantLocked(normalized); err != nil {
		return adminTenantModel{}, err
	}
	return stampOperatorFlag(normalized, store.operatorTenantID), nil
}

// List returns every tenant profile, sorted by tenant_id (cross-tenant / super-admin surface).
func (store *adminTenantModelStore) List(_ context.Context) ([]adminTenantModel, error) {
	store.mu.RLock()
	defer store.mu.RUnlock()
	out := make([]adminTenantModel, 0, len(store.tenants))
	for _, tenant := range store.tenants {
		out = append(out, stampOperatorFlag(tenant, store.operatorTenantID))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TenantID < out[j].TenantID })
	return out, nil
}

// Put creates or upserts a tenant by its OWN tenant_id (cross-tenant / super-admin surface). Unlike Update it
// does not bind to the authenticated tenant — the caller must hold the super-admin permission. CreatedAt is
// preserved on an existing tenant so a super-admin edit never rewrites provenance.
func (store *adminTenantModelStore) Put(_ context.Context, tenant adminTenantModel, now time.Time) (adminTenantModel, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	tenantID := strings.TrimSpace(tenant.TenantID)
	if tenantID == "" {
		return adminTenantModel{}, fmt.Errorf("tenant_id is required")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if existing, ok := store.tenants[tenantID]; ok && tenant.CreatedAt == nil {
		tenant.CreatedAt = copyStringPtr(existing.CreatedAt)
	}
	normalized, err := normalizeAdminTenantModel(tenant, tenantID, now)
	if err != nil {
		return adminTenantModel{}, err
	}
	if err := store.commitAuthoredTenantLocked(normalized); err != nil {
		return adminTenantModel{}, err
	}
	return stampOperatorFlag(normalized, store.operatorTenantID), nil
}

// Delete removes a tenant profile (cross-tenant / super-admin surface). Removing a non-existent tenant is a
// no-op success (idempotent).
func (store *adminTenantModelStore) Delete(_ context.Context, tenantID string) error {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return fmt.Errorf("tenant_id is required")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	_, present := store.tenants[tenantID]
	if _, tombstoned := store.deleted[tenantID]; !present && tombstoned {
		return nil
	}
	tenants := make(map[string]adminTenantModel, len(store.tenants))
	for id, row := range store.tenants {
		if id != tenantID {
			tenants[id] = row
		}
	}
	deleted := make(map[string]string, len(store.deleted)+1)
	for id, at := range store.deleted {
		deleted[id] = at
	}
	// Carry an explicit tombstone even when the local row was already absent.
	deleted[tenantID] = time.Now().UTC().Format(time.RFC3339)
	if err := store.saveCandidateLocked(adminTenantModelSnapshot{Tenants: tenants, Deleted: deleted, PurgeOrders: store.purgeOrders}); err != nil {
		return err
	}
	store.tenants = tenants
	store.deleted = deleted
	store.generation.Add(1)
	return nil
}

func normalizeAdminTenantModel(tenant adminTenantModel, tenantID string, now time.Time) (adminTenantModel, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return adminTenantModel{}, fmt.Errorf("tenant_id is required")
	}
	tenant.TenantID = strings.TrimSpace(tenant.TenantID)
	if tenant.TenantID == "" {
		tenant.TenantID = tenantID
	}
	if tenant.TenantID != tenantID {
		return adminTenantModel{}, fmt.Errorf("tenant_id %s does not match authenticated tenant_id %s", tenant.TenantID, tenantID)
	}
	if !safeAdminTenantToken(tenant.TenantID) {
		return adminTenantModel{}, fmt.Errorf("tenant_id is invalid")
	}
	tenant.DisplayName = strings.TrimSpace(tenant.DisplayName)
	if tenant.DisplayName == "" {
		tenant.DisplayName = tenant.TenantID
	}
	if !safeAdminTenantDisplayText(tenant.DisplayName) {
		return adminTenantModel{}, fmt.Errorf("display_name is invalid")
	}
	if err := normalizeAdminTenantOptionalToken(&tenant.Region, "region"); err != nil {
		return adminTenantModel{}, err
	}
	if err := normalizeAdminTenantOptionalToken(&tenant.DataResidency, "data_residency"); err != nil {
		return adminTenantModel{}, err
	}
	if err := normalizeAdminTenantOptionalToken(&tenant.HomeRegion, "home_region"); err != nil {
		return adminTenantModel{}, err
	}
	if err := normalizeAdminTenantTimezone(&tenant.Timezone); err != nil {
		return adminTenantModel{}, err
	}
	cleanedRegions := make([]string, 0, len(tenant.AllowedRegions))
	for _, region := range tenant.AllowedRegions {
		region = strings.TrimSpace(region)
		if region == "" {
			continue
		}
		if !safeAdminTenantToken(region) {
			return adminTenantModel{}, fmt.Errorf("allowed_regions entry %q is invalid", region)
		}
		cleanedRegions = append(cleanedRegions, region)
	}
	tenant.AllowedRegions = cleanedRegions
	if err := normalizeAdminTenantOptionalToken(&tenant.Plan, "plan"); err != nil {
		return adminTenantModel{}, err
	}
	tenant.Status = strings.TrimSpace(tenant.Status)
	if tenant.Status == "" {
		tenant.Status = "active"
	}
	if !validAdminTenantStatus(tenant.Status) {
		return adminTenantModel{}, fmt.Errorf("tenant status %s is invalid", tenant.Status)
	}
	if err := normalizeAdminTenantOptionalToken(&tenant.PolicyBundleID, "policy_bundle_id"); err != nil {
		return adminTenantModel{}, err
	}
	if err := normalizeAdminTenantOptionalToken(&tenant.PolicyBundleVersion, "policy_bundle_version"); err != nil {
		return adminTenantModel{}, err
	}
	if tenant.MetadataKeyCount < 0 {
		return adminTenantModel{}, fmt.Errorf("metadata_key_count must be non-negative")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if tenant.CreatedAt != nil {
		if err := normalizeAdminRFC3339StringPtr(&tenant.CreatedAt, "created_at"); err != nil {
			return adminTenantModel{}, err
		}
	}
	if tenant.CreatedAt == nil {
		createdAt := now.UTC().Format(time.RFC3339)
		tenant.CreatedAt = &createdAt
	}
	updatedAt := now.UTC().Format(time.RFC3339)
	tenant.UpdatedAt = &updatedAt
	return tenant, nil
}

// normalizeAdminTenantTimezone checks the zone EXISTS rather than merely looking plausible.
//
// A character-class check would accept "Asia/Tokyoo", and the mistake would only surface later as reports
// covering the wrong day. time.LoadLocation consults the actual IANA database, so a typo is refused at the
// point the operator can still see what they typed.
//
// The tenant token validator cannot be reused here: it forbids "/", which every IANA zone contains.
func normalizeAdminTenantTimezone(value *string) error {
	*value = strings.TrimSpace(*value)
	if *value == "" {
		return nil // empty means UTC; see adminTenantModel.Timezone
	}
	if _, err := time.LoadLocation(*value); err != nil {
		return fmt.Errorf("timezone %q is not a known IANA zone (e.g. Asia/Tokyo, Europe/Berlin, UTC)", *value)
	}
	return nil
}

// tenantLocation resolves a tenant's zone for PRESENTATION. Falls back to UTC rather than to the host's local
// zone: the host is wherever the Edge happens to run, which for an MSSP is not any tenant's region, and
// silently adopting it would make the same log read differently depending on which node served it.
func tenantLocation(tenant adminTenantModel) *time.Location {
	name := strings.TrimSpace(tenant.Timezone)
	if name == "" {
		return time.UTC
	}
	loc, err := time.LoadLocation(name)
	if err != nil {
		return time.UTC
	}
	return loc
}

func normalizeAdminTenantOptionalToken(value *string, field string) error {
	*value = strings.TrimSpace(*value)
	if *value == "" {
		return nil
	}
	if !safeAdminTenantToken(*value) {
		return fmt.Errorf("%s is invalid", field)
	}
	return nil
}

func safeAdminTenantToken(value string) bool {
	if value == "" {
		return false
	}
	for _, ch := range value {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '_' || ch == '-' || ch == '.' || ch == ':' {
			continue
		}
		return false
	}
	return true
}

func safeAdminTenantDisplayText(value string) bool {
	if value == "" {
		return false
	}
	for _, ch := range value {
		if ch == '/' || ch < 0x20 || ch == 0x7f {
			return false
		}
	}
	return true
}

func validAdminTenantStatus(status string) bool {
	switch status {
	case "active", "suspended", "archived":
		return true
	default:
		return false
	}
}

// adminTenantModelLifecycleAuditLog records a cross-tenant (super-admin) lifecycle action (create/update/delete)
// with the same non-secret metadata boundary as the self-scoped update audit (no source IP / actor / raw values).
func adminTenantModelLifecycleAuditLog(tenant adminTenantModel, action string, evaluator decision.Evaluator, now time.Time) model.AuditLog {
	log := adminTenantModelAuditLog(tenant, evaluator, now)
	actionCopy := action
	log.Action = &actionCopy
	// created / updated / deleted / purged — the past tense of the action.
	//
	// ★★ IT APPENDED "d" UNCONDITIONALLY (2026-08-17, read off a customer's own audit screen). Every act on
	// the operator envelope passes an action that is ALREADY past tense — operator_elevation_granted,
	// operator_elevation_ended, operator_elevation_approved, operator_delegation_changed — so all four became
	// "…grantedd", "…endedd", "…approvedd", "…changedd". Those are the governance events: the rows a customer
	// reads to know what the operator did in their organization. An event type is the stable key everything
	// downstream matches on — a label map, an export, a retention rule — so a misspelt one is a row nothing
	// can classify, which is exactly how it reached the screen as raw English prose.
	eventType := "admin_tenant_model_" + action
	if !strings.HasSuffix(action, "d") {
		eventType += "d"
	}
	log.EventType = eventType
	reason := "Tenant model " + action + " by super-admin."
	log.Reason = &reason
	if log.Metadata != nil {
		log.Metadata["reason_codes"] = []string{"admin_tenant_model_" + action}
		log.Metadata["cross_tenant_admin"] = true
	}
	return log
}

func adminTenantModelAuditLog(tenant adminTenantModel, evaluator decision.Evaluator, now time.Time) model.AuditLog {
	action := "update"
	result := "success"
	reason := "Tenant model admin metadata updated."
	targetType := "admin_tenant_model"
	return model.AuditLog{
		ID:             randomEdgeID("audit_", now),
		TenantID:       tenant.TenantID,
		EventType:      "admin_tenant_model_updated",
		TargetType:     &targetType,
		TargetID:       &tenant.TenantID,
		Action:         &action,
		Result:         &result,
		Reason:         &reason,
		PolicyBundleID: &evaluator.PolicyBundle.ID,
		EdgeRegionID:   &evaluator.EdgeRegionID,
		EdgeClusterID:  &evaluator.EdgeClusterID,
		Timestamp:      now.UTC().Format(time.RFC3339),
		Metadata: map[string]any{
			"status":                         tenant.Status,
			"display_name_present":           tenant.DisplayName != "",
			"region_present":                 tenant.Region != "",
			"data_residency_present":         tenant.DataResidency != "",
			"plan_present":                   tenant.Plan != "",
			"policy_bundle_id_present":       tenant.PolicyBundleID != "",
			"policy_bundle_version_present":  tenant.PolicyBundleVersion != "",
			"metadata_key_count":             tenant.MetadataKeyCount,
			"tenant_metadata_recorded_scope": "none",
			"runtime_hot_reload":             false,
			"reason_codes":                   []string{"admin_tenant_model_update"},
		},
	}
}

// tenantModelAdminStoreOrNil narrows a tenant store to the cross-tenant surface, or nil when it does not have
// one. Returning nil rather than a stub matters: the bundle-apply path treats nil as "this node has no tenant
// store to update" and skips, where a stub would silently swallow every update the control plane distributed.
func tenantModelAdminStoreOrNil(store adminTenantModelRuntimeStore) adminTenantModelAdminStore {
	if adminStore, ok := store.(adminTenantModelAdminStore); ok {
		return adminStore
	}
	return nil
}

// adminTenantTimezone resolves the IANA zone name to advertise for a tenant.
//
// Returns "UTC" — never "" — when the tenant has none, is unknown, or the store cannot be read. A caller that
// receives an empty string has to invent a default, and the one it would reach for is the BROWSER's zone,
// which is the operator's own location rather than the tenant's region. For an MSSP those are routinely
// different, and the resulting report would silently cover the wrong day.
func adminTenantTimezone(ctx context.Context, store adminTenantModelRuntimeStore, tenantID string) string {
	if store == nil || strings.TrimSpace(tenantID) == "" {
		return "UTC"
	}
	tenant, err := store.Get(ctx, tenantID)
	if err != nil {
		return "UTC"
	}
	if zone := strings.TrimSpace(tenant.Timezone); zone != "" {
		return zone
	}
	return "UTC"
}

// adminTenantModelLifecycleAuditLogFor is adminTenantModelLifecycleAuditLog with the ACTING ADMINISTRATOR
// recorded on it.
//
// ★ MEASURED (2026-08-15). Creating an organization produced an audit record with actor_user_id: null. Not
// only for the shared break-glass token — the same hole for a proper human super_admin signed in with a
// password and TOTP, because the builder never saw the request and so could not know who was asking. The
// whole point of giving the operator a real account is that "who created this organization" has an answer,
// and it did not.
func adminTenantModelLifecycleAuditLogFor(r *http.Request, tenant adminTenantModel, action string, evaluator decision.Evaluator, now time.Time) model.AuditLog {
	record := adminTenantModelLifecycleAuditLog(tenant, action, evaluator, now)
	return stampAdminTenantModelAuditActor(record, r, tenant)
}

func adminTenantModelAuditLogFor(r *http.Request, tenant adminTenantModel, evaluator decision.Evaluator, now time.Time) model.AuditLog {
	return stampAdminTenantModelAuditActor(adminTenantModelAuditLog(tenant, evaluator, now), r, tenant)
}

func stampAdminTenantModelAuditActor(record model.AuditLog, r *http.Request, tenant adminTenantModel) model.AuditLog {
	if identity, ok := adminIdentityFromRequest(r); ok {
		// The actor goes in METADATA, not ActorUserID. The cross-tenant audit contract (CP0020) keeps raw
		// class-2 identifiers — a person's user id, a raw subject, a session id — out of the control-plane
		// audit stream, and TestAdminTenantsSuperAdminListCreateDelete enforces that on this emitter. An admin
		// principal id is a synthetic id rather than one of those, but the place to put it is the field that
		// already carries the operator context, not the one the contract reserves.
		if record.Metadata != nil {
			record.Metadata["actor_admin_principal_id"] = strings.TrimSpace(identity.PrincipalID)
			record.Metadata["actor_auth_method"] = identity.AuthMethod
			// WHICH tenant the actor was operating from, distinct from the tenant being acted ON. An operator
			// administering a customer is the normal case and has to be readable as such.
			record.Metadata["actor_tenant_id"] = identity.TenantID
			if label := strings.TrimSpace(identity.PrincipalLabel); label != "" {
				record.Metadata["actor_label"] = label
			}
			// ★ AND WHEN THAT ACTOR IS THE OPERATOR, SAY SO IN THE WORDS THE SCREEN ALREADY READS (2026-08-17,
			// read in a probe organization's own audit trail). The actor was recorded here and NOWHERE the
			// console looks: with ActorUserID deliberately empty and only actor_* metadata set, the customer's
			// audit screen fell through to its no-actor case and rendered "the organization was created by
			// System". A named operator created it. The record is not what was missing — the shared vocabulary
			// was, and adminOperateWithinTenantAuditLog had already established it, so this emitter uses those
			// keys instead of adding a fourth name for one thing.
			if operating := strings.TrimSpace(identity.TenantID); operating != "" &&
				!strings.EqualFold(operating, strings.TrimSpace(tenant.TenantID)) {
				stampOperatorActor(record.Metadata, identity)
			}
		}
	}
	return record
}

// adminTenantExists says whether this deployment's registry holds the named organization.
//
// ★ IT IS ASKED BEFORE AN ORGANIZATION IS DESCRIBED FROM A HEADER. The model store answers Get for an
// unknown id by synthesising a record — correct for the caller's own organization on a deployment that has
// written no row for it yet, and wrong for one somebody merely named. A node that cannot list (an Edge that
// takes the registry from a bundle) returns an error, and the caller is expected to let the request through
// rather than refuse on a question it could not ask.
func adminTenantExists(ctx context.Context, store adminTenantModelRuntimeStore, tenantID string) (bool, error) {
	lister, ok := store.(adminTenantModelAdminStore)
	if !ok {
		return false, fmt.Errorf("this node does not hold the registry")
	}
	tenants, err := lister.List(ctx)
	if err != nil {
		return false, err
	}
	want := strings.TrimSpace(tenantID)
	for _, t := range tenants {
		if strings.EqualFold(strings.TrimSpace(t.TenantID), want) {
			return true, nil
		}
	}
	return false, nil
}
