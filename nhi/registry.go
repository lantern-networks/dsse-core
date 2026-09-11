package nhi

import (
	"context"
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

type Store struct {
	mu         sync.RWMutex
	identities map[string]model.NonHumanIdentity
	generation uint64 // monotonic config version (bumped on each Upsert); folded into the config-bundle generation
	// persister, when set, makes the registry DURABLE. It was in-memory only, so a routine Edge restart wiped the
	// whole NHI registry: every registered non-human identity vanished, and any decision that validates against
	// the registry then behaves as if the NHI was never registered. Nothing recovers it except re-authoring every
	// NHI by hand. Nil = in-memory only, unchanged from before.
	persister blobstore.Persister
}

// registryPersistSnapshot is the on-disk shape. Only the identities are persisted: generation is a process-local
// change counter for config distribution, not registry state, and restarting it at 0 is correct.
type registryPersistSnapshot struct {
	Identities map[string]model.NonHumanIdentity `json:"identities"`
}

// OnPersistError, when set, is called if a snapshot fails to save. A dropped save is invisible and expensive: the
// Upsert returns success, the Console shows the NHI, and the next Edge restart forgets it. That is the outage this
// persistence prevents, silently recreated while looking healthy. Must not panic.
//
// It does NOT fail the mutation: the in-memory registry is already serving the identity, and rejecting an
// operator's change because the disk is unhappy is the worse failure.
var OnPersistError func(error)

// SetPersister enables durable persistence so registered non-human identities survive an Edge restart. It loads
// any prior snapshot immediately, then every mutation re-saves the full set. Nil disables persistence.
//
// FAIL-CLOSED: a Load or Unmarshal failure is returned so a store that exists but cannot be read never silently
// starts as an empty registry. Empty/nil load (first boot) is fine.
func (store *Store) SetPersister(p blobstore.Persister) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.persister = p
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
	if snap.Identities != nil {
		store.identities = snap.Identities
	}
	return nil
}

// persistLocked writes the full snapshot. The CALLER must hold store.mu. No-op without a persister. A save error
// is surfaced via OnPersistError but does NOT fail the mutation.
func (store *Store) persistLocked() {
	if store.persister == nil {
		return
	}
	data, err := json.Marshal(registryPersistSnapshot{Identities: store.identities})
	if err != nil {
		reportPersistError(fmt.Errorf("marshal NHI registry snapshot: %w", err))
		return
	}
	if err := store.persister.Save(data); err != nil {
		reportPersistError(fmt.Errorf("save NHI registry snapshot: %w", err))
	}
}

func reportPersistError(err error) {
	if OnPersistError != nil {
		OnPersistError(err)
	}
}

type RuntimeStore interface {
	Upsert(context.Context, model.NonHumanIdentity, string, time.Time) (model.NonHumanIdentity, error)
	List(context.Context, string) ([]model.NonHumanIdentity, error)
	CountActive(context.Context, string, time.Time) (int, error)
	MarkUsed(context.Context, string, string, time.Time) (bool, error)
	// ConfigGeneration is the monotonic registry config version, folded into the config-bundle generation so
	// a registry change triggers a fleet-wide re-pull.
	ConfigGeneration() uint64
}

type ListResponse struct {
	TenantID           string                   `json:"tenant_id"`
	Count              int                      `json:"count"`
	ActiveCount        int                      `json:"active_count"`
	WarningCount       int                      `json:"warning_count"`
	GovernanceWarnings []governanceWarning      `json:"governance_warnings,omitempty"`
	Identities         []model.NonHumanIdentity `json:"identities"`
}

type governanceWarning struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Code     string `json:"code"`
	Message  string `json:"message"`
}

type referenceError struct {
	status  int
	message string
}

type UsageReference struct {
	ApplicationID string
	Scopes        []string
}

func (err referenceError) Error() string {
	return err.message
}

func NewStore(items ...model.NonHumanIdentity) *Store {
	store := &Store{identities: map[string]model.NonHumanIdentity{}}
	now := time.Now().UTC()
	for _, item := range items {
		normalized, err := Normalize(item, item.TenantID, now)
		if err == nil {
			store.identities[normalized.ID] = normalized
		}
	}
	return store
}

func (store *Store) Upsert(_ context.Context, identity model.NonHumanIdentity, tenantID string, now time.Time) (model.NonHumanIdentity, error) {
	normalized, err := Normalize(identity, tenantID, now)
	if err != nil {
		return model.NonHumanIdentity{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	store.identities[normalized.ID] = normalized
	store.generation++
	store.persistLocked()
	return normalized, nil
}

// ConfigGeneration returns the monotonic NHI-registry config version (bumped on each Upsert). A config-bundle
// distributor folds it into the aggregate generation so a registry change triggers a fleet-wide re-pull.
func (store *Store) ConfigGeneration() uint64 {
	store.mu.RLock()
	defer store.mu.RUnlock()
	return store.generation
}

func (store *Store) List(_ context.Context, tenantID string) ([]model.NonHumanIdentity, error) {
	store.mu.RLock()
	defer store.mu.RUnlock()
	items := []model.NonHumanIdentity{}
	for _, identity := range store.identities {
		if identity.TenantID == tenantID {
			items = append(items, identity)
		}
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].ID < items[j].ID
	})
	return items, nil
}

func (store *Store) CountActive(ctx context.Context, tenantID string, now time.Time) (int, error) {
	count := 0
	identities, err := store.List(ctx, tenantID)
	if err != nil {
		return 0, err
	}
	for _, identity := range identities {
		if isActive(identity, now) {
			count++
		}
	}
	return count, nil
}

func (store *Store) MarkUsed(_ context.Context, tenantID, actorNHIID string, now time.Time) (bool, error) {
	if store == nil {
		return false, nil
	}
	tenantID = strings.TrimSpace(tenantID)
	actorNHIID = strings.TrimSpace(actorNHIID)
	if tenantID == "" || actorNHIID == "" {
		return false, nil
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	identity, ok := store.identities[actorNHIID]
	if !ok || identity.TenantID != tenantID {
		return false, nil
	}
	lastUsedAt := now.UTC().Format(time.RFC3339)
	identity.LastUsedAt = &lastUsedAt
	store.identities[actorNHIID] = identity
	store.persistLocked()
	return true, nil
}

func List(ctx context.Context, store RuntimeStore, tenantID string, now time.Time) (ListResponse, error) {
	items, err := store.List(ctx, tenantID)
	if err != nil {
		return ListResponse{}, err
	}
	active := 0
	warnings := []governanceWarning{}
	for _, identity := range items {
		if isActive(identity, now) {
			active++
		}
		warnings = append(warnings, governanceWarnings(identity, now)...)
	}
	return ListResponse{
		TenantID:           tenantID,
		Count:              len(items),
		ActiveCount:        active,
		WarningCount:       len(warnings),
		GovernanceWarnings: warnings,
		Identities:         items,
	}, nil
}

func governanceWarnings(identity model.NonHumanIdentity, now time.Time) []governanceWarning {
	if !isActive(identity, now) || !needsStrictAllowlist(identity) {
		return nil
	}
	warnings := []governanceWarning{}
	if !identity.AllowlistEnforced && len(identity.AllowedApplicationIDs) == 0 {
		warnings = append(warnings, governanceWarning{
			ID:       identity.ID,
			Severity: "warning",
			Code:     "empty_allowed_application_ids",
			Message:  "Active AI/automation NHI has no application allowlist; an empty allowlist is treated as allow-all.",
		})
	}
	if !identity.AllowlistEnforced && len(identity.AllowedScopes) == 0 {
		warnings = append(warnings, governanceWarning{
			ID:       identity.ID,
			Severity: "warning",
			Code:     "empty_allowed_scopes",
			Message:  "Active AI/automation NHI has no scope allowlist; an empty allowlist is treated as allow-all.",
		})
	}
	return warnings
}

func needsStrictAllowlist(identity model.NonHumanIdentity) bool {
	switch strings.ToLower(strings.TrimSpace(identity.NHIType)) {
	case "ai_agent", "automation":
		return true
	default:
		return false
	}
}

func validateActiveReference(ctx context.Context, store RuntimeStore, tenantID, actorNHIID string, now time.Time) error {
	return ValidateUsageReference(ctx, store, tenantID, actorNHIID, UsageReference{}, now)
}

func UsageFromHumanApprovalEvent(event model.HumanApprovalEvent) UsageReference {
	scopes := append([]string{}, event.RequestedScopes...)
	if event.ActionType != nil {
		scopes = append(scopes, *event.ActionType)
	}
	return UsageReference{
		ApplicationID: stringPtrValue(event.ApplicationID),
		Scopes:        scopes,
	}
}

func UsageFromDelegatedGrant(grant model.DelegatedAccessGrant) UsageReference {
	return UsageReference{
		ApplicationID: stringPtrValue(grant.ApplicationID),
		Scopes:        append([]string{}, grant.Scopes...),
	}
}

func UsageFromToolCallEvent(event model.ToolCallEvent) UsageReference {
	return UsageReference{
		ApplicationID: stringPtrValue(event.ApplicationID),
		Scopes:        []string{event.ActionType},
	}
}

func ValidateUsageReference(ctx context.Context, store RuntimeStore, tenantID, actorNHIID string, usage UsageReference, now time.Time) error {
	actorNHIID = strings.TrimSpace(actorNHIID)
	if store == nil || actorNHIID == "" {
		return nil
	}
	identities, err := store.List(ctx, tenantID)
	if err != nil {
		return referenceError{status: 500, message: "non-human identity registry is unavailable"}
	}
	if len(identities) == 0 {
		return nil
	}
	for _, identity := range identities {
		if identity.ID != actorNHIID {
			continue
		}
		if !isActive(identity, now) {
			return referenceError{status: 403, message: fmt.Sprintf("non-human identity %s is not active", actorNHIID)}
		}
		if strings.TrimSpace(usage.ApplicationID) != "" && !ApplicationAllowed(identity, usage.ApplicationID) {
			return referenceError{status: 403, message: fmt.Sprintf("non-human identity %s is not allowed for application %s", actorNHIID, strings.TrimSpace(usage.ApplicationID))}
		}
		if scope, ok := FirstDisallowedScope(identity, usage.Scopes); ok {
			if scope == "" {
				return referenceError{status: 403, message: fmt.Sprintf("non-human identity %s requires an allowed scope", actorNHIID)}
			}
			return referenceError{status: 403, message: fmt.Sprintf("non-human identity %s is not allowed for scope %s", actorNHIID, scope)}
		}
		return nil
	}
	return referenceError{status: 404, message: fmt.Sprintf("non-human identity %s is not registered", actorNHIID)}
}

func ValidateRuntimeEvidence(ctx context.Context, store RuntimeStore, req model.DecisionRequest, tenantID, actorNHIID string, now time.Time) (reason string, evidenceResult string, ok bool) {
	actorNHIID = strings.TrimSpace(actorNHIID)
	if store == nil {
		return "", "", true
	}
	identities, err := store.List(ctx, tenantID)
	if err != nil {
		return "Non-Human Identity Registry is unavailable.", "nhi_registry_unavailable", false
	}
	if len(identities) == 0 {
		return "", "", true
	}
	if actorNHIID == "" {
		return "Non-Human Identity is required for delegated agent access.", "nhi_registry_absent", false
	}
	for _, identity := range identities {
		if identity.ID != actorNHIID {
			continue
		}
		if !isActive(identity, now) {
			return fmt.Sprintf("Non-Human Identity %s is not active.", actorNHIID), "nhi_inactive", false
		}
		if !ApplicationAllowed(identity, req.ApplicationID) {
			return fmt.Sprintf("Non-Human Identity %s is not allowed for application %s.", actorNHIID, req.ApplicationID), "nhi_application_not_allowed", false
		}
		if !ScopeAllowed(identity, req.ToolActionType) {
			return fmt.Sprintf("Non-Human Identity %s is not allowed for scope %s.", actorNHIID, req.ToolActionType), "nhi_scope_not_allowed", false
		}
		return "", "", true
	}
	return fmt.Sprintf("Non-Human Identity %s is not registered.", actorNHIID), "nhi_registry_absent", false
}

func StatusForReferenceError(err error) int {
	var refErr referenceError
	if errors.As(err, &refErr) {
		return refErr.status
	}
	return 500
}

func Normalize(identity model.NonHumanIdentity, tenantID string, _ time.Time) (model.NonHumanIdentity, error) {
	identity.ID = strings.TrimSpace(identity.ID)
	identity.TenantID = strings.TrimSpace(identity.TenantID)
	if identity.ID == "" {
		return model.NonHumanIdentity{}, fmt.Errorf("non-human identity id is required")
	}
	if tenantID != "" {
		if identity.TenantID != "" && identity.TenantID != tenantID {
			return model.NonHumanIdentity{}, fmt.Errorf("non-human identity tenant_id %s does not match admin tenant_id %s", identity.TenantID, tenantID)
		}
		identity.TenantID = tenantID
	}
	if identity.TenantID == "" {
		return model.NonHumanIdentity{}, fmt.Errorf("non-human identity tenant_id is required")
	}
	identity.Name = strings.TrimSpace(identity.Name)
	if identity.Name == "" {
		return model.NonHumanIdentity{}, fmt.Errorf("non-human identity name is required")
	}
	identity.NHIType = strings.TrimSpace(identity.NHIType)
	if identity.NHIType == "" {
		return model.NonHumanIdentity{}, fmt.Errorf("non-human identity nhi_type is required")
	}
	identity.OwnerUserID = strings.TrimSpace(identity.OwnerUserID)
	if identity.OwnerUserID == "" {
		return model.NonHumanIdentity{}, fmt.Errorf("non-human identity owner_user_id is required")
	}
	identity.Status = strings.TrimSpace(identity.Status)
	if identity.Status == "" {
		identity.Status = "active"
	}
	if !statusValid(identity.Status) {
		return model.NonHumanIdentity{}, fmt.Errorf("non-human identity status %s is invalid", identity.Status)
	}
	if err := validateOptionalRFC3339(identity.LastUsedAt, "last_used_at"); err != nil {
		return model.NonHumanIdentity{}, err
	}
	if err := validateOptionalRFC3339(identity.ExpiresAt, "expires_at"); err != nil {
		return model.NonHumanIdentity{}, err
	}
	identity.AllowedApplicationIDs = normalizedStringList(identity.AllowedApplicationIDs)
	identity.AllowedScopes = normalizedStringList(identity.AllowedScopes)
	if identity.AllowedApplicationIDs == nil {
		identity.AllowedApplicationIDs = []string{}
	}
	if identity.AllowedScopes == nil {
		identity.AllowedScopes = []string{}
	}
	if identity.Metadata == nil {
		identity.Metadata = map[string]any{}
	}
	return identity, nil
}

func statusValid(status string) bool {
	switch status {
	case "active", "suspended", "expired", "revoked":
		return true
	default:
		return false
	}
}

func ApplicationAllowed(identity model.NonHumanIdentity, applicationID string) bool {
	if len(identity.AllowedApplicationIDs) == 0 {
		// An empty allowlist stays permissive so existing NHI fixtures remain migratable.
		// Operators opt into deny-by-default per NHI with allowlist_enforced.
		return !identity.AllowlistEnforced
	}
	applicationID = strings.TrimSpace(applicationID)
	if applicationID == "" {
		return false
	}
	for _, allowed := range identity.AllowedApplicationIDs {
		if strings.TrimSpace(allowed) == applicationID {
			return true
		}
	}
	return false
}

func ScopeAllowed(identity model.NonHumanIdentity, requestedScope string) bool {
	if len(identity.AllowedScopes) == 0 {
		// See ApplicationAllowed: empty means unconstrained unless allowlist_enforced
		// opts this NHI into strict mode.
		return !identity.AllowlistEnforced
	}
	requestedScope = strings.TrimSpace(requestedScope)
	if requestedScope == "" {
		return false
	}
	for _, allowed := range identity.AllowedScopes {
		if strings.TrimSpace(allowed) == requestedScope {
			return true
		}
	}
	return false
}

func FirstDisallowedScope(identity model.NonHumanIdentity, requestedScopes []string) (string, bool) {
	if len(identity.AllowedScopes) == 0 {
		if !identity.AllowlistEnforced {
			return "", false
		}
		normalized := normalizedStringList(requestedScopes)
		if len(normalized) == 0 {
			return "", true
		}
		return normalized[0], true
	}
	normalized := normalizedStringList(requestedScopes)
	if len(normalized) == 0 {
		return "", false
	}
	for _, scope := range normalized {
		if !ScopeAllowed(identity, scope) {
			return scope, true
		}
	}
	return "", false
}

func isActive(identity model.NonHumanIdentity, now time.Time) bool {
	if identity.Status != "active" {
		return false
	}
	if identity.ExpiresAt == nil || strings.TrimSpace(*identity.ExpiresAt) == "" {
		return true
	}
	expiresAt, err := time.Parse(time.RFC3339, strings.TrimSpace(*identity.ExpiresAt))
	if err != nil {
		return false
	}
	return now.UTC().Before(expiresAt.UTC())
}

func validateOptionalRFC3339(value *string, field string) error {
	if value == nil || strings.TrimSpace(*value) == "" {
		return nil
	}
	if _, err := time.Parse(time.RFC3339, strings.TrimSpace(*value)); err != nil {
		return fmt.Errorf("non-human identity %s must be RFC3339", field)
	}
	trimmed := strings.TrimSpace(*value)
	*value = trimmed
	return nil
}

// normalizedStringList trims, de-dups, and drops empties (order-preserving) — package-local copy of the
// shared admin helper so the package stays self-contained.
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

// stringPtrValue dereferences an optional string (nil => "").
func stringPtrValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
