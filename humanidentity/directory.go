package humanidentity

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/model"
)

type HumanIdentityDirectoryStore struct {
	mu             sync.RWMutex
	users          map[string]model.HumanIdentity
	sourceStates   map[string]HumanIdentitySourceState
	sourcePolicies map[string]HumanIdentitySourcePolicy
	// generation is the monotonic change signal the config bundle aggregates, so an Edge re-pulls when the
	// directory changes. Without it the bundle's CONTENTS would change while its VERSION did not, and no Edge
	// would ever re-pull for a new person — the same defect the tenant registry had.
	generation atomic.Uint64
	// persister, when set, makes the directory DURABLE. It was in-memory only, and that turns a routine Edge
	// restart into a loss of the entire human identity directory: the directory is populated by IMPORT RUNS
	// (and single upserts) at runtime, never re-seeded, so after a restart every identity is gone and every
	// identity-scoped decision loses its subject until the next import lands. Nil = in-memory only.
	persister blobstore.Persister
}

// humanIdentityDirectorySnapshot is the on-disk shape: the complete directory state. All three maps are
// runtime-written and must be restored, or a restart would come back with a partial directory (e.g. identities
// but no source policies, silently re-enabling a disabled source on the next import).
type humanIdentityDirectorySnapshot struct {
	Users          map[string]model.HumanIdentity       `json:"users"`
	SourceStates   map[string]HumanIdentitySourceState  `json:"source_states"`
	SourcePolicies map[string]HumanIdentitySourcePolicy `json:"source_policies"`
}

// OnPersistError reports storage failures or weakened save guarantees to the host.
// Must not panic. Identity Upsert also returns ErrDirectoryPersistence on rejected
// saves; source-policy and import-state writes still report errors best-effort.
var OnPersistError func(error)

func reportPersistError(err error) {
	if OnPersistError != nil {
		OnPersistError(err)
	}
}

type HumanIdentityDirectoryRuntimeStore interface {
	Upsert(context.Context, model.HumanIdentity, string, time.Time) (model.HumanIdentity, error)
	List(context.Context, string, ...HumanIdentityDirectoryListOptions) ([]model.HumanIdentity, error)
	Stats(context.Context, string, time.Time) (HumanIdentityDirectoryStats, error)
}

type HumanIdentityDirectoryBulkUpserter interface {
	UpsertMany(context.Context, []model.HumanIdentity, string, time.Time) ([]model.HumanIdentity, error)
}

type HumanIdentityDirectoryStats struct {
	Total  int
	Active int
}

type HumanIdentitySourceListResponse struct {
	TenantID string                       `json:"tenant_id"`
	Count    int                          `json:"count"`
	Sources  []HumanIdentitySourceSummary `json:"sources"`
}

type HumanIdentitySourceStateListResponse struct {
	TenantID string                     `json:"tenant_id"`
	Count    int                        `json:"count"`
	States   []HumanIdentitySourceState `json:"states"`
}

type HumanIdentitySourcePolicyListResponse struct {
	TenantID string                      `json:"tenant_id"`
	Count    int                         `json:"count"`
	Policies []HumanIdentitySourcePolicy `json:"policies"`
}

type HumanIdentitySourceDueListResponse struct {
	TenantID  string                   `json:"tenant_id"`
	CheckedAt string                   `json:"checked_at"`
	Count     int                      `json:"count"`
	Sources   []HumanIdentitySourceDue `json:"sources"`
}

type HumanIdentitySourceDue struct {
	Source                  string         `json:"source"`
	ConnectorType           string         `json:"connector_type"`
	ReconcileMissing        bool           `json:"reconcile_missing"`
	ExpectedIntervalSeconds int64          `json:"expected_interval_seconds"`
	StaleAfterSeconds       int64          `json:"stale_after_seconds,omitempty"`
	NextExpectedAt          string         `json:"next_expected_at,omitempty"`
	LatestImportRunID       string         `json:"latest_import_run_id,omitempty"`
	Checkpoint              string         `json:"checkpoint,omitempty"`
	DueReason               string         `json:"due_reason"`
	Metadata                map[string]any `json:"metadata,omitempty"`
}

type HumanIdentitySourcePolicy struct {
	TenantID                string         `json:"tenant_id"`
	Source                  string         `json:"source"`
	ConnectorType           string         `json:"connector_type"`
	Enabled                 bool           `json:"enabled"`
	ReconcileMissing        bool           `json:"reconcile_missing"`
	ExpectedIntervalSeconds int64          `json:"expected_interval_seconds,omitempty"`
	StaleAfterSeconds       int64          `json:"stale_after_seconds,omitempty"`
	Metadata                map[string]any `json:"metadata,omitempty"`
	UpdatedAt               string         `json:"updated_at"`
}

type HumanIdentitySourceState struct {
	TenantID        string `json:"tenant_id"`
	Source          string `json:"source"`
	Status          string `json:"status"`
	LastImportRunID string `json:"last_import_run_id,omitempty"`
	Checkpoint      string `json:"checkpoint,omitempty"`
	LastSuccessAt   string `json:"last_success_at,omitempty"`
	LastErrorAt     string `json:"last_error_at,omitempty"`
	LastError       string `json:"last_error,omitempty"`
	Requested       int    `json:"requested"`
	Upserted        int    `json:"upserted"`
	Deactivated     int    `json:"deactivated"`
	ActiveCount     int    `json:"active_count"`
	UpdatedAt       string `json:"updated_at"`
}

type HumanIdentitySourceHealthResponse struct {
	TenantID    string                      `json:"tenant_id"`
	Status      string                      `json:"status"`
	Reasons     []string                    `json:"reasons,omitempty"`
	CheckedAt   string                      `json:"checked_at"`
	StaleAfter  int64                       `json:"stale_after_seconds"`
	SourceCount int                         `json:"source_count"`
	Sources     []HumanIdentitySourceHealth `json:"sources"`
}

type HumanIdentitySourceHealth struct {
	Source            string   `json:"source"`
	Status            string   `json:"status"`
	Reasons           []string `json:"reasons,omitempty"`
	Configured        bool     `json:"configured,omitempty"`
	Enabled           bool     `json:"enabled,omitempty"`
	ConnectorType     string   `json:"connector_type,omitempty"`
	ExpectedInterval  int64    `json:"expected_interval_seconds,omitempty"`
	NextExpectedAt    string   `json:"next_expected_at,omitempty"`
	Due               bool     `json:"due,omitempty"`
	ObservedAt        string   `json:"observed_at,omitempty"`
	LatestImportRunID string   `json:"latest_import_run_id,omitempty"`
	AgeSeconds        int64    `json:"age_seconds,omitempty"`
	StaleAfterSeconds int64    `json:"stale_after_seconds,omitempty"`
	Total             int      `json:"total"`
	Active            int      `json:"active"`
	Suspended         int      `json:"suspended"`
	Deleted           int      `json:"deleted"`
	Expired           int      `json:"expired"`
}

type HumanIdentitySourceSummary struct {
	Source            string `json:"source"`
	ObservedAt        string `json:"observed_at,omitempty"`
	LatestImportRunID string `json:"latest_import_run_id,omitempty"`
	Total             int    `json:"total"`
	Active            int    `json:"active"`
	Suspended         int    `json:"suspended"`
	Deleted           int    `json:"deleted"`
	Expired           int    `json:"expired"`
}

type HumanIdentityImportRunListResponse struct {
	TenantID string                          `json:"tenant_id"`
	Source   string                          `json:"source,omitempty"`
	Limit    int                             `json:"limit"`
	Count    int                             `json:"count"`
	Runs     []HumanIdentityImportRunSummary `json:"runs"`
}

type HumanIdentityImportRunDetailResponse struct {
	TenantID              string                        `json:"tenant_id"`
	ImportRunID           string                        `json:"import_run_id"`
	Summary               HumanIdentityImportRunSummary `json:"summary"`
	UpsertedIdentities    []model.HumanIdentity         `json:"upserted_identities"`
	DeactivatedIdentities []model.HumanIdentity         `json:"deactivated_identities"`
}

type HumanIdentityImportRunSummary struct {
	ImportRunID string `json:"import_run_id"`
	Source      string `json:"source,omitempty"`
	Checkpoint  string `json:"checkpoint,omitempty"`
	ObservedAt  string `json:"observed_at,omitempty"`
	Upserted    int    `json:"upserted"`
	Deactivated int    `json:"deactivated"`
	Active      int    `json:"active"`
	Deleted     int    `json:"deleted"`
}

type HumanIdentityImportRunListOptions struct {
	Limit  int
	Source string
}

type HumanIdentityImportRunLister interface {
	ListImportRuns(context.Context, string, HumanIdentityImportRunListOptions) ([]HumanIdentityImportRunSummary, error)
}

type HumanIdentityImportRunGetter interface {
	GetImportRun(context.Context, string, string) (HumanIdentityImportRunDetailResponse, bool, error)
}

type HumanIdentitySourceLister interface {
	ListSources(context.Context, string, time.Time) ([]HumanIdentitySourceSummary, error)
}

type HumanIdentitySourceStateRecorder interface {
	RecordSourceImport(context.Context, HumanIdentitySourceState) error
}

type HumanIdentitySourceStateLister interface {
	ListSourceStates(context.Context, string) ([]HumanIdentitySourceState, error)
}

type HumanIdentitySourcePolicyUpserter interface {
	UpsertSourcePolicy(context.Context, HumanIdentitySourcePolicy) (HumanIdentitySourcePolicy, error)
}

type HumanIdentitySourcePolicyLister interface {
	ListSourcePolicies(context.Context, string) ([]HumanIdentitySourcePolicy, error)
}

type HumanIdentityDirectoryListOptions struct {
	Source      string
	Status      string
	Subject     string
	Email       string
	ImportRunID string
	Limit       int
	AfterID     string
}

type HumanIdentityDirectoryListResponse struct {
	TenantID    string                `json:"tenant_id"`
	Source      string                `json:"source,omitempty"`
	Status      string                `json:"status,omitempty"`
	Subject     string                `json:"subject,omitempty"`
	Email       string                `json:"email,omitempty"`
	ImportRunID string                `json:"import_run_id,omitempty"`
	Limit       int                   `json:"limit,omitempty"`
	NextCursor  string                `json:"next_cursor,omitempty"`
	Count       int                   `json:"count"`
	ActiveCount int                   `json:"active_count"`
	Identities  []model.HumanIdentity `json:"identities"`
}

const (
	MaxHumanIdentityImportItems       = 500
	MaxHumanIdentityImportRunIDLength = 128
	MaxHumanIdentitySourceCheckpoint  = 2048
	maxHumanIdentitySourceStateError  = 1024
	maxHumanIdentitySourcePolicyMeta  = 32
	maxHumanIdentitySourceNameLength  = 128
)

type HumanIdentityDirectoryImportRequest struct {
	Source           string                `json:"source"`
	ImportRunID      string                `json:"import_run_id"`
	Checkpoint       string                `json:"checkpoint"`
	DryRun           bool                  `json:"dry_run"`
	ReconcileMissing *bool                 `json:"reconcile_missing,omitempty"`
	Identities       []model.HumanIdentity `json:"identities"`
}

type HumanIdentityDirectoryImportResponse struct {
	TenantID              string                `json:"tenant_id"`
	Source                string                `json:"source"`
	ImportRunID           string                `json:"import_run_id"`
	Checkpoint            string                `json:"checkpoint,omitempty"`
	DryRun                bool                  `json:"dry_run"`
	ReconcileMissing      bool                  `json:"reconcile_missing"`
	Requested             int                   `json:"requested"`
	Upserted              int                   `json:"upserted"`
	Deactivated           int                   `json:"deactivated"`
	ActiveCount           int                   `json:"active_count"`
	Identities            []model.HumanIdentity `json:"identities"`
	DeactivatedIdentities []model.HumanIdentity `json:"deactivated_identities"`
}

func NewHumanIdentityDirectoryStore(items ...model.HumanIdentity) *HumanIdentityDirectoryStore {
	store := &HumanIdentityDirectoryStore{
		users:          map[string]model.HumanIdentity{},
		sourceStates:   map[string]HumanIdentitySourceState{},
		sourcePolicies: map[string]HumanIdentitySourcePolicy{},
	}
	now := time.Now().UTC()
	for _, item := range items {
		normalized, err := NormalizeHumanIdentity(item, item.TenantID, now)
		if err == nil {
			store.users[HumanIdentityDirectoryKey(normalized.TenantID, normalized.ID)] = normalized
		}
	}
	return store
}

// SetPersister enables durable persistence so the human identity directory survives an Edge restart. It loads
// any prior snapshot immediately and restores it, then every mutation re-saves the full directory. Nil disables
// persistence.
//
// It FAILS CLOSED on a Load or Unmarshal error: a directory store that exists on disk but cannot be read must
// not silently start EMPTY — that would look identical to a fresh install and let a restart erase the directory
// exactly as the in-memory store did.
func (store *HumanIdentityDirectoryStore) SetPersister(p blobstore.Persister) error {
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
	var snap humanIdentityDirectorySnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return err
	}
	if snap.Users != nil {
		store.users = snap.Users
	}
	if snap.SourceStates != nil {
		store.sourceStates = snap.SourceStates
	}
	if snap.SourcePolicies != nil {
		store.sourcePolicies = snap.SourcePolicies
	}
	return nil
}

// ErrDirectoryPersistence is safe to return to API callers. The underlying storage
// error is reported through OnPersistError and may contain private deployment paths.
var ErrDirectoryPersistence = errors.New("human identity directory could not be saved")

// saveSnapshotLocked saves a candidate while the caller holds store.mu. A reported
// in-place save is already committed; treating it as rejected would diverge memory
// from disk. Stores without a persister remain intentionally in-memory.
func (store *HumanIdentityDirectoryStore) saveSnapshotLocked(users map[string]model.HumanIdentity) error {
	if store.persister == nil {
		return nil
	}
	data, err := json.Marshal(humanIdentityDirectorySnapshot{
		Users:          users,
		SourceStates:   store.sourceStates,
		SourcePolicies: store.sourcePolicies,
	})
	if err != nil {
		reportPersistError(fmt.Errorf("marshal human identity directory snapshot: %w", err))
		return ErrDirectoryPersistence
	}
	if err := store.persister.Save(data); err != nil {
		reportPersistError(fmt.Errorf("save human identity directory snapshot: %w", err))
		if !errors.Is(err, blobstore.ErrSavedWithoutAtomicity) {
			return ErrDirectoryPersistence
		}
	}
	return nil
}

// Source-policy and import-state writes retain their existing best-effort contract.
// Identity Upsert below instead publishes only after its candidate is saved.
func (store *HumanIdentityDirectoryStore) persistLocked() {
	_ = store.saveSnapshotLocked(store.users)
}

func (store *HumanIdentityDirectoryStore) Upsert(_ context.Context, user model.HumanIdentity, tenantID string, now time.Time) (model.HumanIdentity, error) {
	normalized, err := NormalizeHumanIdentity(user, tenantID, now)
	if err != nil {
		return model.HumanIdentity{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	candidate := make(map[string]model.HumanIdentity, len(store.users)+1)
	for key, existing := range store.users {
		candidate[key] = existing
	}
	candidate[HumanIdentityDirectoryKey(normalized.TenantID, normalized.ID)] = normalized
	if err := store.saveSnapshotLocked(candidate); err != nil {
		return model.HumanIdentity{}, err
	}
	store.users = candidate
	store.generation.Add(1)
	return normalized, nil
}

// ConfigGeneration returns the monotonic directory version, bumped on every identity and source-policy
// upsert. The config bundle sums it, which is what makes an enforcing Edge re-pull after somebody is added.
func (store *HumanIdentityDirectoryStore) ConfigGeneration() uint64 {
	if store == nil {
		return 0
	}
	return store.generation.Load()
}

func (store *HumanIdentityDirectoryStore) RecordSourceImport(_ context.Context, state HumanIdentitySourceState) error {
	normalized, err := NormalizeHumanIdentitySourceState(state)
	if err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.sourceStates == nil {
		store.sourceStates = map[string]HumanIdentitySourceState{}
	}
	store.sourceStates[HumanIdentityDirectoryKey(normalized.TenantID, normalized.Source)] = normalized
	store.persistLocked()
	return nil
}

func (store *HumanIdentityDirectoryStore) ListSourceStates(_ context.Context, tenantID string) ([]HumanIdentitySourceState, error) {
	if store == nil {
		return nil, nil
	}
	tenantID = strings.TrimSpace(tenantID)
	store.mu.RLock()
	defer store.mu.RUnlock()
	states := []HumanIdentitySourceState{}
	for _, state := range store.sourceStates {
		if state.TenantID == tenantID {
			states = append(states, state)
		}
	}
	sort.Slice(states, func(i, j int) bool {
		return states[i].Source < states[j].Source
	})
	return states, nil
}

func (store *HumanIdentityDirectoryStore) UpsertSourcePolicy(_ context.Context, policy HumanIdentitySourcePolicy) (HumanIdentitySourcePolicy, error) {
	normalized, err := NormalizeHumanIdentitySourcePolicy(policy)
	if err != nil {
		return HumanIdentitySourcePolicy{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.sourcePolicies == nil {
		store.sourcePolicies = map[string]HumanIdentitySourcePolicy{}
	}
	store.sourcePolicies[HumanIdentityDirectoryKey(normalized.TenantID, normalized.Source)] = normalized
	store.persistLocked()
	store.generation.Add(1)
	return normalized, nil
}

func (store *HumanIdentityDirectoryStore) ListSourcePolicies(_ context.Context, tenantID string) ([]HumanIdentitySourcePolicy, error) {
	if store == nil {
		return nil, nil
	}
	tenantID = strings.TrimSpace(tenantID)
	store.mu.RLock()
	defer store.mu.RUnlock()
	policies := []HumanIdentitySourcePolicy{}
	for _, policy := range store.sourcePolicies {
		if policy.TenantID == tenantID {
			policies = append(policies, policy)
		}
	}
	sort.Slice(policies, func(i, j int) bool {
		return policies[i].Source < policies[j].Source
	})
	return policies, nil
}

func (store *HumanIdentityDirectoryStore) List(_ context.Context, tenantID string, options ...HumanIdentityDirectoryListOptions) ([]model.HumanIdentity, error) {
	if store == nil {
		return nil, nil
	}
	tenantID = strings.TrimSpace(tenantID)
	option := NormalizeHumanIdentityDirectoryListOptions(options...)
	store.mu.RLock()
	defer store.mu.RUnlock()
	users := []model.HumanIdentity{}
	for _, user := range store.users {
		if user.TenantID == tenantID {
			if option.Source != "" && user.Source != option.Source {
				continue
			}
			if option.Status != "" && user.Status != option.Status {
				continue
			}
			if option.Subject != "" && user.Subject != option.Subject {
				continue
			}
			if option.Email != "" {
				if user.Email == nil || *user.Email != option.Email {
					continue
				}
			}
			if option.ImportRunID != "" {
				metadata := user.Metadata
				if fmt.Sprint(metadata["import_run_id"]) != option.ImportRunID && fmt.Sprint(metadata["deactivated_by_import_run_id"]) != option.ImportRunID {
					continue
				}
			}
			if option.AfterID != "" && user.ID <= option.AfterID {
				continue
			}
			users = append(users, user)
		}
	}
	sort.Slice(users, func(i, j int) bool {
		return users[i].ID < users[j].ID
	})
	if option.Limit > 0 && len(users) > option.Limit {
		users = users[:option.Limit]
	}
	return users, nil
}

func (store *HumanIdentityDirectoryStore) Stats(ctx context.Context, tenantID string, now time.Time) (HumanIdentityDirectoryStats, error) {
	users, err := store.List(ctx, tenantID)
	if err != nil {
		return HumanIdentityDirectoryStats{}, err
	}
	stats := HumanIdentityDirectoryStats{Total: len(users)}
	for _, user := range users {
		if HumanIdentityIsActive(user, now) {
			stats.Active++
		}
	}
	return stats, nil
}

func (store *HumanIdentityDirectoryStore) ListImportRuns(ctx context.Context, tenantID string, options HumanIdentityImportRunListOptions) ([]HumanIdentityImportRunSummary, error) {
	users, err := store.List(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	return SummarizeHumanIdentityImportRuns(users, options), nil
}

func (store *HumanIdentityDirectoryStore) GetImportRun(ctx context.Context, tenantID, importRunID string) (HumanIdentityImportRunDetailResponse, bool, error) {
	users, err := store.List(ctx, tenantID)
	if err != nil {
		return HumanIdentityImportRunDetailResponse{}, false, err
	}
	return HumanIdentityImportRunDetailFromUsers(tenantID, importRunID, users)
}

func (store *HumanIdentityDirectoryStore) ListSources(ctx context.Context, tenantID string, now time.Time) ([]HumanIdentitySourceSummary, error) {
	users, err := store.List(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	return summarizeHumanIdentitySources(users, tenantID, now), nil
}

func HumanIdentityDirectoryList(ctx context.Context, store HumanIdentityDirectoryRuntimeStore, tenantID string, now time.Time, options ...HumanIdentityDirectoryListOptions) (HumanIdentityDirectoryListResponse, error) {
	option := NormalizeHumanIdentityDirectoryListOptions(options...)
	storeOption := option
	if storeOption.Limit > 0 {
		storeOption.Limit++
	}
	items, err := store.List(ctx, tenantID, storeOption)
	if err != nil {
		return HumanIdentityDirectoryListResponse{}, err
	}
	nextCursor := ""
	if option.Limit > 0 && len(items) > option.Limit {
		nextCursor = encodeHumanIdentityDirectoryCursor(items[option.Limit-1].ID)
		items = items[:option.Limit]
	}
	active := 0
	for _, item := range items {
		if HumanIdentityIsActive(item, now) {
			active++
		}
	}
	return HumanIdentityDirectoryListResponse{
		TenantID:    tenantID,
		Source:      option.Source,
		Status:      option.Status,
		Subject:     option.Subject,
		Email:       option.Email,
		ImportRunID: option.ImportRunID,
		Limit:       option.Limit,
		NextCursor:  nextCursor,
		Count:       len(items),
		ActiveCount: active,
		Identities:  items,
	}, nil
}

func HumanIdentityDirectoryImportRunList(ctx context.Context, store HumanIdentityDirectoryRuntimeStore, tenantID string, options HumanIdentityImportRunListOptions) (HumanIdentityImportRunListResponse, error) {
	tenantID = strings.TrimSpace(tenantID)
	options.Source = strings.TrimSpace(options.Source)
	if options.Limit <= 0 {
		options.Limit = 25
	}
	if options.Limit > 1000 {
		options.Limit = 1000
	}
	var runs []HumanIdentityImportRunSummary
	var err error
	if lister, ok := store.(HumanIdentityImportRunLister); ok {
		runs, err = lister.ListImportRuns(ctx, tenantID, options)
	} else {
		var users []model.HumanIdentity
		users, err = store.List(ctx, tenantID)
		runs = SummarizeHumanIdentityImportRuns(users, options)
	}
	if err != nil {
		return HumanIdentityImportRunListResponse{}, err
	}
	return HumanIdentityImportRunListResponse{
		TenantID: tenantID,
		Source:   options.Source,
		Limit:    options.Limit,
		Count:    len(runs),
		Runs:     runs,
	}, nil
}

func HumanIdentityDirectoryImportRunDetail(ctx context.Context, store HumanIdentityDirectoryRuntimeStore, tenantID, importRunID string) (HumanIdentityImportRunDetailResponse, bool, error) {
	tenantID = strings.TrimSpace(tenantID)
	importRunID, err := CleanHumanIdentityImportRunID(importRunID)
	if err != nil {
		return HumanIdentityImportRunDetailResponse{}, false, err
	}
	if getter, ok := store.(HumanIdentityImportRunGetter); ok {
		return getter.GetImportRun(ctx, tenantID, importRunID)
	}
	users, err := store.List(ctx, tenantID)
	if err != nil {
		return HumanIdentityImportRunDetailResponse{}, false, err
	}
	return HumanIdentityImportRunDetailFromUsers(tenantID, importRunID, users)
}

func HumanIdentityDirectorySourceList(ctx context.Context, store HumanIdentityDirectoryRuntimeStore, tenantID string, now time.Time) (HumanIdentitySourceListResponse, error) {
	tenantID = strings.TrimSpace(tenantID)
	var sources []HumanIdentitySourceSummary
	var err error
	if lister, ok := store.(HumanIdentitySourceLister); ok {
		sources, err = lister.ListSources(ctx, tenantID, now)
	} else {
		var users []model.HumanIdentity
		users, err = store.List(ctx, tenantID)
		sources = summarizeHumanIdentitySources(users, tenantID, now)
	}
	if err != nil {
		return HumanIdentitySourceListResponse{}, err
	}
	return HumanIdentitySourceListResponse{
		TenantID: tenantID,
		Count:    len(sources),
		Sources:  sources,
	}, nil
}

func HumanIdentityDirectorySourceStateList(ctx context.Context, store HumanIdentityDirectoryRuntimeStore, tenantID string) (HumanIdentitySourceStateListResponse, error) {
	tenantID = strings.TrimSpace(tenantID)
	states := []HumanIdentitySourceState{}
	if lister, ok := store.(HumanIdentitySourceStateLister); ok {
		var err error
		states, err = lister.ListSourceStates(ctx, tenantID)
		if err != nil {
			return HumanIdentitySourceStateListResponse{}, err
		}
	}
	return HumanIdentitySourceStateListResponse{
		TenantID: tenantID,
		Count:    len(states),
		States:   states,
	}, nil
}

func HumanIdentityDirectorySourcePolicyList(ctx context.Context, store HumanIdentityDirectoryRuntimeStore, tenantID string) (HumanIdentitySourcePolicyListResponse, error) {
	tenantID = strings.TrimSpace(tenantID)
	policies := []HumanIdentitySourcePolicy{}
	if lister, ok := store.(HumanIdentitySourcePolicyLister); ok {
		var err error
		policies, err = lister.ListSourcePolicies(ctx, tenantID)
		if err != nil {
			return HumanIdentitySourcePolicyListResponse{}, err
		}
	}
	return HumanIdentitySourcePolicyListResponse{
		TenantID: tenantID,
		Count:    len(policies),
		Policies: policies,
	}, nil
}

func HumanIdentityDirectoryUpsertSourcePolicy(ctx context.Context, store HumanIdentityDirectoryRuntimeStore, tenantID string, policy HumanIdentitySourcePolicy, now time.Time) (HumanIdentitySourcePolicy, error) {
	upserter, ok := store.(HumanIdentitySourcePolicyUpserter)
	if !ok {
		return HumanIdentitySourcePolicy{}, fmt.Errorf("human identity source policy store is not configured")
	}
	policy.TenantID = strings.TrimSpace(tenantID)
	if now.IsZero() {
		now = time.Now()
	}
	policy.UpdatedAt = now.UTC().Format(time.RFC3339)
	return upserter.UpsertSourcePolicy(ctx, policy)
}

func HumanIdentityDirectorySourcePolicyForSource(ctx context.Context, store HumanIdentityDirectoryRuntimeStore, tenantID, source string) (HumanIdentitySourcePolicy, bool, error) {
	tenantID = strings.TrimSpace(tenantID)
	source = strings.TrimSpace(source)
	if source == "" {
		return HumanIdentitySourcePolicy{}, false, nil
	}
	lister, ok := store.(HumanIdentitySourcePolicyLister)
	if !ok {
		return HumanIdentitySourcePolicy{}, false, nil
	}
	policies, err := lister.ListSourcePolicies(ctx, tenantID)
	if err != nil {
		return HumanIdentitySourcePolicy{}, false, err
	}
	for _, policy := range policies {
		if policy.Source == source {
			return policy, true, nil
		}
	}
	return HumanIdentitySourcePolicy{}, false, nil
}

func HumanIdentityDirectorySourceDueListForConnector(result HumanIdentitySourceDueListResponse, connectorID string) HumanIdentitySourceDueListResponse {
	connectorID = strings.TrimSpace(connectorID)
	if connectorID == "" {
		return result
	}
	filtered := result.Sources[:0]
	for _, source := range result.Sources {
		if HumanIdentityConnectorMetadataAllowed(source.Metadata, connectorID) {
			filtered = append(filtered, source)
		}
	}
	result.Sources = filtered
	result.Count = len(filtered)
	return result
}

func HumanIdentityDirectorySourceAllowedForConnector(ctx context.Context, store HumanIdentityDirectoryRuntimeStore, tenantID, source, connectorID string) (bool, error) {
	connectorID = strings.TrimSpace(connectorID)
	if connectorID == "" {
		return true, nil
	}
	source = strings.TrimSpace(source)
	if source == "" {
		source = "directory_import"
	}
	policy, ok, err := HumanIdentityDirectorySourcePolicyForSource(ctx, store, tenantID, source)
	if err != nil {
		return false, err
	}
	if !ok {
		return true, nil
	}
	return HumanIdentityConnectorMetadataAllowed(policy.Metadata, connectorID), nil
}

func HumanIdentityConnectorMetadataAllowed(metadata map[string]any, connectorID string) bool {
	if len(metadata) == 0 {
		return true
	}
	value, ok := metadata["connector_id"]
	if !ok {
		return true
	}
	assignedConnectorID, ok := value.(string)
	if !ok {
		return false
	}
	assignedConnectorID = strings.TrimSpace(assignedConnectorID)
	return assignedConnectorID == "" || assignedConnectorID == connectorID
}

func HumanIdentityDirectorySourceDueList(ctx context.Context, store HumanIdentityDirectoryRuntimeStore, tenantID string, now time.Time) (HumanIdentitySourceDueListResponse, error) {
	tenantID = strings.TrimSpace(tenantID)
	if now.IsZero() {
		now = time.Now()
	}
	sourcePolicyList, err := HumanIdentityDirectorySourcePolicyList(ctx, store, tenantID)
	if err != nil {
		return HumanIdentitySourceDueListResponse{}, err
	}
	sourceStateList, err := HumanIdentityDirectorySourceStateList(ctx, store, tenantID)
	if err != nil {
		return HumanIdentitySourceDueListResponse{}, err
	}
	statesBySource := map[string]HumanIdentitySourceState{}
	for _, state := range sourceStateList.States {
		statesBySource[state.Source] = state
	}
	sourceList, err := HumanIdentityDirectorySourceList(ctx, store, tenantID, now)
	if err != nil {
		return HumanIdentitySourceDueListResponse{}, err
	}
	observedBySource := map[string]HumanIdentitySourceSummary{}
	for _, source := range sourceList.Sources {
		observedBySource[source.Source] = source
	}

	dueSources := []HumanIdentitySourceDue{}
	for _, policy := range sourcePolicyList.Policies {
		if !policy.Enabled || policy.ExpectedIntervalSeconds <= 0 {
			continue
		}
		hasObservation := false
		due := HumanIdentitySourceDue{
			Source:                  policy.Source,
			ConnectorType:           policy.ConnectorType,
			ReconcileMissing:        policy.ReconcileMissing,
			ExpectedIntervalSeconds: policy.ExpectedIntervalSeconds,
			StaleAfterSeconds:       policy.StaleAfterSeconds,
			Metadata:                copyAnyMap(policy.Metadata),
		}
		if state, ok := statesBySource[policy.Source]; ok {
			due.LatestImportRunID = state.LastImportRunID
			due.Checkpoint = state.Checkpoint
			due, ok = applyHumanIdentitySourceDueObservation(due, state.LastSuccessAt, now, policy.ExpectedIntervalSeconds, "source_state")
			if ok {
				dueSources = append(dueSources, due)
				continue
			}
			if strings.TrimSpace(state.LastSuccessAt) != "" {
				hasObservation = true
				continue
			}
		}
		if source, ok := observedBySource[policy.Source]; ok {
			if strings.TrimSpace(due.LatestImportRunID) == "" {
				due.LatestImportRunID = source.LatestImportRunID
			}
			due, ok = applyHumanIdentitySourceDueObservation(due, source.ObservedAt, now, policy.ExpectedIntervalSeconds, "source_observation")
			if ok {
				dueSources = append(dueSources, due)
				continue
			}
			if strings.TrimSpace(source.ObservedAt) != "" {
				hasObservation = true
			}
		}
		if !hasObservation {
			due.DueReason = "source_policy_unobserved"
			dueSources = append(dueSources, due)
		}
	}
	sort.Slice(dueSources, func(i, j int) bool {
		return dueSources[i].Source < dueSources[j].Source
	})
	return HumanIdentitySourceDueListResponse{
		TenantID:  tenantID,
		CheckedAt: now.UTC().Format(time.RFC3339),
		Count:     len(dueSources),
		Sources:   dueSources,
	}, nil
}

func applyHumanIdentitySourceDueObservation(due HumanIdentitySourceDue, observedAtRaw string, now time.Time, expectedIntervalSeconds int64, reasonPrefix string) (HumanIdentitySourceDue, bool) {
	observedAtRaw = strings.TrimSpace(observedAtRaw)
	if observedAtRaw == "" {
		return due, false
	}
	observedAt, err := time.Parse(time.RFC3339, observedAtRaw)
	if err != nil {
		due.DueReason = reasonPrefix + "_invalid"
		return due, true
	}
	nextExpectedAt := observedAt.Add(time.Duration(expectedIntervalSeconds) * time.Second)
	due.NextExpectedAt = nextExpectedAt.UTC().Format(time.RFC3339)
	if now.Before(nextExpectedAt) {
		return due, false
	}
	due.DueReason = "source_import_due"
	return due, true
}

func HumanIdentityDirectorySourceHealth(ctx context.Context, store HumanIdentityDirectoryRuntimeStore, tenantID string, now time.Time, staleAfter time.Duration) (HumanIdentitySourceHealthResponse, error) {
	if staleAfter <= 0 {
		staleAfter = 24 * time.Hour
	}
	sourceList, err := HumanIdentityDirectorySourceList(ctx, store, tenantID, now)
	if err != nil {
		return HumanIdentitySourceHealthResponse{}, err
	}
	sourceStateList, err := HumanIdentityDirectorySourceStateList(ctx, store, tenantID)
	if err != nil {
		return HumanIdentitySourceHealthResponse{}, err
	}
	statesBySource := map[string]HumanIdentitySourceState{}
	for _, state := range sourceStateList.States {
		statesBySource[state.Source] = state
	}
	sourcePolicyList, err := HumanIdentityDirectorySourcePolicyList(ctx, store, tenantID)
	if err != nil {
		return HumanIdentitySourceHealthResponse{}, err
	}
	policiesBySource := map[string]HumanIdentitySourcePolicy{}
	for _, policy := range sourcePolicyList.Policies {
		policiesBySource[policy.Source] = policy
	}
	status := "ok"
	reasonSet := map[string]struct{}{}
	sources := make([]HumanIdentitySourceHealth, 0, len(sourceList.Sources))
	seenSources := map[string]struct{}{}
	for _, source := range sourceList.Sources {
		seenSources[source.Source] = struct{}{}
		health := HumanIdentitySourceHealth{
			Source:            source.Source,
			Status:            "ok",
			ObservedAt:        source.ObservedAt,
			LatestImportRunID: source.LatestImportRunID,
			Total:             source.Total,
			Active:            source.Active,
			Suspended:         source.Suspended,
			Deleted:           source.Deleted,
			Expired:           source.Expired,
		}
		sourceStaleAfter := staleAfter
		if policy, ok := policiesBySource[source.Source]; ok {
			sourceStaleAfter = applyHumanIdentitySourcePolicyHealth(&health, policy, sourceStaleAfter, &status, reasonSet)
		}
		if state, ok := statesBySource[source.Source]; ok {
			applyHumanIdentitySourceStateHealth(&health, state, &status, reasonSet)
		}
		if strings.TrimSpace(source.ObservedAt) == "" {
			if health.Status == "degraded" {
				sources = append(sources, health)
				continue
			}
			health.Status = "unknown"
			health.Reasons = append(health.Reasons, "source_observation_missing")
			if status == "ok" {
				status = "unknown"
			}
			reasonSet["source_observation_missing"] = struct{}{}
			sources = append(sources, health)
			continue
		}
		observedAt, err := time.Parse(time.RFC3339, source.ObservedAt)
		if err != nil {
			health.Status = "degraded"
			health.Reasons = append(health.Reasons, "source_observation_invalid")
			status = "degraded"
			reasonSet["source_observation_invalid"] = struct{}{}
			sources = append(sources, health)
			continue
		}
		age := now.Sub(observedAt)
		if age < 0 {
			age = 0
		}
		health.AgeSeconds = int64(age.Seconds())
		health.StaleAfterSeconds = int64(sourceStaleAfter.Seconds())
		if health.ExpectedInterval > 0 {
			nextExpectedAt := observedAt.Add(time.Duration(health.ExpectedInterval) * time.Second)
			health.NextExpectedAt = nextExpectedAt.UTC().Format(time.RFC3339)
			health.Due = !now.Before(nextExpectedAt)
		}
		if age > sourceStaleAfter {
			health.Status = "degraded"
			health.Reasons = append(health.Reasons, "source_observation_stale")
			status = "degraded"
			reasonSet["source_observation_stale"] = struct{}{}
		}
		sources = append(sources, health)
	}
	for _, state := range sourceStateList.States {
		if _, ok := seenSources[state.Source]; ok {
			continue
		}
		health := HumanIdentitySourceHealth{
			Source:            state.Source,
			Status:            "unknown",
			ObservedAt:        state.LastSuccessAt,
			LatestImportRunID: state.LastImportRunID,
		}
		sourceStaleAfter := staleAfter
		if policy, ok := policiesBySource[state.Source]; ok {
			sourceStaleAfter = applyHumanIdentitySourcePolicyHealth(&health, policy, sourceStaleAfter, &status, reasonSet)
		}
		health.StaleAfterSeconds = int64(sourceStaleAfter.Seconds())
		applyHumanIdentitySourceStateHealth(&health, state, &status, reasonSet)
		if health.Status == "unknown" {
			health.Reasons = append(health.Reasons, "source_observation_missing")
			if status == "ok" {
				status = "unknown"
			}
			reasonSet["source_observation_missing"] = struct{}{}
		}
		sources = append(sources, health)
	}
	for _, policy := range sourcePolicyList.Policies {
		if _, ok := seenSources[policy.Source]; ok {
			continue
		}
		if _, ok := statesBySource[policy.Source]; ok {
			continue
		}
		health := HumanIdentitySourceHealth{
			Source: policy.Source,
			Status: "unknown",
		}
		sourceStaleAfter := applyHumanIdentitySourcePolicyHealth(&health, policy, staleAfter, &status, reasonSet)
		health.StaleAfterSeconds = int64(sourceStaleAfter.Seconds())
		if policy.Enabled {
			health.Status = "degraded"
			health.Reasons = append(health.Reasons, "source_policy_unobserved")
			status = "degraded"
			reasonSet["source_policy_unobserved"] = struct{}{}
		} else {
			health.Reasons = append(health.Reasons, "source_disabled")
			if status == "ok" {
				status = "unknown"
			}
			reasonSet["source_disabled"] = struct{}{}
		}
		sources = append(sources, health)
	}
	sort.Slice(sources, func(i, j int) bool {
		return sources[i].Source < sources[j].Source
	})
	reasons := make([]string, 0, len(reasonSet))
	for reason := range reasonSet {
		reasons = append(reasons, reason)
	}
	sort.Strings(reasons)
	return HumanIdentitySourceHealthResponse{
		TenantID:    sourceList.TenantID,
		Status:      status,
		Reasons:     reasons,
		CheckedAt:   now.UTC().Format(time.RFC3339),
		StaleAfter:  int64(staleAfter.Seconds()),
		SourceCount: len(sources),
		Sources:     sources,
	}, nil
}

func applyHumanIdentitySourcePolicyHealth(health *HumanIdentitySourceHealth, policy HumanIdentitySourcePolicy, fallback time.Duration, status *string, reasonSet map[string]struct{}) time.Duration {
	if health == nil {
		return fallback
	}
	health.Configured = true
	health.Enabled = policy.Enabled
	health.ConnectorType = policy.ConnectorType
	health.ExpectedInterval = policy.ExpectedIntervalSeconds
	staleAfter := fallback
	if policy.StaleAfterSeconds > 0 {
		staleAfter = time.Duration(policy.StaleAfterSeconds) * time.Second
	}
	if !policy.Enabled {
		health.Status = "unknown"
		health.Reasons = append(health.Reasons, "source_disabled")
		if status != nil && *status == "ok" {
			*status = "unknown"
		}
		if reasonSet != nil {
			reasonSet["source_disabled"] = struct{}{}
		}
	}
	return staleAfter
}

func applyHumanIdentitySourceStateHealth(health *HumanIdentitySourceHealth, state HumanIdentitySourceState, status *string, reasonSet map[string]struct{}) {
	if health == nil {
		return
	}
	if strings.TrimSpace(health.LatestImportRunID) == "" {
		health.LatestImportRunID = state.LastImportRunID
	}
	if strings.TrimSpace(health.ObservedAt) == "" {
		health.ObservedAt = state.LastSuccessAt
	}
	if state.Status == "error" {
		health.Status = "degraded"
		health.Reasons = append(health.Reasons, "source_import_error")
		if status != nil {
			*status = "degraded"
		}
		if reasonSet != nil {
			reasonSet["source_import_error"] = struct{}{}
		}
	}
}

func HumanIdentityImportRunDetailFromUsers(tenantID, importRunID string, users []model.HumanIdentity) (HumanIdentityImportRunDetailResponse, bool, error) {
	detail := HumanIdentityImportRunDetailResponse{
		TenantID:              tenantID,
		ImportRunID:           importRunID,
		Summary:               HumanIdentityImportRunSummary{ImportRunID: importRunID},
		UpsertedIdentities:    []model.HumanIdentity{},
		DeactivatedIdentities: []model.HumanIdentity{},
	}
	for _, user := range users {
		if user.TenantID != tenantID {
			continue
		}
		metadata := user.Metadata
		if metadata == nil {
			continue
		}
		if strings.TrimSpace(fmt.Sprint(metadata["import_run_id"])) == importRunID {
			detail.UpsertedIdentities = append(detail.UpsertedIdentities, user)
			detail.Summary.Upserted++
			if user.Status == "active" {
				detail.Summary.Active++
			}
			if user.Status == "deleted" {
				detail.Summary.Deleted++
			}
			updateHumanIdentityImportRunSummary(&detail.Summary, fmt.Sprint(metadata["import_source"]), fmt.Sprint(metadata["import_checkpoint"]), fmt.Sprint(metadata["imported_at"]))
		}
		if strings.TrimSpace(fmt.Sprint(metadata["deactivated_by_import_run_id"])) == importRunID {
			detail.DeactivatedIdentities = append(detail.DeactivatedIdentities, user)
			detail.Summary.Deactivated++
			if user.Status == "deleted" {
				detail.Summary.Deleted++
			}
			updateHumanIdentityImportRunSummary(&detail.Summary, fmt.Sprint(metadata["deactivated_by_import_source"]), fmt.Sprint(metadata["deactivated_by_import_checkpoint"]), fmt.Sprint(metadata["deactivated_at"]))
		}
	}
	sort.Slice(detail.UpsertedIdentities, func(i, j int) bool {
		return detail.UpsertedIdentities[i].ID < detail.UpsertedIdentities[j].ID
	})
	sort.Slice(detail.DeactivatedIdentities, func(i, j int) bool {
		return detail.DeactivatedIdentities[i].ID < detail.DeactivatedIdentities[j].ID
	})
	found := detail.Summary.Upserted > 0 || detail.Summary.Deactivated > 0
	return detail, found, nil
}

func summarizeHumanIdentitySources(users []model.HumanIdentity, tenantID string, now time.Time) []HumanIdentitySourceSummary {
	summaries := map[string]*HumanIdentitySourceSummary{}
	for _, user := range users {
		if strings.TrimSpace(user.TenantID) != strings.TrimSpace(tenantID) {
			continue
		}
		source := valueOrDefault(strings.TrimSpace(user.Source), "identity_directory")
		summary := summaries[source]
		if summary == nil {
			summary = &HumanIdentitySourceSummary{Source: source}
			summaries[source] = summary
		}
		summary.Total++
		switch strings.TrimSpace(user.Status) {
		case "active":
			if HumanIdentityIsActive(user, now) {
				summary.Active++
			} else {
				summary.Expired++
			}
		case "suspended":
			summary.Suspended++
		case "deleted":
			summary.Deleted++
		}
		updateHumanIdentitySourceSummary(summary, user.Metadata)
	}
	sources := make([]HumanIdentitySourceSummary, 0, len(summaries))
	for _, summary := range summaries {
		sources = append(sources, *summary)
	}
	sort.Slice(sources, func(i, j int) bool {
		return sources[i].Source < sources[j].Source
	})
	return sources
}

func updateHumanIdentitySourceSummary(summary *HumanIdentitySourceSummary, metadata map[string]any) {
	if summary == nil || metadata == nil {
		return
	}
	update := func(runID, observedAt string) {
		runID = strings.TrimSpace(runID)
		observedAt = strings.TrimSpace(observedAt)
		if runID == "<nil>" {
			runID = ""
		}
		if observedAt == "<nil>" {
			observedAt = ""
		}
		if observedAt != "" && observedAt >= summary.ObservedAt {
			summary.ObservedAt = observedAt
			if runID != "" {
				summary.LatestImportRunID = runID
			}
		}
	}
	update(fmt.Sprint(metadata["import_run_id"]), fmt.Sprint(metadata["imported_at"]))
	update(fmt.Sprint(metadata["deactivated_by_import_run_id"]), fmt.Sprint(metadata["deactivated_at"]))
}

func SummarizeHumanIdentityImportRuns(users []model.HumanIdentity, options HumanIdentityImportRunListOptions) []HumanIdentityImportRunSummary {
	options.Source = strings.TrimSpace(options.Source)
	if options.Limit <= 0 {
		options.Limit = 25
	}
	summaries := map[string]*HumanIdentityImportRunSummary{}
	for _, user := range users {
		metadata := user.Metadata
		if metadata == nil {
			continue
		}
		if importRunID := strings.TrimSpace(fmt.Sprint(metadata["import_run_id"])); importRunID != "" && importRunID != "<nil>" {
			if options.Source == "" || strings.TrimSpace(fmt.Sprint(metadata["import_source"])) == options.Source {
				summary := HumanIdentityImportRunSummaryFor(summaries, importRunID)
				summary.Upserted++
				if user.Status == "active" {
					summary.Active++
				}
				if user.Status == "deleted" {
					summary.Deleted++
				}
				updateHumanIdentityImportRunSummary(summary, fmt.Sprint(metadata["import_source"]), fmt.Sprint(metadata["import_checkpoint"]), fmt.Sprint(metadata["imported_at"]))
			}
		}
		if importRunID := strings.TrimSpace(fmt.Sprint(metadata["deactivated_by_import_run_id"])); importRunID != "" && importRunID != "<nil>" {
			if options.Source != "" && strings.TrimSpace(fmt.Sprint(metadata["deactivated_by_import_source"])) != options.Source {
				continue
			}
			summary := HumanIdentityImportRunSummaryFor(summaries, importRunID)
			summary.Deactivated++
			if user.Status == "deleted" {
				summary.Deleted++
			}
			updateHumanIdentityImportRunSummary(summary, fmt.Sprint(metadata["deactivated_by_import_source"]), fmt.Sprint(metadata["deactivated_by_import_checkpoint"]), fmt.Sprint(metadata["deactivated_at"]))
		}
	}
	runs := make([]HumanIdentityImportRunSummary, 0, len(summaries))
	for _, summary := range summaries {
		runs = append(runs, *summary)
	}
	sort.Slice(runs, func(i, j int) bool {
		if runs[i].ObservedAt != runs[j].ObservedAt {
			return runs[i].ObservedAt > runs[j].ObservedAt
		}
		return runs[i].ImportRunID > runs[j].ImportRunID
	})
	if options.Limit > 0 && len(runs) > options.Limit {
		runs = runs[:options.Limit]
	}
	return runs
}

func HumanIdentityImportRunSummaryFor(summaries map[string]*HumanIdentityImportRunSummary, importRunID string) *HumanIdentityImportRunSummary {
	if summary, ok := summaries[importRunID]; ok {
		return summary
	}
	summary := &HumanIdentityImportRunSummary{ImportRunID: importRunID}
	summaries[importRunID] = summary
	return summary
}

func updateHumanIdentityImportRunSummary(summary *HumanIdentityImportRunSummary, source, checkpoint, observedAt string) {
	source = strings.TrimSpace(source)
	checkpoint = strings.TrimSpace(checkpoint)
	observedAt = strings.TrimSpace(observedAt)
	if observedAt == "<nil>" {
		observedAt = ""
	}
	isLatest := observedAt != "" && observedAt >= summary.ObservedAt
	if source != "" && source != "<nil>" && (summary.Source == "" || isLatest || summary.ObservedAt == "") {
		summary.Source = source
	}
	if checkpoint != "" && checkpoint != "<nil>" && (summary.Checkpoint == "" || isLatest || summary.ObservedAt == "") {
		summary.Checkpoint = checkpoint
	}
	if isLatest {
		summary.ObservedAt = observedAt
	}
}

func NormalizeHumanIdentityDirectoryListOptions(options ...HumanIdentityDirectoryListOptions) HumanIdentityDirectoryListOptions {
	if len(options) == 0 {
		return HumanIdentityDirectoryListOptions{}
	}
	option := options[0]
	option.Source = strings.TrimSpace(option.Source)
	option.Status = strings.TrimSpace(option.Status)
	option.Subject = strings.TrimSpace(option.Subject)
	option.Email = strings.TrimSpace(option.Email)
	option.ImportRunID = strings.TrimSpace(option.ImportRunID)
	option.AfterID = strings.TrimSpace(option.AfterID)
	if option.Limit < 0 {
		option.Limit = 0
	}
	return option
}

func encodeHumanIdentityDirectoryCursor(afterID string) string {
	afterID = strings.TrimSpace(afterID)
	if afterID == "" {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString([]byte(afterID))
}

func DecodeHumanIdentityDirectoryCursor(cursor string) (string, error) {
	cursor = strings.TrimSpace(cursor)
	if cursor == "" {
		return "", nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return "", fmt.Errorf("human identity cursor is invalid")
	}
	afterID := strings.TrimSpace(string(decoded))
	if afterID == "" {
		return "", fmt.Errorf("human identity cursor is invalid")
	}
	return afterID, nil
}

func HumanIdentityDirectoryImport(ctx context.Context, store HumanIdentityDirectoryRuntimeStore, request HumanIdentityDirectoryImportRequest, tenantID string, now time.Time) (HumanIdentityDirectoryImportResponse, error) {
	source := strings.TrimSpace(request.Source)
	if source == "" {
		source = "directory_import"
	}
	importRunID, err := NormalizeHumanIdentityImportRunID(request.ImportRunID, now)
	if err != nil {
		return HumanIdentityDirectoryImportResponse{}, err
	}
	checkpoint, err := NormalizeHumanIdentitySourceCheckpoint(request.Checkpoint)
	if err != nil {
		return HumanIdentityDirectoryImportResponse{}, err
	}
	reconcileMissing := false
	if policy, ok, err := HumanIdentityDirectorySourcePolicyForSource(ctx, store, tenantID, source); err != nil {
		return HumanIdentityDirectoryImportResponse{}, fmt.Errorf("load human identity source policy: %w", err)
	} else if ok {
		if !policy.Enabled && !request.DryRun {
			return HumanIdentityDirectoryImportResponse{}, fmt.Errorf("human identity source %q is disabled by source policy", source)
		}
		reconcileMissing = policy.ReconcileMissing
	}
	if request.ReconcileMissing != nil {
		reconcileMissing = *request.ReconcileMissing
	}
	if len(request.Identities) == 0 {
		return HumanIdentityDirectoryImportResponse{}, fmt.Errorf("human identity import requires at least one identity")
	}
	if len(request.Identities) > MaxHumanIdentityImportItems {
		return HumanIdentityDirectoryImportResponse{}, fmt.Errorf("human identity import supports at most %d identities", MaxHumanIdentityImportItems)
	}
	upserted := make([]model.HumanIdentity, 0, len(request.Identities))
	seenIDs := map[string]struct{}{}
	for index, identity := range request.Identities {
		if strings.TrimSpace(identity.Source) == "" {
			identity.Source = source
		}
		identity.Metadata = copyHumanIdentityMetadata(identity.Metadata)
		identity.Metadata["import_run_id"] = importRunID
		identity.Metadata["import_source"] = source
		identity.Metadata["imported_at"] = now.UTC().Format(time.RFC3339)
		if checkpoint != "" {
			identity.Metadata["import_checkpoint"] = checkpoint
		}
		if reconcileMissing && strings.TrimSpace(identity.Source) != source {
			return HumanIdentityDirectoryImportResponse{}, fmt.Errorf("import human identity at index %d: source %q does not match reconcile source %q", index, identity.Source, source)
		}
		item, err := NormalizeHumanIdentity(identity, tenantID, now)
		if err != nil {
			return HumanIdentityDirectoryImportResponse{}, fmt.Errorf("import human identity at index %d: %w", index, err)
		}
		if _, ok := seenIDs[item.ID]; ok {
			return HumanIdentityDirectoryImportResponse{}, fmt.Errorf("import human identity at index %d: duplicate human identity id %q", index, item.ID)
		}
		upserted = append(upserted, item)
		seenIDs[item.ID] = struct{}{}
	}
	deactivated := []model.HumanIdentity{}
	if reconcileMissing {
		current, err := store.List(ctx, tenantID, HumanIdentityDirectoryListOptions{Source: source})
		if err != nil {
			return HumanIdentityDirectoryImportResponse{}, fmt.Errorf("list human identities for reconcile: %w", err)
		}
		for _, item := range current {
			if item.Status == "deleted" {
				continue
			}
			if _, ok := seenIDs[item.ID]; ok {
				continue
			}
			item.Metadata = copyHumanIdentityMetadata(item.Metadata)
			item.Status = "deleted"
			item.Metadata["deactivated_by_import_source"] = source
			item.Metadata["deactivated_by_import_run_id"] = importRunID
			item.Metadata["deactivated_at"] = now.UTC().Format(time.RFC3339)
			if checkpoint != "" {
				item.Metadata["deactivated_by_import_checkpoint"] = checkpoint
			}
			deactivated = append(deactivated, item)
		}
	}
	if !request.DryRun {
		writes := make([]model.HumanIdentity, 0, len(upserted)+len(deactivated))
		writes = append(writes, upserted...)
		writes = append(writes, deactivated...)
		updated, err := HumanIdentityDirectoryUpsertMany(ctx, store, writes, tenantID, now)
		if err != nil {
			return HumanIdentityDirectoryImportResponse{}, err
		}
		copy(upserted, updated[:len(upserted)])
		copy(deactivated, updated[len(upserted):])
	}
	active := 0
	for _, item := range upserted {
		if HumanIdentityIsActive(item, now) {
			active++
		}
	}
	response := HumanIdentityDirectoryImportResponse{
		TenantID:              strings.TrimSpace(tenantID),
		Source:                source,
		ImportRunID:           importRunID,
		Checkpoint:            checkpoint,
		DryRun:                request.DryRun,
		ReconcileMissing:      reconcileMissing,
		Requested:             len(request.Identities),
		Upserted:              len(upserted),
		Deactivated:           len(deactivated),
		ActiveCount:           active,
		Identities:            upserted,
		DeactivatedIdentities: deactivated,
	}
	if !request.DryRun {
		HumanIdentityDirectoryRecordSourceImport(ctx, store, response, now)
	}
	return response, nil
}

func HumanIdentityDirectoryRecordSourceImport(ctx context.Context, store HumanIdentityDirectoryRuntimeStore, response HumanIdentityDirectoryImportResponse, now time.Time) {
	recorder, ok := store.(HumanIdentitySourceStateRecorder)
	if !ok {
		return
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	state := HumanIdentitySourceState{
		TenantID:        strings.TrimSpace(response.TenantID),
		Source:          strings.TrimSpace(response.Source),
		Status:          "success",
		LastImportRunID: strings.TrimSpace(response.ImportRunID),
		Checkpoint:      strings.TrimSpace(response.Checkpoint),
		LastSuccessAt:   now.UTC().Format(time.RFC3339),
		Requested:       response.Requested,
		Upserted:        response.Upserted,
		Deactivated:     response.Deactivated,
		ActiveCount:     response.ActiveCount,
		UpdatedAt:       now.UTC().Format(time.RFC3339),
	}
	if err := recorder.RecordSourceImport(ctx, state); err != nil {
		log.Printf("human identity source import state record failed: %v", err)
	}
}

func HumanIdentityDirectoryRecordSourceImportError(ctx context.Context, store HumanIdentityDirectoryRuntimeStore, request HumanIdentityDirectoryImportRequest, tenantID string, importErr error, now time.Time) {
	recorder, ok := store.(HumanIdentitySourceStateRecorder)
	if !ok || importErr == nil {
		return
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	source := strings.TrimSpace(request.Source)
	if source == "" {
		source = "directory_import"
	}
	importRunID := strings.TrimSpace(request.ImportRunID)
	if importRunID != "" {
		if cleaned, err := CleanHumanIdentityImportRunID(importRunID); err == nil {
			importRunID = cleaned
		} else {
			importRunID = ""
		}
	}
	checkpoint, err := NormalizeHumanIdentitySourceCheckpoint(request.Checkpoint)
	if err != nil {
		checkpoint = ""
	}
	lastError := truncateHumanIdentitySourceStateError(importErr.Error())
	state := HumanIdentitySourceState{
		TenantID:        strings.TrimSpace(tenantID),
		Source:          source,
		Status:          "error",
		LastImportRunID: importRunID,
		Checkpoint:      checkpoint,
		LastErrorAt:     now.UTC().Format(time.RFC3339),
		LastError:       lastError,
		UpdatedAt:       now.UTC().Format(time.RFC3339),
	}
	if err := recorder.RecordSourceImport(ctx, state); err != nil {
		log.Printf("human identity source import error state record failed: %v", err)
	}
}

func HumanIdentityDirectoryUpsertMany(ctx context.Context, store HumanIdentityDirectoryRuntimeStore, items []model.HumanIdentity, tenantID string, now time.Time) ([]model.HumanIdentity, error) {
	if len(items) == 0 {
		return nil, nil
	}
	if bulk, ok := store.(HumanIdentityDirectoryBulkUpserter); ok {
		updated, err := bulk.UpsertMany(ctx, items, tenantID, now)
		if err != nil {
			return nil, fmt.Errorf("import human identities: %w", err)
		}
		return updated, nil
	}
	updated := make([]model.HumanIdentity, 0, len(items))
	for index, item := range items {
		next, err := store.Upsert(ctx, item, tenantID, now)
		if err != nil {
			return nil, fmt.Errorf("import human identity at index %d: %w", index, err)
		}
		updated = append(updated, next)
	}
	return updated, nil
}

func copyHumanIdentityMetadata(metadata map[string]any) map[string]any {
	next := map[string]any{}
	for key, value := range metadata {
		next[key] = value
	}
	return next
}

func NormalizeHumanIdentitySourceState(state HumanIdentitySourceState) (HumanIdentitySourceState, error) {
	state.TenantID = strings.TrimSpace(state.TenantID)
	state.Source = strings.TrimSpace(state.Source)
	state.Status = valueOrDefault(strings.TrimSpace(state.Status), "success")
	state.LastImportRunID = strings.TrimSpace(state.LastImportRunID)
	checkpoint, err := NormalizeHumanIdentitySourceCheckpoint(state.Checkpoint)
	if err != nil {
		return HumanIdentitySourceState{}, err
	}
	state.Checkpoint = checkpoint
	state.LastSuccessAt = strings.TrimSpace(state.LastSuccessAt)
	state.LastErrorAt = strings.TrimSpace(state.LastErrorAt)
	state.LastError = truncateHumanIdentitySourceStateError(state.LastError)
	state.UpdatedAt = strings.TrimSpace(state.UpdatedAt)
	if state.TenantID == "" {
		return HumanIdentitySourceState{}, fmt.Errorf("tenant_id is required")
	}
	if state.Source == "" {
		return HumanIdentitySourceState{}, fmt.Errorf("human identity source is required")
	}
	switch state.Status {
	case "success", "error", "unknown":
	default:
		return HumanIdentitySourceState{}, fmt.Errorf("unsupported human identity source state status %q", state.Status)
	}
	if err := validateHumanIdentityRFC3339String(state.LastSuccessAt, "last_success_at"); err != nil {
		return HumanIdentitySourceState{}, err
	}
	if err := validateHumanIdentityRFC3339String(state.LastErrorAt, "last_error_at"); err != nil {
		return HumanIdentitySourceState{}, err
	}
	if state.UpdatedAt == "" {
		state.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	if err := validateHumanIdentityRFC3339String(state.UpdatedAt, "updated_at"); err != nil {
		return HumanIdentitySourceState{}, err
	}
	if state.Requested < 0 || state.Upserted < 0 || state.Deactivated < 0 || state.ActiveCount < 0 {
		return HumanIdentitySourceState{}, fmt.Errorf("human identity source state counts must be non-negative")
	}
	return state, nil
}

func NormalizeHumanIdentitySourcePolicy(policy HumanIdentitySourcePolicy) (HumanIdentitySourcePolicy, error) {
	policy.TenantID = strings.TrimSpace(policy.TenantID)
	policy.Source = strings.TrimSpace(policy.Source)
	policy.ConnectorType = valueOrDefault(strings.TrimSpace(policy.ConnectorType), "generic")
	policy.UpdatedAt = strings.TrimSpace(policy.UpdatedAt)
	if policy.TenantID == "" {
		return HumanIdentitySourcePolicy{}, fmt.Errorf("tenant_id is required")
	}
	if policy.Source == "" {
		return HumanIdentitySourcePolicy{}, fmt.Errorf("human identity source is required")
	}
	if len(policy.Source) > maxHumanIdentitySourceNameLength {
		return HumanIdentitySourcePolicy{}, fmt.Errorf("human identity source must be at most %d characters", maxHumanIdentitySourceNameLength)
	}
	if strings.ContainsAny(policy.Source, "/\\") {
		return HumanIdentitySourcePolicy{}, fmt.Errorf("human identity source must not contain path separators")
	}
	switch policy.ConnectorType {
	case "generic", "scim", "oidc", "hris", "csv", "manual":
	default:
		return HumanIdentitySourcePolicy{}, fmt.Errorf("unsupported human identity source connector_type %q", policy.ConnectorType)
	}
	if policy.ExpectedIntervalSeconds < 0 || policy.StaleAfterSeconds < 0 {
		return HumanIdentitySourcePolicy{}, fmt.Errorf("human identity source policy intervals must be non-negative")
	}
	if policy.ExpectedIntervalSeconds > 0 && policy.ExpectedIntervalSeconds < 60 {
		return HumanIdentitySourcePolicy{}, fmt.Errorf("human identity source expected_interval_seconds must be at least 60")
	}
	if policy.StaleAfterSeconds > 0 && policy.StaleAfterSeconds < 60 {
		return HumanIdentitySourcePolicy{}, fmt.Errorf("human identity source stale_after_seconds must be at least 60")
	}
	if len(policy.Metadata) > maxHumanIdentitySourcePolicyMeta {
		return HumanIdentitySourcePolicy{}, fmt.Errorf("human identity source policy metadata supports at most %d keys", maxHumanIdentitySourcePolicyMeta)
	}
	policy.Metadata = copyHumanIdentityMetadata(policy.Metadata)
	if policy.UpdatedAt == "" {
		policy.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	if err := validateHumanIdentityRFC3339String(policy.UpdatedAt, "updated_at"); err != nil {
		return HumanIdentitySourcePolicy{}, err
	}
	return policy, nil
}

func truncateHumanIdentitySourceStateError(raw string) string {
	value := strings.TrimSpace(raw)
	if len(value) <= maxHumanIdentitySourceStateError {
		return value
	}
	return value[:maxHumanIdentitySourceStateError]
}

func NormalizeHumanIdentitySourceCheckpoint(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if len(value) > MaxHumanIdentitySourceCheckpoint {
		return "", fmt.Errorf("human identity source checkpoint must be at most %d characters", MaxHumanIdentitySourceCheckpoint)
	}
	return value, nil
}

func validateHumanIdentityRFC3339String(value, field string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	if _, err := time.Parse(time.RFC3339, value); err != nil {
		return fmt.Errorf("human identity source state %s must be RFC3339", field)
	}
	return nil
}

func NormalizeHumanIdentityImportRunID(raw string, now time.Time) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return newDirectoryID("human_import_", now), nil
	}
	return CleanHumanIdentityImportRunID(value)
}

func CleanHumanIdentityImportRunID(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", fmt.Errorf("human identity import_run_id is required")
	}
	if len(value) > MaxHumanIdentityImportRunIDLength {
		return "", fmt.Errorf("human identity import_run_id must be at most %d characters", MaxHumanIdentityImportRunIDLength)
	}
	for _, char := range value {
		if !HumanIdentityImportRunIDCharAllowed(char) {
			return "", fmt.Errorf("human identity import_run_id contains unsupported character %q", char)
		}
	}
	return value, nil
}

func HumanIdentityImportRunIDCharAllowed(char rune) bool {
	return (char >= 'a' && char <= 'z') ||
		(char >= 'A' && char <= 'Z') ||
		(char >= '0' && char <= '9') ||
		char == '_' ||
		char == '-' ||
		char == '.' ||
		char == ':' ||
		char == '@'
}

func NormalizeHumanIdentity(user model.HumanIdentity, tenantID string, now time.Time) (model.HumanIdentity, error) {
	user.TenantID = strings.TrimSpace(user.TenantID)
	tenantID = strings.TrimSpace(tenantID)
	if tenantID != "" {
		if user.TenantID != "" && user.TenantID != tenantID {
			return model.HumanIdentity{}, fmt.Errorf("human identity tenant_id %s does not match admin tenant_id %s", user.TenantID, tenantID)
		}
		user.TenantID = tenantID
	}
	user.ID = strings.TrimSpace(user.ID)
	user.Subject = strings.TrimSpace(user.Subject)
	if user.TenantID == "" {
		return model.HumanIdentity{}, fmt.Errorf("tenant_id is required")
	}
	if user.ID == "" {
		return model.HumanIdentity{}, fmt.Errorf("human identity id is required")
	}
	if user.Subject == "" {
		return model.HumanIdentity{}, fmt.Errorf("human identity subject is required")
	}
	user.Source = valueOrDefault(strings.TrimSpace(user.Source), "identity_directory")
	user.Status = valueOrDefault(strings.TrimSpace(user.Status), "active")
	if !HumanIdentityStatusAllowed(user.Status) {
		return model.HumanIdentity{}, fmt.Errorf("unsupported human identity status %q", user.Status)
	}
	user.Email = trimOptionalString(user.Email)
	user.DisplayName = trimOptionalString(user.DisplayName)
	user.Department = trimOptionalString(user.Department)
	if err := validateOptionalRFC3339(user.LastSeenAt, "last_seen_at"); err != nil {
		return model.HumanIdentity{}, err
	}
	if err := validateOptionalRFC3339(user.ExpiresAt, "expires_at"); err != nil {
		return model.HumanIdentity{}, err
	}
	user.LastSeenAt = normalizeOptionalRFC3339String(user.LastSeenAt)
	user.ExpiresAt = normalizeOptionalRFC3339String(user.ExpiresAt)
	if user.Metadata == nil {
		user.Metadata = map[string]any{}
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	return user, nil
}

func HumanIdentityStatusAllowed(status string) bool {
	switch strings.TrimSpace(status) {
	case "active", "suspended", "deleted":
		return true
	default:
		return false
	}
}

func HumanIdentityIsActive(user model.HumanIdentity, now time.Time) bool {
	if strings.TrimSpace(user.Status) != "active" {
		return false
	}
	if user.ExpiresAt == nil || strings.TrimSpace(*user.ExpiresAt) == "" {
		return true
	}
	parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(*user.ExpiresAt))
	if err != nil {
		return false
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	return parsed.UTC().After(now.UTC())
}

func HumanIdentityDirectoryKey(tenantID, id string) string {
	return strings.TrimSpace(tenantID) + "\x00" + strings.TrimSpace(id)
}

func trimOptionalString(value *string) *string {
	if value == nil {
		return nil
	}
	trimmed := strings.TrimSpace(*value)
	if trimmed == "" {
		return nil
	}
	return &trimmed
}

func normalizeOptionalRFC3339String(value *string) *string {
	value = trimOptionalString(value)
	if value == nil {
		return nil
	}
	parsed, err := time.Parse(time.RFC3339, *value)
	if err != nil {
		return value
	}
	normalized := parsed.UTC().Format(time.RFC3339)
	return &normalized
}

// newDirectoryID mints a random id with the given prefix (import-run / record ids). crypto/rand with a
// timestamp fallback. Package-local so the directory store carries no edge-glue dependency.
func newDirectoryID(prefix string, fallback time.Time) string {
	var random [16]byte
	if _, err := rand.Read(random[:]); err == nil {
		return prefix + hex.EncodeToString(random[:])
	}
	return prefix + strconv.FormatInt(fallback.UnixNano(), 16)
}
