package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/model"
	"strings"
	"time"
)

// ErrReceivedRuntimeCache means live controls were applied, but their node-local
// restart cache is unconfirmed. Callers must retry without blocking later sections.
var ErrReceivedRuntimeCache = errors.New("live controls applied; received runtime cache save unconfirmed")

// ApplyReceivedBundle applies authoritative controls even when their node-local
// restart cache cannot be saved. Until retry succeeds, restart may load stale
// controls. A shared author store must never receive this snapshot.
// Policies themselves still follow the existing bundle/authored-policy lifecycle.
func (store *Store) ApplyReceivedBundle(tenant string, policies []model.Policy, cfg TenantConfigBundle, now time.Time) (int, error) {
	tenant = strings.TrimSpace(tenant)
	if store == nil || tenant == "" {
		return 0, fmt.Errorf("received bundle tenant is required")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	switch store.runtimeStatePersister.(type) {
	case contextRuntimePersister, atomicRuntimeStatePersister:
		return 0, fmt.Errorf("received runtime controls require a node-local cache")
	}
	raw, err := json.Marshal(store.runtimeSnapshotLocked())
	if err != nil {
		return 0, err
	}
	state, _, err := decodeRuntimeState(raw)
	if err != nil {
		return 0, err
	}
	candidate := NewStore(nil)
	candidate.adoptRuntimeLocked(state)
	candidate.applyTenantConfigLocked(tenant, cfg)
	raw, err = json.Marshal(candidate.runtimeSnapshotLocked())
	if err != nil {
		return 0, err
	}
	var cacheErr error
	if p := store.runtimeStatePersister; p != nil {
		err = p.Save(raw)
		if err != nil && (!errors.Is(err, blobstore.ErrSavedWithoutAtomicity) || errors.Is(err, blobstore.ErrDurabilityUnconfirmed)) {
			cacheErr = fmt.Errorf("%w: %w: %v", ErrPolicyPersistence, ErrReceivedRuntimeCache, err)
		}
	}
	n := store.replacePoliciesLocked(tenant, policies, now)
	store.applyTenantConfigLocked(tenant, cfg)
	store.generation++
	store.rebuildPolicyCacheLocked()
	return n, cacheErr
}
