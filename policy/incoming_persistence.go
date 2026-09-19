package policy

import (
	"fmt"
	"github.com/lantern-networks/dsse-core/model"
	"log"
	"strings"
)

// Candidate fields are protected by mu until storage confirms the change.
func (store *Store) SetServerInitiatedEnabledConfirmed(tenantID string, enabled bool) error {
	if store == nil {
		return ErrPolicyPersistence
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	before := store.serverInitiatedEnabled
	next := make(map[string]bool, len(before)+1)
	for k, v := range before {
		next[k] = v
	}
	next[strings.TrimSpace(tenantID)] = enabled
	store.serverInitiatedEnabled = next
	if err := store.persistLockedChecked(); err != nil {
		store.serverInitiatedEnabled = before
		log.Printf("incoming setting save: %v", err)
		return ErrPolicyPersistence
	}
	store.generation++
	return nil
}

func (store *Store) UpsertLegacyExceptionConfirmed(tenantID string, ex model.LegacyException) error {
	_, err := store.MutateLegacyExceptionConfirmed(tenantID, ex.ID, func(model.LegacyException) (model.LegacyException, error) { return ex, nil })
	return err
}

// MutateLegacyExceptionConfirmed merges against the current record under the same
// lock used to persist it. Concurrent partial edits cannot erase each other's fields.
// The callback must not call back into the store.
func (store *Store) MutateLegacyExceptionConfirmed(tenantID, id string, mutate func(model.LegacyException) (model.LegacyException, error)) (model.LegacyException, error) {
	if store == nil {
		return model.LegacyException{}, ErrPolicyPersistence
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	tenantID = strings.TrimSpace(tenantID)
	list := append([]model.LegacyException(nil), store.legacyExceptions[tenantID]...)
	index := -1
	current := model.LegacyException{ID: id, TenantID: tenantID, Status: "active"}
	for i := range list {
		if list[i].ID == id {
			index = i
			current = list[i]
			break
		}
	}
	candidate, err := mutate(current)
	if err != nil {
		return model.LegacyException{}, err
	}
	if candidate.ID != id {
		return model.LegacyException{}, fmt.Errorf("exception identity cannot change during update")
	}
	candidate.TenantID = tenantID
	if index < 0 {
		list = append(list, candidate)
	} else {
		list[index] = candidate
	}
	if err := store.saveIncomingExceptionsLocked(tenantID, list); err != nil {
		return model.LegacyException{}, err
	}
	return candidate, nil
}

func (store *Store) RemoveLegacyExceptionConfirmed(tenantID, id string) (bool, error) {
	if store == nil {
		return false, ErrPolicyPersistence
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	tenantID = strings.TrimSpace(tenantID)
	id = strings.TrimSpace(id)
	list := store.legacyExceptions[tenantID]
	for i := range list {
		if list[i].ID == id {
			next := append([]model.LegacyException(nil), list[:i]...)
			next = append(next, list[i+1:]...)
			if err := store.saveIncomingExceptionsLocked(tenantID, next); err != nil {
				return false, err
			}
			return true, nil
		}
	}
	return false, nil
}

func (store *Store) saveIncomingExceptionsLocked(tenant string, list []model.LegacyException) error {
	before := store.legacyExceptions
	next := make(map[string][]model.LegacyException, len(before)+1)
	for k, v := range before {
		next[k] = v
	}
	next[tenant] = list
	store.legacyExceptions = next
	if err := store.persistLockedChecked(); err != nil {
		store.legacyExceptions = before
		log.Printf("incoming exception save: %v", err)
		return ErrPolicyPersistence
	}
	store.generation++
	return nil
}
