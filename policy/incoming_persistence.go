package policy

import (
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
	if store == nil {
		return ErrPolicyPersistence
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	tenantID = strings.TrimSpace(tenantID)
	list := append([]model.LegacyException(nil), store.legacyExceptions[tenantID]...)
	replaced := false
	for i := range list {
		if list[i].ID == ex.ID {
			list[i] = ex
			replaced = true
			break
		}
	}
	if !replaced {
		list = append(list, ex)
	}
	return store.saveIncomingExceptionsLocked(tenantID, list)
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
