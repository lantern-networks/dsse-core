package main

import (
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

// Existing tests build healthy stores through these helpers. Failure tests call
// the checked production constructor directly.
func newDurableAdminTenantModelStore(bundle model.PolicyBundle, now time.Time, path string) *adminTenantModelStore {
	return newOperatorAwareAdminTenantModelStore(bundle, now, path, "")
}
func newOperatorAwareAdminTenantModelStore(bundle model.PolicyBundle, now time.Time, path, operator string) *adminTenantModelStore {
	store, err := openAdminTenantModelStore(bundle, now, path, operator)
	if err != nil {
		panic(err)
	}
	return store
}
