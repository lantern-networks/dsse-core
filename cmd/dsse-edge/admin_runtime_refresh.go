package main

import (
	"github.com/lantern-networks/dsse-core/policy"
	"net/http"
)

func refreshRuntimeManagement(w http.ResponseWriter, s policy.RuntimeStore) bool {
	if shared, ok := s.(interface{ RefreshSharedRuntime() error }); ok {
		if err := shared.RefreshSharedRuntime(); err != nil {
			writeError(w, http.StatusServiceUnavailable, policy.ErrPolicyPersistence)
			return false
		}
	}
	return true
}
