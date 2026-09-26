package main

import (
	"fmt"
	"github.com/lantern-networks/dsse-core/assetcatalog"
	"github.com/lantern-networks/dsse-core/policyrule"
	"net/http"
)

func refreshAuthoredStores(w http.ResponseWriter, rules *policyrule.Store, assets *assetcatalog.Store) bool {
	if err := rules.RefreshShared(); err != nil {
		writeError(w, http.StatusServiceUnavailable, fmt.Errorf("authored rules or assets unavailable"))
		return false
	}
	if err := assets.RefreshShared(); err != nil {
		writeError(w, http.StatusServiceUnavailable, fmt.Errorf("authored rules or assets unavailable"))
		return false
	}
	return true
}
