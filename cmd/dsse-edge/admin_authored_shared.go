package main

import (
	"github.com/lantern-networks/dsse-core/assetcatalog"
	"github.com/lantern-networks/dsse-core/policyrule"
	"net/http"
)

func refreshAuthoredStores(w http.ResponseWriter, rules *policyrule.Store, assets *assetcatalog.Store) bool {
	if err := rules.RefreshShared(); err != nil {
		writeError(w, http.StatusServiceUnavailable, err)
		return false
	}
	if err := assets.RefreshShared(); err != nil {
		writeError(w, http.StatusServiceUnavailable, err)
		return false
	}
	return true
}
