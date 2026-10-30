package main

import (
	"flag"
	"net/http"

	"github.com/lantern-networks/dsse-core/dlp"
)

// Process resource settings belong beside this feature, outside main.go's
// frozen flag and route registrations. Register before flag.Parse.
func registerDLPRetentionFlags() (perStream, process *int64) {
	perStream = flag.Int64("dlp-retention-per-stream-bytes", 64<<20, "streaming DLP Guard undecided-body resource budget per upload, including encrypted file overhead and working buffers; 0 uses the protected 64 MiB default, never unlimited; not a transfer-size limit")
	process = flag.Int64("dlp-retention-process-bytes", 512<<20, "shared streaming DLP Guard undecided-body resource budget for this Edge process; 0 uses the protected 512 MiB default, never unlimited; exhausted uploads alone are refused")
	return perStream, process
}

func registerDLPRetentionStatusRoute(mux *http.ServeMux, adminEndpoint func(string, http.HandlerFunc) http.HandlerFunc, budget *dlp.RetentionBudget, operatorTenant string) {
	mux.HandleFunc("GET /admin/dlp-retention-status", adminEndpoint("admin.state.read", func(w http.ResponseWriter, r *http.Request) {
		if !authorizeFleetConfigurationRead(w, r, operatorTenant) {
			return
		}
		writeJSON(w, http.StatusOK, budget.Status())
	}))
}
