package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/grantstore"
	"github.com/lantern-networks/dsse-core/tenantca"
)

// registerGrantReportRoute receives the grants an Edge minted, so the authority holds what the fleet has
// approved — and so a revocation authored here reaches every node through the config bundle.
//
// ★ SAME RULES AS THE CONNECTOR REPORT NEXT DOOR. A node that PULLS its configuration is not the authority
// for this and must not receive it; the reporting node is identified by the client certificate it presents;
// and the receiver RECORDS rather than re-decides — the ceremony already happened, against an identity
// provider this deployment registered, and this says what it produced.
func registerGrantReportRoute(mux *http.ServeMux, grants *grantstore.Store,
	tenantCARegistry *tenantca.TenantCARegistry, configSourceURL string, devMode bool) {
	if grants == nil || strings.TrimSpace(configSourceURL) != "" {
		return
	}
	mux.HandleFunc("POST /grant-report", func(w http.ResponseWriter, r *http.Request) {
		if _, verified := auditIngestShipperFrom(r, tenantCARegistry); !verified && !devMode {
			writeError(w, http.StatusForbidden, fmt.Errorf("grant-report: this request presents no Edge "+
				"certificate, so these grants could not be attributed to a node"))
			return
		}
		var body struct {
			Grants []grantstore.Grant `json:"grants"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10)).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("grant-report: %w", err))
			return
		}
		added, updated := grants.Merge(body.Grants, time.Now().UTC())
		if added > 0 {
			log.Printf("grant_report_recorded added=%d updated=%d — the authority now holds them, so every "+
				"Edge learns of them and a revocation reaches all of them", added, updated)
		}
		writeJSON(w, http.StatusOK, map[string]any{"added": added, "updated": updated})
	})
}
