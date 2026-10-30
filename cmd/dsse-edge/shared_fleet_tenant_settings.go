package main

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
)

func sharedFleetSettingsRegions(config serverConfig) []string {
	if os.Getenv("DSSE_TOPOLOGY_PROFILE") != "three-regions-multi-edge" || strings.TrimSpace(config.EntrancePortalOrigins) == "" {
		return nil
	}
	return config.RegionEndpoints.regionIDs()
}

func sharedFleetRestrictsRegions(allowed, fleet []string) bool {
	if len(allowed) == 0 || len(fleet) == 0 {
		return false
	}
	set := map[string]bool{}
	for _, region := range allowed {
		set[strings.ToLower(strings.TrimSpace(region))] = true
	}
	for _, region := range fleet {
		if !set[strings.ToLower(region)] {
			return true
		}
	}
	return false
}

// Region boundaries stay in force. Saving a boundary incompatible with this
// global L4 pool requires an explicit acknowledgment of the availability loss.
func confirmSharedFleetTenantChange(w http.ResponseWriter, r *http.Request, config serverConfig, store adminTenantModelRuntimeStore, tenant adminTenantModel, raw []byte, creating bool) bool {
	regions := sharedFleetSettingsRegions(config)
	if os.Getenv("DSSE_TOPOLOGY_PROFILE") != "three-regions-multi-edge" || strings.TrimSpace(config.EntrancePortalOrigins) == "" || len(tenant.AllowedRegions) == 0 {
		return true
	}
	if !creating {
		previous, err := store.Get(r.Context(), tenant.TenantID)
		if err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "Tenant settings unavailable; no Region change was saved."})
			return false
		}
		if sameRegionSet(previous.AllowedRegions, tenant.AllowedRegions) {
			return true
		}
	}
	if len(regions) == 0 {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "Shared-fleet Region inventory unavailable; no Region change was saved."})
		return false
	}
	if !sharedFleetRestrictsRegions(tenant.AllowedRegions, regions) {
		return true
	}
	var confirmation struct {
		Acknowledged bool `json:"acknowledge_shared_fleet_residency_impact"`
	}
	if json.Unmarshal(raw, &confirmation) == nil && confirmation.Acknowledged {
		return true
	}
	writeJSON(w, http.StatusConflict, map[string]any{
		"error": "This deployment sends new connections to Edges in every Region. Edges outside these allowed Regions will refuse this tenant, so some new connections may fail. Use a separately scoped pool or explicitly acknowledge this availability impact; Region restrictions will not be widened.",
		"code":  "shared_fleet_residency_confirmation_required", "shared_fleet_regions": regions,
	})
	return false
}

func sameRegionSet(a, b []string) bool {
	set := func(values []string) map[string]bool {
		out := map[string]bool{}
		for _, v := range values {
			out[strings.ToLower(strings.TrimSpace(v))] = true
		}
		return out
	}
	left, right := set(a), set(b)
	if len(left) != len(right) {
		return false
	}
	for key := range left {
		if !right[key] {
			return false
		}
	}
	return true
}

type sharedFleetTenantView struct {
	adminTenantModel
	SharedFleetRegions []string `json:"shared_fleet_regions,omitempty"`
	SharedFleetWarning string   `json:"shared_fleet_warning,omitempty"`
}

func tenantSharedFleetView(config serverConfig, tenant adminTenantModel) sharedFleetTenantView {
	regions := sharedFleetSettingsRegions(config)
	view := sharedFleetTenantView{adminTenantModel: tenant, SharedFleetRegions: regions}
	if sharedFleetRestrictsRegions(tenant.AllowedRegions, regions) {
		view.SharedFleetWarning = "Some new connections may be refused: this shared pool includes Edges outside the tenant's allowed Regions. The existing Region boundary remains enforced."
	}
	return view
}
