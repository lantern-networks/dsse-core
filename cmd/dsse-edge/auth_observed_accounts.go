package main

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/idpregistry"
)

const maxObservedAuthAccountsPerDevice = 32

// A candidate list is bounded, but it must continue to admit new users on a
// shared workstation. Re-observing an existing candidate updates its display
// name without changing the order; a newly observed principal replaces the
// oldest candidate when the list is full. This is never an authorization grant.
func (e *deviceRuntimeInfo) observeAuthAccount(principal, display string) {
	if e.authAccounts == nil {
		e.authAccounts = map[string]string{}
	}
	if _, exists := e.authAccounts[principal]; exists {
		e.authAccounts[principal] = display
		return
	}
	if len(e.authAccounts) == maxObservedAuthAccountsPerDevice {
		if len(e.authAccountOrder) == 0 {
			e.authAccountOrder = parseObservedAuthAccountOrder(nil, e.authAccounts)
		}
		delete(e.authAccounts, e.authAccountOrder[0])
		e.authAccountOrder = e.authAccountOrder[1:]
	}
	e.authAccounts[principal] = display
	e.authAccountOrder = append(e.authAccountOrder, principal)
}

// Older device-state rows have no order. Restore them deterministically, and
// ignore duplicates or principals that are not present in the validated rows.
func parseObservedAuthAccountOrder(value any, accounts map[string]string) []string {
	order := make([]string, 0, len(accounts))
	seen := make(map[string]bool, len(accounts))
	appendValid := func(principal string) {
		if _, ok := accounts[principal]; ok && !seen[principal] {
			order = append(order, principal)
			seen[principal] = true
		}
	}
	switch typed := value.(type) {
	case []string:
		for _, principal := range typed {
			appendValid(principal)
		}
	case []any:
		for _, raw := range typed {
			if principal, ok := raw.(string); ok {
				appendValid(principal)
			}
		}
	}
	missing := make([]string, 0, len(accounts)-len(order))
	for principal := range accounts {
		if !seen[principal] {
			missing = append(missing, principal)
		}
	}
	sort.Strings(missing)
	return append(order, missing...)
}

// An observed account is a picker candidate, not authorization evidence. The
// administrator still has to match it to a verified IdP subject explicitly.
type observedAuthAccount struct {
	DeviceID    string `json:"device_id"`
	OSPrincipal string `json:"os_principal"`
	DisplayName string `json:"display_name"`
	ObservedAt  string `json:"observed_at"`
}

func observedAuthAccountRows(accounts map[string]string) []map[string]string {
	rows := make([]map[string]string, 0, len(accounts))
	for principal, display := range accounts {
		if idpregistry.ValidOSPrincipal(principal) && display != "" {
			rows = append(rows, map[string]string{"os_principal": principal, "display_name": display})
		}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i]["os_principal"] < rows[j]["os_principal"] })
	return rows
}

func observedAuthAccountSignature(accounts map[string]string) string {
	rows := observedAuthAccountRows(accounts)
	parts := make([]string, 0, len(rows))
	for _, row := range rows {
		parts = append(parts, row["os_principal"]+"\x00"+row["display_name"])
	}
	return strings.Join(parts, "\x1e")
}

func parseObservedAuthAccountRows(value any) map[string]string {
	result := map[string]string{}
	var rows []any
	switch typed := value.(type) {
	case []any:
		rows = typed
	case []map[string]string:
		for _, row := range typed {
			rows = append(rows, map[string]any{"os_principal": row["os_principal"], "display_name": row["display_name"]})
		}
	case []map[string]any:
		for _, row := range typed {
			rows = append(rows, row)
		}
	default:
		return result
	}
	if len(rows) > maxObservedAuthAccountsPerDevice {
		return result
	}
	for _, raw := range rows {
		row, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		principal, _ := row["os_principal"].(string)
		display, _ := row["display_name"].(string)
		display = sanitizeRuntimeField(display, 128)
		if idpregistry.ValidOSPrincipal(principal) && display != "" {
			result[principal] = display
		}
	}
	return result
}

func (s *endpointRuntimeStore) observedAuthAccounts(tenant string) []observedAuthAccount {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []observedAuthAccount
	for device, e := range s.m {
		if e.tenant != tenant {
			continue
		}
		for principal, display := range e.authAccounts {
			out = append(out, observedAuthAccount{DeviceID: device, OSPrincipal: principal, DisplayName: display, ObservedAt: rfc3339OrEmpty(e.lastSeen)})
		}
	}
	return out
}

func fleetObservedAuthAccounts(local []observedAuthAccount, projection *fleetDeviceProjection, tenant string) ([]observedAuthAccount, bool) {
	rows, seeded := projection.Devices(tenant)
	accounts := map[string]observedAuthAccount{}
	for _, row := range rows {
		for principal, display := range row.AuthAccounts {
			account := observedAuthAccount{DeviceID: row.DeviceID, OSPrincipal: principal, DisplayName: display, ObservedAt: row.Timestamp}
			accounts[row.DeviceID+"\x00"+principal] = account
		}
	}
	for _, account := range local {
		key := account.DeviceID + "\x00" + account.OSPrincipal
		if old, ok := accounts[key]; !ok || newerObservedAuthAccount(account, old) {
			accounts[key] = account
		}
	}
	out := make([]observedAuthAccount, 0, len(accounts))
	for _, account := range accounts {
		out = append(out, account)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].DeviceID != out[j].DeviceID {
			return out[i].DeviceID < out[j].DeviceID
		}
		return out[i].OSPrincipal < out[j].OSPrincipal
	})
	return out, seeded
}

func newerObservedAuthAccount(a, b observedAuthAccount) bool {
	at, ae := time.Parse(time.RFC3339, a.ObservedAt)
	bt, be := time.Parse(time.RFC3339, b.ObservedAt)
	return ae == nil && (be != nil || !at.Before(bt))
}

// OS principals are deliberately absent from the general device-runtime view.
// Only identity administrators may read verified-tenant candidates for an
// explicit assignment to a directory subject.
func registerObservedAuthAccountRoutes(mux *http.ServeMux, adminEndpoint func(string, http.HandlerFunc) http.HandlerFunc, noHotStore bool) {
	mux.HandleFunc("GET /admin/auth-observed-accounts", adminEndpoint("admin.identity.read", func(w http.ResponseWriter, r *http.Request) {
		tenant := adminTenantIDFromRequest(r)
		if tenant == "" {
			writeError(w, http.StatusBadRequest, fmt.Errorf("tenant is required"))
			return
		}
		local := deviceRuntime.observedAuthAccounts(tenant)
		accounts, seeded := fleetObservedAuthAccounts(local, fleetDeviceProjectionStore, tenant)
		writeJSON(w, http.StatusOK, map[string]any{
			"tenant_id":  tenant,
			"fleet_wide": noHotStore || seeded,
			"accounts":   accounts,
		})
	}))
}
