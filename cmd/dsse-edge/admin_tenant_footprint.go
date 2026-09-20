package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/agentrollout"
	"github.com/lantern-networks/dsse-core/delegatedgrant"
	"github.com/lantern-networks/dsse-core/enrolledinventory"
	"github.com/lantern-networks/dsse-core/enrolltoken"
	"github.com/lantern-networks/dsse-core/grantstore"
	"github.com/lantern-networks/dsse-core/humanapproval"
	"github.com/lantern-networks/dsse-core/idpregistry"
	"github.com/lantern-networks/dsse-core/knownbypass"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/policycandidate"
	"github.com/lantern-networks/dsse-core/policyrule"
	"github.com/lantern-networks/dsse-core/revocation"
	"github.com/lantern-networks/dsse-core/seatallocation"
	"github.com/lantern-networks/dsse-core/tenantca"
	"github.com/lantern-networks/dsse-core/vlan"
)

// The tenant DATA FOOTPRINT: how much of a tenant is still here, per store, on this node.
//
// ★ WHY THIS EXISTS BEFORE ANY ERASURE (2026-08-15). A customer whose contract ends will ask for its data to
// be erased, and the answer has to be checkable. The data is not in one place — the lab measurement found 25
// tenant-keyed Postgres tables, two ClickHouse tables, per-tenant log directories on EVERY Edge's disk, object
// storage, and both planes' durable state. An erasure that reports "done" without being able to say what is
// left is a claim nobody can verify, and the residue is already visible: the log directory of a tenant renamed
// weeks ago is still sitting on the Edge because nothing ever cleaned it up.
//
// So counting comes first. This is what an operator runs BEFORE erasing (what is there), and again AFTER
// (nothing left) — the same number from the same code, which is the only kind of before/after worth having.
//
// It declares its own coverage. Every store this node cannot reach is named in NotCounted rather than left
// out, because a footprint that silently omits a store reads as "nothing there" for exactly the store that
// still holds everything.
type adminTenantFootprint struct {
	TenantID string `json:"tenant_id"`
	// Node identifies WHICH node this footprint describes. A tenant's logs live on every Edge that served it,
	// so one node's zero is not the fleet's zero.
	Node       string                    `json:"node"`
	CountedAt  string                    `json:"counted_at"`
	Stores     []adminTenantFootprintRow `json:"stores"`
	Total      int64                     `json:"total"`
	NotCounted []string                  `json:"not_counted"`
}

type adminTenantFootprintRow struct {
	Store string `json:"store"`
	// Count is the number of records/files. -1 means the store was reachable but the count FAILED, which is
	// different from zero and must never be rendered as "clean".
	Count int64  `json:"count"`
	Error string `json:"error,omitempty"`
	Note  string `json:"note,omitempty"`
}

// adminTenantFootprintPostgresTables is every table carrying a tenant_id column, as measured on the reference
// lab on 2026-08-15. It is written out rather than discovered so that a table ADDED later and not listed here
// shows up as a gap in review — the alternative (query information_schema) silently keeps working while the
// purge that reads this list silently misses the new table.
//
// The list is asserted against the live schema by TestTenantFootprintCoversEveryTenantKeyedTable, so adding a
// tenant-keyed table without adding it here fails that test rather than quietly shrinking what "complete"
// means.
// ★ AND THE GATE IMMEDIATELY EARNED ITS KEEP. The list started as what the reference lab's live database
// actually had — 25 tables — and the schema scan found four more: device_inventory, agent_status_events,
// agent_update_events and admin_tenant_model_deletions. They are absent from the lab because their Postgres
// backends are not switched on there. So measuring the RUNNING system, which is normally the honest thing to
// do, would have shipped a purge that silently skipped a customer's device inventory and agent telemetry —
// exactly the data an erasure request is about. A deployment is a subset of the schema, and "complete" has to
// be defined against the schema.
var adminTenantFootprintPostgresTables = []string{
	"admin_api_tokens",
	"admin_audit_outbox",
	"admin_export_jobs",
	"admin_local_credentials",
	"admin_principals",
	"admin_sessions",
	"admin_sites",
	"admin_tenant_models",
	// The tombstone table. Counted like anything else, but an erasure must treat it LAST and deliberately:
	// removing a tenant's tombstone before every Edge has applied it un-deletes the tenant on whichever node
	// had not caught up.
	"admin_tenant_model_deletions",
	// The erasure orders (migration 041). Same treatment as the tombstone above and for the same reason — it is
	// the other half of what this node tells the fleet about a terminated tenant, and dropping it before the
	// rest of the erasure has succeeded leaves nodes that have not caught up with nothing to act on.
	"admin_tenant_model_purge_orders",
	"agent_status_events",
	"agent_update_events",
	"application_catalog",
	"config_versions",
	"connector_registrations",
	"device_inventory",
	"domain_event_outbox",
	"enrolled_identity_claims",
	"enrolment_tokens",
	"export_worker_task_dead_letters",
	"export_worker_tasks",
	"hot_events",
	"human_identities",
	"human_identity_source_policies",
	"human_identity_source_states",
	"non_human_identities",
	"observed_steer_exclusions",
	"internal_certificate_authorities",
	"steer_exclusion_policies",
	"usage_meter_records",
	"workload_attestation_nonces",
}

// countAdminTenantFootprint counts what this node still holds for a tenant. It never fails as a whole: a store
// that cannot be counted contributes a row with its error, because "one store is unreachable" must not erase
// the counts from the others.
func countAdminTenantFootprint(ctx context.Context, node, tenantID string, db *sql.DB, writer *logs.Writer,
	credentials *localAdminCredentialStore, ledger *enrolledinventory.Ledger, rules *policyrule.Store,
	deviceCAs *tenantca.TenantCARegistry, namedNetworks *vlan.Store, extra adminTenantExtraStores, now time.Time) adminTenantFootprint {

	footprint := adminTenantFootprint{
		TenantID:   strings.TrimSpace(tenantID),
		Node:       strings.TrimSpace(node),
		CountedAt:  now.UTC().Format(time.RFC3339),
		Stores:     []adminTenantFootprintRow{},
		NotCounted: []string{},
	}
	if footprint.TenantID == "" {
		return footprint
	}

	if credentials != nil {
		footprint.add(adminTenantFootprintRow{Store: "admin_accounts", Count: int64(len(credentials.List(footprint.TenantID)))})
	} else {
		footprint.NotCounted = append(footprint.NotCounted, "admin_accounts (no local credential store on this node)")
	}

	if ledger != nil {
		footprint.add(adminTenantFootprintRow{Store: "enrolled_identities", Count: int64(ledger.CountTenantRecords(footprint.TenantID))})
	} else {
		footprint.NotCounted = append(footprint.NotCounted, "enrolled_identities (no ledger on this node)")
	}

	// Counted so that "erase it" can be checked against "how much was there" — an erasure whose completeness
	// is measured only over the stores it happens to know about is measuring itself.
	if rules != nil {
		footprint.add(adminTenantFootprintRow{Store: "authored_rules", Count: int64(len(rules.List(footprint.TenantID, "")))})
	} else {
		footprint.NotCounted = append(footprint.NotCounted, "authored_rules (no rule store on this node)")
	}

	if deviceCAs != nil {
		footprint.add(adminTenantFootprintRow{Store: "device_cas", Count: int64(deviceCAs.Registrations()[footprint.TenantID])})
	} else {
		footprint.NotCounted = append(footprint.NotCounted, "device_cas (no tenant CA registry on this node)")
	}

	// ★ NAMED NETWORKS AND THEIR BOUNDARY POLICIES (2026-08-18). Measured on the reference deployment: a
	// disposable organization with one Named Network was deleted and erased, the erasure answered complete=true
	// with remaining.total=0, and the Named Network was still there with that organization's id on it. This
	// store was in neither the count nor the erasure, and a store nobody counts contributes nothing to "what is
	// left" — so the answer could not have been anything else.
	if namedNetworks != nil {
		objects, policies := namedNetworks.CountForTenant(footprint.TenantID)
		footprint.add(adminTenantFootprintRow{Store: "named_networks", Count: int64(objects)})
		footprint.add(adminTenantFootprintRow{Store: "named_network_boundary_policies", Count: int64(policies)})
	} else {
		footprint.NotCounted = append(footprint.NotCounted, "named_networks (no VLAN boundary store on this node)")
	}

	// ★ THE SIX STORES A MECHANICAL SWEEP NAMED (2026-08-18). The Named-Network residue was found by hand; the
	// gate written straight after it (TestEveryDurableCPStoreIsCountedOrExcusedInWriting) listed six more
	// durable control-plane stores that were in neither the count nor the erasure. Each holds something an
	// organization authored or something said ABOUT its devices, and each therefore belongs in "what is left".
	extra.count(&footprint)

	if writer != nil {
		files, bytes, err := countTenantLogFiles(writer.Dir(), footprint.TenantID)
		row := adminTenantFootprintRow{Store: "log_files", Count: files, Note: fmt.Sprintf("%d byte(s) on this node's disk", bytes)}
		if err != nil {
			row.Count, row.Error, row.Note = -1, err.Error(), ""
		}
		footprint.add(row)
	} else {
		footprint.NotCounted = append(footprint.NotCounted, "log_files (no log writer on this node)")
	}

	if db != nil {
		for _, table := range adminTenantFootprintPostgresTables {
			footprint.add(countTenantRows(ctx, db, table, footprint.TenantID))
		}
	} else {
		footprint.NotCounted = append(footprint.NotCounted,
			fmt.Sprintf("postgres (%d tenant-keyed table(s)) — this node has no Postgres handle", len(adminTenantFootprintPostgresTables)))
	}

	// Stores this process genuinely cannot reach. Named, not omitted: an operator reading a footprint has to
	// know that a zero here covers these or does not.
	footprint.NotCounted = append(footprint.NotCounted,
		"clickhouse (events, events_rollup_5m) — counted by the analytics plane, not by an Edge",
		"object storage (dsse-cold-archive, clickhouse-cold) — counted by the archive owner",
		"tenant values embedded inside JSON payload columns — a column-level count does not see them",
		"other Edges — a tenant's logs live on every node that served it, and this counts ONE node")
	sort.Slice(footprint.Stores, func(i, j int) bool { return footprint.Stores[i].Store < footprint.Stores[j].Store })
	return footprint
}

func (f *adminTenantFootprint) add(row adminTenantFootprintRow) {
	// A store with nothing in it is still worth showing: the point of the report is "what is left", and an
	// omitted zero is indistinguishable from a store nobody looked at.
	f.Stores = append(f.Stores, row)
	if row.Count > 0 {
		f.Total += row.Count
	}
}

// Clean reports whether this node holds nothing for the tenant. A store that FAILED to count (-1) is not
// clean: an unknown is never evidence of absence, and this is the value an erasure claim rests on.
func (f adminTenantFootprint) Clean() bool {
	for _, row := range f.Stores {
		if row.Count != 0 {
			return false
		}
	}
	return true
}

func countTenantRows(ctx context.Context, db *sql.DB, table, tenantID string) adminTenantFootprintRow {
	row := adminTenantFootprintRow{Store: "postgres." + table}
	// The table name is from the package-level list above, never from a request — no identifier is interpolated
	// from input here. The tenant id is bound as a parameter.
	var count int64
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM "+table+" WHERE tenant_id = $1", tenantID).Scan(&count); err != nil {
		// ★ A TABLE THIS DEPLOYMENT DOES NOT HAVE IS A ZERO, NOT AN UNKNOWN (2026-08-15). The list is defined
		// against the SCHEMA, and a deployment is a subset of it — the reference lab has four of these tables
		// missing because their Postgres backends are switched off. Left as -1 those four would keep every
		// tenant permanently "not clean", and a verification that can never come back green is one an operator
		// learns to ignore. It stays visible as a note, so "there is no such table here" is still readable and
		// is never confused with "the query failed", which remains an unknown.
		if isUndefinedTableError(err) {
			row.Count = 0
			row.Note = "this deployment does not have this table (its backend is not enabled here)"
			return row
		}
		row.Count, row.Error = -1, err.Error()
		return row
	}
	row.Count = count
	return row
}

// isUndefinedTableError reports whether the error is PostgreSQL's undefined_table (SQLSTATE 42P01). Matched on
// the code rather than the message so a localized or reworded server does not turn a known-absent table back
// into an unknown.
func isUndefinedTableError(err error) bool {
	if err == nil {
		return false
	}
	var pqErr interface{ SQLState() string }
	if errors.As(err, &pqErr) && pqErr.SQLState() == "42P01" {
		return true
	}
	// lib/pq's *pq.Error exposes Code rather than SQLState on older versions; fall back to the text it produces,
	// which is stable and specific ("relation \"x\" does not exist").
	return strings.Contains(err.Error(), "does not exist") && strings.Contains(err.Error(), "relation")
}

// countTenantLogFiles counts the files under this node's log directory for one tenant, and their total size.
// The layout is logs.Writer's own: <dir>/tenants/<sanitized tenant id>/…
func countTenantLogFiles(dir, tenantID string) (files int64, bytes int64, err error) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return 0, 0, nil
	}
	root := filepath.Join(dir, "tenants", logs.SafeTenantSegment(tenantID))
	entries, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, 0, nil // no directory is a real zero: this node never wrote a log for that tenant
		}
		return 0, 0, err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		files++
		if info, ierr := entry.Info(); ierr == nil {
			bytes += info.Size()
		}
	}
	return files, bytes, nil
}

// adminFootprintNodeName labels which node a footprint describes. A tenant's logs live on every Edge that
// served it, so a report that does not say WHICH node it counted invites reading one node's zero as the
// fleet's zero — the same mistake as reading an empty tenant section as "every tenant was deleted".
func adminFootprintNodeName(configSourceURL string) string {
	if host, err := os.Hostname(); err == nil && strings.TrimSpace(host) != "" {
		if strings.TrimSpace(configSourceURL) == "" {
			return host + " (control plane: this node authors its own config)"
		}
		return host + " (edge: pulls config from " + strings.TrimSpace(configSourceURL) + ")"
	}
	return "unknown-node"
}

// tenantModelFleetCarryingTable reports whether a table's rows exist to TELL OTHER NODES about a terminated
// tenant, rather than to hold the tenant's own data. An erasure must take these last and only when everything
// else succeeded: while they exist the deletion and the erasure order keep being carried to any node that has
// not applied them, and removing them early un-deletes the tenant, or abandons its data, exactly there.
func tenantModelFleetCarryingTable(table string) bool {
	switch table {
	case "admin_tenant_model_deletions", "admin_tenant_model_purge_orders":
		return true
	}
	return false
}

// adminTenantExtraStores is the set of durable control-plane stores that hold tenant-scoped records and are
// neither Postgres tables nor one of the five the footprint counted originally. They travel together because
// they are counted and erased together, and because a store added to one list and forgotten in the other is
// precisely the failure that produced them.
//
// DeviceIDs is how the two DEVICE-KEYED stores are reached. Neither the high-risk overlay nor the admission
// kill-switches know whose a device is — only the enrolled ledger does — so the caller resolves the ids and
// passes them here. On the erasure path they MUST be captured before the ledger is cleared.
type adminTenantExtraStores struct {
	TenantRestrictions interface {
		CountTenantRestrictions(string) int
		RemoveTenantRestrictions(string) (int, error)
	}
	TenantTrustDistributions *tenantTrustDistributor
	DelegatedGrants          *delegatedgrant.Store
	HumanApprovals           *humanapproval.Store
	ClientlessGrants         *grantstore.Store
	IdPConnections           *idpregistry.Store
	HighRisk                 *revocation.HighRiskOverlay
	Admissions               *revocation.AdmissionRevocations
	// ★ FOUND WHEN THE GATE'S OWN PATTERN WAS FIXED (2026-08-18). It read [cC]p, and the helper most call sites
	// use is mustCPStateBlobPersister — capital P — so it had been seeing 18 store keys of 29 and passing. Four
	// of the eleven it could not see hold tenant-scoped records.
	CatalogOverrides *knownbypass.OverrideStore
	// ★ ROUTES ARE A TENANT'S (2026-08-25). A Site's routes say which of an organization's internal names a
	// connector fronts — as tenant-scoped as anything here — and the store only became durable today, which
	// is when it became something an erasure has to account for.
	ConnectorRoutes  *connectorRouteGovernance
	SeatAllocations  *seatallocation.Store
	PolicyCandidates *policycandidate.Store
	EnrolmentTokens  *enrolltoken.Store
	// TenantTransportAuthorities is each organization's TRANSPORT CA, held on the control plane so an Edge
	// that appears under load can be handed short-lived server material instead of having files placed on it.
	// It is the organization's own authority, so it is counted and erased with them.
	TenantTransportAuthorities *tenantTransportAuthority
	// TenantInterceptionAuthorities is the authority an organization DELEGATED for interception. Theirs, so
	// counted with them and erased with them — and erasing it is how an organization takes the operator's
	// ability to intercept for them away.
	TenantInterceptionAuthorities *tenantInterceptionAuthority
	// ★ WHAT AN ORGANIZATION WAS TOLD TO RUN, AND WHAT WAS PUBLISHED TO IT ALONE (2026-08-28). Both stores
	// became visible to the gate the day they moved to shared control-plane state, and neither was in the
	// count or the erasure: a deleted organization left behind its desired version, its incident freeze with
	// the reason a person typed for it, and any canary build published into it — bytes included.
	//
	// The deployment's CATALOGUE is not theirs and is not touched; see publishedAgentUpdateStore.RemoveTenant.
	AgentRolloutPlans     *agentrollout.AgentRolloutStore
	PublishedAgentUpdates *publishedAgentUpdateStore
	DeviceIDs             []string
}

func (e adminTenantExtraStores) count(f *adminTenantFootprint) {
	add := func(store string, present bool, n int, absent string) {
		if !present {
			f.NotCounted = append(f.NotCounted, store+" ("+absent+")")
			return
		}
		f.add(adminTenantFootprintRow{Store: store, Count: int64(n)})
	}
	add("delegated_access_grants", e.DelegatedGrants != nil, e.DelegatedGrants.CountForTenant(f.TenantID), "no delegated-grant store on this node")
	add("human_approvals", e.HumanApprovals != nil, e.HumanApprovals.CountForTenant(f.TenantID), "no human-approval store on this node")
	add("clientless_grants", e.ClientlessGrants != nil, e.ClientlessGrants.CountForTenant(f.TenantID), "no clientless grant store on this node")
	add("end_user_idp_connections", e.IdPConnections != nil, e.IdPConnections.CountForTenant(f.TenantID), "no end-user IdP registry on this node")
	add("high_risk_marks", e.HighRisk != nil, e.HighRisk.CountDevices(e.DeviceIDs)+e.HighRisk.CountUsers(f.TenantID), "no high-risk overlay on this node")
	add("admission_kill_switches", e.Admissions != nil, e.Admissions.CountDevices(e.DeviceIDs), "no admission revocation store on this node")
	add("bypass_catalog_overrides", e.CatalogOverrides != nil, e.CatalogOverrides.CountForTenant(f.TenantID), "no bypass-catalog override store on this node")
	add("connector_route_governance", e.ConnectorRoutes != nil, e.ConnectorRoutes.CountForTenant(f.TenantID), "no connector route governance on this node")
	if e.TenantRestrictions != nil {
		add("saas_tenant_restrictions", true, e.TenantRestrictions.CountTenantRestrictions(f.TenantID), "")
	} else {
		add("saas_tenant_restrictions", false, 0, "no managed SaaS configuration on this node")
	}
	add("seat_allocation", e.SeatAllocations != nil, e.SeatAllocations.CountForTenant(f.TenantID), "no seat allocation store on this node")
	add("policy_candidates", e.PolicyCandidates != nil, e.PolicyCandidates.CountForTenant(f.TenantID), "no policy candidate store on this node")
	add("enrolment_tokens_store", e.EnrolmentTokens != nil, e.EnrolmentTokens.CountForTenant(f.TenantID), "no file/blob enrolment token store on this node")
	add("tenant_transport_authorities", e.TenantTransportAuthorities != nil,
		e.TenantTransportAuthorities.CountForTenant(f.TenantID), "this node issues no per-organization transport material")
	if e.TenantTrustDistributions != nil {
		n, err := e.TenantTrustDistributions.CountForTenant(f.TenantID)
		if err != nil {
			f.add(adminTenantFootprintRow{Store: "tenant_trust_distributions", Count: -1, Error: err.Error()})
		} else {
			add("tenant_trust_distributions", true, n, "")
		}
	} else {
		add("tenant_trust_distributions", false, 0, "no trust distribution authority on this node")
	}
	add("tenant_interception_authorities", e.TenantInterceptionAuthorities != nil,
		e.TenantInterceptionAuthorities.CountForTenant(f.TenantID), "no organization has delegated interception to this node")
	add("agent_rollout_plans", e.AgentRolloutPlans != nil, e.AgentRolloutPlans.CountForTenant(f.TenantID),
		"no agent rollout store on this node")
	add("published_agent_releases", e.PublishedAgentUpdates != nil, e.PublishedAgentUpdates.CountForTenant(f.TenantID),
		"no published-release store on this node")
}

// erase removes every record these stores hold for the tenant, appending a row per store that had any.
func (e adminTenantExtraStores) erase(result *adminTenantPurgeResult) {
	e.eraseContext(context.Background(), result)
}

func (e adminTenantExtraStores) eraseContext(ctx context.Context, result *adminTenantPurgeResult) {
	add := func(store string, n int) {
		if n > 0 {
			result.Erased = append(result.Erased, adminTenantPurgeRow{Store: store, Count: int64(n)})
		}
	}
	eraseChecked := func(store string, remove func(string) (int, error)) {
		n, err := remove(result.TenantID)
		if err != nil {
			result.Failures = append(result.Failures, store+": erasure saving could not be confirmed")
		} else {
			add(store, n)
		}
	}

	tenantID := result.TenantID
	if e.TenantRestrictions != nil {
		n, err := e.TenantRestrictions.RemoveTenantRestrictions(tenantID)
		if err != nil {
			result.Failures = append(result.Failures, "SaaS restriction erasure failed: "+err.Error())
		} else {
			add("saas_tenant_restrictions", n)
		}
	}
	if e.DelegatedGrants != nil {
		eraseChecked("delegated_access_grants", e.DelegatedGrants.RemoveTenantChecked)
	}
	if e.HumanApprovals != nil {
		eraseChecked("human_approvals", e.HumanApprovals.RemoveTenantChecked)
	}
	if e.ClientlessGrants != nil {
		eraseChecked("clientless_grants", e.ClientlessGrants.RemoveTenantChecked)
	}
	if e.IdPConnections != nil {
		eraseChecked("end_user_idp_connections", e.IdPConnections.RemoveTenantChecked)
	}
	if e.HighRisk != nil {
		if n, err := e.HighRisk.RemoveTenantRisksContext(ctx, tenantID, e.DeviceIDs); err != nil {
			result.Failures = append(result.Failures, "risk erasure saving could not be confirmed")
		} else {
			add("high_risk_marks", n)
		}
	}
	if e.Admissions != nil {
		if n, err := e.Admissions.RemoveDevicesContext(ctx, e.DeviceIDs); err != nil {
			result.Failures = append(result.Failures, "admission revocation erasure saving could not be confirmed")
		} else {
			add("admission_kill_switches", n)
		}
	}
	if e.ConnectorRoutes != nil {
		eraseChecked("connector_route_governance", e.ConnectorRoutes.RemoveTenantChecked)
	}
	if e.CatalogOverrides != nil {
		if n, err := e.CatalogOverrides.RemoveTenantContext(ctx, tenantID); err != nil {
			result.Failures = append(result.Failures, "bypass catalog override erasure could not be confirmed")
		} else {
			add("bypass_catalog_overrides", n)
		}
	}
	if e.SeatAllocations != nil {
		if n, err := e.SeatAllocations.RemoveTenantContext(ctx, tenantID); err != nil {
			result.Failures = append(result.Failures, "seat allocation erasure could not be confirmed")
		} else {
			add("seat_allocation", n)
		}
	}
	if e.PolicyCandidates != nil {
		if n, err := e.PolicyCandidates.RemoveTenant(tenantID); err != nil {
			result.Failures = append(result.Failures, "policy candidate erasure could not be confirmed")
		} else {
			add("policy_candidates", n)
		}
	}
	if e.TenantTransportAuthorities != nil {
		eraseChecked("tenant_transport_authorities", e.TenantTransportAuthorities.RemoveTenantChecked)
	}
	if e.TenantInterceptionAuthorities != nil {
		eraseChecked("tenant_interception_authorities", e.TenantInterceptionAuthorities.RemoveTenantChecked)
	}
	if e.TenantTrustDistributions != nil {
		n, err := e.TenantTrustDistributions.RemoveTenant(tenantID)
		if err != nil {
			result.Failures = append(result.Failures, "tenant_trust_distributions: "+err.Error())
		} else {
			add("tenant_trust_distributions", n)
		}
	}
	if e.EnrolmentTokens != nil {
		n := e.EnrolmentTokens.RemoveTenant(tenantID)
		if err := e.EnrolmentTokens.Health(); err != nil {
			result.Failures = append(result.Failures, "enrolment_tokens_store: "+err.Error())
		} else {
			add("enrolment_tokens_store", n)
		}
	}
	if e.AgentRolloutPlans != nil {
		eraseChecked("agent_rollout_plans", func(tenant string) (int, error) { return e.AgentRolloutPlans.RemoveTenantContext(ctx, tenant) })
	}
	if e.PublishedAgentUpdates != nil {
		n, cleanup, err := e.PublishedAgentUpdates.removeTenantWithCleanup(tenantID)
		result.ArtifactCleanup = cleanup
		add("published_agent_releases", n)
		if err != nil {
			failure := "published_agent_releases: erasure saving could not be confirmed"
			if cleanup["manifests"] == "absence_confirmed" {
				location := "local"
				if cleanup["shared"] == "unconfirmed" {
					location = "shared"
				}
				failure = "published_agent_releases: manifests are absent; " + location + " artifact cleanup is unconfirmed; repair storage and retry erasure"
			}
			result.Failures = append(result.Failures, failure)
		}
	}
}

// tenantExtraStoresFor fills in the device ids the two DEVICE-KEYED stores need, from the enrolled ledger.
// Retained removal records are included so a deleted tenant can be erased or
// retried after restart. The ledger is cleared only after its dependent cleanup.
func tenantExtraStoresFor(base adminTenantExtraStores, ledger *enrolledinventory.Ledger, tenantID string) adminTenantExtraStores {
	if ledger == nil {
		return base
	}
	seen := make(map[string]bool, len(base.DeviceIDs))
	for _, id := range base.DeviceIDs {
		seen[id] = true
	}
	for _, entry := range ledger.Authoritative() {
		if strings.EqualFold(strings.TrimSpace(entry.TenantID), strings.TrimSpace(tenantID)) && !seen[entry.Identity] {
			base.DeviceIDs = append(base.DeviceIDs, entry.Identity)
			seen[entry.Identity] = true
		}
	}
	return base
}

// policyCandidateStoreOrNil / enrolmentTokenStoreOrNil narrow the interfaces the server config carries to the
// concrete stores that can answer "how much of this tenant is here". A deployment wired to a different
// implementation reports the store as NOT COUNTED rather than as empty — the distinction the footprint exists
// to keep.
func policyCandidateStoreOrNil(v policycandidate.RuntimeStore) *policycandidate.Store {
	concrete, _ := v.(*policycandidate.Store)
	return concrete
}

func enrolmentTokenStoreOrNil(v enrolltoken.Authority) *enrolltoken.Store {
	concrete, _ := v.(*enrolltoken.Store)
	return concrete
}
