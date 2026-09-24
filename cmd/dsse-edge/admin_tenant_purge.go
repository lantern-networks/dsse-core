package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/enrolledinventory"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/policyrule"
	"github.com/lantern-networks/dsse-core/tenantca"
	"github.com/lantern-networks/dsse-core/vlan"
)

// The tenant PURGE: erase everything this node holds for a tenant whose contract has ended.
//
// ★ DECISION (2026-08-15). A customer will ask for complete erasure after termination and that has to be
// possible. It is deliberately NOT the same act as deleting the organization:
//
//   - deleting a tenant is routine and reversible in effect (re-create it and carry on);
//   - purging is irreversible and erases the record of what was done, so erasing the evidence must never be a
//     side effect of pressing delete on a customer.
//
// The response IS the proof: it re-counts the same footprint afterwards and returns it. An erasure that
// reports "done" without a count is a claim nobody can check, and this product has enough of those already.
type adminTenantPurgeResult struct {
	TenantID string `json:"tenant_id"`
	Node     string `json:"node"`
	PurgedAt string `json:"purged_at"`
	// Erased is what went, per store, on this node.
	Erased []adminTenantPurgeRow `json:"erased"`
	// ArtifactCleanup records absence checks even when no manifest was removed on this call.
	ArtifactCleanup map[string]string `json:"artifact_cleanup,omitempty"`
	// Remaining is the footprint taken AFTER the erasure — the evidence, not a summary of intent.
	Remaining adminTenantFootprint `json:"remaining"`
	// Complete is true only when this node holds nothing at all afterwards. It says nothing about other nodes;
	// Remaining.NotCounted names them.
	Complete bool     `json:"complete"`
	Failures []string `json:"failures"`
	// ElapsedMS is how long the erasure took on this node. Reported because it is the number that decides
	// whether this call is safe to make synchronously: the first real erasure took 7m49s holding the request
	// open, and nothing in the response said so.
	ElapsedMS int64 `json:"elapsed_ms"`
}

type adminTenantPurgeRow struct {
	Store string `json:"store"`
	Count int64  `json:"count"`
	Error string `json:"error,omitempty"`
}

// purgeAdminTenantData erases a tenant from every store this node can reach, then counts what is left.
//
// Order matters in one place: the tombstone table is erased LAST and only when everything else succeeded.
// Removing a tenant's tombstone while an Edge has not yet applied the deletion would un-delete the tenant on
// that node — the purge would put back the very thing it is finishing.
func purgeAdminTenantData(ctx context.Context, node, tenantID string, db *sql.DB, writer *logs.Writer,
	credentials *localAdminCredentialStore, ledger *enrolledinventory.Ledger, rules *policyrule.Store,
	deviceCAs *tenantca.TenantCARegistry, deviceCARegistryPath string, deviceTrust transportTrustAnchorStore,
	namedNetworks *vlan.Store, extra adminTenantExtraStores, holds *legalHoldStore, now time.Time) adminTenantPurgeResult {

	tenantID = strings.TrimSpace(tenantID)
	started := time.Now()
	result := adminTenantPurgeResult{
		TenantID: tenantID,
		Node:     node,
		PurgedAt: now.UTC().Format(time.RFC3339),
		Erased:   []adminTenantPurgeRow{},
		Failures: []string{},
	}

	// Recheck at the shared destructive boundary, including signed remote orders.
	// A failed check must leave all stores and the standing order untouched.
	_, held, _, protectionErr := holds.adminStatus(ctx, tenantID)
	if protectionErr != nil {
		result.Failures = append(result.Failures, "legal_hold: state unavailable or erasure recovery required")
		return result
	}
	if held {
		result.Failures = append(result.Failures, "legal_hold: tenant is held")
		return result
	}
	// A durable operation fence covers all stores and external filesystem work.
	// It outlives the SQL session but holds no transaction across nested writers.
	owned, finishErasure, fenceErr := holds.beginErasure(retentionWriteContext(ctx), tenantID, node)
	if fenceErr != nil {
		result.Failures = append(result.Failures, "tenant erasure could not be started; protection or recovery check required")
		result.ElapsedMS = time.Since(started).Milliseconds()
		return result
	}
	ctx = owned
	released := false
	closeErasure := func() {
		if released {
			return
		}
		released = true
		// A failed external call may have an unknown outcome. Keep exclusion until
		// offline reconciliation proves that no prior work can resume.
		if holds != nil && len(result.Failures) != 0 {
			result.Failures = append(result.Failures, "tenant erasure marker retained after partial failure; recovery required")
			return
		}
		if err := finishErasure(); err != nil {
			result.Failures = append(result.Failures, "tenant erasure completion could not be saved; recovery required")
		}
	}
	// Deny admission and retain ownership when dependent cleanup reports a
	// failure. A failed admission erase must keep its retry targets at restart.
	if ledger != nil {
		if _, err := ledger.RetireTenantContext(ctx, tenantID, now.UTC().Format(time.RFC3339)); err != nil {
			result.Failures = append(result.Failures, "tenant identity retirement saving could not be confirmed")
			result.Remaining = countAdminTenantFootprint(ctx, node, tenantID, db, writer, credentials, ledger, rules, deviceCAs, namedNetworks, extra, now)
			closeErasure()
			result.ElapsedMS = time.Since(started).Milliseconds()
			return result
		}
		extra = tenantExtraStoresFor(extra, ledger, tenantID)
	}

	credentialSweepAllowed := true
	if credentials != nil {
		removed, err := credentials.DeleteAllForTenant(tenantID)
		if err != nil {
			result.Failures = append(result.Failures, "admin_accounts: credential deletion incomplete")
			credentialSweepAllowed = false
		}
		if len(removed) > 0 {
			result.Erased = append(result.Erased, adminTenantPurgeRow{Store: "admin_accounts", Count: int64(len(removed))})
		}
	}
	extra.eraseContext(ctx, &result)
	// ★ The authored rules an organization wrote in the Console. Measured on 2026-08-17: an organization
	// deleted through the Console left its access rule on BOTH planes, still carrying its id — the one thing
	// it had authored outliving the organization itself.
	if rules != nil {
		removed, err := rules.RemoveTenantContext(ctx, tenantID)
		if err != nil {
			// Keep retired identities and fleet retry markers until erasure is confirmed.
			// Persistence errors can contain private paths or database details.
			result.Failures = append(result.Failures, "rule erasure saving could not be confirmed")
		} else if removed > 0 {
			result.Erased = append(result.Erased, adminTenantPurgeRow{Store: "authored_rules", Count: int64(removed)})
		}
	}
	// ★★ AND THE CA THAT ADMITS ITS DEVICES (2026-08-17, measured: an organization deleted through the Console
	// left its device CA in the registry, so any machine holding a certificate from that CA was still admitted
	// AS that organization — an admission path outliving the organization).
	//
	// BOTH HALVES, attribution first, exactly as the per-CA withdrawal route does and for the reason recorded
	// there: the pool a handshake reads is the registry's clone plus the trust store's own certificates, and
	// only a change to the store rebuilds it. Removing trust first rebuilds the pool from a registry that
	// still holds the CA, and the withdrawal defeats itself.
	if deviceCAs != nil {
		removed, err := purgeTenantDeviceCAs(deviceCAs, deviceCARegistryPath, deviceTrust, tenantID)
		if removed > 0 {
			result.Erased = append(result.Erased, adminTenantPurgeRow{Store: "device_cas", Count: int64(removed)})
		}
		if err != nil {
			result.Failures = append(result.Failures, "device_cas: "+err.Error())
		}
	}
	// ★ THE NAMED NETWORKS THIS ORGANIZATION DEFINED, AND THE BOUNDARY POLICIES BETWEEN THEM (2026-08-18).
	// Measured: a disposable organization with one Named Network was deleted and erased, the erasure answered
	// complete=true with remaining.total=0, and the Named Network was still there carrying that organization's
	// id. It was in neither the count nor the erasure — and a store nobody counts contributes nothing to "what
	// is left", so the answer could not have been anything else.
	if namedNetworks != nil {
		objects, policies, err := namedNetworks.RemoveTenantContext(ctx, tenantID)
		if err != nil {
			log.Printf("tenant network erasure: %v", err)
			result.Failures = append(result.Failures, "network erasure saving could not be confirmed")
		}
		if objects > 0 {
			result.Erased = append(result.Erased, adminTenantPurgeRow{Store: "named_networks", Count: int64(objects)})
		}
		if policies > 0 {
			result.Erased = append(result.Erased, adminTenantPurgeRow{Store: "named_network_boundary_policies", Count: int64(policies)})
		}
	}
	if ledger != nil && len(result.Failures) == 0 {
		removed, err := ledger.RemoveTenantContext(ctx, tenantID)
		if err != nil {
			result.Failures = append(result.Failures, "tenant identity erasure saving could not be confirmed")
		} else if len(removed) > 0 {
			result.Erased = append(result.Erased, adminTenantPurgeRow{Store: "enrolled_identities", Count: int64(len(removed))})
		}
	}
	var logFootprint []adminTenantFootprintRow
	if writer != nil {
		files, err := purgeTenantLogDirectoryWithHold(ctx, writer, tenantID, holds)
		remaining := adminTenantFootprintRow{Store: "log_files", Count: 0, Note: "absence verified by the file erasure owner"}
		if err != nil {
			remaining.Count = -1
			remaining.Note = ""
			remaining.Error = "file erasure or verification is unconfirmed; reconcile after the original owner ends"
		}
		logFootprint = append(logFootprint, remaining)
		row := adminTenantPurgeRow{Store: "log_files", Count: files}
		if err != nil {
			row.Error = err.Error()
			result.Failures = append(result.Failures, "log_files: "+err.Error())
		}
		if files > 0 || err != nil {
			result.Erased = append(result.Erased, row)
		}
	}
	if db != nil {
		for _, table := range adminTenantFootprintPostgresTables {
			if tenantModelFleetCarryingTable(table) {
				continue // last, and only if the rest worked — see below
			}
			if table == "admin_local_credentials" && !credentialSweepAllowed {
				continue // Do not bypass a rejected generation-aware account deletion.
			}
			row := purgeTenantRows(ctx, db, table, tenantID, holds)
			if row.Error != "" {
				result.Failures = append(result.Failures, row.Store+": "+row.Error)
			}
			if row.Count > 0 || row.Error != "" {
				result.Erased = append(result.Erased, row)
			}
		}
		// The tombstone and the erasure order — the two rows whose entire job is to TELL THE REST OF THE FLEET
		// about this tenant. Only once nothing else failed: while they exist the deletion and the erasure keep
		// being carried to any node that has not applied them, and removing them early resurrects the tenant, or
		// abandons its data, exactly there.
		//
		// ★ THE ORDER JOINED THE TOMBSTONE HERE WHEN THE POSTGRES BACKEND FINALLY HAD ONE (2026-08-18). Left
		// standing forever it would be honest about the fleet and dishonest about this node: Complete is
		// "Remaining.Clean()", so a row that never goes means this node can never report a finished erasure —
		// and an erasure that always reads incomplete is one nobody can act on.
		// Read once, before the loop: erasing the first of these can itself add a failure, and re-reading would
		// then keep the second for a reason that did not exist when the decision was made.
		closeErasure() // Keep delivery markers if completion cannot be confirmed.
		everythingElseWorked := len(result.Failures) == 0
		for _, table := range adminTenantFootprintPostgresTables {
			if !tenantModelFleetCarryingTable(table) {
				continue
			}
			if !everythingElseWorked {
				result.Failures = append(result.Failures, table+
					": kept, because something else failed and this is what keeps the deletion and the erasure travelling to nodes that have not applied them")
				continue
			}
			row := purgeTenantRows(ctx, db, table, tenantID, holds)
			if row.Error != "" {
				result.Failures = append(result.Failures, row.Store+": "+row.Error)
			}
			if row.Count > 0 {
				result.Erased = append(result.Erased, row)
			}
		}
	}

	closeErasure()
	result.Remaining = countAdminTenantFootprint(ctx, node, tenantID, db, writer, credentials, ledger, rules, deviceCAs, namedNetworks, extra, now, logFootprint...)
	result.Complete = len(result.Failures) == 0 && result.Remaining.Clean()
	result.ElapsedMS = time.Since(started).Milliseconds()
	log.Printf("tenant %q purged on this node: erased %d store(s), %d failure(s), complete=%v",
		tenantID, len(result.Erased), len(result.Failures), result.Complete)
	return result
}

// adminTenantPurgeBatchSize bounds each DELETE statement.
//
// ★ MEASURED, BOTH WAYS (2026-08-15). The first real erasure on the lab removed 875,974 rows from hot_events
// and 80,510 from the audit outbox as ONE statement each, and took 7m49s with the HTTP request held open the
// whole time. The wall clock was the smaller problem: for all of it a single transaction held locks on a table
// every other writer on that node also uses, so erasing a large customer would stall the live audit path for
// everyone else.
//
// Re-measured against the same volume, batched: 875,974 rows in 7.7s — 61x, and no multi-minute lock. Not a
// perfectly matched control (the original rows had accumulated over weeks, so the table's physical state
// differed, and that run also erased the audit rows), but far beyond what that explains; holding one enormous
// transaction was the cost.
//
// This still does not make an erasure asynchronous. A tenant large enough to outlast an HTTP timeout wants a
// job with progress, which does not exist yet and is named as missing rather than pretended away.
const adminTenantPurgeBatchSize = 5000

func purgeTenantRows(ctx context.Context, db *sql.DB, table, tenantID string, holds *legalHoldStore) adminTenantPurgeRow {
	row := adminTenantPurgeRow{Store: "postgres." + table}
	// The table name comes from the package-level list, never from a request; the tenant id is bound.
	//
	// ctid is the physical row address, so the subquery picks a bounded set without needing a primary key —
	// and these tables do not agree on one.
	statement := "DELETE FROM " + table + " WHERE ctid IN (SELECT ctid FROM " + table + " WHERE tenant_id = $1 LIMIT $2)"
	for {
		res, err := executeTenantPurgeBatch(ctx, db, table, statement, tenantID, holds)
		if err != nil {
			if isUndefinedTableError(err) {
				return row // this deployment does not have the table: nothing to erase, and not a failure
			}
			// Whatever went already, went. Reporting the count with the error is the honest shape: a partial
			// erasure that claims zero would send an operator looking in the wrong place.
			row.Error = err.Error()
			return row
		}
		affected, _ := res.RowsAffected()
		row.Count += affected
		if affected < adminTenantPurgeBatchSize {
			return row
		}
		if row.Count%(adminTenantPurgeBatchSize*20) == 0 {
			log.Printf("tenant purge: %s — %d row(s) erased so far", row.Store, row.Count)
		}
		// A cancelled request must not leave a loop running against the database.
		if err := ctx.Err(); err != nil {
			row.Error = "stopped after " + err.Error()
			return row
		}
	}
}

// purgeTenantLogDirectory removes a tenant's whole log partition from this node's disk and returns how many
// files went. The writer is asked to close its handles for that tenant first: on a system that keeps an open
// file descriptor, unlinking the path leaves the bytes alive until the process lets go, and an erasure that
// depends on a later restart is not an erasure.
func purgeTenantLogDirectory(writer *logs.Writer, tenantID string) (int64, error) {
	return purgeTenantLogDirectoryContext(context.Background(), writer, tenantID)
}

func purgeTenantLogDirectoryContext(ctx context.Context, writer *logs.Writer, tenantID string) (int64, error) {
	if writer == nil {
		return 0, nil
	}
	root := filepath.Join(writer.Dir(), "tenants", logs.SafeTenantSegment(tenantID))
	return eraseTenantLogFiles(ctx,
		func() (int64, error) { n, _, err := countTenantLogFiles(writer.Dir(), tenantID); return n, err },
		func() error { return writer.CloseTenant(tenantID) },
		func() error { return os.RemoveAll(root) })
}

// Each callback is a single filesystem phase. Check cancellation between phases
// so a late Close cannot start deletion after its request has already returned.
// Verify absence under the same owner rather than reopening the filesystem later
// from the response's footprint collector.
func eraseTenantLogFiles(ctx context.Context, count func() (int64, error), closeFiles, remove func() error) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	files, err := count()
	if err != nil {
		return 0, err
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if err := closeFiles(); err != nil {
		return 0, fmt.Errorf("log handles could not be closed: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if err := remove(); err != nil {
		return 0, err
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	remaining, err := count()
	if err != nil {
		return 0, err
	}
	if remaining != 0 {
		return 0, fmt.Errorf("log files remain after erasure")
	}
	return files, nil
}

// adminAuthPostgresDB returns the shared Postgres handle when the admin auth store is the Postgres one, and
// nil otherwise. nil is a correct answer, not a failure: an Edge with no database still has logs and a ledger
// to erase, and the footprint it returns says plainly that Postgres was not counted here.
func adminAuthPostgresDB(store adminAuthRuntimeStore) *sql.DB {
	if pg, ok := store.(postgresAdminAuthStore); ok {
		return pg.DB
	}
	return nil
}

// purgeTenantDeviceCAs takes every CA attributed to one organization out of BOTH the attribution registry and
// the trust set a handshake reads. Withdrawing the attribution alone is the shape of a defect this file's
// sibling route already paid for: the CA stops being anybody's and goes on admitting devices.
func purgeTenantDeviceCAs(registry *tenantca.TenantCARegistry, registryPath string,
	trust transportTrustAnchorStore, tenantID string) (int, error) {
	fingerprints := []string{}
	for _, fact := range registry.Facts(time.Now()) {
		if strings.EqualFold(strings.TrimSpace(fact.TenantID), strings.TrimSpace(tenantID)) {
			fingerprints = append(fingerprints, fact.SHA256)
		}
	}
	if len(fingerprints) == 0 {
		return 0, nil
	}
	removed := registry.Withdraw(tenantID)
	if strings.TrimSpace(registryPath) != "" {
		if err := registry.Save(registryPath); err != nil {
			return removed, fmt.Errorf("the attribution was removed but not saved, so a restart would bring it back: %w", err)
		}
	}
	if trust == nil {
		// Said, not swallowed: on a node with no runtime trust store the attribution is gone and the admission
		// is whatever the static configuration says, which this cannot change.
		return removed, fmt.Errorf("no runtime device-trust store on this node, so those CAs may still admit devices here")
	}
	for _, fingerprint := range fingerprints {
		if _, _, err := trust.Withdraw(fingerprint); err != nil {
			if !strings.Contains(err.Error(), "no distributed certificate has that fingerprint") {
				return removed, fmt.Errorf("a CA could not be taken out of the device trust set, so it would keep admitting devices: %w", err)
			}
		}
	}
	// The pool a handshake reads folds in the registry, and only a change to the store rebuilds it.
	if err := trust.Reapply(); err != nil {
		return removed, fmt.Errorf("the trust set a handshake reads could not be rebuilt, so those CAs may still admit devices: %w", err)
	}
	return removed, nil
}

// Credential cleanup uses the same transaction-local protocol as account mutations.
// Commit each bounded batch before counting it, without authorizing other tables.
func executeTenantPurgeBatch(ctx context.Context, db *sql.DB, table, statement, tenantID string, holds *legalHoldStore) (sql.Result, error) {
	ctx = retentionWriteContext(ctx)
	ctx, cancel := context.WithTimeout(ctx, cpStateBlobDBTimeout)
	defer cancel()
	// Detach SQL cancellation only when policy and data share this transaction.
	// A separate policy pool or filesystem step must retain its existing guard.
	budget := &cpStatementBudget{request: ctx, sqlCtx: ctx, cancel: func() {}}
	if holds != nil {
		if p, ok := holds.persister.(postgresBlobPersister); ok && p.db == db {
			budget = newCPStatementBudget(ctx)
		}
	}
	defer budget.cancel()
	tx, finish, err := beginTenantPurgeHoldGuardWithBudget(budget, holds, db, tenantID)
	if err != nil {
		return nil, err
	}
	defer finish()
	if tx == nil {
		tx, err = db.BeginTx(ctx, nil)
		if err != nil {
			return nil, err
		}
	}
	defer tx.Rollback()
	if table == "admin_local_credentials" {
		if _, err := budget.exec(tx, `SET LOCAL dsse.credential_write_protocol = '1'`); err != nil {
			return nil, err
		}
	}
	result, err := budget.exec(tx, statement, tenantID, adminTenantPurgeBatchSize)
	if err != nil {
		return nil, err
	}
	if err := budget.commit(tx); err != nil {
		return nil, err
	}
	return result, nil
}
