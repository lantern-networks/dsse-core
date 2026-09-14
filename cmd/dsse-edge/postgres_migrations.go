package main

import (
	"fmt"
	"strings"

	migrationstore "github.com/lantern-networks/dsse-core/migrations"
)

const (
	postgresMigrationExportWorkerQueue         = "001"
	postgresMigrationAdminExportJobs           = "002"
	postgresMigrationHotEvents                 = "003"
	postgresMigrationAdminAuditOutbox          = "004"
	postgresMigrationAdminAuth                 = "005"
	postgresMigrationDomainEventOutbox         = "006"
	postgresMigrationDomainEventStream         = "007"
	postgresMigrationUsageMeter                = "008"
	postgresMigrationNonHumanIdentity          = "009"
	postgresMigrationHotEventsText             = "010"
	postgresMigrationWorkloadNonce             = "011"
	postgresMigrationHumanIdentity             = "012"
	postgresMigrationHumanIdentityImportRun    = "013"
	postgresMigrationHumanIdentitySource       = "014"
	postgresMigrationHumanIdentitySourceState  = "015"
	postgresMigrationHumanIdentitySourcePolicy = "016"
	postgresMigrationConnectorRegistry         = "017"
	postgresMigrationDeviceInventory           = "018"
	postgresMigrationAgentTelemetry            = "019"
	postgresMigrationLocalCredentials          = "020"
	postgresMigrationCredentialTOTP            = "048"
	postgresMigrationSteerExclusions           = "021"
	postgresMigrationConfigVersions            = "022"
	postgresMigrationAdminTenantModel          = "023"
	postgresMigrationAdminTenantModelOperator  = "024"
	postgresMigrationAdminSites                = "025"
	postgresMigrationApplicationCatalog        = "026"
	postgresMigrationObservedExclusions        = "027"
	postgresMigrationCPStateBlobs              = "028"
	postgresMigrationEnrolmentTokens           = "029"
	postgresMigrationEnrolmentTokenIssuerLabel = "030"
	postgresMigrationObservedTrustTelemetry    = "031"
	postgresMigrationObservedAgentPolicyKeys   = "032"
	// 042 adds the recovery name a device says it holds, and what it deliberately did not apply. Listed here
	// because a component applies ONLY its own migrations: a migration file this list does not name is a file
	// that never runs, and the column then exists in the in-memory store and nowhere else.
	postgresMigrationObservedRecoveryName   = "042"
	postgresMigrationObservedRecoveryTarget = "043"
	// ★★★ 045 — the interception refusal journal and the SNI a device actually presents. Adding the columns
	// without adding this line creates neither: every write is dropped with "column does not exist", which on
	// 2026-08-22 took the observed store to "no devices reported" across three posture checks within a minute
	// of deploying. The list is explicit on purpose; the cost of that is that it has to be extended.
	postgresMigrationObservedInterceptionRefusals = "045"
	postgresMigrationInternalCAs                  = "046"
	// ★ A MIGRATION FILE THAT NOTHING SELECTS IS NOT A MIGRATION (2026-08-12, ninth review). 033 was written
	// and never listed here, while the INSERT it exists for already named the composite conflict target — so
	// against a real PostgreSQL every update outcome failed with "no unique constraint matching", answered 500,
	// and the whole reporting lane was dead in exactly the deployment it was built for.
	postgresMigrationAgentUpdateEventScope = "033"
	// 034 adds `refused` to the status CHECK: a device told to update that cannot is a fleet state, and every
	// one of those rows was being rejected.
	postgresMigrationAgentUpdateRefused = "034"
	// 035 makes "this identity has already enrolled" a row rather than a field in a blob, so every issuer
	// takes the SAME decision instead of each answering from the state it loaded.
	postgresMigrationEnrolledIdentityClaims = "035"
	// 036 records that the EXISTING fleet has been imported into the claim — the migration's end, so a node
	// with nothing to contribute cannot mistake its own empty backfill for the deployment being ready.
	postgresMigrationEnrolledIdentityClaimBarrier = "036"
	// 037 moves claim rows written before the tenant key was canonicalised. Without it the canonicalisation
	// re-opens the double-claim hole for every identity claimed before the upgrade.
	postgresMigrationEnrolledIdentityClaimTenantCase = "037"
	// 038 records DELETED tenants. The bundle's tenant section UPSERTs — deliberately, since an absent entry is
	// indistinguishable from a truncated payload — so a deletion has to be named to travel at all. Without the
	// table the control plane deletes a tenant and every Edge keeps serving it.
	postgresMigrationAdminTenantModelDeletions = "038"
	// 039 carries the STANDING DELEGATION. Without it the Postgres backend answers false for every
	// organization, whatever they granted — the operator envelope is inert in the backend the deployment
	// documentation names for production, and the customer's own screen reads "not allowed" one second after
	// they allowed it. The file store held it from the start, so the two backends disagreed about the one
	// field that decides whether the operator may act inside a customer at all.
	postgresMigrationAdminTenantModelDelegation = "039"
	// 040 carries the REST of the envelope, found by comparing the model's fields to the store's columns rather
	// than by noticing another one. operator_elevation_requires_approval fails OPEN when dropped — the
	// organization's requirement that it approve first simply does not apply — and operator_elevations is the
	// customer's only record that the operator ever used the envelope at all.
	postgresMigrationAdminTenantModelEnvelope = "040"
	// 041 records ERASURE ORDERS. Found the same way 039 and 040 were — by comparing what the file store does
	// to what the Postgres store implements, rather than by waiting for a symptom. The Postgres backend had no
	// OrderPurge and no PurgeOrders at all, and both call sites reach them through a type assertion, so on a
	// Postgres control plane an ordered erasure recorded nothing, erased this node's own copy, and answered
	// with a result. Nodes that were offline, or that simply are not this one, were never told.
	postgresMigrationAdminTenantModelPurgeOrders = "041"
	// 044 carries WHO withdrew the delegation. The operator decided that an MSSP operator may not reopen what
	// the customer closed, and that rule rests on exactly one bit; dropped, it reads false and the rule fails
	// OPEN. Same class as 039 and 040 — a field the model has and the production backend does not, which is
	// how the envelope came to be inert on Postgres while every test on the file store passed.
	postgresMigrationAdminTenantModelDelegationWithdrawal = "044"
)

// The shared -postgres-dsn connection carries both the CP-state blob table and the enrolment-token ROWS. They
// travel together because they are selected by the same flag and opened on the same handle: an operator who set
// -enrolment-token-store=postgres and found the table missing would have no separate knob to turn.
func postgresCPStateBlobsMigrationVersions() []string {
	return []string{postgresMigrationCPStateBlobs, postgresMigrationEnrolmentTokens, postgresMigrationEnrolmentTokenIssuerLabel, "047"}
}

func selectPostgresComponentMigrations(migrations []migrationstore.Migration, component string, versions ...string) ([]migrationstore.Migration, error) {
	selected, err := migrationstore.SelectVersions(migrations, versions...)
	if err != nil {
		return nil, fmt.Errorf("select %s migrations: %w", component, err)
	}
	return selected, nil
}

func postgresExportWorkerMigrationVersions(hotStoreMode string) []string {
	versions := []string{
		postgresMigrationExportWorkerQueue,
		postgresMigrationAdminExportJobs,
		postgresMigrationAdminAuditOutbox,
	}
	if strings.EqualFold(strings.TrimSpace(hotStoreMode), "postgres") {
		versions = append(versions, postgresHotStoreMigrationVersions()...)
	}
	return versions
}

func postgresHotStoreMigrationVersions() []string {
	return []string{
		postgresMigrationHotEvents,
		postgresMigrationHotEventsText,
	}
}

func postgresDomainEventOutboxMigrationVersions() []string {
	return []string{
		postgresMigrationDomainEventOutbox,
		postgresMigrationDomainEventStream,
	}
}

func postgresUsageMeterMigrationVersions() []string {
	return []string{
		postgresMigrationUsageMeter,
	}
}

func postgresNonHumanIdentityMigrationVersions() []string {
	return []string{
		postgresMigrationNonHumanIdentity,
	}
}

func postgresWorkloadAttestationNonceMigrationVersions() []string {
	return []string{
		postgresMigrationWorkloadNonce,
	}
}

func postgresHumanIdentityDirectoryMigrationVersions() []string {
	return []string{
		postgresMigrationHumanIdentity,
		postgresMigrationHumanIdentityImportRun,
		postgresMigrationHumanIdentitySource,
		postgresMigrationHumanIdentitySourceState,
		postgresMigrationHumanIdentitySourcePolicy,
	}
}

func postgresConnectorRegistryMigrationVersions() []string {
	return []string{
		postgresMigrationConnectorRegistry,
	}
}

func postgresDeviceInventoryMigrationVersions() []string {
	return []string{
		postgresMigrationDeviceInventory,
	}
}

// postgresEnrolledIdentityClaimMigrationVersions is the one-time identity claim an ISSUING Edge needs.
func postgresEnrolledIdentityClaimMigrationVersions() []string {
	return []string{
		postgresMigrationEnrolledIdentityClaims,
		postgresMigrationEnrolledIdentityClaimBarrier,
		postgresMigrationEnrolledIdentityClaimTenantCase,
	}
}

func postgresAgentTelemetryMigrationVersions() []string {
	return []string{
		postgresMigrationAgentTelemetry,
		// 033 re-keys agent_update_events and agent_status_events to (tenant, device, event). It belongs to the
		// same store, so it is applied wherever the telemetry tables are.
		postgresMigrationAgentUpdateEventScope,
		postgresMigrationAgentUpdateRefused,
	}
}

func postgresAdminSiteMigrationVersions() []string {
	return []string{
		postgresMigrationAdminSites,
	}
}

func postgresApplicationCatalogMigrationVersions() []string {
	return []string{
		postgresMigrationApplicationCatalog,
	}
}

func postgresObservedExclusionMigrationVersions() []string {
	return []string{
		postgresMigrationObservedExclusions,
		postgresMigrationObservedTrustTelemetry,
		postgresMigrationObservedAgentPolicyKeys,
		postgresMigrationObservedRecoveryName,
		postgresMigrationObservedRecoveryTarget,
		postgresMigrationObservedInterceptionRefusals,
	}
}
