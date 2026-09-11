package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

// TestPostgresObservedExclusionMigrationMatchesSchemaSQL keeps the on-disk migration in lockstep with the in-code
// schema contract, the same fidelity guard the application catalog / site / tenant model stores use.
func TestPostgresObservedExclusionMigrationMatchesSchemaSQL(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "migrations", "027_observed_steer_exclusions.sql"))
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	want := normalizePostgresExportTaskSQLContract(strings.Join(postgresObservedExclusionSchemaSQL(), "\n"))
	got := normalizePostgresExportTaskSQLContract(string(data))
	if got != want {
		t.Fatalf("observed exclusion migration SQL does not match schema helper\nmigration: %s\nhelper:    %s", got, want)
	}
}

// TestPostgresObservedExclusionSchemaSecurityContracts pins the per-device upsert key (composite PK on tenant_id +
// device_identity, which both tenant-scopes reads and enforces one latest-wins row per device) and the columns
// that must survive a round-trip.
func TestPostgresObservedExclusionSchemaSecurityContracts(t *testing.T) {
	sqlText := strings.Join(postgresObservedExclusionSchemaSQL(), "\n")
	for _, want := range []string{
		"PRIMARY KEY (tenant_id, device_identity)",
		"tenant_id text NOT NULL",
		"device_identity text NOT NULL",
		"effective_app_signing_ids jsonb NOT NULL DEFAULT '[]'",
		"admin_app_signing_ids jsonb NOT NULL DEFAULT '[]'",
		"unmanaged_app_signing_ids jsonb NOT NULL DEFAULT '[]'",
		"server_app_signing_id_count integer NOT NULL DEFAULT 0",
		"reported_at timestamptz NOT NULL",
	} {
		if !strings.Contains(sqlText, want) {
			t.Fatalf("observed exclusion schema SQL missing %q:\n%s", want, sqlText)
		}
	}
}

// TestPostgresObservedExclusionMigrationVersions confirms the component migration set: the 027 base table and
// the 031 trust-telemetry columns.
//
// ★★★ AND 045, ADDED AFTER THE OMISSION BIT (2026-08-22). The columns and the migration file both landed and
// this list did not, so nothing selected the file: every device report was dropped with "column does not
// exist" and three posture checks went to "no devices reported" within a minute of the deploy. The list is
// explicit on purpose — that is what makes an unlisted file visible — and the cost is that it must be
// extended, which is what this test is for.
func TestPostgresObservedExclusionMigrationVersions(t *testing.T) {
	versions := postgresObservedExclusionMigrationVersions()
	want := []string{postgresMigrationObservedExclusions, postgresMigrationObservedTrustTelemetry,
		postgresMigrationObservedAgentPolicyKeys, postgresMigrationObservedRecoveryName,
		postgresMigrationObservedRecoveryTarget, postgresMigrationObservedInterceptionRefusals}
	if len(versions) != len(want) {
		t.Fatalf("observed exclusion migration versions = %#v, want %#v", versions, want)
	}
	for i := range want {
		if versions[i] != want[i] {
			t.Fatalf("observed exclusion migration versions = %#v, want %#v", versions, want)
		}
	}
}

// TestPostgresObservedTrustTelemetryMigrationMatchesSchemaSQL keeps 031 in lockstep with its in-code contract,
// like the 027 guard above.
func TestPostgresObservedTrustTelemetryMigrationMatchesSchemaSQL(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "migrations", "031_observed_trust_telemetry.sql"))
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	// The migration file carries its WHY as comment lines; the contract is about the statements.
	statements := []string{}
	for _, line := range strings.Split(string(data), "\n") {
		if t := strings.TrimSpace(line); t != "" && !strings.HasPrefix(t, "--") {
			statements = append(statements, t)
		}
	}
	want := normalizePostgresExportTaskSQLContract(strings.Join(postgresObservedTrustTelemetrySchemaSQL(), "\n"))
	got := normalizePostgresExportTaskSQLContract(strings.Join(statements, "\n"))
	if got != want {
		t.Fatalf("observed trust-telemetry migration SQL does not match schema helper\nmigration: %s\nhelper:    %s", got, want)
	}
}

// TestPostgresObservedTrustTelemetryColumnsAreRecordedAndScanned pins that the canonical column list carries
// the trust fields — the exact ones this backend used to discard while the in-memory backend kept them, which
// would have made every PKI gate read "silent" on a postgres deployment.
func TestPostgresObservedTrustTelemetryColumnsAreRecordedAndScanned(t *testing.T) {
	for _, col := range []string{
		"pinned_transport_ca_sha256", "adopted_trust_serial",
		"pinned_interception_root_sha256", "trust_refusals", "fallback_client_cert_pem", "agent_policy_public_keys",
	} {
		if !strings.Contains(observedExclusionColumns, col) {
			t.Fatalf("observedExclusionColumns is missing %q — the postgres backend would drop it silently", col)
		}
	}
}

// TestSetupPostgresObservedExclusionStoreRequiresDSN confirms the backend fails fast (rather than silently
// degrading) when no DSN is available.
func TestSetupPostgresObservedExclusionStoreRequiresDSN(t *testing.T) {
	_, _, err := setupPostgresObservedExclusionStore(context.Background(), "", "migrations", false)
	if err == nil || !strings.Contains(err.Error(), "observed-exclusion-store-postgres-dsn is required") {
		t.Fatalf("setup error = %v, want DSN-required error", err)
	}
}

// TestPostgresObservedExclusionStoreImplementsAPI is a compile-time assertion mirror (the var assertion in the
// store file proves it too); kept explicit so the contract break shows up as a failing test, not just a build error.
func TestPostgresObservedExclusionStoreImplementsAPI(t *testing.T) {
	var _ observedExclusionStoreAPI = (*postgresObservedExclusionStore)(nil)
}

// TestPostgresObservedExclusionStoreE2E exercises Record (latest-wins upsert), Query (filters + pagination), and
// ByApp (aggregate + class) against a real Postgres, plus tenant scoping. Env-gated and skipped when
// POSTGRES_QUEUE_E2E_DSN is unset, matching the other postgres E2E tests.
func TestPostgresObservedExclusionStoreE2E(t *testing.T) {
	dsn := os.Getenv("POSTGRES_QUEUE_E2E_DSN")
	if dsn == "" {
		t.Skip("POSTGRES_QUEUE_E2E_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	store, closeStore, err := setupPostgresObservedExclusionStore(ctx, dsn, filepath.Join("..", "..", "migrations"), true)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	t.Cleanup(func() {
		_, _ = store.db.ExecContext(context.Background(), "DROP TABLE IF EXISTS observed_steer_exclusions")
		_ = closeStore()
	})
	if _, err := store.db.ExecContext(ctx, "TRUNCATE observed_steer_exclusions"); err != nil {
		t.Fatalf("truncate: %v", err)
	}

	tenantA := "tenant_lab_001"
	tenantB := "tenant_other_001"
	t0 := time.Date(2026, 6, 28, 3, 0, 0, 0, time.UTC)

	// device-1: an unmanaged (anomalous) effective entry.
	store.Record(observedExclusionEntry{
		TenantID: tenantA, DeviceIdentity: "device-1", DeviceGroup: "eng", Platform: "macos",
		EffectiveAppSigningIDs: []string{"a.out", "com.admin.app", "com.rogue.app"},
		AdminAppSigningIDs:     []string{"com.admin.app"},
		UnmanagedAppSigningIDs: []string{"com.rogue.app"},
		ReportedAt:             t0,
	})
	// device-2: only admin + floor (not anomalous), carrying the full trust half of the report — the fields
	// this backend used to discard.
	store.Record(observedExclusionEntry{
		TenantID: tenantA, DeviceIdentity: "device-2", DeviceGroup: "sales", Platform: "windows",
		EffectiveAppSigningIDs:       []string{"a.out", "com.admin.app"},
		AdminAppSigningIDs:           []string{"com.admin.app"},
		ReportedAt:                   t0.Add(time.Minute),
		PinnedTransportCASHA256:      []string{strings.Repeat("ab", 32)},
		AdoptedTrustSerial:           5,
		PinnedInterceptionRootSHA256: []string{strings.Repeat("cd", 32)},
		TrustRefusals: []observedTrustRefusal{{ServedSHA256: strings.Repeat("ef", 32),
			Reason: "x509: certificate signed by unknown authority", FirstAt: t0, LastAt: t0.Add(time.Minute), Count: 3}},
		FallbackClientCertPEM: "-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n",
		AgentPolicyPublicKeys: []string{strings.Repeat("ab", 32)},
	})
	// Other tenant must never appear in tenant A reads.
	store.Record(observedExclusionEntry{
		TenantID: tenantB, DeviceIdentity: "device-x", EffectiveAppSigningIDs: []string{"com.other.app"}, ReportedAt: t0,
	})

	// Latest-wins upsert: re-report device-1 with a different group; only one row should remain.
	store.Record(observedExclusionEntry{
		TenantID: tenantA, DeviceIdentity: "device-1", DeviceGroup: "eng-renamed", Platform: "macos",
		EffectiveAppSigningIDs: []string{"a.out", "com.admin.app", "com.rogue.app"},
		AdminAppSigningIDs:     []string{"com.admin.app"},
		UnmanagedAppSigningIDs: []string{"com.rogue.app"},
		ReportedAt:             t0.Add(2 * time.Minute),
	})

	// Query all for tenant A: 2 devices, newest first (device-1 re-reported last).
	all := store.Query(tenantA, observedQueryFilter{})
	if all.Total != 2 || len(all.Entries) != 2 {
		t.Fatalf("query all = total %d / %d entries, want 2/2", all.Total, len(all.Entries))
	}
	if all.Entries[0].DeviceIdentity != "device-1" || all.Entries[0].DeviceGroup != "eng-renamed" {
		t.Fatalf("latest-wins upsert / ordering wrong: %#v", all.Entries[0])
	}

	// AnomalousOnly => only device-1.
	anom := store.Query(tenantA, observedQueryFilter{AnomalousOnly: true})
	if anom.Total != 1 || anom.Entries[0].DeviceIdentity != "device-1" {
		t.Fatalf("anomalous filter = %#v, want only device-1", anom.Entries)
	}

	// Device prefix filter (case-insensitive) matches both.
	if pref := store.Query(tenantA, observedQueryFilter{Device: "DEVICE-*"}); pref.Total != 2 {
		t.Fatalf("prefix filter total = %d, want 2", pref.Total)
	}
	// Device exact filter — and the trust half of the report survives the round-trip. These fields feed the
	// anchor-withdraw and CA-retire gates; a backend that drops them reads as "every device silent".
	exact := store.Query(tenantA, observedQueryFilter{Device: "device-2"})
	if exact.Total != 1 || exact.Entries[0].DeviceIdentity != "device-2" {
		t.Fatalf("exact filter = %#v, want device-2", exact.Entries)
	}
	d2 := exact.Entries[0]
	if len(d2.PinnedTransportCASHA256) != 1 || d2.PinnedTransportCASHA256[0] != strings.Repeat("ab", 32) {
		t.Fatalf("pinned_transport_ca_sha256 did not round-trip: %#v", d2.PinnedTransportCASHA256)
	}
	if d2.AdoptedTrustSerial != 5 {
		t.Fatalf("adopted_trust_serial did not round-trip: %d", d2.AdoptedTrustSerial)
	}
	if len(d2.PinnedInterceptionRootSHA256) != 1 || d2.PinnedInterceptionRootSHA256[0] != strings.Repeat("cd", 32) {
		t.Fatalf("pinned_interception_root_sha256 did not round-trip: %#v", d2.PinnedInterceptionRootSHA256)
	}
	if len(d2.TrustRefusals) != 1 || d2.TrustRefusals[0].Count != 3 ||
		d2.TrustRefusals[0].Reason != "x509: certificate signed by unknown authority" {
		t.Fatalf("trust_refusals did not round-trip: %#v", d2.TrustRefusals)
	}
	if !strings.Contains(d2.FallbackClientCertPEM, "BEGIN CERTIFICATE") {
		t.Fatalf("fallback_client_cert_pem did not round-trip: %q", d2.FallbackClientCertPEM)
	}
	if len(d2.AgentPolicyPublicKeys) != 1 || d2.AgentPolicyPublicKeys[0] != strings.Repeat("ab", 32) {
		t.Fatalf("agent_policy_public_keys did not round-trip: %#v", d2.AgentPolicyPublicKeys)
	}
	// And the readiness the withdraw gate consumes now works on this backend. A separate tenant with a FRESH
	// report, because readiness deliberately ignores reports older than the telemetry shelf life — tenant A's
	// fixed June timestamps are stale by design (they pin ordering), and stale must read silent.
	tenantC := "tenant_readiness_001"
	store.Record(observedExclusionEntry{
		TenantID: tenantC, DeviceIdentity: "device-r",
		EffectiveAppSigningIDs:  []string{"a.out"},
		ReportedAt:              time.Now().UTC(),
		PinnedTransportCASHA256: []string{strings.Repeat("ab", 32)},
		AdoptedTrustSerial:      5,
	})
	ready := store.TransportCAReadinessAtSerial(tenantC, strings.Repeat("ab", 32), []string{"device-r"}, 5)
	if len(ready.Ready) != 1 || ready.Ready[0] != "device-r" || !ready.SafeToCut {
		t.Fatalf("postgres-backed readiness = %#v, want device-r ready", ready)
	}
	// Group filter (case-insensitive).
	if grp := store.Query(tenantA, observedQueryFilter{Group: "SALES"}); grp.Total != 1 || grp.Entries[0].DeviceIdentity != "device-2" {
		t.Fatalf("group filter = %#v, want device-2", grp.Entries)
	}
	// App membership filter (case-insensitive) => both have com.admin.app.
	if app := store.Query(tenantA, observedQueryFilter{App: "COM.ADMIN.APP"}); app.Total != 2 {
		t.Fatalf("app filter total = %d, want 2", app.Total)
	}
	if app := store.Query(tenantA, observedQueryFilter{App: "com.rogue.app"}); app.Total != 1 || app.Entries[0].DeviceIdentity != "device-1" {
		t.Fatalf("app filter (rogue) = %#v, want device-1", app.Entries)
	}

	// Pagination: limit 1, two pages.
	p0 := store.Query(tenantA, observedQueryFilter{Limit: 1, Offset: 0})
	p1 := store.Query(tenantA, observedQueryFilter{Limit: 1, Offset: 1})
	if p0.Total != 2 || len(p0.Entries) != 1 || p1.Total != 2 || len(p1.Entries) != 1 {
		t.Fatalf("pagination = page0 %d/%d page1 %d/%d, want total 2 + 1 entry each", p0.Total, len(p0.Entries), p1.Total, len(p1.Entries))
	}
	if p0.Entries[0].DeviceIdentity == p1.Entries[0].DeviceIdentity {
		t.Fatalf("pagination returned the same device twice: %s", p0.Entries[0].DeviceIdentity)
	}

	// ByApp: com.rogue.app is unmanaged (class wins), com.admin.app admin, a.out floor; device_total = 2.
	byApp := store.ByApp(tenantA, 10)
	if byApp.DeviceTotal != 2 {
		t.Fatalf("by-app device total = %d, want 2", byApp.DeviceTotal)
	}
	class := map[string]observedByAppEntry{}
	for _, a := range byApp.Apps {
		class[strings.ToLower(a.AppID)] = a
	}
	if class["com.rogue.app"].Class != appClassUnmanaged || class["com.rogue.app"].DeviceCount != 1 {
		t.Fatalf("com.rogue.app = %#v, want unmanaged/1", class["com.rogue.app"])
	}
	if class["com.admin.app"].Class != appClassAdmin || class["com.admin.app"].DeviceCount != 2 {
		t.Fatalf("com.admin.app = %#v, want admin/2", class["com.admin.app"])
	}
	if class["a.out"].Class != appClassFloor || class["a.out"].DeviceCount != 2 {
		t.Fatalf("a.out = %#v, want floor/2", class["a.out"])
	}
	// Unmanaged sorts first.
	if byApp.Apps[0].Class != appClassUnmanaged {
		t.Fatalf("by-app ordering: first = %#v, want unmanaged first", byApp.Apps[0])
	}

	// Tenant scoping: tenant B sees only its own device, tenant A never sees device-x.
	if b := store.Query(tenantB, observedQueryFilter{}); b.Total != 1 || b.Entries[0].DeviceIdentity != "device-x" {
		t.Fatalf("tenant B query = %#v, want only device-x", b.Entries)
	}
	for _, e := range all.Entries {
		if e.DeviceIdentity == "device-x" {
			t.Fatal("tenant A leaked tenant B's device")
		}
	}
}

// 032 in lockstep with its in-code contract, like the 027/031 guards.
func TestPostgresObservedAgentPolicyKeysMigrationMatchesSchemaSQL(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "migrations", "032_observed_agent_policy_keys.sql"))
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	statements := []string{}
	for _, line := range strings.Split(string(data), "\n") {
		if t := strings.TrimSpace(line); t != "" && !strings.HasPrefix(t, "--") {
			statements = append(statements, t)
		}
	}
	want := normalizePostgresExportTaskSQLContract(strings.Join(postgresObservedAgentPolicyKeysSchemaSQL(), "\n"))
	got := normalizePostgresExportTaskSQLContract(strings.Join(statements, "\n"))
	if got != want {
		t.Fatalf("032 migration SQL does not match schema helper\nmigration: %s\nhelper:    %s", got, want)
	}
}

// TestPostgresObservedRecoveryNameMigrationMatchesSchemaSQL keeps 042 in lockstep with its in-code contract,
// like the 027/031/032 guards above.
//
// ★ A COMPONENT APPLIES ONLY THE MIGRATIONS IT NAMES, so a file that exists and is not listed never runs. The
// first version of 042 was in the tree, in the image, and unapplied — and the store then failed every write
// with "column does not exist", which the report path swallows as best-effort.
func TestPostgresObservedRecoveryNameMigrationMatchesSchemaSQL(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "migrations", "042_observed_recovery_name.sql"))
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	statements := []string{}
	for _, line := range strings.Split(string(data), "\n") {
		if t := strings.TrimSpace(line); t != "" && !strings.HasPrefix(t, "--") {
			statements = append(statements, t)
		}
	}
	want := normalizePostgresExportTaskSQLContract(strings.Join(postgresObservedRecoveryNameSchemaSQL(), "\n"))
	got := normalizePostgresExportTaskSQLContract(strings.Join(statements, "\n"))
	if got != want {
		t.Fatalf("042 migration SQL does not match the schema helper\nmigration: %s\nhelper:    %s", got, want)
	}
}

// TestPostgresObservedRecoveryTargetMigrationMatchesSchemaSQL — 043, in lockstep with its contract.
//
// ★ IT IS ITS OWN FILE BECAUSE 042 WAS ALREADY APPLIED. Appending the column there ran nothing, and the
// store then dropped every device report with "column does not exist" until somebody read the log.
func TestPostgresObservedRecoveryTargetMigrationMatchesSchemaSQL(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "migrations", "043_observed_recovery_target.sql"))
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	statements := []string{}
	for _, line := range strings.Split(string(data), "\n") {
		if t := strings.TrimSpace(line); t != "" && !strings.HasPrefix(t, "--") {
			statements = append(statements, t)
		}
	}
	want := normalizePostgresExportTaskSQLContract(strings.Join(postgresObservedRecoveryTargetSchemaSQL(), "\n"))
	got := normalizePostgresExportTaskSQLContract(strings.Join(statements, "\n"))
	if got != want {
		t.Fatalf("043 migration SQL does not match the schema helper\nmigration: %s\nhelper:    %s", got, want)
	}
}

// ★★★ 045 IS ITS OWN FILE, AND ITS SQL IS THE SAME AS THE CODE'S (2026-08-22).
//
// The two columns were first appended to the 043 helper, whose file this deployment has already applied —
// which is the mistake 043's own header warns about: nothing would have run, every write would have been
// dropped with "column does not exist", and the interception refusals this exists to keep would have read as
// "no device reported". An applied migration is history; new facts need new files.
func TestPostgresObservedInterceptionRefusalsMigrationMatchesSchemaSQL(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "migrations", "045_observed_interception_refusals.sql"))
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	statements := []string{}
	for _, line := range strings.Split(string(data), "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" && !strings.HasPrefix(trimmed, "--") {
			statements = append(statements, trimmed)
		}
	}
	want := normalizePostgresExportTaskSQLContract(strings.Join(postgresObservedInterceptionRefusalsSchemaSQL(), "\n"))
	got := normalizePostgresExportTaskSQLContract(strings.Join(statements, "\n"))
	if got != want {
		t.Fatalf("045 migration SQL does not match the schema helper\nmigration: %s\nhelper:    %s", got, want)
	}
	// ★ AND IT DID NOT LAND IN 043. The columns being in both would apply nothing on a deployment that has
	// already run 043, which is the failure this file exists to avoid.
	older, err := os.ReadFile(filepath.Join("..", "..", "migrations", "043_observed_recovery_target.sql"))
	if err != nil {
		t.Fatalf("read 043: %v", err)
	}
	if strings.Contains(string(older), "interception_refusals") {
		t.Fatal("interception_refusals was appended to 043, which this deployment has already applied — the " +
			"column would never be created and every write would be dropped")
	}
}
