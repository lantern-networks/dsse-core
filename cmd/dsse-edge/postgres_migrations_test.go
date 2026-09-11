package main

import (
	"reflect"
	"strings"
	"testing"

	migrationstore "github.com/lantern-networks/dsse-core/migrations"
)

func TestPostgresExportWorkerMigrationVersions(t *testing.T) {
	if got, want := postgresExportWorkerMigrationVersions("jsonl"), []string{"001", "002", "004"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("jsonl worker versions = %#v, want %#v", got, want)
	}
	if got, want := postgresExportWorkerMigrationVersions(" postgres "), []string{"001", "002", "004", "003", "010"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("postgres worker versions = %#v, want %#v", got, want)
	}
}

func TestPostgresHotStoreMigrationVersions(t *testing.T) {
	if got, want := postgresHotStoreMigrationVersions(), []string{"003", "010"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("hot store versions = %#v, want %#v", got, want)
	}
}

func TestPostgresWorkloadAttestationNonceMigrationVersions(t *testing.T) {
	if got, want := postgresWorkloadAttestationNonceMigrationVersions(), []string{"011"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("workload attestation nonce versions = %#v, want %#v", got, want)
	}
}

func TestPostgresHumanIdentityDirectoryMigrationVersions(t *testing.T) {
	if got, want := postgresHumanIdentityDirectoryMigrationVersions(), []string{"012", "013", "014", "015", "016"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("human identity directory versions = %#v, want %#v", got, want)
	}
}

func TestPostgresConnectorRegistryMigrationVersions(t *testing.T) {
	if got, want := postgresConnectorRegistryMigrationVersions(), []string{"017"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("connector registry versions = %#v, want %#v", got, want)
	}
}

func TestPostgresDeviceInventoryMigrationVersions(t *testing.T) {
	if got, want := postgresDeviceInventoryMigrationVersions(), []string{"018"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("device inventory versions = %#v, want %#v", got, want)
	}
}

func TestPostgresDomainEventOutboxMigrationVersions(t *testing.T) {
	if got, want := postgresDomainEventOutboxMigrationVersions(), []string{"006", "007"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("domain event outbox versions = %#v, want %#v", got, want)
	}
}

func TestSelectPostgresDomainEventOutboxMigrationsIncludesStreamCheck(t *testing.T) {
	migrations := []migrationstore.Migration{
		{Version: "006", Name: "domain_event_outbox"},
		{Version: "007", Name: "domain_event_outbox_stream_check"},
		{Version: "999", Name: "unrelated"},
	}
	selected, err := selectPostgresComponentMigrations(migrations, "domain event outbox", postgresDomainEventOutboxMigrationVersions()...)
	if err != nil {
		t.Fatalf("select domain event outbox migrations returned error: %v", err)
	}
	if got, want := len(selected), 2; got != want {
		t.Fatalf("selected migrations = %#v, want %d", selected, want)
	}
	if selected[0].Version != "006" || selected[1].Version != "007" {
		t.Fatalf("selected migrations = %#v, want 006 then 007", selected)
	}
}

func TestSelectPostgresUsageMeterMigrations(t *testing.T) {
	migrations := []migrationstore.Migration{
		{Version: "008", Name: "usage_meter_records"},
		{Version: "999", Name: "unrelated"},
	}
	selected, err := selectPostgresComponentMigrations(migrations, "usage meter", postgresUsageMeterMigrationVersions()...)
	if err != nil {
		t.Fatalf("select usage meter migrations returned error: %v", err)
	}
	if got, want := len(selected), 1; got != want {
		t.Fatalf("selected migrations = %#v, want %d", selected, want)
	}
	if selected[0].Version != "008" {
		t.Fatalf("selected migrations = %#v, want 008", selected)
	}
}

func TestSelectPostgresComponentMigrationsWrapsComponentName(t *testing.T) {
	_, err := selectPostgresComponentMigrations([]migrationstore.Migration{{Version: "001", Name: "queue"}}, "admin auth", postgresMigrationAdminAuth)
	if err == nil || !containsAll(err.Error(), []string{"select admin auth migrations", "missing migration version"}) {
		t.Fatalf("error = %v, want component-scoped missing migration error", err)
	}
}

func containsAll(value string, parts []string) bool {
	for _, part := range parts {
		if !strings.Contains(value, part) {
			return false
		}
	}
	return true
}
