package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	migrationstore "github.com/lantern-networks/dsse-core/migrations"
)

func exerciseTOTPRestartProtection(t *testing.T, open func() credentialPersistence) {
	t.Helper()
	now := time.Now().UTC()
	load := func() *localAdminCredentialStore {
		s, err := newLocalAdminCredentialStoreWithPersistence("DSSE", open())
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	s := load()
	email := "totp-restart@example.invalid"
	token, err := s.Invite(email, "tenant_totp", "adm_totp", []string{"admin"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetActivationPassword(token, "initial-passphrase-long", now); err != nil {
		t.Fatal(err)
	}
	secret, _, err := s.BeginTOTPEnrollment(token, now)
	if err != nil {
		t.Fatal(err)
	}
	enrollmentCode, _ := totpCodeForCounter(secret, uint64(now.Unix())/totpPeriod)
	recovery, err := s.CompleteActivation(token, enrollmentCode, now)
	if err != nil {
		t.Fatal(err)
	}
	code, _ := totpCodeForCounter(s.byEmail[email].TOTPSecret, uint64(now.Unix())/totpPeriod)
	if _, err := s.VerifyTOTP(email, code, now); err != nil {
		t.Fatal(err)
	}
	consumed := s.byEmail[email].LastTOTPCounter
	s = load()
	if s.byEmail[email].LastTOTPCounter != consumed || consumed == 0 {
		t.Fatal("restart lost the consumed step")
	}
	if _, err := s.VerifyTOTP(email, code, now); err == nil {
		t.Fatal("restart accepted a consumed code")
	}
	if _, err := s.VerifyTOTP(email, recovery[0], now); err != nil {
		t.Fatal(err)
	}
	s = load()
	if _, err := s.VerifyTOTP(email, recovery[0], now); err == nil {
		t.Fatal("restart accepted a consumed recovery code")
	}
	future := now.Add(3 * totpPeriod * time.Second)
	next, _ := totpCodeForCounter(s.byEmail[email].TOTPSecret, uint64(future.Unix())/totpPeriod)
	if _, err := s.VerifyTOTP(email, next, future); err != nil {
		t.Fatalf("fresh code rejected: %v", err)
	}
	// Replacing the authenticator starts a separate counter history. The old
	// authenticator has consumed a future step, so retaining it would reject this one.
	token, err = s.Invite(email, "tenant_totp", "unused_new_id", []string{"admin"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetActivationPassword(token, "replacement-passphrase-long", now); err != nil {
		t.Fatal(err)
	}
	secret, _, err = s.BeginTOTPEnrollment(token, now)
	if err != nil {
		t.Fatal(err)
	}
	fresh, _ := totpCodeForCounter(secret, uint64(now.Unix())/totpPeriod)
	if _, err := s.CompleteActivation(token, fresh, now); err != nil {
		t.Fatal(err)
	}
	s = load()
	if s.byEmail[email].LastTOTPCounter != 0 {
		t.Fatal("new authenticator inherited old counter")
	}
	if _, err := s.VerifyTOTP(email, fresh, now); err != nil {
		t.Fatalf("new authenticator rejected: %v", err)
	}
}

func TestTOTPCounterSurvivesFileRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	exerciseTOTPRestartProtection(t, func() credentialPersistence { return newFileCredentialPersistence(path) })
}

func TestLegacyCredentialFileWithoutCounterLoads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	if err := os.WriteFile(path, []byte(`[{"email":"legacy@example.invalid","principal_id":"legacy","tenant_id":"tenant","status":"pending_activation"}]`), 0600); err != nil {
		t.Fatal(err)
	}
	s, err := newLocalAdminCredentialStoreWithPersistence("DSSE", newFileCredentialPersistence(path))
	if err != nil {
		t.Fatal(err)
	}
	if c := s.byEmail["legacy@example.invalid"]; c == nil || c.LastTOTPCounter != 0 {
		t.Fatal("legacy snapshot does not load")
	}
}

func TestTOTPCounterPostgresUpgradeAndRestart(t *testing.T) {
	dsn := os.Getenv("POSTGRES_QUEUE_E2E_DSN")
	if dsn == "" {
		t.Skip("POSTGRES_QUEUE_E2E_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := fmt.Sprintf("totp_restart_%d", time.Now().UnixNano())
	if _, err := admin.ExecContext(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := admin.ExecContext(context.Background(), `DROP SCHEMA `+schema+` CASCADE`); err != nil {
			t.Error(err)
		}
	}()
	scopedDSN := dsn + " search_path=" + schema
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		u, err := url.Parse(dsn)
		if err != nil {
			t.Fatal(err)
		}
		q := u.Query()
		q.Set("search_path", schema)
		u.RawQuery = q.Encode()
		scopedDSN = u.String()
	}
	old, err := sql.Open("postgres", scopedDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	migrations, err := migrationstore.LoadDir("../../migrations")
	if err != nil {
		t.Fatal(err)
	}
	selected, err := selectPostgresComponentMigrations(migrations, "legacy credentials", postgresMigrationLocalCredentials)
	if err != nil {
		t.Fatal(err)
	}
	if err := migrationstore.Apply(ctx, old, selected); err != nil {
		t.Fatal(err)
	}
	if _, err := old.ExecContext(ctx, `INSERT INTO admin_local_credentials(email,principal_id,tenant_id,status) VALUES('legacy@example.invalid','legacy','tenant','pending_activation')`); err != nil {
		t.Fatal(err)
	}
	// Exercise the production component migration selection, not a hand-written ALTER.
	persistence, closeDB, err := setupLocalCredentialPersistence(ctx, "postgres", scopedDSN, "../../migrations", true)
	if err != nil {
		t.Fatal(err)
	}
	defer closeDB()
	rows, err := persistence.LoadAll(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].LastTOTPCounter != 0 {
		t.Fatal("legacy PostgreSQL row was not upgraded")
	}
	exerciseTOTPRestartProtection(t, func() credentialPersistence { return persistence })
	exerciseConcurrentCredentialConsumption(t, persistence)
	store, err := newLocalAdminCredentialStoreWithPersistence("DSSE", persistence)
	if err != nil {
		t.Fatal(err)
	}
	email := "totp-restart@example.invalid"
	before := cloneCredential(store.byEmail[email])
	if _, err := old.ExecContext(ctx, `CREATE FUNCTION reject_credential_write() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected write refusal'; END $$;
 CREATE TRIGGER reject_credential_write BEFORE INSERT OR UPDATE OR DELETE ON admin_local_credentials FOR EACH ROW EXECUTE FUNCTION reject_credential_write()`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetRoles(before.TenantID, before.PrincipalID, []string{"analyst"}, time.Now()); !errors.Is(err, errCredentialPersistence) {
		t.Fatal("PostgreSQL role save failure was hidden")
	}
	if _, err := store.Delete(before.TenantID, before.PrincipalID, time.Now()); !errors.Is(err, errCredentialPersistence) {
		t.Fatal("PostgreSQL deletion failure was hidden")
	}
	future := time.Now().UTC().Add(5 * totpPeriod * time.Second)
	code, _ := totpCodeForCounter(before.TOTPSecret, uint64(future.Unix())/totpPeriod)
	if credential, err := store.VerifyTOTP(email, code, future); credential != nil || !errors.Is(err, errCredentialPersistence) {
		t.Fatal("PostgreSQL save failure issued a successful authentication")
	}
	reloaded, err := newLocalAdminCredentialStoreWithPersistence("DSSE", persistence)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []*localAdminCredentialStore{store, reloaded} {
		c := s.byEmail[email]
		if c == nil || c.LastTOTPCounter != before.LastTOTPCounter || len(c.Roles) != 1 || c.Roles[0] != "admin" {
			t.Fatal("refused PostgreSQL mutation changed account state")
		}
	}
	if _, err := old.ExecContext(ctx, `DROP TRIGGER reject_credential_write ON admin_local_credentials`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.VerifyTOTP(email, code, future); err != nil {
		t.Fatal(err)
	}
	reloaded, err = newLocalAdminCredentialStoreWithPersistence("DSSE", persistence)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reloaded.VerifyTOTP(email, code, future); err == nil {
		t.Fatal("PostgreSQL retry failed to preserve replay protection")
	}
	for _, field := range []string{"roles", "recovery_code_hashes"} {
		// The column names are fixed test cases, never external input.
		if _, err := old.ExecContext(ctx, `UPDATE admin_local_credentials SET `+field+`='{}'::jsonb WHERE email='legacy@example.invalid'`); err != nil {
			t.Fatal(err)
		}
		if _, err := newLocalAdminCredentialStoreWithPersistence("DSSE", persistence); err == nil {
			t.Fatalf("malformed %s was silently dropped", field)
		}
		if _, err := old.ExecContext(ctx, `UPDATE admin_local_credentials SET `+field+`='[]'::jsonb WHERE email='legacy@example.invalid'`); err != nil {
			t.Fatal(err)
		}
	}

}

func exerciseConcurrentCredentialConsumption(t *testing.T, p credentialPersistence) {
	t.Helper()
	load := func() *localAdminCredentialStore {
		s, e := newLocalAdminCredentialStoreWithPersistence("DSSE", p)
		if e != nil {
			t.Fatal(e)
		}
		return s
	}
	s := load()
	now := time.Now().UTC()
	email := "concurrent@example.invalid"
	token, e := s.Invite(email, "tenant_cas", "adm_cas", []string{"admin"}, now)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.SetActivationPassword(token, "long-test-password", now); e != nil {
		t.Fatal(e)
	}
	secret, _, e := s.BeginTOTPEnrollment(token, now)
	if e != nil {
		t.Fatal(e)
	}
	code, _ := totpCodeForCounter(secret, uint64(now.Unix())/totpPeriod)
	recovery, e := s.CompleteActivation(token, code, now)
	if e != nil {
		t.Fatal(e)
	}
	for _, value := range []string{code, recovery[0]} {
		a, b := load(), load()
		start := make(chan struct{})
		results := make(chan error, 2)
		for _, node := range []*localAdminCredentialStore{a, b} {
			go func(n *localAdminCredentialStore) { <-start; _, e := n.VerifyTOTP(email, value, now); results <- e }(node)
		}
		close(start)
		success := 0
		for i := 0; i < 2; i++ {
			if <-results == nil {
				success++
			}
		}
		if success != 1 {
			t.Fatalf("same code accepted by %d authorities", success)
		}
		// The losing authority refreshes on conflict; both now refuse replay.
		for _, node := range []*localAdminCredentialStore{a, b} {
			if c, e := node.VerifyTOTP(email, value, now); e == nil || c != nil {
				t.Fatal("replay after conflict accepted")
			}
		}
	}
	a, b := load(), load()
	if _, e := a.SetStatus("tenant_cas", "adm_cas", credentialStatusSuspended, now); e != nil {
		t.Fatal(e)
	}
	if _, e := b.SetRoles("tenant_cas", "adm_cas", []string{"analyst"}, now); !errors.Is(e, errCredentialPersistence) {
		t.Fatal("stale role write accepted")
	}
	if b.byEmail[email].Status != credentialStatusSuspended {
		t.Fatal("conflict did not refresh suspension")
	}
	if _, e := b.SetRoles("tenant_cas", "adm_cas", []string{"analyst"}, now); e != nil {
		t.Fatal(e)
	}
	// An existing row deleted elsewhere must never be reinserted by a stale upsert.
	a, b = load(), load()
	oldGeneration := cloneCredential(a.byEmail[email])
	if _, e := a.Delete("tenant_cas", "adm_cas", now); e != nil {
		t.Fatal(e)
	}
	if _, e := b.SetStatus("tenant_cas", "adm_cas", credentialStatusActive, now); !errors.Is(e, errCredentialPersistence) {
		t.Fatal("stale write resurrected deleted account")
	}
	if load().byEmail[email] != nil {
		t.Fatal("deleted account exists")
	}
	// A stale generation must also fail after the same address is recreated.
	stale := oldGeneration
	fresh := load()
	if _, e := fresh.Invite(email, "tenant_cas", "adm_recreated", []string{"admin"}, now); e != nil {
		t.Fatal(e)
	}
	if e := p.Upsert(context.Background(), stale); !errors.Is(e, errCredentialConflict) {
		t.Fatal("stale generation replaced recreated account")
	}
	if load().byEmail[email].PrincipalID != "adm_recreated" {
		t.Fatal("recreated identity overwritten")
	}
	if _, e := fresh.Delete("tenant_cas", "adm_recreated", now); e != nil {
		t.Fatal(e)
	}
}
