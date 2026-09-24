package main

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/enrolltoken"
)

func TestPostgresEnrolmentStatementCancellationKeepsLeader(t *testing.T) {
	for _, operation := range []string{"issue", "spend", "revoke"} {
		for _, cancellation := range []string{"deadline", "cancel"} {
			t.Run(operation+"/"+cancellation, func(t *testing.T) {
				_, _, leader, peer := trustDistributionPostgresFixture(t)
				t.Setenv("ENROLMENT_TOKEN_E2E_DSN", os.Getenv("POSTGRES_QUEUE_E2E_DSN"))
				db := openEnrolmentTokenDB(t)
				s := newPostgresEnrolmentTokenStore(db)
				now := time.Now().UTC()
				const tenant = "tenant_test_statement"
				tok, _, err := s.Issue(enrolltoken.DefaultPolicy(), tenant, "", "original", "issuer", "", now.Add(time.Hour), now)
				if err != nil {
					t.Fatal(err)
				}
				before, err := s.ListContext(context.Background(), tenant)
				if err != nil {
					t.Fatal(err)
				}
				var pid int
				if err := leader.conn.QueryRowContext(context.Background(), "SELECT pg_backend_pid()").Scan(&pid); err != nil {
					t.Fatal(err)
				}
				term := leader.leaderSince.Load()
				if _, err := db.Exec(`CREATE FUNCTION slow_enrolment() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(0.3); RETURN NEW; END $$; CREATE TRIGGER slow_enrolment BEFORE INSERT OR UPDATE ON enrolment_tokens FOR EACH ROW EXECUTE FUNCTION slow_enrolment()`); err != nil {
					t.Fatal(err)
				}
				apply := func(ctx context.Context) error {
					switch operation {
					case "issue":
						out, secret, err := s.IssueContext(ctx, enrolltoken.DefaultPolicy(), tenant, "", "retry", "issuer", "", now.Add(time.Hour), now)
						if err != nil && (secret != "" || out.ID != "") {
							return errors.New("failed issue disclosed credential")
						}
						return err
					case "spend":
						out, err := s.SpendContext(ctx, tok.ID, tenant, "device", now)
						if err != nil && out.ID != "" {
							return errors.New("failed spend reported committed token")
						}
						return err
					default:
						out, ok, err := s.RevokeForTenantContext(ctx, tenant, tok.ID, "issuer", now)
						if err != nil && (ok || out.ID != "") {
							t.Error("failed revoke reported success")
							return errors.New("failed revoke reported success")
						}
						return err
					}
				}
				timeout := 80 * time.Millisecond
				if cancellation == "cancel" {
					timeout = 2 * time.Second
				}
				ctx, cancel := context.WithTimeout(captureCPWriteLease(context.Background()), timeout)
				defer cancel()
				done := make(chan error, 1)
				go func() { done <- apply(ctx) }()
				if cancellation == "cancel" {
					observed := false
					for until := time.Now().Add(time.Second); time.Now().Before(until); {
						var sleeping bool
						if err := db.QueryRow(`SELECT coalesce(wait_event,'')='PgSleep' FROM pg_stat_activity WHERE pid=$1`, pid).Scan(&sleeping); err != nil {
							t.Fatal(err)
						}
						if sleeping {
							observed = true
							cancel()
							break
						}
						time.Sleep(5 * time.Millisecond)
					}
					if !observed {
						t.Fatal("slow data statement not observed")
					}
				}
				err = <-done
				if err == nil {
					t.Fatal("canceled operation succeeded")
				}
				if operation != "revoke" && !errors.Is(err, enrolltoken.ErrStateUnavailable) {
					t.Fatalf("wrong error classification: %v", err)
				}
				after, err := s.ListContext(context.Background(), tenant)
				if err != nil || !reflect.DeepEqual(before, after) {
					t.Fatalf("canceled operation changed persisted state: %v", err)
				}
				leader.tick()
				peer.tick()
				if !leader.IsLeader() || peer.IsLeader() {
					t.Fatal("canceled token data statement lost leadership")
				}
				var afterPID int
				var setting string
				if err := leader.conn.QueryRowContext(context.Background(), "SELECT pg_backend_pid(), current_setting('statement_timeout')").Scan(&afterPID, &setting); err != nil || afterPID != pid || term != leader.leaderSince.Load() || setting != "0" {
					t.Fatalf("session/term/timeout changed: %v", err)
				}
				if _, err := db.Exec(`DROP TRIGGER slow_enrolment ON enrolment_tokens; DROP FUNCTION slow_enrolment()`); err != nil {
					t.Fatal(err)
				}
				if err := apply(captureCPWriteLease(context.Background())); err != nil {
					t.Fatalf("retry: %v", err)
				}
				fresh, err := newPostgresEnrolmentTokenStore(db).ListContext(context.Background(), tenant)
				if err != nil {
					t.Fatal(err)
				}
				switch operation {
				case "issue":
					if len(fresh) != 2 {
						t.Fatal("retry issue not persisted")
					}
				case "spend":
					if len(fresh) != 1 || fresh[0].UsedBy != "device" {
						t.Fatal("retry spend not persisted")
					}
					if err := apply(captureCPWriteLease(context.Background())); !errors.Is(err, enrolltoken.ErrTokenUsed) {
						t.Fatalf("second spend: %v", err)
					}
				case "revoke":
					if len(fresh) != 1 || fresh[0].RevokedBy != "issuer" {
						t.Fatal("retry revoke not persisted")
					}
				}
				t.Logf("same_pid=%d same_term=true original_state_preserved=true retry_persisted=true", pid)
			})
		}
	}
}

// COMMIT no longer forwards request cancellation (see cpStatementBudget.commit).
// A token whose COMMIT finishes after the request deadline is durable, so it is
// returned; withholding it would orphan a live credential. Leadership is kept.
func TestPostgresEnrolmentCommitAfterDeadlineReturnsDurableToken(t *testing.T) {
	_, _, leader, peer := trustDistributionPostgresFixture(t)
	t.Setenv("ENROLMENT_TOKEN_E2E_DSN", os.Getenv("POSTGRES_QUEUE_E2E_DSN"))
	db := openEnrolmentTokenDB(t)
	s := newPostgresEnrolmentTokenStore(db)
	installSlowEnrolmentCommit(t, db, "0.3")
	ctx, cancel := context.WithTimeout(captureCPWriteLease(context.Background()), 80*time.Millisecond)
	defer cancel()
	now := time.Now().UTC()
	tok, secret, err := s.IssueContext(ctx, enrolltoken.DefaultPolicy(), "tenant_test_commit", "", "", "issuer", "", now.Add(time.Hour), now)
	if ctx.Err() == nil {
		t.Fatal("request deadline did not pass during COMMIT; the case did not exercise the boundary")
	}
	if err != nil || tok.ID == "" || secret == "" {
		t.Fatalf("committed token was not returned: %v", err)
	}
	leader.tick()
	peer.tick()
	if !leader.IsLeader() || peer.IsLeader() {
		t.Fatal("request deadline during COMMIT cost leadership")
	}
	rows, err := s.ListContext(context.Background(), "tenant_test_commit")
	if err != nil || len(rows) != 1 || rows[0].ID != tok.ID {
		t.Fatalf("returned token is not the durable one: %v %d", err, len(rows))
	}
}

// A COMMIT that does not finish within budget+grace is cut off by the transport
// backstop. Its outcome is unknown, so no credential may be disclosed.
func TestPostgresEnrolmentHungCommitDoesNotDiscloseToken(t *testing.T) {
	trustDistributionPostgresFixture(t)
	t.Setenv("ENROLMENT_TOKEN_E2E_DSN", os.Getenv("POSTGRES_QUEUE_E2E_DSN"))
	db := openEnrolmentTokenDB(t)
	s := newPostgresEnrolmentTokenStore(db)
	installSlowEnrolmentCommit(t, db, "3")
	ctx, cancel := context.WithTimeout(captureCPWriteLease(context.Background()), 80*time.Millisecond)
	defer cancel()
	now := time.Now().UTC()
	tok, secret, err := s.IssueContext(ctx, enrolltoken.DefaultPolicy(), "tenant_test_hung_commit", "", "", "issuer", "", now.Add(time.Hour), now)
	if !errors.Is(err, enrolltoken.ErrStateUnavailable) || tok.ID != "" || secret != "" {
		t.Fatal("hung commit disclosed a token or reported success")
	}
}

// enrolment_tokens lives in the shared public schema, not a per-test schema:
// replace any trigger a previous run left behind and remove it afterwards, so
// the slow COMMIT cannot leak into later tests or a second run.
func installSlowEnrolmentCommit(t *testing.T, db *sql.DB, seconds string) {
	t.Helper()
	drop := `DROP TRIGGER IF EXISTS slow_enrolment_commit ON enrolment_tokens; DROP FUNCTION IF EXISTS slow_enrolment_commit()`
	if _, err := db.Exec(drop + `; CREATE FUNCTION slow_enrolment_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(` + seconds + `); RETURN NEW; END $$; CREATE CONSTRAINT TRIGGER slow_enrolment_commit AFTER INSERT ON enrolment_tokens DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION slow_enrolment_commit()`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := db.Exec(drop); err != nil {
			t.Errorf("remove slow COMMIT trigger: %v", err)
		}
	})
}
