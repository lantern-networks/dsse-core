package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"strings"
	"time"

	enrolledinventory "github.com/lantern-networks/dsse-core/enrolledinventory"
	migrationstore "github.com/lantern-networks/dsse-core/migrations"
)

// enrolled_identity_claim_postgres.go — one-time consumption of a device identity, decided in one place.
//
// ★ EVERY ISSUER WAS ANSWERING FROM ITS OWN MEMORY (2026-08-13, twenty-fourth review). "Has this identity
// already enrolled?" came from an in-memory ledger saved back as a whole blob, so two Edges holding a device
// CA each answered from the state they happened to load and the second issued a certificate for a name the
// first had already used. Giving each node its own file made it worse, not better: the markers then cannot
// reach each other at all.
//
// A conditional UPDATE is what a one-time decision looks like when more than one process can take it. The
// grant counter is the administrator's permission to enrol again, and it is the same rule the in-memory merge
// applies — a claim may only be taken under a grant NEWER than the one the standing claim was taken under —
// so a re-imaged machine still gets back in through the operator, and two racing issuers under the same grant
// produce exactly one winner because exactly one UPDATE reports a row.
type postgresEnrolledIdentityClaims struct {
	db     *sql.DB
	nodeID string
}

const enrolledIdentityClaimTimeout = 5 * time.Second

// ClaimIdentity records that this node is issuing for (tenant, identity) under grant. It reports whether the
// claim was taken: false means somebody already holds it under this grant or a newer one, which is a refusal
// to issue rather than an error.
func (c postgresEnrolledIdentityClaims) ClaimIdentity(ctx context.Context, tenantID, identity string, grant int) (bool, error) {
	if c.db == nil {
		return false, fmt.Errorf("enrolled identity claims: no database")
	}
	tenantID, identity = canonicalClaimTenant(tenantID), strings.TrimSpace(identity)
	if identity == "" {
		return false, fmt.Errorf("enrolled identity claims: identity is required")
	}
	ctx, cancel := context.WithTimeout(ctx, enrolledIdentityClaimTimeout)
	defer cancel()
	// INSERT when nobody holds it; UPDATE only when this grant is strictly newer than the standing one. The
	// WHERE on the conflict path is what makes this atomic: PostgreSQL evaluates it while holding the row.
	res, err := c.db.ExecContext(ctx,
		`INSERT INTO enrolled_identity_claims (tenant_id, identity, reenrolment_grant, claimed_at, claimed_by)
		 VALUES ($1, $2, $3, now(), $4)
		 ON CONFLICT (tenant_id, identity) DO UPDATE
		   SET reenrolment_grant = EXCLUDED.reenrolment_grant, claimed_at = now(), claimed_by = EXCLUDED.claimed_by
		   WHERE enrolled_identity_claims.reenrolment_grant < EXCLUDED.reenrolment_grant`,
		tenantID, strings.ToLower(identity), grant, c.nodeID)
	if err != nil {
		return false, fmt.Errorf("claim identity %q: %w", identity, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		// A driver that cannot report this cannot be read as success: issuing on an unknown outcome is the
		// thing the claim exists to prevent.
		return false, fmt.Errorf("claim identity %q: the database did not report whether the claim was taken: %w", identity, err)
	}
	return n > 0, nil
}

// setupPostgresEnrolledIdentityClaims applies migration 035 and returns the claim.
//
// The migration is applied HERE rather than assumed, for the reason every other component here applies its
// own: an Edge given a DSN whose schema predates this table would otherwise fail on the first enrolment of
// the deployment — the moment furthest from anyone watching a startup log.
func setupPostgresEnrolledIdentityClaims(ctx context.Context, db *sql.DB, migrationDir string, runMigrations bool, nodeID string) (postgresEnrolledIdentityClaims, error) {
	if db == nil {
		return postgresEnrolledIdentityClaims{}, fmt.Errorf("enrolled identity claims require -postgres-dsn")
	}
	if runMigrations {
		migrations, err := migrationstore.LoadDir(migrationDir)
		if err != nil {
			return postgresEnrolledIdentityClaims{}, fmt.Errorf("load enrolled identity claim migrations: %w", err)
		}
		migrations, err = selectPostgresComponentMigrations(migrations, "enrolled identity claims",
			postgresEnrolledIdentityClaimMigrationVersions()...)
		if err != nil {
			return postgresEnrolledIdentityClaims{}, err
		}
		if err := migrationstore.Apply(ctx, db, migrations); err != nil {
			return postgresEnrolledIdentityClaims{}, fmt.Errorf("apply enrolled identity claim migrations: %w", err)
		}
	}
	return postgresEnrolledIdentityClaims{db: db, nodeID: nodeID}, nil
}

// ReleaseIdentity gives back a claim this node took and could not honour. It only removes a claim at the SAME
// grant it was taken under, so it can never undo a newer administrator decision that arrived in between.
func (c postgresEnrolledIdentityClaims) ReleaseIdentity(ctx context.Context, tenantID, identity string, grant int) error {
	if c.db == nil {
		return fmt.Errorf("enrolled identity claims: no database")
	}
	ctx, cancel := context.WithTimeout(ctx, enrolledIdentityClaimTimeout)
	defer cancel()
	_, err := c.db.ExecContext(ctx,
		`DELETE FROM enrolled_identity_claims
		  WHERE tenant_id = $1 AND identity = $2 AND reenrolment_grant = $3 AND claimed_by = $4`,
		canonicalClaimTenant(tenantID), strings.ToLower(strings.TrimSpace(identity)), grant, c.nodeID)
	if err != nil {
		return fmt.Errorf("release claim on %q: %w", identity, err)
	}
	return nil
}

// BackfillClaims records identities this node already knows to be enrolled.
//
// ★ CREATING THE TABLE DOES NOT POPULATE IT (2026-08-13, twenty-fifth review). Every identity enrolled before
// the shared claim existed has no row, so a NEW issuer — which has no local marker for it either — takes the
// empty claim and issues a certificate for a name already in use. The original issuer still refuses from its
// own marker, which is exactly what makes the gap invisible from wherever you happen to be standing.
//
// ★ IT RAISES A STALE GRANT RATHER THAN LEAVING IT (2026-08-13, twenty-sixth review). DO NOTHING looked
// conservative and was the opposite: a node whose ledger predates a re-enrolment backfills grant 0 first, the
// node that knows about grant 1 then does nothing, and the row stays at 0 — after which a ClaimIdentity under
// grant 1 SUCCEEDS and issues a second certificate under a permission that was already spent. The condition is
// the same one ClaimIdentity uses, so a grant only ever moves forward and an operator's re-arm cannot be
// undone by a restart.
func (c postgresEnrolledIdentityClaims) BackfillClaims(ctx context.Context, claims []enrolledinventory.IdentityClaim) (int, error) {
	if c.db == nil {
		return 0, fmt.Errorf("enrolled identity claims: no database")
	}
	if len(claims) == 0 {
		return 0, nil
	}
	ctx, cancel := context.WithTimeout(ctx, enrolledIdentityClaimTimeout*time.Duration(1+len(claims)/50))
	defer cancel()
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("backfill identity claims: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // committed below; rollback is the failure path
	inserted := 0
	for _, cl := range claims {
		res, xerr := tx.ExecContext(ctx,
			`INSERT INTO enrolled_identity_claims (tenant_id, identity, reenrolment_grant, claimed_at, claimed_by)
			 VALUES ($1, $2, $3, now(), $4)
			 ON CONFLICT (tenant_id, identity) DO UPDATE
			   SET reenrolment_grant = EXCLUDED.reenrolment_grant, claimed_at = now(), claimed_by = EXCLUDED.claimed_by
			   WHERE enrolled_identity_claims.reenrolment_grant < EXCLUDED.reenrolment_grant`,
			canonicalClaimTenant(cl.TenantID), strings.ToLower(strings.TrimSpace(cl.Identity)), cl.Grant,
			c.nodeID+" (backfill)")
		if xerr != nil {
			return inserted, fmt.Errorf("backfill claim on %q: %w", cl.Identity, xerr)
		}
		if n, _ := res.RowsAffected(); n > 0 {
			inserted++
		}
	}
	if cerr := tx.Commit(); cerr != nil {
		return 0, fmt.Errorf("backfill identity claims: %w", cerr)
	}
	return inserted, nil
}

// canonicalClaimTenant is how a tenant id becomes a claim key.
//
// ★ THE REST OF THE SYSTEM TREATS TENANTS CASE-INSENSITIVELY AND THIS PRIMARY KEY DID NOT (2026-08-13,
// twenty-sixth review). The ledger compares with EqualFold and the token store canonicalises, so
// `Tenant_A/device-1` and `tenant_a/device-1` are the same device everywhere except here — where they would
// be two rows, two claims, and two certificates for one machine. A key that disagrees with the identity model
// around it is not a key.
func canonicalClaimTenant(tenantID string) string {
	return strings.ToLower(strings.TrimSpace(tenantID))
}

// ensureIdentityClaimBarrier records — or requires — that the EXISTING fleet has been imported into the claim.
//
// contributed is how many identities THIS node just backfilled. A node that contributed some has evidence it
// held part of the legacy fleet, and may declare the migration finished. A node that contributed none has no
// such evidence: during a rolling upgrade that is exactly the new issuer, whose ledger holds no markers, and
// letting it declare would end the migration before the node holding the fleet had run.
//
// freshDeployment is the operator saying there is no fleet to migrate. It is a one-time statement about
// history, not a standing security property — unlike the -enroll-sole-issuer flag this thread removed, which
// asserted something no one could check and that stayed true or false forever.
func ensureIdentityClaimBarrier(ctx context.Context, db *sql.DB, knownEnrolled int, nodeID string, freshDeployment bool) error {
	if db == nil {
		return fmt.Errorf("the identity claim barrier needs a database")
	}
	ctx, cancel := context.WithTimeout(ctx, enrolledIdentityClaimTimeout)
	defer cancel()
	var completedBy string
	var identities int
	err := db.QueryRowContext(ctx, `SELECT completed_by, identities FROM enrolled_identity_claim_barrier WHERE id`).
		Scan(&completedBy, &identities)
	if err == nil {
		log.Printf("enroll: the identity-claim migration is complete (declared by %q, %d identity(ies)) — issuing is permitted",
			completedBy, identities)
		return nil
	}
	if err != sql.ErrNoRows {
		return fmt.Errorf("read the identity claim barrier: %w", err)
	}
	reason, mayDeclare := identityClaimBarrierDecision(knownEnrolled, freshDeployment)
	if !mayDeclare {
		return fmt.Errorf("this Edge issues device certificates, and the deployment's existing identities have " +
			"NOT been imported into the shared claim yet. This node contributed none — its enrolled inventory " +
			"holds no completed enrolments — so it cannot be the one to say the migration is finished: during a " +
			"rolling upgrade that is exactly the new node, and declaring here would end the migration before the " +
			"node holding the fleet has run. Start the Edge that HAS the enrolments first, or pass " +
			"-enrol-claim-fresh-deployment if this deployment has never enrolled anything")
	}
	if _, err := db.ExecContext(ctx,
		`INSERT INTO enrolled_identity_claim_barrier (id, completed_by, identities, reason)
		 VALUES (true, $1, $2, $3) ON CONFLICT (id) DO NOTHING`, nodeID, knownEnrolled, reason); err != nil {
		return fmt.Errorf("record the identity claim barrier: %w", err)
	}
	log.Printf("enroll: identity-claim migration declared complete by this node (%s, %d identity(ies))", reason, knownEnrolled)
	return nil
}

// identityClaimBarrierDecision is WHO may declare the migration finished, and why.
//
// A named decision rather than a switch inside the database call, so the rule can be exercised without a
// database and the test calls the same thing the product does — an earlier version of that test
// re-implemented the condition beside it, which asserts that two copies of an expression agree.
// knownEnrolled is how many identities this node KNOWS are already enrolled — deliberately NOT how many rows
// its backfill inserted. A deployment whose previous release already wrote claim rows inserts none on
// upgrade, and answering the barrier with that number refused startup to the only Edge that could satisfy it.
func identityClaimBarrierDecision(knownEnrolled int, freshDeployment bool) (reason string, mayDeclare bool) {
	switch {
	case knownEnrolled > 0:
		// It holds part of the legacy fleet and has just offered it. Evidence, not a claim.
		return "backfilled from this node's enrolled inventory", true
	case freshDeployment:
		// The operator states there is no fleet. A one-time statement about history, which the barrier row
		// then makes permanent so nobody has to make it again.
		return "operator declared a new deployment with no fleet to migrate", true
	default:
		// The rolling-upgrade case: a new node, an empty ledger, nothing to contribute and no standing to end
		// the migration.
		return "", false
	}
}
