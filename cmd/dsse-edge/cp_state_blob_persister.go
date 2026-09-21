package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
	migrationstore "github.com/lantern-networks/dsse-core/migrations"
)

// cp_state_blob_persister wires the CP's authored-state stores (policy rules, grants, approvals, overlays,
// catalogs, …) to shared Postgres instead of node-local JSON files. Each store persists its whole snapshot as one
// opaque blob keyed by a stable store key; on Postgres those blobs live in cp_state_blobs (migration 028), so a
// standby CP can serve the state the active authored — the prerequisite for CP HA. See
//  and blobstore.Persister.

const cpStateBlobDBTimeout = 5 * time.Second

// cpStateBlobDB is the process-wide shared connection the CP-state blob persisters use, opened once in main
// from -postgres-dsn (nil on the zero-DB edge). Package-global because the stores it backs are wired across
// several functions (main, serverConfig.withDefaults, newServerWithConfig).
var cpStateBlobDB *sql.DB

// postgresBlobPersister is a blobstore.Persister backed by one row of cp_state_blobs.
type postgresBlobPersister struct {
	db  *sql.DB
	key string
}

func (p postgresBlobPersister) Load() ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), cpStateBlobDBTimeout)
	defer cancel()
	var payload []byte
	err := p.db.QueryRowContext(ctx, "SELECT payload FROM cp_state_blobs WHERE store_key=$1", p.key).Scan(&payload)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("load cp_state_blob %q: %w", p.key, err)
	}
	return payload, nil
}

func (p postgresBlobPersister) Save(data []byte) error {
	if p.key == "admin_runtime_state" {
		// Legacy toggle writers must not erase a SaaS setting authored by another CP.
		// Managed SaaS changes use Update and modify only their tenant's field.
		return p.Update(func(current []byte) ([]byte, error) {
			var next map[string]json.RawMessage
			if err := json.Unmarshal(data, &next); err != nil {
				return nil, err
			}
			var old map[string]json.RawMessage
			if len(current) > 0 {
				if err := json.Unmarshal(current, &old); err != nil {
					return nil, err
				}
			}
			if section, ok := old["saas_tenant_restrictions"]; ok {
				next["saas_tenant_restrictions"] = section
			}
			return json.Marshal(next)
		})
	}

	ctx, cancel := context.WithTimeout(context.Background(), cpStateBlobDBTimeout)
	defer cancel()
	_, err := p.db.ExecContext(ctx,
		`INSERT INTO cp_state_blobs (store_key, payload, updated_at) VALUES ($1, $2, now())
		 ON CONFLICT (store_key) DO UPDATE SET payload = EXCLUDED.payload, updated_at = EXCLUDED.updated_at`,
		p.key, data)
	if err != nil {
		return fmt.Errorf("save cp_state_blob %q: %w", p.key, err)
	}
	return nil
}

// Update serializes a read-modify-write across all CP processes. The callback's
// state becomes visible only after commit; unknown JSON fields can be preserved.
func (p postgresBlobPersister) Update(edit func([]byte) ([]byte, error)) error {
	return p.updateContext(context.Background(), edit, false)
}

// UpdateContext carries administrative leadership through to the database
// commit. An absent row is passed as nil, distinct from a corrupt empty object.
func (p postgresBlobPersister) UpdateContext(ctx context.Context, edit func([]byte) ([]byte, error)) error {
	return p.updateContext(ctx, edit, true)
}
func (p postgresBlobPersister) updateContext(parent context.Context, edit func([]byte) ([]byte, error), absentAsNil bool) (err error) {
	commitAttempted := false
	defer func() {
		if err != nil && !commitAttempted {
			err = fmt.Errorf("%w: %w", blobstore.ErrWriteNotCommitted, err)
		}
	}()
	ctx, cancel := context.WithTimeout(parent, cpStateBlobDBTimeout)
	defer cancel()
	tx, finish, err := beginCPWriteTransaction(ctx, p.db)
	if err != nil {
		return err
	}
	defer finish()
	defer tx.Rollback()
	inserted, err := tx.ExecContext(ctx, `INSERT INTO cp_state_blobs (store_key,payload,updated_at) VALUES ($1,'{}',now()) ON CONFLICT (store_key) DO NOTHING`, p.key)
	if err != nil {
		return err
	}
	var raw []byte
	if err := tx.QueryRowContext(ctx, `SELECT payload FROM cp_state_blobs WHERE store_key=$1 FOR UPDATE`, p.key).Scan(&raw); err != nil {
		return err
	}
	if n, err := inserted.RowsAffected(); err != nil {
		return err
	} else if absentAsNil && n == 1 {
		raw = nil
	}
	updated, err := edit(raw)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE cp_state_blobs SET payload=$2,updated_at=now() WHERE store_key=$1`, p.key, updated); err != nil {
		return err
	}
	commitAttempted = true
	return tx.Commit()
}

// newCPStateBlobDB opens the shared connection the CP-state blob persisters use and ensures cp_state_blobs exists.
// Reuses -postgres-dsn. Returns nil when no DSN is set (e.g. the zero-DB enforcement edge) so stores fall back to
// files.
func newCPStateBlobDB(dsn, migrationDir string, runMigrations bool) (*sql.DB, error) {
	dsn = strings.TrimSpace(dsn)
	if dsn == "" {
		return nil, nil
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("open cp-state blob db: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping cp-state blob db: %w", err)
	}
	if runMigrations {
		migrations, err := migrationstore.LoadDir(migrationDir)
		if err != nil {
			db.Close()
			return nil, fmt.Errorf("load cp-state blob migrations: %w", err)
		}
		selected, err := selectPostgresComponentMigrations(migrations, "cp-state blobs", postgresCPStateBlobsMigrationVersions()...)
		if err != nil {
			db.Close()
			return nil, err
		}
		if err := migrationstore.Apply(ctx, db, selected); err != nil {
			db.Close()
			// ★★ SAY WHAT "during recovery" MEANS HERE (2026-08-29, measured on a joining region's first
			// start). Postgres answers `cannot set transaction read-write mode during recovery` when the
			// connection landed on a REPLICA — which, in a region that joins an existing deployment, is what
			// its local database door hands out for the first seconds, before its health checks have marked
			// the followers down and settled on the primary. The message is correct and says nothing about
			// the deployment, so an operator reads it as a broken database rather than as a race that the
			// next start wins.
			if strings.Contains(err.Error(), "during recovery") || strings.Contains(err.Error(), "read-only") {
				return nil, fmt.Errorf("apply cp-state blob migrations: %w — this connection reached a REPLICA, "+
					"not the primary. In a region that joins an existing deployment that is what its database "+
					"door hands out until its health checks settle, so this start is expected to be retried "+
					"rather than repaired", err)
			}
			return nil, fmt.Errorf("apply cp-state blob migrations: %w", err)
		}
	}
	return db, nil
}

// mustCPStateBlobPersister resolves a store's flag value against the shared cpStateBlobDB, fataling on a config
// error (postgres requested without a DSN). Convenience for the many void-returning store constructors/setters.
func mustCPStateBlobPersister(storeValue, key string) blobstore.Persister {
	p, err := cpStateBlobPersister(storeValue, cpStateBlobDB, key)
	if err != nil {
		log.Fatalf("resolve %s store: %v", key, err)
	}
	return p
}

// cpStateBlobPersisterImportPrefix marks a value as "postgres from now on, and seed it once from this file":
//
//	-high-risk-store=postgres+import:/cp-state/high_risk.json
//
// ★ IT EXISTS BECAUSE MOVING A STORE TO POSTGRES STARTED IT EMPTY (2026-08-18). Control-plane HA is a state
// SHARING problem before it is a leader-election one: a standby cannot serve what the active wrote to its own
// disk. Every control-plane store already has a Postgres path, so the move is a flag change — except that
// nothing carries the state across. Flipping the flags on a running deployment silently discards whatever those
// files held, which for this product's stores means kill-switch revocations, legal holds, the tenant registry's
// deletion tombstones, registered end-user IdPs, and standing grants.
//
// The alternative designs were worse. Guessing the old path from -state-dir does not work: the reference
// deployment names its files explicitly and two of them match neither the store key nor the default filename.
// A separate import tool has to be run at exactly the right moment by someone who knows every key. Naming the
// source in the same flag that names the destination puts the whole move in one line of the deployment file,
// where it is reviewable, and it is self-retiring — once the blob exists the import never runs again, so the
// operator can shorten the value to "postgres" whenever they like, or never.
const cpStateBlobPersisterImportPrefix = "postgres+import:"

// storeShouldBeWired answers "is there a backend to resolve for this store".
//
// ★★★ AN EDGE IS AN EDGE, AND "NOBODY WIRED IT" MADE ONE A DIFFERENT PROGRAM (2026-08-21, measured).
//
// Nine stores were resolved only when their own flag was set — `if strings.TrimSpace(config.X) != ""`. An
// Edge that was never given the flag skipped the persister entirely and answered from an empty map, while
// its neighbour, built from the same source and running the same binary, answered from a file. Measured as
// one customer administrator reading the same 121 admin routes from two Edges seconds apart: 82 answers
// identical, 18 different — this organization's enrolment tokens on one Edge and [] on the other, licence
// allocated=30 versus 0, the decrypt allowlist present versus empty. Which Edge a load balancer picked
// decided what a customer saw and what the node enforced.
//
// A fleet grows and shrinks under load and its members are interchangeable, so the answer cannot depend on
// which flags somebody remembered for which node. When the deployment has a shared database there is a right
// answer available for free, so the store is wired to it.
//
// It changes nothing where there is nothing to share: with no -postgres-dsn this is exactly the old
// condition, cpStateBlobPersister returns (nil, nil), and every call site's existing `p != nil` skips the
// wiring just as it did before.
func storeShouldBeWired(value string) bool {
	return strings.TrimSpace(value) != "" || cpStateBlobDB != nil
}

// cpStateBlobPersister resolves a store's -X-store flag value into a Persister: "postgres" → shared cp_state_blobs
// (requires blobDB); "postgres+import:<path>" → the same, seeded once from <path> if the blob has never been
// written; "" → nil (in-memory only); anything else → a file at that path (the historical behaviour).
func cpStateBlobPersister(storeValue string, blobDB *sql.DB, key string) (blobstore.Persister, error) {
	v := strings.TrimSpace(storeValue)
	switch {
	case v == "":
		// ★★ AN UNWIRED STORE IS NOT A LICENCE TO BE DIFFERENT (2026-08-21). Empty used to mean "in-memory,
		// per process", so an Edge that was never given a flag answered from nothing while its neighbour
		// answered from a file — same source, same build, different program. With a shared database there is
		// a right answer available for free, so it is used, and said out loud so an operator can see which
		// stores were decided for them.
		if blobDB != nil && !storeStaysNodeLocal(key) {
			log.Printf("state store %q: no backend was configured and this deployment has a shared database — "+
				"using it, so every Edge in the fleet answers from the same state", key)
			return postgresBlobPersister{db: blobDB, key: key}, nil
		}
		return nil, nil
	case v == "postgres" || strings.HasPrefix(v, cpStateBlobPersisterImportPrefix):
		if blobDB == nil {
			return nil, fmt.Errorf("%s-store=%s requires -postgres-dsn", key, v)
		}
		if key == "tenant_device_authorities" || key == "tenant_trust_distributions" {
			if err := requirePKIHistoryWriteGuard(blobDB); err != nil {
				return nil, err
			}
		}
		persister := postgresBlobPersister{db: blobDB, key: key}
		if strings.HasPrefix(v, cpStateBlobPersisterImportPrefix) {
			source := strings.TrimSpace(strings.TrimPrefix(v, cpStateBlobPersisterImportPrefix))
			if err := importCPStateBlobOnce(persister, source, key); err != nil {
				return nil, err
			}
		}
		return persister, nil
	default:
		// ★ EVERY FILE-BACKED STORE HERE IS PER-NODE, AND A SHARED MOUNT BREAKS IT SILENTLY (2026-08-15).
		// Claim the path for this node before handing back a persister. Two Edges pointed at one path have
		// cost this project a re-usable device identity once and a config-distribution freeze once, and in
		// both cases the SYMPTOM was somewhere else entirely — an identity enrolling twice, a node
		// permanently behind. Only the enrolled inventory had any protection, and its own comment says it
		// cannot tell one bind-mounted path from another; a stamp naming the owner can.
		//
		// A live owner is a hard error (the caller fatals): starting a second writer against the same store is
		// a deployment mistake whose damage is invisible until much later. A stale one is taken over, said out
		// loud, and carried on with.
		// ★ AND IT IS A WARNING, NOT A REFUSAL (2026-08-15, same day, an hour later). The first version fataled
		// here and took the reference lab down within minutes — correctly, in the sense that the lab's two
		// Edges really do share /dataplane-ne, which is the very misconfiguration this exists to find. But a
		// diagnosis aid that turns a known-and-working deployment into a crash loop is the mistake this file
		// already made once with the stamp write, and refusing to start is not this check's call to make: the
		// single-writer persister is the hard guard on actual data damage, and it acts at the moment of damage
		// rather than on a suspicion at boot.
		//
		// So it says so, by name, on every start, and an operator decides. Loud and running beats silent, and
		// beats correct-but-down.
		if previous, cerr := blobstore.ClaimPath(v, cpStateNodeID(), time.Now()); cerr != nil {
			log.Printf("WARNING: state store %q: %v — this node is starting anyway, and both nodes will lose each "+
				"other's writes to this path until one of them is given its own.", key, cerr)
		} else if previous != "" {
			log.Printf("state store %q: took over %q from node %q, whose ownership stamp had gone stale. If that "+
				"node is still running, this path is SHARED and both nodes will lose each other's writes.", key, v, previous)
		}
		// Keep a few previous snapshots for the admin runtime state, and only for it. That store holds the
		// enabled/disabled status of security controls and is the sole copy — gitignored, with no version
		// history anywhere — so when an east-west posture was found reverted on 2026-08-05 there was nothing
		// to compare against and what it had been had to be reconstructed from an unrelated table. Other
		// stores here can be rebuilt from their source of truth and do not need the disk.
		if key == "admin_runtime_state" {
			return blobstore.OwnedFilePersister{
				File:   blobstore.FilePersister{Path: v, KeepVersions: 5},
				NodeID: cpStateNodeID(),
			}, nil
		}
		// ★ THE ENROLMENT LEDGER MUST NOT BE SILENTLY OVERWRITTEN BY ANOTHER PROCESS (2026-08-12, twenty-third
		// review). Every Edge holding it WRITES it — after each config-bundle apply — and a reference topology
		// gave three of them the same bind-mounted path, so an enrolment recorded by one node was erased by
		// another saving an older snapshot, and the identity could be enrolled a second time. The deployments
		// were given node-local paths; this makes the NEXT one that shares a path say so, instead of losing
		// the record of a spent identity quietly.
		if key == "tenant_trust_distributions" || key == "enrolled_inventory" || key == "tenant_transport_authorities" ||
			key == "tenant_device_authorities" || key == "tenant_interception_authorities" {
			// Both guards: the stamp says WHO owns the path (a deployment question, answered at startup), and
			// the single-writer check refuses to overwrite bytes it did not write (a data question, answered at
			// the moment of damage). Neither replaces the other — a stamp cannot stop a write that is already
			// happening, and the single-writer check cannot say why.
			return blobstore.NewSingleWriterFilePersister(blobstore.FilePersister{Path: v}), nil
		}
		return blobstore.OwnedFilePersister{File: blobstore.FilePersister{Path: v}, NodeID: cpStateNodeID()}, nil
	}
}

// cpStateNodeID labels this node in a state path's ownership stamp.
//
// ★ IT MUST BE STABLE ACROSS A REDEPLOY (2026-08-15). The first version used the hostname, which in a
// container world is per-CONTAINER: recreating the same logical node gives it a new one, so a node came back
// from a routine redeploy and did not recognise its own state. Measured immediately — the reference lab's
// Edge crash-looped after a rebuild, refused by a stamp it had written itself twenty minutes earlier.
//
// The region/cluster identity is the one that survives a container being replaced, and it is what the fleet
// view already keys nodes on. Two replicas in ONE cluster look alike to this check, which is the deliberate
// trade: it can miss that kind of sharing, where the alternative blocked every legitimate redeploy. The
// single-writer persister still catches the damage itself.
func cpStateNodeID() string {
	// deviceRuntimeEdgeID is already "<region>/<cluster>", set from the same flags the fleet view keys nodes
	// on. Reused rather than recomputed: two expressions of "which node is this" are two answers to the
	// question the whole check exists to make answerable, and this file has watched that go wrong elsewhere.
	if id := strings.TrimSpace(deviceRuntimeEdgeID); id != "" && id != "/" {
		return id
	}
	if host, err := os.Hostname(); err == nil && strings.TrimSpace(host) != "" {
		return strings.TrimSpace(host)
	}
	return "unknown-node"
}

// importCPStateBlobOnce seeds a cp_state_blobs row from a file the control plane used to persist to, and does
// it exactly once: only when the blob has NEVER been written. A blob that exists is the authority from then on,
// so a redeploy, a restart, or a second control plane reading the same row can never be overwritten by whatever
// stale file happens to still be sitting on one node's disk.
//
// Failures are refusals, not warnings. This runs while the operator is moving a store to shared state, and the
// failure mode it guards against — starting with an empty store and reporting nothing — is the one that looks
// exactly like success. An unreadable source file, or a write that does not land, must stop the boot rather
// than produce a control plane that has quietly forgotten its kill-switches.
//
// An ABSENT source file is not a failure: it is the ordinary state of a deployment that never had this store on
// disk, or that has already been moved and had its old file cleaned up. Said out loud either way.
func importCPStateBlobOnce(persister postgresBlobPersister, sourcePath, key string) error {
	sourcePath = strings.TrimSpace(sourcePath)
	if sourcePath == "" {
		return fmt.Errorf("%s-store=%s<path> names no file to import from", key, cpStateBlobPersisterImportPrefix)
	}
	existing, err := persister.Load()
	if err != nil {
		return fmt.Errorf("cp state import %q: could not tell whether the shared store already holds this, so it was not touched: %w", key, err)
	}
	if existing != nil {
		// Already shared, which is the steady state once the move is done — so this is silent, EXCEPT when the
		// named source still exists and says something different.
		//
		// ★ A SKIP IN THAT SHAPE IS HOW THE MOVE LOSES STATE (2026-08-18, found on the reference deployment).
		// cp_state_blobs held one row: admin_runtime_state, 50 bytes, written on 2026-07-12 and containing
		// nothing but a schema version — a leftover from an experiment. The file the control plane had actually
		// been using was 3,882 bytes of live state from that morning. The additive rule is right (a second
		// control plane may have authored the blob), but applying it without a word would have moved this
		// deployment onto an empty shell and reported a clean migration.
		//
		// It does not overwrite and it does not refuse: only one of the two is authored by a person, and this
		// code cannot tell which. It says exactly what it found and leaves the decision where it belongs.
		if data, err := os.ReadFile(sourcePath); err == nil && len(data) > 0 && !bytes.Equal(data, existing) {
			log.Printf("★ cp state import %q: NOT imported — the shared store already holds %d byte(s) for this key, "+
				"but %s exists and differs (%d byte(s)). The shared store wins, so whatever that file holds is NOT "+
				"in effect. If the file is the state this deployment was actually running on, delete the row "+
				"(DELETE FROM cp_state_blobs WHERE store_key = '%s') and start again; if the shared store is right, "+
				"remove the +import: from this store's flag so this stops being asked every boot.",
				key, len(existing), sourcePath, len(data), key)
		}
		return nil
	}
	data, err := os.ReadFile(sourcePath)
	if errors.Is(err, os.ErrNotExist) {
		log.Printf("cp state import %q: nothing to carry across — %s does not exist, so the shared store starts empty", key, sourcePath)
		return nil
	}
	if err != nil {
		return fmt.Errorf("cp state import %q: %s is named as the source but could not be read, and starting empty would look identical to a successful move: %w", key, sourcePath, err)
	}
	if len(data) == 0 {
		log.Printf("cp state import %q: %s is empty, so the shared store starts empty", key, sourcePath)
		return nil
	}
	// The bytes are carried VERBATIM. Both persisters hand the store the same opaque blob — the file persister
	// wrote exactly what the Postgres one will read — so there is no format to convert and nothing to interpret.
	// Anything cleverer here would be a second implementation of every store's encoding.
	if err := persister.CompareAndSwap(nil, data); err != nil {
		if errors.Is(err, errAuthorityConflict) {
			// Another CP initialized the store first.
			return nil
		}
		return fmt.Errorf("cp state import %q: read %d byte(s) from %s but could not write them to the shared store: %w", key, len(data), sourcePath, err)
	}
	log.Printf("★ cp state import %q: carried %d byte(s) from %s into the shared store — this control plane's state for %q is now readable by every control plane on this database, and the import will not run again",
		key, len(data), sourcePath, key)
	return nil
}

// storeBackend returns the BACKEND a -X-store value selects, with any one-time import source stripped:
// "postgres+import:/cp-state/x.json" → "postgres". Everything else is returned unchanged (a path selects the
// file backend, "" selects in-memory, "memory" selects volatile).
//
// ★★ EVERY "IS THIS STORE ON POSTGRES?" TEST MUST GO THROUGH HERE (2026-08-18). The import form was added and
// four places were already comparing the raw flag value to "postgres" exactly. Two of them fail SILENTLY, which
// is how the import would have shipped a hole rather than closed one:
//
//	enrolIssuerNeedsExclusiveStore   the guard that stops one device name being enrolled twice across nodes
//	                                 simply switches off — the exact incident enrolled_identity_claims exists for
//	connector runtime secret         "the runtime secret is required when the registry is on postgres" stops
//	                                 applying, so a security requirement disappears with nothing said
//	workload attestation nonce       refuses the boot claiming postgres is required when postgres IS what was
//	                                 asked for — loud, so merely wrong rather than dangerous
//	hot store                        neither "postgres" nor "clickhouse" matches, so it quietly falls through
//
// Found by reading the comparisons before moving the reference control plane, not by the lab failing.
func storeBackend(value string) string {
	v := strings.TrimSpace(value)
	if strings.HasPrefix(v, cpStateBlobPersisterImportPrefix) {
		return "postgres"
	}
	return v
}

// storeImportSource returns the one-time import path a -X-store value names, or "" when it names none.
func storeImportSource(value string) string {
	v := strings.TrimSpace(value)
	if !strings.HasPrefix(v, cpStateBlobPersisterImportPrefix) {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(v, cpStateBlobPersisterImportPrefix))
}

// sharedAgentUpdateArtifactShelf is where a deployment keeps the BYTES of its published releases so that any
// of its control planes can serve them. It is the same table the state blobs use, one row per release, because
// a release's bytes are exactly as node-independent as the manifest naming them and nothing about them is
// worth a second mechanism.
//
// One row per release rather than one per organization: publishes accumulate versions, and a single row that
// every upload rewrites would grow without limit and be re-read in full to serve one download.
//
// nil when this deployment has no shared database, which leaves every node keeping bytes on its own disk —
// correct for a single control plane, and what the code did before this existed.
func sharedAgentUpdateArtifactShelf(db *sql.DB) *agentUpdateArtifactShelf {
	if db == nil {
		return nil
	}
	return &agentUpdateArtifactShelf{
		open: func(key string) blobstore.Persister {
			if strings.TrimSpace(key) == "" {
				return nil
			}
			return postgresBlobPersister{db: db, key: key}
		},
		// forget is what an organization's erasure needs: every release published to it alone, in one
		// statement, because the alternative is re-opening manifests to learn which versions existed and
		// answering "erased" over whatever that missed.
		forget: func(tenantID string) error {
			prefix := artifactBlobKeyPrefix(tenantID)
			if strings.TrimSpace(tenantID) == "" || prefix == "" {
				return nil
			}
			ctx, cancel := context.WithTimeout(context.Background(), cpStateBlobDBTimeout)
			defer cancel()
			// ★ NOT `LIKE`. Organization ids are `tenant_` + base32, and `_` is LIKE's single-character
			// wildcard — so a prefix match written the obvious way is a pattern that also matches keys
			// belonging to other stores, and this statement is a DELETE. left() compares text to text.
			_, err := db.ExecContext(ctx, "DELETE FROM cp_state_blobs WHERE left(store_key, length($1)) = $1", prefix)
			return err
		},
	}
}

// Do not let a receiving cache mutate its publisher's shared authority. An
// explicit shared setting is contradictory and must fail before serving traffic.
func configBundleStorePersister(value, sourceURL, key string) (blobstore.Persister, error) {
	db := cpStateBlobDB
	if strings.TrimSpace(sourceURL) != "" {
		v := strings.TrimSpace(value)
		if v == "postgres" || strings.HasPrefix(v, cpStateBlobPersisterImportPrefix) {
			return nil, fmt.Errorf("%s is a config-bundle receiver cache: use a node-local file with -config-source-url, not shared Postgres", key)
		}
		db = nil
	}
	return cpStateBlobPersister(value, db, key)
}
