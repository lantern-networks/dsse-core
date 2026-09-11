package main

import (
	"os"
	"path/filepath"
	"testing"
)

// ★★★ MOVING A CONTROL-PLANE STORE TO POSTGRES STARTED IT EMPTY (2026-08-18).
//
// Control-plane HA is a state SHARING problem before it is a leader-election one: a standby cannot serve what
// the active wrote to its own disk. Every control-plane store already has a Postgres path, so the move is a
// flag change — and the flag change silently discarded whatever the file held. For this product's stores that
// is kill-switch revocations, legal holds, the tenant registry's deletion tombstones, registered end-user IdPs
// and standing grants: all of them read as "there were none" afterwards, which is indistinguishable from a
// clean move.
//
// -X-store=postgres+import:<path> carries the file across once. These are the properties that make it safe to
// leave in a deployment file permanently, rather than something to run by hand at the right moment.
func TestCPStateBlobImportCarriesTheFileAcrossExactlyOnce(t *testing.T) {
	dsn := os.Getenv("DSSE_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("set DSSE_TEST_POSTGRES_DSN to verify the CP-state import against a real PostgreSQL")
	}
	db, err := newCPStateBlobDB(dsn, filepath.Join("..", "..", "migrations"), true)
	if err != nil {
		t.Fatalf("open the blob db: %v", err)
	}
	if db == nil {
		t.Fatal("no database, so this test measures nothing")
	}
	defer db.Close()

	dir := t.TempDir()
	source := filepath.Join(dir, "high_risk.json")
	original := []byte(`{"marked":{"win-dev-1":"critical"}}`)
	if err := os.WriteFile(source, original, 0o600); err != nil {
		t.Fatalf("write the source: %v", err)
	}
	// A key of this test's own, so a re-run and the lab's real keys never collide.
	const key = "test_cp_state_import_high_risk"
	if _, err := db.Exec("DELETE FROM cp_state_blobs WHERE store_key = $1", key); err != nil {
		t.Fatalf("clear the key: %v", err)
	}

	// 1. The blob has never been written, so the file is carried across.
	persister, err := cpStateBlobPersister(cpStateBlobPersisterImportPrefix+source, db, key)
	if err != nil {
		t.Fatalf("resolve with import: %v", err)
	}
	got, err := persister.Load()
	if err != nil {
		t.Fatalf("load after import: %v", err)
	}
	if string(got) != string(original) {
		t.Fatalf("the import did not carry the file verbatim: got %q want %q", got, original)
	}

	// 2. ★ AND NEVER AGAIN. The blob is the authority from the moment it exists — a second control plane, a
	// redeploy, or a restart must not be able to overwrite shared state with whatever stale file is still
	// sitting on one node's disk. This is the property that makes the flag safe to leave in place.
	shared := []byte(`{"marked":{"win-dev-1":"critical","nw-laptop-001":"high"}}`)
	if err := persister.Save(shared); err != nil {
		t.Fatalf("save the shared state: %v", err)
	}
	if err := os.WriteFile(source, []byte(`{"marked":{}}`), 0o600); err != nil {
		t.Fatalf("rewrite the stale source: %v", err)
	}
	if _, err := cpStateBlobPersister(cpStateBlobPersisterImportPrefix+source, db, key); err != nil {
		t.Fatalf("resolve a second time: %v", err)
	}
	again, err := persister.Load()
	if err != nil {
		t.Fatalf("load after the second resolve: %v", err)
	}
	if string(again) != string(shared) {
		t.Fatalf("a stale file overwrote shared state — the import is not once-only: got %q want %q", again, shared)
	}

	// ★★ A SKIP MUST BE LOUD WHEN THE SOURCE STILL SAYS SOMETHING ELSE (2026-08-18). The reference deployment
	// had one leftover blob — 50 bytes, a schema version and nothing else, written a month earlier — while the
	// file the control plane was actually running on held 3,882 bytes of live state. Skipping silently would
	// have moved the deployment onto the empty shell and reported a clean migration. The rule stays additive;
	// what changes is that it says so.
	//
	// The assertion here is on the BEHAVIOUR the log describes: the shared store is untouched, and the differing
	// file is not what is in effect. (The message itself is asserted by reading it, not by matching a string —
	// a test that pins wording fails on every rewording and protects nothing.)
	stale := []byte(`{"schema_version":"only"}`)
	if err := persister.Save(stale); err != nil {
		t.Fatalf("write the stale blob: %v", err)
	}
	if err := os.WriteFile(source, []byte(`{"schema_version":"only","real":"state"}`), 0o600); err != nil {
		t.Fatalf("rewrite the differing source: %v", err)
	}
	if _, err := cpStateBlobPersister(cpStateBlobPersisterImportPrefix+source, db, key); err != nil {
		t.Fatalf("a differing source must not fail the boot — it is reported, not refused: %v", err)
	}
	if got, err := persister.Load(); err != nil {
		t.Fatalf("load after the differing-source skip: %v", err)
	} else if string(got) != string(stale) {
		t.Fatalf("the differing file overwrote the shared store: %q", got)
	}

	// 3. An absent source is the ordinary state of a deployment that never had this store on disk. Not an error.
	if _, err := db.Exec("DELETE FROM cp_state_blobs WHERE store_key = $1", key+"_absent"); err != nil {
		t.Fatalf("clear the absent key: %v", err)
	}
	if _, err := cpStateBlobPersister(cpStateBlobPersisterImportPrefix+filepath.Join(dir, "not_here.json"), db, key+"_absent"); err != nil {
		t.Fatalf("an absent source must not fail the boot: %v", err)
	}

	// 4. ★ A source that is NAMED and cannot be read is a REFUSAL. Starting empty here looks exactly like a
	// successful move, which is the whole failure this exists to prevent.
	if _, err := cpStateBlobPersister(cpStateBlobPersisterImportPrefix+dir, db, key+"_unreadable"); err == nil {
		t.Fatal("an unreadable source was accepted, so a control plane can still start having quietly forgotten its state")
	}

	// 5. And a value that names no file at all.
	if _, err := cpStateBlobPersister(cpStateBlobPersisterImportPrefix, db, key+"_nopath"); err == nil {
		t.Fatal("postgres+import: with no path was accepted")
	}

	// 6. ★ THE CONTROL: plain "postgres" must NOT import, or the test above would pass for a store that always
	// reads its file — which is the behaviour being replaced.
	if _, err := db.Exec("DELETE FROM cp_state_blobs WHERE store_key = $1", key+"_plain"); err != nil {
		t.Fatalf("clear the control key: %v", err)
	}
	plain, err := cpStateBlobPersister("postgres", db, key+"_plain")
	if err != nil {
		t.Fatalf("resolve plain postgres: %v", err)
	}
	if blob, err := plain.Load(); err != nil {
		t.Fatalf("load the control: %v", err)
	} else if len(blob) != 0 {
		t.Fatalf("plain postgres imported something: %q", blob)
	}

	for _, k := range []string{key, key + "_absent", key + "_unreadable", key + "_nopath", key + "_plain"} {
		if _, err := db.Exec("DELETE FROM cp_state_blobs WHERE store_key = $1", k); err != nil {
			t.Fatalf("clean up %q: %v", k, err)
		}
	}
}
