package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/lantern-networks/dsse-core/archive"
	"github.com/lantern-networks/dsse-core/blobstore"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// Execute the published maintenance statement rather than a second implementation.
func archiveRecoverySQL(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile("../../docs/archive-recovery.md")
	if err != nil {
		t.Fatal(err)
	}
	_, tail, ok := strings.Cut(string(raw), "```sql\n")
	if !ok {
		t.Fatal("recovery SQL missing")
	}
	stmt, _, ok := strings.Cut(tail, "\n```")
	if !ok {
		t.Fatal("recovery SQL unterminated")
	}
	return stmt
}

type recoverySaveProbe struct {
	blobstore.FilePersister
	mode string
}

func (p *recoverySaveProbe) Save(raw []byte) error {
	if p.mode == "before" {
		return fmt.Errorf("injected before save")
	}
	if err := p.FilePersister.Save(raw); err != nil {
		return err
	}
	if p.mode == "after" {
		return fmt.Errorf("injected after save")
	}
	return nil
}

type recoveryUploadProbe struct {
	fakeArchive
	unknown bool
}

func (p *recoveryUploadProbe) Put(ctx context.Context, key string, r io.Reader, n int64, opts archive.PutOptions) (archive.PutResult, error) {
	result, err := p.fakeArchive.Put(ctx, key, r, n, opts)
	if err == nil && p.unknown {
		return archive.PutResult{}, fmt.Errorf("injected lost upload acknowledgement")
	}
	return result, err
}

// Writers are quiescent during maintenance. This does not simulate S3 or a
// COMMIT network partition: the committed branch inspects an actual success.
func TestPostgresAuditArchiveMaintenanceRecovery(t *testing.T) {
	d, _, _, _ := trustDistributionPostgresFixture(t)
	pg := d.store.(postgresBlobPersister)
	pg.key = "audit_chain"
	if _, err := pg.db.Exec(`CREATE TABLE hot_events(tenant_id text,stream text,event_id text,received_at timestamptz,payload bytea)`); err != nil {
		t.Fatal(err)
	}
	statement := archiveRecoverySQL(t)
	for _, mode := range []string{"head_rollback", "commit_rollback", "upload_unknown", "committed", "file_before", "file_after"} {
		t.Run(mode, func(t *testing.T) {
			tenant, peer := "recover_"+mode, "peer_"+mode
			arc := &recoveryUploadProbe{fakeArchive: fakeArchive{objs: map[string][]byte{}}}
			var persister blobstore.Persister = pg
			var file *recoverySaveProbe
			if strings.HasPrefix(mode, "file_") {
				file = &recoverySaveProbe{FilePersister: blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "chain.json")}}
				persister = file
			}
			chain := newAuditChainStore(persister)
			insert := func(who, id string) {
				t.Helper()
				payload, _ := json.Marshal(map[string]string{"tenant_id": who, "event_id": id})
				if _, err := pg.db.Exec(`INSERT INTO hot_events VALUES($1,'audit',$2,now()-interval '10 days',$3)`, who, id, payload); err != nil {
					t.Fatal(err)
				}
			}
			count := func(who string) int {
				t.Helper()
				var n int
				if err := pg.db.QueryRow(`SELECT count(*) FROM hot_events WHERE tenant_id=$1`, who).Scan(&n); err != nil {
					t.Fatal(err)
				}
				return n
			}
			prune := func(s *auditChainStore, who string) {
				archiveThenPruneStream(context.Background(), pg.db, retentionConfig{archive: arc, auditChain: s}, who, "audit", time.Now().Add(-time.Hour), time.Now())
			}
			insert(tenant, "baseline")
			prune(chain, tenant)
			insert(peer, "baseline")
			prune(chain, peer)
			saved, err := persister.Load()
			if err != nil {
				t.Fatal(err)
			}
			trusted, err := decodeAuditChainState(saved)
			if err != nil || trusted[tenant].Seq != 1 || trusted[peer].Seq != 1 {
				t.Fatal("baseline", err)
			}
			insert(peer, "keep-hot")
			insert(tenant, "retry-event")
			switch mode {
			case "head_rollback":
				_, err = pg.db.Exec(`CREATE FUNCTION recovery_refuse_head() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected head rollback'; END $$; CREATE TRIGGER recovery_refuse_head BEFORE UPDATE ON cp_state_blobs FOR EACH ROW EXECUTE FUNCTION recovery_refuse_head()`)
			case "commit_rollback":
				_, err = pg.db.Exec(`CREATE FUNCTION recovery_refuse_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected commit rollback'; END $$; CREATE CONSTRAINT TRIGGER recovery_refuse_commit AFTER DELETE ON hot_events DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION recovery_refuse_commit()`)
			case "upload_unknown":
				arc.unknown = true
			case "file_before":
				file.mode = "before"
			case "file_after":
				file.mode = "after"
			}
			if err != nil {
				t.Fatal(err)
			}
			prune(chain, tenant)
			switch mode {
			case "head_rollback":
				_, err = pg.db.Exec(`DROP TRIGGER recovery_refuse_head ON cp_state_blobs; DROP FUNCTION recovery_refuse_head()`)
			case "commit_rollback":
				_, err = pg.db.Exec(`DROP TRIGGER recovery_refuse_commit ON hot_events; DROP FUNCTION recovery_refuse_commit()`)
			}
			if err != nil {
				t.Fatal(err)
			}
			arc.unknown = false
			if file != nil {
				file.mode = ""
			}
			wantHot := 1
			if mode == "committed" {
				wantHot = 0
			}
			if count(tenant) != wantHot || count(peer) != 1 {
				t.Fatal("failure/commit outcome lost rows")
			}
			before, err := persister.Load()
			if err != nil {
				t.Fatal(err)
			}
			current, err := decodeAuditChainState(before)
			if err != nil {
				t.Fatal(err)
			}
			if current[peer] != trusted[peer] {
				t.Fatal("peer head changed")
			}
			verified, err := verifyAuditChain(context.Background(), arc, tenant)
			if err != nil || !verified.OK || verified.Segments != 2 {
				t.Fatal("unverifiable extension", verified, err)
			}
			objects, _ := arc.List(context.Background(), "hot_events/"+tenant+"/audit/", 0)
			sort.Slice(objects, func(i, j int) bool { return objects[i].Key < objects[j].Key })
			oldObjects := map[string][]byte{}
			for _, o := range objects {
				oldObjects[o.Key] = append([]byte(nil), arc.objs[o.Key]...)
			}
			if hashObjectBytes(arc.objs[objects[0].Key]) != trusted[tenant].LastHash {
				t.Fatal("trusted prefix changed")
			}
			// Inspect the orphan payload, not only its linked header/count.
			readEvent := func(raw []byte) map[string]string {
				t.Helper()
				gz, err := gzip.NewReader(bytes.NewReader(raw))
				if err != nil {
					t.Fatal(err)
				}
				content, err := io.ReadAll(gz)
				gz.Close()
				if err != nil {
					t.Fatal(err)
				}
				lines := bytes.Split(bytes.TrimSpace(content), []byte("\n"))
				if len(lines) != 2 {
					t.Fatal("unexpected segment record count")
				}
				var event map[string]string
				if err := json.Unmarshal(lines[1], &event); err != nil {
					t.Fatal(err)
				}
				return event
			}
			event := readEvent(arc.objs[objects[1].Key])
			if event["tenant_id"] != tenant || event["event_id"] != "retry-event" {
				t.Fatal("wrong orphan event")
			}
			head := auditChainState{Seq: 2, LastHash: hashObjectBytes(arc.objs[objects[1].Key])}
			if mode == "committed" || mode == "file_after" {
				if current[tenant] != head {
					t.Fatal("confirmed storage differs from object")
				}
				// No head write when the expected outcome already reached storage.
			} else {
				if current[tenant] != trusted[tenant] {
					t.Fatal("unexpected persistent outcome")
				}
				n := len(arc.objs)
				prune(newAuditChainStore(persister), tenant)
				if len(arc.objs) != n || count(tenant) != 1 {
					t.Fatal("restart bypassed reconciliation")
				}
				if file == nil {
					for _, bad := range []struct {
						expected, hash string
						seq            int
					}{
						{hex.EncodeToString(append(append([]byte(nil), before...), ' ')), head.LastHash, 2},
						{hex.EncodeToString(before), "not-a-hash", 2},
						{hex.EncodeToString(before), head.LastHash, 3},
					} {
						rows, err := pg.db.Query(statement, tenant, bad.expected, bad.seq, bad.hash)
						if err != nil {
							t.Fatal(err)
						}
						if rows.Next() {
							t.Fatal("unsafe repair accepted")
						}
						if err := rows.Err(); err != nil {
							t.Fatal(err)
						}
						rows.Close()
					}
					tx, err := pg.db.Begin()
					if err != nil {
						t.Fatal(err)
					}
					defer tx.Rollback()
					if _, err := tx.Exec(`SET LOCAL lock_timeout='1s'; SET LOCAL statement_timeout='5s'`); err != nil {
						t.Fatal(err)
					}
					var updated string
					if err := tx.QueryRow(statement, tenant, hex.EncodeToString(before), 2, head.LastHash).Scan(&updated); err != nil {
						t.Fatal(err)
					}
					raw, err := hex.DecodeString(updated)
					if err != nil {
						t.Fatal(err)
					}
					repaired, err := decodeAuditChainState(raw)
					current[tenant] = head
					expected, _ := json.Marshal(current)
					actual, _ := json.Marshal(repaired)
					if err != nil || !bytes.Equal(expected, actual) {
						t.Fatal("repair changed unapproved heads")
					}
					if err := tx.Commit(); err != nil {
						t.Fatal(err)
					}
				} else {
					reread, err := file.Load()
					if err != nil || !bytes.Equal(before, reread) {
						t.Fatal("snapshot changed before offline repair")
					}
					current[tenant] = head
					repaired, _ := json.Marshal(current)
					if err := file.FilePersister.Save(repaired); err != nil {
						t.Fatal(err)
					}
				}
			}
			fresh := newAuditChainStore(persister)
			seq, hash, err := fresh.Next(tenant)
			if err != nil || seq != 2 || hash != head.LastHash {
				t.Fatal("repaired state not reloadable", seq, err)
			}
			if count(tenant) != wantHot {
				t.Fatal("maintenance deleted hot rows")
			}
			if mode == "committed" {
				insert(tenant, "future-event")
			}
			prune(fresh, tenant)
			seq, _, err = newAuditChainStore(persister).Next(tenant)
			if err != nil || seq != 3 || count(tenant) != 0 || count(peer) != 1 {
				t.Fatal("recovery did not resume safely", seq, err)
			}
			verified, err = verifyAuditChain(context.Background(), arc, tenant)
			if err != nil || !verified.OK || verified.Segments != 3 {
				t.Fatal("resumed chain invalid", verified, err)
			}
			copies := 0
			for key, raw := range arc.objs {
				if strings.HasPrefix(key, "hot_events/"+tenant+"/audit/") && readEvent(raw)["event_id"] == "retry-event" {
					copies++
				}
			}
			wantCopies := 2
			if mode == "committed" {
				wantCopies = 1
			}
			if copies != wantCopies {
				t.Fatalf("unexpected preserved event copies: %d, want %d", copies, wantCopies)
			}
			for key, raw := range oldObjects {
				if !bytes.Equal(raw, arc.objs[key]) {
					t.Fatal("recovery modified archived evidence")
				}
			}
			peerSeq, peerHash, err := newAuditChainStore(persister).Next(peer)
			if err != nil || (auditChainState{Seq: peerSeq, LastHash: peerHash}) != trusted[peer] {
				t.Fatal("recovery damaged peer")
			}
			t.Logf("outcome=%s verified_objects=3 repair_hot_deletes=0 resumed_hot=0 peer_hot=1", mode)
		})
	}
}
