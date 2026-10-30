package grantstore

import (
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
)

// Expensive opt-in: the review's 100 tenants x 4096 expired fences. Measure a
// real atomic file write alongside authorization, not just JSON serialization.
func TestLargeFenceSnapshotKeepsAuthorizationReadersRunning(t *testing.T) {
	if os.Getenv("DSSE_GRANT_SCALE_TEST") != "1" {
		t.Skip("opt-in large file snapshot measurement")
	}
	s := NewStore()
	now := time.Now().UTC().Truncate(time.Second)
	for tenant := 0; tenant < 100; tenant++ {
		for row := 0; row < 4096; row++ {
			g := rollingGrant(fmt.Sprintf("fence-%d-%d", tenant, row), now.Add(-time.Hour))
			g.TenantID = fmt.Sprint("tenant-", tenant)
			g.UserID = fmt.Sprint("user-", row)
			g.IssuedAt = now.Add(-time.Hour).Format(time.RFC3339)
			g.ExpiresAt = now.Add(-time.Minute).Format(time.RFC3339)
			g.ReauthenticateAfter = g.IssuedAt
			g.Revoked = true
			s.grants[g.GrantID] = g
		}
	}
	s.rebuildReauthenticationIndexLocked()
	existing := grantFixture("live", now)
	existing.IssuedAt = now.Format(time.RFC3339)
	existing.ExpiresAt = now.Add(time.Hour).Format(time.RFC3339)
	s.grants[existing.GrantID] = existing
	path := filepath.Join(t.TempDir(), "grants.json")
	s.persister = blobstore.FilePersister{Path: path}
	done := make(chan error, 1)
	var started atomic.Bool
	go func() { started.Store(true); _, e := s.Mint(grantFixture("new", now), time.Hour, now); done <- e }()
	for !started.Load() {
		time.Sleep(time.Millisecond)
	}
	begin := time.Now()
	maxRead := time.Duration(0)
	reads := 0
	for {
		select {
		case e := <-done:
			if e != nil {
				t.Fatal(e)
			}
			info, e := os.Stat(path)
			if e != nil {
				t.Fatal(e)
			}
			t.Logf("rows=%d snapshot_bytes=%d mint=%s authorization_reads=%d longest_read=%s", len(s.grants), info.Size(), time.Since(begin), reads, maxRead)
			if reads == 0 || maxRead > time.Second {
				t.Fatal("authorization stopped during snapshot write")
			}
			return
		default:
			at := time.Now()
			if !s.ValidForAuthorization(existing.GrantID, now) {
				t.Fatal("existing authorization was lost")
			}
			elapsed := time.Since(at)
			if elapsed > maxRead {
				maxRead = elapsed
			}
			reads++
			time.Sleep(time.Millisecond)
		}
	}
}
