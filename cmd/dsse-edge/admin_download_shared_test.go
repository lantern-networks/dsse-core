package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/lantern-networks/dsse-core/logs"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type downloadFailureFixture struct {
	transactionalCAFixture
	fail bool
}

func (p *downloadFailureFixture) Save(raw []byte) error {
	if p.fail {
		return fmt.Errorf("storage refused")
	}
	return p.transactionalCAFixture.Save(raw)
}
func downloadTestJob(tenant string) adminExportJob {
	object, checksum := "export/test.gz", "test-checksum"
	return adminExportJob{ID: "job-" + tenant, TenantID: tenant, Status: "completed", ObjectRef: &object, PayloadChecksum: &checksum}
}
func TestDownloadSharedPreservesPeer(t *testing.T) {
	p := &transactionalCAFixture{}
	a, b := newAdminDownloadTokenStore(), newAdminDownloadTokenStore()
	if err := a.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	if err := b.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	first, err := a.Create(downloadTestJob("a"), "test.gz", "review", []byte("private-export"), now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = b.Create(downloadTestJob("b"), "test.gz", "review", []byte("other-export"), now); err != nil {
		t.Fatal(err)
	}
	fresh := newAdminDownloadTokenStore()
	if err = fresh.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	if _, ok := fresh.Consume(first.Token, now); !ok {
		t.Fatal("stale issuer erased peer token")
	}
}
func TestDownloadRefusesUnconfirmedSpend(t *testing.T) {
	p := &downloadFailureFixture{}
	s := newAdminDownloadTokenStore()
	if err := s.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tok, err := s.Create(downloadTestJob("a"), "test.gz", "review", []byte("private-export"), now)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := p.Load()
	p.fail = true
	p.failCommit = true
	if got, ok := s.Consume(tok.Token, now); ok || len(got.Payload) > 0 {
		t.Fatal("unconfirmed spend released payload")
	}
	after, _ := p.Load()
	if !bytes.Equal(before, after) {
		t.Fatal("rejected spend changed row")
	}
}

func TestDownloadCommitFailureAndRecovery(t *testing.T) {
	p := &downloadFailureFixture{}
	s := newAdminDownloadTokenStore()
	if err := s.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	p.fail = true
	p.failCommit = true
	if got, err := s.Create(downloadTestJob("a"), "test.gz", "review", []byte("private-export"), now); err == nil || got.Token != "" {
		t.Fatal("unconfirmed issue returned credential")
	}
	p.fail = false
	p.failCommit = false
	tok, err := s.Create(downloadTestJob("a"), "test.gz", "review", []byte("private-export"), now)
	if err != nil {
		t.Fatal(err)
	}
	original, _ := p.Load()
	for _, bad := range [][]byte{nil, []byte(`null`), []byte(`broken`)} {
		p.Save(bad)
		if got, ok, err := s.ConsumeContext(context.Background(), tok.Token, now); err == nil || ok || len(got.Payload) > 0 {
			t.Fatal("unknown shared state released data")
		}
	}
	p.Save(original)
	p.failCommit = true
	if got, ok, err := s.ConsumeContext(context.Background(), tok.Token, now); err == nil || ok || len(got.Payload) > 0 || got.Token != "" {
		t.Fatal("commit refusal released data")
	}
	p.failCommit = false
	if got, ok, err := s.ConsumeContext(context.Background(), tok.Token, now); err != nil || !ok || string(got.Payload) != "private-export" {
		t.Fatal("retry failed", err)
	}
	fresh := newAdminDownloadTokenStore()
	if err = fresh.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	if _, ok := fresh.Consume(tok.Token, now); ok {
		t.Fatal("reload resurrected spent token")
	}
}

func TestPostgresDownloadSpentOnceAndRequestTerm(t *testing.T) {
	d, _, a, b := trustDistributionPostgresFixture(t)
	p := d.store.(postgresBlobPersister)
	p.key = "export_download_tokens"
	stores := []*adminDownloadTokenStore{newAdminDownloadTokenStore(), newAdminDownloadTokenStore()}
	for _, s := range stores {
		if err := s.SetPersister(p); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now()
	tok, err := stores[0].Create(downloadTestJob("a"), "test.gz", "review", []byte("private-export"), now)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := stores[1].Create(downloadTestJob("b"), "test.gz", "review", []byte("other-export"), now)
	if err != nil {
		t.Fatal(err)
	}
	// Exercise row-level serialization without the process-local elector mutex.
	elector := cpLeaderElectorInstance
	cpLeaderElectorInstance = nil
	var winners atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func(s *adminDownloadTokenStore) {
			defer wg.Done()
			<-start
			got, ok, err := s.ConsumeContext(context.Background(), tok.Token, now)
			if err != nil {
				t.Error(err)
			}
			if ok {
				if string(got.Payload) != "private-export" {
					t.Error("payload changed")
				}
				winners.Add(1)
			}
		}(stores[i%2])
	}
	close(start)
	wg.Wait()
	cpLeaderElectorInstance = elector
	if winners.Load() != 1 {
		t.Fatalf("one-use winners=%d", winners.Load())
	}
	old := retentionWriteContext(context.Background())
	a.release()
	b.tick()
	b.release()
	a.tick()
	before, _ := p.Load()
	if _, ok, err := stores[0].ConsumeContext(old, peer.Token, now); err == nil || ok {
		t.Fatal("old request spent token")
	}
	if got, err := stores[0].CreateContext(old, downloadTestJob("c"), "test.gz", "review", nil, now); err == nil || got.Token != "" {
		t.Fatal("old request issued token")
	}
	after, _ := p.Load()
	if !bytes.Equal(before, after) {
		t.Fatal("old request mutated shared row")
	}
	fresh := newAdminDownloadTokenStore()
	if err = fresh.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	if _, ok := fresh.Consume(tok.Token, now); ok {
		t.Fatal("spent token resurrected")
	}
	if got, ok := fresh.Consume(peer.Token, now); !ok || got.TenantID != "b" {
		t.Fatal("peer token lost")
	}
}

func TestDownloadHTTPDoesNotServeOnCommitFailure(t *testing.T) {
	p := &downloadFailureFixture{}
	s := newAdminDownloadTokenStore()
	if err := s.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tok, err := s.Create(downloadTestJob("a"), "test.gz", "issuer", []byte("private-export"), now)
	if err != nil {
		t.Fatal(err)
	}
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	outbox := &recordingAdminAuditOutboxDeadReader{}
	mux := http.NewServeMux()
	registerAdminSessionRoutes(mux, func(_ string, next http.HandlerFunc) http.HandlerFunc { return next }, serverConfig{}, testEvaluator(), writer, outbox, newAdminAuthStore(), s, nil, nil, true)
	request := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "/admin/export-downloads/"+tok.Token, nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}
	p.failCommit = true
	failed := request()
	if failed.Code != 503 || strings.Contains(failed.Body.String(), "private-export") || strings.Contains(failed.Body.String(), tok.Token) {
		t.Fatal("unconfirmed HTTP download was served")
	}
	p.failCommit = false
	success := request()
	if success.Code != 200 || success.Body.String() != "private-export" {
		t.Fatal("confirmed retry failed")
	}
	again := request()
	if again.Code != 404 {
		t.Fatal("second HTTP download succeeded")
	}
	event := adminDownloadAuditLog("admin_export_download_failed", tok, testEvaluator(), "127.0.0.1", "test")
	if *event.Result != "failure" || *event.ActorUserID != "anonymous_token_bearer" || event.TenantID != "a" {
		t.Fatal("failure audit attribution wrong")
	}
	raw, _ := json.Marshal(event)
	if bytes.Contains(raw, []byte(tok.Token)) || bytes.Contains(raw, []byte("private-export")) {
		t.Fatal("audit contains credential/payload")
	}
}

// The database may reject before invoking the row callback. Cached metadata
// supports failure attribution but must never authorize the bearer request.
type downloadEarlyRefusalFixture struct {
	*transactionalCAFixture
	refuse bool
}

func (p *downloadEarlyRefusalFixture) UpdateContext(ctx context.Context, edit func([]byte) ([]byte, error)) error {
	if p.refuse {
		return fmt.Errorf("unavailable before callback")
	}
	return p.transactionalCAFixture.UpdateContext(ctx, edit)
}
func TestDownloadEarlyRefusalKeepsAuditMetadataOnly(t *testing.T) {
	p := &downloadEarlyRefusalFixture{transactionalCAFixture: &transactionalCAFixture{}}
	s := newAdminDownloadTokenStore()
	if err := s.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tok, err := s.Create(downloadTestJob("a"), "private-path.gz", "issuer", []byte("private-export"), now)
	if err != nil {
		t.Fatal(err)
	}
	p.refuse = true
	got, ok, err := s.ConsumeContext(context.Background(), tok.Token, now)
	if err == nil || ok || got.TenantID != "a" || got.Token != "" || got.LocalFilename != "" || len(got.Payload) > 0 {
		t.Fatal("early refusal lost attribution or released secret")
	}
}
