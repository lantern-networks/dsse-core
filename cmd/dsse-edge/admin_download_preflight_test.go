package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestPostgresInvalidDownloadDoesNotWaitForCPWriter(t *testing.T) {
	d, _, _, _ := trustDistributionPostgresFixture(t)
	p := d.store.(postgresBlobPersister)
	p.key = "export_download_tokens"
	issuer, reader := newAdminDownloadTokenStore(), newAdminDownloadTokenStore()
	if err := issuer.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	spent, err := issuer.Create(downloadTestJob("a"), "test.gz", "review", []byte("private-export"), now)
	if err != nil {
		t.Fatal(err)
	}
	expired, err := issuer.Create(downloadTestJob("b"), "test.gz", "review", []byte("expired-export"), now)
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	// The reader still caches both active tokens. Preflight must read the shared
	// row, without joining the advisory-lock session used by the busy writer.
	if _, ok := issuer.Consume(spent.Token, now); !ok {
		t.Fatal("spend failed")
	}
	raw, err := p.Load()
	if err != nil {
		t.Fatal(err)
	}
	var tokens map[string]adminDownloadToken
	if err := json.Unmarshal(raw, &tokens); err != nil {
		t.Fatal(err)
	}
	old := tokens[expired.Token]
	old.ExpiresAt = now.Add(-time.Minute).UTC().Format(time.RFC3339)
	tokens[expired.Token] = old
	before, _ := json.Marshal(tokens)
	if err := p.Save(before); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	registerAdminSessionRoutes(mux, func(_ string, next http.HandlerFunc) http.HandlerFunc { return next }, serverConfig{}, testEvaluator(), nil, nil, newAdminAuthStore(), reader, nil, nil, true)
	lease := retentionWriteContext(context.Background())
	tx, finish, err := beginCPWriteTransaction(lease, p.db)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { finish() }()
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT INTO cp_state_blobs(store_key,payload) VALUES ('busy_writer','{}')`); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"unknown-bearer", spent.Token, expired.Token} {
		done := make(chan *httptest.ResponseRecorder, 1)
		go func() {
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, httptest.NewRequest("GET", "/admin/export-downloads/"+value, nil))
			done <- w
		}()
		select {
		case w := <-done:
			if w.Code != http.StatusNotFound {
				t.Fatalf("invalid bearer status=%d", w.Code)
			}
		case <-time.After(2 * time.Second):
			// Always drain the request before global fixture cleanup, including
			// when running this regression against the old implementation.
			tx.Rollback()
			finish()
			finish = func() {}
			<-done
			t.Fatal("invalid bearer waited for CP writer")
		}
	}
	after, err := p.Load()
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("invalid bearer changed token row", err)
	}
}

type downloadPreflightRaceFixture struct {
	transactionalCAFixture
	beforeUpdate func()
}

func (p *downloadPreflightRaceFixture) UpdateContext(ctx context.Context, edit func([]byte) ([]byte, error)) error {
	if p.beforeUpdate != nil {
		p.beforeUpdate()
	}
	return p.transactionalCAFixture.UpdateContext(ctx, edit)
}

func TestDownloadPreflightDoesNotAuthorizeSpend(t *testing.T) {
	p := &downloadPreflightRaceFixture{}
	s := newAdminDownloadTokenStore()
	if err := s.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tok, err := s.Create(downloadTestJob("a"), "test.gz", "review", []byte("private-export"), now)
	if err != nil {
		t.Fatal(err)
	}
	p.beforeUpdate = func() {
		raw, _ := p.Load()
		var tokens map[string]adminDownloadToken
		json.Unmarshal(raw, &tokens)
		used := tokens[tok.Token]
		used.Status, used.Payload = "used", nil
		tokens[tok.Token] = used
		raw, _ = json.Marshal(tokens)
		p.Save(raw)
	}
	got, ok, err := s.ConsumeContext(context.Background(), tok.Token, now)
	if err != nil || ok || got.Token != "" || len(got.Payload) != 0 {
		t.Fatal("preflight bypassed transactional spend", err)
	}
}
