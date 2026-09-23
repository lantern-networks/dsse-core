package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// standbyDownloadRow reads the shared row like any node, and refuses every write
// the way beginCPWriteTransaction does on a control plane that holds no term.
type standbyDownloadRow struct {
	transactionalCAFixture
	standby bool
}

func (p *standbyDownloadRow) UpdateContext(ctx context.Context, edit func([]byte) ([]byte, error)) error {
	if p.standby {
		return writeNotCommittedError{errCPLeadershipChanged}
	}
	return p.transactionalCAFixture.UpdateContext(ctx, edit)
}

// On a standby the storage is healthy; only the write term is elsewhere. The
// answer used to be 503 "storage is unavailable; retry later", which retrying on
// the same node never fixes. It is now the same 409 every other admin write gives.
func TestDownloadOnAStandbyIsNotBlamedOnStorage(t *testing.T) {
	p := &standbyDownloadRow{}
	s := newAdminDownloadTokenStore()
	if err := s.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	tok, err := s.Create(downloadTestJob("tenant_a"), "test.gz", "review", []byte("private-export"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	p.standby = true
	if _, err := s.Create(downloadTestJob("tenant_a"), "next.gz", "review", []byte("x"), time.Now()); !errors.Is(err, errDownloadNotLeader) {
		t.Fatalf("standby issuance blamed on storage: %v", err)
	}
	mux := http.NewServeMux()
	registerAdminSessionRoutes(mux, func(_ string, next http.HandlerFunc) http.HandlerFunc { return next }, serverConfig{}, testEvaluator(), nil, nil, newAdminAuthStore(), s, nil, nil, true)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest("GET", "/admin/export-downloads/"+tok.Token, nil))
	if rr.Code != http.StatusConflict || strings.Contains(rr.Body.String(), "retry later") {
		t.Fatalf("standby consume: %d %s", rr.Code, rr.Body)
	}
	p.standby = false
	if got, ok, err := s.ConsumeContext(context.Background(), tok.Token, time.Now()); err != nil || !ok || string(got.Payload) != "private-export" {
		t.Fatalf("refused standby attempt consumed the link: ok=%v err=%v", ok, err)
	}
}
