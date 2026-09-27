package main

import (
	"encoding/json"
	"errors"
	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/grantstore"
	"github.com/lantern-networks/dsse-core/logs"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type grantDurabilityWriter struct {
	blobstore.FilePersister
	outcome error
}

func (p *grantDurabilityWriter) Save(b []byte) error {
	if err := p.FilePersister.Save(b); err != nil {
		return err
	}
	return p.outcome
}
func TestGrantRevocationReportsWeakSaveAndUnconfirmedFlush(t *testing.T) {
	now := time.Now()
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: writer})
	s := theGrantStore.Load()
	p := &grantDurabilityWriter{FilePersister: blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "grants.json")}}
	if err := s.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"private-in-place-cookie", "private-unflushed-cookie"} {
		if _, err := s.Mint(grantstore.Grant{GrantID: id, TenantID: "tenant_lab_001"}, time.Hour, now); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		id          string
		outcome     error
		status      int
		persistence string
	}{
		{"private-in-place-cookie", blobstore.ErrSavedWithoutAtomicity, 200, "saved_non_atomic"},
		{"private-unflushed-cookie", errors.Join(blobstore.ErrSavedWithoutAtomicity, blobstore.ErrDurabilityUnconfirmed), 500, "unconfirmed"},
		{"private-unflushed-cookie", nil, 200, ""},
	} {
		p.outcome = tc.outcome
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest("POST", "/admin/grants/"+tc.id+"/revoke", nil))
		if rr.Code != tc.status {
			t.Fatalf("HTTP%d want%d: %s", rr.Code, tc.status, rr.Body)
		}
		var body map[string]any
		if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if tc.persistence != "" && body["persistence"] != tc.persistence {
			t.Fatalf("wrong persistence: %v", body)
		}
		if tc.persistence == "" && body["persistence"] != nil {
			t.Fatal("recovered save still uncertain")
		}
		if s.Valid(tc.id, now) {
			t.Fatal("revocation not retained")
		}
	}
	audits := readTransportAudits(t, writer)
	domain := 0
	for _, a := range audits {
		if a.EventType != "admin_access_grant_revoked" {
			continue
		}
		domain++
		switch domain {
		case 1:
			if stringPtrValue(a.Result) != "revoked" || a.Metadata["persistence"] != "saved_non_atomic" {
				t.Fatalf("missing weaker-save audit: %+v", a)
			}
		case 2:
			if stringPtrValue(a.Result) != "partial" || a.Metadata["persistence"] != "unconfirmed" {
				t.Fatalf("missing partial audit: %+v", a)
			}
		case 3:
			if stringPtrValue(a.Result) != "revoked" || a.Metadata["persistence"] != nil {
				t.Fatal("recovery audit wrong")
			}
		}
	}
	if domain != 3 {
		t.Fatalf("domain audits=%d", domain)
	}
	raw, _ := json.Marshal(audits)
	for _, id := range []string{"private-in-place-cookie", "private-unflushed-cookie"} {
		if strings.Contains(string(raw), id) {
			t.Fatal("bearer credential in audit")
		}
	}
	restarted := grantstore.NewStore()
	if err := restarted.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	for _, g := range restarted.ListAll() {
		if !g.Revoked {
			t.Fatal("saved revocation lost")
		}
	}
}
