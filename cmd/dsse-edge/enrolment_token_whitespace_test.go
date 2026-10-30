package main

import (
	"context"
	"errors"
	"github.com/lantern-networks/dsse-core/enrolltoken"
	"testing"
	"time"
)

func TestPostgresEnrolmentWhitespaceTenantCannotBecomeUnscoped(t *testing.T) {
	db := openEnrolmentTokenDB(t)
	s := newPostgresEnrolmentTokenStore(db)
	now := time.Now().UTC()
	tok, secret, err := s.Issue(enrolltoken.DefaultPolicy(), "tenant_test_whitespace", "", "case", "admin", "", now.Add(time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := s.ListContext(context.Background(), " \t ")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Errorf("whitespace filter exposed %d tokens", len(rows))
	}
	if _, err = s.Verify(secret, " \t ", now); !errors.Is(err, enrolltoken.ErrWrongTenant) {
		t.Errorf("whitespace verify accepted: %v", err)
	}
	if _, err = s.Spend(tok.ID, " \t ", "device", now); !errors.Is(err, enrolltoken.ErrWrongTenant) {
		t.Errorf("whitespace spend accepted: %v", err)
	}
	if _, ok, err := s.RevokeForTenantContext(context.Background(), " \t ", tok.ID, "admin", now); err != nil || ok {
		t.Errorf("whitespace revoke accepted: ok=%t err=%v", ok, err)
	}
	if _, err = s.Verify(secret, "tenant_test_whitespace", now); err != nil {
		t.Fatalf("invalid scoped requests changed token: %v", err)
	}
}
