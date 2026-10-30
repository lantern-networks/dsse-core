package enrolltoken

import (
	"errors"
	"testing"
	"time"
)

func TestWhitespaceTenantCannotBecomeUnscoped(t *testing.T) {
	s := NewStore()
	now := time.Now().UTC()
	tok, secret, err := s.Issue(DefaultPolicy(), "tenant", "", "case", "admin", "", now.Add(time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	if got := s.List(" \t "); len(got) != 0 {
		t.Fatal("whitespace lists all")
	}
	if _, err = s.Verify(secret, " \t ", now); !errors.Is(err, ErrWrongTenant) {
		t.Errorf("verify whitespace accepted: %v", err)
	}
	if _, err = s.Spend(tok.ID, " \t ", "device", now); !errors.Is(err, ErrWrongTenant) {
		t.Errorf("spend whitespace accepted: %v", err)
	}
	if _, err = s.Verify(secret, "tenant", now); err != nil {
		t.Fatal("invalid scope spent token")
	}
}
