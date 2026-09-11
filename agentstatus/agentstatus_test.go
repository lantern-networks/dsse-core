package agentstatus

import (
	"sync"
	"testing"
)

func TestProtectionIconLabel(t *testing.T) {
	cases := []struct {
		p    Protection
		icon string
	}{
		{Steering, "green"},
		{CaptiveOnboarding, "amber"},
		{Disarmed, "amber"},
		{Dark, "red"},
		{Error, "red"},
		{Stopped, "gray"},
		{Protection("unknown"), "gray"},
	}
	for _, c := range cases {
		if got := c.p.Icon(); got != c.icon {
			t.Fatalf("%s.Icon() = %q, want %q", c.p, got, c.icon)
		}
		if c.p.Label() == "" {
			t.Fatalf("%s.Label() empty", c.p)
		}
	}
}

func TestHolderSetSnapshotJSONRoundTrip(t *testing.T) {
	h := NewHolder(Status{Protection: Stopped})
	h.Set(func(s *Status) {
		s.Tenant = "acme"
		s.Group = "developers"
		s.Region = "ap-northeast-1"
		s.Posture = "fail-closed"
		s.Enrolled = true
		s.PolicyVersion = 7
	})
	h.SetProtection(Steering, 1_700_000_000)

	snap := h.Snapshot()
	if snap.Protection != Steering || snap.Tenant != "acme" || snap.PolicyVersion != 7 || snap.UpdatedUnix != 1_700_000_000 {
		t.Fatalf("snapshot lost fields: %+v", snap)
	}

	b, err := h.JSON()
	if err != nil {
		t.Fatalf("json: %v", err)
	}
	got, err := Parse(b)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got != snap {
		t.Fatalf("round-trip mismatch:\n got=%+v\nwant=%+v", got, snap)
	}
}

func TestHolderConcurrentAccess(t *testing.T) {
	h := NewHolder(Status{Protection: Stopped})
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func(n int) { defer wg.Done(); h.SetProtection(Steering, int64(n)) }(i)
		go func() { defer wg.Done(); _ = h.Snapshot() }()
	}
	wg.Wait()
	if h.Snapshot().Protection != Steering {
		t.Fatalf("expected steering after concurrent sets")
	}
}
