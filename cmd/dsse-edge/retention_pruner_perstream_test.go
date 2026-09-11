package main

import (
	"testing"
	"time"
)

func TestParseRetentionOverrides(t *testing.T) {
	m := parseRetentionOverrides("audit=8760h, access=168h ,bad-entry, x=notaduration, =5h")
	if got := m["audit"]; got != 8760*time.Hour {
		t.Fatalf("audit = %v, want 8760h", got)
	}
	if got := m["access"]; got != 168*time.Hour {
		t.Fatalf("access = %v, want 168h", got)
	}
	if _, ok := m["x"]; ok {
		t.Fatal("invalid duration must be skipped")
	}
	if len(m) != 2 {
		t.Fatalf("want 2 valid overrides, got %d: %v", len(m), m)
	}
}

func TestRetentionForStream(t *testing.T) {
	cfg := retentionConfig{hotEvents: 720 * time.Hour, perStream: map[string]time.Duration{"audit": 8760 * time.Hour, "access": 0}}
	if got := cfg.retentionForStream("audit"); got != 8760*time.Hour {
		t.Fatalf("audit override = %v, want 8760h", got)
	}
	if got := cfg.retentionForStream("access"); got != 0 {
		t.Fatalf("access override = %v, want 0 (keep forever)", got)
	}
	if got := cfg.retentionForStream("connector"); got != 720*time.Hour {
		t.Fatalf("connector (no override) = %v, want global 720h", got)
	}
}

func TestRetentionForStreamAdminOverrideWins(t *testing.T) {
	ov := newRetentionOverrideStore(nil)
	ov.Set("access", 7) // admin: keep access 7 days (overrides the flag)
	cfg := retentionConfig{hotEvents: 720 * time.Hour, perStream: map[string]time.Duration{"access": 24 * time.Hour}, override: ov}
	if got := cfg.retentionForStream("access"); got != 7*24*time.Hour {
		t.Fatalf("admin override should win: got %v, want 168h", got)
	}
	// A stream without an admin override falls back to the flag/global.
	if got := cfg.retentionForStream("connector"); got != 720*time.Hour {
		t.Fatalf("no override → global: got %v, want 720h", got)
	}
}
