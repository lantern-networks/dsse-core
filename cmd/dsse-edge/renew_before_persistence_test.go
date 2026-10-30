package main

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/durablefile"
	"github.com/lantern-networks/dsse-core/enrolledinventory"
)

func TestRenewBeforeReportsPostRenameDurabilityFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cutoff.json")
	s := mustRenewBeforeSetting(t, path)
	s.write = func(path string, raw []byte, mode os.FileMode) error {
		if err := durablefile.Write(path, raw, mode); err != nil {
			return err
		}
		return durablefile.ErrReplacedNotFlushed
	}
	at := time.Now().UTC()
	if err := s.Set(at); !errors.Is(err, durablefile.ErrReplacedNotFlushed) {
		t.Fatalf("durability failure hidden: %v", err)
	}
	if got, _ := s.At(); !got.Equal(at) {
		t.Fatal("visible file and runtime cutoff disagree")
	}
	if got, _ := mustRenewBeforeSetting(t, path).At(); !got.Equal(at) {
		t.Fatal("restart lost cutoff precision")
	}
	if err := s.Clear(); !errors.Is(err, durablefile.ErrReplacedNotFlushed) {
		t.Fatalf("clear durability failure hidden: %v", err)
	}
	if _, ok := s.At(); ok {
		t.Fatal("visible cleared file disagrees with memory")
	}
	if _, ok := mustRenewBeforeSetting(t, path).At(); ok {
		t.Fatal("clear not visible after restart")
	}
}

func TestRenewBeforeFailedPersistenceKeepsEffectiveCutoff(t *testing.T) {
	for _, clear := range []bool{false, true} {
		t.Run(map[bool]string{false: "set", true: "clear"}[clear], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "cutoff.json")
			s := mustRenewBeforeSetting(t, path)
			before := time.Date(2026, 10, 23, 1, 0, 0, 0, time.UTC)
			if err := s.Set(before); err != nil {
				t.Fatal(err)
			}
			// A non-empty directory makes both replacement and removal fail,
			// including when tests execute with elevated filesystem privileges.
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(path, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(path, "occupied"), []byte("x"), 0600); err != nil {
				t.Fatal(err)
			}
			var err error
			if clear {
				err = s.Clear()
			} else {
				err = s.Set(before.Add(time.Hour))
			}
			if err == nil {
				t.Fatal("persistence unexpectedly succeeded")
			}
			if got, ok := s.At(); !ok || !got.Equal(before) {
				t.Fatalf("failed change became effective: %v, %v", got, ok)
			}
		})
	}
}

func TestRecoveryReadinessKeepsCaseDistinctTenantsSeparate(t *testing.T) {
	l := enrolledinventory.NewLedger()
	for _, e := range []struct{ id, tenant string }{{"device-a", "Acme"}, {"device-b", "acme"}} {
		if _, err := l.RecordEnrolmentDecidedElsewhere(e.id, e.tenant, "", "", time.Now().UTC().Format(time.RFC3339)); err != nil {
			t.Fatal(err)
		}
	}
	for tenant, want := range map[string][]string{"Acme": {"device-a"}, "acme": {"device-b"}, "ACME": {}} {
		if got := keptForTenant(l, tenant, []string{"device-a", "device-b"}); !slices.Equal(got, want) {
			t.Fatalf("tenant %s: got %v, want %v", tenant, got, want)
		}
	}
}
