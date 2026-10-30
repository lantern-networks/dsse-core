package policy

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestUpstreamTLSAuthorPersistenceIsolationAndAtomicFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime.json")
	s := NewStore(nil)
	if s.UpstreamTLSModeFor("one") != UpstreamTLSBrowserCompatible {
		t.Fatal("default is not browser compatible")
	}
	if err := s.SetUpstreamTLSModeConfirmed("one", UpstreamTLSStrict); !errors.Is(err, ErrPolicyPersistence) {
		t.Fatal("memory-only change accepted", err)
	}
	if err := s.SetRuntimeStatePath(path); err != nil {
		t.Fatal(err)
	}
	before := s.ConfigGeneration()
	for _, mode := range []string{"", "compatibility", "STRICT", " strict "} {
		if err := s.SetUpstreamTLSModeConfirmed("one", mode); err == nil {
			t.Fatal("invalid accepted", mode)
		}
	}
	if s.ConfigGeneration() != before || len(s.Tenants()) != 0 {
		t.Fatal("invalid input changed state")
	}
	if err := s.SetUpstreamTLSModeConfirmed("one", UpstreamTLSStrict); err != nil {
		t.Fatal(err)
	}
	if s.ConfigGeneration() <= before || s.UpstreamTLSModeFor("two") != UpstreamTLSBrowserCompatible {
		t.Fatal("generation or isolation")
	}
	restored := NewStore(nil)
	if err := restored.SetRuntimeStatePath(path); err != nil {
		t.Fatal(err)
	}
	if restored.UpstreamTLSModeFor("one") != UpstreamTLSStrict || len(restored.Tenants()) != 1 {
		t.Fatal("mode-only tenant missing on restart")
	}
	failed := NewStore(nil)
	_ = failed.SetRuntimeStatePersister(trFailPersister{})
	before = failed.ConfigGeneration()
	if err := failed.SetUpstreamTLSModeConfirmed("one", UpstreamTLSStrict); !errors.Is(err, ErrPolicyPersistence) {
		t.Fatal(err)
	}
	if failed.ConfigGeneration() != before || failed.UpstreamTLSModeFor("one") != UpstreamTLSBrowserCompatible {
		t.Fatal("failed write published")
	}
}

func TestUpstreamTLSSharedMergeAndFailClosedRefresh(t *testing.T) {
	shared := &trSharedPersister{}
	one, two := NewStore(nil), NewStore(nil)
	for _, s := range []*Store{one, two} {
		if err := s.SetRuntimeStatePersister(shared); err != nil {
			t.Fatal(err)
		}
	}
	if err := one.SetUpstreamTLSModeConfirmed("one", UpstreamTLSStrict); err != nil {
		t.Fatal(err)
	}
	if err := two.SetUpstreamTLSModeConfirmed("two", UpstreamTLSStrict); err != nil {
		t.Fatal(err)
	}
	if err := one.RefreshSharedRuntime(); err != nil {
		t.Fatal(err)
	}
	if one.UpstreamTLSModeFor("two") != UpstreamTLSStrict || two.UpstreamTLSModeFor("one") != UpstreamTLSStrict {
		t.Fatal("shared merge lost tenant")
	}
	shared.fail = true
	before := one.ConfigGeneration()
	if err := one.SetUpstreamTLSModeConfirmed("one", UpstreamTLSBrowserCompatible); !errors.Is(err, ErrPolicyPersistence) {
		t.Fatal(err)
	}
	if one.UpstreamTLSModeFor("one") != UpstreamTLSStrict || one.ConfigGeneration() != before {
		t.Fatal("failed authority update published")
	}
	if one.RefreshSharedRuntime() == nil {
		t.Fatal("authority error hidden")
	}
}

func TestUpstreamTLSReceivedCacheResetValidationAndErasure(t *testing.T) {
	cp := NewStore(nil)
	_ = cp.SetRuntimeStatePath(filepath.Join(t.TempDir(), "cp.json"))
	for _, tenant := range []string{"one", "two"} {
		if err := cp.SetUpstreamTLSModeConfirmed(tenant, UpstreamTLSStrict); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(t.TempDir(), "edge.json")
	edge := NewStore(nil)
	_ = edge.SetRuntimeStatePath(path)
	apply := func(tenant string, cfg TenantConfigBundle) {
		t.Helper()
		raw, _ := json.Marshal(cfg)
		var decoded TenantConfigBundle
		if err := json.Unmarshal(raw, &decoded); err != nil {
			t.Fatal(err)
		}
		if _, err := edge.ApplyReceivedBundle(tenant, nil, decoded, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	for _, tenant := range cp.Tenants() {
		apply(tenant, cp.SnapshotTenantConfig(tenant))
	}
	before := edge.ConfigGeneration()
	invalid := TenantConfigBundle{UpstreamTLSMode: "unknown"}
	if _, err := edge.ApplyReceivedBundle("one", nil, invalid, time.Now()); err == nil {
		t.Fatal("received invalid mode")
	}
	edge.ApplyBundle("one", nil, invalid, time.Now())
	if edge.ConfigGeneration() != before || edge.UpstreamTLSModeFor("one") != UpstreamTLSStrict {
		t.Fatal("invalid bundle mutated state")
	}
	apply("one", TenantConfigBundle{})
	fresh := NewStore(nil)
	if err := fresh.SetRuntimeStatePath(path); err != nil {
		t.Fatal(err)
	}
	if fresh.UpstreamTLSModeFor("one") != UpstreamTLSBrowserCompatible || fresh.UpstreamTLSModeFor("two") != UpstreamTLSStrict {
		t.Fatal("restart reset/isolation")
	}
	if n, err := cp.RemoveUpstreamTLSSettingsContext(context.Background(), "two"); n != 1 || err != nil {
		t.Fatal(n, err)
	}
	// The erasure record is an explicit reset to the default, not an absent
	// tenant: an offline Edge still needs to learn that strict was withdrawn.
	resetPublished := false
	for _, tenant := range cp.Tenants() {
		if tenant == "two" {
			resetPublished = true
		}
	}
	if !resetPublished || cp.SnapshotTenantConfig("two").UpstreamTLSMode != UpstreamTLSBrowserCompatible {
		t.Fatal("erasure reset marker omitted from distribution")
	}
	apply("two", cp.SnapshotTenantConfig("two"))
	if edge.UpstreamTLSModeFor("two") != UpstreamTLSBrowserCompatible || cp.CountUpstreamTLSSettings("two") != 0 {
		t.Fatal("erasure not propagated")
	}
	raw, _ := json.Marshal(adminPolicyRuntimeStateFile{UpstreamTLSModes: map[string]string{"one": "invalid"}})
	if _, _, err := decodeRuntimeState(raw); err == nil {
		t.Fatal("invalid durable state accepted")
	}
}
